use super::{to_kst, Caller, Core};
use chrono::TimeZone;
use netbridge_proto::*;
use rusqlite::{params, OptionalExtension};

pub fn fmt_bytes(b: u64) -> String {
    const MB: f64 = 1024.0 * 1024.0;
    if b >= 1024 * 1024 * 1024 {
        format!("{:.1}GB", b as f64 / (MB * 1024.0))
    } else {
        format!("{:.0}MB", (b as f64 / MB).ceil())
    }
}

/// Lowercase extension after the last dot ("" when none).
pub fn ext_of(name: &str) -> String {
    name.rsplit_once('.').map(|(_, e)| e.to_ascii_lowercase()).unwrap_or_default()
}

/// Unfinished uploads count only once their completion has reserved them.
/// Counted per route: each direction of each link has its own daily allowance.
pub(super) fn used_since(c: &rusqlite::Connection, user_id: i64, start: i64, route: &Route) -> rusqlite::Result<u64> {
    let n: i64 = c.query_row(
        "SELECT COALESCE(SUM(size),0) FROM transfers WHERE user_id=?1 AND created_at>=?2 AND from_net=?3 AND to_net=?4 AND state NOT IN ('Rejected','Blocked') AND (state<>'Uploading' OR reserved=1)",
        params![user_id, start, route.from.as_str(), route.to.as_str()],
        |r| r.get(0),
    )?;
    Ok(n as u64)
}

fn scope_key(s: LimitScope) -> (&'static str, i64) {
    match s {
        LimitScope::Dept(id) => ("dept", id),
        LimitScope::User(id) => ("user", id),
    }
}

impl Core {
    fn override_of(&self, scope: LimitScope) -> Result<Option<Limits>, ApiError> {
        let (s, id) = scope_key(scope);
        self.db.with(|c| {
            c.query_row("SELECT daily_bytes, per_file_bytes FROM limit_overrides WHERE scope=?1 AND scope_id=?2", params![s, id], |r| {
                Ok(Limits { daily_bytes: r.get::<_, i64>(0)? as u64, per_file_bytes: r.get::<_, i64>(1)? as u64 })
            })
            .optional()
        })
    }

    /// User override, then department override, then the route's limits.
    pub fn effective_limits(&self, user_id: i64, route: &RoutePolicy) -> Result<Limits, ApiError> {
        if let Some(l) = self.override_of(LimitScope::User(user_id))? {
            return Ok(l);
        }
        let dept: Option<i64> = self.db.with(|c| c.query_row("SELECT dept_id FROM users WHERE id=?1", [user_id], |r| r.get(0)))?;
        if let Some(d) = dept {
            if let Some(l) = self.override_of(LimitScope::Dept(d))? {
                return Ok(l);
            }
        }
        Ok(route.lim())
    }

    pub fn set_limit_override(&self, scope: LimitScope, limits: Option<Limits>) -> Result<(), ApiError> {
        let (s, id) = scope_key(scope);
        self.db.with(|c| match limits {
            Some(l) => c
                .execute(
                    "INSERT INTO limit_overrides(scope,scope_id,daily_bytes,per_file_bytes) VALUES(?1,?2,?3,?4) ON CONFLICT(scope,scope_id) DO UPDATE SET daily_bytes=excluded.daily_bytes, per_file_bytes=excluded.per_file_bytes",
                    params![s, id, l.daily_bytes as i64, l.per_file_bytes as i64],
                )
                .map(|_| ()),
            None => c.execute("DELETE FROM limit_overrides WHERE scope=?1 AND scope_id=?2", params![s, id]).map(|_| ()),
        })
    }

    /// Start of today in KST as a unix timestamp.
    pub fn kst_day_start(&self) -> i64 {
        let d = to_kst(self.clock.now()).date_naive();
        super::kst().from_local_datetime(&d.and_hms_opt(0, 0, 0).unwrap()).unwrap().timestamp()
    }

    /// Bytes sent since KST midnight, not counting rejected or blocked transfers.
    pub fn used_today(&self, user_id: i64, route: &Route) -> Result<u64, ApiError> {
        let start = self.kst_day_start();
        self.db.with(|c| used_since(c, user_id, start, route))
    }

    pub fn check_file(&self, user_id: i64, p: &RoutePolicy, name: &str, size: u64) -> Result<(), ApiError> {
        self.check_file_with(user_id, p, name, size, 0)
    }

    /// `pending` is the size of files earlier in the same batch.
    pub fn check_file_with(&self, user_id: i64, p: &RoutePolicy, name: &str, size: u64, pending: u64) -> Result<(), ApiError> {
        let ext = ext_of(name);
        if p.blocked().iter().any(|e| e.eq_ignore_ascii_case(&ext)) || (!p.allowed().is_empty() && !p.allowed().iter().any(|e| e.eq_ignore_ascii_case(&ext))) {
            let shown = if ext.is_empty() { "확장자 없음".to_string() } else { ext };
            return Err(ApiError::new(ErrorCode::Blocked, format!("{name}: 보낼 수 없는 파일 형식입니다 ({shown})")));
        }
        let l = self.effective_limits(user_id, p)?;
        if size > l.per_file_bytes {
            return Err(ApiError::new(ErrorCode::LimitExceeded, format!("{name}: 파일 1개 한도({})를 넘습니다 ({})", fmt_bytes(l.per_file_bytes), fmt_bytes(size))));
        }
        let used = self.used_today(user_id, &p.route)? + pending;
        if used + size > l.daily_bytes {
            let left = l.daily_bytes.saturating_sub(used);
            return Err(ApiError::new(ErrorCode::LimitExceeded, format!("{name}: 하루 한도({})를 넘습니다. 오늘 남은 양: {}", fmt_bytes(l.daily_bytes), fmt_bytes(left))));
        }
        Ok(())
    }

    pub async fn set_policy(&self, p: &Policy, by: Option<&Caller>) -> Result<(), ApiError> {
        for r in p.pii_rules.iter().filter(|r| !r.builtin) {
            let pat = r.pattern.as_deref().unwrap_or("");
            if pat.is_empty() {
                return Err(ApiError::bad(format!("{}: 정규식을 입력하세요", r.name)));
            }
            netbridge_pii::validate_custom(pat).map_err(|e| ApiError::bad(format!("{}: {e}", r.name)))?;
        }
        if p.pw_min_len < 4 || p.login_fail_lock == 0 || p.file_retention_days == 0 || p.post_deadline_days == 0 {
            return Err(ApiError::bad("정책 값이 올바르지 않습니다 (비밀번호 4자 이상, 잠금 횟수·보관 기간·사후결재 기한은 1 이상)"));
        }
        let old = self.db.policy()?;
        self.store_policy(p)?;
        let diff = policy_diff(&old, p);
        self.audit(by.map(|c| (c.user_id, c.username.as_str())), "policy_change", by.map(|c| c.ip.as_str()), &diff);
        self.push_everyone(Event::PolicyChanged { policy: p.clone() }).await;
        Ok(())
    }
}

/// "field: old → new" for each changed top-level field.
fn policy_diff(old: &Policy, new: &Policy) -> String {
    let a = serde_json::to_value(old).unwrap_or_default();
    let b = serde_json::to_value(new).unwrap_or_default();
    let (Some(a), Some(b)) = (a.as_object(), b.as_object()) else { return String::new() };
    let parts: Vec<String> = b.iter().filter(|(k, v)| a.get(*k) != Some(v)).map(|(k, v)| format!("{k}: {} → {v}", a.get(k).cloned().unwrap_or_default())).collect();
    if parts.is_empty() {
        "변경 없음".into()
    } else {
        parts.join("; ")
    }
}

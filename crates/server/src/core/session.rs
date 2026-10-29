use super::auth::{parse_role, random_hex, sha};
use super::{CallCtx, Caller, Core};
use netbridge_proto::*;
use rusqlite::{params, OptionalExtension};

/// A device authenticated by its key, before any user login.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceRef {
    pub device_id: i64,
    pub user_id: i64,
    pub side: Side,
}

impl Core {
    pub fn device_auth(&self, key: &str) -> Option<DeviceRef> {
        let h = sha(key);
        self.db
            .with(|c| c.query_row("SELECT id, user_id, side FROM devices WHERE key_hash=?1", [h], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?, r.get::<_, String>(2)?))).optional())
            .ok()
            .flatten()
            .map(|(device_id, user_id, s)| DeviceRef { device_id, user_id, side: NetId(s) })
    }

    /// Returns (session id, token, newly created). An open session is reused so both PCs share it.
    pub(super) fn open_session(&self, uid: i64) -> Result<(i64, String, bool), ApiError> {
        let now = self.clock.now();
        let max = self.db.policy()?.session_max_minutes;
        let open = self.db.with(|c| {
            c.query_row("SELECT id, token, created_at FROM sessions WHERE user_id=?1 AND ended_at IS NULL ORDER BY id DESC LIMIT 1", [uid], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?, r.get::<_, i64>(2)?)))
                .optional()
        })?;
        if let Some((id, token, created)) = open {
            if !max.is_some_and(|m| now - created > m as i64 * 60) {
                return Ok((id, token, false));
            }
            self.end_session_row(id, "최대 유지 시간 초과")?;
        }
        let token = random_hex(32);
        let id = self.db.with(|c| {
            c.execute("INSERT INTO sessions(user_id,token,created_at,last_seen) VALUES(?1,?2,?3,?3)", params![uid, token, now])?;
            Ok(c.last_insert_rowid())
        })?;
        Ok((id, token, true))
    }

    fn end_session_row(&self, id: i64, reason: &str) -> Result<(), ApiError> {
        let now = self.clock.now();
        self.db.with(|c| c.execute("UPDATE sessions SET ended_at=?2, end_reason=?3 WHERE id=?1 AND ended_at IS NULL", params![id, now, reason]).map(|_| ()))
    }

    /// Validates the bearer token. Reconnects never end a session; only logout, an admin, or the max age do.
    pub(super) async fn authenticate(&self, ctx: &CallCtx) -> Result<Caller, ApiError> {
        let expired = || ApiError::new(ErrorCode::SessionExpired, "로그인이 필요합니다");
        let token = ctx.token.as_deref().ok_or_else(expired)?;
        let row = self.db.with(|c| {
            c.query_row("SELECT s.id, s.user_id, s.created_at, s.ended_at, u.username, u.role, u.locked FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token=?1", [token], |r| {
                Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?, r.get::<_, i64>(2)?, r.get::<_, Option<i64>>(3)?, r.get::<_, String>(4)?, r.get::<_, String>(5)?, r.get::<_, bool>(6)?))
            })
            .optional()
        })?;
        let Some((sid, uid, created, ended, username, role, locked)) = row else { return Err(expired()) };
        if ended.is_some() {
            return Err(expired());
        }
        let now = self.clock.now();
        let max = self.db.policy()?.session_max_minutes;
        let caller = Caller { session_id: sid, user_id: uid, username, role: parse_role(&role), side: ctx.side.clone(), ip: ctx.client_ip.clone() };
        if locked || max.is_some_and(|m| now - created > m as i64 * 60) {
            let reason = if locked { "계정 잠김" } else { "최대 유지 시간 초과" };
            self.logout(&caller, reason).await?;
            return Err(ApiError::new(ErrorCode::SessionExpired, format!("세션이 종료되었습니다 ({reason})")));
        }
        // the admin may have taken this network away since the login
        if !self.user_networks(uid)?.contains(&ctx.side) {
            return Err(ApiError::new(ErrorCode::Forbidden, format!("이 계정은 {}에서 사용할 수 없습니다", self.topo.name(&ctx.side))));
        }
        self.db.with(|c| c.execute("UPDATE sessions SET last_seen=?2 WHERE id=?1", params![sid, now]))?;
        Ok(caller)
    }

    /// Ends the caller's session on both networks.
    pub async fn logout(&self, c: &Caller, reason: &str) -> Result<(), ApiError> {
        self.end_session_row(c.session_id, reason)?;
        self.audit(Some((c.user_id, &c.username)), "logout", Some(&c.ip), reason);
        self.push_user(c.user_id, Event::SessionEnded { reason: reason.to_string() }).await;
        Ok(())
    }
}

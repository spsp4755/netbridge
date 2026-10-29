use super::auth::{check_password_policy, hash_password, role_str};
use super::{Caller, Core};
use netbridge_proto::*;
use rusqlite::{params, OptionalExtension};

impl Core {
    pub(super) async fn admin(&self, c: &Caller, req: AdminRequest) -> ApiResult {
        if c.role != Role::Admin {
            return Err(ApiError::new(ErrorCode::Forbidden, "관리자 권한이 필요합니다"));
        }
        if !self.is_local(&c.side) {
            return Err(ApiError::new(ErrorCode::Forbidden, format!("관리자 기능은 {}에서만 사용할 수 있습니다", self.topo.name(&self.net))));
        }
        let me = Some((c.user_id, c.username.as_str()));
        let ip = Some(c.ip.as_str());
        match req {
            AdminRequest::ListUsers => self.list_users().map(ApiResponse::Users),
            AdminRequest::UpsertUser { user } => {
                if user.approver_id.is_some() && user.approver_id == user.id {
                    return Err(ApiError::bad("본인을 결재자로 지정할 수 없습니다"));
                }
                let id = match user.id {
                    None => self.create_user(&user)?,
                    Some(id) => {
                        self.db
                            .with(|db| {
                                db.execute(
                                    "UPDATE users SET username=?2, name=?3, dept_id=?4, role=?5, approver_id=?6, networks=?7 WHERE id=?1",
                                    params![id, user.username.trim(), user.name.trim(), user.dept_id, role_str(user.role), user.approver_id, serde_json::to_string(&user.networks).unwrap_or_else(|_| "[]".into())],
                                )
                            })
                            .map_err(|e| if e.message.contains("UNIQUE") { ApiError::bad("이미 있는 아이디입니다") } else { e })?;
                        id
                    }
                };
                // PCs on networks the user may no longer use are disconnected and unregistered
                let allowed = self.user_networks(id)?;
                for (side, dev) in self.devices_of(id)?.into_iter().filter(|(s, _)| !allowed.contains(s)) {
                    self.push(&side, dev, Event::SessionEnded { reason: format!("{} 사용 권한이 해제되었습니다", self.topo.name(&side)) }).await;
                    if self.is_local(&side) {
                        self.hub.drop_device(dev);
                    } else if let Ok(p) = self.peer(&side) {
                        let _ = p.drop_device(dev).await;
                    }
                    self.db.with(|db| db.execute("DELETE FROM devices WHERE id=?1", [dev]))?;
                }
                self.audit(me, "admin", ip, &format!("사용자 저장: {} ({})", user.username, user.name));
                Ok(ApiResponse::Id(id))
            }
            AdminRequest::ResetPassword { user_id, new } => {
                check_password_policy(&new, &self.db.policy()?)?;
                let now = self.clock.now();
                self.db.with(|db| db.execute("UPDATE users SET pw_hash=?2, pw_changed_at=?3, must_change=1, fail_count=0, locked=0 WHERE id=?1", params![user_id, hash_password(&new), now]))?;
                // whoever knew the old password must not keep a live session
                self.end_user_sessions(c, user_id, "관리자가 비밀번호를 초기화했습니다").await?;
                self.audit(me, "admin", ip, &format!("비밀번호 초기화: 사용자 #{user_id}"));
                Ok(ApiResponse::Ok)
            }
            AdminRequest::UnlockUser { user_id } => {
                self.db.with(|db| db.execute("UPDATE users SET locked=0, fail_count=0 WHERE id=?1", [user_id]))?;
                self.audit(me, "admin", ip, &format!("잠금 해제: 사용자 #{user_id}"));
                Ok(ApiResponse::Ok)
            }
            AdminRequest::ReleaseDevice { user_id, side } => {
                let dev: Option<i64> = self.db.with(|db| db.query_row("SELECT id FROM devices WHERE user_id=?1 AND side=?2", params![user_id, side.as_str()], |r| r.get(0)).optional())?;
                // a released (possibly lost) PC must stop receiving tokens and clipboard
                self.end_user_sessions(c, user_id, "관리자가 PC 등록을 해제했습니다").await?;
                if let Some(d) = dev {
                    if self.is_local(&side) {
                        self.hub.drop_device(d);
                    } else {
                        self.peer(&side)?.drop_device(d).await?;
                    }
                }
                self.db.with(|db| db.execute("DELETE FROM devices WHERE user_id=?1 AND side=?2", params![user_id, side.as_str()]))?;
                self.audit(me, "admin", ip, &format!("기기 해제: 사용자 #{user_id} {}", self.topo.name(&side)));
                Ok(ApiResponse::Ok)
            }
            AdminRequest::ListDepts => self
                .db
                .with(|db| {
                    let mut st = db.prepare("SELECT id, name FROM depts ORDER BY name")?;
                    let v = st.query_map([], |r| Ok(Dept { id: r.get(0)?, name: r.get(1)? }))?.collect::<rusqlite::Result<Vec<_>>>()?;
                    Ok(v)
                })
                .map(ApiResponse::Depts),
            AdminRequest::UpsertDept { id, name } => {
                let name = name.trim().to_string();
                if name.is_empty() {
                    return Err(ApiError::bad("부서 이름을 입력하세요"));
                }
                let id = self
                    .db
                    .with(|db| match id {
                        Some(id) => db.execute("UPDATE depts SET name=?2 WHERE id=?1", params![id, name]).map(|_| id),
                        None => db.execute("INSERT INTO depts(name) VALUES(?1)", [&name]).map(|_| db.last_insert_rowid()),
                    })
                    .map_err(|e| if e.message.contains("UNIQUE") { ApiError::bad("이미 있는 부서입니다") } else { e })?;
                self.audit(me, "admin", ip, &format!("부서 저장: {name}"));
                Ok(ApiResponse::Id(id))
            }
            AdminRequest::GetPolicy => Ok(ApiResponse::Policy(self.db.policy()?)),
            AdminRequest::SetPolicy { policy } => self.set_policy(&policy, Some(c)).await.map(|_| ApiResponse::Ok),
            AdminRequest::ListLimitOverrides => self.list_limit_overrides().map(ApiResponse::LimitOverrides),
            AdminRequest::SetLimitOverride { scope, limits } => {
                self.set_limit_override(scope, limits)?;
                self.audit(me, "admin", ip, &format!("용량 한도 변경: {scope:?} → {limits:?}"));
                Ok(ApiResponse::Ok)
            }
            AdminRequest::ListRoutePolicies => Ok(ApiResponse::RoutePolicies(self.route_policies()?)),
            AdminRequest::SetRoutePolicy { mut policy } => {
                let clean = |v: &[String]| v.iter().map(|e| e.trim().trim_start_matches('.').to_ascii_lowercase()).filter(|e| !e.is_empty()).collect::<Vec<_>>();
                for r in &mut policy.approval_rules {
                    r.exts = clean(&r.exts);
                }
                policy.blocked_exts = policy.blocked_exts.as_deref().map(clean);
                policy.allowed_exts = policy.allowed_exts.as_deref().map(clean);
                if policy.limits.is_some_and(|l| l.daily_bytes == 0 || l.per_file_bytes == 0) {
                    return Err(ApiError::bad("하루 한도와 파일 1개 한도는 0보다 커야 합니다"));
                }
                self.route_policy(&policy.route)?;
                let old = self.route_policies()?.into_iter().find(|p| p.route == policy.route).expect("checked route");
                self.set_route_policy(&policy)?;
                let diff = route_diff(&old, &policy);
                self.audit(me, "policy_change", ip, &format!("통로 정책 {}: {diff}", policy.route.label(&self.topo)));
                self.push_everyone(Event::PolicyChanged { policy: self.db.policy()? }).await;
                Ok(ApiResponse::Ok)
            }
            AdminRequest::QueryAudit { query } => self.query_audit(&query).map(ApiResponse::Audit),
            AdminRequest::ListSessions => self.list_sessions().await.map(ApiResponse::Sessions),
            AdminRequest::KillSession { session_id } => {
                let row: Option<(i64, String)> = self
                    .db
                    .with(|db| db.query_row("SELECT s.user_id, u.username FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.id=?1 AND s.ended_at IS NULL", [session_id], |r| Ok((r.get(0)?, r.get(1)?))).optional())?;
                let (uid, username) = row.ok_or_else(|| ApiError::new(ErrorCode::NotFound, "이미 끝난 세션입니다"))?;
                let target = Caller { session_id, user_id: uid, username: username.clone(), role: Role::User, side: c.side.clone(), ip: c.ip.clone() };
                self.logout(&target, "관리자가 세션을 종료했습니다").await?;
                self.audit(me, "admin", ip, &format!("세션 강제 종료: {username}"));
                Ok(ApiResponse::Ok)
            }
        }
    }

    /// Ends every open session of `user_id` the same way a logout does (devices get SessionEnded).
    async fn end_user_sessions(&self, c: &Caller, user_id: i64, reason: &str) -> Result<(), ApiError> {
        let sessions: Vec<i64> = self.db.with(|db| {
            let mut st = db.prepare("SELECT id FROM sessions WHERE user_id=?1 AND ended_at IS NULL")?;
            let v = st.query_map([user_id], |r| r.get(0))?.collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(v)
        })?;
        let username: String = self.db.with(|db| db.query_row("SELECT username FROM users WHERE id=?1", [user_id], |r| r.get(0)))?;
        for sid in sessions {
            let target = Caller { session_id: sid, user_id, username: username.clone(), role: Role::User, side: c.side.clone(), ip: c.ip.clone() };
            self.logout(&target, reason).await?;
        }
        Ok(())
    }

    fn list_users(&self) -> Result<Vec<UserInfo>, ApiError> {
        let mut users: Vec<UserInfo> = self.db.with(|db| {
            let mut st = db.prepare("SELECT id, username, name, dept_id, role, approver_id, locked, networks FROM users ORDER BY username")?;
            let v = st
                .query_map([], |r| {
                    Ok(UserInfo {
                        id: r.get(0)?,
                        username: r.get(1)?,
                        name: r.get(2)?,
                        dept_id: r.get(3)?,
                        role: super::auth::parse_role(&r.get::<_, String>(4)?),
                        approver_id: r.get(5)?,
                        locked: r.get(6)?,
                        devices: vec![],
                        networks: serde_json::from_str(&r.get::<_, String>(7)?).unwrap_or_default(),
                    })
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(v)
        })?;
        for u in &mut users {
            u.devices = self.devices_of(u.id)?.into_iter().map(|(s, _)| s).collect();
            u.devices.sort();
        }
        Ok(users)
    }

    fn list_limit_overrides(&self) -> Result<Vec<LimitOverride>, ApiError> {
        self.db.with(|db| {
            let mut st = db.prepare(
                "SELECT o.scope, o.scope_id, o.daily_bytes, o.per_file_bytes, COALESCE(d.name, u.name || ' (' || u.username || ')', '?')
                 FROM limit_overrides o LEFT JOIN depts d ON o.scope='dept' AND d.id=o.scope_id LEFT JOIN users u ON o.scope='user' AND u.id=o.scope_id
                 ORDER BY o.scope, o.scope_id",
            )?;
            let v = st
                .query_map([], |r| {
                    let id: i64 = r.get(1)?;
                    let scope = if r.get::<_, String>(0)? == "dept" { LimitScope::Dept(id) } else { LimitScope::User(id) };
                    Ok(LimitOverride { scope, label: r.get(4)?, limits: Limits { daily_bytes: r.get::<_, i64>(2)? as u64, per_file_bytes: r.get::<_, i64>(3)? as u64 } })
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(v)
        })
    }

    fn query_audit(&self, q: &AuditQuery) -> Result<Vec<AuditRow>, ApiError> {
        let limit = q.limit.unwrap_or(1000).min(20000);
        self.db.with(|db| {
            let mut st = db.prepare(
                "SELECT at, username, kind, ip, detail FROM audit
                 WHERE (?1 IS NULL OR at>=?1) AND (?2 IS NULL OR at<=?2) AND (?3 IS NULL OR username=?3) AND (?4 IS NULL OR kind=?4)
                 ORDER BY id DESC LIMIT ?5",
            )?;
            let v = st
                .query_map(params![q.from, q.to, q.user.as_deref().filter(|s| !s.is_empty()), q.kind.as_deref().filter(|s| !s.is_empty()), limit], |r| {
                    Ok(AuditRow { at: r.get(0)?, user: r.get(1)?, kind: r.get(2)?, ip: r.get(3)?, detail: r.get(4)? })
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(v)
        })
    }

    async fn list_sessions(&self) -> Result<Vec<SessionInfo>, ApiError> {
        let mut live: Vec<(NetId, Vec<i64>)> = vec![(self.net.clone(), self.hub.online())];
        for (n, p) in &self.peers {
            live.push((n.clone(), p.online_devices().await.unwrap_or_default()));
        }
        let rows: Vec<(i64, i64, String, String, i64, i64)> = self.db.with(|db| {
            let mut st = db.prepare("SELECT s.id, s.user_id, u.username, u.name, s.created_at, s.last_seen FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.ended_at IS NULL ORDER BY s.last_seen DESC")?;
            let v = st.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?)))?.collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(v)
        })?;
        rows.into_iter()
            .map(|(id, uid, username, name, created_at, last_seen)| {
                let mut online: Vec<Side> = self.devices_of(uid)?.into_iter().filter(|(s, d)| live.iter().any(|(n, ids)| n == s && ids.contains(d))).map(|(s, _)| s).collect();
                online.sort();
                Ok(SessionInfo { id, username, name, created_at, last_seen, online })
            })
            .collect()
    }
}

/// "field: old → new" for each changed field of a route policy.
fn route_diff(old: &RoutePolicy, new: &RoutePolicy) -> String {
    let a = serde_json::to_value(old).unwrap_or_default();
    let b = serde_json::to_value(new).unwrap_or_default();
    let (Some(a), Some(b)) = (a.as_object(), b.as_object()) else { return String::new() };
    let v: Vec<String> = b.iter().filter(|(k, v)| a.get(*k) != Some(*v)).map(|(k, v)| format!("{k}: {} → {v}", a.get(k).cloned().unwrap_or_default())).collect();
    if v.is_empty() {
        "변경 없음".into()
    } else {
        v.join(", ")
    }
}

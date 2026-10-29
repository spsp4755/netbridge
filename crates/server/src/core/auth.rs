use super::{Caller, Core};
use argon2::password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use netbridge_proto::*;
use rusqlite::{params, OptionalExtension};

pub fn hash_password(pw: &str) -> String {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default().hash_password(pw.as_bytes(), &salt).expect("argon2").to_string()
}

pub fn verify_password(pw: &str, hash: &str) -> bool {
    PasswordHash::new(hash).map(|h| Argon2::default().verify_password(pw.as_bytes(), &h).is_ok()).unwrap_or(false)
}

pub fn check_password_policy(pw: &str, p: &Policy) -> Result<(), ApiError> {
    if pw.chars().count() < p.pw_min_len as usize {
        return Err(ApiError::bad(format!("비밀번호는 {}자 이상이어야 합니다", p.pw_min_len)));
    }
    if p.pw_require_mix {
        let letter = pw.chars().any(|c| c.is_ascii_alphabetic());
        let digit = pw.chars().any(|c| c.is_ascii_digit());
        let special = pw.chars().any(|c| !c.is_ascii_alphanumeric());
        if !(letter && digit && special) {
            return Err(ApiError::bad("비밀번호는 영문, 숫자, 특수문자를 모두 포함해야 합니다"));
        }
    }
    Ok(())
}

const BAD_LOGIN: &str = "아이디 또는 비밀번호가 올바르지 않습니다";

impl Core {
    pub fn create_user(&self, u: &UserInput) -> Result<i64, ApiError> {
        let username = u.username.trim();
        if username.is_empty() || u.name.trim().is_empty() {
            return Err(ApiError::bad("아이디와 이름을 입력하세요"));
        }
        let pw = u.password.as_deref().ok_or_else(|| ApiError::bad("초기 비밀번호를 입력하세요"))?;
        check_password_policy(pw, &self.db.policy()?)?;
        let hash = hash_password(pw);
        let now = self.clock.now();
        let role = role_str(u.role);
        self.db.with(|c| {
            c.execute(
                "INSERT INTO users(username,name,dept_id,role,approver_id,pw_hash,pw_changed_at,must_change) VALUES(?1,?2,?3,?4,?5,?6,?7,1)",
                params![username, u.name.trim(), u.dept_id, role, u.approver_id, hash, now],
            )?;
            Ok(c.last_insert_rowid())
        })
        .map_err(|e| if e.message.contains("UNIQUE") { ApiError::bad("이미 있는 아이디입니다") } else { e })
    }

    pub fn clear_must_change(&self, user_id: i64) -> Result<(), ApiError> {
        self.db.with(|c| c.execute("UPDATE users SET must_change=0 WHERE id=?1", [user_id]).map(|_| ()))
    }

    pub(super) async fn login(&self, ctx: &super::CallCtx, username: &str, password: &str, device_key: Option<&str>) -> ApiResult {
        let policy = self.db.policy()?;
        let row = self.db.with(|c| {
            c.query_row("SELECT id, pw_hash, locked, fail_count FROM users WHERE username=?1", [username.trim()], |r| {
                Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?, r.get::<_, bool>(2)?, r.get::<_, i64>(3)?))
            })
            .optional()
        })?;
        let Some((uid, hash, locked, fails)) = row else {
            self.audit(None, "login_fail", Some(&ctx.client_ip), &format!("없는 아이디: {username}"));
            return Err(ApiError::new(ErrorCode::Unauthorized, BAD_LOGIN));
        };
        let user = Some((uid, username));
        if locked {
            return Err(ApiError::new(ErrorCode::AccountLocked, "계정이 잠겼습니다. 관리자에게 잠금 해제를 요청하세요"));
        }
        if !verify_password(password, &hash) {
            let fails = fails + 1;
            let lock = fails >= policy.login_fail_lock as i64;
            self.db.with(|c| c.execute("UPDATE users SET fail_count=?2, locked=?3 WHERE id=?1", params![uid, fails, lock]))?;
            self.audit(user, "login_fail", Some(&ctx.client_ip), &format!("{}회 실패", fails));
            return Err(if lock {
                ApiError::new(ErrorCode::AccountLocked, "로그인 실패가 반복되어 계정이 잠겼습니다. 관리자에게 잠금 해제를 요청하세요")
            } else {
                ApiError::new(ErrorCode::Unauthorized, format!("{BAD_LOGIN} ({fails}/{}회)", policy.login_fail_lock))
            });
        }
        self.db.with(|c| c.execute("UPDATE users SET fail_count=0 WHERE id=?1", [uid]))?;

        let key = self.bind_device(uid, ctx.side, device_key)?;
        let (session_id, token, created) = self.open_session(uid)?;
        let caller = Caller { session_id, user_id: uid, username: username.trim().to_string(), role: Role::User, side: ctx.side, ip: ctx.client_ip.clone() };
        let me = self.me(&caller)?;
        if created {
            if let Some((side, dev)) = self.devices_of(uid)?.into_iter().find(|(s, _)| *s != ctx.side) {
                let peer_me = Me { side, client_ip: String::new(), ..me.clone() };
                self.push(side, dev, Event::SessionStarted { token: token.clone(), me: peer_me }).await;
            }
        }
        self.audit(user, "login", Some(&ctx.client_ip), &format!("{} 로그인", ctx.side.label()));
        Ok(ApiResponse::LoggedIn { token, device_key: key, me })
    }

    /// Registers this PC for the user on first login; afterwards the stored key must match.
    fn bind_device(&self, uid: i64, side: Side, key: Option<&str>) -> Result<String, ApiError> {
        let existing = self.db.with(|c| {
            c.query_row("SELECT key_hash FROM devices WHERE user_id=?1 AND side=?2", params![uid, side.as_str()], |r| r.get::<_, String>(0)).optional()
        })?;
        match existing {
            Some(h) => match key {
                Some(k) if sha(k) == h => Ok(k.to_string()),
                _ => Err(ApiError::new(ErrorCode::DeviceMismatch, "등록된 PC가 아닙니다. 관리자에게 기기 해제를 요청하세요")),
            },
            None => {
                let k = random_hex(32);
                let now = self.clock.now();
                self.db.with(|c| c.execute("INSERT INTO devices(user_id,side,key_hash,created_at) VALUES(?1,?2,?3,?4)", params![uid, side.as_str(), sha(&k), now]))?;
                Ok(k)
            }
        }
    }

    pub(super) fn unlock(&self, c: &Caller, password: &str) -> ApiResult {
        let hash = self.db.with(|db| db.query_row("SELECT pw_hash FROM users WHERE id=?1", [c.user_id], |r| r.get::<_, String>(0)))?;
        if verify_password(password, &hash) {
            Ok(ApiResponse::Ok)
        } else {
            self.audit(Some((c.user_id, &c.username)), "unlock_fail", Some(&c.ip), "화면 잠금 해제 실패");
            Err(ApiError::new(ErrorCode::Unauthorized, "비밀번호가 올바르지 않습니다"))
        }
    }

    pub(super) fn change_password(&self, c: &Caller, old: &str, new: &str) -> ApiResult {
        let hash = self.db.with(|db| db.query_row("SELECT pw_hash FROM users WHERE id=?1", [c.user_id], |r| r.get::<_, String>(0)))?;
        if !verify_password(old, &hash) {
            return Err(ApiError::new(ErrorCode::Unauthorized, "현재 비밀번호가 올바르지 않습니다"));
        }
        if old == new {
            return Err(ApiError::bad("이전과 다른 비밀번호를 입력하세요"));
        }
        check_password_policy(new, &self.db.policy()?)?;
        let now = self.clock.now();
        self.db.with(|db| db.execute("UPDATE users SET pw_hash=?2, pw_changed_at=?3, must_change=0 WHERE id=?1", params![c.user_id, hash_password(new), now]))?;
        self.audit(Some((c.user_id, &c.username)), "password_change", Some(&c.ip), "비밀번호 변경");
        Ok(ApiResponse::Ok)
    }

    pub fn me(&self, c: &Caller) -> Result<Me, ApiError> {
        let policy = self.db.policy()?;
        let now = self.clock.now();
        let (name, dept, role, must, changed) = self.db.with(|db| {
            db.query_row(
                "SELECT u.name, d.name, u.role, u.must_change, u.pw_changed_at FROM users u LEFT JOIN depts d ON d.id=u.dept_id WHERE u.id=?1",
                [c.user_id],
                |r| Ok((r.get::<_, String>(0)?, r.get::<_, Option<String>>(1)?, r.get::<_, String>(2)?, r.get::<_, bool>(3)?, r.get::<_, i64>(4)?)),
            )
        })?;
        let expired = policy.pw_max_age_days.is_some_and(|d| now - changed > d as i64 * 86400);
        Ok(Me {
            user_id: c.user_id,
            username: c.username.clone(),
            name,
            dept,
            role: parse_role(&role),
            side: c.side,
            client_ip: c.ip.clone(),
            policy,
            must_change_password: must || expired,
        })
    }
}

pub fn role_str(r: Role) -> &'static str {
    match r {
        Role::User => "user",
        Role::Admin => "admin",
    }
}

pub fn parse_role(s: &str) -> Role {
    if s == "admin" { Role::Admin } else { Role::User }
}

pub fn sha(s: &str) -> String {
    use sha2::Digest;
    hex::encode(sha2::Sha256::digest(s.as_bytes()))
}

pub fn random_hex(bytes: usize) -> String {
    use rand::RngCore;
    let mut b = vec![0u8; bytes];
    rand::rngs::OsRng.fill_bytes(&mut b);
    hex::encode(b)
}

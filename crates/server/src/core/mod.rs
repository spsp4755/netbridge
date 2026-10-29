mod auth;
mod limits;
mod session;
mod transfer;
mod approval;
mod clipboard;
mod admin;
mod routes;
pub use session::DeviceRef;

pub use approval::pick_mode;
pub use auth::{hash_password, verify_password};
pub use transfer::{sanitize_name, FileGrant, FileOp};

use crate::db::Db;
use crate::files::Files;
use crate::hub::Hub;
use async_trait::async_trait;
use chrono::{DateTime, FixedOffset, Utc};
use netbridge_proto::*;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

/// Who is calling and from which network.
#[derive(Debug, Clone)]
pub struct CallCtx {
    pub token: Option<String>,
    pub client_ip: String,
    pub side: Side,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ScanResult {
    pub hits: Vec<PiiHit>,
    pub unscannable: bool,
    pub size: u64,
    pub sha256: String,
}

/// Operations on another network's server, driven by the central server.
#[async_trait]
pub trait Peer: Send + Sync {
    /// Size, hash and PII scan of that network's copy of an upload.
    async fn scan(&self, id: i64, name: &str, policy: &Policy) -> Result<ScanResult, ApiError>;
    /// Copies the external copy of a transfer into `dest`.
    async fn fetch_file(&self, id: i64, dest: &Path) -> Result<(), ApiError>;
    async fn push_file(&self, id: i64, src: &Path) -> Result<(), ApiError>;
    async fn delete_file(&self, id: i64) -> Result<(), ApiError>;
    /// True when an external device connection received it.
    async fn push_event(&self, device_id: i64, ev: Event) -> Result<bool, ApiError>;
    async fn online_devices(&self) -> Result<Vec<i64>, ApiError>;
    /// Closes the device's live connections there (after an admin releases it).
    async fn drop_device(&self, device_id: i64) -> Result<(), ApiError>;
    /// Sends that network's copy straight to a neighbor network over their own link.
    async fn forward(&self, id: i64, to: &NetId, sha256: &str) -> Result<(), ApiError>;
}

pub fn scan_bytes(name: &str, bytes: &[u8], policy: &Policy) -> ScanResult {
    use sha2::Digest;
    let sha256 = hex::encode(sha2::Sha256::digest(bytes));
    let size = bytes.len() as u64;
    match netbridge_pii::extract_text(name, bytes) {
        netbridge_pii::Extracted::Text(t) => ScanResult { hits: netbridge_pii::scan_text(&t, &policy.pii_rules), unscannable: false, size, sha256 },
        netbridge_pii::Extracted::Unscannable(_) => ScanResult { hits: vec![], unscannable: true, size, sha256 },
    }
}

/// shortcut: files above this are not read into memory for PII scanning and count as unscannable; stream extraction if large text files must be scanned.
pub const MAX_SCAN_BYTES: u64 = 512 * 1024 * 1024;

/// Scans a file on local disk (see MAX_SCAN_BYTES).
pub fn scan_path(name: &str, path: &Path, policy: &Policy) -> std::io::Result<ScanResult> {
    let size = std::fs::metadata(path)?.len();
    if size > MAX_SCAN_BYTES {
        let files_sha = {
            use sha2::Digest;
            let mut h = sha2::Sha256::new();
            let mut f = std::fs::File::open(path)?;
            std::io::copy(&mut f, &mut h)?;
            hex::encode(h.finalize())
        };
        return Ok(ScanResult { hits: vec![], unscannable: true, size, sha256: files_sha });
    }
    Ok(scan_bytes(name, &std::fs::read(path)?, policy))
}

/// Wall clock that tests can pin and move.
#[derive(Default)]
pub struct Clock(Mutex<Option<i64>>);

impl Clock {
    pub fn now(&self) -> i64 {
        self.0.lock().unwrap().unwrap_or_else(|| Utc::now().timestamp())
    }
    pub fn set(&self, ts: i64) {
        *self.0.lock().unwrap() = Some(ts);
    }
    pub fn advance(&self, secs: i64) {
        let now = self.now();
        self.set(now + secs);
    }
}

pub fn kst() -> FixedOffset {
    FixedOffset::east_opt(9 * 3600).unwrap()
}

pub fn to_kst(ts: i64) -> DateTime<FixedOffset> {
    DateTime::from_timestamp(ts, 0).unwrap_or_default().with_timezone(&kst())
}

/// The central server's business logic. Requests relayed by other networks' servers arrive with their `side`.
pub struct Core {
    pub db: Db,
    pub data_dir: PathBuf,
    pub files: Files,
    pub hub: Hub,
    /// This server's network.
    pub net: NetId,
    pub topo: Topology,
    pub peers: HashMap<NetId, Arc<dyn Peer>>,
    pub clock: Clock,
}

/// The authenticated caller.
#[derive(Debug, Clone)]
pub struct Caller {
    pub session_id: i64,
    pub user_id: i64,
    pub username: String,
    pub role: Role,
    pub side: Side,
    pub ip: String,
}

impl Core {
    pub fn new(db: Db, data_dir: PathBuf, net: NetId, topo: Topology, peers: HashMap<NetId, Arc<dyn Peer>>) -> anyhow::Result<Core> {
        let files = Files::new(data_dir.join("files"))?;
        let core = Core { db, data_dir, files, hub: Hub::default(), net, topo, peers, clock: Clock::default() };
        core.migrate_route_policies().map_err(|e| anyhow::anyhow!("{e}"))?;
        Ok(core)
    }

    /// The original layout: this server is 업무망 (internal), `peer` is 인터넷망 (external).
    pub fn two_network(db: Db, data_dir: PathBuf, peer: Arc<dyn Peer>) -> anyhow::Result<Core> {
        Core::new(db, data_dir, NetId::internal(), Topology::legacy(), HashMap::from([(NetId::external(), peer)]))
    }

    pub fn is_local(&self, net: &NetId) -> bool {
        *net == self.net
    }

    pub fn peer(&self, net: &NetId) -> Result<&Arc<dyn Peer>, ApiError> {
        self.peers.get(net).ok_or_else(|| ApiError::new(ErrorCode::LinkDown, format!("{} 연계서버가 설정되어 있지 않습니다", self.topo.name(net))))
    }

    pub fn net_name(&self, net: &NetId) -> String {
        self.topo.name(net)
    }

    pub async fn handle(&self, ctx: CallCtx, req: ApiRequest) -> ApiResult {
        match req {
            ApiRequest::Login { username, password, device_key } => self.login(&ctx, &username, &password, device_key.as_deref()).await,
            other => {
                let caller = self.authenticate(&ctx).await?;
                self.handle_authed(&caller, other).await
            }
        }
    }

    async fn handle_authed(&self, c: &Caller, req: ApiRequest) -> ApiResult {
        match req {
            ApiRequest::Login { .. } => unreachable!(),
            ApiRequest::Logout => self.logout(c, "로그아웃").await.map(|_| ApiResponse::Ok),
            ApiRequest::Unlock { password } => self.unlock(c, &password),
            ApiRequest::ChangePassword { old, new } => self.change_password(c, &old, &new),
            ApiRequest::Me => self.me(c).map(ApiResponse::Me),
            ApiRequest::Usage { to } => {
                let p = self.user_route(c, &to)?;
                Ok(ApiResponse::Usage(Usage { limits: self.effective_limits(c.user_id, &p)?, used_today: self.used_today(c.user_id, &p.route)? }))
            }
            ApiRequest::CreateTransfers { to, files, reason } => self.create_transfers(c, &to, &files, &reason).map(ApiResponse::Ids),
            ApiRequest::CompleteUpload { id } => self.complete_upload(c, id).await.map(ApiResponse::Transfer),
            ApiRequest::ListOutgoing => self.list_outgoing(c).map(ApiResponse::Transfers),
            ApiRequest::ListIncoming => self.list_incoming(c).map(ApiResponse::Transfers),
            ApiRequest::MarkDownloaded { id } => self.mark_downloaded(c, id).map(|_| ApiResponse::Ok),
            ApiRequest::SubmitForApproval { id, reason } => self.submit_for_approval(c, id, &reason).await.map(ApiResponse::Transfer),
            ApiRequest::ListApprovals => self.list_approvals(c).map(ApiResponse::Approvals),
            ApiRequest::Decide { approval_id, approve, comment } => self.decide(c, approval_id, approve, comment).await.map(|_| ApiResponse::Ok),
            ApiRequest::GetDelegation => self.get_delegation(c.user_id).map(ApiResponse::Delegation),
            ApiRequest::SetDelegation { proxy_username, from, to } => self.set_delegation(c, &proxy_username, from, to).map(|_| ApiResponse::Ok),
            ApiRequest::ClearDelegation => self.clear_delegation(c).map(|_| ApiResponse::Ok),
            ApiRequest::Clipboard { to, text } => self.clipboard(c, &to, &text).await,
            ApiRequest::Admin { req } => self.admin(c, req).await,
        }
    }

    /// Sends an event to a device on any network; true when it was delivered.
    pub async fn push(&self, side: &NetId, device_id: i64, ev: Event) -> bool {
        if self.is_local(side) {
            return self.hub.push(device_id, ev);
        }
        match self.peers.get(side) {
            Some(p) => p.push_event(device_id, ev).await.unwrap_or(false),
            None => false,
        }
    }

    /// Pushes to every live device on every network.
    pub async fn push_everyone(&self, ev: Event) {
        for d in self.hub.online() {
            self.hub.push(d, ev.clone());
        }
        for p in self.peers.values() {
            for d in p.online_devices().await.unwrap_or_default() {
                let _ = p.push_event(d, ev.clone()).await;
            }
        }
    }

    /// Removes a transfer's payload from the server of `net`.
    pub async fn remove_at(&self, net: &NetId, id: i64) {
        if self.is_local(net) {
            self.files.remove(id);
        } else if let Ok(p) = self.peer(net) {
            let _ = p.delete_file(id).await;
        }
    }

    /// Pushes to every registered device of the user.
    pub async fn push_user(&self, user_id: i64, ev: Event) {
        for (side, id) in self.devices_of(user_id).unwrap_or_default() {
            self.push(&side, id, ev.clone()).await;
        }
    }

    pub fn devices_of(&self, user_id: i64) -> Result<Vec<(Side, i64)>, ApiError> {
        self.db.with(|c| {
            let mut st = c.prepare("SELECT side, id FROM devices WHERE user_id=?1")?;
            let rows = st.query_map([user_id], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))?;
            Ok(rows.filter_map(|r| r.ok()).map(|(s, id)| (NetId(s), id)).collect())
        })
    }

    pub fn audit(&self, user: Option<(i64, &str)>, kind: &str, ip: Option<&str>, detail: &str) {
        let now = self.clock.now();
        let _ = self.db.with(|c| {
            c.execute(
                "INSERT INTO audit(at,user_id,username,kind,ip,detail) VALUES(?1,?2,?3,?4,?5,?6)",
                rusqlite::params![now, user.map(|u| u.0), user.map(|u| u.1), kind, ip, detail],
            )
        });
    }

    pub fn store_policy(&self, p: &Policy) -> Result<(), ApiError> {
        self.db.set_setting("policy", &serde_json::to_string(p).map_err(ApiError::internal)?)
    }
}

/// Enum <-> TEXT column via its serde name.
pub fn enc<T: serde::Serialize>(v: &T) -> String {
    serde_json::to_string(v).unwrap_or_default().trim_matches('"').to_string()
}

pub fn dec<T: serde::de::DeserializeOwned>(s: &str) -> rusqlite::Result<T> {
    serde_json::from_str(&format!("\"{s}\"")).map_err(|e| rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(e)))
}

impl Core {
    /// Notice to every admin's devices.
    pub async fn notify_admins(&self, message: &str) {
        let admins: Vec<i64> = self
            .db
            .with(|c| {
                let mut st = c.prepare("SELECT id FROM users WHERE role='admin'")?;
                let v = st.query_map([], |r| r.get(0))?.filter_map(|r| r.ok()).collect();
                Ok(v)
            })
            .unwrap_or_default();
        for a in admins {
            self.push_user(a, Event::Notice { message: message.to_string() }).await;
        }
    }
}

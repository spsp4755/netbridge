#![allow(dead_code)]
use async_trait::async_trait;
use netbridge_proto::*;
use netbridge_server::core::{CallCtx, Core, Peer, ScanResult};
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::{Arc, Mutex};

/// In-memory stand-in for the external server.
#[derive(Default)]
pub struct FakePeer {
    pub pushed: Mutex<Vec<(i64, Event)>>,
    pub online: Mutex<HashSet<i64>>,
    pub files: Mutex<HashMap<i64, Vec<u8>>>,
    pub fetches: std::sync::atomic::AtomicUsize,
    pub dropped: Mutex<Vec<i64>>,
    /// Other fake nodes reachable over a direct node-to-node link.
    pub neighbors: Mutex<HashMap<NetId, Arc<FakePeer>>>,
    pub forwards: Mutex<Vec<(i64, NetId)>>,
}

#[async_trait]
impl Peer for FakePeer {
    async fn scan(&self, id: i64, name: &str, policy: &Policy) -> Result<ScanResult, ApiError> {
        // a real scan crosses the link; let concurrent callers interleave here
        tokio::task::yield_now().await;
        let bytes = self.files.lock().unwrap().get(&id).cloned().ok_or_else(|| ApiError::bad("no file"))?;
        Ok(netbridge_server::core::scan_bytes(name, &bytes, policy))
    }
    async fn fetch_file(&self, id: i64, dest: &Path) -> Result<(), ApiError> {
        self.fetches.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        // long enough for a concurrent second delivery to overlap
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let bytes = self.files.lock().unwrap().get(&id).cloned().ok_or_else(|| ApiError::bad("no file"))?;
        std::fs::write(dest, bytes).map_err(ApiError::internal)
    }
    async fn push_file(&self, id: i64, src: &Path) -> Result<(), ApiError> {
        let bytes = std::fs::read(src).map_err(ApiError::internal)?;
        self.files.lock().unwrap().insert(id, bytes);
        Ok(())
    }
    async fn delete_file(&self, id: i64) -> Result<(), ApiError> {
        self.files.lock().unwrap().remove(&id);
        Ok(())
    }
    async fn push_event(&self, device_id: i64, ev: Event) -> Result<bool, ApiError> {
        let online = self.online.lock().unwrap().contains(&device_id);
        self.pushed.lock().unwrap().push((device_id, ev));
        Ok(online)
    }
    async fn drop_device(&self, device_id: i64) -> Result<(), ApiError> {
        self.dropped.lock().unwrap().push(device_id);
        self.online.lock().unwrap().remove(&device_id);
        Ok(())
    }
    async fn online_devices(&self) -> Result<Vec<i64>, ApiError> {
        Ok(self.online.lock().unwrap().iter().copied().collect())
    }
    async fn forward(&self, id: i64, to: &NetId, sha256: &str) -> Result<(), ApiError> {
        let n = self.neighbors.lock().unwrap().get(to).cloned().ok_or_else(|| ApiError::new(ErrorCode::LinkDown, "no neighbor"))?;
        let bytes = self.files.lock().unwrap().get(&id).cloned().ok_or_else(|| ApiError::bad("no file"))?;
        if sha_hex(&bytes) != sha256 {
            return Err(ApiError::new(ErrorCode::Conflict, "hash"));
        }
        n.files.lock().unwrap().insert(id, bytes);
        self.forwards.lock().unwrap().push((id, to.clone()));
        Ok(())
    }
}

/// The other network of the legacy two-network layout.
pub fn other(side: &NetId) -> NetId {
    if *side == NetId::internal() { NetId::external() } else { NetId::internal() }
}

pub struct Kit {
    pub core: Arc<Core>,
    pub peer: Arc<FakePeer>,
    pub _dir: tempfile::TempDir,
}

pub fn kit() -> Kit {
    let dir = tempfile::tempdir().unwrap();
    let peer = Arc::new(FakePeer::default());
    let core = Arc::new(Core::two_network(netbridge_server::db::Db::open_memory().unwrap(), dir.path().to_path_buf(), peer.clone()).unwrap());
    core.clock.set(1_800_000_000); // 2027-01-15T08:00:00Z
    Kit { core, peer, _dir: dir }
}

/// Four networks A–D, central server on B; routes A-B, B-C, B-D, C-D (C and D also linked directly).
pub struct Kit4 {
    pub core: Arc<Core>,
    pub peers: HashMap<NetId, Arc<FakePeer>>,
    pub _dir: tempfile::TempDir,
}

pub fn net(s: &str) -> NetId {
    NetId::new(s)
}

pub fn kit4() -> Kit4 {
    let dir = tempfile::tempdir().unwrap();
    let ids = ["A", "B", "C", "D"];
    let networks = ids.iter().map(|i| NetInfo { id: net(i), name: format!("{i}망") }).collect();
    let mut routes = vec![];
    for (a, b) in [("A", "B"), ("B", "C"), ("B", "D"), ("C", "D")] {
        routes.push(Route::new(net(a), net(b)));
        routes.push(Route::new(net(b), net(a)));
    }
    let topo = Topology { hub: net("B"), networks, routes };
    let peers: HashMap<NetId, Arc<FakePeer>> = ["A", "C", "D"].iter().map(|i| (net(i), Arc::new(FakePeer::default()))).collect();
    peers[&net("C")].neighbors.lock().unwrap().insert(net("D"), peers[&net("D")].clone());
    peers[&net("D")].neighbors.lock().unwrap().insert(net("C"), peers[&net("C")].clone());
    let dyn_peers: HashMap<NetId, Arc<dyn Peer>> = peers.iter().map(|(k, v)| (k.clone(), v.clone() as Arc<dyn Peer>)).collect();
    let core = Arc::new(Core::new(netbridge_server::db::Db::open_memory().unwrap(), dir.path().to_path_buf(), net("B"), topo, dyn_peers).unwrap());
    core.clock.set(1_800_000_000);
    Kit4 { core, peers, _dir: dir }
}

impl Kit4 {
    pub fn user(&self, username: &str, approver: Option<i64>, networks: &[&str]) -> i64 {
        let id = self
            .core
            .create_user(&UserInput {
                id: None,
                username: username.into(),
                name: username.into(),
                dept_id: None,
                role: Role::User,
                approver_id: approver,
                password: Some(PW.into()),
                networks: networks.iter().map(|n| net(n)).collect(),
            })
            .unwrap();
        self.core.clear_must_change(id).unwrap();
        id
    }

    pub async fn call(&self, side: &str, token: Option<&str>, req: ApiRequest) -> ApiResult {
        self.core.handle(CallCtx { token: token.map(String::from), client_ip: format!("10.0.{}.1", side.as_bytes()[0]), side: net(side) }, req).await
    }

    pub async fn login(&self, side: &str, username: &str) -> Result<String, ApiError> {
        match self.call(side, None, ApiRequest::Login { username: username.into(), password: PW.into(), device_key: None }).await? {
            ApiResponse::LoggedIn { token, .. } => Ok(token),
            other => panic!("{other:?}"),
        }
    }

    /// Creates, uploads (into that network's store) and completes one file.
    pub async fn send(&self, from: &str, to: &str, token: &str, name: &str, bytes: &[u8]) -> Result<TransferInfo, ApiError> {
        let files = vec![FileMeta { name: name.into(), size: bytes.len() as u64, sha256: sha_hex(bytes) }];
        let id = match self.call(from, Some(token), ApiRequest::CreateTransfers { to: net(to), files, reason: "업무".into() }).await? {
            ApiResponse::Ids(ids) => ids[0],
            r => panic!("{r:?}"),
        };
        if net(from) == self.core.net {
            self.core.files.write_at(id, 0, bytes).unwrap();
        } else {
            self.peers[&net(from)].files.lock().unwrap().insert(id, bytes.to_vec());
        }
        match self.call(from, Some(token), ApiRequest::CompleteUpload { id }).await? {
            ApiResponse::Transfer(t) => Ok(t),
            r => panic!("{r:?}"),
        }
    }

    pub fn post_rule(&self) {
        for mut p in self.core.route_policies().unwrap() {
            p.approval_rules = vec![ApprovalRule { order: 1, max_size: None, exts: vec![], dept_id: None, mode: ApprovalMode::Post }];
            self.core.set_route_policy(&p).unwrap();
        }
    }
}

pub const PW: &str = "Passw0rd!";

pub fn ctx(side: Side, token: Option<&str>) -> CallCtx {
    CallCtx { token: token.map(String::from), client_ip: format!("10.{}.0.5", if side == NetId::external() { 1 } else { 2 }), side }
}

impl Kit {
    pub fn user(&self, username: &str, role: Role, approver: Option<i64>) -> i64 {
        let id = self
            .core
            .create_user(&UserInput { id: None, username: username.into(), name: format!("{username} 님"), dept_id: None, role, approver_id: approver, password: Some(PW.into()), networks: vec![] })
            .unwrap();
        self.core.clear_must_change(id).unwrap();
        id
    }

    pub async fn call(&self, side: Side, token: Option<&str>, req: ApiRequest) -> ApiResult {
        self.core.handle(ctx(side, token), req).await
    }

    /// Logs in and returns (token, device_key).
    pub async fn login(&self, side: Side, username: &str, device_key: Option<&str>) -> (String, String) {
        match self.call(side, None, ApiRequest::Login { username: username.into(), password: PW.into(), device_key: device_key.map(String::from) }).await {
            Ok(ApiResponse::LoggedIn { token, device_key, .. }) => (token, device_key),
            other => panic!("login failed: {other:?}"),
        }
    }

    pub fn device_id(&self, key: &str) -> i64 {
        self.core.device_auth(key).unwrap().device_id
    }

    pub fn pushed_external(&self) -> Vec<(i64, Event)> {
        self.peer.pushed.lock().unwrap().clone()
    }
}

impl Kit {
    /// Inserts a transfer row directly (for usage accounting tests).
    pub fn insert_transfer(&self, uid: i64, size: u64, state: &str, at: i64) {
        self.core
            .db
            .with(|c| {
                c.execute(
                    "INSERT INTO transfers(user_id,direction,from_net,to_net,file_name,size,sha256,reason,state,sender_ip,created_at) VALUES(?1,'','external','internal','f.txt',?2,'',?3,?4,'1.1.1.1',?5)",
                    rusqlite::params![uid, size as i64, "r", state, at],
                )
            })
            .unwrap();
    }

    pub fn dept(&self, name: &str) -> i64 {
        self.core.db.with(|c| { c.execute("INSERT INTO depts(name) VALUES(?1)", [name])?; Ok(c.last_insert_rowid()) }).unwrap()
    }
}

pub fn sha_hex(b: &[u8]) -> String {
    use sha2::Digest;
    hex::encode(sha2::Sha256::digest(b))
}

impl Kit {
    pub async fn create(&self, side: Side, token: &str, name: &str, bytes: &[u8]) -> ApiResult {
        self.create_with(side, token, name, bytes, "").await
    }

    pub async fn create_with(&self, side: Side, token: &str, name: &str, bytes: &[u8], reason: &str) -> ApiResult {
        let files = vec![FileMeta { name: name.into(), size: bytes.len() as u64, sha256: sha_hex(bytes) }];
        let to = other(&side);
        self.call(side, Some(token), ApiRequest::CreateTransfers { to, files, reason: reason.into() }).await
    }

    /// Creates, uploads and completes one file from `side`; returns the transfer.
    pub async fn send(&self, side: Side, token: &str, name: &str, bytes: &[u8]) -> Result<TransferInfo, ApiError> {
        self.send_with(side, token, name, bytes, "").await
    }

    pub async fn send_with(&self, side: Side, token: &str, name: &str, bytes: &[u8], reason: &str) -> Result<TransferInfo, ApiError> {
        let id = match self.create_with(side.clone(), token, name, bytes, reason).await? {
            ApiResponse::Ids(ids) => ids[0],
            r => panic!("{r:?}"),
        };
        if side == NetId::internal() {
            self.core.files.write_at(id, 0, bytes).unwrap();
        } else {
            self.peer.files.lock().unwrap().insert(id, bytes.to_vec());
        }
        match self.call(side, Some(token), ApiRequest::CompleteUpload { id }).await? {
            ApiResponse::Transfer(t) => Ok(t),
            r => panic!("{r:?}"),
        }
    }

    pub async fn incoming(&self, side: Side, token: &str) -> Vec<TransferInfo> {
        match self.call(side, Some(token), ApiRequest::ListIncoming).await.unwrap() {
            ApiResponse::Transfers(t) => t,
            r => panic!("{r:?}"),
        }
    }

    pub async fn approvals(&self, side: Side, token: &str) -> Vec<ApprovalItem> {
        match self.call(side, Some(token), ApiRequest::ListApprovals).await.unwrap() {
            ApiResponse::Approvals(a) => a,
            r => panic!("{r:?}"),
        }
    }

    /// Same approval rules on every route.
    pub fn set_rules(&self, rules: Vec<ApprovalRule>) {
        for mut p in self.core.route_policies().unwrap() {
            p.approval_rules = rules.clone();
            self.core.set_route_policy(&p).unwrap();
        }
    }

    /// Approval rules for one route only.
    pub fn set_route_rules(&self, route: Route, rules: Vec<ApprovalRule>) {
        let mut p = self.core.route_policy(&route).unwrap();
        p.approval_rules = rules;
        self.core.set_route_policy(&p).unwrap();
    }

    pub fn ext_in() -> Route {
        Route::new(NetId::external(), NetId::internal())
    }

    pub fn int_ext() -> Route {
        Route::new(NetId::internal(), NetId::external())
    }

    /// a (approver b) logged in on both sides; b logged in on both sides. Returns (a token, b token).
    pub async fn pair(&self) -> (String, String) {
        let b = self.user("b", Role::User, None);
        self.user("a", Role::User, Some(b));
        let (ta, _) = self.login(NetId::external(), "a", None).await;
        self.login(NetId::internal(), "a", None).await;
        let (tb, _) = self.login(NetId::internal(), "b", None).await;
        self.login(NetId::external(), "b", None).await;
        (ta, tb)
    }
}

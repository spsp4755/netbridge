//! Starts a real external and internal server on localhost and drives them through clientcore.
use netbridge_clientcore::net::{sha256_file, Net, NetEvent};
use netbridge_proto::*;
use netbridge_server::config::ServerConfig;
use netbridge_server::server::{start, Running};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;

const PW: &str = "Passw0rd!";

struct Env {
    dir: tempfile::TempDir,
    ext: Running,
    int: Running,
}

impl Env {
    fn ca(&self) -> PathBuf {
        self.dir.path().join("certs/ca.pem")
    }
    fn net(&self, side: Side) -> Arc<Net> {
        let port = if side == NetId::external() { self.ext.app_addr.port() } else { self.int.app_addr.port() };
        Arc::new(Net::new(&format!("https://127.0.0.1:{port}"), &self.ca()).unwrap())
    }
    async fn wait_linked(&self) {
        for _ in 0..100 {
            if self.ext.relay.as_ref().unwrap().link.connected() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("link never came up");
    }
    fn user(&self, username: &str, role: Role, approver: Option<i64>) -> i64 {
        let core = self.int.core.as_ref().unwrap();
        let id = core
            .create_user(&UserInput { id: None, username: username.into(), name: format!("{username} 님"), dept_id: None, role, approver_id: approver, password: Some(PW.into()), networks: vec![] })
            .unwrap();
        core.clear_must_change(id).unwrap();
        id
    }
    fn set_policy(&self, f: impl FnOnce(&mut Policy)) {
        let core = self.int.core.as_ref().unwrap();
        let mut p = core.db.policy().unwrap();
        f(&mut p);
        core.store_policy(&p).unwrap();
    }
}

async fn env() -> Env {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    netbridge_server::certs::gen_certs(&d.join("certs"), &["127.0.0.1".into()], &["127.0.0.1".into()]).unwrap();
    std::fs::write(
        d.join("external.toml"),
        "side = \"external\"\nlisten = \"127.0.0.1:0\"\ndata_dir = \"ext\"\ntls_cert = \"certs/external.pem\"\ntls_key = \"certs/external.key\"\nca_cert = \"certs/ca.pem\"\n[link]\nlisten = \"127.0.0.1:0\"\n",
    )
    .unwrap();
    let ext = start(ServerConfig::load(&d.join("external.toml")).unwrap()).await.unwrap();
    std::fs::write(
        d.join("internal.toml"),
        format!(
            "side = \"internal\"\nlisten = \"127.0.0.1:0\"\ndata_dir = \"int\"\ntls_cert = \"certs/internal.pem\"\ntls_key = \"certs/internal.key\"\nca_cert = \"certs/ca.pem\"\n[link]\nexternal_url = \"https://127.0.0.1:{}\"\nclient_cert = \"certs/link-client.pem\"\nclient_key = \"certs/link-client.key\"\n",
            ext.link_addr.unwrap().port()
        ),
    )
    .unwrap();
    let int = start(ServerConfig::load(&d.join("internal.toml")).unwrap()).await.unwrap();
    let e = Env { dir, ext, int };
    e.wait_linked().await;
    e
}

async fn login(net: &Net, username: &str, key: Option<String>) -> (Me, String) {
    match net.call(ApiRequest::Login { username: username.into(), password: PW.into(), device_key: key }).await.unwrap() {
        ApiResponse::LoggedIn { token, device_key, me } => {
            net.set_token(Some(token));
            (me, device_key)
        }
        r => panic!("{r:?}"),
    }
}

fn events(net: &Arc<Net>, key: &str) -> mpsc::UnboundedReceiver<NetEvent> {
    let (tx, rx) = mpsc::unbounded_channel();
    net.clone().spawn_events(key.to_string(), tx);
    rx
}

async fn next_event(rx: &mut mpsc::UnboundedReceiver<NetEvent>, pred: impl Fn(&NetEvent) -> bool) -> NetEvent {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        match tokio::time::timeout_at(deadline, rx.recv()).await {
            Ok(Some(e)) if pred(&e) => return e,
            Ok(Some(_)) => continue,
            other => panic!("no matching event: {other:?}"),
        }
    }
}

async fn send_file(net: &Net, to: NetId, path: &Path) -> Result<TransferInfo, ApiError> {
    let meta = FileMeta { name: path.file_name().unwrap().to_string_lossy().into(), size: std::fs::metadata(path).unwrap().len(), sha256: sha256_file(path).unwrap() };
    let id = match net.call(ApiRequest::CreateTransfers { to, files: vec![meta], reason: "업무".into() }).await? {
        ApiResponse::Ids(v) => v[0],
        r => panic!("{r:?}"),
    };
    net.upload(id, path, |_| {}).await?;
    match net.call(ApiRequest::CompleteUpload { id }).await? {
        ApiResponse::Transfer(t) => Ok(t),
        r => panic!("{r:?}"),
    }
}

async fn incoming(net: &Net) -> Vec<TransferInfo> {
    match net.call(ApiRequest::ListIncoming).await.unwrap() {
        ApiResponse::Transfers(v) => v,
        r => panic!("{r:?}"),
    }
}

/// a: external + internal PCs; b approves on internal.
async fn setup(e: &Env) -> (Arc<Net>, Arc<Net>, Arc<Net>, String) {
    let b = e.user("b", Role::User, None);
    e.user("a", Role::User, Some(b));
    let a_int = e.net(NetId::internal());
    let (_, ikey) = login(&a_int, "a", None).await;
    a_int.call(ApiRequest::Logout).await.unwrap();
    a_int.set_token(None);
    let a_ext = e.net(NetId::external());
    let b_int = e.net(NetId::internal());
    login(&b_int, "b", None).await;
    (a_ext, a_int, b_int, ikey)
}

#[tokio::test]
async fn full_flow_pre_approval() {
    let e = env().await;
    let (a_ext, a_int, b_int, ikey) = setup(&e).await;
    let mut ev = events(&a_int, &ikey);
    next_event(&mut ev, |x| matches!(x, NetEvent::Connected)).await;

    // logging in on the internet PC logs the internal PC in too
    login(&a_ext, "a", None).await;
    let token = match next_event(&mut ev, |x| matches!(x, NetEvent::Event(Event::SessionStarted { .. }))).await {
        NetEvent::Event(Event::SessionStarted { token, me }) => {
            assert_eq!(me.side, NetId::internal());
            token
        }
        _ => unreachable!(),
    };
    a_int.set_token(Some(token));

    let src = e.dir.path().join("보고서.txt");
    let body: Vec<u8> = (0..3_000_000u32).map(|i| b"abcdefghij"[(i % 10) as usize]).collect();
    std::fs::write(&src, &body).unwrap();
    let t = send_file(&a_ext, NetId::internal(), &src).await.unwrap();
    assert_eq!(t.state, TransferState::Pending);
    assert!(incoming(&a_int).await.is_empty());

    let items = match b_int.call(ApiRequest::ListApprovals).await.unwrap() {
        ApiResponse::Approvals(v) => v,
        r => panic!("{r:?}"),
    };
    b_int.call(ApiRequest::Decide { approval_id: items[0].approval.id, approve: true, comment: None }).await.unwrap();
    next_event(&mut ev, |x| matches!(x, NetEvent::Event(Event::TransferUpdated { transfer }) if transfer.state == TransferState::Available)).await;

    let inc = incoming(&a_int).await;
    assert_eq!(inc.len(), 1);
    let out_dir = e.dir.path().join("받은파일");
    std::fs::create_dir_all(&out_dir).unwrap();
    let saved = a_int.download(&inc[0], &out_dir, |_| {}).await.unwrap();
    assert_eq!(std::fs::read(&saved).unwrap(), body);
    assert_eq!(saved.file_name().unwrap().to_string_lossy(), "보고서.txt");
    a_int.call(ApiRequest::MarkDownloaded { id: inc[0].id }).await.unwrap();
    let inc = incoming(&a_int).await;
    assert_eq!(inc[0].sender_ip, "127.0.0.1");
    assert_eq!(inc[0].receiver_ip.as_deref(), Some("127.0.0.1"));
    // a second download of the same name does not overwrite the first
    let again = a_int.download(&inc[0], &out_dir, |_| {}).await.unwrap();
    assert_ne!(again, saved);
}

#[tokio::test]
async fn post_approval_flow_internal_to_external() {
    let e = env().await;
    let (a_ext, a_int, _b, ikey) = setup(&e).await;
    let core = e.int.core.as_ref().unwrap();
    let mut p = core.route_policy(&Route::new(NetId::internal(), NetId::external())).unwrap();
    p.approval_rules = vec![ApprovalRule { order: 0, max_size: None, exts: vec![], dept_id: None, mode: ApprovalMode::Post }];
    core.set_route_policy(&p).unwrap();
    login(&a_int, "a", Some(ikey)).await;
    login(&a_ext, "a", None).await;
    let src = e.dir.path().join("out.csv");
    std::fs::write(&src, "a,b\n1,2\n").unwrap();
    let t = send_file(&a_int, NetId::external(), &src).await.unwrap();
    assert_eq!((t.state, t.mode), (TransferState::Available, Some(ApprovalMode::Post)));
    let inc = incoming(&a_ext).await;
    let saved = a_ext.download(&inc[0], e.dir.path(), |_| {}).await.unwrap();
    assert_eq!(std::fs::read_to_string(saved).unwrap(), "a,b\n1,2\n");
}

#[tokio::test]
async fn clipboard_external_to_internal() {
    let e = env().await;
    let (a_ext, a_int, _b, ikey) = setup(&e).await;
    let mut ev = events(&a_int, &ikey);
    next_event(&mut ev, |x| matches!(x, NetEvent::Connected)).await;
    login(&a_ext, "a", None).await;
    a_ext.call(ApiRequest::Clipboard { to: NetId::internal(), text: "복사한 내용".into() }).await.unwrap();
    match next_event(&mut ev, |x| matches!(x, NetEvent::Event(Event::Clipboard { .. }))).await {
        NetEvent::Event(Event::Clipboard { text, .. }) => assert_eq!(text, "복사한 내용"),
        _ => unreachable!(),
    }
}

#[tokio::test]
async fn pii_block_e2e() {
    let e = env().await;
    let (a_ext, _a_int, _b, _) = setup(&e).await;
    e.set_policy(|p| p.pii_rules.iter_mut().find(|r| r.id == "card").unwrap().action = PiiAction::Block);
    login(&a_ext, "a", None).await;
    let src = e.dir.path().join("cards.txt");
    std::fs::write(&src, "카드 4111-1111-1111-1111").unwrap();
    let t = send_file(&a_ext, NetId::internal(), &src).await.unwrap();
    assert_eq!(t.state, TransferState::Blocked);
}

#[tokio::test]
async fn link_drop_and_recover_keeps_session() {
    let e = env().await;
    let (a_ext, _a_int, _b, _) = setup(&e).await;
    login(&a_ext, "a", None).await;
    e.ext.relay.as_ref().unwrap().link.kick();
    tokio::time::sleep(Duration::from_millis(50)).await;
    let err = a_ext.call(ApiRequest::Me).await.unwrap_err();
    assert_eq!(err.code, ErrorCode::LinkDown);
    e.wait_linked().await;
    assert!(matches!(a_ext.call(ApiRequest::Me).await.unwrap(), ApiResponse::Me(_)));
}

#[tokio::test]
async fn ws_reconnect_keeps_session() {
    let e = env().await;
    let (_a_ext, a_int, _b, ikey) = setup(&e).await;
    login(&a_int, "a", Some(ikey.clone())).await;
    let (tx, mut rx) = mpsc::unbounded_channel();
    let task = a_int.clone().spawn_events(ikey.clone(), tx);
    next_event(&mut rx, |x| matches!(x, NetEvent::Connected)).await;
    task.abort();
    let mut rx2 = events(&a_int, &ikey);
    next_event(&mut rx2, |x| matches!(x, NetEvent::Connected)).await;
    assert!(matches!(a_int.call(ApiRequest::Me).await.unwrap(), ApiResponse::Me(_)));
}

#[tokio::test]
async fn unknown_device_key_is_rejected_by_ws() {
    let e = env().await;
    let net = e.net(NetId::external());
    let mut rx = events(&net, "nope");
    match next_event(&mut rx, |x| matches!(x, NetEvent::Disconnected(_) | NetEvent::Rejected)).await {
        NetEvent::Rejected => {}
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn ws_accepts_device_key_header_only() {
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;
    let e = env().await;
    let (_a_ext, a_int, _b, ikey) = setup(&e).await;
    login(&a_int, "a", Some(ikey.clone())).await;
    let tls = Arc::new(netbridge_clientcore::net::tls_config(&e.ca()).unwrap());
    let url = format!("{}/ws", a_int.base().replacen("https://", "wss://", 1));
    let mut req = url.into_client_request().unwrap();
    req.headers_mut().insert(DEVICE_KEY_HEADER, ikey.parse().unwrap());
    let r = tokio_tungstenite::connect_async_tls_with_config(req, None, false, Some(tokio_tungstenite::Connector::Rustls(tls))).await;
    assert!(r.is_ok(), "{:?}", r.err());
}

/// Plain-HTTP stand-in for /upload that answers 503 for the first `busy` requests.
async fn busy_server(busy: usize) -> (String, Arc<std::sync::atomic::AtomicUsize>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let hits = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let h = hits.clone();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = l.accept().await.unwrap();
            let n = h.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let mut buf = vec![];
            let mut tmp = [0u8; 4096];
            // read headers and the declared body before answering
            loop {
                let m = s.read(&mut tmp).await.unwrap();
                if m == 0 { break }
                buf.extend_from_slice(&tmp[..m]);
                let text = String::from_utf8_lossy(&buf).to_string();
                if let Some(end) = text.find("\r\n\r\n") {
                    let len: usize = text.lines().find_map(|l| l.to_ascii_lowercase().strip_prefix("content-length:").map(|v| v.trim().parse().unwrap())).unwrap_or(0);
                    if buf.len() >= end + 4 + len { break }
                }
            }
            let resp = if n < busy {
                "HTTP/1.1 503 Service Unavailable\r\ncontent-type: application/json\r\nconnection: close\r\ncontent-length: 2\r\n\r\n{}".to_string()
            } else {
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\nconnection: close\r\ncontent-length: 10\r\n\r\n{\"have\":5}".to_string()
            };
            s.write_all(resp.as_bytes()).await.unwrap();
        }
    });
    (format!("http://{addr}"), hits)
}

#[tokio::test]
async fn upload_retries_when_server_busy() {
    let d = tempfile::tempdir().unwrap();
    netbridge_server::certs::gen_certs(&d.path().join("certs"), &["127.0.0.1".into()], &["127.0.0.1".into()]).unwrap();
    let f = d.path().join("f.txt");
    std::fs::write(&f, b"hello").unwrap();
    let (url, hits) = busy_server(2).await;
    let net = Net::new(&url, &d.path().join("certs/ca.pem")).unwrap();
    net.upload(1, &f, |_| {}).await.unwrap();
    assert_eq!(hits.load(std::sync::atomic::Ordering::SeqCst), 3);
    // still busy after the retries: give up with the server's error
    let (url, hits) = busy_server(usize::MAX).await;
    let net = Net::new(&url, &d.path().join("certs/ca.pem")).unwrap();
    assert!(net.upload(1, &f, |_| {}).await.is_err());
    assert_eq!(hits.load(std::sync::atomic::Ordering::SeqCst), 3);
}

//! Real servers for three networks: central B, nodes C and D linked to B and to each other.
//! A file sent C→D must travel over the C–D link only.
use netbridge_clientcore::net::{sha256_file, Net};
use netbridge_proto::*;
use netbridge_server::config::ServerConfig;
use netbridge_server::server::start;
use std::time::Duration;

const PW: &str = "Passw0rd!";
const CERTS: &str = "tls_cert = \"certs/external.pem\"\ntls_key = \"certs/external.key\"\nca_cert = \"certs/ca.pem\"\n";

#[tokio::test]
async fn c_to_d_goes_over_the_neighbor_link() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    netbridge_server::certs::gen_certs(&d.join("certs"), &["127.0.0.1".into()], &["127.0.0.1".into()]).unwrap();
    let link = "client_cert = \"certs/link-client.pem\"\nclient_key = \"certs/link-client.key\"\n";
    std::fs::write(d.join("d.toml"), format!("role = \"node\"\nnetwork = \"D\"\nlisten = \"127.0.0.1:0\"\ndata_dir = \"d\"\n{CERTS}[link]\nlisten = \"127.0.0.1:0\"\n")).unwrap();
    let dn = start(ServerConfig::load(&d.join("d.toml")).unwrap()).await.unwrap();
    std::fs::write(
        d.join("c.toml"),
        format!(
            "role = \"node\"\nnetwork = \"C\"\nlisten = \"127.0.0.1:0\"\ndata_dir = \"c\"\n{CERTS}[link]\nlisten = \"127.0.0.1:0\"\n{link}[[neighbors]]\nnetwork = \"D\"\nurl = \"https://127.0.0.1:{}\"\n",
            dn.link_addr.unwrap().port()
        ),
    )
    .unwrap();
    let cn = start(ServerConfig::load(&d.join("c.toml")).unwrap()).await.unwrap();
    std::fs::write(
        d.join("b.toml"),
        format!(
            "role = \"hub\"\nnetwork = \"B\"\nlisten = \"127.0.0.1:0\"\ndata_dir = \"b\"\n{CERTS}[link]\n{link}\
             [[networks]]\nid = \"B\"\nname = \"B망\"\n[[networks]]\nid = \"C\"\nname = \"C망\"\n[[networks]]\nid = \"D\"\nname = \"D망\"\n\
             [[routes]]\na = \"B\"\nb = \"C\"\n[[routes]]\na = \"B\"\nb = \"D\"\n[[routes]]\na = \"C\"\nb = \"D\"\n\
             [[links]]\nnetwork = \"C\"\nurl = \"https://127.0.0.1:{}\"\n[[links]]\nnetwork = \"D\"\nurl = \"https://127.0.0.1:{}\"\n",
            cn.link_addr.unwrap().port(),
            dn.link_addr.unwrap().port()
        ),
    )
    .unwrap();
    let hub = start(ServerConfig::load(&d.join("b.toml")).unwrap()).await.unwrap();
    let core = hub.core.clone().unwrap();
    for _ in 0..200 {
        if cn.relay.as_ref().unwrap().link.connected() && dn.relay.as_ref().unwrap().link.connected() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let boss = core.create_user(&UserInput { id: None, username: "boss".into(), name: "boss".into(), dept_id: None, role: Role::User, approver_id: None, password: Some(PW.into()), networks: vec![] }).unwrap();
    let u = core.create_user(&UserInput { id: None, username: "u".into(), name: "u".into(), dept_id: None, role: Role::User, approver_id: Some(boss), password: Some(PW.into()), networks: vec![] }).unwrap();
    core.clear_must_change(u).unwrap();
    let mut p = core.route_policies().unwrap().into_iter().find(|p| p.route == Route::new(NetId::new("C"), NetId::new("D"))).unwrap();
    p.approval_rules = vec![ApprovalRule { order: 0, max_size: None, exts: vec![], dept_id: None, mode: ApprovalMode::Post }];
    core.set_route_policy(&p).unwrap();

    let ca = d.join("certs/ca.pem");
    let on_c = Net::new(&format!("https://127.0.0.1:{}", cn.app_addr.port()), &ca).unwrap();
    let hello = on_c.hello().await.unwrap();
    assert_eq!(hello.side, NetId::new("C"));
    assert_eq!(hello.topology.targets(&NetId::new("C")), vec![NetId::new("B"), NetId::new("D")]);
    match on_c.call(ApiRequest::Login { username: "u".into(), password: PW.into(), device_key: None }).await.unwrap() {
        ApiResponse::LoggedIn { token, .. } => on_c.set_token(Some(token)),
        r => panic!("{r:?}"),
    }
    let src = d.join("report.txt");
    std::fs::write(&src, "C에서 D로").unwrap();
    let meta = FileMeta { name: "report.txt".into(), size: std::fs::metadata(&src).unwrap().len(), sha256: sha256_file(&src).unwrap() };
    let id = match on_c.call(ApiRequest::CreateTransfers { to: NetId::new("D"), files: vec![meta], reason: "업무".into() }).await.unwrap() {
        ApiResponse::Ids(v) => v[0],
        r => panic!("{r:?}"),
    };
    on_c.upload(id, &src, |_| {}).await.unwrap();
    let t = match on_c.call(ApiRequest::CompleteUpload { id }).await.unwrap() {
        ApiResponse::Transfer(t) => t,
        r => panic!("{r:?}"),
    };
    assert_eq!(t.state, TransferState::Available, "{t:?}");
    assert!(dn.relay.as_ref().unwrap().files.path(id).exists(), "file not on D");
    assert!(!cn.relay.as_ref().unwrap().files.path(id).exists(), "C kept its copy");
    assert!(!core.files.path(id).exists(), "file passed through the central server");

    let on_d = Net::new(&format!("https://127.0.0.1:{}", dn.app_addr.port()), &ca).unwrap();
    match on_d.call(ApiRequest::Login { username: "u".into(), password: PW.into(), device_key: None }).await.unwrap() {
        ApiResponse::LoggedIn { token, .. } => on_d.set_token(Some(token)),
        r => panic!("{r:?}"),
    }
    let list = match on_d.call(ApiRequest::ListIncoming).await.unwrap() {
        ApiResponse::Transfers(v) => v,
        r => panic!("{r:?}"),
    };
    let out = d.join("recv");
    let got = on_d.download(&list[0], &out, |_| {}).await.unwrap();
    assert_eq!(std::fs::read_to_string(got).unwrap(), "C에서 D로");
    for r in [hub, cn, dn] {
        r.shutdown();
    }
}

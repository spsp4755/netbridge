use netbridge_proto::*;
use netbridge_server::link::{LinkBody, LinkFrame};
use netbridge_server::{certs, server};

#[test]
fn link_frame_roundtrip() {
    let f = LinkFrame { id: 7, body: LinkBody::Api { token: Some("t".into()), client_ip: "1.2.3.4".into(), req: ApiRequest::Me } };
    let s = serde_json::to_string(&f).unwrap();
    let back: LinkFrame = serde_json::from_str(&s).unwrap();
    assert_eq!(back, f);
}

pub fn write_configs(dir: &std::path::Path) -> (std::path::PathBuf, std::path::PathBuf) {
    certs::gen_certs(&dir.join("certs"), &["127.0.0.1".into()], &["127.0.0.1".into()]).unwrap();
    std::fs::write(
        dir.join("external.toml"),
        r#"side = "external"
listen = "127.0.0.1:0"
data_dir = "ext-data"
tls_cert = "certs/external.pem"
tls_key = "certs/external.key"
ca_cert = "certs/ca.pem"
[link]
listen = "127.0.0.1:0"
"#,
    )
    .unwrap();
    (dir.join("external.toml"), dir.join("certs"))
}

#[tokio::test]
async fn link_requires_client_cert() {
    let dir = tempfile::tempdir().unwrap();
    let (ext_cfg, certs_dir) = write_configs(dir.path());
    let ext = server::start(netbridge_server::config::ServerConfig::load(&ext_cfg).unwrap()).await.unwrap();
    let link = ext.link_addr.unwrap();
    let url = format!("https://127.0.0.1:{}/link/online", link.port());

    let no_cert = certs::client_tls(&certs_dir.join("ca.pem"), None).unwrap();
    let c = reqwest::Client::builder().use_preconfigured_tls(no_cert).build().unwrap();
    assert!(c.get(&url).send().await.is_err(), "link must reject clients without a certificate");

    let with_cert = certs::client_tls(&certs_dir.join("ca.pem"), Some((&certs_dir.join("link-client.pem"), &certs_dir.join("link-client.key")))).unwrap();
    let c = reqwest::Client::builder().use_preconfigured_tls(with_cert).build().unwrap();
    let r = c.get(&url).send().await.unwrap();
    assert!(r.status().is_success());

    // app-facing /api answers LinkDown while no internal server is connected
    let app = format!("https://127.0.0.1:{}/api", ext.app_addr.port());
    let tls = certs::client_tls(&certs_dir.join("ca.pem"), None).unwrap();
    let c = reqwest::Client::builder().use_preconfigured_tls(tls).build().unwrap();
    let r = c.post(&app).json(&ApiRequest::Me).send().await.unwrap();
    assert_eq!(r.status().as_u16(), 503);
    let e: ApiError = r.json().await.unwrap();
    assert_eq!(e.code, ErrorCode::LinkDown);
    ext.shutdown();
}

async fn connect_link(certs_dir: &std::path::Path, port: u16) -> tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>> {
    let tls = certs::client_tls(&certs_dir.join("ca.pem"), Some((&certs_dir.join("link-client.pem"), &certs_dir.join("link-client.key")))).unwrap();
    let c = tokio_tungstenite::Connector::Rustls(std::sync::Arc::new(tls));
    tokio_tungstenite::connect_async_tls_with_config(format!("wss://127.0.0.1:{port}/link/ws"), None, false, Some(c)).await.unwrap().0
}

#[tokio::test]
async fn old_link_closing_does_not_drop_new_link() {
    let dir = tempfile::tempdir().unwrap();
    let (ext_cfg, certs_dir) = write_configs(dir.path());
    let ext = server::start(netbridge_server::config::ServerConfig::load(&ext_cfg).unwrap()).await.unwrap();
    let port = ext.link_addr.unwrap().port();
    let hub = ext.relay.as_ref().unwrap().link.clone();
    let old = connect_link(&certs_dir, port).await;
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    let new = connect_link(&certs_dir, port).await;
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    drop(old);
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    assert!(hub.connected(), "the newer link must stay attached");
    drop(new);
    ext.shutdown();
}

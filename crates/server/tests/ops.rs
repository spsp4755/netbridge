//! Operator commands: backup, status, health, log settings.
use netbridge_server::config::ServerConfig;
use netbridge_server::{db::Db, ops, server};

fn internal_cfg(dir: &std::path::Path, extra: &str) -> ServerConfig {
    std::fs::write(
        dir.join("internal.toml"),
        format!("side = \"internal\"\nlisten = \"127.0.0.1:0\"\ndata_dir = \"data\"\ntls_cert = \"certs/internal.pem\"\ntls_key = \"certs/internal.key\"\nca_cert = \"certs/ca.pem\"\n{extra}[link]\nexternal_url = \"https://127.0.0.1:1\"\nclient_cert = \"certs/link-client.pem\"\nclient_key = \"certs/link-client.key\"\n"),
    )
    .unwrap();
    ServerConfig::load(&dir.join("internal.toml")).unwrap()
}

#[test]
fn log_settings_default_next_to_config() {
    let d = tempfile::tempdir().unwrap();
    let cfg = internal_cfg(d.path(), "");
    assert_eq!(cfg.log_dir, d.path().join("logs"));
    assert_eq!(cfg.log_keep_days, 30);
    let cfg = internal_cfg(d.path(), "log_dir = \"var/log\"\nlog_keep_days = 7\n");
    assert_eq!(cfg.log_dir, d.path().join("var/log"));
    assert_eq!(cfg.log_keep_days, 7);
}

#[test]
fn backup_copies_live_db_to_timestamped_file() {
    let d = tempfile::tempdir().unwrap();
    let cfg = internal_cfg(d.path(), "");
    let db = Db::open(&cfg.db_path()).unwrap();
    db.set_setting("marker", "hello").unwrap();
    // the server keeps the DB open while backing up
    let out = ops::backup(&cfg, None).unwrap();
    let name = out.file_name().unwrap().to_string_lossy().to_string();
    assert!(name.starts_with("netbridge-") && name.ends_with(".db"), "{name}");
    let copy = Db::open(&out).unwrap();
    assert_eq!(copy.setting("marker").unwrap().as_deref(), Some("hello"));
    // an explicit target is used as given and never overwritten
    let target = d.path().join("b.db");
    assert_eq!(ops::backup(&cfg, Some(&target)).unwrap(), target);
    assert!(ops::backup(&cfg, Some(&target)).is_err());
    drop(db);
}

#[test]
fn status_reports_counts_and_link() {
    let d = tempfile::tempdir().unwrap();
    let cfg = internal_cfg(d.path(), "");
    let db = Db::open(&cfg.db_path()).unwrap();
    db.with(|c| c.execute("INSERT INTO users(username,name,role,pw_hash,pw_changed_at) VALUES('a','a','user','x',0)", [])).unwrap();
    let s = ops::status(&cfg).unwrap();
    assert!(s.contains(env!("CARGO_PKG_VERSION")), "{s}");
    assert!(s.contains("사용자: 1"), "{s}");
    assert!(s.contains("오늘 전송: 0"), "{s}");
    assert!(s.contains("https://127.0.0.1:1"), "{s}");
    // no certs in this directory
    assert!(s.contains("없음"), "{s}");
}

#[tokio::test]
async fn health_needs_no_auth() {
    let d = tempfile::tempdir().unwrap();
    netbridge_server::certs::gen_certs(&d.path().join("certs"), &["127.0.0.1".into()], &["127.0.0.1".into()]).unwrap();
    std::fs::write(
        d.path().join("external.toml"),
        "side = \"external\"\nlisten = \"127.0.0.1:0\"\ndata_dir = \"ext\"\ntls_cert = \"certs/external.pem\"\ntls_key = \"certs/external.key\"\nca_cert = \"certs/ca.pem\"\n[link]\nlisten = \"127.0.0.1:0\"\n",
    )
    .unwrap();
    let ext = server::start(ServerConfig::load(&d.path().join("external.toml")).unwrap()).await.unwrap();
    let tls = netbridge_server::certs::client_tls(&d.path().join("certs/ca.pem"), None).unwrap();
    let c = reqwest::Client::builder().use_preconfigured_tls(tls).build().unwrap();
    let r = c.get(format!("https://127.0.0.1:{}/health", ext.app_addr.port())).send().await.unwrap();
    assert_eq!(r.status().as_u16(), 200);
    let v: serde_json::Value = r.json().await.unwrap();
    assert_eq!(v["ok"], true);
    assert_eq!(v["version"], env!("CARGO_PKG_VERSION"));
    ext.shutdown();
}

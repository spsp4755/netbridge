use netbridge_proto::Policy;
use netbridge_server::{certs, db::Db};
use rustls::client::danger::ServerCertVerifier;
use std::sync::Arc;

#[test]
fn db_open_creates_schema_idempotent() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("nb.db");
    drop(Db::open(&p).unwrap());
    let db = Db::open(&p).unwrap();
    assert_eq!(db.policy().unwrap(), Policy::default());
    assert!(db.approval_rules().unwrap().is_empty());
}

#[test]
fn gen_certs_produces_chain() {
    let dir = tempfile::tempdir().unwrap();
    certs::gen_certs(dir.path(), &["localhost".into(), "10.0.0.1".into()], &["127.0.0.1".into()]).unwrap();
    for f in ["ca.pem", "ca.key", "external.pem", "external.key", "internal.pem", "internal.key", "link-client.pem", "link-client.key"] {
        assert!(dir.path().join(f).exists(), "{f}");
    }
    certs::install_crypto();
    let roots = Arc::new(certs::root_store(&dir.path().join("ca.pem")).unwrap());
    let verifier = rustls::client::WebPkiServerVerifier::builder(roots).build().unwrap();
    let chain = certs::load_certs(&dir.path().join("external.pem")).unwrap();
    let now = rustls::pki_types::UnixTime::now();
    let ip = rustls::pki_types::ServerName::try_from("10.0.0.1").unwrap();
    verifier.verify_server_cert(&chain[0], &chain[1..], &ip, &[], now).unwrap();
    let wrong = rustls::pki_types::ServerName::try_from("127.0.0.1").unwrap();
    assert!(verifier.verify_server_cert(&chain[0], &chain[1..], &wrong, &[], now).is_err());
    // building TLS configs from the generated files must work
    certs::server_tls(&dir.path().join("internal.pem"), &dir.path().join("internal.key")).unwrap();
    certs::link_server_tls(&dir.path().join("external.pem"), &dir.path().join("external.key"), &dir.path().join("ca.pem")).unwrap();
    certs::client_tls(&dir.path().join("ca.pem"), Some((&dir.path().join("link-client.pem"), &dir.path().join("link-client.key")))).unwrap();
}

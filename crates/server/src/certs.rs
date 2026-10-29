use anyhow::{Context, Result};
use rcgen::{BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose, SanType};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::path::Path;
use std::sync::Arc;

/// Installs the ring provider once; aws-lc is avoided so Windows cross builds need no cmake/nasm.
pub fn install_crypto() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

fn san(host: &str) -> Result<SanType> {
    Ok(match host.parse::<std::net::IpAddr>() {
        Ok(ip) => SanType::IpAddress(ip),
        Err(_) => SanType::DnsName(host.to_string().try_into()?),
    })
}

fn leaf(cn: &str, hosts: &[String], client: bool, ca: &rcgen::Certificate, ca_key: &KeyPair) -> Result<(String, String)> {
    let mut p = CertificateParams::default();
    p.distinguished_name.push(DnType::CommonName, cn);
    p.subject_alt_names = hosts.iter().map(|h| san(h)).collect::<Result<_>>()?;
    p.extended_key_usages = vec![if client { ExtendedKeyUsagePurpose::ClientAuth } else { ExtendedKeyUsagePurpose::ServerAuth }];
    p.not_after = rcgen::date_time_ymd(2046, 1, 1);
    let key = KeyPair::generate()?;
    let cert = p.signed_by(&key, ca, ca_key)?;
    Ok((format!("{}{}", cert.pem(), ca.pem()), key.serialize_pem()))
}

/// Writes ca, external, internal and link-client certificates into `out`.
pub fn gen_certs(out: &Path, external_hosts: &[String], internal_hosts: &[String]) -> Result<()> {
    std::fs::create_dir_all(out)?;
    let mut ca = CertificateParams::default();
    ca.distinguished_name.push(DnType::CommonName, "NetBridge CA");
    ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    ca.not_after = rcgen::date_time_ymd(2046, 1, 1);
    let ca_key = KeyPair::generate()?;
    let ca_cert = ca.self_signed(&ca_key)?;
    let write = |name: &str, body: &str| std::fs::write(out.join(name), body).with_context(|| name.to_string());
    write("ca.pem", &ca_cert.pem())?;
    write("ca.key", &ca_key.serialize_pem())?;
    for (name, hosts, client) in [
        ("external", external_hosts, false),
        ("internal", internal_hosts, false),
        ("link-client", &["netbridge-link".to_string()][..], true),
    ] {
        let (cert, key) = leaf(&format!("NetBridge {name}"), hosts, client, &ca_cert, &ca_key)?;
        write(&format!("{name}.pem"), &cert)?;
        write(&format!("{name}.key"), &key)?;
    }
    Ok(())
}

pub fn load_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
    let data = std::fs::read(path).with_context(|| format!("인증서를 읽을 수 없습니다: {}", path.display()))?;
    Ok(rustls_pemfile::certs(&mut data.as_slice()).collect::<Result<_, _>>()?)
}

pub fn load_key(path: &Path) -> Result<PrivateKeyDer<'static>> {
    let data = std::fs::read(path).with_context(|| format!("키를 읽을 수 없습니다: {}", path.display()))?;
    rustls_pemfile::private_key(&mut data.as_slice())?.context("키 파일에 개인키가 없습니다")
}

pub fn root_store(ca: &Path) -> Result<rustls::RootCertStore> {
    let mut roots = rustls::RootCertStore::empty();
    for c in load_certs(ca)? {
        roots.add(c)?;
    }
    Ok(roots)
}

/// TLS for the app-facing listener (no client certificate).
pub fn server_tls(cert: &Path, key: &Path) -> Result<rustls::ServerConfig> {
    install_crypto();
    let mut cfg = rustls::ServerConfig::builder().with_no_client_auth().with_single_cert(load_certs(cert)?, load_key(key)?)?;
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(cfg)
}

/// TLS for the external server's link listener: a CA-signed client certificate is mandatory.
pub fn link_server_tls(cert: &Path, key: &Path, ca: &Path) -> Result<rustls::ServerConfig> {
    install_crypto();
    let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(root_store(ca)?)).build()?;
    let mut cfg = rustls::ServerConfig::builder().with_client_cert_verifier(verifier).with_single_cert(load_certs(cert)?, load_key(key)?)?;
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(cfg)
}

/// Client TLS pinned to the NetBridge CA, optionally presenting a client certificate.
pub fn client_tls(ca: &Path, client: Option<(&Path, &Path)>) -> Result<rustls::ClientConfig> {
    install_crypto();
    let b = rustls::ClientConfig::builder().with_root_certificates(root_store(ca)?);
    Ok(match client {
        Some((c, k)) => b.with_client_auth_cert(load_certs(c)?, load_key(k)?)?,
        None => b.with_no_client_auth(),
    })
}

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
    gen_certs_named(out, &[("external".to_string(), external_hosts.to_vec()), ("internal".to_string(), internal_hosts.to_vec())])
}

/// CA, one server certificate `<name>.pem/.key` per (name, hosts), and the link client certificate.
pub fn gen_certs_named(out: &Path, servers: &[(String, Vec<String>)]) -> Result<()> {
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
    let link = vec!["netbridge-link".to_string()];
    // link-client: the central server's certificate towards nodes; link-neighbor: nodes towards neighbor nodes
    let all = servers.iter().map(|(n, h)| (n.as_str(), h.as_slice(), false)).chain([("link-client", link.as_slice(), true), ("link-neighbor", link.as_slice(), true)]);
    for (name, hosts, client) in all {
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

/// Accepts only one exact client certificate (on top of the CA check): a node's link listener
/// must take the central server, not a neighbor node that holds another CA-signed certificate.
#[derive(Debug)]
struct Pinned {
    inner: Arc<dyn rustls::server::danger::ClientCertVerifier>,
    cert: CertificateDer<'static>,
}

impl rustls::server::danger::ClientCertVerifier for Pinned {
    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        self.inner.root_hint_subjects()
    }
    fn verify_client_cert(&self, end_entity: &CertificateDer<'_>, intermediates: &[CertificateDer<'_>], now: rustls::pki_types::UnixTime) -> Result<rustls::server::danger::ClientCertVerified, rustls::Error> {
        if end_entity.as_ref() != self.cert.as_ref() {
            return Err(rustls::Error::General("not the central server's link certificate".into()));
        }
        self.inner.verify_client_cert(end_entity, intermediates, now)
    }
    fn verify_tls12_signature(&self, message: &[u8], cert: &CertificateDer<'_>, dss: &rustls::DigitallySignedStruct) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }
    fn verify_tls13_signature(&self, message: &[u8], cert: &CertificateDer<'_>, dss: &rustls::DigitallySignedStruct) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

/// TLS for a node's link listeners: a CA-signed client certificate is mandatory; with `pin`, only that certificate.
pub fn link_server_tls(cert: &Path, key: &Path, ca: &Path, pin: Option<&Path>) -> Result<rustls::ServerConfig> {
    install_crypto();
    let mut verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(root_store(ca)?)).build()?;
    if let Some(p) = pin {
        let cert = load_certs(p)?.into_iter().next().context("고정할 중앙 서버 인증서가 비어 있습니다")?;
        verifier = Arc::new(Pinned { inner: verifier, cert });
    }
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

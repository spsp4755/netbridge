use anyhow::{Context, Result};
use netbridge_proto::Side;
use serde::Deserialize;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    #[serde(deserialize_with = "side")]
    pub side: Side,
    /// Address the desktop apps of this network connect to.
    pub listen: SocketAddr,
    pub data_dir: PathBuf,
    pub tls_cert: PathBuf,
    pub tls_key: PathBuf,
    pub ca_cert: PathBuf,
    pub link: LinkConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct LinkConfig {
    /// External server: mTLS listener the internal server connects to.
    pub listen: Option<SocketAddr>,
    /// Internal server: base URL of the external server's link listener.
    pub external_url: Option<String>,
    pub client_cert: Option<PathBuf>,
    pub client_key: Option<PathBuf>,
}

fn side<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Side, D::Error> {
    let s = String::deserialize(d)?;
    Side::parse(&s).ok_or_else(|| serde::de::Error::custom("side must be \"external\" or \"internal\""))
}

impl ServerConfig {
    pub fn load(path: &Path) -> Result<ServerConfig> {
        let text = std::fs::read_to_string(path).with_context(|| format!("설정 파일을 읽을 수 없습니다: {}", path.display()))?;
        let mut cfg: ServerConfig = toml::from_str(&text).context("설정 파일 형식 오류")?;
        // Relative paths are relative to the config file.
        let base = path.parent().unwrap_or(Path::new("."));
        for p in [&mut cfg.data_dir, &mut cfg.tls_cert, &mut cfg.tls_key, &mut cfg.ca_cert] {
            *p = base.join(&*p);
        }
        for p in [&mut cfg.link.client_cert, &mut cfg.link.client_key].into_iter().flatten() {
            *p = base.join(&*p);
        }
        match cfg.side {
            Side::External if cfg.link.listen.is_none() => anyhow::bail!("외부 서버는 [link] listen 값이 필요합니다"),
            Side::Internal if cfg.link.external_url.is_none() || cfg.link.client_cert.is_none() || cfg.link.client_key.is_none() => {
                anyhow::bail!("내부 서버는 [link] external_url, client_cert, client_key 값이 필요합니다")
            }
            _ => {}
        }
        Ok(cfg)
    }
}

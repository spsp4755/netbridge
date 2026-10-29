use anyhow::{bail, Context, Result};
use netbridge_proto::{NetId, NetInfo, Route, Topology};
use serde::Deserialize;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

/// The central server holds the database; every other network runs a node that relays to it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Hub,
    Node,
}

/// A link the central server opens to a node (mTLS WebSocket + HTTPS).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct HubLink {
    pub network: NetId,
    /// Base URL of the node's link listener, e.g. https://10.0.1.5:19443
    pub url: String,
}

/// Another node this node pushes files to directly (a link that bypasses the central server).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Neighbor {
    pub network: NetId,
    pub url: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct RoutePair {
    pub a: NetId,
    pub b: NetId,
}

#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub role: Role,
    pub network: NetId,
    /// Address the desktop apps of this network connect to.
    pub listen: SocketAddr,
    pub data_dir: PathBuf,
    pub tls_cert: PathBuf,
    pub tls_key: PathBuf,
    pub ca_cert: PathBuf,
    /// Daily-rotated log files; default `logs` next to the config file.
    pub log_dir: PathBuf,
    pub log_keep_days: usize,
    /// Node: mTLS listener for the central server and neighbor nodes.
    pub link_listen: Option<SocketAddr>,
    /// Client certificate for outgoing links (central → nodes, node → neighbors).
    pub client_cert: Option<PathBuf>,
    pub client_key: Option<PathBuf>,
    /// Central server only.
    pub topology: Option<Topology>,
    pub links: Vec<HubLink>,
    /// Node only.
    pub neighbors: Vec<Neighbor>,
}

#[derive(Deserialize)]
struct Raw {
    side: Option<String>,
    role: Option<String>,
    network: Option<NetId>,
    listen: SocketAddr,
    data_dir: PathBuf,
    tls_cert: PathBuf,
    tls_key: PathBuf,
    ca_cert: PathBuf,
    #[serde(default = "default_log_dir")]
    log_dir: PathBuf,
    #[serde(default = "default_log_keep_days")]
    log_keep_days: usize,
    #[serde(default)]
    link: RawLink,
    #[serde(default)]
    networks: Vec<NetInfo>,
    #[serde(default)]
    links: Vec<HubLink>,
    #[serde(default)]
    routes: Vec<RoutePair>,
    #[serde(default)]
    neighbors: Vec<Neighbor>,
}

#[derive(Deserialize, Default)]
struct RawLink {
    listen: Option<SocketAddr>,
    /// Legacy internal server: the external server's link listener.
    external_url: Option<String>,
    client_cert: Option<PathBuf>,
    client_key: Option<PathBuf>,
}

fn default_log_dir() -> PathBuf {
    "logs".into()
}

fn default_log_keep_days() -> usize {
    30
}

impl ServerConfig {
    pub fn load(path: &Path) -> Result<ServerConfig> {
        let text = std::fs::read_to_string(path).with_context(|| format!("설정 파일을 읽을 수 없습니다: {}", path.display()))?;
        let mut cfg = Self::parse(&text)?;
        // Relative paths are relative to the config file.
        let base = path.parent().unwrap_or(Path::new("."));
        for p in [&mut cfg.data_dir, &mut cfg.tls_cert, &mut cfg.tls_key, &mut cfg.ca_cert, &mut cfg.log_dir] {
            *p = base.join(&*p);
        }
        for p in [&mut cfg.client_cert, &mut cfg.client_key].into_iter().flatten() {
            *p = base.join(&*p);
        }
        Ok(cfg)
    }

    pub fn parse(text: &str) -> Result<ServerConfig> {
        let r: Raw = toml::from_str(text).context("설정 파일 형식 오류")?;
        let mut cfg = ServerConfig {
            role: Role::Node,
            network: NetId::new(""),
            listen: r.listen,
            data_dir: r.data_dir,
            tls_cert: r.tls_cert,
            tls_key: r.tls_key,
            ca_cert: r.ca_cert,
            log_dir: r.log_dir,
            log_keep_days: r.log_keep_days,
            link_listen: r.link.listen,
            client_cert: r.link.client_cert,
            client_key: r.link.client_key,
            topology: None,
            links: r.links,
            neighbors: r.neighbors,
        };
        match (r.side.as_deref(), r.role.as_deref()) {
            // 0.1–0.3 two-network files
            (Some("internal"), None) => {
                cfg.role = Role::Hub;
                cfg.network = NetId::internal();
                cfg.topology = Some(Topology::legacy());
                let url = r.link.external_url.context("내부 서버는 [link] external_url 값이 필요합니다")?;
                cfg.links = vec![HubLink { network: NetId::external(), url }];
            }
            (Some("external"), None) => {
                cfg.role = Role::Node;
                cfg.network = NetId::external();
            }
            (Some(_), None) => bail!("side must be \"external\" or \"internal\""),
            (None, Some(role)) => {
                cfg.network = r.network.context("network 값이 필요합니다 (이 서버가 속한 망 ID)")?;
                cfg.role = match role {
                    "hub" => Role::Hub,
                    "node" => Role::Node,
                    _ => bail!("role 은 \"hub\" 또는 \"node\" 입니다"),
                };
                if cfg.role == Role::Hub {
                    let mut routes = vec![];
                    for p in &r.routes {
                        routes.push(Route::new(p.a.clone(), p.b.clone()));
                        routes.push(Route::new(p.b.clone(), p.a.clone()));
                    }
                    cfg.topology = Some(Topology { hub: cfg.network.clone(), networks: r.networks, routes });
                }
            }
            (Some(_), Some(_)) => bail!("side 와 role 을 함께 쓸 수 없습니다 (새 설정은 role/network 를 씁니다)"),
            (None, None) => bail!("role 값이 필요합니다 (\"hub\" 또는 \"node\")"),
        }
        cfg.validate()?;
        Ok(cfg)
    }

    fn validate(&self) -> Result<()> {
        match self.role {
            Role::Node => {
                if self.link_listen.is_none() {
                    bail!("망 서버(node)는 [link] listen 값이 필요합니다");
                }
                if !self.neighbors.is_empty() && (self.client_cert.is_none() || self.client_key.is_none()) {
                    bail!("[[neighbors]] 를 쓰려면 [link] client_cert, client_key 값이 필요합니다");
                }
            }
            Role::Hub => {
                if self.client_cert.is_none() || self.client_key.is_none() {
                    bail!("중앙 서버는 [link] client_cert, client_key 값이 필요합니다");
                }
                let t = self.topology.as_ref().expect("hub topology");
                let known = |id: &NetId| t.networks.iter().any(|n| n.id == *id);
                if !known(&self.network) {
                    bail!("[[networks]] 에 중앙 서버의 망 {} 이 없습니다", self.network);
                }
                for r in &t.routes {
                    for id in [&r.from, &r.to] {
                        if !known(id) {
                            bail!("[[routes]] 의 망 {id} 이 [[networks]] 에 없습니다");
                        }
                    }
                }
                for n in &t.networks {
                    if n.id != self.network && !self.links.iter().any(|l| l.network == n.id) {
                        bail!("망 {} 에 대한 [[links]] 주소가 없습니다 (중앙 서버는 모든 망과 직접 연결되어야 합니다)", n.id);
                    }
                }
            }
        }
        Ok(())
    }

    /// The central server's database (nodes have none).
    pub fn db_path(&self) -> PathBuf {
        self.data_dir.join("netbridge.db")
    }

    pub fn is_hub(&self) -> bool {
        self.role == Role::Hub
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const COMMON: &str = "listen = \"0.0.0.0:8443\"\ndata_dir = \"d\"\ntls_cert = \"c\"\ntls_key = \"k\"\nca_cert = \"ca\"\n";

    #[test]
    fn legacy_internal_becomes_two_network_hub() {
        let c = ServerConfig::parse(&format!("side = \"internal\"\n{COMMON}[link]\nexternal_url = \"https://x:19443\"\nclient_cert = \"lc\"\nclient_key = \"lk\"\n")).unwrap();
        assert_eq!(c.role, Role::Hub);
        assert_eq!(c.network, NetId::internal());
        assert_eq!(c.topology, Some(Topology::legacy()));
        assert_eq!(c.links, vec![HubLink { network: NetId::external(), url: "https://x:19443".into() }]);
    }

    #[test]
    fn legacy_external_becomes_node() {
        let c = ServerConfig::parse(&format!("side = \"external\"\n{COMMON}[link]\nlisten = \"127.0.0.1:19443\"\n")).unwrap();
        assert_eq!((c.role, c.network), (Role::Node, NetId::external()));
    }

    fn four_networks(links: &str) -> String {
        format!(
            "role = \"hub\"\nnetwork = \"B\"\n{COMMON}[link]\nclient_cert = \"lc\"\nclient_key = \"lk\"\n\
             [[networks]]\nid = \"A\"\nname = \"A망\"\n[[networks]]\nid = \"B\"\nname = \"B망\"\n[[networks]]\nid = \"C\"\nname = \"C망\"\n[[networks]]\nid = \"D\"\nname = \"D망\"\n\
             [[routes]]\na = \"A\"\nb = \"B\"\n[[routes]]\na = \"B\"\nb = \"C\"\n[[routes]]\na = \"B\"\nb = \"D\"\n[[routes]]\na = \"C\"\nb = \"D\"\n{links}"
        )
    }

    #[test]
    fn four_network_hub_has_both_directions_of_each_route() {
        let links = "[[links]]\nnetwork = \"A\"\nurl = \"https://a\"\n[[links]]\nnetwork = \"C\"\nurl = \"https://c\"\n[[links]]\nnetwork = \"D\"\nurl = \"https://d\"\n";
        let c = ServerConfig::parse(&four_networks(links)).unwrap();
        let t = c.topology.unwrap();
        assert_eq!(t.routes.len(), 8);
        let (a, b, c_, d) = (NetId::new("A"), NetId::new("B"), NetId::new("C"), NetId::new("D"));
        assert_eq!(t.targets(&a), vec![b.clone()]);
        assert_eq!(t.targets(&b), vec![a.clone(), c_.clone(), d.clone()]);
        assert!(t.has_route(&Route::new(c_.clone(), d.clone())));
        assert!(!t.has_route(&Route::new(a, c_)));
    }

    #[test]
    fn hub_must_link_every_network() {
        let e = ServerConfig::parse(&four_networks("[[links]]\nnetwork = \"A\"\nurl = \"https://a\"\n")).unwrap_err();
        assert!(e.to_string().contains("[[links]]"), "{e}");
    }
}

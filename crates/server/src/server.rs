use crate::certs;
use crate::config::{Role, ServerConfig};
use crate::core::{Core, Peer};
use crate::db::Db;
use crate::files::Files;
use crate::http::{app_router, Backend};
use crate::hub::Hub;
use crate::link::{run_link_client, LinkHub, LinkPeer};
use crate::relay::{link_router, neighbor_router, Relay};
use axum::Router;
use netbridge_proto::NetId;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

pub struct Running {
    pub app_addr: SocketAddr,
    pub link_addr: Option<SocketAddr>,
    /// Node: listener for neighbor pushes.
    pub neighbor_addr: Option<SocketAddr>,
    pub core: Option<Arc<Core>>,
    pub relay: Option<Arc<Relay>>,
    handles: Vec<axum_server::Handle>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl Running {
    pub fn shutdown(&self) {
        for h in &self.handles {
            h.shutdown();
        }
        for t in &self.tasks {
            t.abort();
        }
    }
}

fn serve(addr: SocketAddr, tls: rustls::ServerConfig, router: Router) -> anyhow::Result<(SocketAddr, axum_server::Handle)> {
    let listener = std::net::TcpListener::bind(addr)?;
    listener.set_nonblocking(true)?;
    let local = listener.local_addr()?;
    let handle = axum_server::Handle::new();
    let server = axum_server::from_tcp_rustls(listener, axum_server::tls_rustls::RustlsConfig::from_config(Arc::new(tls))).handle(handle.clone());
    tokio::spawn(async move {
        if let Err(e) = server.serve(router.into_make_service_with_connect_info::<SocketAddr>()).await {
            tracing::error!("listener {local} stopped: {e}");
        }
    });
    Ok((local, handle))
}

pub async fn start(cfg: ServerConfig) -> anyhow::Result<Running> {
    certs::install_crypto();
    std::fs::create_dir_all(&cfg.data_dir)?;
    let app_tls = certs::server_tls(&cfg.tls_cert, &cfg.tls_key)?;
    let client_tls = |cfg: &ServerConfig| -> anyhow::Result<rustls::ClientConfig> {
        let (cc, ck) = (cfg.client_cert.as_ref().unwrap(), cfg.client_key.as_ref().unwrap());
        certs::client_tls(&cfg.ca_cert, Some((cc, ck)))
    };
    match cfg.role {
        Role::Hub => {
            let mut peers: HashMap<NetId, Arc<dyn Peer>> = HashMap::new();
            for l in &cfg.links {
                peers.insert(l.network.clone(), Arc::new(LinkPeer::new(&l.url, client_tls(&cfg)?)?));
            }
            let db = Db::open(&cfg.db_path())?;
            let topo = cfg.topology.clone().expect("hub topology");
            let mut core = Core::new(db, cfg.data_dir.clone(), cfg.network.clone(), topo, peers)?;
            core.scanners = cfg.scanners.clone();
            let core = Arc::new(core);
            let link_tls = Arc::new(client_tls(&cfg)?);
            let mut tasks = vec![];
            for l in &cfg.links {
                let ws_url = format!("{}/link/ws", l.url.trim_end_matches('/').replacen("https://", "wss://", 1));
                tasks.push(tokio::spawn(run_link_client(core.clone(), l.network.clone(), ws_url, link_tls.clone())));
            }
            let sweeper = core.clone();
            tasks.push(tokio::spawn(async move {
                let mut t = tokio::time::interval(Duration::from_secs(60));
                loop {
                    t.tick().await;
                    sweeper.sweep().await;
                }
            }));
            let backend: Arc<dyn Backend> = core.clone();
            let (app_addr, h) = serve(cfg.listen, app_tls, app_router(backend))?;
            tracing::info!("central server ({}) listening on {app_addr}, linking to {} network(s)", cfg.network, cfg.links.len());
            Ok(Running { app_addr, link_addr: None, neighbor_addr: None, core: Some(core), relay: None, handles: vec![h], tasks })
        }
        Role::Node => {
            let mut neighbors = HashMap::new();
            for n in &cfg.neighbors {
                neighbors.insert(n.network.clone(), LinkPeer::new(&n.url, client_tls(&cfg)?)?);
            }
            let relay = Arc::new(Relay {
                net: cfg.network.clone(),
                link: Arc::new(LinkHub::default()),
                files: Files::new(cfg.data_dir.join("files"))?,
                hub: Hub::default(),
                neighbors,
                topo: Default::default(),
                scanners: cfg.scanners.clone(),
            });
            let link_tls = certs::link_server_tls(&cfg.tls_cert, &cfg.tls_key, &cfg.ca_cert)?;
            let (link_addr, h1) = serve(cfg.link_listen.unwrap(), link_tls, link_router(relay.clone()))?;
            let backend: Arc<dyn Backend> = relay.clone();
            let (app_addr, h2) = serve(cfg.listen, app_tls, app_router(backend))?;
            let mut handles = vec![h1, h2];
            let mut neighbor_addr = None;
            if let Some(addr) = cfg.neighbor_listen {
                let tls = certs::link_server_tls(&cfg.tls_cert, &cfg.tls_key, &cfg.ca_cert)?;
                let (a, h) = serve(addr, tls, neighbor_router(relay.clone()))?;
                neighbor_addr = Some(a);
                handles.push(h);
            }
            tracing::info!("network {} server listening on {app_addr}, link on {link_addr}", cfg.network);
            Ok(Running { app_addr, link_addr: Some(link_addr), neighbor_addr, core: None, relay: Some(relay), handles, tasks: vec![] })
        }
    }
}

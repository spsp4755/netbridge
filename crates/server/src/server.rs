use crate::certs;
use crate::config::ServerConfig;
use crate::core::Core;
use crate::db::Db;
use crate::files::Files;
use crate::http::{app_router, Backend};
use crate::hub::Hub;
use crate::link::{run_link_client, LinkHub, LinkPeer};
use crate::relay::{link_router, Relay};
use axum::Router;
use netbridge_proto::Side;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

pub struct Running {
    pub app_addr: SocketAddr,
    pub link_addr: Option<SocketAddr>,
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
    match cfg.side {
        Side::Internal => {
            let link = &cfg.link;
            let (cc, ck) = (link.client_cert.as_ref().unwrap(), link.client_key.as_ref().unwrap());
            let base = link.external_url.clone().unwrap();
            let peer = LinkPeer::new(&base, certs::client_tls(&cfg.ca_cert, Some((cc, ck)))?)?;
            let db = Db::open(&cfg.db_path())?;
            let core = Arc::new(Core::new(db, cfg.data_dir.clone(), Arc::new(peer))?);
            let ws_url = format!("{}/link/ws", base.trim_end_matches('/').replacen("https://", "wss://", 1));
            let link_tls = Arc::new(certs::client_tls(&cfg.ca_cert, Some((cc, ck)))?);
            let mut tasks = vec![tokio::spawn(run_link_client(core.clone(), ws_url, link_tls))];
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
            tracing::info!("internal server listening on {app_addr}, linking to {base}");
            Ok(Running { app_addr, link_addr: None, core: Some(core), relay: None, handles: vec![h], tasks })
        }
        Side::External => {
            let relay = Arc::new(Relay { link: Arc::new(LinkHub::default()), files: Files::new(cfg.data_dir.join("files"))?, hub: Hub::default() });
            let link_tls = certs::link_server_tls(&cfg.tls_cert, &cfg.tls_key, &cfg.ca_cert)?;
            let (link_addr, h1) = serve(cfg.link.listen.unwrap(), link_tls, link_router(relay.clone()))?;
            let backend: Arc<dyn Backend> = relay.clone();
            let (app_addr, h2) = serve(cfg.listen, app_tls, app_router(backend))?;
            tracing::info!("external server listening on {app_addr}, link on {link_addr}");
            Ok(Running { app_addr, link_addr: Some(link_addr), core: None, relay: Some(relay), handles: vec![h1, h2], tasks: vec![] })
        }
    }
}

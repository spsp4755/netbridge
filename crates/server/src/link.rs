//! Internal <-> external link. The internal server opens every connection:
//! a WebSocket carrying the external server's API calls, and mTLS HTTPS for files, scans and pushes.

use crate::core::{CallCtx, Core, FileGrant, FileOp, Peer, ScanResult};
use async_trait::async_trait;
use futures_util::{SinkExt, StreamExt};
use netbridge_proto::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LinkFrame {
    pub id: u64,
    pub body: LinkBody,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum LinkBody {
    Api { token: Option<String>, client_ip: String, req: ApiRequest },
    DeviceAuth { key: String },
    AuthorizeFile { token: Option<String>, client_ip: String, id: i64, upload: bool },
    ReplyApi(Result<ApiResponse, ApiError>),
    ReplyDevice(Option<i64>),
    ReplyFile(Result<FileGrant, ApiError>),
}

pub fn link_down() -> ApiError {
    ApiError::new(ErrorCode::LinkDown, "업무망 연계 구간이 끊어졌습니다. 잠시 후 다시 시도하세요")
}

/// External side: the currently attached link socket and calls waiting for a reply.
#[derive(Default)]
pub struct LinkHub {
    /// (generation, sender) of the attached link; an older link must not clear a newer one.
    tx: Mutex<Option<(u64, mpsc::UnboundedSender<String>)>>,
    generation: AtomicU64,
    pending: Mutex<HashMap<u64, oneshot::Sender<LinkBody>>>,
    next: AtomicU64,
    kick: Mutex<Option<oneshot::Sender<()>>>,
}

impl LinkHub {
    pub fn connected(&self) -> bool {
        self.tx.lock().unwrap().as_ref().is_some_and(|(_, t)| !t.is_closed())
    }

    pub async fn call(&self, body: LinkBody, timeout: Duration) -> Result<LinkBody, ApiError> {
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = oneshot::channel();
        self.pending.lock().unwrap().insert(id, tx);
        let text = serde_json::to_string(&LinkFrame { id, body }).map_err(ApiError::internal)?;
        let sent = self.tx.lock().unwrap().as_ref().is_some_and(|(_, t)| t.send(text).is_ok());
        if !sent {
            self.pending.lock().unwrap().remove(&id);
            return Err(link_down());
        }
        match tokio::time::timeout(timeout, rx).await {
            Ok(Ok(b)) => Ok(b),
            _ => {
                self.pending.lock().unwrap().remove(&id);
                Err(link_down())
            }
        }
    }

    /// Closes the current link; the internal server reconnects.
    pub fn kick(&self) {
        if let Some(k) = self.kick.lock().unwrap().take() {
            let _ = k.send(());
        }
    }

    /// Serves one link socket until it closes. A new link replaces the old one.
    pub async fn attach(self: Arc<Self>, socket: axum::extract::ws::WebSocket) {
        use axum::extract::ws::Message;
        let (mut sink, mut stream) = socket.split();
        let (tx, mut rx) = mpsc::unbounded_channel::<String>();
        let (kick_tx, mut kick_rx) = oneshot::channel();
        let gen = self.generation.fetch_add(1, Ordering::SeqCst) + 1;
        // the internal server reconnected: the previous socket is stale
        if let Some(old) = self.kick.lock().unwrap().replace(kick_tx) {
            let _ = old.send(());
        }
        *self.tx.lock().unwrap() = Some((gen, tx));
        tracing::info!("internal server linked");
        let mut ping = tokio::time::interval(Duration::from_secs(15));
        loop {
            tokio::select! {
                out = rx.recv() => {
                    let Some(text) = out else { break };
                    if sink.send(Message::Text(text.into())).await.is_err() { break }
                }
                _ = ping.tick() => {
                    if sink.send(Message::Ping(Default::default())).await.is_err() { break }
                }
                _ = &mut kick_rx => break,
                msg = stream.next() => match msg {
                    Some(Ok(Message::Text(t))) => {
                        if let Ok(f) = serde_json::from_str::<LinkFrame>(t.as_str()) {
                            if let Some(w) = self.pending.lock().unwrap().remove(&f.id) {
                                let _ = w.send(f.body);
                            }
                        }
                    }
                    Some(Ok(Message::Close(_))) | None | Some(Err(_)) => break,
                    _ => {}
                }
            }
        }
        let _ = sink.close().await;
        let mut cur = self.tx.lock().unwrap();
        if cur.as_ref().is_some_and(|(g, _)| *g == gen) {
            *cur = None;
            drop(cur);
            // waiting callers get LinkDown when their sender is dropped
            self.pending.lock().unwrap().clear();
        }
        tracing::warn!("internal server link closed");
    }
}

/// Internal side: keeps the link WebSocket up and answers the external server's calls.
pub async fn run_link_client(core: Arc<Core>, ws_url: String, tls: Arc<rustls::ClientConfig>) {
    let mut backoff = 1u64;
    loop {
        let connector = tokio_tungstenite::Connector::Rustls(tls.clone());
        match tokio_tungstenite::connect_async_tls_with_config(ws_url.as_str(), None, false, Some(connector)).await {
            Ok((socket, _)) => {
                tracing::info!("linked to external server");
                backoff = 1;
                serve_link(core.clone(), socket).await;
                tracing::warn!("link to external server lost; reconnecting");
            }
            Err(e) => tracing::warn!("link connect failed: {e}"),
        }
        tokio::time::sleep(Duration::from_secs(backoff)).await;
        backoff = (backoff * 2).min(30);
    }
}

async fn serve_link<S>(core: Arc<Core>, socket: tokio_tungstenite::WebSocketStream<S>)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    use tokio_tungstenite::tungstenite::Message;
    let (mut sink, mut stream) = socket.split();
    let (tx, mut rx) = mpsc::unbounded_channel::<String>();
    let writer = tokio::spawn(async move {
        while let Some(t) = rx.recv().await {
            if sink.send(Message::Text(t.into())).await.is_err() {
                break;
            }
        }
    });
    // External server pings every 15s; treat 60s of silence as a dead link.
    while let Ok(Some(msg)) = tokio::time::timeout(Duration::from_secs(60), stream.next()).await {
        let Ok(msg) = msg else { break };
        let Message::Text(t) = msg else {
            if matches!(msg, Message::Close(_)) {
                break;
            }
            continue;
        };
        let Ok(frame) = serde_json::from_str::<LinkFrame>(t.as_str()) else { continue };
        let core = core.clone();
        let tx = tx.clone();
        tokio::spawn(async move {
            let body = answer(&core, frame.body).await;
            if let Ok(text) = serde_json::to_string(&LinkFrame { id: frame.id, body }) {
                let _ = tx.send(text);
            }
        });
    }
    writer.abort();
}

/// Everything arriving over the link is from the external network.
async fn answer(core: &Core, body: LinkBody) -> LinkBody {
    match body {
        LinkBody::Api { token, client_ip, req } => LinkBody::ReplyApi(core.handle(CallCtx { token, client_ip, side: Side::External }, req).await),
        LinkBody::DeviceAuth { key } => LinkBody::ReplyDevice(core.device_auth(&key).filter(|d| d.side == Side::External).map(|d| d.device_id)),
        LinkBody::AuthorizeFile { token, client_ip, id, upload } => {
            let op = if upload { FileOp::Upload } else { FileOp::Download };
            LinkBody::ReplyFile(core.authorize_file(&CallCtx { token, client_ip, side: Side::External }, id, op).await)
        }
        other => LinkBody::ReplyApi(Err(ApiError::bad(format!("unexpected link frame {other:?}")))),
    }
}

/// Internal side's view of the external server over mTLS HTTPS.
pub struct LinkPeer {
    base: String,
    http: reqwest::Client,
}

impl LinkPeer {
    pub fn new(base: &str, tls: rustls::ClientConfig) -> anyhow::Result<LinkPeer> {
        let http = reqwest::Client::builder().use_preconfigured_tls(tls).connect_timeout(Duration::from_secs(10)).build()?;
        Ok(LinkPeer { base: base.trim_end_matches('/').to_string(), http })
    }

    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.base)
    }
}

fn down(e: impl std::fmt::Display) -> ApiError {
    tracing::warn!("link request failed: {e}");
    link_down()
}

async fn check(r: reqwest::Response) -> Result<reqwest::Response, ApiError> {
    if r.status().is_success() {
        Ok(r)
    } else {
        Err(r.json::<ApiError>().await.unwrap_or_else(|e| ApiError::internal(e)))
    }
}

#[async_trait]
impl Peer for LinkPeer {
    async fn scan(&self, id: i64, name: &str, policy: &Policy) -> Result<ScanResult, ApiError> {
        let r = self.http.post(self.url(&format!("/link/scan/{id}"))).json(&serde_json::json!({ "name": name, "policy": policy })).send().await.map_err(down)?;
        check(r).await?.json().await.map_err(down)
    }

    async fn fetch_file(&self, id: i64, dest: &Path) -> Result<(), ApiError> {
        use tokio::io::AsyncWriteExt;
        let r = check(self.http.get(self.url(&format!("/link/files/{id}"))).send().await.map_err(down)?).await?;
        let mut f = tokio::fs::File::create(dest).await.map_err(ApiError::internal)?;
        let mut s = r.bytes_stream();
        while let Some(chunk) = s.next().await {
            f.write_all(&chunk.map_err(down)?).await.map_err(ApiError::internal)?;
        }
        f.flush().await.map_err(ApiError::internal)?;
        Ok(())
    }

    async fn push_file(&self, id: i64, src: &Path) -> Result<(), ApiError> {
        let f = tokio::fs::File::open(src).await.map_err(ApiError::internal)?;
        let body = reqwest::Body::wrap_stream(tokio_util::io::ReaderStream::with_capacity(f, 256 * 1024));
        check(self.http.put(self.url(&format!("/link/files/{id}"))).body(body).send().await.map_err(down)?).await?;
        Ok(())
    }

    async fn delete_file(&self, id: i64) -> Result<(), ApiError> {
        check(self.http.delete(self.url(&format!("/link/files/{id}"))).send().await.map_err(down)?).await?;
        Ok(())
    }

    async fn push_event(&self, device_id: i64, ev: Event) -> Result<bool, ApiError> {
        let r = self.http.post(self.url("/link/push")).json(&serde_json::json!({ "device_id": device_id, "event": ev })).send().await.map_err(down)?;
        let v: serde_json::Value = check(r).await?.json().await.map_err(down)?;
        Ok(v["delivered"].as_bool().unwrap_or(false))
    }

    async fn drop_device(&self, device_id: i64) -> Result<(), ApiError> {
        check(self.http.post(self.url("/link/drop")).json(&serde_json::json!({ "device_id": device_id })).send().await.map_err(down)?).await?;
        Ok(())
    }

    async fn online_devices(&self) -> Result<Vec<i64>, ApiError> {
        check(self.http.get(self.url("/link/online")).send().await.map_err(down)?).await?.json().await.map_err(down)
    }
}

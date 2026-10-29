//! A network's node: app requests are relayed to the central server; payload bytes stay here
//! and move only over a link this network has (to the central server or a neighbor node).

use crate::core::{scan_path, CallCtx, FileGrant, FileOp};
use crate::files::Files;
use crate::http::{serve_file, Backend, ErrResp};
use crate::hub::Hub;
use crate::link::{LinkBody, LinkHub, LinkPeer, SHA_HEADER};
use std::collections::HashMap;
use std::sync::Mutex;
use async_trait::async_trait;
use axum::body::Body;
use axum::extract::ws::WebSocketUpgrade;
use axum::extract::{DefaultBodyLimit, Path, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use futures_util::StreamExt;
use netbridge_proto::*;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;

pub struct Relay {
    pub net: NetId,
    pub link: Arc<LinkHub>,
    pub files: Files,
    pub hub: Hub,
    /// Neighbor nodes this node sends files to directly.
    pub neighbors: HashMap<NetId, LinkPeer>,
    /// Last layout received from the central server.
    pub topo: Mutex<Option<Topology>>,
    /// Antivirus / CDR tools run on files stored here.
    pub scanners: Vec<netbridge_scan::ExternalScanner>,
}

const API_TIMEOUT: Duration = Duration::from_secs(600);

fn unexpected() -> ApiError {
    ApiError::internal("연계 응답 형식 오류")
}

#[async_trait]
impl Backend for Relay {
    fn side(&self) -> Side {
        self.net.clone()
    }
    async fn topology(&self) -> Topology {
        if let Ok(LinkBody::ReplyTopology(t)) = self.link.call(LinkBody::Topology, Duration::from_secs(3)).await {
            *self.topo.lock().unwrap() = Some(t.clone());
            return t;
        }
        // central server unreachable: last known layout, or just this network
        self.topo.lock().unwrap().clone().unwrap_or_else(|| Topology { hub: self.net.clone(), networks: vec![NetInfo { id: self.net.clone(), name: self.net.0.clone() }], routes: vec![] })
    }
    fn files(&self) -> &Files {
        &self.files
    }
    fn hub(&self) -> &Hub {
        &self.hub
    }
    async fn api(&self, ctx: CallCtx, req: ApiRequest) -> ApiResult {
        match self.link.call(LinkBody::Api { token: ctx.token, client_ip: ctx.client_ip, req }, API_TIMEOUT).await? {
            LinkBody::ReplyApi(r) => r,
            _ => Err(unexpected()),
        }
    }
    async fn device(&self, key: &str) -> Result<Option<i64>, ApiError> {
        match self.link.call(LinkBody::DeviceAuth { key: key.to_string() }, Duration::from_secs(30)).await? {
            LinkBody::ReplyDevice(d) => Ok(d),
            _ => Err(unexpected()),
        }
    }
    async fn authorize(&self, ctx: CallCtx, id: i64, op: FileOp) -> Result<FileGrant, ApiError> {
        let body = LinkBody::AuthorizeFile { token: ctx.token, client_ip: ctx.client_ip, id, upload: op == FileOp::Upload };
        match self.link.call(body, Duration::from_secs(30)).await? {
            LinkBody::ReplyFile(r) => r,
            _ => Err(unexpected()),
        }
    }
}

type R = Arc<Relay>;

/// Routes served only on the mTLS link listener.
pub fn link_router(r: R) -> Router {
    Router::new()
        .route("/link/ws", get(link_ws))
        .route("/link/files/{id}", get(get_file).put(put_file).delete(delete_file))
        .route("/link/scan/{id}", post(scan))
        .route("/link/push", post(push))
        .route("/link/online", get(online))
        .route("/link/drop", post(drop_device))
        .route("/link/forward/{id}", post(forward))
        .layer(DefaultBodyLimit::disable())
        .with_state(r)
}

async fn link_ws(State(r): State<R>, upgrade: WebSocketUpgrade) -> Response {
    let hub = r.link.clone();
    upgrade.on_upgrade(move |s| hub.attach(s))
}

async fn get_file(State(r): State<R>, Path(id): Path<i64>, headers: HeaderMap) -> Result<Response, ErrResp> {
    serve_file(&r.files, id, &headers).await
}

async fn put_file(State(r): State<R>, Path(id): Path<i64>, headers: HeaderMap, body: Body) -> Result<Response, ErrResp> {
    let path = r.files.path(id);
    // a unique temp name per push, so a retried or duplicate push of the same id never shares a file
    let tmp = path.with_extension(format!("{:016x}.part", rand::random::<u64>()));
    let expect = headers.get(SHA_HEADER).and_then(|v| v.to_str().ok()).map(|s| s.to_ascii_lowercase());
    let res = write_stream(&tmp, body).await;
    let res = match (res, expect) {
        (Ok(()), Some(want)) => {
            let t = tmp.clone();
            let got = tokio::task::spawn_blocking(move || crate::files::sha256_of(&t)).await.map_err(ApiError::internal)?;
            match got {
                Ok(h) if h == want => Ok(()),
                Ok(_) => Err(ApiError::new(ErrorCode::Conflict, "받은 파일의 해시가 다릅니다")),
                Err(e) => Err(ApiError::internal(e)),
            }
        }
        (res, _) => res,
    };
    let res = match res {
        Ok(()) => tokio::fs::rename(&tmp, &path).await.map_err(ApiError::internal),
        Err(e) => Err(e),
    };
    if res.is_err() {
        let _ = tokio::fs::remove_file(&tmp).await;
    }
    res?;
    Ok(Json(serde_json::json!({ "ok": true })).into_response())
}

async fn write_stream(tmp: &std::path::Path, body: Body) -> Result<(), ApiError> {
    let mut f = tokio::fs::File::create(tmp).await.map_err(ApiError::internal)?;
    let mut s = body.into_data_stream();
    while let Some(chunk) = s.next().await {
        let chunk = chunk.map_err(ApiError::internal)?;
        f.write_all(&chunk).await.map_err(ApiError::internal)?;
    }
    f.sync_all().await.map_err(ApiError::internal)
}

async fn delete_file(State(r): State<R>, Path(id): Path<i64>) -> Json<serde_json::Value> {
    r.files.remove(id);
    Json(serde_json::json!({ "ok": true }))
}

#[derive(serde::Deserialize)]
struct ScanReq {
    name: String,
    policy: Policy,
}

async fn scan(State(r): State<R>, Path(id): Path<i64>, Json(q): Json<ScanReq>) -> Result<Response, ErrResp> {
    let path = r.files.path(id);
    let scanners = r.scanners.clone();
    let res = tokio::task::spawn_blocking(move || scan_path(&q.name, &path, &q.policy, &scanners)).await.map_err(ApiError::internal)?;
    let res = res.map_err(|_| ApiError::bad("올린 파일이 없습니다"))?;
    Ok(Json(res).into_response())
}

#[derive(serde::Deserialize)]
struct PushReq {
    device_id: i64,
    event: Event,
}

async fn push(State(r): State<R>, Json(q): Json<PushReq>) -> Json<serde_json::Value> {
    Json(serde_json::json!({ "delivered": r.hub.push(q.device_id, q.event) }))
}

#[derive(serde::Deserialize)]
struct DropReq {
    device_id: i64,
}

async fn drop_device(State(r): State<R>, Json(q): Json<DropReq>) -> Json<serde_json::Value> {
    r.hub.drop_device(q.device_id);
    Json(serde_json::json!({ "ok": true }))
}

async fn online(State(r): State<R>) -> Json<Vec<i64>> {
    Json(r.hub.online())
}

#[derive(serde::Deserialize)]
struct ForwardReq {
    to: NetId,
    sha256: String,
}

/// Central server's order to send this node's copy straight to a neighbor network.
async fn forward(State(r): State<R>, Path(id): Path<i64>, Json(q): Json<ForwardReq>) -> Result<Response, ErrResp> {
    let n = r.neighbors.get(&q.to).ok_or_else(|| ApiError::new(ErrorCode::LinkDown, format!("{} 연계 주소가 이 서버 설정([[neighbors]])에 없습니다", q.to)))?;
    n.push_checked(id, &r.files.path(id), Some(&q.sha256)).await?;
    Ok(Json(serde_json::json!({ "ok": true })).into_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn slow_body(byte: u8) -> Body {
        // many small chunks with yields so two uploads interleave
        let s = futures_util::stream::iter(0..64).then(move |_| async move {
            tokio::task::yield_now().await;
            Ok::<_, std::io::Error>(axum::body::Bytes::from(vec![byte; 1024]))
        });
        Body::from_stream(s)
    }

    fn relay(dir: &std::path::Path) -> Arc<Relay> {
        Arc::new(Relay {
            net: NetId::new("C"),
            link: Arc::new(LinkHub::default()),
            files: Files::new(dir.to_path_buf()).unwrap(),
            hub: Hub::default(),
            neighbors: HashMap::new(),
            topo: Default::default(),
            scanners: vec![],
        })
    }

    #[tokio::test]
    async fn push_with_wrong_hash_is_rejected_and_not_kept() {
        let dir = tempfile::tempdir().unwrap();
        let r = relay(dir.path());
        let mut h = HeaderMap::new();
        h.insert(SHA_HEADER, "00".repeat(32).parse().unwrap());
        assert!(put_file(State(r.clone()), Path(9), h, slow_body(b'x')).await.is_err());
        assert!(!r.files.path(9).exists());
        let mut h = HeaderMap::new();
        h.insert(SHA_HEADER, crate::files::sha256_of_bytes(&vec![b'x'; 64 * 1024]).parse().unwrap());
        assert!(put_file(State(r.clone()), Path(9), h, slow_body(b'x')).await.is_ok());
        assert!(r.files.path(9).exists());
    }

    #[tokio::test]
    async fn concurrent_pushes_of_same_id_do_not_collide() {
        let dir = tempfile::tempdir().unwrap();
        let r = relay(dir.path());
        let (a, b) = tokio::join!(put_file(State(r.clone()), Path(7), HeaderMap::new(), slow_body(b'a')), put_file(State(r.clone()), Path(7), HeaderMap::new(), slow_body(b'b')));
        assert!(a.is_ok() && b.is_ok());
        let got = std::fs::read(r.files.path(7)).unwrap();
        assert_eq!(got.len(), 64 * 1024);
        assert!(got.iter().all(|x| *x == got[0]), "file mixes two uploads");
        let leftovers: Vec<_> = std::fs::read_dir(dir.path()).unwrap().filter_map(|e| e.ok()).filter(|e| e.path().extension().is_some_and(|x| x == "part")).collect();
        assert!(leftovers.is_empty());
    }
}

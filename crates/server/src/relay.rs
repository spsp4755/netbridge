//! External server: app requests are relayed to the internal server; payload bytes stay here.

use crate::core::{scan_path, CallCtx, FileGrant, FileOp};
use crate::files::Files;
use crate::http::{serve_file, Backend, ErrResp};
use crate::hub::Hub;
use crate::link::{LinkBody, LinkHub};
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
    pub link: Arc<LinkHub>,
    pub files: Files,
    pub hub: Hub,
}

const API_TIMEOUT: Duration = Duration::from_secs(600);

fn unexpected() -> ApiError {
    ApiError::internal("연계 응답 형식 오류")
}

#[async_trait]
impl Backend for Relay {
    fn side(&self) -> Side {
        Side::External
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

async fn put_file(State(r): State<R>, Path(id): Path<i64>, body: Body) -> Result<Response, ErrResp> {
    let path = r.files.path(id);
    // a unique temp name per push, so a retried or duplicate push of the same id never shares a file
    let tmp = path.with_extension(format!("{:016x}.part", rand::random::<u64>()));
    let res = write_stream(&tmp, body).await;
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
    let res = tokio::task::spawn_blocking(move || scan_path(&q.name, &path, &q.policy)).await.map_err(ApiError::internal)?;
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

    #[tokio::test]
    async fn concurrent_pushes_of_same_id_do_not_collide() {
        let dir = tempfile::tempdir().unwrap();
        let r = Arc::new(Relay { link: Arc::new(LinkHub::default()), files: Files::new(dir.path().to_path_buf()).unwrap(), hub: Hub::default() });
        let (a, b) = tokio::join!(put_file(State(r.clone()), Path(7), slow_body(b'a')), put_file(State(r.clone()), Path(7), slow_body(b'b')));
        assert!(a.is_ok() && b.is_ok());
        let got = std::fs::read(r.files.path(7)).unwrap();
        assert_eq!(got.len(), 64 * 1024);
        assert!(got.iter().all(|x| *x == got[0]), "file mixes two uploads");
        let leftovers: Vec<_> = std::fs::read_dir(dir.path()).unwrap().filter_map(|e| e.ok()).filter(|e| e.path().extension().is_some_and(|x| x == "part")).collect();
        assert!(leftovers.is_empty());
    }
}

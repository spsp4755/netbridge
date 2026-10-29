use crate::core::{CallCtx, FileGrant, FileOp};
use crate::files::{Files, WriteError};
use crate::hub::Hub;
use async_trait::async_trait;
use axum::body::{Body, Bytes};
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{ConnectInfo, DefaultBodyLimit, Path, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::{Json, Router};
use netbridge_proto::*;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncSeekExt};

/// What an app-facing listener needs; the internal server answers itself, the external one relays.
#[async_trait]
pub trait Backend: Send + Sync + 'static {
    fn side(&self) -> Side;
    fn files(&self) -> &Files;
    fn hub(&self) -> &Hub;
    async fn api(&self, ctx: CallCtx, req: ApiRequest) -> ApiResult;
    /// Device id for a device key registered on this network.
    async fn device(&self, key: &str) -> Result<Option<i64>, ApiError>;
    async fn authorize(&self, ctx: CallCtx, id: i64, op: FileOp) -> Result<FileGrant, ApiError>;
}

pub fn status_of(code: ErrorCode) -> StatusCode {
    match code {
        ErrorCode::BadRequest => StatusCode::BAD_REQUEST,
        ErrorCode::Unauthorized | ErrorCode::SessionExpired => StatusCode::UNAUTHORIZED,
        ErrorCode::AccountLocked => StatusCode::LOCKED,
        ErrorCode::DeviceMismatch | ErrorCode::Forbidden => StatusCode::FORBIDDEN,
        ErrorCode::NotFound => StatusCode::NOT_FOUND,
        ErrorCode::LimitExceeded | ErrorCode::Blocked => StatusCode::UNPROCESSABLE_ENTITY,
        ErrorCode::Conflict | ErrorCode::PeerOffline => StatusCode::CONFLICT,
        ErrorCode::LinkDown => StatusCode::SERVICE_UNAVAILABLE,
        ErrorCode::Internal => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

pub struct ErrResp(pub ApiError);

impl IntoResponse for ErrResp {
    fn into_response(self) -> Response {
        (status_of(self.0.code), Json(self.0)).into_response()
    }
}

impl From<ApiError> for ErrResp {
    fn from(e: ApiError) -> Self {
        ErrResp(e)
    }
}

fn ctx_of(side: Side, headers: &HeaderMap, addr: SocketAddr) -> CallCtx {
    let token = headers.get(header::AUTHORIZATION).and_then(|v| v.to_str().ok()).and_then(|v| v.strip_prefix("Bearer ")).map(|s| s.trim().to_string());
    let ip = match addr.ip() {
        std::net::IpAddr::V6(v6) => v6.to_ipv4_mapped().map(|v4| v4.to_string()).unwrap_or_else(|| v6.to_string()),
        v4 => v4.to_string(),
    };
    CallCtx { token, client_ip: ip, side }
}

type B = Arc<dyn Backend>;

pub fn app_router(b: B) -> Router {
    Router::new()
        .route("/hello", get(hello))
        .route("/api", post(api))
        .route("/ws", get(ws))
        .route("/upload/{id}", put(upload))
        .route("/download/{id}", get(download))
        .layer(DefaultBodyLimit::max(8 * 1024 * 1024))
        .with_state(b)
}

async fn hello(State(b): State<B>) -> Json<Hello> {
    Json(Hello { side: b.side(), server_time: chrono::Utc::now().timestamp() })
}

async fn api(State(b): State<B>, ConnectInfo(addr): ConnectInfo<SocketAddr>, headers: HeaderMap, body: Bytes) -> Result<Json<ApiResponse>, ErrResp> {
    let req: ApiRequest = serde_json::from_slice(&body).map_err(|e| ApiError::bad(format!("요청 형식 오류: {e}")))?;
    Ok(Json(b.api(ctx_of(b.side(), &headers, addr), req).await?))
}

async fn ws(State(b): State<B>, Query(q): Query<HashMap<String, String>>, upgrade: WebSocketUpgrade) -> Result<Response, ErrResp> {
    let key = q.get("device_key").cloned().unwrap_or_default();
    let dev = b.device(&key).await?.ok_or_else(|| ApiError::new(ErrorCode::Unauthorized, "등록되지 않은 기기입니다"))?;
    Ok(upgrade.on_upgrade(move |socket| run_ws(socket, b, dev)))
}

async fn run_ws(mut socket: WebSocket, b: B, dev: i64) {
    let mut rx = b.hub().register(dev);
    let mut ping = tokio::time::interval(std::time::Duration::from_secs(20));
    loop {
        tokio::select! {
            ev = rx.recv() => {
                let Some(ev) = ev else { break };
                let Ok(text) = serde_json::to_string(&ev) else { continue };
                if socket.send(Message::Text(text.into())).await.is_err() { break }
            }
            _ = ping.tick() => {
                if socket.send(Message::Ping(Bytes::new())).await.is_err() { break }
            }
            msg = socket.recv() => match msg {
                Some(Ok(Message::Close(_))) | None | Some(Err(_)) => break,
                _ => {}
            }
        }
    }
}

async fn upload(
    State(b): State<B>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Query(q): Query<HashMap<String, u64>>,
    body: Bytes,
) -> Result<Response, ErrResp> {
    let grant = b.authorize(ctx_of(b.side(), &headers, addr), id, FileOp::Upload).await?;
    let offset = q.get("offset").copied().unwrap_or(0);
    let files_ok = |have: u64| Json(serde_json::json!({ "have": have })).into_response();
    match b.files().write_at_max(id, offset, &body, grant.size) {
        Ok(have) => Ok(files_ok(have)),
        Err(WriteError::Conflict { have }) => Ok((StatusCode::CONFLICT, Json(serde_json::json!({ "have": have }))).into_response()),
        Err(WriteError::TooLarge) => Err(ApiError::new(ErrorCode::LimitExceeded, "신고한 크기보다 큰 파일입니다").into()),
        Err(WriteError::Io(e)) => Err(ApiError::internal(e).into()),
    }
}

async fn download(State(b): State<B>, ConnectInfo(addr): ConnectInfo<SocketAddr>, headers: HeaderMap, Path(id): Path<i64>) -> Result<Response, ErrResp> {
    b.authorize(ctx_of(b.side(), &headers, addr), id, FileOp::Download).await?;
    serve_file(b.files(), id, &headers).await
}

/// Streams a stored file, honouring `Range: bytes=N-`.
pub async fn serve_file(files: &Files, id: i64, headers: &HeaderMap) -> Result<Response, ErrResp> {
    let path = files.path(id);
    let mut f = tokio::fs::File::open(&path).await.map_err(|_| ApiError::new(ErrorCode::NotFound, "파일이 서버에 없습니다"))?;
    let len = f.metadata().await.map_err(ApiError::internal)?.len();
    let start = headers
        .get(header::RANGE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("bytes="))
        .and_then(|v| v.split('-').next())
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|s| *s <= len)
        .unwrap_or(0);
    f.seek(std::io::SeekFrom::Start(start)).await.map_err(ApiError::internal)?;
    let stream = tokio_util::io::ReaderStream::with_capacity(f.take(len - start), 256 * 1024);
    let mut resp = Response::new(Body::from_stream(stream));
    if start > 0 {
        *resp.status_mut() = StatusCode::PARTIAL_CONTENT;
        resp.headers_mut().insert(header::CONTENT_RANGE, format!("bytes {start}-{}/{len}", len.saturating_sub(1)).parse().unwrap());
    }
    let h = resp.headers_mut();
    h.insert(header::CONTENT_TYPE, "application/octet-stream".parse().unwrap());
    h.insert(header::CONTENT_LENGTH, (len - start).into());
    Ok(resp)
}

#[async_trait]
impl Backend for crate::core::Core {
    fn side(&self) -> Side {
        Side::Internal
    }
    fn files(&self) -> &Files {
        &self.files
    }
    fn hub(&self) -> &Hub {
        &self.hub
    }
    async fn api(&self, ctx: CallCtx, req: ApiRequest) -> ApiResult {
        self.handle(ctx, req).await
    }
    async fn device(&self, key: &str) -> Result<Option<i64>, ApiError> {
        Ok(self.device_auth(key).filter(|d| d.side == Side::Internal).map(|d| d.device_id))
    }
    async fn authorize(&self, ctx: CallCtx, id: i64, op: FileOp) -> Result<FileGrant, ApiError> {
        self.authorize_file(&ctx, id, op).await
    }
}

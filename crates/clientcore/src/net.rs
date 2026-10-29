use futures_util::StreamExt;
use netbridge_proto::*;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use tokio::sync::mpsc::UnboundedSender;

pub const CHUNK: usize = 1024 * 1024;

#[derive(Debug, Clone, PartialEq)]
pub enum NetEvent {
    Connected,
    Disconnected(String),
    /// The server does not know this device key (released by an admin); log in again.
    Rejected,
    Event(Event),
}

/// Connection to this network's NetBridge server, pinned to the NetBridge CA.
pub struct Net {
    base: String,
    http: reqwest::Client,
    ws_tls: Arc<rustls::ClientConfig>,
    token: Mutex<Option<String>>,
}

fn offline(e: impl std::fmt::Display) -> ApiError {
    ApiError::new(ErrorCode::LinkDown, format!("서버에 연결할 수 없습니다 ({e})"))
}

pub fn tls_config(ca_pem: &Path) -> anyhow::Result<rustls::ClientConfig> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let data = std::fs::read(ca_pem).map_err(|e| anyhow::anyhow!("CA 인증서를 읽을 수 없습니다 ({}): {e}", ca_pem.display()))?;
    let mut roots = rustls::RootCertStore::empty();
    for c in rustls_pemfile::certs(&mut data.as_slice()) {
        roots.add(c?)?;
    }
    anyhow::ensure!(!roots.is_empty(), "CA 인증서 파일에 인증서가 없습니다");
    Ok(rustls::ClientConfig::builder().with_root_certificates(roots).with_no_client_auth())
}

pub fn sha256_file(path: &Path) -> std::io::Result<String> {
    use sha2::Digest;
    let mut h = sha2::Sha256::new();
    let mut f = std::fs::File::open(path)?;
    std::io::copy(&mut f, &mut h)?;
    Ok(hex::encode(h.finalize()))
}

/// `dir/name`, or `dir/name (n).ext` when that already exists.
pub fn unique_path(dir: &Path, name: &str) -> PathBuf {
    let p = dir.join(name);
    if !p.exists() {
        return p;
    }
    let (stem, ext) = match name.rsplit_once('.') {
        Some((s, e)) if !s.is_empty() => (s.to_string(), format!(".{e}")),
        _ => (name.to_string(), String::new()),
    };
    (1..).map(|n| dir.join(format!("{stem} ({n}){ext}"))).find(|p| !p.exists()).unwrap()
}

impl Net {
    pub fn new(server_url: &str, ca_pem: &Path) -> anyhow::Result<Net> {
        let tls = tls_config(ca_pem)?;
        let http = reqwest::Client::builder().use_preconfigured_tls(tls.clone()).connect_timeout(Duration::from_secs(10)).build()?;
        Ok(Net { base: server_url.trim().trim_end_matches('/').to_string(), http, ws_tls: Arc::new(tls), token: Mutex::new(None) })
    }

    pub fn base(&self) -> &str {
        &self.base
    }

    pub fn set_token(&self, t: Option<String>) {
        *self.token.lock().unwrap() = t;
    }

    pub fn token(&self) -> Option<String> {
        self.token.lock().unwrap().clone()
    }

    fn auth(&self, rb: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match self.token() {
            Some(t) => rb.bearer_auth(t),
            None => rb,
        }
    }

    async fn error_of(r: reqwest::Response) -> ApiError {
        let status = r.status();
        r.json::<ApiError>().await.unwrap_or_else(|_| ApiError::internal(format!("HTTP {status}")))
    }

    pub async fn hello(&self) -> Result<Hello, ApiError> {
        let r = self.http.get(format!("{}/hello", self.base)).timeout(Duration::from_secs(10)).send().await.map_err(offline)?;
        r.json().await.map_err(offline)
    }

    pub async fn call(&self, req: ApiRequest) -> ApiResult {
        let r = self.auth(self.http.post(format!("{}/api", self.base))).json(&req).send().await.map_err(offline)?;
        if r.status().is_success() {
            r.json().await.map_err(offline)
        } else {
            Err(Self::error_of(r).await)
        }
    }

    /// Uploads in 1 MiB chunks; on 409 or a dropped connection it resumes from what the server has.
    pub async fn upload(&self, id: i64, path: &Path, progress: impl Fn(u64) + Send) -> Result<(), ApiError> {
        let mut f = tokio::fs::File::open(path).await.map_err(|e| ApiError::bad(format!("파일을 열 수 없습니다: {e}")))?;
        let len = f.metadata().await.map_err(ApiError::internal)?.len();
        let mut pos = 0u64;
        let mut buf = vec![0u8; CHUNK];
        let mut failures = 0;
        loop {
            f.seek(std::io::SeekFrom::Start(pos)).await.map_err(ApiError::internal)?;
            let n = read_full(&mut f, &mut buf).await.map_err(ApiError::internal)?;
            if n == 0 && pos >= len {
                return Ok(());
            }
            let url = format!("{}/upload/{id}?offset={pos}", self.base);
            let res = self.auth(self.http.put(url)).body(buf[..n].to_vec()).send().await;
            let r = match res {
                Ok(r) => r,
                Err(e) => {
                    failures += 1;
                    if failures > 10 {
                        return Err(offline(e));
                    }
                    tokio::time::sleep(Duration::from_secs(failures.min(5))).await;
                    continue;
                }
            };
            failures = 0;
            let status = r.status();
            if status.is_success() || status.as_u16() == 409 {
                let v: serde_json::Value = r.json().await.map_err(offline)?;
                pos = v["have"].as_u64().unwrap_or(pos);
                progress(pos);
                if pos >= len {
                    return Ok(());
                }
            } else {
                return Err(Self::error_of(r).await);
            }
        }
    }

    /// Saves into `dir` under the transfer's name (never overwriting) and checks the SHA-256.
    pub async fn download(&self, t: &TransferInfo, dir: &Path, progress: impl Fn(u64) + Send) -> Result<PathBuf, ApiError> {
        tokio::fs::create_dir_all(dir).await.map_err(|e| ApiError::bad(format!("저장 폴더를 만들 수 없습니다: {e}")))?;
        let part = dir.join(format!(".netbridge-{}.part", t.id));
        let mut have = tokio::fs::metadata(&part).await.map(|m| m.len()).unwrap_or(0);
        if have > t.size {
            let _ = tokio::fs::remove_file(&part).await;
            have = 0;
        }
        let mut rb = self.auth(self.http.get(format!("{}/download/{}", self.base, t.id)));
        if have > 0 {
            rb = rb.header(reqwest::header::RANGE, format!("bytes={have}-"));
        }
        let r = rb.send().await.map_err(offline)?;
        if !r.status().is_success() {
            return Err(Self::error_of(r).await);
        }
        if r.status().as_u16() != 206 {
            have = 0;
        }
        let mut f = tokio::fs::OpenOptions::new().create(true).write(true).append(have > 0).truncate(have == 0).open(&part).await.map_err(ApiError::internal)?;
        let mut done = have;
        let mut s = r.bytes_stream();
        while let Some(chunk) = s.next().await {
            let chunk = chunk.map_err(offline)?;
            f.write_all(&chunk).await.map_err(ApiError::internal)?;
            done += chunk.len() as u64;
            progress(done);
        }
        f.flush().await.map_err(ApiError::internal)?;
        drop(f);
        let p = part.clone();
        let sha = tokio::task::spawn_blocking(move || sha256_file(&p)).await.map_err(ApiError::internal)?.map_err(ApiError::internal)?;
        if sha != t.sha256 {
            let _ = tokio::fs::remove_file(&part).await;
            return Err(ApiError::new(ErrorCode::Conflict, "받은 파일이 손상되었습니다. 다시 받으세요"));
        }
        let dest = unique_path(dir, &t.file_name);
        tokio::fs::rename(&part, &dest).await.map_err(ApiError::internal)?;
        Ok(dest)
    }

    /// Keeps a device WebSocket open, reconnecting with backoff (1s → 30s). Never ends the session.
    pub fn spawn_events(self: Arc<Self>, device_key: String, tx: UnboundedSender<NetEvent>) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut backoff = 1u64;
            loop {
                use tokio_tungstenite::tungstenite::client::IntoClientRequest;
                let url = format!("{}/ws", self.base.replacen("https://", "wss://", 1));
                let mut req = url.into_client_request().expect("url");
                // a header, not the query string, so the key never lands in access logs
                match device_key.parse() {
                    Ok(v) => req.headers_mut().insert(DEVICE_KEY_HEADER, v),
                    Err(_) => {
                        let _ = tx.send(NetEvent::Rejected);
                        return;
                    }
                };
                let connector = tokio_tungstenite::Connector::Rustls(self.ws_tls.clone());
                match tokio_tungstenite::connect_async_tls_with_config(req, None, false, Some(connector)).await {
                    Ok((mut ws, _)) => {
                        backoff = 1;
                        if tx.send(NetEvent::Connected).is_err() {
                            return;
                        }
                        // the server pings every 20s
                        let reason = loop {
                            match tokio::time::timeout(Duration::from_secs(60), ws.next()).await {
                                Ok(Some(Ok(tokio_tungstenite::tungstenite::Message::Text(t)))) => {
                                    if let Ok(ev) = serde_json::from_str::<Event>(t.as_str()) {
                                        if tx.send(NetEvent::Event(ev)).is_err() {
                                            return;
                                        }
                                    }
                                }
                                Ok(Some(Ok(tokio_tungstenite::tungstenite::Message::Close(_)))) | Ok(None) => break "서버가 연결을 닫았습니다".to_string(),
                                Ok(Some(Ok(_))) => {}
                                Ok(Some(Err(e))) => break e.to_string(),
                                Err(_) => break "응답 없음".to_string(),
                            }
                        };
                        if tx.send(NetEvent::Disconnected(reason)).is_err() {
                            return;
                        }
                    }
                    Err(tokio_tungstenite::tungstenite::Error::Http(resp)) if resp.status().as_u16() == 401 => {
                        let _ = tx.send(NetEvent::Rejected);
                        return;
                    }
                    Err(e) => {
                        if tx.send(NetEvent::Disconnected(e.to_string())).is_err() {
                            return;
                        }
                    }
                }
                tokio::time::sleep(Duration::from_secs(backoff)).await;
                backoff = (backoff * 2).min(30);
            }
        })
    }
}

async fn read_full(f: &mut tokio::fs::File, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut n = 0;
    while n < buf.len() {
        let m = f.read(&mut buf[n..]).await?;
        if m == 0 {
            break;
        }
        n += m;
    }
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unique_path_appends_counter() {
        let d = tempfile::tempdir().unwrap();
        assert_eq!(unique_path(d.path(), "a.txt"), d.path().join("a.txt"));
        std::fs::write(d.path().join("a.txt"), "").unwrap();
        assert_eq!(unique_path(d.path(), "a.txt"), d.path().join("a (1).txt"));
        std::fs::write(d.path().join("a (1).txt"), "").unwrap();
        assert_eq!(unique_path(d.path(), "a.txt"), d.path().join("a (2).txt"));
        std::fs::write(d.path().join("noext"), "").unwrap();
        assert_eq!(unique_path(d.path(), "noext"), d.path().join("noext (1)"));
    }
}

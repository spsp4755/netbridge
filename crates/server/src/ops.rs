//! Operator commands that work on a stopped or running server: backup and status.
use crate::config::ServerConfig;
use crate::core::{kst, to_kst};
use anyhow::{ensure, Context, Result};
use chrono::TimeZone;
use std::fmt::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Consistent copy of the live database (`VACUUM INTO`), safe while the server runs.
/// Default target: `<data_dir>/backup/netbridge-YYYYMMDD-HHMMSS.db` (KST). Never overwrites.
pub fn backup(cfg: &ServerConfig, out: Option<&Path>) -> Result<PathBuf> {
    ensure!(cfg.is_hub(), "백업할 DB는 중앙 연계서버에만 있습니다");
    let db = cfg.db_path();
    ensure!(db.exists(), "DB 파일이 없습니다: {}", db.display());
    let out = match out {
        Some(p) => p.to_path_buf(),
        None => cfg.data_dir.join("backup").join(format!("netbridge-{}.db", to_kst(chrono::Utc::now().timestamp()).format("%Y%m%d-%H%M%S"))),
    };
    ensure!(!out.exists(), "이미 있는 파일입니다: {}", out.display());
    if let Some(d) = out.parent().filter(|d| !d.as_os_str().is_empty()) {
        std::fs::create_dir_all(d)?;
    }
    let c = rusqlite::Connection::open(&db)?;
    c.busy_timeout(Duration::from_secs(30))?;
    c.execute("VACUUM INTO ?1", [out.to_string_lossy()]).with_context(|| format!("백업 실패: {}", out.display()))?;
    Ok(out)
}

fn file_state(p: &Path) -> &'static str {
    if p.is_file() { "있음" } else { "없음" }
}

/// Human-readable summary for `netbridge-server status`.
pub fn status(cfg: &ServerConfig) -> Result<String> {
    let mut s = String::new();
    writeln!(s, "NetBridge 연계서버 {}", env!("CARGO_PKG_VERSION"))?;
    writeln!(s, "구분: {} (망 {})", if cfg.is_hub() { "중앙 서버" } else { "망 서버" }, cfg.network)?;
    writeln!(s, "앱 접속 주소: {}", cfg.listen)?;
    writeln!(s, "데이터 폴더: {}", cfg.data_dir.display())?;
    writeln!(s, "로그 폴더: {} ({}일 보관)", cfg.log_dir.display(), cfg.log_keep_days)?;
    let mut files = vec![("서버 인증서", &cfg.tls_cert), ("서버 키", &cfg.tls_key), ("CA 인증서", &cfg.ca_cert)];
    files.extend(cfg.client_cert.iter().map(|p| ("연계 인증서", p)));
    files.extend(cfg.client_key.iter().map(|p| ("연계 키", p)));
    for (label, p) in files {
        writeln!(s, "{label}: {} ({})", p.display(), file_state(p))?;
    }
    match cfg.is_hub() {
        true => {
            let db = cfg.db_path();
            if db.exists() {
                let c = rusqlite::Connection::open(&db)?;
                c.busy_timeout(Duration::from_secs(5))?;
                let users: i64 = c.query_row("SELECT COUNT(*) FROM users", [], |r| r.get(0))?;
                let day = to_kst(chrono::Utc::now().timestamp()).date_naive();
                let start = kst().from_local_datetime(&day.and_hms_opt(0, 0, 0).unwrap()).unwrap().timestamp();
                let today: i64 = c.query_row("SELECT COUNT(*) FROM transfers WHERE created_at>=?1", [start], |r| r.get(0))?;
                writeln!(s, "DB: {}", db.display())?;
                writeln!(s, "사용자: {users}")?;
                writeln!(s, "오늘 전송: {today}")?;
            } else {
                writeln!(s, "DB: {} (없음 — 서버를 한 번 실행하면 만들어집니다)", db.display())?;
            }
            for l in &cfg.links {
                writeln!(s, "망 {} 연계 주소: {} ({})", l.network, l.url, probe(&l.url))?;
            }
        }
        false => {
            writeln!(s, "연계 구간 주소: {}", cfg.link_listen.map(|a| a.to_string()).unwrap_or_default())?;
            for n in &cfg.neighbors {
                writeln!(s, "이웃 망 {} 연계 주소: {} ({})", n.network, n.url, probe(&n.url))?;
            }
        }
    }
    Ok(s)
}

/// TCP reachability of the external server's link port (TLS is not checked).
fn probe(url: &str) -> String {
    let addr = reqwest::Url::parse(url).ok().and_then(|u| u.socket_addrs(|| Some(443)).ok()).and_then(|a| a.into_iter().next());
    let Some(addr) = addr else { return "주소 형식 오류".into() };
    match std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(3)) {
        Ok(_) => "연결 가능".into(),
        Err(e) => format!("연결 안 됨: {e}"),
    }
}

use anyhow::Context;
use clap::{Parser, Subcommand};
use netbridge_proto::{Role, UserInput};
use netbridge_server::config::ServerConfig;
use netbridge_server::core::{hash_password, Core};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "netbridge-server", version, about = "NetBridge 망연계 연계서버")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// 서버를 실행합니다
    Run {
        #[arg(long, default_value = "server.toml")]
        config: PathBuf,
    },
    /// CA와 외부·내부·연계 인증서를 만듭니다
    GenCerts {
        #[arg(long, default_value = "certs")]
        out: PathBuf,
        /// 외부 연계서버 주소 (IP 또는 도메인, 여러 개 가능)
        #[arg(long = "external-host", required = true)]
        external: Vec<String>,
        /// 내부 연계서버 주소 (IP 또는 도메인, 여러 개 가능)
        #[arg(long = "internal-host", required = true)]
        internal: Vec<String>,
    },
    /// 내부 서버에 관리자 계정을 만들거나 비밀번호를 다시 정합니다
    InitAdmin {
        #[arg(long, default_value = "server.toml")]
        config: PathBuf,
        #[arg(long)]
        username: String,
        #[arg(long)]
        password: String,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt().with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into())).init();
    match Cli::parse().cmd {
        Cmd::Run { config } => {
            let cfg = ServerConfig::load(&config)?;
            let _running = netbridge_server::server::start(cfg).await?;
            tokio::signal::ctrl_c().await?;
            Ok(())
        }
        Cmd::GenCerts { out, external, internal } => {
            netbridge_server::certs::gen_certs(&out, &external, &internal)?;
            println!("인증서를 만들었습니다: {}", out.display());
            println!("- ca.pem          : 모든 앱과 서버에 배포 (ca.key는 안전한 곳에 따로 보관)");
            println!("- external.pem/key: 외부 연계서버");
            println!("- internal.pem/key: 내부 연계서버");
            println!("- link-client.*   : 내부 연계서버 (연계 구간 접속용)");
            Ok(())
        }
        Cmd::InitAdmin { config, username, password } => {
            let cfg = ServerConfig::load(&config)?;
            anyhow::ensure!(cfg.side == netbridge_proto::Side::Internal, "관리자 계정은 내부 연계서버에서 만듭니다");
            let db = netbridge_server::db::Db::open(&cfg.data_dir.join("netbridge.db"))?;
            let exists: Option<i64> = db
                .with(|c| {
                    use rusqlite::OptionalExtension;
                    c.query_row("SELECT id FROM users WHERE username=?1", [&username], |r| r.get(0)).optional()
                })
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            match exists {
                Some(id) => {
                    db.with(|c| c.execute("UPDATE users SET pw_hash=?2, role='admin', locked=0, fail_count=0, must_change=0 WHERE id=?1", rusqlite::params![id, hash_password(&password)]))
                        .map_err(|e| anyhow::anyhow!("{e}"))?;
                    println!("관리자 {username}의 비밀번호를 다시 정했습니다");
                }
                None => {
                    let core = Core::new(db, cfg.data_dir.clone(), std::sync::Arc::new(NoPeer)).context("init")?;
                    let id = core
                        .create_user(&UserInput { id: None, username: username.clone(), name: "관리자".into(), dept_id: None, role: Role::Admin, approver_id: None, password: Some(password) })
                        .map_err(|e| anyhow::anyhow!("{e}"))?;
                    core.clear_must_change(id).map_err(|e| anyhow::anyhow!("{e}"))?;
                    println!("관리자 {username}을 만들었습니다");
                }
            }
            Ok(())
        }
    }
}

/// Peer for offline CLI commands that never touch the external server.
struct NoPeer;

#[async_trait::async_trait]
impl netbridge_server::core::Peer for NoPeer {
    async fn scan(&self, _: i64, _: &str, _: &netbridge_proto::Policy) -> Result<netbridge_server::core::ScanResult, netbridge_proto::ApiError> {
        Err(netbridge_server::link::link_down())
    }
    async fn fetch_file(&self, _: i64, _: &std::path::Path) -> Result<(), netbridge_proto::ApiError> {
        Err(netbridge_server::link::link_down())
    }
    async fn push_file(&self, _: i64, _: &std::path::Path) -> Result<(), netbridge_proto::ApiError> {
        Err(netbridge_server::link::link_down())
    }
    async fn delete_file(&self, _: i64) -> Result<(), netbridge_proto::ApiError> {
        Ok(())
    }
    async fn push_event(&self, _: i64, _: netbridge_proto::Event) -> Result<bool, netbridge_proto::ApiError> {
        Ok(false)
    }
    async fn online_devices(&self) -> Result<Vec<i64>, netbridge_proto::ApiError> {
        Ok(vec![])
    }
    async fn drop_device(&self, _: i64) -> Result<(), netbridge_proto::ApiError> {
        Ok(())
    }
}

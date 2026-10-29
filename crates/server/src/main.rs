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
        /// Windows 서비스 관리자가 실행할 때 씁니다 (install-service가 넣어 줌)
        #[arg(long, hide = true)]
        service: Option<String>,
    },
    /// CA와 외부·내부·연계 인증서를 만듭니다
    GenCerts {
        #[arg(long, default_value = "certs")]
        out: PathBuf,
        /// 외부 연계서버 주소 (두 망 구성, IP 또는 도메인, 여러 개 가능)
        #[arg(long = "external-host")]
        external: Vec<String>,
        /// 내부 연계서버 주소 (두 망 구성)
        #[arg(long = "internal-host")]
        internal: Vec<String>,
        /// 여러 망 구성: 망ID=주소[,주소...] (예: --server A=10.0.1.10 --server B=10.0.2.10). <망ID>.pem/.key 를 만듭니다
        #[arg(long = "server")]
        servers: Vec<String>,
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
    /// 내부 서버 DB를 실행 중에도 안전하게 백업합니다
    Backup {
        #[arg(long, default_value = "server.toml")]
        config: PathBuf,
        /// 백업 파일 경로 (기본: <data_dir>/backup/netbridge-날짜-시각.db)
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// 버전, DB, 사용자 수, 오늘 전송 건수, 연계 설정을 보여 줍니다
    Status {
        #[arg(long, default_value = "server.toml")]
        config: PathBuf,
    },
    /// Windows 서비스로 등록합니다 (관리자 권한, 자동 시작)
    InstallService {
        /// 설정 파일 (절대 경로로 바꿔 등록합니다)
        #[arg(long)]
        config: PathBuf,
        /// 서비스 이름 (기본: NetBridge-Internal 또는 NetBridge-External)
        #[arg(long)]
        name: Option<String>,
    },
    /// Windows 서비스 등록을 지웁니다 (실행 중이면 멈춤)
    UninstallService {
        #[arg(long)]
        name: String,
    },
}

/// Logs to stdout and, when `cfg` is given, to daily files in its log_dir.
fn init_logs(cfg: Option<&ServerConfig>) -> anyhow::Result<Option<tracing_appender::non_blocking::WorkerGuard>> {
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;
    let filter = tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into());
    let stdout = tracing_subscriber::fmt::layer();
    let Some(cfg) = cfg else {
        tracing_subscriber::registry().with(filter).with(stdout).init();
        return Ok(None);
    };
    std::fs::create_dir_all(&cfg.log_dir).with_context(|| format!("로그 폴더를 만들 수 없습니다: {}", cfg.log_dir.display()))?;
    let appender = tracing_appender::rolling::Builder::new()
        .rotation(tracing_appender::rolling::Rotation::DAILY)
        .filename_prefix("netbridge-server")
        .filename_suffix("log")
        .max_log_files(cfg.log_keep_days.max(1))
        .build(&cfg.log_dir)?;
    let (writer, guard) = tracing_appender::non_blocking(appender);
    tracing_subscriber::registry().with(filter).with(stdout).with(tracing_subscriber::fmt::layer().with_writer(writer).with_ansi(false)).init();
    Ok(Some(guard))
}

/// Runs the server until `stop` resolves, then shuts the listeners down.
fn run_server(cfg: ServerConfig, stop: impl std::future::Future<Output = ()>) -> anyhow::Result<()> {
    tokio::runtime::Runtime::new()?.block_on(async {
        let running = netbridge_server::server::start(cfg).await?;
        stop.await;
        tracing::info!("stopping");
        running.shutdown();
        Ok(())
    })
}

/// Ctrl+C, or SIGTERM from systemd.
async fn stop_signal() {
    #[cfg(unix)]
    {
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).expect("SIGTERM handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = term.recv() => {}
        }
    }
    #[cfg(not(unix))]
    let _ = tokio::signal::ctrl_c().await;
}

fn main() -> anyhow::Result<()> {
    match Cli::parse().cmd {
        Cmd::Run { config, service } => {
            let cfg = ServerConfig::load(&config)?;
            let _guard = init_logs(Some(&cfg))?;
            match service {
                Some(name) => run_service(name, cfg),
                None => run_server(cfg, stop_signal()),
            }
        }
        Cmd::GenCerts { out, external, internal, servers } => {
            let mut named: Vec<(String, Vec<String>)> = vec![];
            for s in &servers {
                let (id, hosts) = s.split_once('=').context("--server 는 망ID=주소 형식입니다")?;
                named.push((id.trim().to_string(), hosts.split(',').map(|h| h.trim().to_string()).filter(|h| !h.is_empty()).collect()));
            }
            if !external.is_empty() {
                named.push(("external".into(), external));
            }
            if !internal.is_empty() {
                named.push(("internal".into(), internal));
            }
            anyhow::ensure!(!named.is_empty(), "--server 망ID=주소 (여러 망) 또는 --external-host/--internal-host (두 망) 가 필요합니다");
            netbridge_server::certs::gen_certs_named(&out, &named)?;
            println!("인증서를 만들었습니다: {}", out.display());
            println!("- ca.pem        : 모든 앱과 서버에 배포 (ca.key는 안전한 곳에 따로 보관)");
            for (id, _) in &named {
                println!("- {id}.pem/key : 망 {id} 연계서버 (설정의 tls_cert/tls_key)");
            }
            println!("- link-client.* : 중앙 서버와, 이웃 망으로 직접 보내는 망 서버 (연계 구간 접속용)");
            Ok(())
        }
        Cmd::InitAdmin { config, username, password } => init_admin(&config, username, password),
        Cmd::Backup { config, out } => {
            let cfg = ServerConfig::load(&config)?;
            let p = netbridge_server::ops::backup(&cfg, out.as_deref())?;
            println!("백업했습니다: {}", p.display());
            Ok(())
        }
        Cmd::Status { config } => {
            let cfg = ServerConfig::load(&config)?;
            print!("{}", netbridge_server::ops::status(&cfg)?);
            Ok(())
        }
        Cmd::InstallService { config, name } => {
            let config = std::path::absolute(&config)?;
            let cfg = ServerConfig::load(&config)?;
            let name = name.unwrap_or_else(|| {
                format!(
                    "NetBridge-{}",
                    if cfg.network == netbridge_proto::NetId::internal() {
                        "Internal".to_string()
                    } else if cfg.network == netbridge_proto::NetId::external() {
                        "External".to_string()
                    } else {
                        cfg.network.to_string()
                    }
                )
            });
            install_service(&name, &config)
        }
        Cmd::UninstallService { name } => uninstall_service(&name),
    }
}

#[cfg(windows)]
fn run_service(name: String, cfg: ServerConfig) -> anyhow::Result<()> {
    netbridge_server::winsvc::run(
        name,
        Box::new(move |stop| {
            run_server(cfg, async move {
                let _ = stop.await;
            })
        }),
    )
}

#[cfg(windows)]
fn install_service(name: &str, config: &std::path::Path) -> anyhow::Result<()> {
    netbridge_server::winsvc::install(name, &std::env::current_exe()?, config)?;
    println!("서비스 {name}을 등록하고 시작했습니다 (자동 시작). 로그는 설정 파일 옆 logs 폴더에 남습니다.");
    Ok(())
}

#[cfg(windows)]
fn uninstall_service(name: &str) -> anyhow::Result<()> {
    netbridge_server::winsvc::uninstall(name)?;
    println!("서비스 {name}을 지웠습니다");
    Ok(())
}

const NOT_WINDOWS: &str = "Windows 서비스 명령은 Windows에서만 쓸 수 있습니다. Linux에서는 deploy/netbridge-server.service (systemd) 예시를 쓰세요";

#[cfg(not(windows))]
fn run_service(_: String, _: ServerConfig) -> anyhow::Result<()> {
    anyhow::bail!(NOT_WINDOWS)
}

#[cfg(not(windows))]
fn install_service(_: &str, _: &std::path::Path) -> anyhow::Result<()> {
    anyhow::bail!(NOT_WINDOWS)
}

#[cfg(not(windows))]
fn uninstall_service(_: &str) -> anyhow::Result<()> {
    anyhow::bail!(NOT_WINDOWS)
}

fn init_admin(config: &std::path::Path, username: String, password: String) -> anyhow::Result<()> {
    let cfg = ServerConfig::load(config)?;
    anyhow::ensure!(cfg.is_hub(), "관리자 계정은 중앙 연계서버에서 만듭니다");
    let db = netbridge_server::db::Db::open(&cfg.db_path())?;
    let exists: Option<i64> = db
        .with(|c| {
            use rusqlite::OptionalExtension;
            c.query_row("SELECT id FROM users WHERE username=?1", [&username], |r| r.get(0)).optional()
        })
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    match exists {
        Some(id) => {
            db.with(|c| c.execute("UPDATE users SET pw_hash=?2, role='admin', locked=0, fail_count=0, must_change=0 WHERE id=?1", rusqlite::params![id, hash_password(&password)])).map_err(|e| anyhow::anyhow!("{e}"))?;
            // like an admin reset in the app: sessions opened with the old password end
            db.with(|c| c.execute("UPDATE sessions SET ended_at=?2, end_reason='비밀번호 재설정' WHERE user_id=?1 AND ended_at IS NULL", rusqlite::params![id, chrono::Utc::now().timestamp()]))
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            println!("관리자 {username}의 비밀번호를 다시 정했습니다");
        }
        None => {
            let core = Core::new(db, cfg.data_dir.clone(), cfg.network.clone(), cfg.topology.clone().unwrap(), Default::default()).context("init")?;
            let id = core
                .create_user(&UserInput { id: None, username: username.clone(), name: "관리자".into(), dept_id: None, role: Role::Admin, approver_id: None, password: Some(password), networks: vec![] })
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            core.clear_must_change(id).map_err(|e| anyhow::anyhow!("{e}"))?;
            println!("관리자 {username}을 만들었습니다");
        }
    }
    Ok(())
}

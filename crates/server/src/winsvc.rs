//! Windows service: registration and the SCM entry point for `run --service <name>`.
use anyhow::{Context, Result};
use std::ffi::OsString;
use std::path::Path;
use std::sync::Mutex;
use std::time::Duration;
use windows_service::service::{
    ServiceAccess, ServiceAction, ServiceActionType, ServiceControl, ServiceControlAccept, ServiceErrorControl, ServiceExitCode, ServiceFailureActions, ServiceFailureResetPeriod,
    ServiceInfo, ServiceStartType, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_dispatcher;
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

/// The server body; it returns once the receiver fires (SCM Stop).
pub type Body = Box<dyn FnOnce(tokio::sync::oneshot::Receiver<()>) -> Result<()> + Send>;

static PENDING: Mutex<Option<(String, Body)>> = Mutex::new(None);

pub fn install(name: &str, exe: &Path, config: &Path) -> Result<()> {
    let m = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE).context("서비스 관리자에 연결할 수 없습니다 (관리자 권한으로 실행하세요)")?;
    let info = ServiceInfo {
        name: name.into(),
        display_name: OsString::from(format!("NetBridge 연계서버 ({name})")),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: exe.to_path_buf(),
        launch_arguments: vec!["run".into(), "--config".into(), config.as_os_str().to_owned(), "--service".into(), name.into()],
        dependencies: vec![],
        account_name: None, // LocalSystem
        account_password: None,
    };
    let svc = m.create_service(&info, ServiceAccess::CHANGE_CONFIG | ServiceAccess::START).with_context(|| format!("서비스 {name}을 만들 수 없습니다"))?;
    svc.set_description("NetBridge 망연계 자료전송 연계서버")?;
    // restart after a crash or an error exit: 10s, 30s, then every 60s; counter resets after a day
    let restart = |s| ServiceAction { action_type: ServiceActionType::Restart, delay: Duration::from_secs(s) };
    svc.update_failure_actions(ServiceFailureActions {
        reset_period: ServiceFailureResetPeriod::After(Duration::from_secs(86400)),
        reboot_msg: None,
        command: None,
        actions: Some(vec![restart(10), restart(30), restart(60)]),
    })?;
    svc.set_failure_actions_on_non_crash_failures(true)?;
    svc.start::<&str>(&[]).with_context(|| format!("서비스 {name}을 시작할 수 없습니다. 로그 폴더를 확인하세요"))?;
    Ok(())
}

pub fn uninstall(name: &str) -> Result<()> {
    let m = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT).context("서비스 관리자에 연결할 수 없습니다 (관리자 권한으로 실행하세요)")?;
    let svc = m.open_service(name, ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE).with_context(|| format!("서비스 {name}이 없습니다"))?;
    if svc.query_status()?.current_state != ServiceState::Stopped {
        let _ = svc.stop();
        for _ in 0..30 {
            if svc.query_status()?.current_state == ServiceState::Stopped {
                break;
            }
            std::thread::sleep(Duration::from_secs(1));
        }
    }
    svc.delete()?;
    Ok(())
}

/// Hands the process to the service dispatcher; blocks until the service stops.
pub fn run(name: String, body: Body) -> Result<()> {
    *PENDING.lock().unwrap() = Some((name.clone(), body));
    service_dispatcher::start(&name, ffi_service_main).context("서비스 관리자가 실행한 경우에만 --service를 쓸 수 있습니다")?;
    Ok(())
}

windows_service::define_windows_service!(ffi_service_main, service_main);

fn service_main(_args: Vec<OsString>) {
    let Some((name, body)) = PENDING.lock().unwrap().take() else { return };
    let (tx, rx) = tokio::sync::oneshot::channel();
    let tx = Mutex::new(Some(tx));
    let handler = move |ev: ServiceControl| match ev {
        ServiceControl::Stop | ServiceControl::Shutdown => {
            if let Some(tx) = tx.lock().unwrap().take() {
                let _ = tx.send(());
            }
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    };
    let Ok(status) = service_control_handler::register(&name, handler) else { return };
    let set = |state, accept, code| {
        let _ = status.set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: state,
            controls_accepted: accept,
            exit_code: ServiceExitCode::Win32(code),
            checkpoint: 0,
            wait_hint: Duration::from_secs(10),
            process_id: None,
        });
    };
    set(ServiceState::Running, ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN, 0);
    let res = body(rx);
    if let Err(e) = &res {
        tracing::error!("service stopped with error: {e:#}");
    }
    // non-zero exit code so SCM recovery actions (restart) can fire
    set(ServiceState::Stopped, ServiceControlAccept::empty(), if res.is_ok() { 0 } else { 1 });
}

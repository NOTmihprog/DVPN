//! The node as a Windows service (`dvpn service install`): starts with the system as
//! LocalSystem, restarts after a failure, logs to `dvpn.log` next to `config.toml`; a stop or
//! the system shutting down ends it as Ctrl+C does (routes and DNS rules removed).

use std::ffi::OsString;
use std::io::Write as _;
use std::path::Path;
use std::sync::Mutex;
use std::time::Duration;

use windows_service::service::{
    ServiceAccess, ServiceAction, ServiceActionType, ServiceControl, ServiceControlAccept, ServiceErrorControl,
    ServiceExitCode, ServiceFailureActions, ServiceFailureResetPeriod, ServiceInfo, ServiceStartType, ServiceState,
    ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
use windows_service::{define_windows_service, service_dispatcher};

pub const NAME: &str = "dvpn";

/// The node's run, given the signal to stop.
pub type Body = Box<dyn FnOnce(tokio::sync::oneshot::Receiver<()>) + Send>;

static BODY: Mutex<Option<Body>> = Mutex::new(None);

define_windows_service!(ffi_service_main, service_main);

/// Runs as the service (`dvpn service run`, what the service manager starts): returns when it
/// has stopped. An error when not started by the service manager.
pub fn dispatch(body: Body) -> windows_service::Result<()> {
    *BODY.lock().unwrap_or_else(|e| e.into_inner()) = Some(body);
    service_dispatcher::start(NAME, ffi_service_main)
}

fn status(state: ServiceState, accept: ServiceControlAccept) -> ServiceStatus {
    ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: state,
        controls_accepted: accept,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::from_secs(15),
        process_id: None,
    }
}

fn service_main(_args: Vec<OsString>) {
    let (tx, rx) = tokio::sync::oneshot::channel();
    let tx = Mutex::new(Some(tx));
    let handler = move |c| match c {
        ServiceControl::Stop | ServiceControl::Shutdown => {
            if let Some(t) = tx.lock().unwrap_or_else(|e| e.into_inner()).take() {
                let _ = t.send(());
            }
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    };
    let Ok(h) = service_control_handler::register(NAME, handler) else { return };
    let _ = h
        .set_service_status(status(ServiceState::Running, ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN));
    if let Some(body) = BODY.lock().unwrap_or_else(|e| e.into_inner()).take() {
        body(rx);
    }
    let _ = h.set_service_status(status(ServiceState::Stopped, ServiceControlAccept::empty()));
}

/// The service's log: `dvpn.log` in the config directory, started afresh past 10 MiB.
pub fn log_to_file(dir: &Path) {
    let path = dir.join("dvpn.log");
    if std::fs::metadata(&path).is_ok_and(|m| m.len() > 10 << 20) {
        let _ = std::fs::rename(&path, dir.join("dvpn.log.old"));
    }
    let Ok(file) = std::fs::OpenOptions::new().create(true).append(true).open(&path) else { return };
    let file = Mutex::new(file);
    dvpn::logger::set_sink(Box::new(move |level, text| {
        let now = chrono::Local::now().format("%Y-%m-%d %H:%M:%S%.3f");
        let mut f = file.lock().unwrap_or_else(|e| e.into_inner());
        let _ = writeln!(f, "{now} {level:<5} {text}");
    }));
}

fn manager(access: ServiceManagerAccess) -> windows_service::Result<ServiceManager> {
    ServiceManager::local_computer(None::<&str>, access)
}

/// Registers and starts the service for the node in `dir`.
pub fn install(dir: &Path) -> windows_service::Result<()> {
    let m = manager(ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE)?;
    let exe = std::env::current_exe().map_err(windows_service::Error::Winapi)?;
    let info = ServiceInfo {
        name: NAME.into(),
        display_name: "DVPN".into(),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: exe,
        launch_arguments: vec!["--dir".into(), dir.as_os_str().to_owned(), "service".into(), "run".into()],
        dependencies: vec![],
        account_name: None, // LocalSystem
        account_password: None,
    };
    let s = m.create_service(&info, ServiceAccess::CHANGE_CONFIG | ServiceAccess::START)?;
    s.set_description("DVPN node: decentralized VPN (dvpn.log next to config.toml)")?;
    let restart = ServiceAction { action_type: ServiceActionType::Restart, delay: Duration::from_secs(5) };
    s.update_failure_actions(ServiceFailureActions {
        reset_period: ServiceFailureResetPeriod::After(Duration::from_secs(24 * 3600)),
        reboot_msg: None,
        command: None,
        actions: Some(vec![restart.clone(), restart.clone(), restart]),
    })?;
    s.start::<&str>(&[])
}

/// Waits until the service reports `state` (up to 20 s).
fn wait_for(s: &windows_service::service::Service, state: ServiceState) -> windows_service::Result<bool> {
    for _ in 0..80 {
        if s.query_status()?.current_state == state {
            return Ok(true);
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    Ok(false)
}

/// Stops (if running) and removes the service.
pub fn uninstall() -> windows_service::Result<()> {
    let m = manager(ServiceManagerAccess::CONNECT)?;
    let s = m.open_service(NAME, ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE)?;
    if s.query_status()?.current_state != ServiceState::Stopped {
        let _ = s.stop();
        wait_for(&s, ServiceState::Stopped)?;
    }
    s.delete()
}

pub fn start() -> windows_service::Result<bool> {
    let m = manager(ServiceManagerAccess::CONNECT)?;
    let s = m.open_service(NAME, ServiceAccess::QUERY_STATUS | ServiceAccess::START)?;
    s.start::<&str>(&[])?;
    wait_for(&s, ServiceState::Running)
}

pub fn stop() -> windows_service::Result<bool> {
    let m = manager(ServiceManagerAccess::CONNECT)?;
    let s = m.open_service(NAME, ServiceAccess::QUERY_STATUS | ServiceAccess::STOP)?;
    s.stop()?;
    wait_for(&s, ServiceState::Stopped)
}

/// The service's state, `None` when it is not installed.
pub fn state() -> windows_service::Result<Option<ServiceState>> {
    let m = manager(ServiceManagerAccess::CONNECT)?;
    match m.open_service(NAME, ServiceAccess::QUERY_STATUS) {
        Ok(s) => Ok(Some(s.query_status()?.current_state)),
        Err(windows_service::Error::Winapi(e)) if e.raw_os_error() == Some(1060) => Ok(None), // not installed
        Err(e) => Err(e),
    }
}

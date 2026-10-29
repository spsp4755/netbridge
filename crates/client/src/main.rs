#![cfg_attr(windows, windows_subsystem = "windows")]

mod app;
mod fonts;
mod hotkey;
mod icon;
#[cfg(windows)]
mod single;
mod theme;
#[cfg(windows)]
mod tray;
mod ui;

fn main() -> eframe::Result<()> {
    // a GUI-subsystem exe has no console: keep panics in %APPDATA%\NetBridge\crash.log
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let dir = netbridge_clientcore::config::config_dir();
        let _ = std::fs::create_dir_all(&dir);
        let line = format!("{} {info}\n{}\n", chrono::Utc::now().to_rfc3339(), std::backtrace::Backtrace::force_capture());
        let _ = std::fs::OpenOptions::new().create(true).append(true).open(dir.join("crash.log")).and_then(|mut f| std::io::Write::write_all(&mut f, line.as_bytes()));
        default_hook(info);
    }));
    #[cfg(windows)]
    let Some(instance) = single::acquire() else {
        // another copy is running: it has been asked to show its window
        return Ok(());
    };
    let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().expect("tokio runtime");
    let handle = rt.handle().clone();
    let minimized = std::env::args().any(|a| a == "--minimized");
    let options = eframe::NativeOptions {
        viewport: eframe::egui::ViewportBuilder::default().with_title("NetBridge 자료전송").with_inner_size([1240.0, 800.0]).with_min_inner_size([960.0, 600.0]).with_icon(icon::icon_data()),
        ..Default::default()
    };
    let result = eframe::run_native(
        "NetBridge",
        options,
        Box::new(move |cc| {
            if minimized {
                // started from the Windows startup folder: stay in the tray
                let cmd = if cfg!(windows) { eframe::egui::ViewportCommand::Visible(false) } else { eframe::egui::ViewportCommand::Minimized(true) };
                cc.egui_ctx.send_viewport_cmd(cmd);
            }
            #[cfg(windows)]
            instance.on_show(cc.egui_ctx.clone());
            Ok(Box::new(app::App::new(cc, handle)))
        }),
    );
    drop(rt);
    result
}

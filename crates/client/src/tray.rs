//! Windows tray icon: closing the window hides it here; the menu reopens, logs out or quits.
use crate::app::Job;
use eframe::egui::{self, ViewportCommand};
use std::sync::mpsc::Sender;
use tray_icon::menu::{Menu, MenuEvent, MenuItem, PredefinedMenuItem};
use tray_icon::{TrayIcon, TrayIconBuilder, TrayIconEvent};

/// Keeps the tray icon alive; dropping it removes the icon.
pub struct Tray {
    _icon: TrayIcon,
}

fn show(ctx: &egui::Context) {
    ctx.send_viewport_cmd(ViewportCommand::Visible(true));
    ctx.send_viewport_cmd(ViewportCommand::Minimized(false));
    ctx.send_viewport_cmd(ViewportCommand::Focus);
    ctx.request_repaint();
}

pub fn create(ctx: egui::Context, tx: Sender<Job>) -> Option<Tray> {
    let open = MenuItem::new("열기", true, None);
    let logout = MenuItem::new("로그아웃", true, None);
    let quit = MenuItem::new("종료", true, None);
    let menu = Menu::new();
    menu.append_items(&[&open, &logout, &PredefinedMenuItem::separator(), &quit]).ok()?;
    let (rgba, n) = crate::icon::rgba();
    let icon = tray_icon::Icon::from_rgba(rgba, n, n).ok()?;
    let tray = TrayIconBuilder::new().with_menu(Box::new(menu)).with_tooltip("NetBridge 자료전송").with_icon(icon).build().ok()?;
    let (open_id, logout_id, quit_id) = (open.id().clone(), logout.id().clone(), quit.id().clone());
    let c = ctx.clone();
    MenuEvent::set_event_handler(Some(move |e: MenuEvent| {
        if e.id == open_id {
            show(&c);
        } else if e.id == logout_id {
            let _ = tx.send(Box::new(|a: &mut crate::app::App| a.logout()));
            c.request_repaint();
        } else if e.id == quit_id {
            let _ = tx.send(Box::new(|a: &mut crate::app::App| a.quitting = true));
            c.send_viewport_cmd(ViewportCommand::Visible(true));
            c.send_viewport_cmd(ViewportCommand::Close);
            c.request_repaint();
        }
    }));
    TrayIconEvent::set_event_handler(Some(move |e: TrayIconEvent| {
        if matches!(e, TrayIconEvent::DoubleClick { .. }) {
            show(&ctx);
        }
    }));
    Some(Tray { _icon: tray })
}

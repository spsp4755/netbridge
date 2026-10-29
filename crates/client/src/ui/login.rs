use crate::app::App;
use crate::ui::*;
use eframe::egui::{self, Color32, RichText};
use netbridge_clientcore::config::config_dir;
use netbridge_clientcore::secret;
use netbridge_proto::*;

#[derive(Default)]
pub struct State {
    pub username: String,
    pub password: String,
    pub busy: bool,
    pub error: Option<String>,
    window_active: bool,
    on_password: bool,
}

#[derive(Default)]
pub struct LockState {
    pub password: String,
    pub error: Option<String>,
}

/// Brand panel on the left, form card on the right: used by the setup and login screens.
pub fn split_screen(ui: &mut egui::Ui, logo: &egui::TextureHandle, side: Option<Side>, form: impl FnOnce(&mut egui::Ui)) {
    let accent = side.map(side_color).unwrap_or(ACCENT);
    let size = egui::vec2(860.0_f32.min(ui.available_width() - 40.0), 480.0);
    ui.add_space(((ui.available_height() - size.y) / 2.0).max(10.0));
    ui.vertical_centered(|ui| {
        card_frame().inner_margin(0).shadow(egui::Shadow { offset: [0, 10], blur: 30, spread: 0, color: Color32::from_black_alpha(30) }).show(ui, |ui| {
            ui.set_width(size.x);
            ui.set_height(size.y);
            ui.horizontal_top(|ui| {
                ui.spacing_mut().item_spacing.x = 0.0;
                egui::Frame::new().fill(NAV_BG).corner_radius(egui::CornerRadius { nw: 10, sw: 10, ne: 0, se: 0 }).inner_margin(36).show(ui, |ui| {
                    ui.set_width(300.0);
                    ui.set_height(size.y - 72.0);
                    ui.vertical(|ui| {
                        ui.add(egui::Image::new(logo).fit_to_exact_size(egui::vec2(52.0, 52.0)));
                        ui.add_space(14.0);
                        ui.label(bold("NetBridge", 28.0).color(Color32::WHITE));
                        ui.label(RichText::new("망연계 자료전송 시스템").size(15.0).color(NAV_TEXT));
                        ui.add_space(22.0);
                        for line in ["파일 · 클립보드 양방향 전송", "사전 · 사후결재와 대결", "개인정보 자동 탐지", "모든 전송 감사 기록"] {
                            ui.label(RichText::new(format!("✔  {line}")).color(Color32::from_rgb(214, 224, 240)));
                        }
                        ui.with_layout(egui::Layout::bottom_up(egui::Align::Min), |ui| {
                            ui.label(RichText::new(format!("버전 {}", env!("CARGO_PKG_VERSION"))).small().color(Color32::from_rgb(130, 146, 172)));
                            if let Some(side) = side {
                                pill(ui, &format!("●  {} PC", side.label()), Color32::WHITE, accent);
                            }
                        });
                    });
                });
                egui::Frame::new().inner_margin(egui::Margin { left: 44, right: 44, top: 48, bottom: 30 }).show(ui, |ui| {
                    ui.set_width(size.x - 372.0 - 88.0);
                    ui.vertical(form);
                });
            });
        });
    });
}

pub fn show(app: &mut App, ui: &mut egui::Ui) {
    let logo = app.logo.clone();
    let side = app.side;
    split_screen(ui, &logo, side, |ui| {
        ui.label(bold("로그인", 24.0).color(TEXT));
        if let Some(side) = side {
            ui.label(muted(format!("{}에서 로그인하면 {} PC도 함께 로그인됩니다.", side.label(), side.other().label())));
        }
        ui.add_space(20.0);
        let field_w = ui.available_width();
        ui.label(muted("아이디"));
        let user = ui.add(egui::TextEdit::singleline(&mut app.login.username).desired_width(field_w).margin(egui::vec2(10.0, 8.0)));
        ui.add_space(4.0);
        ui.label(muted("비밀번호"));
        let pw = ui.add(egui::TextEdit::singleline(&mut app.login.password).password(true).desired_width(field_w).margin(egui::vec2(10.0, 8.0)));
        // egui drops focus while the window is inactive; give it back to the field last used
        if pw.has_focus() {
            app.login.on_password = true;
        } else if user.has_focus() {
            app.login.on_password = false;
        }
        let active = ui.input(|i| i.focused);
        if active && !app.login.window_active {
            if app.login.on_password {
                pw.request_focus()
            } else {
                user.request_focus()
            }
        }
        app.login.window_active = active;
        let enter = ui.input(|i| i.key_pressed(egui::Key::Enter));
        if user.lost_focus() && enter {
            pw.request_focus();
            app.login.on_password = true;
        } else if pw.lost_focus() && enter {
            submit(app);
        }
        if caps_lock_on() {
            ui.label(RichText::new("Caps Lock이 켜져 있습니다").small().color(WARN));
        }
        ui.add_space(12.0);
        error_line(ui, &app.login.error);
        ui.add_enabled_ui(!app.login.busy, |ui| {
            let label = if app.login.busy { "로그인하는 중…" } else { "로그인" };
            if ui.add_sized([field_w, 40.0], primary(label)).clicked() {
                submit(app);
            }
        });
        ui.with_layout(egui::Layout::bottom_up(egui::Align::Min), |ui| {
            ui.label(RichText::new("계정이나 접속 문제는 시스템 관리자에게 문의하세요.").small().color(MUTED));
        });
    });
}

#[cfg(windows)]
fn caps_lock_on() -> bool {
    use windows_sys::Win32::UI::Input::KeyboardAndMouse::{GetKeyState, VK_CAPITAL};
    unsafe { GetKeyState(VK_CAPITAL as i32) & 1 != 0 }
}

#[cfg(not(windows))]
fn caps_lock_on() -> bool {
    false
}

fn submit(app: &mut App) {
    if app.login.busy || app.login.username.trim().is_empty() || app.login.password.is_empty() {
        return;
    }
    app.login.busy = true;
    app.login.error = None;
    let device_key = secret::load_device_key(&config_dir(), &secret::slot(&app.cfg.server_url, &app.login.username));
    let req = ApiRequest::Login { username: app.login.username.trim().to_string(), password: app.login.password.clone(), device_key };
    let Some(net) = app.net.clone() else { return };
    app.run(async move { net.call(req).await }, |a, r| {
        a.login.busy = false;
        match r {
            Ok(ApiResponse::LoggedIn { token, device_key, me }) => a.on_logged_in(token, device_key, me),
            Ok(_) => a.login.error = Some("알 수 없는 응답입니다".into()),
            Err(e) => {
                a.login.password.clear();
                a.login.error = Some(e.message);
            }
        }
    });
}

/// Idle lock: the session stays open; only this window is locked.
pub fn lock_modal(app: &mut App, ctx: &egui::Context) {
    egui::Modal::new(egui::Id::new("lock")).frame(modal_frame()).show(ctx, |ui| {
        ui.set_width(360.0);
        ui.label(bold("🔒 화면 잠금", 19.0));
        ui.label(muted("일정 시간 사용하지 않아 화면을 잠갔습니다. 로그인은 유지됩니다. 비밀번호를 입력하세요."));
        let r = ui.add(egui::TextEdit::singleline(&mut app.lock.password).password(true).desired_width(f32::INFINITY).margin(egui::vec2(10.0, 8.0)));
        if !r.has_focus() && ui.memory(|m| m.focused().is_none()) {
            r.request_focus();
        }
        error_line(ui, &app.lock.error);
        let enter = r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
        ui.horizontal(|ui| {
            if ui.add(primary("잠금 해제")).clicked() || enter {
                let pw = std::mem::take(&mut app.lock.password);
                app.api_or(
                    ApiRequest::Unlock { password: pw },
                    |a, _| {
                        a.locked = false;
                        a.lock.error = None;
                    },
                    |a, e| a.lock.error = Some(e.message.clone()),
                );
            }
            if ui.add(secondary("로그아웃")).clicked() {
                app.logout();
            }
        });
    });
}

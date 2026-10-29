use crate::app::{App, Phase};
use crate::ui::{error_line, title};
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

pub fn show(app: &mut App, ui: &mut egui::Ui) {
    ui.vertical_centered(|ui| {
        ui.add_space(70.0);
        ui.set_max_width(380.0);
        title(ui, "NetBridge 자료전송");
        if let Some(side) = app.side {
            ui.label(RichText::new(format!("{} PC", side.label())).color(Color32::from_rgb(22, 93, 196)).strong());
            ui.label(format!("{}에서 로그인하면 {} PC도 함께 로그인됩니다.", side.label(), side.other().label()));
        }
        ui.add_space(16.0);
        egui::Grid::new("login").num_columns(2).spacing([12.0, 10.0]).show(ui, |ui| {
            ui.label("아이디");
            let user = ui.add(egui::TextEdit::singleline(&mut app.login.username).desired_width(220.0));
            ui.end_row();
            ui.label("비밀번호");
            let pw = ui.add(egui::TextEdit::singleline(&mut app.login.password).password(true).desired_width(220.0));
            ui.end_row();
            // egui drops focus while the window is inactive; give it back to the field last used
            if pw.has_focus() {
                app.login.on_password = true;
            } else if user.has_focus() {
                app.login.on_password = false;
            }
            let active = ui.input(|i| i.focused);
            if active && !app.login.window_active {
                if app.login.on_password { pw.request_focus() } else { user.request_focus() }
            }
            app.login.window_active = active;
            let enter = ui.input(|i| i.key_pressed(egui::Key::Enter));
            if user.lost_focus() && enter {
                pw.request_focus();
                app.login.on_password = true;
            } else if pw.lost_focus() && enter {
                submit(app);
            }
        });
        ui.add_space(10.0);
        error_line(ui, &app.login.error);
        ui.add_enabled_ui(!app.login.busy, |ui| {
            if ui.add_sized([220.0, 32.0], egui::Button::new("로그인")).clicked() {
                submit(app);
            }
        });
        ui.add_space(30.0);
        if ui.small_button("서버 설정 변경").clicked() {
            app.phase = Phase::Setup;
        }
    });
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
    egui::Modal::new(egui::Id::new("lock")).show(ctx, |ui| {
        ui.set_width(320.0);
        ui.heading("화면 잠금");
        ui.label("일정 시간 사용하지 않아 화면을 잠갔습니다. 비밀번호를 입력하세요.");
        let r = ui.add(egui::TextEdit::singleline(&mut app.lock.password).password(true));
        error_line(ui, &app.lock.error);
        let enter = r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
        ui.horizontal(|ui| {
            if ui.button("잠금 해제").clicked() || enter {
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
            if ui.button("로그아웃").clicked() {
                app.logout();
            }
        });
    });
}

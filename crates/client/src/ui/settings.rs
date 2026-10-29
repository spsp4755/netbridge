use crate::app::App;
use crate::hotkey;
use crate::ui::*;
use eframe::egui::{self, RichText};
use netbridge_clientcore::config::DEFAULT_HOTKEY;
use netbridge_proto::*;

#[derive(Default)]
pub struct PwForm {
    pub old: String,
    pub new: String,
    pub confirm: String,
    pub error: Option<String>,
    /// Must change before using the app (first login or expired).
    pub forced: bool,
}

#[derive(Default)]
pub struct State {
    pub capturing: bool,
    pub hotkey_error: Option<String>,
    pub pw: PwForm,
}

pub fn show(app: &mut App, ui: &mut egui::Ui) {
    page_header(ui, "설정", Some("이 PC에만 적용되는 설정과 내 계정 설정입니다."));
    card(ui, |ui| hotkey_section(app, ui));
    ui.add_space(10.0);
    card(ui, |ui| {
        section_title(ui, "받은 파일 저장 폴더");
        ui.horizontal(|ui| {
            ui.label(RichText::new(app.cfg.download_dir.display().to_string()).monospace());
            if ui.add(secondary("바꾸기")).clicked() {
                if let Some(p) = rfd::FileDialog::new().set_directory(&app.cfg.download_dir).pick_folder() {
                    app.cfg.download_dir = p;
                    save(app);
                }
            }
            if ui.add(secondary("열기")).clicked() {
                let _ = std::fs::create_dir_all(&app.cfg.download_dir);
                let _ = open::that(&app.cfg.download_dir);
            }
        });
    });
    ui.add_space(10.0);
    card(ui, |ui| {
        section_title(ui, "비밀번호 변경");
        password_form(app, ui);
    });
    ui.add_space(10.0);
    card(ui, |ui| {
        section_title(ui, "연결 정보");
        let me = app.me.as_ref();
        kv_grid(
            ui,
            "conn",
            &[
                ("서버", app.cfg.server_url.clone()),
                ("CA 인증서", app.cfg.ca_pem_path.display().to_string()),
                ("내 IP", me.map(|m| m.client_ip.clone()).unwrap_or_default()),
                ("계정", me.map(|m| format!("{} ({})", m.name, m.username)).unwrap_or_default()),
                ("버전", env!("CARGO_PKG_VERSION").to_string()),
            ],
        );
        ui.add_space(4.0);
        if ui.add(secondary("프로그램 정보")).clicked() {
            app.about = true;
        }
    });
}

fn hotkey_section(app: &mut App, ui: &mut egui::Ui) {
    section_title(ui, "클립보드 단축키");
    ui.label(muted(format!("텍스트를 복사한 뒤 단축키를 누르면 {} PC의 클립보드로 보냅니다.", app.side.map(|s| s.other().label()).unwrap_or("반대편 망"))));
    ui.horizontal(|ui| {
        egui::Frame::new().fill(NEUTRAL_SOFT).corner_radius(6).inner_margin(egui::Margin::symmetric(12, 6)).show(ui, |ui| {
            ui.label(bold(if app.settings.capturing { "…" } else { &app.cfg.hotkey }, 16.0));
        });
        if app.settings.capturing {
            ui.label(RichText::new("새 단축키를 누르세요 (취소: Esc)").color(ACCENT));
        } else if ui.add(secondary("변경")).clicked() {
            app.settings.capturing = true;
            app.settings.hotkey_error = None;
        }
        if app.cfg.hotkey != DEFAULT_HOTKEY && ui.add(secondary("기본값(Alt+F3)")).clicked() {
            apply_hotkey(app, DEFAULT_HOTKEY.to_string());
        }
    });
    if app.settings.capturing {
        let pressed = ui.ctx().input(|i| {
            i.events.iter().find_map(|e| match e {
                egui::Event::Key { key, pressed: true, modifiers, .. } => Some((*key, *modifiers)),
                _ => None,
            })
        });
        if let Some((key, m)) = pressed {
            if key == egui::Key::Escape {
                app.settings.capturing = false;
            } else if let Some(s) = hotkey::from_egui(m, key) {
                app.settings.capturing = false;
                apply_hotkey(app, s);
            }
        }
    }
    error_line(ui, &app.settings.hotkey_error);
    error_line(ui, &app.hotkey_error);
}

fn save(app: &mut App) {
    if let Err(e) = app.cfg.save() {
        app.toast_err(format!("설정을 저장할 수 없습니다: {e}"));
    }
}

fn apply_hotkey(app: &mut App, s: String) {
    let r = match app.hotkeys.as_mut() {
        Some(h) => h.set(&s),
        None => Err(app.hotkey_error.clone().unwrap_or_else(|| "단축키 기능을 사용할 수 없습니다".into())),
    };
    match r {
        Ok(()) => {
            app.cfg.hotkey = s.clone();
            app.hotkey_error = None;
            app.settings.hotkey_error = None;
            save(app);
            app.toast(format!("클립보드 단축키를 {s}(으)로 바꿨습니다"));
        }
        Err(e) => app.settings.hotkey_error = Some(format!("{s}: {e}")),
    }
}

fn password_form(app: &mut App, ui: &mut egui::Ui) {
    let pw = &mut app.settings.pw;
    egui::Grid::new("pw").num_columns(2).spacing([14.0, 8.0]).show(ui, |ui| {
        for (label, field) in [("현재 비밀번호", &mut pw.old), ("새 비밀번호", &mut pw.new), ("새 비밀번호 확인", &mut pw.confirm)] {
            ui.label(muted(label));
            ui.add(egui::TextEdit::singleline(field).password(true).desired_width(260.0).margin(egui::vec2(10.0, 7.0)));
            ui.end_row();
        }
    });
    if let Some(p) = app.me.as_ref().map(|m| &m.policy) {
        ui.label(RichText::new(format!("{}자 이상{}", p.pw_min_len, if p.pw_require_mix { ", 영문·숫자·특수문자 포함" } else { "" })).small().color(MUTED));
    }
    error_line(ui, &app.settings.pw.error);
    if ui.add(primary("비밀번호 변경")).clicked() {
        let pw = &mut app.settings.pw;
        if pw.new != pw.confirm {
            pw.error = Some("새 비밀번호가 서로 다릅니다".into());
            return;
        }
        let req = ApiRequest::ChangePassword { old: pw.old.clone(), new: pw.new.clone() };
        app.api_or(
            req,
            |a, _| {
                a.settings.pw = PwForm::default();
                a.toast("비밀번호를 바꿨습니다");
            },
            |a, e| a.settings.pw.error = Some(e.message.clone()),
        );
    }
}

pub fn forced_password_modal(app: &mut App, ctx: &egui::Context) {
    egui::Modal::new(egui::Id::new("forcepw")).show(ctx, |ui| {
        ui.set_width(440.0);
        ui.label(bold("비밀번호를 바꿔 주세요", 19.0));
        ui.label(muted("처음 로그인했거나 비밀번호 사용 기간이 지났습니다. 바꾸기 전에는 다른 기능을 쓸 수 없습니다."));
        ui.add_space(8.0);
        password_form(app, ui);
        ui.separator();
        if ui.add(egui::Button::new("로그아웃").small()).clicked() {
            app.logout();
        }
    });
}

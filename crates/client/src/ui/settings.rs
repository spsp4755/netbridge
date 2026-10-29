use crate::app::App;
use crate::hotkey;
use crate::ui::{error_line, title};
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
    title(ui, "설정");

    ui.strong("클립보드 단축키");
    ui.label(format!("텍스트를 복사한 뒤 단축키를 누르면 {} PC의 클립보드로 보냅니다.", app.side.map(|s| s.other().label()).unwrap_or("반대편 망")));
    ui.horizontal(|ui| {
        ui.label(RichText::new(&app.cfg.hotkey).monospace().size(16.0));
        if app.settings.capturing {
            ui.label("새 단축키를 누르세요 (취소: Esc)");
        } else if ui.button("변경").clicked() {
            app.settings.capturing = true;
            app.settings.hotkey_error = None;
        }
        if app.cfg.hotkey != DEFAULT_HOTKEY && ui.button("기본값(Alt+F3)").clicked() {
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

    ui.add_space(14.0);
    ui.strong("받은 파일 저장 폴더");
    ui.horizontal(|ui| {
        ui.label(app.cfg.download_dir.display().to_string());
        if ui.button("바꾸기").clicked() {
            if let Some(p) = rfd::FileDialog::new().set_directory(&app.cfg.download_dir).pick_folder() {
                app.cfg.download_dir = p;
                save(app);
            }
        }
    });

    ui.add_space(14.0);
    ui.strong("비밀번호 변경");
    password_form(app, ui);

    ui.add_space(14.0);
    ui.strong("연결 정보");
    ui.label(format!("서버: {}", app.cfg.server_url));
    ui.label(format!("CA 인증서: {}", app.cfg.ca_pem_path.display()));
    ui.label(format!("버전: {}", env!("CARGO_PKG_VERSION")));
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
    egui::Grid::new("pw").num_columns(2).spacing([12.0, 6.0]).show(ui, |ui| {
        ui.label("현재 비밀번호");
        ui.add(egui::TextEdit::singleline(&mut pw.old).password(true).desired_width(220.0));
        ui.end_row();
        ui.label("새 비밀번호");
        ui.add(egui::TextEdit::singleline(&mut pw.new).password(true).desired_width(220.0));
        ui.end_row();
        ui.label("새 비밀번호 확인");
        ui.add(egui::TextEdit::singleline(&mut pw.confirm).password(true).desired_width(220.0));
        ui.end_row();
    });
    if let Some(p) = app.me.as_ref().map(|m| &m.policy) {
        ui.label(RichText::new(format!("{}자 이상{}", p.pw_min_len, if p.pw_require_mix { ", 영문·숫자·특수문자 포함" } else { "" })).small());
    }
    error_line(ui, &app.settings.pw.error);
    if ui.button("비밀번호 변경").clicked() {
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
        ui.set_width(380.0);
        ui.heading("비밀번호를 바꿔 주세요");
        ui.label("처음 로그인했거나 비밀번호 사용 기간이 지났습니다.");
        ui.add_space(6.0);
        password_form(app, ui);
        if ui.small_button("로그아웃").clicked() {
            app.logout();
        }
    });
}

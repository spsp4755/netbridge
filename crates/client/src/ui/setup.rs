use crate::app::App;
use crate::ui::login::split_screen;
use crate::ui::*;
use eframe::egui;
use std::path::PathBuf;

#[derive(Default)]
pub struct State {
    pub server_url: String,
    pub ca_path: String,
    pub error: Option<String>,
}

pub fn show(app: &mut App, ui: &mut egui::Ui) {
    let logo = app.logo.clone();
    split_screen(ui, &logo, None, |ui| {
        ui.label(bold("연결 설정", 24.0).color(TEXT));
        ui.label(muted("이 PC가 연결할 연계서버 주소와 CA 인증서를 입력하세요. 담당자에게 받은 값을 그대로 넣으면 됩니다."));
        ui.add_space(20.0);
        let w = ui.available_width();
        ui.label(muted("서버 주소"));
        ui.add(egui::TextEdit::singleline(&mut app.setup.server_url).hint_text("https://10.0.0.10:8443").desired_width(w).margin(egui::vec2(10.0, 8.0)));
        ui.add_space(4.0);
        ui.label(muted("CA 인증서 (ca.pem)"));
        ui.horizontal(|ui| {
            ui.add(egui::TextEdit::singleline(&mut app.setup.ca_path).desired_width(w - 100.0).margin(egui::vec2(10.0, 8.0)));
            if ui.add(secondary("찾아보기")).clicked() {
                if let Some(p) = rfd::FileDialog::new().add_filter("인증서", &["pem", "crt"]).pick_file() {
                    app.setup.ca_path = p.display().to_string();
                }
            }
        });
        ui.add_space(12.0);
        error_line(ui, &app.setup.error);
        if ui.add_sized([w, 40.0], primary("연결 확인 후 저장")).clicked() {
            let url = app.setup.server_url.trim().trim_end_matches('/').to_string();
            if !url.starts_with("https://") {
                app.setup.error = Some("서버 주소는 https:// 로 시작해야 합니다".into());
                return;
            }
            app.setup.error = None;
            app.cfg.server_url = url;
            app.cfg.ca_pem_path = PathBuf::from(app.setup.ca_path.trim());
            if let Err(e) = app.cfg.save() {
                app.setup.error = Some(format!("설정을 저장할 수 없습니다: {e}"));
                return;
            }
            app.connect();
        }
        if !app.cfg.server_url.is_empty() && ui.add_sized([w, 34.0], secondary("취소")).clicked() {
            app.connect();
        }
    });
}

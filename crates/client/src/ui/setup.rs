use crate::app::App;
use crate::ui::{error_line, title};
use eframe::egui;
use std::path::PathBuf;

#[derive(Default)]
pub struct State {
    pub server_url: String,
    pub ca_path: String,
    pub error: Option<String>,
}

pub fn show(app: &mut App, ui: &mut egui::Ui) {
    ui.vertical_centered(|ui| {
        ui.add_space(60.0);
        ui.set_max_width(560.0);
        title(ui, "NetBridge 연결 설정");
        ui.label("이 PC가 연결할 연계서버 주소와 CA 인증서를 입력하세요. 담당자에게 받은 값을 그대로 넣으면 됩니다.");
        ui.add_space(12.0);
        egui::Grid::new("setup").num_columns(2).spacing([12.0, 10.0]).show(ui, |ui| {
            ui.label("서버 주소");
            ui.add(egui::TextEdit::singleline(&mut app.setup.server_url).hint_text("https://10.0.0.10:8443").desired_width(360.0));
            ui.end_row();
            ui.label("CA 인증서");
            ui.horizontal(|ui| {
                ui.add(egui::TextEdit::singleline(&mut app.setup.ca_path).desired_width(280.0));
                if ui.button("찾아보기").clicked() {
                    if let Some(p) = rfd::FileDialog::new().add_filter("인증서", &["pem", "crt"]).pick_file() {
                        app.setup.ca_path = p.display().to_string();
                    }
                }
            });
            ui.end_row();
        });
        ui.add_space(12.0);
        error_line(ui, &app.setup.error);
        if ui.button("연결 확인 후 저장").clicked() {
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
    });
}

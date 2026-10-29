use crate::app::App;
use crate::ui::*;
use chrono::NaiveDate;
use eframe::egui;
use egui_extras::DatePickerButton;
use netbridge_proto::*;

pub struct State {
    pub current: Option<Delegation>,
    pub loaded: bool,
    pub proxy: String,
    pub from: NaiveDate,
    pub to: NaiveDate,
}

impl Default for State {
    fn default() -> Self {
        let today = chrono::Utc::now().with_timezone(&chrono::FixedOffset::east_opt(9 * 3600).unwrap()).date_naive();
        State { current: None, loaded: false, proxy: String::new(), from: today, to: today }
    }
}

pub fn refresh(app: &mut App) {
    app.api(ApiRequest::GetDelegation, |a, r| {
        if let ApiResponse::Delegation(d) = r {
            if let Some(d) = &d {
                a.delegation.proxy = d.proxy_username.clone();
                a.delegation.from = d.from;
                a.delegation.to = d.to;
            }
            a.delegation.current = d;
            a.delegation.loaded = true;
        }
    });
}

pub fn show(app: &mut App, ui: &mut egui::Ui) {
    page_header(ui, "대결 지정", Some("부재중일 때 내 결재를 대신 처리할 사람과 기간을 지정합니다. 기간 동안에는 대리인도 결재할 수 있고, 이력에 \"대결\"로 남습니다."));
    card(ui, |ui| {
        section_title(ui, "현재 상태");
        match &app.delegation.current {
            Some(d) => {
                ui.horizontal(|ui| {
                    tone_pill(ui, "대결 지정됨", Tone::Success);
                    ui.label(bold(format!("{} ({})", d.proxy_name, d.proxy_username), 14.0));
                    ui.label(muted(format!("{} ~ {}", d.from, d.to)));
                });
            }
            None => {
                ui.horizontal(|ui| {
                    tone_pill(ui, "지정 안 됨", Tone::Neutral);
                    ui.label(muted(if app.delegation.loaded { "현재 지정된 대리인이 없습니다." } else { "불러오는 중…" }));
                });
            }
        }
    });
    ui.add_space(10.0);
    card(ui, |ui| {
        section_title(ui, "대리인 지정");
        egui::Grid::new("deleg").num_columns(2).spacing([14.0, 10.0]).show(ui, |ui| {
            ui.label(muted("대리인 아이디"));
            ui.add(egui::TextEdit::singleline(&mut app.delegation.proxy).desired_width(240.0).margin(egui::vec2(10.0, 7.0)));
            ui.end_row();
            ui.label(muted("시작일"));
            ui.add(DatePickerButton::new(&mut app.delegation.from).id_salt("from"));
            ui.end_row();
            ui.label(muted("종료일"));
            ui.add(DatePickerButton::new(&mut app.delegation.to).id_salt("to"));
            ui.end_row();
        });
        ui.add_space(8.0);
        ui.horizontal(|ui| {
            if ui.add(primary("지정")).clicked() {
                let req = ApiRequest::SetDelegation { proxy_username: app.delegation.proxy.trim().to_string(), from: app.delegation.from, to: app.delegation.to };
                app.api(req, |a, _| {
                    a.toast("대결을 지정했습니다");
                    refresh(a);
                });
            }
            if app.delegation.current.is_some() && ui.add(secondary("해제")).clicked() {
                app.api(ApiRequest::ClearDelegation, |a, _| {
                    a.toast("대결을 해제했습니다");
                    a.delegation.current = None;
                });
            }
        });
    });
}

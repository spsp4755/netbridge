use crate::app::App;
use crate::ui::{approval_text, fmt_bytes, fmt_ts, pii_summary, state_text, title};
use eframe::egui;
use egui_extras::{Column, TableBuilder};
use netbridge_proto::*;

#[derive(Default)]
pub struct State {
    pub loaded: bool,
    pub items: Vec<TransferInfo>,
}

pub fn refresh(app: &mut App) {
    app.api(ApiRequest::ListOutgoing, |a, r| {
        if let ApiResponse::Transfers(v) = r {
            a.outgoing.items = v;
            a.outgoing.loaded = true;
        }
    });
}

pub fn show(app: &mut App, ui: &mut egui::Ui) {
    title(ui, "보낸 파일");
    if ui.button("새로고침").clicked() {
        refresh(app);
    }
    ui.add_space(6.0);
    if app.outgoing.items.is_empty() {
        ui.label(if app.outgoing.loaded { "보낸 파일이 없습니다." } else { "불러오는 중…" });
        return;
    }
    let awaiting = app.outgoing.items.iter().filter(|t| t.state == TransferState::AwaitingReason).count();
    if awaiting > 0 {
        ui.label(egui::RichText::new(format!("사유 입력이 필요한 파일이 {awaiting}개 있습니다. 파일 이름 옆 버튼을 눌러 결재를 요청하세요.")).color(egui::Color32::from_rgb(180, 110, 0)));
    }
    let mut ask = None;
    TableBuilder::new(ui)
        .striped(true)
        .column(Column::auto().at_least(115.0))
        .column(Column::auto().at_least(120.0))
        .column(Column::remainder().at_least(220.0).clip(true))
        .column(Column::auto().at_least(65.0))
        .column(Column::auto().at_least(75.0))
        .column(Column::auto().at_least(190.0))
        .column(Column::auto().at_least(95.0))
        .column(Column::auto().at_least(95.0))
        .column(Column::auto().at_least(120.0))
        .header(22.0, |mut h| {
            for c in ["보낸 시각", "방향", "파일", "크기", "상태", "결재", "송신 IP", "수신 IP", "개인정보"] {
                h.col(|ui| {
                    ui.strong(c);
                });
            }
        })
        .body(|mut body| {
            for t in &app.outgoing.items {
                body.row(24.0, |mut row| {
                    row.col(|ui| {
                        ui.label(fmt_ts(t.created_at));
                    });
                    row.col(|ui| {
                        ui.label(t.direction.label());
                    });
                    row.col(|ui| {
                        let mut tip = format!("사유: {}\nSHA-256: {}", t.reason, t.sha256);
                        if let Some(c) = t.approval.as_ref().and_then(|a| a.comment.clone()) {
                            tip.push_str(&format!("\n결재 의견: {c}"));
                        }
                        if let Some(b) = &t.block_reason {
                            tip.push_str(&format!("\n{b}"));
                        }
                        ui.horizontal(|ui| {
                            ui.label(&t.file_name).on_hover_text(tip);
                            if t.state == TransferState::AwaitingReason && ui.small_button("결재 요청").clicked() {
                                ask = Some((t.id, t.file_name.clone()));
                            }
                        });
                    });
                    row.col(|ui| {
                        ui.label(fmt_bytes(t.size));
                    });
                    row.col(|ui| {
                        ui.label(state_text(t.state));
                    });
                    row.col(|ui| {
                        ui.label(approval_text(&t.approval));
                    });
                    row.col(|ui| {
                        ui.label(&t.sender_ip);
                    });
                    row.col(|ui| {
                        ui.label(t.receiver_ip.clone().unwrap_or_else(|| "-".into()));
                    });
                    row.col(|ui| {
                        ui.label(pii_summary(&t.pii, t.unscannable));
                    });
                });
            }
        });
    if let Some((id, name)) = ask {
        app.send.reason_for = Some((id, name, String::new()));
    }
}

use crate::app::App;
use crate::ui::*;
use eframe::egui::{self, RichText};
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
    page_header(ui, "보낸 파일", Some("내가 보낸 파일의 진행 상태, 결재 결과와 송수신 IP입니다. 파일 이름에 마우스를 올리면 사유와 해시가 보입니다."));
    ui.horizontal(|ui| {
        let total = app.outgoing.items.len();
        let pending = app.outgoing.items.iter().filter(|t| matches!(t.state, TransferState::Pending | TransferState::Uploading | TransferState::Delivering)).count();
        let done = app.outgoing.items.iter().filter(|t| matches!(t.state, TransferState::Available | TransferState::Downloaded)).count();
        let bad = app.outgoing.items.iter().filter(|t| matches!(t.state, TransferState::Rejected | TransferState::Blocked)).count();
        tone_pill(ui, &format!("전체 {total}"), Tone::Neutral);
        tone_pill(ui, &format!("진행 중 {pending}"), Tone::Info);
        tone_pill(ui, &format!("전달됨 {done}"), Tone::Success);
        tone_pill(ui, &format!("반려·차단 {bad}"), Tone::Danger);
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if ui.add(secondary("⟳ 새로고침")).clicked() {
                refresh(app);
            }
        });
    });
    ui.add_space(8.0);
    if app.outgoing.items.is_empty() {
        card(ui, |ui| {
            if app.outgoing.loaded {
                empty_state(ui, "☰", "보낸 파일이 없습니다", "파일 보내기 화면에서 파일을 보내면 여기에서 진행 상태를 볼 수 있습니다.");
            } else {
                empty_state(ui, "⟳", "불러오는 중…", "잠시만 기다려 주세요.");
            }
        });
        return;
    }
    let awaiting = app.outgoing.items.iter().filter(|t| t.state == TransferState::AwaitingReason).count();
    if awaiting > 0 {
        banner(ui, Tone::Warn, &format!("사유 입력이 필요한 파일이 {awaiting}개 있습니다. 파일 이름 옆 [결재 요청]을 눌러 사유를 입력하세요."));
        ui.add_space(6.0);
    }
    let mut ask = None;
    card(ui, |ui| {
        egui::ScrollArea::horizontal().show(ui, |ui| {
            TableBuilder::new(ui)
                .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
                .striped(true)
                .column(Column::auto().at_least(110.0))
                .column(Column::auto().at_least(100.0))
                .column(Column::remainder().at_least(150.0).clip(true))
                .column(Column::auto().at_least(55.0))
                .column(Column::auto().at_least(70.0))
                .column(Column::auto().at_least(140.0))
                .column(Column::auto().at_least(75.0))
                .column(Column::auto().at_least(75.0))
                .column(Column::auto().at_least(80.0))
                .header(28.0, |mut h| {
                    for c in ["보낸 시각", "방향", "파일", "크기", "상태", "결재", "송신 IP", "수신 IP", "개인정보"] {
                        h.col(|ui| {
                            ui.label(muted(c));
                        });
                    }
                })
                .body(|mut body| {
                    for t in &app.outgoing.items {
                        body.row(34.0, |mut row| {
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
                                    ui.label(bold(&t.file_name, 14.0)).on_hover_text(tip);
                                    if t.state == TransferState::AwaitingReason && ui.add(primary("결재 요청").min_size(egui::vec2(0.0, 26.0))).clicked() {
                                        ask = Some((t.id, t.file_name.clone()));
                                    }
                                });
                            });
                            row.col(|ui| {
                                ui.label(fmt_bytes(t.size));
                            });
                            row.col(|ui| {
                                state_pill(ui, t.state);
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
                                let s = pii_summary(&t.pii, t.unscannable);
                                if s == "-" {
                                    ui.label(muted("없음"));
                                } else {
                                    ui.label(RichText::new(s).color(DANGER));
                                }
                            });
                        });
                    }
                })
        })
    });
    if let Some((id, name)) = ask {
        app.send.reason_for = Some((id, name, String::new()));
    }
}

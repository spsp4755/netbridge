use crate::app::App;
use crate::ui::*;
use eframe::egui::{self, Color32, RichText};
use netbridge_proto::*;
use std::collections::HashMap;

#[derive(Default)]
pub struct State {
    pub loaded: bool,
    pub items: Vec<ApprovalItem>,
    pub comments: HashMap<i64, String>,
    pub busy: Option<i64>,
}

pub fn refresh(app: &mut App) {
    app.api(ApiRequest::ListApprovals, |a, r| {
        if let ApiResponse::Approvals(v) = r {
            a.approvals.items = v;
            a.approvals.loaded = true;
        }
    });
}

pub fn show(app: &mut App, ui: &mut egui::Ui) {
    page_header(ui, "결재함", Some("내가 결재할 전송 요청입니다. 사전결재는 승인해야 전달되고, 사후결재는 이미 전달된 파일을 확인합니다."));
    let pending: Vec<ApprovalItem> = app.approvals.items.iter().filter(|i| i.approval.status == ApprovalStatus::Pending).cloned().collect();
    let done: Vec<ApprovalItem> = app.approvals.items.iter().filter(|i| i.approval.status != ApprovalStatus::Pending).cloned().collect();
    ui.horizontal(|ui| {
        tone_pill(ui, &format!("결재 대기 {}", pending.len()), if pending.is_empty() { Tone::Neutral } else { Tone::Warn });
        tone_pill(ui, &format!("처리 {}", done.len()), Tone::Neutral);
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if ui.add(secondary("⟳ 새로고침")).clicked() {
                refresh(app);
            }
        });
    });
    ui.add_space(8.0);
    if pending.is_empty() {
        card(ui, |ui| {
            if app.approvals.loaded {
                empty_state(ui, "✔", "대기 중인 결재가 없습니다", "새 결재 요청이 오면 알림과 함께 여기에 나타납니다.");
            } else {
                empty_state(ui, "⟳", "불러오는 중…", "잠시만 기다려 주세요.");
            }
        });
    }
    let mut action: Option<(i64, bool)> = None;
    let mut preview: Option<TransferInfo> = None;
    for it in &pending {
        let t = &it.transfer;
        card(ui, |ui| {
            ui.horizontal(|ui| {
                match it.approval.mode {
                    ApprovalMode::Pre => tone_pill(ui, "사전결재", Tone::Warn),
                    ApprovalMode::Post => tone_pill(ui, "사후결재 · 이미 전달됨", Tone::Info),
                };
                if it.as_proxy {
                    pill(ui, &format!("대결 · 원결재자 {}", it.approval.approver), Color32::from_rgb(110, 60, 160), Color32::from_rgb(242, 234, 250));
                }
                if it.approval.overdue {
                    tone_pill(ui, "기한 초과", Tone::Danger);
                }
                ui.label(bold(format!("{}  ({})", t.file_name, fmt_bytes(t.size)), 15.0));
            });
            ui.add_space(4.0);
            egui::Grid::new(("ap", it.approval.id)).num_columns(2).spacing([12.0, 4.0]).show(ui, |ui| {
                ui.label(muted("보낸 사람"));
                ui.label(format!("{}  ({}, {})", t.owner, t.sender_ip, fmt_ts(t.created_at)));
                ui.end_row();
                ui.label(muted("방향"));
                ui.label(t.direction.label());
                ui.end_row();
                ui.label(muted("파일"));
                ui.label(format!("{}  ({})", t.file_name, fmt_bytes(t.size)));
                ui.end_row();
                ui.label(muted("SHA-256"));
                ui.label(RichText::new(&t.sha256).monospace().small());
                ui.end_row();
                ui.label(muted("사유"));
                ui.label(&t.reason);
                ui.end_row();
                ui.label(muted("개인정보"));
                let s = pii_summary(&t.pii, t.unscannable);
                ui.label(if s == "-" { RichText::new("탐지 없음") } else { RichText::new(s).color(Color32::from_rgb(190, 40, 40)) });
                ui.end_row();
            });
            let comment = app.approvals.comments.entry(it.approval.id).or_default();
            ui.add_space(4.0);
            ui.add(egui::TextEdit::singleline(comment).hint_text("의견 (반려할 때는 필수)").desired_width(f32::INFINITY).margin(egui::vec2(10.0, 7.0)));
            ui.horizontal(|ui| {
                let busy = app.approvals.busy == Some(it.approval.id);
                ui.add_enabled_ui(!busy, |ui| {
                    if ui.add(primary("승인")).clicked() {
                        action = Some((it.approval.id, true));
                    }
                    if ui.add(danger("반려")).clicked() {
                        action = Some((it.approval.id, false));
                    }
                });
                // pre-approval content only exists on the sending network
                let here = Some(t.direction.from_side()) == app.side;
                if it.approval.mode == ApprovalMode::Pre {
                    if here {
                        if ui.add(secondary("미리 보기")).clicked() {
                            preview = Some(t.clone());
                        }
                    } else {
                        ui.label(RichText::new(format!("미리 보기는 {} PC에서 할 수 있습니다", t.direction.from_side().label())).small());
                    }
                }
                if busy {
                    ui.spinner();
                }
            });
        });
        ui.add_space(8.0);
    }
    if let Some((id, approve)) = action {
        let comment = app.approvals.comments.get(&id).cloned().filter(|s| !s.trim().is_empty());
        if !approve && comment.is_none() {
            app.toast_err("반려 사유를 입력하세요");
        } else {
            app.approvals.busy = Some(id);
            app.api_or(
                ApiRequest::Decide { approval_id: id, approve, comment },
                move |a, _| {
                    a.approvals.busy = None;
                    a.toast(if approve { "승인했습니다" } else { "반려했습니다" });
                    refresh(a);
                },
                |a, _| a.approvals.busy = None,
            );
        }
    }
    if let Some(t) = preview {
        open_preview(app, t);
    }
    if !done.is_empty() {
        ui.add_space(10.0);
        card(ui, |ui| {
            section_title(ui, "처리한 결재");
            egui::Grid::new("done").striped(true).num_columns(5).spacing([20.0, 8.0]).show(ui, |ui| {
                for c in ["처리 시각", "보낸 사람", "파일", "결과", "의견"] {
                    ui.label(muted(c));
                }
                ui.end_row();
                for it in &done {
                    let a = &it.approval;
                    ui.label(a.decided_at.map(fmt_ts).unwrap_or_default());
                    ui.label(&it.transfer.owner);
                    ui.label(&it.transfer.file_name);
                    let tone = if a.status == ApprovalStatus::Approved { Tone::Success } else { Tone::Danger };
                    tone_pill(ui, &format!("{} {}{}", a.mode.label(), a.status.label(), if a.by_proxy { " (대결)" } else { "" }), tone);
                    ui.label(a.comment.clone().unwrap_or_default());
                    ui.end_row();
                }
            });
        });
    }
}

fn open_preview(app: &mut App, t: TransferInfo) {
    let Some(net) = app.net.clone() else { return };
    let dir = std::env::temp_dir().join("NetBridge-미리보기");
    app.run(async move { net.download(&t, &dir, |_| {}).await }, |a, r| match r {
        Ok(p) => {
            if let Err(e) = open::that(&p) {
                a.toast_err(format!("파일을 열 수 없습니다: {e}"));
            }
        }
        Err(e) => a.api_error(e),
    });
}

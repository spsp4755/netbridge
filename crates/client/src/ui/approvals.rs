use crate::app::App;
use crate::ui::{fmt_bytes, fmt_ts, pii_summary, title};
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
    title(ui, "결재함");
    if ui.button("새로고침").clicked() {
        refresh(app);
    }
    ui.add_space(6.0);
    let pending: Vec<ApprovalItem> = app.approvals.items.iter().filter(|i| i.approval.status == ApprovalStatus::Pending).cloned().collect();
    let done: Vec<ApprovalItem> = app.approvals.items.iter().filter(|i| i.approval.status != ApprovalStatus::Pending).cloned().collect();
    ui.strong(format!("결재 대기 {}건", pending.len()));
    if pending.is_empty() {
        ui.label(if app.approvals.loaded { "대기 중인 결재가 없습니다." } else { "불러오는 중…" });
    }
    let mut action: Option<(i64, bool)> = None;
    let mut preview: Option<TransferInfo> = None;
    for it in &pending {
        let t = &it.transfer;
        egui::Frame::group(ui.style()).show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal(|ui| {
                let badge = match it.approval.mode {
                    ApprovalMode::Pre => RichText::new("사전결재").color(Color32::from_rgb(180, 110, 0)).strong(),
                    ApprovalMode::Post => RichText::new("사후결재 (이미 전달됨)").color(Color32::from_rgb(22, 93, 196)).strong(),
                };
                ui.label(badge);
                if it.as_proxy {
                    ui.label(RichText::new(format!("대결 · 원결재자 {}", it.approval.approver)).color(Color32::from_rgb(120, 60, 160)));
                }
                if it.approval.overdue {
                    ui.label(RichText::new("기한 초과").color(Color32::from_rgb(190, 40, 40)));
                }
            });
            egui::Grid::new(("ap", it.approval.id)).num_columns(2).spacing([12.0, 4.0]).show(ui, |ui| {
                ui.label("보낸 사람");
                ui.label(format!("{}  ({}, {})", t.owner, t.sender_ip, fmt_ts(t.created_at)));
                ui.end_row();
                ui.label("방향");
                ui.label(t.direction.label());
                ui.end_row();
                ui.label("파일");
                ui.label(format!("{}  ({})", t.file_name, fmt_bytes(t.size)));
                ui.end_row();
                ui.label("SHA-256");
                ui.label(RichText::new(&t.sha256).monospace().small());
                ui.end_row();
                ui.label("사유");
                ui.label(&t.reason);
                ui.end_row();
                ui.label("개인정보");
                let s = pii_summary(&t.pii, t.unscannable);
                ui.label(if s == "-" { RichText::new("탐지 없음") } else { RichText::new(s).color(Color32::from_rgb(190, 40, 40)) });
                ui.end_row();
            });
            let comment = app.approvals.comments.entry(it.approval.id).or_default();
            ui.add(egui::TextEdit::singleline(comment).hint_text("의견 (반려할 때 사유)").desired_width(400.0));
            ui.horizontal(|ui| {
                let busy = app.approvals.busy == Some(it.approval.id);
                ui.add_enabled_ui(!busy, |ui| {
                    if ui.button(RichText::new("승인").strong()).clicked() {
                        action = Some((it.approval.id, true));
                    }
                    if ui.button("반려").clicked() {
                        action = Some((it.approval.id, false));
                    }
                });
                // pre-approval content only exists on the sending network
                let here = Some(t.direction.from_side()) == app.side;
                if it.approval.mode == ApprovalMode::Pre {
                    if here {
                        if ui.button("미리 보기").clicked() {
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
        ui.add_space(4.0);
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
        ui.separator();
        ui.strong("처리한 결재");
        egui::Grid::new("done").striped(true).num_columns(5).spacing([16.0, 4.0]).show(ui, |ui| {
            for it in &done {
                let a = &it.approval;
                ui.label(a.decided_at.map(fmt_ts).unwrap_or_default());
                ui.label(&it.transfer.owner);
                ui.label(&it.transfer.file_name);
                ui.label(format!("{} {}{}", a.mode.label(), a.status.label(), if a.by_proxy { " (대결)" } else { "" }));
                ui.label(a.comment.clone().unwrap_or_default());
                ui.end_row();
            }
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

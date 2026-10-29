use crate::app::App;
use crate::ui::{fmt_bytes, pii_summary, state_text, title};
use eframe::egui::{self, Color32, RichText};
use netbridge_clientcore::net::sha256_file;
use netbridge_proto::*;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

#[derive(Default)]
pub struct State {
    pub files: Vec<(PathBuf, u64)>,
    pub reason: String,
    pub busy: bool,
    /// file path -> (sent, total)
    pub progress: Arc<Mutex<HashMap<PathBuf, (u64, u64)>>>,
    pub results: Vec<(String, Result<TransferInfo, String>)>,
    /// (transfer id, file name, reason being typed) for a PII file waiting for its reason
    pub reason_for: Option<(i64, String, String)>,
}

fn add(app: &mut App, p: PathBuf) {
    if p.is_dir() {
        app.toast_err(format!("폴더는 보낼 수 없습니다: {}", p.display()));
        return;
    }
    if app.send.files.iter().any(|(f, _)| *f == p) {
        return;
    }
    match std::fs::metadata(&p) {
        Ok(m) => app.send.files.push((p, m.len())),
        Err(e) => app.toast_err(format!("파일을 읽을 수 없습니다: {e}")),
    }
}

pub fn show(app: &mut App, ui: &mut egui::Ui) {
    let to = app.side.map(|s| s.other().label()).unwrap_or("반대편 망");
    title(ui, &format!("파일 보내기 → {to}"));
    let dropped: Vec<PathBuf> = ui.ctx().input(|i| i.raw.dropped_files.iter().filter_map(|f| f.path.clone()).collect());
    if !app.send.busy {
        for p in dropped {
            add(app, p);
        }
    }
    let hovering = ui.ctx().input(|i| !i.raw.hovered_files.is_empty());
    let frame = egui::Frame::group(ui.style()).fill(if hovering { Color32::from_rgb(225, 238, 252) } else { ui.visuals().faint_bg_color });
    frame.show(ui, |ui| {
        ui.set_min_size(egui::vec2(ui.available_width(), 90.0));
        ui.vertical_centered(|ui| {
            ui.add_space(14.0);
            ui.label(RichText::new("보낼 파일을 여기로 끌어다 놓으세요").size(16.0));
            ui.add_space(6.0);
            if ui.add_enabled(!app.send.busy, egui::Button::new("파일 선택…")).clicked() {
                if let Some(ps) = rfd::FileDialog::new().pick_files() {
                    for p in ps {
                        add(app, p);
                    }
                }
            }
        });
    });
    ui.add_space(8.0);
    if !app.send.files.is_empty() {
        let progress = app.send.progress.lock().unwrap().clone();
        let mut remove = None;
        egui::Grid::new("files").striped(true).num_columns(4).spacing([16.0, 6.0]).show(ui, |ui| {
            ui.strong("파일");
            ui.strong("크기");
            ui.strong("진행");
            ui.label("");
            ui.end_row();
            for (i, (p, size)) in app.send.files.iter().enumerate() {
                ui.label(p.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default());
                ui.label(fmt_bytes(*size));
                match progress.get(p) {
                    Some((done, total)) if *total > 0 => {
                        ui.add(egui::ProgressBar::new(*done as f32 / *total as f32).desired_width(160.0).show_percentage());
                    }
                    _ => {
                        ui.label("");
                    }
                }
                if ui.add_enabled(!app.send.busy, egui::Button::new("빼기").small()).clicked() {
                    remove = Some(i);
                }
                ui.end_row();
            }
        });
        if let Some(i) = remove {
            app.send.files.remove(i);
        }
        let total: u64 = app.send.files.iter().map(|(_, s)| s).sum();
        ui.label(format!("{}개, 모두 {}", app.send.files.len(), fmt_bytes(total)));
    }
    ui.add_space(8.0);
    ui.label("보내는 사유 (선택 — 개인정보가 탐지되면 결재 요청 때 입력을 요청합니다)");
    ui.add(egui::TextEdit::multiline(&mut app.send.reason).desired_rows(2).desired_width(f32::INFINITY).hint_text("예: 고객 제출용 보고서 반입"));
    ui.add_space(8.0);
    let can = !app.send.busy && !app.send.files.is_empty();
    ui.horizontal(|ui| {
        if ui.add_enabled(can, egui::Button::new(RichText::new("보내기").strong()).min_size(egui::vec2(120.0, 32.0))).clicked() {
            start(app);
        }
        if app.send.busy {
            ui.spinner();
            ui.label("보내는 중…");
        }
    });
    if !app.send.results.is_empty() {
        ui.add_space(12.0);
        ui.separator();
        ui.strong("보낸 결과");
        let mut ask = None;
        egui::Grid::new("results").striped(true).num_columns(5).spacing([16.0, 6.0]).show(ui, |ui| {
            for (name, r) in &app.send.results {
                ui.label(name);
                match r {
                    Ok(t) => {
                        ui.label(state_text(t.state));
                        ui.label(t.mode.map(|m| m.label()).unwrap_or("-"));
                        ui.label(t.block_reason.clone().unwrap_or_else(|| format!("개인정보: {}", pii_summary(&t.pii, t.unscannable))));
                        if t.state == TransferState::AwaitingReason && ui.button("사유 입력 후 결재 요청").clicked() {
                            ask = Some((t.id, t.file_name.clone()));
                        }
                    }
                    Err(e) => {
                        ui.label(RichText::new("실패").color(Color32::from_rgb(190, 40, 40)));
                        ui.label("-");
                        ui.label(e);
                        ui.label("");
                    }
                }
                ui.end_row();
            }
        });
        if let Some((id, name)) = ask {
            app.send.reason_for = Some((id, name, String::new()));
        }
        if app.send.results.iter().any(|(_, r)| matches!(r, Ok(t) if t.state == TransferState::AwaitingReason)) {
            ui.label(RichText::new("개인정보가 탐지된 파일은 사유를 입력해야 결재자에게 올라갑니다.").color(Color32::from_rgb(180, 110, 0)));
        }
    }
}

/// Asks the sender why a file with personal data is being sent, then submits it for pre-approval.
pub fn reason_modal(app: &mut App, ctx: &egui::Context) {
    let Some((id, name, mut reason)) = app.send.reason_for.take() else { return };
    let mut keep = true;
    egui::Modal::new(egui::Id::new("reason")).show(ctx, |ui| {
        ui.set_width(420.0);
        ui.heading("결재 요청");
        ui.label(format!("{name} 에서 개인정보가 탐지되어 사전결재가 필요합니다. 보내는 사유를 입력하세요."));
        let r = ui.add(egui::TextEdit::multiline(&mut reason).desired_rows(3).desired_width(f32::INFINITY));
        if reason.is_empty() && ui.memory(|m| m.focused().is_none()) {
            r.request_focus();
        }
        ui.horizontal(|ui| {
            if ui.add_enabled(!reason.trim().is_empty(), egui::Button::new("결재 요청")).clicked() {
                let r = reason.trim().to_string();
                app.api(ApiRequest::SubmitForApproval { id, reason: r }, move |a, resp| {
                    if let ApiResponse::Transfer(t) = resp {
                        for (_, res) in a.send.results.iter_mut() {
                            if matches!(res, Ok(x) if x.id == t.id) {
                                *res = Ok(t.clone());
                            }
                        }
                    }
                    a.toast("결재를 요청했습니다");
                    crate::ui::history::refresh(a);
                });
                keep = false;
            }
            if ui.button("취소").clicked() {
                keep = false;
            }
        });
    });
    if keep {
        app.send.reason_for = Some((id, name, reason));
    }
}

fn start(app: &mut App) {
    let Some(net) = app.net.clone() else { return };
    app.send.busy = true;
    app.send.results.clear();
    let files = app.send.files.clone();
    let reason = app.send.reason.trim().to_string();
    let progress = app.send.progress.clone();
    progress.lock().unwrap().clear();
    let ctx = app.ctx.clone();
    app.run(
        async move {
            let mut metas = vec![];
            for (p, size) in &files {
                let path = p.clone();
                let sha = tokio::task::spawn_blocking(move || sha256_file(&path)).await;
                match sha {
                    Ok(Ok(sha256)) => metas.push(FileMeta { name: p.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default(), size: *size, sha256 }),
                    _ => return Err(format!("파일을 읽을 수 없습니다: {}", p.display())),
                }
            }
            let ids = match net.call(ApiRequest::CreateTransfers { files: metas, reason }).await {
                Ok(ApiResponse::Ids(ids)) => ids,
                Ok(_) => return Err("알 수 없는 응답입니다".into()),
                Err(e) => return Err(e.message),
            };
            let mut out = vec![];
            for ((p, size), id) in files.iter().zip(ids) {
                let name = p.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
                let (prog, key, ctx2, total) = (progress.clone(), p.clone(), ctx.clone(), *size);
                let up = net
                    .upload(id, p, move |done| {
                        prog.lock().unwrap().insert(key.clone(), (done, total));
                        ctx2.request_repaint();
                    })
                    .await;
                let r = match up {
                    Ok(()) => match net.call(ApiRequest::CompleteUpload { id }).await {
                        Ok(ApiResponse::Transfer(t)) => Ok(t),
                        Ok(_) => Err("알 수 없는 응답입니다".to_string()),
                        Err(e) => Err(e.message),
                    },
                    Err(e) => Err(e.message),
                };
                out.push((name, r));
            }
            Ok(out)
        },
        |a, r| {
            a.send.busy = false;
            match r {
                Ok(results) => {
                    let all_ok = results.iter().all(|(_, r)| r.is_ok());
                    a.send.results = results;
                    if all_ok {
                        a.send.files.clear();
                        a.send.reason.clear();
                        a.toast("파일을 보냈습니다");
                    }
                }
                Err(e) => a.toast_err(e),
            }
            a.refresh_usage();
        },
    );
}

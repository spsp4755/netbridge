use crate::app::App;
use crate::ui::*;
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
    let (from, to) = match app.side {
        Some(s) => (s.label(), s.other().label()),
        None => ("이 망", "반대편 망"),
    };
    page_header(ui, "파일 보내기", Some(&format!("{from}에서 {to}(으)로 파일을 보냅니다. 개인정보가 탐지되면 결재를 거쳐 전달됩니다.")));
    let dropped: Vec<PathBuf> = ui.ctx().input(|i| i.raw.dropped_files.iter().filter_map(|f| f.path.clone()).collect());
    if !app.send.busy {
        for p in dropped {
            add(app, p);
        }
    }
    usage_card(app, ui);
    ui.add_space(12.0);
    let hovering = ui.ctx().input(|i| !i.raw.hovered_files.is_empty());
    let zone = card_frame().fill(if hovering { ACCENT_SOFT } else { CARD }).stroke(egui::Stroke::NONE).show(ui, |ui| {
        ui.set_width(ui.available_width());
        ui.vertical_centered(|ui| {
            ui.add_space(10.0);
            ui.label(RichText::new("⬆").size(34.0).color(if hovering { ACCENT } else { Color32::from_rgb(150, 165, 190) }));
            ui.label(bold(if hovering { "놓으면 목록에 추가됩니다" } else { "보낼 파일을 여기로 끌어다 놓으세요" }, 16.0));
            ui.label(muted("여러 개를 한꺼번에 보낼 수 있습니다 · 폴더는 압축해서 보내세요"));
            ui.add_space(4.0);
            if ui.add_enabled(!app.send.busy, primary("파일 선택…")).clicked() {
                if let Some(ps) = rfd::FileDialog::new().pick_files() {
                    for p in ps {
                        add(app, p);
                    }
                }
            }
            ui.add_space(6.0);
        });
    });
    let r = zone.response.rect;
    let stroke = egui::Stroke::new(1.5_f32, if hovering { ACCENT } else { Color32::from_rgb(190, 200, 216) });
    let pts = [r.left_top(), r.right_top(), r.right_bottom(), r.left_bottom(), r.left_top()];
    ui.painter().extend(egui::Shape::dashed_line(&pts, stroke, 6.0, 4.0));
    ui.add_space(12.0);

    if !app.send.files.is_empty() {
        let progress = app.send.progress.lock().unwrap().clone();
        let limit = app.usage.as_ref().map(|u| u.limits.per_file_bytes);
        let mut remove = None;
        card(ui, |ui| {
            let total: u64 = app.send.files.iter().map(|(_, s)| s).sum();
            ui.horizontal(|ui| {
                section_title(ui, &format!("보낼 파일 {}개", app.send.files.len()));
                ui.label(muted(format!("· 모두 {}", fmt_bytes(total))));
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.add_enabled(!app.send.busy, egui::Button::new("모두 빼기").small()).clicked() {
                        app.send.files.clear();
                    }
                });
            });
            ui.separator();
            for (i, (p, size)) in app.send.files.iter().enumerate() {
                ui.horizontal(|ui| {
                    ui.label(RichText::new("🗋").size(18.0).color(ACCENT));
                    ui.vertical(|ui| {
                        ui.spacing_mut().item_spacing.y = 2.0;
                        ui.label(bold(p.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default(), 14.0));
                        let over = limit.is_some_and(|l| *size > l);
                        ui.label(if over {
                            RichText::new(format!("{} · 파일 1개 최대 용량을 넘습니다", fmt_bytes(*size))).small().color(DANGER)
                        } else {
                            RichText::new(format!("{} · {}", fmt_bytes(*size), p.parent().map(|d| d.display().to_string()).unwrap_or_default())).small().color(MUTED)
                        });
                    });
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui.add_enabled(!app.send.busy, egui::Button::new("🗙").frame(false)).on_hover_text("목록에서 빼기").clicked() {
                            remove = Some(i);
                        }
                        if let Some((done, total)) = progress.get(p).filter(|(_, t)| *t > 0) {
                            ui.add(egui::ProgressBar::new(*done as f32 / *total as f32).desired_width(180.0).desired_height(8.0).fill(ACCENT));
                            ui.label(muted(format!("{}%", done * 100 / total)));
                        }
                    });
                });
            }
        });
        if let Some(i) = remove {
            app.send.files.remove(i);
        }
        ui.add_space(12.0);
    }

    card(ui, |ui| {
        section_title(ui, "보내는 사유");
        ui.label(muted("선택 입력입니다. 개인정보가 탐지된 파일은 결재를 요청할 때 사유를 꼭 적어야 합니다."));
        ui.add(egui::TextEdit::multiline(&mut app.send.reason).desired_rows(2).desired_width(f32::INFINITY).hint_text("예: 고객 제출용 보고서 반입").margin(egui::vec2(10.0, 8.0)));
        ui.add_space(6.0);
        let fits = app.usage.as_ref().map_or(true, |u| batch_check(&app.send.files.iter().map(|(_, s)| *s).collect::<Vec<_>>(), u).is_ok());
        let can = !app.send.busy && !app.send.files.is_empty() && fits;
        ui.horizontal(|ui| {
            let label = if app.send.files.is_empty() { "보내기".to_string() } else { format!("{}개 파일 보내기", app.send.files.len()) };
            if ui.add_enabled(can, primary(&label).min_size(egui::vec2(160.0, 38.0))).clicked() {
                start(app);
            }
            if app.send.busy {
                ui.add(egui::Spinner::new().color(ACCENT));
                ui.label(muted("검사하고 보내는 중…"));
            }
        });
    });

    if !app.send.results.is_empty() {
        ui.add_space(12.0);
        let mut ask = None;
        card(ui, |ui| {
            section_title(ui, "보낸 결과");
            for (name, r) in &app.send.results {
                ui.separator();
                ui.horizontal(|ui| match r {
                    Ok(t) => {
                        state_pill(ui, t.state);
                        ui.label(bold(name, 14.0));
                        if let Some(m) = t.mode {
                            tone_pill(ui, m.label(), Tone::Neutral);
                        }
                        let detail = t.block_reason.clone().unwrap_or_else(|| format!("개인정보: {}", pii_summary(&t.pii, t.unscannable)));
                        ui.label(muted(detail));
                        if t.state == TransferState::AwaitingReason {
                            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                if ui.add(primary("사유 입력 후 결재 요청")).clicked() {
                                    ask = Some((t.id, t.file_name.clone()));
                                }
                            });
                        }
                    }
                    Err(e) => {
                        tone_pill(ui, "실패", Tone::Danger);
                        ui.label(bold(name, 14.0));
                        ui.label(RichText::new(e).color(DANGER));
                    }
                });
            }
            if app.send.results.iter().any(|(_, r)| matches!(r, Ok(t) if t.state == TransferState::AwaitingReason)) {
                ui.add_space(4.0);
                banner(ui, Tone::Warn, "개인정보가 탐지된 파일은 사유를 입력해야 결재자에게 올라갑니다.");
            }
        });
        if let Some((id, name)) = ask {
            app.send.reason_for = Some((id, name, String::new()));
        }
    }
}

/// Today's allowance: limit, used, left, per-file maximum, and whether the selected files fit.
fn usage_card(app: &App, ui: &mut egui::Ui) {
    let Some(u) = &app.usage else { return };
    let left = u.limits.daily_bytes.saturating_sub(u.used_today);
    let selected: u64 = app.send.files.iter().map(|(_, s)| s).sum();
    let check = batch_check(&app.send.files.iter().map(|(_, s)| *s).collect::<Vec<_>>(), u);
    card(ui, |ui| {
        ui.horizontal(|ui| {
            ui.vertical(|ui| {
                ui.label(muted("오늘 전송 한도"));
                ui.label(bold(fmt_bytes(u.limits.daily_bytes), 20.0).color(TEXT));
            });
            ui.add_space(24.0);
            ui.vertical(|ui| {
                ui.label(muted("사용함"));
                ui.label(bold(fmt_bytes(u.used_today), 20.0).color(ACCENT));
            });
            ui.add_space(24.0);
            ui.vertical(|ui| {
                ui.label(muted("남음"));
                ui.label(bold(fmt_bytes(left), 20.0).color(if left == 0 { DANGER } else { SUCCESS }));
            });
            ui.add_space(24.0);
            ui.vertical(|ui| {
                ui.label(muted("파일 1개 최대"));
                ui.label(bold(fmt_bytes(u.limits.per_file_bytes), 20.0).color(TEXT));
            });
        });
        ui.add_space(4.0);
        let frac = if u.limits.daily_bytes > 0 { (u.used_today as f32 / u.limits.daily_bytes as f32).min(1.0) } else { 1.0 };
        let after = if u.limits.daily_bytes > 0 { ((u.used_today + selected) as f32 / u.limits.daily_bytes as f32).min(1.0) } else { 1.0 };
        let (bar, _) = ui.allocate_exact_size(egui::vec2(ui.available_width(), 10.0), egui::Sense::hover());
        let p = ui.painter();
        p.rect_filled(bar, 5.0, NEUTRAL_SOFT);
        if after > frac {
            let mut r = bar;
            r.set_width(bar.width() * after);
            p.rect_filled(r, 5.0, if check.is_ok() { Color32::from_rgb(160, 190, 245) } else { DANGER_SOFT });
        }
        if frac > 0.0 {
            let mut r = bar;
            r.set_width((bar.width() * frac).max(10.0));
            p.rect_filled(r, 5.0, if frac > 0.9 { DANGER } else { ACCENT });
        }
        let pct = if u.limits.daily_bytes > 0 { u.used_today * 100 / u.limits.daily_bytes } else { 100 };
        ui.label(RichText::new(format!("오늘 {pct}% 사용 · 한국 시간 자정에 초기화됩니다")).small().color(MUTED));
        if !app.send.files.is_empty() {
            match &check {
                Ok(()) => banner(ui, Tone::Info, &format!("선택한 파일 {}개, 모두 {} — 보낸 뒤 남는 양 {}", app.send.files.len(), fmt_bytes(selected), fmt_bytes(left - selected))),
                Err(msg) => banner(ui, Tone::Danger, msg),
            }
        }
    });
}

/// Same rule as the server: every file within the per-file limit and the batch within what is left today.
pub fn batch_check(sizes: &[u64], u: &Usage) -> Result<(), String> {
    if let Some(s) = sizes.iter().find(|s| **s > u.limits.per_file_bytes) {
        return Err(format!("파일 1개 최대 {}를 넘는 파일이 있습니다 ({})", fmt_bytes(u.limits.per_file_bytes), fmt_bytes(*s)));
    }
    let total: u64 = sizes.iter().sum();
    let left = u.limits.daily_bytes.saturating_sub(u.used_today);
    if total > left {
        return Err(format!("선택한 파일이 모두 {}로 오늘 남은 양 {}를 넘습니다. 일부를 빼거나 내일 보내세요", fmt_bytes(total), fmt_bytes(left)));
    }
    Ok(())
}

/// Asks the sender why a file with personal data is being sent, then submits it for pre-approval.
pub fn reason_modal(app: &mut App, ctx: &egui::Context) {
    let Some((id, name, mut reason)) = app.send.reason_for.take() else {
        return;
    };
    let mut keep = true;
    egui::Modal::new(egui::Id::new("reason")).frame(modal_frame()).show(ctx, |ui| {
        ui.set_width(460.0);
        ui.label(bold("결재 요청", 19.0));
        ui.add_space(4.0);
        banner(ui, Tone::Warn, &format!("{name} 에서 개인정보가 탐지되어 사전결재가 필요합니다."));
        ui.label("결재자에게 보여 줄 보내는 사유를 입력하세요.");
        let r = ui.add(egui::TextEdit::multiline(&mut reason).desired_rows(3).desired_width(f32::INFINITY).margin(egui::vec2(10.0, 8.0)));
        if reason.is_empty() && ui.memory(|m| m.focused().is_none()) {
            r.request_focus();
        }
        ui.horizontal(|ui| {
            if ui.add_enabled(!reason.trim().is_empty(), primary("결재 요청")).clicked() {
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
            if ui.add(secondary("취소")).clicked() {
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
                        if a.send.results.iter().any(|(_, r)| matches!(r, Ok(t) if t.state == TransferState::AwaitingReason)) {
                            a.notify("개인정보가 탐지된 파일이 있습니다. 사유를 입력해 결재를 요청하세요", Tone::Warn, 8);
                        } else {
                            a.toast("파일을 보냈습니다");
                        }
                    }
                }
                Err(e) => a.toast_err(e),
            }
            a.refresh_usage();
        },
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    const GB: u64 = 1024 * 1024 * 1024;

    fn usage(used: u64) -> Usage {
        Usage { used_today: used, limits: Limits { daily_bytes: 10 * GB, per_file_bytes: 2 * GB } }
    }

    #[test]
    fn five_files_of_1_9_gb_fit_a_10_gb_day_with_2_gb_files() {
        let f = 19 * GB / 10;
        assert!(batch_check(&[f; 5], &usage(0)).is_ok());
        assert!(batch_check(&[f; 6], &usage(0)).is_err());
        assert!(batch_check(&[f; 5], &usage(GB)).is_err());
        assert!(batch_check(&[2 * GB + 1], &usage(0)).is_err());
    }
}

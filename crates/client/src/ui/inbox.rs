use crate::app::App;
use crate::ui::*;
use eframe::egui::{self, RichText};
use egui_extras::{Column, TableBuilder};
use netbridge_proto::*;
use std::collections::HashSet;
use std::path::PathBuf;

#[derive(Default)]
pub struct State {
    pub loaded: bool,
    pub items: Vec<TransferInfo>,
    pub busy: HashSet<i64>,
    pub last_saved: Option<PathBuf>,
}

pub fn refresh(app: &mut App) {
    app.api(ApiRequest::ListIncoming, |a, r| {
        if let ApiResponse::Transfers(v) = r {
            a.inbox.items = v;
            a.inbox.loaded = true;
        }
    });
}

pub fn show(app: &mut App, ui: &mut egui::Ui) {
    let from = app.side.map(|s| s.other().label()).unwrap_or("반대편 망");
    page_header(ui, "받은 파일", Some(&format!("{from}에서 보낸 파일입니다. 받으면 저장 폴더에 저장됩니다.")));
    ui.horizontal(|ui| {
        ui.label(muted("저장 폴더"));
        ui.label(app.cfg.download_dir.display().to_string());
        if ui.add(secondary("폴더 열기")).clicked() {
            let _ = std::fs::create_dir_all(&app.cfg.download_dir);
            let _ = open::that(&app.cfg.download_dir);
        }
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if ui.add(secondary("⟳ 새로고침")).clicked() {
                refresh(app);
            }
        });
    });
    if let Some(p) = app.inbox.last_saved.clone() {
        ui.add_space(4.0);
        egui::Frame::new().fill(SUCCESS_SOFT).corner_radius(8).inner_margin(egui::Margin::symmetric(12, 6)).show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal(|ui| {
                ui.label(RichText::new(format!("✔ 저장했습니다: {}", p.display())).color(SUCCESS));
                if ui.add(egui::Button::new("열기").small()).clicked() {
                    let _ = open::that(&p);
                }
                if ui.add(egui::Button::new("폴더에서 보기").small()).clicked() {
                    let _ = open::that(p.parent().unwrap_or(&p));
                }
            });
        });
    }
    ui.add_space(8.0);
    if app.inbox.items.is_empty() {
        card(ui, |ui| {
            if app.inbox.loaded {
                empty_state(ui, "⬇", "받을 파일이 없습니다", &format!("{from}에서 파일을 보내면 여기에 나타납니다."));
            } else {
                empty_state(ui, "⟳", "불러오는 중…", "잠시만 기다려 주세요.");
            }
        });
        return;
    }
    let mut download = None;
    card(ui, |ui| {
        TableBuilder::new(ui)
            .striped(true)
            .column(Column::auto().at_least(120.0))
            .column(Column::remainder().at_least(180.0).clip(true))
            .column(Column::auto().at_least(70.0))
            .column(Column::auto().at_least(100.0))
            .column(Column::auto().at_least(200.0))
            .column(Column::auto().at_least(80.0))
            .column(Column::auto().at_least(70.0))
            .header(28.0, |mut h| {
                for c in ["보낸 시각", "파일", "크기", "송신 IP", "결재", "상태", ""] {
                    h.col(|ui| {
                        ui.label(muted(c));
                    });
                }
            })
            .body(|mut body| {
                for t in &app.inbox.items {
                    body.row(34.0, |mut row| {
                        row.col(|ui| {
                            ui.label(fmt_ts(t.created_at));
                        });
                        row.col(|ui| {
                            ui.label(bold(&t.file_name, 14.0)).on_hover_text(format!("보낸 사람: {}\n사유: {}\nSHA-256: {}", t.owner, t.reason, t.sha256));
                        });
                        row.col(|ui| {
                            ui.label(fmt_bytes(t.size));
                        });
                        row.col(|ui| {
                            ui.label(&t.sender_ip);
                        });
                        row.col(|ui| {
                            ui.label(approval_text(&t.approval));
                        });
                        row.col(|ui| {
                            state_pill(ui, t.state);
                        });
                        row.col(|ui| {
                            let busy = app.inbox.busy.contains(&t.id);
                            if busy {
                                ui.spinner();
                            } else if t.state == TransferState::Available && ui.add(primary("받기").min_size(egui::vec2(64.0, 28.0))).clicked() {
                                download = Some(t.clone());
                            } else if t.state == TransferState::Downloaded && ui.add(egui::Button::new("다시 받기").small()).clicked() {
                                download = Some(t.clone());
                            }
                        });
                    });
                }
            })
    });
    if let Some(t) = download {
        start_download(app, t);
    }
}

fn start_download(app: &mut App, t: TransferInfo) {
    let Some(net) = app.net.clone() else { return };
    app.inbox.busy.insert(t.id);
    let dir = app.cfg.download_dir.clone();
    let id = t.id;
    app.run(
        async move {
            let p = net.download(&t, &dir, |_| {}).await?;
            net.call(ApiRequest::MarkDownloaded { id: t.id }).await?;
            Ok::<_, ApiError>(p)
        },
        move |a, r| {
            a.inbox.busy.remove(&id);
            match r {
                Ok(p) => {
                    a.toast(format!("저장했습니다: {}", p.display()));
                    a.inbox.last_saved = Some(p);
                    refresh(a);
                }
                Err(e) => a.api_error(e),
            }
        },
    );
}

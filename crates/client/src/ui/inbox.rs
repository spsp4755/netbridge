use crate::app::App;
use crate::ui::{approval_text, fmt_bytes, fmt_ts, state_text, title};
use eframe::egui;
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
    title(ui, &format!("받은 파일 ← {from}"));
    ui.horizontal(|ui| {
        if ui.button("새로고침").clicked() {
            refresh(app);
        }
        ui.label(format!("저장 폴더: {}", app.cfg.download_dir.display()));
        if ui.small_button("폴더 열기").clicked() {
            let _ = std::fs::create_dir_all(&app.cfg.download_dir);
            let _ = open::that(&app.cfg.download_dir);
        }
    });
    if let Some(p) = app.inbox.last_saved.clone() {
        ui.horizontal(|ui| {
            ui.label(format!("마지막으로 받은 파일: {}", p.display()));
            if ui.small_button("열기").clicked() {
                let _ = open::that(&p);
            }
        });
    }
    ui.add_space(6.0);
    if app.inbox.items.is_empty() {
        ui.label(if app.inbox.loaded { "받을 파일이 없습니다." } else { "불러오는 중…" });
        return;
    }
    let mut download = None;
    TableBuilder::new(ui)
        .striped(true)
        .column(Column::auto().at_least(120.0))
        .column(Column::remainder().at_least(180.0).clip(true))
        .column(Column::auto().at_least(70.0))
        .column(Column::auto().at_least(100.0))
        .column(Column::auto().at_least(200.0))
        .column(Column::auto().at_least(80.0))
        .column(Column::auto().at_least(70.0))
        .header(22.0, |mut h| {
            for c in ["보낸 시각", "파일", "크기", "송신 IP", "결재", "상태", ""] {
                h.col(|ui| {
                    ui.strong(c);
                });
            }
        })
        .body(|mut body| {
            for t in &app.inbox.items {
                body.row(24.0, |mut row| {
                    row.col(|ui| {
                        ui.label(fmt_ts(t.created_at));
                    });
                    row.col(|ui| {
                        ui.label(&t.file_name).on_hover_text(format!("사유: {}\nSHA-256: {}", t.reason, t.sha256));
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
                        ui.label(state_text(t.state));
                    });
                    row.col(|ui| {
                        let busy = app.inbox.busy.contains(&t.id);
                        if busy {
                            ui.spinner();
                        } else if ui.button("받기").clicked() {
                            download = Some(t.clone());
                        }
                    });
                });
            }
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

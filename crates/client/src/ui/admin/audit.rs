use super::adm;
use crate::app::App;
use crate::ui::fmt_ts;
use chrono::TimeZone;
use eframe::egui;
use egui_extras::{Column, DatePickerButton, TableBuilder};
use netbridge_proto::*;

const KINDS: [(&str, &str); 14] = [
    ("", "전체"),
    ("login", "로그인"),
    ("login_fail", "로그인 실패"),
    ("logout", "로그아웃"),
    ("transfer", "파일 전송"),
    ("transfer_blocked", "전송 차단"),
    ("download", "파일 받음"),
    ("approval", "결재"),
    ("post_overdue", "사후결재 기한 초과"),
    ("delegation", "대결"),
    ("clipboard", "클립보드"),
    ("clipboard_blocked", "클립보드 차단"),
    ("policy_change", "정책 변경"),
    ("admin", "관리자 작업"),
];

fn kind_label(k: &str) -> &str {
    KINDS.iter().find(|(id, _)| *id == k).map(|(_, l)| *l).unwrap_or(k)
}

pub fn audit(app: &mut App, ui: &mut egui::Ui) {
    ui.horizontal_wrapped(|ui| {
        ui.label("기간");
        ui.add(DatePickerButton::new(&mut app.admin.audit_from).id_salt("af"));
        ui.label("~");
        ui.add(DatePickerButton::new(&mut app.admin.audit_to).id_salt("at"));
        ui.label("사용자");
        ui.add(egui::TextEdit::singleline(&mut app.admin.audit_user).desired_width(100.0).hint_text("아이디"));
        ui.label("종류");
        egui::ComboBox::from_id_salt("akind").selected_text(kind_label(&app.admin.audit_kind)).show_ui(ui, |ui| {
            for (id, l) in KINDS {
                ui.selectable_value(&mut app.admin.audit_kind, id.to_string(), l);
            }
        });
        if ui.button("검색").clicked() {
            search(app);
        }
        if ui.add_enabled(!app.admin.audit.is_empty(), egui::Button::new("CSV 저장")).clicked() {
            export_csv(app);
        }
    });
    ui.label(format!("{}건", app.admin.audit.len()));
    TableBuilder::new(ui)
        .striped(true)
        .column(Column::auto().at_least(120.0))
        .column(Column::auto().at_least(80.0))
        .column(Column::auto().at_least(100.0))
        .column(Column::auto().at_least(100.0))
        .column(Column::remainder().clip(true))
        .header(22.0, |mut h| {
            for c in ["시각", "사용자", "종류", "IP", "내용"] {
                h.col(|ui| {
                    ui.strong(c);
                });
            }
        })
        .body(|body| {
            let rows = &app.admin.audit;
            body.rows(22.0, rows.len(), |mut row| {
                let r = &rows[row.index()];
                row.col(|ui| {
                    ui.label(fmt_ts(r.at));
                });
                row.col(|ui| {
                    ui.label(r.user.clone().unwrap_or_default());
                });
                row.col(|ui| {
                    ui.label(kind_label(&r.kind));
                });
                row.col(|ui| {
                    ui.label(r.ip.clone().unwrap_or_default());
                });
                row.col(|ui| {
                    ui.label(&r.detail).on_hover_text(&r.detail);
                });
            });
        });
}

fn search(app: &mut App) {
    let kst = chrono::FixedOffset::east_opt(9 * 3600).unwrap();
    let ts = |d: chrono::NaiveDate, end: bool| {
        let t = if end { d.and_hms_opt(23, 59, 59).unwrap() } else { d.and_hms_opt(0, 0, 0).unwrap() };
        kst.from_local_datetime(&t).unwrap().timestamp()
    };
    let query = AuditQuery {
        from: Some(ts(app.admin.audit_from, false)),
        to: Some(ts(app.admin.audit_to, true)),
        user: Some(app.admin.audit_user.trim().to_string()).filter(|s| !s.is_empty()),
        kind: Some(app.admin.audit_kind.clone()).filter(|s| !s.is_empty()),
        limit: Some(20_000),
    };
    adm(app, AdminRequest::QueryAudit { query }, |a, r| {
        if let ApiResponse::Audit(v) = r {
            a.admin.audit = v;
        }
    });
}

fn csv_field(s: &str) -> String {
    if s.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

/// UTF-8 with BOM so Excel opens Korean text correctly.
pub fn to_csv(rows: &[AuditRow]) -> String {
    let mut out = String::from("\u{feff}시각,사용자,종류,IP,내용\r\n");
    for r in rows {
        let cols = [fmt_ts(r.at), r.user.clone().unwrap_or_default(), kind_label(&r.kind).to_string(), r.ip.clone().unwrap_or_default(), r.detail.clone()];
        out.push_str(&cols.iter().map(|c| csv_field(c)).collect::<Vec<_>>().join(","));
        out.push_str("\r\n");
    }
    out
}

fn export_csv(app: &mut App) {
    let name = format!("netbridge-audit-{}-{}.csv", app.admin.audit_from, app.admin.audit_to);
    let Some(path) = rfd::FileDialog::new().set_file_name(name).add_filter("CSV", &["csv"]).save_file() else { return };
    match std::fs::write(&path, to_csv(&app.admin.audit)) {
        Ok(()) => app.toast(format!("저장했습니다: {}", path.display())),
        Err(e) => app.toast_err(format!("저장 실패: {e}")),
    }
}

pub fn refresh_sessions(app: &App) {
    adm(app, AdminRequest::ListSessions, |a, r| {
        if let ApiResponse::Sessions(v) = r {
            a.admin.sessions = v;
        }
    });
}

pub fn sessions(app: &mut App, ui: &mut egui::Ui) {
    if ui.button("새로고침").clicked() {
        refresh_sessions(app);
    }
    let sessions = app.admin.sessions.clone();
    let mut kill = None;
    egui::Grid::new("sess").striped(true).num_columns(5).spacing([16.0, 6.0]).show(ui, |ui| {
        for c in ["사용자", "로그인", "마지막 사용", "접속 중인 PC", ""] {
            ui.strong(c);
        }
        ui.end_row();
        for s in &sessions {
            ui.label(format!("{} ({})", s.name, s.username));
            ui.label(fmt_ts(s.created_at));
            ui.label(fmt_ts(s.last_seen));
            let on: Vec<String> = s.online.iter().map(|x| app.name(x)).collect();
            ui.label(if on.is_empty() { "없음".to_string() } else { on.join(", ") });
            if ui.small_button("강제 종료").clicked() {
                kill = Some(s.id);
            }
            ui.end_row();
        }
    });
    if let Some(id) = kill {
        adm(app, AdminRequest::KillSession { session_id: id }, |a, _| {
            a.toast("세션을 종료했습니다");
            refresh_sessions(a);
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csv_escapes_and_has_bom() {
        let rows = vec![AuditRow { at: 1_800_000_000, user: Some("a".into()), kind: "login".into(), ip: Some("1.1.1.1".into()), detail: "x, \"y\"".into() }];
        let s = to_csv(&rows);
        assert!(s.starts_with('\u{feff}'));
        assert!(s.contains("2027-01-15 17:00,a,로그인,1.1.1.1,\"x, \"\"y\"\"\"\r\n"), "{s}");
    }
}

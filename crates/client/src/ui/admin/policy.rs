use super::{load_policy, save_policy};
use crate::app::App;
use eframe::egui::{self, Color32, RichText};
use netbridge_proto::*;

fn opt_u32(ui: &mut egui::Ui, v: &mut Option<u32>, default: u32, unit: &str, off: &str) {
    ui.horizontal(|ui| {
        let mut on = v.is_some();
        if ui.checkbox(&mut on, "").changed() {
            *v = on.then_some(default);
        }
        match v.as_mut() {
            Some(x) => {
                ui.add(egui::DragValue::new(x).range(1..=100_000).suffix(unit));
            }
            None => {
                ui.label(off);
            }
        }
    });
}

fn action_combo(ui: &mut egui::Ui, id: impl std::hash::Hash, a: &mut PiiAction) {
    egui::ComboBox::from_id_salt(id).selected_text(a.label()).show_ui(ui, |ui| {
        for x in [PiiAction::LogOnly, PiiAction::ForcePre, PiiAction::Block] {
            ui.selectable_value(a, x, x.label());
        }
    });
}

pub fn policy(app: &mut App, ui: &mut egui::Ui) {
    ui.label("보안 규정이나 인증 요건이 바뀌면 여기서 값만 바꾸면 됩니다. 저장하면 양쪽 서버와 접속 중인 PC에 바로 반영됩니다.");
    ui.add_space(6.0);
    let Some(p) = app.admin.policy.as_mut() else {
        ui.label("불러오는 중…");
        return;
    };
    egui::Grid::new("policy").num_columns(2).striped(true).spacing([16.0, 8.0]).show(ui, |ui| {
        ui.label("세션 최대 유지 시간");
        opt_u32(ui, &mut p.session_max_minutes, 480, " 분", "제한 없음 (로그아웃할 때까지 유지)");
        ui.end_row();
        ui.label("미사용 시 화면 잠금");
        opt_u32(ui, &mut p.idle_lock_minutes, 10, " 분", "사용 안 함");
        ui.end_row();
        ui.label("비밀번호 최소 길이");
        ui.add(egui::DragValue::new(&mut p.pw_min_len).range(4..=64).suffix(" 자"));
        ui.end_row();
        ui.label("비밀번호 조합");
        ui.checkbox(&mut p.pw_require_mix, "영문·숫자·특수문자 모두 포함");
        ui.end_row();
        ui.label("비밀번호 변경 주기");
        opt_u32(ui, &mut p.pw_max_age_days, 90, " 일", "없음");
        ui.end_row();
        ui.label("로그인 실패 잠금");
        ui.add(egui::DragValue::new(&mut p.login_fail_lock).range(1..=20).suffix(" 회"));
        ui.end_row();
        ui.label("차단 확장자");
        ui.add(egui::TextEdit::singleline(&mut app.admin.blocked_text).desired_width(360.0));
        ui.end_row();
        ui.label("허용 확장자 (비우면 차단 목록 외 전부 허용)");
        ui.add(egui::TextEdit::singleline(&mut app.admin.allowed_text).desired_width(360.0));
        ui.end_row();
        ui.label("파일 보관 기간");
        ui.add(egui::DragValue::new(&mut p.file_retention_days).range(1..=3650).suffix(" 일"));
        ui.end_row();
        ui.label("이력 보관 기간");
        ui.add(egui::DragValue::new(&mut p.audit_retention_days).range(1..=36500).suffix(" 일"));
        ui.end_row();
        ui.label("사후결재 기한");
        ui.add(egui::DragValue::new(&mut p.post_deadline_days).range(1..=365).suffix(" 일"));
        ui.end_row();
        ui.label("클립보드 최대 크기");
        let mut kb = p.clipboard_max_bytes / 1024;
        if ui.add(egui::DragValue::new(&mut kb).range(1..=10_240).suffix(" KB")).changed() {
            p.clipboard_max_bytes = kb * 1024;
        }
        ui.end_row();
        ui.label("내용 검사 불가 파일");
        action_combo(ui, "unscan", &mut p.pii_unscannable_action);
        ui.end_row();
    });
    ui.add_space(8.0);
    ui.horizontal(|ui| {
        if ui.button(RichText::new("저장").strong()).clicked() {
            save_policy(app);
        }
        if ui.button("되돌리기").clicked() {
            load_policy(app);
        }
        ui.separator();
        if ui.button("정책 내보내기").clicked() {
            export(app);
        }
        if ui.button("정책 가져오기").clicked() {
            import(app);
        }
    });
}

fn export(app: &mut App) {
    let Some(p) = app.admin.policy.clone() else { return };
    let Some(path) = rfd::FileDialog::new().set_file_name("netbridge-policy.json").add_filter("JSON", &["json"]).save_file() else { return };
    match serde_json::to_string_pretty(&p).map_err(|e| e.to_string()).and_then(|s| std::fs::write(&path, s).map_err(|e| e.to_string())) {
        Ok(()) => app.toast(format!("정책을 내보냈습니다: {}", path.display())),
        Err(e) => app.toast_err(format!("내보내기 실패: {e}")),
    }
}

fn import(app: &mut App) {
    let Some(path) = rfd::FileDialog::new().add_filter("JSON", &["json"]).pick_file() else { return };
    match std::fs::read_to_string(&path).map_err(|e| e.to_string()).and_then(|s| serde_json::from_str::<Policy>(&s).map_err(|e| e.to_string())) {
        Ok(p) => {
            app.admin.blocked_text = crate::ui::exts_to_text(&p.blocked_exts);
            app.admin.allowed_text = crate::ui::exts_to_text(&p.allowed_exts);
            app.admin.policy = Some(p);
            app.toast("정책을 불러왔습니다. 확인한 뒤 저장을 누르면 적용됩니다");
        }
        Err(e) => app.toast_err(format!("정책 파일 형식 오류: {e}")),
    }
}

pub fn pii(app: &mut App, ui: &mut egui::Ui) {
    let Some(p) = app.admin.policy.as_mut() else {
        ui.label("불러오는 중…");
        return;
    };
    ui.label("보내는 파일과 클립보드에서 개인정보를 찾습니다. 항목마다 몇 건 이상일 때 어떤 조치를 할지 정합니다. 클립보드는 결재가 없으므로 \"사전결재 강제\"도 차단으로 처리합니다.");
    ui.add_space(6.0);
    let mut remove = None;
    egui::Grid::new("pii").striped(true).num_columns(5).spacing([12.0, 6.0]).show(ui, |ui| {
        for c in ["사용", "항목", "기준 건수", "조치", "정규식"] {
            ui.strong(c);
        }
        ui.end_row();
        for (i, r) in p.pii_rules.iter_mut().enumerate() {
            ui.checkbox(&mut r.enabled, "");
            if r.builtin {
                ui.label(&r.name);
            } else {
                ui.add(egui::TextEdit::singleline(&mut r.name).desired_width(120.0));
            }
            ui.add(egui::DragValue::new(&mut r.threshold).range(1..=10_000).suffix(" 건 이상"));
            action_combo(ui, ("pa", i), &mut r.action);
            if r.builtin {
                ui.label(RichText::new("기본 제공").small());
            } else {
                ui.horizontal(|ui| {
                    let pat = r.pattern.get_or_insert_with(String::new);
                    ui.add(egui::TextEdit::singleline(pat).desired_width(220.0).font(egui::TextStyle::Monospace));
                    if let Err(e) = netbridge_pii::validate_custom(pat) {
                        ui.label(RichText::new("✕").color(Color32::from_rgb(190, 40, 40))).on_hover_text(e);
                    }
                    if ui.small_button("삭제").clicked() {
                        remove = Some(i);
                    }
                });
            }
            ui.end_row();
        }
    });
    if let Some(i) = remove {
        p.pii_rules.remove(i);
    }
    let (mut add, mut save) = (false, false);
    ui.horizontal(|ui| {
        add = ui.button("사용자 정의 항목 추가").clicked();
        save = ui.button(RichText::new("저장").strong()).clicked();
    });
    if add {
        let n = p.pii_rules.iter().filter(|r| !r.builtin).count() + 1;
        p.pii_rules.push(PiiRule { id: format!("custom{n}-{}", chrono::Utc::now().timestamp()), name: format!("사용자 정의 {n}"), enabled: true, builtin: false, pattern: Some(String::new()), threshold: 1, action: PiiAction::ForcePre });
    }
    if save {
        save_policy(app);
    }
    ui.add_space(10.0);
    ui.strong("시험해 보기");
    ui.add(egui::TextEdit::multiline(&mut app.admin.pii_test).desired_rows(3).desired_width(f32::INFINITY).hint_text("예: 주민번호 900101-1234568, 카드 4111-1111-1111-1111"));
    if let Some(p) = &app.admin.policy {
        if !app.admin.pii_test.is_empty() {
            let hits = netbridge_pii::scan_text(&app.admin.pii_test, &p.pii_rules);
            let action = netbridge_pii::decide(&hits, false, &p.pii_rules, p.pii_unscannable_action);
            ui.label(format!("탐지: {}", crate::ui::pii_summary(&hits, false)));
            ui.label(format!("조치: {}", action.map(|a| a.label()).unwrap_or("없음")));
            ui.label(format!("이력에 남는 모습: {}", netbridge_pii::mask_text(&app.admin.pii_test, &p.pii_rules)));
        }
    }
}

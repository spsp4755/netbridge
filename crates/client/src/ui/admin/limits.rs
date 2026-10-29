use super::{adm, dept_name, refresh, save_policy};
use crate::app::App;
use crate::ui::{fmt_bytes, mb_edit, text_to_exts};
use eframe::egui;
use netbridge_proto::*;

pub fn limits(app: &mut App, ui: &mut egui::Ui) {
    ui.strong("전사 기본값");
    if let Some(p) = app.admin.policy.as_mut() {
        egui::Grid::new("deflim").num_columns(2).spacing([12.0, 6.0]).show(ui, |ui| {
            ui.label("하루 총 전송량");
            mb_edit(ui, &mut p.default_limits.daily_bytes);
            ui.end_row();
            ui.label("파일 1개 최대 크기");
            mb_edit(ui, &mut p.default_limits.per_file_bytes);
            ui.end_row();
        });
        if ui.button("기본값 저장").clicked() {
            save_policy(app);
        }
    }
    ui.add_space(12.0);
    ui.strong("부서·개인 예외 (개인 → 부서 → 전사 순으로 적용)");
    let overrides = app.admin.overrides.clone();
    let mut remove = None;
    egui::Grid::new("ov").striped(true).num_columns(4).spacing([16.0, 4.0]).show(ui, |ui| {
        for o in &overrides {
            ui.label(match o.scope {
                LimitScope::Dept(_) => "부서",
                LimitScope::User(_) => "개인",
            });
            ui.label(&o.label);
            ui.label(format!("하루 {} · 파일 {}", fmt_bytes(o.limits.daily_bytes), fmt_bytes(o.limits.per_file_bytes)));
            if ui.small_button("삭제").clicked() {
                remove = Some(o.scope);
            }
            ui.end_row();
        }
    });
    if let Some(scope) = remove {
        adm(app, AdminRequest::SetLimitOverride { scope, limits: None }, |a, _| refresh(a));
    }
    ui.add_space(8.0);
    egui::Frame::group(ui.style()).show(ui, |ui| {
        ui.horizontal(|ui| {
            ui.radio_value(&mut app.admin.ov_user, false, "부서");
            ui.radio_value(&mut app.admin.ov_user, true, "개인");
            let label = if app.admin.ov_user { super::user_label(app, app.admin.ov_target) } else { dept_name(app, app.admin.ov_target) };
            let users = app.admin.users.clone();
            let depts = app.admin.depts.clone();
            egui::ComboBox::from_id_salt("ovt").selected_text(label).show_ui(ui, |ui| {
                if app.admin.ov_user {
                    for u in &users {
                        ui.selectable_value(&mut app.admin.ov_target, Some(u.id), format!("{} ({})", u.name, u.username));
                    }
                } else {
                    for d in &depts {
                        ui.selectable_value(&mut app.admin.ov_target, Some(d.id), &d.name);
                    }
                }
            });
        });
        ui.horizontal(|ui| {
            ui.label("하루");
            mb_edit(ui, &mut app.admin.ov_limits.daily_bytes);
            ui.label("파일 1개");
            mb_edit(ui, &mut app.admin.ov_limits.per_file_bytes);
            if ui.add_enabled(app.admin.ov_target.is_some(), egui::Button::new("예외 저장")).clicked() {
                let id = app.admin.ov_target.unwrap();
                let scope = if app.admin.ov_user { LimitScope::User(id) } else { LimitScope::Dept(id) };
                adm(app, AdminRequest::SetLimitOverride { scope, limits: Some(app.admin.ov_limits) }, |a, _| {
                    a.toast("예외 한도를 저장했습니다");
                    refresh(a);
                });
            }
        });
    });
}

pub fn rules(app: &mut App, ui: &mut egui::Ui) {
    ui.label("위에서부터 처음 맞는 규칙의 결재 방식을 씁니다. 맞는 규칙이 없으면 사전결재입니다. 개인정보 탐지로 \"사전결재 강제\"가 되면 규칙과 상관없이 사전결재입니다.");
    ui.add_space(6.0);
    let depts = app.admin.depts.clone();
    let mut swap = None;
    let mut remove = None;
    let n = app.admin.rules.len();
    app.admin.rule_exts.resize(n, String::new());
    egui::Grid::new("rules").striped(true).num_columns(7).spacing([10.0, 6.0]).show(ui, |ui| {
        for c in ["순서", "방향", "최대 크기", "확장자 (쉼표로 구분, 비우면 전체)", "부서", "결재 방식", ""] {
            ui.strong(c);
        }
        ui.end_row();
        for i in 0..n {
            ui.horizontal(|ui| {
                ui.label(format!("{}", i + 1));
                if ui.add_enabled(i > 0, egui::Button::new("▲").small()).clicked() {
                    swap = Some((i, i - 1));
                }
                if ui.add_enabled(i + 1 < n, egui::Button::new("▼").small()).clicked() {
                    swap = Some((i, i + 1));
                }
            });
            let r = &mut app.admin.rules[i];
            let dir_label = |d: Option<Direction>| d.map(|d| d.label()).unwrap_or("양방향");
            egui::ComboBox::from_id_salt(("rdir", i)).selected_text(dir_label(r.direction)).show_ui(ui, |ui| {
                ui.selectable_value(&mut r.direction, None, "양방향");
                ui.selectable_value(&mut r.direction, Some(Direction::ToInternal), Direction::ToInternal.label());
                ui.selectable_value(&mut r.direction, Some(Direction::ToExternal), Direction::ToExternal.label());
            });
            ui.horizontal(|ui| {
                let mut on = r.max_size.is_some();
                if ui.checkbox(&mut on, "").changed() {
                    r.max_size = on.then_some(10 * MIB);
                }
                if let Some(m) = r.max_size.as_mut() {
                    mb_edit(ui, m);
                    ui.label("이하");
                } else {
                    ui.label("제한 없음");
                }
            });
            ui.add(egui::TextEdit::singleline(&mut app.admin.rule_exts[i]).desired_width(180.0));
            let dname = r.dept_id.and_then(|id| depts.iter().find(|d| d.id == id)).map(|d| d.name.clone()).unwrap_or_else(|| "전체".into());
            egui::ComboBox::from_id_salt(("rdept", i)).selected_text(dname).show_ui(ui, |ui| {
                ui.selectable_value(&mut r.dept_id, None, "전체");
                for d in &depts {
                    ui.selectable_value(&mut r.dept_id, Some(d.id), &d.name);
                }
            });
            egui::ComboBox::from_id_salt(("rmode", i)).selected_text(r.mode.label()).show_ui(ui, |ui| {
                ui.selectable_value(&mut r.mode, ApprovalMode::Pre, "사전결재");
                ui.selectable_value(&mut r.mode, ApprovalMode::Post, "사후결재");
            });
            if ui.small_button("삭제").clicked() {
                remove = Some(i);
            }
            ui.end_row();
        }
    });
    if let Some((a, b)) = swap {
        app.admin.rules.swap(a, b);
        app.admin.rule_exts.swap(a, b);
    }
    if let Some(i) = remove {
        app.admin.rules.remove(i);
        app.admin.rule_exts.remove(i);
    }
    ui.horizontal(|ui| {
        if ui.button("규칙 추가").clicked() {
            app.admin.rules.push(ApprovalRule { order: 0, direction: None, max_size: Some(10 * MIB), exts: vec![], dept_id: None, mode: ApprovalMode::Post });
            app.admin.rule_exts.push(String::new());
        }
        if ui.button("저장").clicked() {
            let rules: Vec<ApprovalRule> = app
                .admin
                .rules
                .iter()
                .zip(&app.admin.rule_exts)
                .enumerate()
                .map(|(i, (r, e))| ApprovalRule { order: i as i32, exts: text_to_exts(e), ..r.clone() })
                .collect();
            adm(app, AdminRequest::SetApprovalRules { rules }, |a, _| {
                a.toast("결재 규칙을 저장했습니다");
                refresh(a);
            });
        }
    });
}

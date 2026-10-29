use super::{adm, dept_name, refresh, save_policy};
use crate::app::App;
use crate::ui::{fmt_bytes, mb_edit};
use eframe::egui;
use netbridge_proto::*;

pub fn limits(app: &mut App, ui: &mut egui::Ui) {
    ui.strong("모든 통로 기본값 (통로 정책에서 따로 정하지 않은 통로에 적용)");
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

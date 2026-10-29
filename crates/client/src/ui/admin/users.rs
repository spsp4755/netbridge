use super::{adm, dept_name, refresh, user_label};
use crate::app::App;
use eframe::egui::{self, Color32, RichText};
use egui_extras::{Column, TableBuilder};
use netbridge_proto::*;

fn new_user() -> UserInput {
    UserInput { id: None, username: String::new(), name: String::new(), dept_id: None, role: Role::User, approver_id: None, password: Some(String::new()) }
}

pub fn users(app: &mut App, ui: &mut egui::Ui) {
    if ui.button("사용자 추가").clicked() {
        app.admin.user_form = Some(new_user());
    }
    user_form(app, ui);
    reset_form(app, ui);
    ui.add_space(6.0);
    let users = app.admin.users.clone();
    let mut edit = None;
    let mut actions: Vec<AdminRequest> = vec![];
    TableBuilder::new(ui)
        .striped(true)
        .column(Column::auto().at_least(90.0))
        .column(Column::auto().at_least(90.0))
        .column(Column::auto().at_least(90.0))
        .column(Column::auto().at_least(60.0))
        .column(Column::auto().at_least(130.0))
        .column(Column::auto().at_least(120.0))
        .column(Column::remainder().at_least(260.0))
        .header(22.0, |mut h| {
            for c in ["아이디", "이름", "부서", "역할", "결재자", "등록 PC", "관리"] {
                h.col(|ui| {
                    ui.strong(c);
                });
            }
        })
        .body(|mut body| {
            for u in &users {
                body.row(26.0, |mut row| {
                    row.col(|ui| {
                        ui.label(&u.username);
                        if u.locked {
                            ui.label(RichText::new("잠김").color(Color32::from_rgb(190, 40, 40)));
                        }
                    });
                    row.col(|ui| {
                        ui.label(&u.name);
                    });
                    row.col(|ui| {
                        ui.label(dept_name(app, u.dept_id));
                    });
                    row.col(|ui| {
                        ui.label(if u.role == Role::Admin { "관리자" } else { "사용자" });
                    });
                    row.col(|ui| {
                        ui.label(user_label(app, u.approver_id));
                    });
                    row.col(|ui| {
                        let s: Vec<&str> = u.devices.iter().map(|s| s.label()).collect();
                        ui.label(if s.is_empty() { "-".to_string() } else { s.join(", ") });
                    });
                    row.col(|ui| {
                        ui.horizontal(|ui| {
                        if ui.small_button("수정").clicked() {
                            edit = Some(u.clone());
                        }
                        if ui.small_button("비밀번호 초기화").clicked() {
                            app.admin.reset_pw = Some((u.id, String::new()));
                        }
                        if u.locked && ui.small_button("잠금 해제").clicked() {
                            actions.push(AdminRequest::UnlockUser { user_id: u.id });
                        }
                        for side in &u.devices {
                            if ui.small_button(format!("{} PC 해제", side.label())).clicked() {
                                actions.push(AdminRequest::ReleaseDevice { user_id: u.id, side: *side });
                            }
                        }
                        });
                    });
                });
            }
        });
    if let Some(u) = edit {
        app.admin.user_form = Some(UserInput { id: Some(u.id), username: u.username, name: u.name, dept_id: u.dept_id, role: u.role, approver_id: u.approver_id, password: None });
    }
    for req in actions {
        adm(app, req, |a, _| {
            a.toast("처리했습니다");
            refresh(a);
        });
    }
}

fn user_form(app: &mut App, ui: &mut egui::Ui) {
    let Some(mut f) = app.admin.user_form.take() else { return };
    let mut keep = true;
    let users = app.admin.users.clone();
    let depts = app.admin.depts.clone();
    egui::Frame::group(ui.style()).show(ui, |ui| {
        ui.strong(if f.id.is_some() { "사용자 수정" } else { "사용자 추가" });
        egui::Grid::new("uform").num_columns(2).spacing([12.0, 6.0]).show(ui, |ui| {
            ui.label("아이디");
            ui.text_edit_singleline(&mut f.username);
            ui.end_row();
            ui.label("이름");
            ui.text_edit_singleline(&mut f.name);
            ui.end_row();
            ui.label("부서");
            egui::ComboBox::from_id_salt("udept").selected_text(dept_name(app, f.dept_id)).show_ui(ui, |ui| {
                ui.selectable_value(&mut f.dept_id, None, "-");
                for d in &depts {
                    ui.selectable_value(&mut f.dept_id, Some(d.id), &d.name);
                }
            });
            ui.end_row();
            ui.label("역할");
            egui::ComboBox::from_id_salt("urole").selected_text(if f.role == Role::Admin { "관리자" } else { "사용자" }).show_ui(ui, |ui| {
                ui.selectable_value(&mut f.role, Role::User, "사용자");
                ui.selectable_value(&mut f.role, Role::Admin, "관리자");
            });
            ui.end_row();
            ui.label("결재자");
            egui::ComboBox::from_id_salt("uappr").selected_text(user_label(app, f.approver_id)).show_ui(ui, |ui| {
                ui.selectable_value(&mut f.approver_id, None, "-");
                for u in users.iter().filter(|u| Some(u.id) != f.id) {
                    ui.selectable_value(&mut f.approver_id, Some(u.id), format!("{} ({})", u.name, u.username));
                }
            });
            ui.end_row();
            if let Some(pw) = f.password.as_mut() {
                ui.label("초기 비밀번호");
                ui.add(egui::TextEdit::singleline(pw).password(true));
                ui.end_row();
            }
        });
        ui.horizontal(|ui| {
            if ui.button("저장").clicked() {
                let user = f.clone();
                adm(app, AdminRequest::UpsertUser { user }, |a, _| {
                    a.admin.user_form = None;
                    a.toast("사용자를 저장했습니다");
                    refresh(a);
                });
            }
            if ui.button("취소").clicked() {
                keep = false;
            }
        });
    });
    if keep {
        // the save callback clears the form on success
        if app.admin.user_form.is_none() {
            app.admin.user_form = Some(f);
        }
    }
}

fn reset_form(app: &mut App, ui: &mut egui::Ui) {
    let Some((id, mut pw)) = app.admin.reset_pw.take() else { return };
    let mut keep = true;
    egui::Frame::group(ui.style()).show(ui, |ui| {
        ui.strong(format!("비밀번호 초기화: {}", user_label(app, Some(id))));
        ui.horizontal(|ui| {
            ui.label("새 비밀번호");
            ui.add(egui::TextEdit::singleline(&mut pw).password(true));
            if ui.button("초기화").clicked() {
                adm(app, AdminRequest::ResetPassword { user_id: id, new: pw.clone() }, |a, _| a.toast("비밀번호를 초기화했습니다. 다음 로그인 때 변경을 요구합니다"));
                keep = false;
            }
            if ui.button("취소").clicked() {
                keep = false;
            }
        });
    });
    if keep {
        app.admin.reset_pw = Some((id, pw));
    }
}

pub fn depts(app: &mut App, ui: &mut egui::Ui) {
    ui.horizontal(|ui| {
        ui.label("새 부서");
        ui.text_edit_singleline(&mut app.admin.dept_name);
        if ui.button("추가").clicked() {
            let name = std::mem::take(&mut app.admin.dept_name);
            adm(app, AdminRequest::UpsertDept { id: None, name }, |a, _| refresh(a));
        }
    });
    ui.add_space(6.0);
    let depts = app.admin.depts.clone();
    let mut save = None;
    for d in &depts {
        ui.horizontal(|ui| {
            match &mut app.admin.dept_edit {
                Some((id, name)) if *id == d.id => {
                    ui.text_edit_singleline(name);
                    if ui.small_button("저장").clicked() {
                        save = Some((*id, name.clone()));
                    }
                }
                _ => {
                    ui.label(&d.name);
                    if ui.small_button("이름 바꾸기").clicked() {
                        app.admin.dept_edit = Some((d.id, d.name.clone()));
                    }
                }
            }
            let members = app.admin.users.iter().filter(|u| u.dept_id == Some(d.id)).count();
            ui.label(RichText::new(format!("{members}명")).small());
        });
    }
    if let Some((id, name)) = save {
        app.admin.dept_edit = None;
        adm(app, AdminRequest::UpsertDept { id: Some(id), name }, |a, _| refresh(a));
    }
}

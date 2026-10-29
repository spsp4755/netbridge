//! 통로 정책: each direction of each link has its own transfer rules. Unset items follow the global policy.
use super::{adm, refresh};
use crate::app::App;
use crate::ui::*;
use eframe::egui::{self, RichText};
use netbridge_proto::*;

/// Loads route `i` into the editable draft.
pub fn select(app: &mut App, i: usize) {
    let Some(p) = app.admin.routes.get(i).cloned() else { return };
    app.admin.route_sel = i;
    app.admin.rule_exts = p.approval_rules.iter().map(|r| exts_to_text(&r.exts)).collect();
    app.admin.r_blocked = p.blocked_exts.as_deref().map(exts_to_text).unwrap_or_default();
    app.admin.r_allowed = p.allowed_exts.as_deref().map(exts_to_text).unwrap_or_default();
    app.admin.draft = Some(p);
}

fn action_combo(ui: &mut egui::Ui, id: impl std::hash::Hash, a: &mut PiiAction) {
    egui::ComboBox::from_id_salt(id).selected_text(a.label()).show_ui(ui, |ui| {
        for x in [PiiAction::LogOnly, PiiAction::ForcePre, PiiAction::Block] {
            ui.selectable_value(a, x, x.label());
        }
    });
}

pub fn routes(app: &mut App, ui: &mut egui::Ui) {
    if app.admin.routes.is_empty() {
        empty_state(ui, "⇄", "통로가 없습니다", "중앙 서버 설정 파일의 [[routes]] 에 통로를 적으면 여기에 나타납니다.");
        return;
    }
    if app.admin.draft.is_none() {
        select(app, app.admin.route_sel.min(app.admin.routes.len() - 1));
    }
    ui.label(muted("통로마다, 방향마다 규칙이 따로 있습니다. 비워 둔 항목은 보안정책·용량 한도 탭의 전역 값을 따릅니다. 저장하면 접속 중인 PC에 바로 반영됩니다."));
    ui.add_space(6.0);
    let routes = app.admin.routes.clone();
    let mut pick = None;
    ui.horizontal_top(|ui| {
        ui.vertical(|ui| {
            ui.set_width(250.0);
            for (i, p) in routes.iter().enumerate() {
                let on = i == app.admin.route_sel;
                let c = app.net_color(&p.route.from);
                let text = format!("{}{}", app.route_label(&p.route), if p.enabled { "" } else { "  (사용 안 함)" });
                if ui.add_sized([250.0, 30.0], egui::SelectableLabel::new(on, RichText::new(text).color(if p.enabled { c } else { MUTED }))).clicked() {
                    pick = Some(i);
                }
            }
        });
        ui.separator();
        ui.vertical(|ui| editor(app, ui));
    });
    if let Some(i) = pick {
        select(app, i);
    }
}

fn editor(app: &mut App, ui: &mut egui::Ui) {
    let global = app.admin.policy.clone().unwrap_or_default();
    let depts = app.admin.depts.clone();
    let reverse = app.admin.draft.as_ref().map(|d| d.route.reverse());
    let label = app.admin.draft.as_ref().map(|d| app.route_label(&d.route)).unwrap_or_default();
    let Some(d) = app.admin.draft.as_mut() else { return };
    ui.label(bold(&label, 17.0));
    ui.horizontal(|ui| {
        ui.checkbox(&mut d.enabled, "이 방향 사용");
        ui.checkbox(&mut d.clipboard, "클립보드 허용");
    });
    ui.separator();

    section_title(ui, "용량 한도");
    let mut own = d.limits.is_some();
    if ui.checkbox(&mut own, "이 통로만의 한도 사용").changed() {
        d.limits = own.then_some(global.default_limits);
    }
    match d.limits.as_mut() {
        Some(l) => {
            ui.horizontal(|ui| {
                ui.label("하루");
                mb_edit(ui, &mut l.daily_bytes);
                ui.label("파일 1개");
                mb_edit(ui, &mut l.per_file_bytes);
            });
        }
        None => {
            ui.label(muted(format!("전역 기본값: 하루 {} · 파일 1개 {}", fmt_bytes(global.default_limits.daily_bytes), fmt_bytes(global.default_limits.per_file_bytes))));
        }
    }

    section_title(ui, "확장자");
    let mut own = d.blocked_exts.is_some();
    if ui.checkbox(&mut own, "이 통로만의 차단·허용 확장자 사용").changed() {
        d.blocked_exts = own.then(|| global.blocked_exts.clone());
        d.allowed_exts = own.then(|| global.allowed_exts.clone());
        app.admin.r_blocked = d.blocked_exts.as_deref().map(exts_to_text).unwrap_or_default();
        app.admin.r_allowed = d.allowed_exts.as_deref().map(exts_to_text).unwrap_or_default();
    }
    if d.blocked_exts.is_some() {
        egui::Grid::new("rexts").num_columns(2).spacing([10.0, 6.0]).show(ui, |ui| {
            ui.label("차단");
            ui.add(egui::TextEdit::singleline(&mut app.admin.r_blocked).desired_width(320.0));
            ui.end_row();
            ui.label("허용 (비우면 차단 외 전부)");
            ui.add(egui::TextEdit::singleline(&mut app.admin.r_allowed).desired_width(320.0));
            ui.end_row();
        });
    } else {
        ui.label(muted(format!("전역: 차단 {}", if global.blocked_exts.is_empty() { "없음".into() } else { exts_to_text(&global.blocked_exts) })));
    }

    section_title(ui, "파일 검사 결과에 따른 조치");
    egui::Grid::new("threats").num_columns(4).spacing([14.0, 6.0]).show(ui, |ui| {
        for (i, k) in ThreatKind::ALL.iter().enumerate() {
            let mut a = d.threat_action(*k);
            ui.label(k.label());
            action_combo(ui, ("th", i), &mut a);
            if a != d.threat_action(*k) {
                d.threat_actions.retain(|(t, _)| t != k);
                d.threat_actions.push((*k, a));
            }
            if i % 2 == 1 {
                ui.end_row();
            }
        }
    });
    ui.horizontal(|ui| {
        ui.label("개인정보 내용 검사 불가 파일");
        let mut own = d.unscannable_action.is_some();
        if ui.checkbox(&mut own, "따로 정함").changed() {
            d.unscannable_action = own.then_some(global.pii_unscannable_action);
        }
        match d.unscannable_action.as_mut() {
            Some(a) => action_combo(ui, "unscan", a),
            None => {
                ui.label(muted(format!("전역: {}", global.pii_unscannable_action.label())));
            }
        }
    });

    section_title(ui, "개인정보 조치 (통로별)");
    egui::Grid::new("rpii").striped(true).num_columns(4).spacing([12.0, 4.0]).show(ui, |ui| {
        for c in ["항목", "이 통로만 따로", "기준", "조치"] {
            ui.label(muted(c));
        }
        ui.end_row();
        for g in &global.pii_rules {
            ui.label(&g.name);
            let idx = d.pii.iter().position(|x| x.rule_id == g.id);
            let mut own = idx.is_some();
            if ui.checkbox(&mut own, "").changed() {
                if own {
                    d.pii.push(RoutePii { rule_id: g.id.clone(), enabled: g.enabled, threshold: g.threshold, action: g.action });
                } else {
                    d.pii.retain(|x| x.rule_id != g.id);
                }
            }
            match d.pii.iter_mut().find(|x| x.rule_id == g.id) {
                Some(o) => {
                    ui.add(egui::DragValue::new(&mut o.threshold).range(1..=10000).suffix(" 건 이상"));
                    action_combo(ui, ("rp", &g.id), &mut o.action);
                }
                None => {
                    ui.label(muted(format!("{}건", g.threshold)));
                    ui.label(muted(g.action.label()));
                }
            }
            ui.end_row();
        }
    });

    section_title(ui, "결재 규칙");
    ui.label(muted("위에서부터 처음 맞는 규칙의 결재 방식을 씁니다. 맞는 규칙이 없으면 사전결재입니다. 개인정보·위협 탐지로 사전결재가 되면 규칙과 상관없이 사전결재입니다."));
    let mut swap = None;
    let mut remove = None;
    let n = d.approval_rules.len();
    app.admin.rule_exts.resize(n, String::new());
    egui::Grid::new("rules").striped(true).num_columns(6).spacing([10.0, 6.0]).show(ui, |ui| {
        for c in ["순서", "최대 크기", "확장자 (비우면 전체)", "부서", "결재 방식", ""] {
            ui.label(muted(c));
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
            let r = &mut d.approval_rules[i];
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
            ui.add(egui::TextEdit::singleline(&mut app.admin.rule_exts[i]).desired_width(150.0));
            let dname = r.dept_id.and_then(|id| depts.iter().find(|d| d.id == id)).map(|d| d.name.clone()).unwrap_or_else(|| "전체".into());
            egui::ComboBox::from_id_salt(("rdept", i)).selected_text(dname).show_ui(ui, |ui| {
                ui.selectable_value(&mut r.dept_id, None, "전체");
                for dp in &depts {
                    ui.selectable_value(&mut r.dept_id, Some(dp.id), &dp.name);
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
        d.approval_rules.swap(a, b);
        app.admin.rule_exts.swap(a, b);
    }
    if let Some(i) = remove {
        d.approval_rules.remove(i);
        app.admin.rule_exts.remove(i);
    }
    if ui.button("규칙 추가").clicked() {
        d.approval_rules.push(ApprovalRule { order: 0, max_size: Some(10 * MIB), exts: vec![], dept_id: None, mode: ApprovalMode::Post });
        app.admin.rule_exts.push(String::new());
    }

    ui.add_space(10.0);
    let mut save = false;
    let mut revert = false;
    let mut copy = false;
    ui.horizontal(|ui| {
        save = ui.add(primary("저장")).clicked();
        revert = ui.add(secondary("되돌리기")).clicked();
        copy = ui.add(secondary("반대 방향과 같게")).on_hover_text("반대 방향 통로의 규칙을 이 방향에 복사합니다 (저장해야 반영)").clicked();
    });
    if copy {
        if let Some(rev) = reverse.and_then(|r| app.admin.routes.iter().find(|p| p.route == r).cloned()) {
            let cur = app.admin.draft.clone().unwrap_or_else(|| rev.clone());
            app.admin.rule_exts = rev.approval_rules.iter().map(|r| exts_to_text(&r.exts)).collect();
            app.admin.r_blocked = rev.blocked_exts.as_deref().map(exts_to_text).unwrap_or_default();
            app.admin.r_allowed = rev.allowed_exts.as_deref().map(exts_to_text).unwrap_or_default();
            // rules only: whether this direction is on and allows clipboard stays as the admin set it
            app.admin.draft = Some(RoutePolicy { route: cur.route, enabled: cur.enabled, clipboard: cur.clipboard, ..rev });
        }
    }
    if revert {
        let i = app.admin.route_sel;
        select(app, i);
    }
    if save {
        let Some(mut p) = app.admin.draft.clone() else { return };
        p.approval_rules = p.approval_rules.iter().zip(&app.admin.rule_exts).enumerate().map(|(i, (r, e))| ApprovalRule { order: i as i32, exts: text_to_exts(e), ..r.clone() }).collect();
        if p.blocked_exts.is_some() {
            p.blocked_exts = Some(text_to_exts(&app.admin.r_blocked));
            p.allowed_exts = Some(text_to_exts(&app.admin.r_allowed));
        }
        adm(app, AdminRequest::SetRoutePolicy { policy: p }, |a, _| {
            a.toast("통로 정책을 저장했습니다. 접속 중인 PC에 바로 반영됩니다");
            a.admin.draft = None;
            refresh(a);
        });
    }
}

mod audit;
mod limits;
mod policy;
mod users;

use crate::app::App;
use crate::ui::title;
use chrono::NaiveDate;
use eframe::egui;
use netbridge_proto::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Tab {
    #[default]
    Users,
    Depts,
    Limits,
    Rules,
    Policy,
    Pii,
    Audit,
    Sessions,
}

pub struct State {
    pub tab: Tab,
    pub users: Vec<UserInfo>,
    pub depts: Vec<Dept>,
    pub policy: Option<Policy>,
    pub blocked_text: String,
    pub allowed_text: String,
    pub overrides: Vec<LimitOverride>,
    pub rules: Vec<ApprovalRule>,
    pub rule_exts: Vec<String>,
    pub audit: Vec<AuditRow>,
    pub sessions: Vec<SessionInfo>,
    pub user_form: Option<UserInput>,
    pub reset_pw: Option<(i64, String)>,
    pub dept_name: String,
    pub dept_edit: Option<(i64, String)>,
    pub ov_user: bool,
    pub ov_target: Option<i64>,
    pub ov_limits: Limits,
    pub pii_test: String,
    pub audit_from: NaiveDate,
    pub audit_to: NaiveDate,
    pub audit_user: String,
    pub audit_kind: String,
}

impl Default for State {
    fn default() -> Self {
        let today = chrono::Utc::now().with_timezone(&chrono::FixedOffset::east_opt(9 * 3600).unwrap()).date_naive();
        State {
            tab: Tab::Users,
            users: vec![],
            depts: vec![],
            policy: None,
            blocked_text: String::new(),
            allowed_text: String::new(),
            overrides: vec![],
            rules: vec![],
            rule_exts: vec![],
            audit: vec![],
            sessions: vec![],
            user_form: None,
            reset_pw: None,
            dept_name: String::new(),
            dept_edit: None,
            ov_user: false,
            ov_target: None,
            ov_limits: Policy::default().default_limits,
            pii_test: String::new(),
            audit_from: today - chrono::Duration::days(7),
            audit_to: today,
            audit_user: String::new(),
            audit_kind: String::new(),
        }
    }
}

pub fn adm(app: &App, req: AdminRequest, apply: impl FnOnce(&mut App, ApiResponse) + Send + 'static) {
    app.api(ApiRequest::Admin { req }, apply);
}

pub fn refresh(app: &mut App) {
    adm(app, AdminRequest::ListUsers, |a, r| {
        if let ApiResponse::Users(v) = r {
            a.admin.users = v;
        }
    });
    adm(app, AdminRequest::ListDepts, |a, r| {
        if let ApiResponse::Depts(v) = r {
            a.admin.depts = v;
        }
    });
    load_policy(app);
    adm(app, AdminRequest::ListLimitOverrides, |a, r| {
        if let ApiResponse::LimitOverrides(v) = r {
            a.admin.overrides = v;
        }
    });
    adm(app, AdminRequest::ListApprovalRules, |a, r| {
        if let ApiResponse::ApprovalRules(v) = r {
            a.admin.rule_exts = v.iter().map(|r| crate::ui::exts_to_text(&r.exts)).collect();
            a.admin.rules = v;
        }
    });
    audit::refresh_sessions(app);
}

pub fn load_policy(app: &App) {
    adm(app, AdminRequest::GetPolicy, |a, r| {
        if let ApiResponse::Policy(p) = r {
            a.admin.blocked_text = crate::ui::exts_to_text(&p.blocked_exts);
            a.admin.allowed_text = crate::ui::exts_to_text(&p.allowed_exts);
            a.admin.policy = Some(p);
        }
    });
}

/// Saves the draft policy (with the extension text fields applied).
pub fn save_policy(app: &mut App) {
    let Some(mut p) = app.admin.policy.clone() else { return };
    p.blocked_exts = crate::ui::text_to_exts(&app.admin.blocked_text);
    p.allowed_exts = crate::ui::text_to_exts(&app.admin.allowed_text);
    adm(app, AdminRequest::SetPolicy { policy: p }, |a, _| {
        a.toast("보안정책을 저장했습니다. 접속 중인 모든 PC에 바로 반영됩니다");
        load_policy(a);
    });
}

pub fn dept_name(app: &App, id: Option<i64>) -> String {
    id.and_then(|id| app.admin.depts.iter().find(|d| d.id == id)).map(|d| d.name.clone()).unwrap_or_else(|| "-".into())
}

pub fn user_label(app: &App, id: Option<i64>) -> String {
    id.and_then(|id| app.admin.users.iter().find(|u| u.id == id)).map(|u| format!("{} ({})", u.name, u.username)).unwrap_or_else(|| "-".into())
}

pub fn show(app: &mut App, ui: &mut egui::Ui) {
    if !app.is_admin_console() {
        ui.label("관리자 기능은 업무망 PC에서 관리자 계정으로만 사용할 수 있습니다.");
        return;
    }
    title(ui, "관리자 설정");
    ui.horizontal_wrapped(|ui| {
        for (t, label) in [
            (Tab::Users, "사용자"),
            (Tab::Depts, "부서"),
            (Tab::Limits, "용량 한도"),
            (Tab::Rules, "결재 규칙"),
            (Tab::Policy, "보안정책"),
            (Tab::Pii, "개인정보 탐지"),
            (Tab::Audit, "이력 조회"),
            (Tab::Sessions, "접속 세션"),
        ] {
            ui.selectable_value(&mut app.admin.tab, t, label);
        }
        ui.separator();
        if ui.small_button("새로고침").clicked() {
            refresh(app);
        }
    });
    ui.separator();
    match app.admin.tab {
        Tab::Users => users::users(app, ui),
        Tab::Depts => users::depts(app, ui),
        Tab::Limits => limits::limits(app, ui),
        Tab::Rules => limits::rules(app, ui),
        Tab::Policy => policy::policy(app, ui),
        Tab::Pii => policy::pii(app, ui),
        Tab::Audit => audit::audit(app, ui),
        Tab::Sessions => audit::sessions(app, ui),
    }
}

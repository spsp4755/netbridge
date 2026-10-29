mod audit;
mod limits;
mod policy;
mod routes;
mod users;

use crate::app::App;
use crate::ui::*;
use chrono::NaiveDate;
use eframe::egui;
use netbridge_proto::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Tab {
    #[default]
    Overview,
    Users,
    Depts,
    Limits,
    Routes,
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
    pub routes: Vec<RoutePolicy>,
    pub route_sel: usize,
    /// Route being edited (saved with SetRoutePolicy).
    pub draft: Option<RoutePolicy>,
    pub rule_exts: Vec<String>,
    pub r_blocked: String,
    pub r_allowed: String,
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
            tab: Tab::Overview,
            users: vec![],
            depts: vec![],
            policy: None,
            blocked_text: String::new(),
            allowed_text: String::new(),
            overrides: vec![],
            routes: vec![],
            route_sel: 0,
            draft: None,
            rule_exts: vec![],
            r_blocked: String::new(),
            r_allowed: String::new(),
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
    adm(app, AdminRequest::ListRoutePolicies, |a, r| {
        if let ApiResponse::RoutePolicies(v) = r {
            a.admin.routes = v;
            if a.admin.draft.is_none() && !a.admin.routes.is_empty() {
                routes::select(a, a.admin.route_sel.min(a.admin.routes.len() - 1));
            }
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
    let Some(mut p) = app.admin.policy.clone() else {
        return;
    };
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
    page_header(ui, "관리자 콘솔", Some("사용자, 결재 규칙, 보안정책과 감사 이력을 관리합니다. 바꾼 정책은 접속 중인 모든 PC에 바로 반영됩니다."));
    let tabs = [
        (Tab::Overview, "개요"),
        (Tab::Users, "사용자"),
        (Tab::Depts, "부서"),
        (Tab::Limits, "용량 한도"),
        (Tab::Routes, "통로 정책"),
        (Tab::Policy, "보안정책"),
        (Tab::Pii, "개인정보 탐지"),
        (Tab::Audit, "이력 조회"),
        (Tab::Sessions, "접속 세션"),
    ];
    let picked = ui
        .horizontal(|ui| {
            let t = tab_bar(ui, app.admin.tab, &tabs);
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.add(secondary("⟳ 새로고침")).clicked() {
                    refresh(app);
                }
            });
            t
        })
        .inner;
    let y = ui.cursor().top();
    ui.painter().hline(ui.max_rect().x_range(), y, egui::Stroke::new(1.0_f32, BORDER));
    ui.add_space(12.0);
    if let Some(t) = picked {
        app.admin.tab = t;
    }
    if app.admin.tab == Tab::Overview {
        overview(app, ui);
        return;
    }
    card(ui, |ui| match app.admin.tab {
        Tab::Overview => {}
        Tab::Users => users::users(app, ui),
        Tab::Depts => users::depts(app, ui),
        Tab::Limits => limits::limits(app, ui),
        Tab::Routes => routes::routes(app, ui),
        Tab::Policy => policy::policy(app, ui),
        Tab::Pii => policy::pii(app, ui),
        Tab::Audit => audit::audit(app, ui),
        Tab::Sessions => audit::sessions(app, ui),
    });
}

fn overview(app: &mut App, ui: &mut egui::Ui) {
    let a = &app.admin;
    let locked = a.users.iter().filter(|u| u.locked).count();
    let admins = a.users.iter().filter(|u| u.role == Role::Admin).count();
    let online = a.sessions.iter().filter(|s| !s.online.is_empty()).count();
    let both = a.sessions.iter().filter(|s| s.online.len() >= 2).count();
    ui.columns(4, |c| {
        stat_tile(&mut c[0], "사용자", a.users.len().to_string(), &format!("관리자 {admins} · 잠김 {locked}"), TEXT);
        stat_tile(&mut c[1], "로그인 세션", a.sessions.len().to_string(), &format!("접속 중 {online} · 여러 망 {both}"), SUCCESS);
        stat_tile(&mut c[2], "부서", a.depts.len().to_string(), "결재선 기준 조직", TEXT);
        stat_tile(&mut c[3], "통로", a.routes.len().to_string(), &format!("사용 {} · 방향별 정책", a.routes.iter().filter(|r| r.enabled).count()), ACCENT);
    });
    ui.add_space(12.0);
    let Some(p) = a.policy.clone() else {
        card(ui, |ui| empty_state(ui, "⟳", "정책을 불러오는 중…", "잠시만 기다려 주세요."));
        return;
    };
    let mins = |m: Option<u32>| m.map(|m| format!("{m}분")).unwrap_or_else(|| "제한 없음".into());
    let mut open_tab = None;
    ui.columns(2, |cols| {
        card(&mut cols[0], |ui| {
            section_title(ui, "보안정책 요약");
            kv_grid(
                ui,
                "ov-pol",
                &[
                    ("세션 최대 시간", mins(p.session_max_minutes)),
                    ("미사용 화면 잠금", mins(p.idle_lock_minutes)),
                    ("비밀번호", format!("{}자 이상{}", p.pw_min_len, if p.pw_require_mix { " · 조합 필수" } else { "" })),
                    ("비밀번호 사용 기간", p.pw_max_age_days.map(|d| format!("{d}일")).unwrap_or_else(|| "제한 없음".into())),
                    ("로그인 실패 잠금", format!("{}회", p.login_fail_lock)),
                    ("차단 확장자", if p.blocked_exts.is_empty() { "없음".into() } else { format!("{}개", p.blocked_exts.len()) }),
                    ("파일 보관", format!("{}일", p.file_retention_days)),
                    ("감사 기록 보관", format!("{}일", p.audit_retention_days)),
                ],
            );
            ui.horizontal(|ui| {
                if ui.add(secondary("보안정책 바꾸기")).clicked() {
                    open_tab = Some(Tab::Policy);
                }
            });
        });
        card(&mut cols[1], |ui| {
            section_title(ui, "전송 기본값");
            kv_grid(
                ui,
                "ov-lim",
                &[
                    ("하루 전송량", fmt_bytes(p.default_limits.daily_bytes)),
                    ("파일 1개 최대", fmt_bytes(p.default_limits.per_file_bytes)),
                    ("사후결재 기한", format!("{}일", p.post_deadline_days)),
                    ("클립보드 최대", fmt_bytes(p.clipboard_max_bytes as u64)),
                    ("개인정보 규칙", format!("{}개 중 {}개 사용", p.pii_rules.len(), p.pii_rules.iter().filter(|r| r.enabled).count())),
                    ("개별 한도", format!("{}건", a.overrides.len())),
                ],
            );
            ui.horizontal(|ui| {
                if ui.add(secondary("용량 한도")).clicked() {
                    open_tab = Some(Tab::Limits);
                }
                if ui.add(secondary("개인정보 탐지")).clicked() {
                    open_tab = Some(Tab::Pii);
                }
            });
        });
    });
    if let Some(t) = open_tab {
        app.admin.tab = t;
    }
}

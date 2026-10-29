use chrono::NaiveDate;
use serde::{Deserialize, Serialize};

pub type Ts = i64; // unix seconds, UTC

/// A network (망) id from the server configuration, e.g. "A" or the legacy "internal"/"external".
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct NetId(pub String);

/// The network of a server or caller.
pub type Side = NetId;

impl NetId {
    pub fn new(s: impl Into<String>) -> NetId {
        NetId(s.into())
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
    /// Legacy two-network ids (업무망 / 인터넷망).
    pub fn internal() -> NetId {
        NetId::new("internal")
    }
    pub fn external() -> NetId {
        NetId::new("external")
    }
}

impl std::fmt::Display for NetId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// One direction of a link between two networks.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Route {
    pub from: NetId,
    pub to: NetId,
}

impl Route {
    pub fn new(from: NetId, to: NetId) -> Route {
        Route { from, to }
    }
    pub fn reverse(&self) -> Route {
        Route { from: self.to.clone(), to: self.from.clone() }
    }
    pub fn label(&self, topo: &Topology) -> String {
        format!("{} → {}", topo.name(&self.from), topo.name(&self.to))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetInfo {
    pub id: NetId,
    pub name: String,
}

/// Networks and the links between them, from the central server's configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Topology {
    /// The network whose server holds the database.
    pub hub: NetId,
    pub networks: Vec<NetInfo>,
    /// Allowed directions; a link appears as two routes.
    pub routes: Vec<Route>,
}

impl Topology {
    /// The original two-network layout.
    pub fn legacy() -> Topology {
        let (i, e) = (NetId::internal(), NetId::external());
        Topology {
            hub: i.clone(),
            networks: vec![NetInfo { id: e.clone(), name: "인터넷망".into() }, NetInfo { id: i.clone(), name: "업무망".into() }],
            routes: vec![Route::new(e.clone(), i.clone()), Route::new(i, e)],
        }
    }
    pub fn name(&self, id: &NetId) -> String {
        self.networks.iter().find(|n| n.id == *id).map(|n| n.name.clone()).unwrap_or_else(|| id.0.clone())
    }
    pub fn has_route(&self, r: &Route) -> bool {
        self.routes.contains(r)
    }
    /// Networks this one may send to.
    pub fn targets(&self, from: &NetId) -> Vec<NetId> {
        self.routes.iter().filter(|r| r.from == *from).map(|r| r.to.clone()).collect()
    }
    pub fn index(&self, id: &NetId) -> usize {
        self.networks.iter().position(|n| n.id == *id).unwrap_or(0)
    }
}

/// What a content scan found (see the netbridge-scan crate).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ThreatKind {
    Executable,
    Script,
    Macro,
    PdfActive,
    ArchiveDanger,
    Encrypted,
    AvInfected,
    ScannerError,
}

impl ThreatKind {
    pub const ALL: [ThreatKind; 8] =
        [ThreatKind::Executable, ThreatKind::Script, ThreatKind::Macro, ThreatKind::PdfActive, ThreatKind::ArchiveDanger, ThreatKind::Encrypted, ThreatKind::AvInfected, ThreatKind::ScannerError];
    pub fn label(self) -> &'static str {
        match self {
            ThreatKind::Executable => "실행 파일",
            ThreatKind::Script => "스크립트",
            ThreatKind::Macro => "문서 매크로",
            ThreatKind::PdfActive => "PDF 실행 요소",
            ThreatKind::ArchiveDanger => "위험한 압축",
            ThreatKind::Encrypted => "암호 걸린 파일",
            ThreatKind::AvInfected => "백신 탐지",
            ThreatKind::ScannerError => "검사기 오류",
        }
    }
    pub fn default_action(self) -> PiiAction {
        match self {
            ThreatKind::Executable | ThreatKind::Script | ThreatKind::ArchiveDanger | ThreatKind::AvInfected => PiiAction::Block,
            ThreatKind::Macro | ThreatKind::PdfActive | ThreatKind::Encrypted | ThreatKind::ScannerError => PiiAction::ForcePre,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    pub kind: ThreatKind,
    pub detail: String,
}

/// Per-route override of a global PII rule's threshold and action.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoutePii {
    pub rule_id: String,
    pub enabled: bool,
    pub threshold: u32,
    pub action: PiiAction,
}

/// Transfer policy of one direction of one link. `None` fields follow the global policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoutePolicy {
    pub route: Route,
    pub enabled: bool,
    pub clipboard: bool,
    pub limits: Option<Limits>,
    pub blocked_exts: Option<Vec<String>>,
    /// Empty means every extension not in `blocked_exts` is allowed.
    pub allowed_exts: Option<Vec<String>>,
    /// First match decides; no match means pre-approval.
    pub approval_rules: Vec<ApprovalRule>,
    /// Overrides of global PII rules for this route; a rule not listed uses its global values.
    pub pii: Vec<RoutePii>,
    pub unscannable_action: Option<PiiAction>,
    pub threat_actions: Vec<(ThreatKind, PiiAction)>,
}

impl RoutePolicy {
    /// A new route follows the global policy until the admin overrides its fields.
    pub fn new(route: Route) -> RoutePolicy {
        RoutePolicy {
            route,
            enabled: true,
            clipboard: true,
            limits: None,
            blocked_exts: None,
            allowed_exts: None,
            approval_rules: vec![],
            pii: vec![],
            unscannable_action: None,
            threat_actions: ThreatKind::ALL.iter().map(|k| (*k, k.default_action())).collect(),
        }
    }
    /// Fills every inherited field from the global policy.
    pub fn resolved(&self, g: &Policy) -> RoutePolicy {
        RoutePolicy {
            limits: Some(self.limits.unwrap_or(g.default_limits)),
            blocked_exts: Some(self.blocked_exts.clone().unwrap_or_else(|| g.blocked_exts.clone())),
            allowed_exts: Some(self.allowed_exts.clone().unwrap_or_else(|| g.allowed_exts.clone())),
            unscannable_action: Some(self.unscannable_action.unwrap_or(g.pii_unscannable_action)),
            ..self.clone()
        }
    }
    pub fn lim(&self) -> Limits {
        self.limits.unwrap_or(Policy::default().default_limits)
    }
    pub fn blocked(&self) -> &[String] {
        self.blocked_exts.as_deref().unwrap_or_default()
    }
    pub fn allowed(&self) -> &[String] {
        self.allowed_exts.as_deref().unwrap_or_default()
    }
    pub fn unscannable(&self) -> PiiAction {
        self.unscannable_action.unwrap_or(PiiAction::ForcePre)
    }
    /// The global PII rules with this route's thresholds and actions.
    pub fn effective_pii(&self, global: &[PiiRule]) -> Vec<PiiRule> {
        global
            .iter()
            .map(|g| match self.pii.iter().find(|r| r.rule_id == g.id) {
                Some(r) => PiiRule { enabled: g.enabled && r.enabled, threshold: r.threshold, action: r.action, ..g.clone() },
                None => g.clone(),
            })
            .collect()
    }
    pub fn threat_action(&self, k: ThreatKind) -> PiiAction {
        self.threat_actions.iter().find(|(t, _)| *t == k).map(|(_, a)| *a).unwrap_or(k.default_action())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Role {
    User,
    Admin,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ApprovalMode {
    Pre,
    Post,
}

impl ApprovalMode {
    pub fn label(self) -> &'static str {
        match self {
            ApprovalMode::Pre => "사전결재",
            ApprovalMode::Post => "사후결재",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum PiiAction {
    LogOnly,
    ForcePre,
    Block,
}

impl PiiAction {
    pub fn label(self) -> &'static str {
        match self {
            PiiAction::LogOnly => "기록만",
            PiiAction::ForcePre => "사전결재 강제",
            PiiAction::Block => "차단",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Limits {
    pub daily_bytes: u64,
    pub per_file_bytes: u64,
}

pub const MIB: u64 = 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PiiRule {
    pub id: String,
    pub name: String,
    pub enabled: bool,
    pub builtin: bool,
    /// Regex for custom rules; builtin rules ignore it.
    pub pattern: Option<String>,
    pub threshold: u32,
    pub action: PiiAction,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Policy {
    pub session_max_minutes: Option<u32>,
    pub idle_lock_minutes: Option<u32>,
    pub pw_min_len: u8,
    pub pw_require_mix: bool,
    pub pw_max_age_days: Option<u32>,
    pub login_fail_lock: u8,
    pub blocked_exts: Vec<String>,
    /// Empty means every extension not in `blocked_exts` is allowed.
    pub allowed_exts: Vec<String>,
    pub file_retention_days: u32,
    pub audit_retention_days: u32,
    pub post_deadline_days: u32,
    pub clipboard_max_bytes: u32,
    pub default_limits: Limits,
    pub pii_rules: Vec<PiiRule>,
    pub pii_unscannable_action: PiiAction,
}

fn builtin(id: &str, name: &str, action: PiiAction) -> PiiRule {
    PiiRule { id: id.into(), name: name.into(), enabled: true, builtin: true, pattern: None, threshold: 1, action }
}

pub fn builtin_pii_rules() -> Vec<PiiRule> {
    vec![
        builtin("rrn", "주민·외국인등록번호", PiiAction::ForcePre),
        builtin("phone", "휴대전화번호", PiiAction::LogOnly),
        builtin("card", "신용카드번호", PiiAction::ForcePre),
        builtin("account", "계좌번호", PiiAction::LogOnly),
        builtin("passport", "여권번호", PiiAction::ForcePre),
        builtin("driver", "운전면허번호", PiiAction::ForcePre),
        builtin("email", "이메일 주소", PiiAction::LogOnly),
    ]
}

impl Default for Policy {
    fn default() -> Self {
        Policy {
            session_max_minutes: None,
            idle_lock_minutes: None,
            pw_min_len: 9,
            pw_require_mix: true,
            pw_max_age_days: Some(90),
            login_fail_lock: 5,
            blocked_exts: ["exe", "dll", "bat", "cmd", "ps1", "vbs", "js", "msi"].iter().map(|s| s.to_string()).collect(),
            allowed_exts: vec![],
            file_retention_days: 7,
            audit_retention_days: 365,
            post_deadline_days: 3,
            clipboard_max_bytes: 100 * 1024,
            default_limits: Limits { daily_bytes: 1024 * MIB, per_file_bytes: 100 * MIB },
            pii_rules: builtin_pii_rules(),
            pii_unscannable_action: PiiAction::ForcePre,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalRule {
    pub order: i32,
    /// Rule matches when size <= max_size.
    pub max_size: Option<u64>,
    /// Lowercase extensions without dot; empty = any.
    pub exts: Vec<String>,
    pub dept_id: Option<i64>,
    pub mode: ApprovalMode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransferState {
    Uploading,
    /// PII forced pre-approval but no reason was given; the sender must add one to submit.
    AwaitingReason,
    Pending,
    /// Being copied to the receiving network (claimed by exactly one delivery).
    Delivering,
    Available,
    Rejected,
    Blocked,
    Downloaded,
    Expired,
}

impl TransferState {
    pub fn label(self) -> &'static str {
        match self {
            TransferState::Uploading => "올리는 중",
            TransferState::AwaitingReason => "사유 입력 필요",
            TransferState::Pending => "결재 대기",
            TransferState::Delivering => "전달 중",
            TransferState::Available => "받을 수 있음",
            TransferState::Rejected => "반려",
            TransferState::Blocked => "차단",
            TransferState::Downloaded => "받음",
            TransferState::Expired => "기간 만료",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PiiHit {
    pub rule_id: String,
    pub name: String,
    pub count: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ApprovalStatus {
    Pending,
    Approved,
    Rejected,
}

impl ApprovalStatus {
    pub fn label(self) -> &'static str {
        match self {
            ApprovalStatus::Pending => "대기",
            ApprovalStatus::Approved => "승인",
            ApprovalStatus::Rejected => "반려",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalInfo {
    pub id: i64,
    pub mode: ApprovalMode,
    pub status: ApprovalStatus,
    pub approver: String,
    pub decided_by: Option<String>,
    pub by_proxy: bool,
    pub comment: Option<String>,
    pub decided_at: Option<Ts>,
    pub overdue: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransferInfo {
    pub id: i64,
    pub owner: String,
    pub route: Route,
    pub file_name: String,
    pub size: u64,
    pub sha256: String,
    pub reason: String,
    pub state: TransferState,
    pub mode: Option<ApprovalMode>,
    pub pii: Vec<PiiHit>,
    pub unscannable: bool,
    /// Content scan findings (executables, macros, antivirus, ...).
    #[serde(default)]
    pub threats: Vec<Finding>,
    pub block_reason: Option<String>,
    pub sender_ip: String,
    pub receiver_ip: Option<String>,
    pub created_at: Ts,
    pub approval: Option<ApprovalInfo>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalItem {
    pub approval: ApprovalInfo,
    pub transfer: TransferInfo,
    /// True when the caller may decide it only as a proxy.
    pub as_proxy: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileMeta {
    pub name: String,
    pub size: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Me {
    pub user_id: i64,
    pub username: String,
    pub name: String,
    pub dept: Option<String>,
    pub role: Role,
    pub side: Side,
    pub client_ip: String,
    pub policy: Policy,
    pub must_change_password: bool,
    /// Networks this user may use (all when the admin set none).
    pub networks: Vec<NetId>,
    /// Enabled routes from `side` to the user's other networks.
    pub routes: Vec<RoutePolicy>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Delegation {
    pub proxy_username: String,
    pub proxy_name: String,
    pub from: NaiveDate,
    pub to: NaiveDate,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Usage {
    pub limits: Limits,
    pub used_today: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserInfo {
    pub id: i64,
    pub username: String,
    pub name: String,
    pub dept_id: Option<i64>,
    pub role: Role,
    pub approver_id: Option<i64>,
    pub locked: bool,
    pub devices: Vec<Side>,
    /// Empty = every network.
    pub networks: Vec<NetId>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserInput {
    pub id: Option<i64>,
    pub username: String,
    pub name: String,
    pub dept_id: Option<i64>,
    pub role: Role,
    pub approver_id: Option<i64>,
    /// Required when creating.
    pub password: Option<String>,
    /// Empty = every network.
    #[serde(default)]
    pub networks: Vec<NetId>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Dept {
    pub id: i64,
    pub name: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LimitScope {
    Dept(i64),
    User(i64),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LimitOverride {
    pub scope: LimitScope,
    pub label: String,
    pub limits: Limits,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditQuery {
    pub from: Option<Ts>,
    pub to: Option<Ts>,
    pub user: Option<String>,
    pub kind: Option<String>,
    pub limit: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditRow {
    pub at: Ts,
    pub user: Option<String>,
    pub kind: String,
    pub ip: Option<String>,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionInfo {
    pub id: i64,
    pub username: String,
    pub name: String,
    pub created_at: Ts,
    pub last_seen: Ts,
    pub online: Vec<Side>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hello {
    pub side: Side,
    pub topology: Topology,
    pub server_time: Ts,
}

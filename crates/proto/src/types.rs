use chrono::NaiveDate;
use serde::{Deserialize, Serialize};

pub type Ts = i64; // unix seconds, UTC

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Side {
    External,
    Internal,
}

impl Side {
    pub fn other(self) -> Side {
        match self {
            Side::External => Side::Internal,
            Side::Internal => Side::External,
        }
    }
    pub fn label(self) -> &'static str {
        match self {
            Side::External => "인터넷망",
            Side::Internal => "업무망",
        }
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Side::External => "external",
            Side::Internal => "internal",
        }
    }
    pub fn parse(s: &str) -> Option<Side> {
        match s {
            "external" => Some(Side::External),
            "internal" => Some(Side::Internal),
            _ => None,
        }
    }
    /// Direction of a transfer sent from this side.
    pub fn outgoing(self) -> Direction {
        match self {
            Side::External => Direction::ToInternal,
            Side::Internal => Direction::ToExternal,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Direction {
    ToInternal,
    ToExternal,
}

impl Direction {
    pub fn from_side(self) -> Side {
        match self {
            Direction::ToInternal => Side::External,
            Direction::ToExternal => Side::Internal,
        }
    }
    pub fn label(self) -> &'static str {
        match self {
            Direction::ToInternal => "인터넷망 → 업무망",
            Direction::ToExternal => "업무망 → 인터넷망",
        }
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
    pub direction: Option<Direction>,
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
    pub direction: Direction,
    pub file_name: String,
    pub size: u64,
    pub sha256: String,
    pub reason: String,
    pub state: TransferState,
    pub mode: Option<ApprovalMode>,
    pub pii: Vec<PiiHit>,
    pub unscannable: bool,
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
    pub server_time: Ts,
}

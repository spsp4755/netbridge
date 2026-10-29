use crate::types::*;
use chrono::NaiveDate;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op")]
pub enum ApiRequest {
    Login { username: String, password: String, device_key: Option<String> },
    Logout,
    Unlock { password: String },
    ChangePassword { old: String, new: String },
    Me,
    Usage { to: NetId },
    CreateTransfers { to: NetId, files: Vec<FileMeta>, reason: String },
    CompleteUpload { id: i64 },
    ListOutgoing,
    ListIncoming,
    MarkDownloaded { id: i64 },
    /// Adds the reason to a transfer in AwaitingReason and sends it to the approver.
    SubmitForApproval { id: i64, reason: String },
    ListApprovals,
    Decide { approval_id: i64, approve: bool, comment: Option<String> },
    GetDelegation,
    SetDelegation { proxy_username: String, from: NaiveDate, to: NaiveDate },
    ClearDelegation,
    Clipboard { to: NetId, text: String },
    Admin { req: AdminRequest },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op")]
pub enum AdminRequest {
    ListUsers,
    UpsertUser { user: UserInput },
    ResetPassword { user_id: i64, new: String },
    UnlockUser { user_id: i64 },
    ReleaseDevice { user_id: i64, side: Side },
    ListDepts,
    UpsertDept { id: Option<i64>, name: String },
    GetPolicy,
    SetPolicy { policy: Policy },
    ListLimitOverrides,
    SetLimitOverride { scope: LimitScope, limits: Option<Limits> },
    ListRoutePolicies,
    SetRoutePolicy { policy: RoutePolicy },
    QueryAudit { query: AuditQuery },
    ListSessions,
    KillSession { session_id: i64 },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "data")]
pub enum ApiResponse {
    Ok,
    LoggedIn { token: String, device_key: String, me: Me },
    Me(Me),
    Usage(Usage),
    Ids(Vec<i64>),
    Transfer(TransferInfo),
    Transfers(Vec<TransferInfo>),
    Approvals(Vec<ApprovalItem>),
    Delegation(Option<Delegation>),
    Users(Vec<UserInfo>),
    Id(i64),
    Depts(Vec<Dept>),
    Policy(Policy),
    LimitOverrides(Vec<LimitOverride>),
    RoutePolicies(Vec<RoutePolicy>),
    Audit(Vec<AuditRow>),
    Sessions(Vec<SessionInfo>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ErrorCode {
    BadRequest,
    Unauthorized,
    SessionExpired,
    AccountLocked,
    DeviceMismatch,
    Forbidden,
    NotFound,
    LimitExceeded,
    Blocked,
    Conflict,
    PeerOffline,
    LinkDown,
    Internal,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiError {
    pub code: ErrorCode,
    pub message: String,
}

impl ApiError {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        ApiError { code, message: message.into() }
    }
    pub fn bad(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::BadRequest, message)
    }
    pub fn internal(e: impl std::fmt::Display) -> Self {
        Self::new(ErrorCode::Internal, format!("서버 오류: {e}"))
    }
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for ApiError {}

pub type ApiResult = Result<ApiResponse, ApiError>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "ev")]
pub enum Event {
    SessionStarted { token: String, me: Me },
    SessionEnded { reason: String },
    Clipboard { text: String, from_ip: String },
    TransferUpdated { transfer: TransferInfo },
    ApprovalRequested { approval_id: i64, from: String, file_name: String },
    Notice { message: String },
    PolicyChanged { policy: Policy },
}

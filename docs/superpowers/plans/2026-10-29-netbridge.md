# NetBridge 구현 계획

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 상용 망연계 제품을 대체하는 자료전송 시스템(외부·내부 연계서버 + Windows 네이티브 앱 + 설치파일)을 만든다.

**Architecture:** Rust 워크스페이스다. 같은 서버 실행파일이 역할값에 따라 내부 연계서버(기준 DB 보유)나 외부 연계서버(중계와 파일 보관)로 뜬다. 두 서버 사이 연결은 **모두 내부 서버가 먼저 연다.** 외부→내부 API 호출은 내부 서버가 열어 둔 mTLS WebSocket으로 흐르고, 파일·검사·푸시는 내부 서버가 외부 서버에 mTLS HTTPS로 요청한다. 앱은 eframe/egui이고, 네트워크와 설정 로직은 `clientcore` 라이브러리로 분리해 끝까지 도는 테스트(e2e)에서 그대로 쓴다.

**Tech Stack:** Rust 1.99, tokio, axum 0.8, rustls, reqwest(rustls), tokio-tungstenite, rusqlite(bundled), argon2, rcgen, regex, zip, quick-xml, pdf-extract, eframe/egui, global-hotkey, arboard, tray-icon, windows(DPAPI), NSIS(Docker 안에서 makensis), mingw-w64 교차 컴파일

**Spec:** `docs/superpowers/specs/2026-10-29-netbridge-design.md`

## Global Constraints

- 화면은 eframe/egui 네이티브만 쓴다. WebView는 쓰지 않는다. 한글 글꼴(NanumGothic, OFL)을 실행파일에 넣는다.
- 클라이언트 배포물은 NSIS exe 설치파일 하나다. 시작 메뉴 등록, 시작 프로그램 등록, 제거 기능을 넣는다.
- 각 앱은 **자기 망의 연계서버에만** 접속한다. 내부 서버는 외부에서 들어오는 연결을 받지 않는다.
- 용량 한도, 개인정보 검사, 결재 판정은 **서버에서만** 한다.
- 결재 방식은 사전결재(`Pre`), 사후결재(`Post`), 대결만 둔다. 맞는 규칙이 없으면 `Pre`로 처리한다.
- 세션은 로그아웃, 관리자 강제 종료, 정책의 최대 유지 시간 초과 때만 끝난다. 재연결은 세션을 끝내지 않는다.
- 클립보드는 결재하지 않는다. 기본 단축키는 `Alt+F3`이고 사용자가 바꿀 수 있다.
- 하루 기준은 KST(UTC+9) 자정이다.
- 정책 기본값은 설계 문서 7.9장 표와 같다. 한도 기본값은 하루 1GiB, 파일 1개 100MiB, 클립보드 100KiB다(Claude 결정).
- 비밀번호는 argon2로 해시한다. 사용자 비밀번호는 PC에 저장하지 않는다. 기기 키는 Windows DPAPI로 보호한다.
- 전송은 본인의 반대편 망 PC로만 보낸다(Claude 결정. 설계 문서의 "반대편 망 PC").
- 폐쇄망 빌드용으로 `cargo vendor`를 지원한다.

## Review Focus

1. **파일 업로드 중 끊김**: 같은 오프셋부터 이어서 올리면 최종 SHA-256이 맞아야 하고, 해시가 다르면 `CompleteUpload`가 거부해야 한다. → Task 6에 `resume_upload_after_disconnect` 테스트
2. **파일명 공격**: `..\..\x.exe`, 이중 확장자 `a.txt.exe`, 대문자 `A.EXE`는 차단 확장자 검사와 저장 경로에서 모두 무력화되어야 한다. → Task 6에 `blocked_ext_case_and_double_ext`, `path_traversal_name_is_sanitized`
3. **자정 경계 한도**: KST 23:59에 보낸 양은 다음 날 00:00 이후 한도에 들어가면 안 된다. → Task 5에 `daily_usage_resets_at_kst_midnight`
4. **2020년 10월 이후 발급 주민번호**: 검증 숫자가 맞지 않아도 탐지되어야 한다. 날짜가 틀린 13자리 숫자는 탐지되면 안 된다. → Task 2에 `rrn_new_format_without_checksum_detected`, `rrn_invalid_date_not_detected`
5. **연계 구간 끊김**: 외부 쪽 앱의 API 호출은 오류를 받고, 연계가 복구되면 세션을 다시 로그인하지 않고 계속 써야 한다. → Task 9에 `link_drop_and_recover_keeps_session`

---

## 파일 구조

```
Cargo.toml                         워크스페이스
crates/proto/src/lib.rs            요청·응답·이벤트·정책 타입 (serde)
crates/pii/src/{lib,detect,extract,mask}.rs   개인정보 탐지, 문서 글자 추출, 가리기
crates/server/src/
  main.rs        서브커맨드: run, gen-certs, init-admin
  config.rs      server.toml
  certs.rs       rcgen CA/서버/연계 인증서 생성, rustls 설정
  db.rs          rusqlite 스키마와 마이그레이션
  core/mod.rs    Core::handle — 내부 서버의 모든 업무 로직 진입점
  core/{auth,session,policy,limits,transfer,approval,clipboard,admin,audit}.rs
  hub.rs         기기별 WebSocket 푸시 연결 관리
  http.rs        axum 라우터 (/api, /ws, /upload, /download)
  link.rs        내부↔외부 연계 (WS RPC + mTLS HTTPS)
  relay.rs       외부 서버: /api를 연계로 넘기고 파일만 직접 보관
  files.rs       파일 저장소 (조각 쓰기, 해시, 보관 기간 정리)
crates/clientcore/src/{lib,config,net,secret}.rs  앱 네트워크·설정·DPAPI
crates/clientcore/tests/e2e.rs     두 서버를 띄우고 끝까지 도는 테스트
crates/client/src/
  main.rs app.rs fonts.rs hotkey.rs tray.rs
  ui/{login,send,inbox,history,approvals,delegation,settings,admin}.rs
assets/fonts/NanumGothic-Regular.ttf, assets/icon.ico
installer/netbridge.nsi
build/Dockerfile.windows, scripts/build-windows.sh, scripts/vendor.sh
README.md
```

---

### Task 1: 워크스페이스와 proto 타입

**Files:** Create `Cargo.toml`, `crates/proto/{Cargo.toml,src/lib.rs}`

**Interfaces — Produces:**
- `enum Side { External, Internal }`, `enum Direction { ToInternal, ToExternal }`, `enum Role { User, Admin }`
- `enum ApprovalMode { Pre, Post }`, `enum PiiAction { LogOnly, ForcePre, Block }`
- `struct Limits { daily_bytes: u64, per_file_bytes: u64 }`
- `struct PiiRule { id: String, name: String, enabled: bool, builtin: bool, pattern: Option<String>, threshold: u32, action: PiiAction }`
- `struct Policy { session_max_minutes: Option<u32>, idle_lock_minutes: Option<u32>, pw_min_len: u8, pw_require_mix: bool, pw_max_age_days: Option<u32>, login_fail_lock: u8, blocked_exts: Vec<String>, allowed_exts: Vec<String>, file_retention_days: u32, audit_retention_days: u32, post_deadline_days: u32, clipboard_max_bytes: u32, default_limits: Limits, pii_rules: Vec<PiiRule>, pii_unscannable_action: PiiAction }`과 7.9장 기본값을 쓰는 `impl Default`
- `struct ApprovalRule { order: i32, direction: Option<Direction>, max_size: Option<u64>, exts: Vec<String>, dept_id: Option<i64>, mode: ApprovalMode }`
- `enum TransferState { Uploading, Pending, Available, Rejected, Blocked, Downloaded, Expired }`
- `struct TransferInfo { id, direction, file_name, size, sha256, reason, state, mode: Option<ApprovalMode>, pii: Vec<PiiHit>, unscannable: bool, sender_ip, receiver_ip: Option<String>, created_at, approval: Option<ApprovalInfo> }`
- `struct PiiHit { rule_id: String, name: String, count: u32 }`
- `#[serde(tag="op")] enum ApiRequest`: `Login{username,password,device_key:Option<String>}`, `Logout`, `Unlock{password}`, `ChangePassword{old,new}`, `Me`, `CreateTransfers{files: Vec<FileMeta>, reason}`, `CompleteUpload{id}`, `ListOutgoing`, `ListIncoming`, `MarkDownloaded{id}`, `ListApprovals`, `Decide{approval_id, approve: bool, comment}`, `GetDelegation`, `SetDelegation{proxy_username, from, to}`, `ClearDelegation`, `Clipboard{text}`, `Usage`, `Admin(AdminRequest)`
- `enum AdminRequest`: `ListUsers`, `UpsertUser{..}`, `ResetPassword{user_id,new}`, `UnlockUser{user_id}`, `ReleaseDevice{user_id, side}`, `ListDepts`, `UpsertDept{id:Option<i64>, name}`, `GetPolicy`, `SetPolicy(Policy)`, `ListLimitOverrides`, `SetLimitOverride{scope: LimitScope, limits: Option<Limits>}`, `ListApprovalRules`, `SetApprovalRules(Vec<ApprovalRule>)`, `QueryAudit(AuditQuery)`, `ListSessions`, `KillSession{session_id}`
- `enum ApiResponse` (요청별 결과 하나씩) / `struct ApiError { code: ErrorCode, message: String }` — 메시지는 한국어
- `#[serde(tag="ev")] enum Event`: `SessionStarted{token, me}`, `SessionEnded{reason}`, `Clipboard{text, from_ip}`, `TransferUpdated(TransferInfo)`, `ApprovalRequested{..}`, `PolicyChanged(Policy)`
- `fn hostname_side_label(Side) -> &'static str` ("인터넷망"/"업무망")

- [ ] Step 1: 테스트 `api_request_roundtrip` — `ApiRequest::Login{..}`를 JSON으로 바꾸면 `"op":"Login"`이 들어가고 다시 읽으면 같다. `policy_default_matches_spec` — `Policy::default().login_fail_lock == 5`, `file_retention_days == 7`, `audit_retention_days == 365`, `post_deadline_days == 3`, `pw_min_len == 9`, `blocked_exts`에 `exe`가 있다.
- [ ] Step 2: 실패 확인 → 구현 → `cargo test -p netbridge-proto` 통과 → 커밋

### Task 2: 개인정보 탐지 (pii)

**Files:** Create `crates/pii/src/{lib,detect,extract,mask}.rs`

**Interfaces — Produces:**
- `fn builtin_rules() -> Vec<PiiRule>` — id: `rrn`, `phone`, `card`, `account`, `passport`, `driver`, `email`
- `fn scan_text(text: &str, rules: &[PiiRule]) -> Vec<PiiHit>` — `enabled`이고 `count >= threshold`인 항목만
- `fn mask_text(text: &str, rules: &[PiiRule]) -> String`
- `enum Extracted { Text(String), Unscannable(String) }`, `fn extract_text(name: &str, bytes: &[u8]) -> Extracted`
- `fn decide(hits: &[PiiHit], unscannable: bool, rules: &[PiiRule], unscannable_action: PiiAction) -> Option<PiiAction>` — 가장 강한 조치 (Block > ForcePre > LogOnly)

탐지 규칙(정규식에 더해 검증):
- 주민·외국인등록번호: `\d{6}-?[1-8]\d{6}`. 앞 6자리는 유효한 날짜여야 한다(7번째 자리로 세기 결정: 1·2·5·6→1900, 3·4·7·8→2000). **검증 숫자는 확인하지 않는다.** 2020년 10월 이후 번호에는 검증 숫자가 없기 때문이다.
- 휴대전화: `01[016789]-?\d{3,4}-?\d{4}`
- 카드: 4자리씩 `-` 또는 공백으로 나뉜 13~19자리이고 Luhn 검사를 통과해야 한다.
- 계좌: 하이픈이 있어야 한다. `\d{3,6}-\d{2,6}-\d{2,6}(-\d{1,3})?` 중 전화·주민 패턴과 겹치지 않는 것
- 여권: `[MSRODG]\d{8}` 또는 `[MSRODG]\d{3}[A-Z]\d{4}`
- 운전면허: `\d{2}-\d{2}-\d{6}-\d{2}`
- 이메일: 일반적인 형식
- 사용자 정의 규칙: `pattern` 정규식. 컴파일 실패하면 `SetPolicy`가 거부한다(Task 8).

가리기: 일치한 문자열의 앞 ⌈길이/3⌉글자만 남기고 나머지 숫자·문자를 `*`로 바꾼다. 주민번호는 `900101-1******` 형태가 된다.

글자 추출: txt/csv/log/json/xml/html/md는 UTF-8(실패하면 EUC-KR — `encoding_rs`)로 읽는다. docx/xlsx/pptx/hwpx는 zip 안의 `.xml` 항목에서 텍스트 노드만 모은다. pdf는 `pdf_extract::extract_text_from_mem`을 `catch_unwind`로 감싸 쓴다. 그 밖의 형식은 `Unscannable`이다.

- [ ] Step 1: 테스트
  - `rrn_old_format_detected`: `"주민 900101-1234568"` → rrn 1건
  - `rrn_new_format_without_checksum_detected`: `"0210153000000"` (2002-10-15, 검증 숫자 불일치) → rrn 1건
  - `rrn_invalid_date_not_detected`: `"991399-1234567"` → 0건
  - `card_luhn`: `"4111-1111-1111-1111"` → card 1건, `"4111-1111-1111-1112"` → 0건
  - `phone_and_email`: `"010-1234-5678 a.b@example.com"` → phone 1, email 1
  - `threshold_respected`: email 규칙 threshold 2에 이메일 1개 → 빈 결과
  - `custom_rule`: pattern `사번\d{6}` → `"사번123456"` 1건
  - `mask_rrn`: `mask_text("900101-1234568")` == `"900101-1******"`
  - `extract_docx`: 테스트에서 zip으로 만든 `word/document.xml`(`<w:t>010-1234-5678</w:t>`) → `Text`에 번호가 들어 있다.
  - `extract_unknown_is_unscannable`: `a.png` → `Unscannable`
  - `decide_strongest`: LogOnly·Block 혼합 → `Some(Block)`, 빈 결과에 unscannable=false → `None`
- [ ] Step 2: 구현 → `cargo test -p netbridge-pii` 통과 → 커밋

### Task 3: 서버 뼈대 — 설정, 인증서, DB, init-admin

**Files:** Create `crates/server/src/{main,config,certs,db}.rs`, `crates/server/server.example.toml`

**Interfaces — Produces:**
- `struct ServerConfig { side: Side, listen: SocketAddr, data_dir: PathBuf, tls_cert: PathBuf, tls_key: PathBuf, ca_cert: PathBuf, link: LinkConfig }` — 외부: `link.listen`(mTLS 연계 수신 주소), 내부: `link.external_url`, `link.client_cert`, `link.client_key`
- `fn gen_certs(out: &Path, external_hosts: &[String], internal_hosts: &[String]) -> Result<()>` — `ca.pem/ca.key`, `external.pem/key`, `internal.pem/key`, `link-client.pem/key`
- `fn server_tls(cfg) -> rustls::ServerConfig`, `fn link_server_tls(cfg) -> ServerConfig`(클라이언트 인증서 필수), `fn link_client_tls(cfg) -> ClientConfig`
- `struct Db(Mutex<rusqlite::Connection>)`, `Db::open(path) -> Result<Db>` — 테이블: `depts, users, devices, sessions, transfers, approvals, delegations, limit_overrides, approval_rules, policy(json 한 행), audit`
- 서브커맨드: `netbridge-server gen-certs --out DIR --external-host H.. --internal-host H..`, `netbridge-server init-admin --config F --username U --password P`, `netbridge-server run --config F`

- [ ] Step 1: 테스트 `db_open_creates_schema_idempotent` — 같은 경로를 두 번 열어도 오류가 없고 `policy` 행이 `Policy::default()`와 같다. `gen_certs_produces_chain` — 만든 서버 인증서를 CA로 검증할 수 있다(`webpki`/`rustls` 검증기로).
- [ ] Step 2: 구현 → 통과 → 커밋

### Task 4: 계정·기기·세션 (Core 진입점)

**Files:** Create `crates/server/src/core/{mod,auth,session}.rs`, `crates/server/src/hub.rs`

**Interfaces — Produces:**
- `struct CallCtx { token: Option<String>, client_ip: String, side: Side }`
- `struct Core { db: Db, files: Files, hub: Hub, link: Option<LinkHandle>, now: Box<dyn Fn() -> DateTime<Utc> + Send + Sync> }` — `now`는 테스트에서 시간을 바꾸기 위해 둔다.
- `impl Core { async fn handle(&self, ctx: CallCtx, req: ApiRequest) -> Result<ApiResponse, ApiError> }`
- `fn device_auth(&self, device_key: &str) -> Option<DeviceRef { device_id, user_id, side }>`
- `trait Pusher { fn push(&self, side: Side, device_id: i64, ev: Event) }` — 내부 쪽은 `Hub`, 외부 쪽은 연계를 거친다.

동작:
- `Login`: 비밀번호 확인, 실패 횟수 증가, `policy.login_fail_lock`회 실패하면 잠금. 이 쪽(side)에 등록된 기기가 없으면 새 기기 키를 만들어 돌려준다. 키가 있는데 전달된 키와 다르면 오류 `DeviceMismatch`("관리자에게 기기 해제를 요청하세요")를 낸다. 사용자에게 살아 있는 세션이 있으면 **같은 토큰**을 돌려준다(재접속). 없으면 새로 만들고, 반대편 기기에 `Event::SessionStarted`를 푸시한다.
- 토큰 검사: 세션이 끝났거나 `session_max_minutes`를 넘었으면 `SessionExpired`.
- `Logout`: 세션을 끝내고 양쪽 기기에 `SessionEnded{reason:"로그아웃"}`을 푸시한다.
- `Unlock`, `ChangePassword`(정책의 길이·조합 검사), `Me`
- 모든 동작은 `audit`에 `kind, user_id, ip, detail`로 남긴다.

- [ ] Step 1: 테스트 (Core를 임시 DB로 직접 호출)
  - `login_registers_device_and_returns_key`
  - `second_side_login_reuses_token`: 외부에서 로그인한 뒤 내부에서 로그인하면 같은 토큰을 받는다.
  - `peer_device_gets_session_started`: 내부 기기가 등록된 상태에서 외부 로그인 → 테스트 Pusher가 내부 기기로 `SessionStarted`를 받는다.
  - `lock_after_five_failures`: 5회 실패 후 맞는 비밀번호로도 `AccountLocked`
  - `session_survives_until_logout`: `now`를 30일 뒤로 돌려도(`session_max_minutes=None`) `Me`가 성공한다.
  - `session_max_minutes_enforced`: 60으로 두고 61분 뒤 → `SessionExpired`
  - `logout_ends_both_sides`
  - `device_mismatch_rejected`
- [ ] Step 2: 구현 → 통과 → 커밋

### Task 5: 정책과 용량 한도

**Files:** Create `crates/server/src/core/{policy,limits}.rs`

**Interfaces — Produces:**
- `fn effective_limits(&self, user_id) -> Limits` — 개인 → 부서 → `policy.default_limits` 순서로 처음 있는 값
- `fn used_today(&self, user_id, now) -> u64` — KST 자정 이후 만든 전송 중 `Rejected`, `Blocked`를 뺀 크기 합
- `fn check_file(&self, user_id, name, size, now) -> Result<(), ApiError>` — 확장자(마지막 확장자 기준, 소문자로 비교. `allowed_exts`가 비어 있지 않으면 그 목록만 허용), 파일 1개 한도, 하루 한도. 오류 메시지에 남은 양을 넣는다.
- `fn policy(&self) -> Policy`, `fn set_policy(&self, p: Policy) -> Result<()>` — 사용자 정의 PII 정규식 검증, 바뀐 값을 audit에 남기고 `PolicyChanged`를 모든 기기에 푸시한다.

- [ ] Step 1: 테스트 `user_override_beats_dept_beats_default`, `daily_usage_resets_at_kst_midnight`(14:59Z에 900MB, 15:01Z에 200MB 확인 → 15:01Z는 새 날이므로 통과), `per_file_limit_message_has_numbers`, `rejected_not_counted`, `set_policy_rejects_bad_regex`
- [ ] Step 2: 구현 → 통과 → 커밋

### Task 6: 파일 저장소와 전송 생성·업로드

**Files:** Create `crates/server/src/files.rs`, `crates/server/src/core/transfer.rs`

**Interfaces — Produces:**
- `struct Files { root: PathBuf }`: `fn path(id) -> PathBuf` (저장 이름은 id만 쓴다. 원래 파일명은 DB에만 둔다), `fn write_at(id, offset, bytes) -> Result<u64>` (현재 길이와 offset이 다르면 `Conflict{have}`), `fn len(id)`, `fn sha256(id) -> String`, `fn remove(id)`
- `CreateTransfers` → 파일마다 `check_file`를 거친 뒤 `Uploading` 행을 만들고 `Vec<i64>`를 돌려준다. 파일명은 `sanitize_name`으로 경로 구분자와 제어문자를 뺀다. 사유가 비어 있으면 오류.
- HTTP `PUT /upload/{id}?offset=N` (Task 9에서 붙임)
- `CompleteUpload{id}` → 크기·해시 확인 → 보내는 쪽 서버에서 PII 검사(내부 쪽이면 직접, 외부 쪽이면 `link.scan(id)`) → Task 7의 `route_transfer`
- `ListOutgoing`, `ListIncoming`(내 반대편 망에서 온 `Available`·`Downloaded`), `MarkDownloaded{id}` → `receiver_ip`를 기록한다.

- [ ] Step 1: 테스트 `resume_upload_after_disconnect`, `hash_mismatch_rejected`, `blocked_ext_case_and_double_ext`(`A.EXE`, `a.txt.exe` 차단, `a.exe.txt` 허용), `path_traversal_name_is_sanitized`(`..\\..\\x.txt` → `x.txt`), `empty_reason_rejected`
- [ ] Step 2: 구현 → 통과 → 커밋

### Task 7: 결재 (사전·사후·대결)

**Files:** Create `crates/server/src/core/approval.rs`

**Interfaces — Produces:**
- `fn pick_mode(rules: &[ApprovalRule], direction, size, ext, dept_id) -> ApprovalMode` — `order` 순서로 처음 맞는 규칙, 없으면 `Pre`
- `async fn route_transfer(&self, id, pii: Vec<PiiHit>, unscannable: bool)`:
  - PII 조치가 `Block`이면 `Blocked` 처리하고 보낸 사람에게 알린다.
  - 조치가 `ForcePre`이거나 사용자가 사후결재 제한 상태면 `Pre`를 쓴다. 아니면 `pick_mode`
  - `Pre`: `Pending` + 결재 요청을 만들고 결재자와 유효한 대리인에게 `ApprovalRequested`를 푸시한다.
  - `Post`: 바로 `deliver(id)`를 하고 결재 요청은 `Pending`으로 남긴다.
- `async fn deliver(&self, id)` — 받는 쪽 서버로 파일을 옮긴다(`ToInternal`: `link.fetch_file`, `ToExternal`: `link.push_file`). 그다음 `Available`로 바꾸고 보낸 사람의 반대편 기기에 `TransferUpdated`를 푸시한다.
- `Decide{approval_id, approve, comment}` — 권한: 결재자 본인이거나, 오늘(KST)이 대결 기간 안에 있는 대리인. 대리인이 결재하면 `by_proxy=true`. `Pre` 승인 → `deliver`, `Pre` 반려 → `Rejected` 처리하고 보내는 쪽 파일을 지운다. `Post` 반려 → 기록하고 관리자에게 알린다.
- `ListApprovals` — 내가 결재할 수 있는 대기 건(대결 포함)과 내가 처리한 건
- `SetDelegation`·`GetDelegation`·`ClearDelegation`
- `fn sweep(&self, now)` — 1분마다 돈다. 기한(`post_deadline_days`)이 지난 `Post` 대기 건을 `overdue`로 표시하고 관리자에게 알린다. 그 사용자는 사후결재 제한 상태가 된다(미결 건이 없어지면 풀린다). 보관 기간이 지난 파일을 지우고 `Expired`로 바꾼다. 보관 기간이 지난 audit을 지운다.

- [ ] Step 1: 테스트
  - `no_rule_defaults_to_pre`, `first_matching_rule_wins`
  - `pre_not_visible_before_approval`: 내부 쪽 `ListIncoming`에 대기 건이 없다.
  - `pre_approve_delivers`, `pre_reject_deletes_file`
  - `post_delivers_immediately_and_queues_approval`
  - `post_overdue_restricts_user_to_pre`: `now`를 4일 뒤로 돌려 `sweep` → 다음 전송은 사후 규칙에 맞아도 `Pre`
  - `proxy_can_decide_within_period_only`
  - `pii_force_pre_overrides_post_rule`, `pii_block_blocks`
  - `retention_expires_files`
- [ ] Step 2: 구현 → 통과 → 커밋

### Task 8: 클립보드, 관리자 기능, 감사 이력

**Files:** Create `crates/server/src/core/{clipboard,admin,audit}.rs`

**Interfaces — Produces:**
- `Clipboard{text}` → `clipboard_max_bytes` 확인 → PII 검사(`ForcePre`도 `Block`으로 처리) → 반대편 기기가 연결되어 있지 않으면 오류 `PeerOffline`("반대편 PC가 연결되어 있지 않습니다") → 푸시 → 가린 내용으로 audit에 남긴다.
- `Usage` → `{ limits, used_today }`
- `Admin(..)`: 관리자 역할만 쓸 수 있고, **내부 쪽에서 온 요청만** 받는다(`ctx.side == Internal`. 아니면 `Forbidden`). 사용자·부서 CRUD, 비밀번호 초기화, 잠금 해제, 기기 해제, 정책, 한도 예외, 결재 규칙, 세션 목록·강제 종료
- `QueryAudit(AuditQuery{from, to, user: Option<String>, kind: Option<String>, limit})` → `Vec<AuditRow{at, user, kind, ip, detail}>`. CSV 저장은 앱에서 한다.

- [ ] Step 1: 테스트 `clipboard_pushed_to_peer_and_masked_in_audit`, `clipboard_peer_offline_errors`, `clipboard_too_large`, `admin_forbidden_from_external_side`, `admin_forbidden_for_user_role`, `kill_session_pushes_session_ended`, `audit_query_filters`
- [ ] Step 2: 구현 → 통과 → 커밋

### Task 9: HTTP와 연계 구간

**Files:** Create `crates/server/src/{http,link,relay}.rs`, 수정 `main.rs`

**Interfaces — Produces:**
- 앱 쪽 HTTPS (양쪽 서버 공통 경로):
  - `POST /api` (헤더 `Authorization: Bearer <token>`, 본문 `ApiRequest`) → `ApiResponse` 또는 `ApiError`(HTTP 4xx)
  - `GET /ws?device_key=K` → `Event` JSON 텍스트 프레임. 서버는 20초마다 ping을 보낸다.
  - `PUT /upload/{id}?offset=N`, `GET /download/{id}` (Bearer, `Range` 지원) — 내려받기 권한은 Core가 판정한다. 받는 사람의 `Available` 건이거나, 결재 권한자가 보내는 쪽 서버에서 미리 보기하는 경우다.
  - `GET /hello` → `{ side, server_time }` (인증 없이)
  - client_ip는 소켓 주소에서 얻는다.
- 연계 (내부가 클라이언트, 외부가 mTLS 서버 `link.listen`):
  - 내부 → 외부 `GET /link/ws`: 외부가 앱에서 받은 `/api` 요청을 `LinkFrame{id, Api{ctx, req}}`로 보내면 내부가 `LinkFrame{id, Reply(Result)}`로 답한다. 기기 인증도 `DeviceAuth{key}` 프레임으로 묻는다. 연결이 끊기면 내부는 1→2→4…최대 30초 간격으로 다시 연결한다. 외부는 연계가 없는 동안 `/api`에 `LinkDown`("연계 구간이 끊어졌습니다") 오류를 낸다.
  - 내부 → 외부 HTTPS: `GET /link/files/{id}`(가져오기), `PUT /link/files/{id}`(보내기), `POST /link/scan/{id}`(본문 Policy, 응답 `{hits, unscannable}`), `POST /link/push`(본문 `{device_id, event}`), `DELETE /link/files/{id}`
  - `struct LinkHandle` (내부 쪽): `fetch_file(id)`, `push_file(id)`, `scan(id, &Policy)`, `push(device_id, Event)`, `delete_file(id)`
- `relay.rs` (외부 쪽): `/api`를 연계로 넘기고, `/upload`·`/download`는 로컬 `Files`를 쓴다(권한은 연계로 물어본다), `/ws`는 기기 인증을 연계로 묻고 로컬 Hub에 붙인다.

- [ ] Step 1: e2e 테스트는 Task 10에 둔다. 여기서는 `link_frame_roundtrip`과 `link_requires_client_cert` 테스트를 둔다. 연계 수신 포트에 클라이언트 인증서 없이 붙으면 TLS 핸드셰이크가 실패해야 한다.
- [ ] Step 2: 구현 → `cargo test -p netbridge-server` 통과 → 커밋

### Task 10: clientcore와 끝까지 도는 테스트

**Files:** Create `crates/clientcore/src/{lib,config,net,secret}.rs`, `crates/clientcore/tests/e2e.rs`

**Interfaces — Produces:**
- `struct ClientConfig { server_url: String, ca_pem_path: PathBuf, hotkey: String /*"Alt+F3"*/, download_dir: PathBuf }`, `load() / save()` — 위치는 `%APPDATA%\NetBridge\config.toml` (`dirs::config_dir()`)
- `secret::{store_device_key(side_label, key), load_device_key(side_label) -> Option<String>, clear_device_key(..)}` — Windows는 DPAPI(`CryptProtectData`), 그 밖의 OS는 권한 0600 평문 파일(개발용)
- `struct Net` — `Net::new(cfg) -> Result<Net>` (CA 고정, 시스템 루트 인증서 안 씀)
  - `async fn hello(&self) -> Result<Hello>`
  - `async fn call(&self, req: ApiRequest) -> Result<ApiResponse, ApiError>`
  - `async fn upload(&self, id, path, progress: impl Fn(u64)) -> Result<()>` — 1MiB 조각. `Conflict{have}`를 받으면 have부터 다시 올린다.
  - `async fn download(&self, id, dest, progress) -> Result<()>` — 받은 뒤 SHA-256을 확인한다.
  - `fn run_events(self: Arc<Self>, device_key, tx: mpsc::Sender<NetEvent>)` — `/ws`에 붙어 있다가 끊기면 1→2→4…최대 30초 간격으로 다시 붙는다. `NetEvent::{Connected, Disconnected, Event(Event)}`
  - `fn set_token(&self, Option<String>)`
  - `fn sha256_file(path) -> Result<String>`

- [ ] Step 1: e2e 테스트 — 임시 폴더에 인증서를 만들고 두 서버를 127.0.0.1 임의 포트로 띄운다.
  - `full_flow_pre_approval`: 관리자가 사용자 a(결재자 b)를 만든다 → a가 외부에서 로그인 → 내부 기기 이벤트 채널로 `SessionStarted`를 받는다 → 외부에서 파일을 올린다 → b가 내부에서 승인한다 → a의 내부 `ListIncoming`에 나타난다 → 내려받은 파일의 해시가 같고 송신·수신 IP가 기록된다.
  - `post_approval_flow`, `clipboard_external_to_internal`, `pii_block_e2e`(카드번호가 든 txt, Block 정책)
  - `link_drop_and_recover_keeps_session`: 외부 서버의 연계 수신을 끊었다가 다시 연다 → 외부 `Me`가 `LinkDown` 뒤 같은 토큰으로 성공한다.
  - `ws_reconnect_keeps_session`: 앱의 WS를 강제로 끊는다 → 다시 붙은 뒤 `Me`가 성공한다.
- [ ] Step 2: 구현 → `cargo test -p netbridge-clientcore` 통과 → 커밋

### Task 11: egui 앱 — 로그인, 보내기, 받기, 이력, 상태줄

**Files:** Create `crates/client/src/{main,app,fonts}.rs`, `ui/{login,send,inbox,history}.rs`, `assets/fonts/NanumGothic-Regular.ttf`

**Interfaces — Consumes:** clientcore 전체 — **Produces:** `struct App`, `enum Screen`, 백그라운드 tokio 런타임 + `Arc<Mutex<Shared>>` + `ctx.request_repaint()`

- 첫 실행: 서버 주소와 CA 인증서 파일을 입력한다(설치 폴더에 `ca.pem`이 있으면 자동으로 채운다) → `hello`로 망을 확인하고 제목줄에 "NetBridge — 인터넷망"처럼 보여 준다.
- 로그인 → 왼쪽 메뉴: 파일 보내기 / 받은 파일 / 보낸 파일 / 결재함 / 대결 / 설정 (+ 관리자)
- 보내기: 끌어다 놓기(`ctx.input(|i| i.raw.dropped_files)`)와 파일 선택(`rfd`) → 사유 입력 → 진행률 → 결과(결재 대기·전달됨·차단 사유·탐지 항목)
- 받은 파일: 목록(파일명, 크기, 송신 IP, 결재 방식, 시각) → 받기 → 저장 폴더
- 보낸 파일: 상태, 결재자, 대결 여부, 송신·수신 IP
- 상태줄: 내 IP(서버가 본 주소, `Me` 응답에 넣는다), 서버 주소, 연결 상태(초록/빨강), 오늘 사용량/한도
- 로그인 상태에서 연결이 끊기면 화면을 유지하고 "다시 연결 중…"만 표시한다.
- 미사용 잠금: `idle_lock_minutes`가 있으면 입력이 없는 시간을 재서 잠금 화면을 띄운다(`Unlock`).
- 반대편에서 로그인했다는 `SessionStarted` 이벤트를 받으면 자동으로 로그인 상태가 된다.

- [ ] Step 1: `cargo build -p netbridge-client` 성공. 화면 단위 테스트는 하지 않는다(egui). 대신 Task 10의 e2e가 로직을 덮는다.
- [ ] Step 2: 로컬 두 서버 + 리눅스 빌드 앱 2개로 직접 실행해 확인 → 커밋

### Task 12: 결재함, 대결, 설정(단축키), 클립보드, 트레이

**Files:** Create `ui/{approvals,delegation,settings}.rs`, `hotkey.rs`, `tray.rs`

- 결재함: 대기 건(보낸 사람, 파일, 크기, 해시, 사유, PII 탐지 결과, 대결 표시) → 승인/반려(의견). 보내는 쪽 망 앱이면 "미리 보기"로 파일을 임시 폴더에 받아 기본 프로그램으로 연다(`open` 크레이트).
- 대결: 대리인 아이디와 기간(시작일·종료일) 지정, 해제
- 설정: 단축키 입력(키를 눌러 기록, `global_hotkey::hotkey::HotKey::from_str`로 확인) → 등록에 실패하면 "다른 프로그램이 사용 중인 단축키입니다", 저장 폴더, 비밀번호 변경
- 단축키: `GlobalHotKeyEvent::set_event_handler` 콜백 안에서 `arboard`로 텍스트를 읽어 런타임 핸들로 `Clipboard{text}`를 보낸다. 창이 숨겨져 있어도 동작해야 하므로 UI 갱신에 의존하지 않는다.
- 받은 클립보드: 이벤트 작업에서 바로 `arboard`로 넣고, 트레이 툴팁·창 알림을 띄운다.
- 트레이: 창 닫기 요청 → 숨기기(`ViewportCommand::Visible(false)`), 트레이 메뉴 "열기 / 로그아웃 / 종료"

- [ ] Step 1: `hotkey::parse("Alt+F3")` 성공, `parse("Ctrl+Shift+V")` 성공, `parse("Nope")` 실패 단위 테스트
- [ ] Step 2: 구현 → 빌드 → 커밋

### Task 13: 관리자 화면

**Files:** Create `ui/admin/{mod,users,limits,rules,policy,pii,audit,sessions}.rs`

- 업무망 앱에서 관리자 계정일 때만 메뉴를 보여 준다(서버도 Task 8에서 막는다).
- 사용자·부서: 목록, 추가·수정(아이디, 이름, 부서, 역할, 결재자), 비밀번호 초기화, 잠금 해제, 기기 해제(망별)
- 용량 한도: 전사 기본값, 부서·개인 예외 목록. 입력 단위는 MB다.
- 결재 규칙: 순서 위·아래 이동, 조건(방향, 최대 크기, 확장자, 부서) → 사전/사후
- 보안정책: 7.9장 항목 전부 + "정책 내보내기/가져오기"(JSON 파일)
- 개인정보: 항목별 켜기, 기준 건수, 조치, 사용자 정의 정규식 추가와 시험 입력란(`pii::scan_text`를 앱에서 미리 돌려 본다)
- 이력: 기간·사용자·종류 검색 → 표 → CSV 저장(UTF-8 BOM, 엑셀용)
- 세션: 접속 중 목록과 강제 종료

- [ ] Step 1: 빌드 → 로컬 실행으로 정책 저장 후 반대편 앱의 미사용 잠금이 바뀌는지 확인 → 커밋

### Task 14: Windows 빌드, 설치파일, 문서

**Files:** Create `build/Dockerfile.windows`, `scripts/build-windows.sh`, `scripts/vendor.sh`, `installer/netbridge.nsi`, `assets/icon.ico`, `README.md`, `CHANGELOG.md`

- Docker 이미지(rust + mingw-w64 + nsis)에서 `x86_64-pc-windows-gnu`로 `netbridge.exe`(GUI, `windows_subsystem="windows"`)와 `netbridge-server.exe`를 만든다. 리눅스용 `netbridge-server`도 만든다.
- NSIS: `NetBridge-Setup-0.1.0.exe` — Program Files 설치, 시작 메뉴·바탕화면 바로가기, 시작 프로그램 등록(선택), 제거 프로그램 등록. `ca.pem`을 설치파일 옆에 두면 함께 복사한다.
- 서버 배포물: `netbridge-server-0.1.0-{windows,linux}.zip` (실행파일 + `server.example.toml` + 설치 안내)
- README: 인증서 만들기 → 내부·외부 서버 설정 → `init-admin` → 앱 설치 → 첫 실행. 폐쇄망 빌드(`scripts/vendor.sh`) 방법
- [ ] Step 1: `scripts/build-windows.sh` 실행 → `dist/`에 설치파일과 zip이 생긴다.
- [ ] Step 2: WSL에서 `dist/netbridge.exe`를 Windows로 실행해 창이 뜨고 한글이 보이는지 확인한다. 서버 exe로 `/hello`에 응답하는지 확인한다.
- [ ] Step 3: 커밋

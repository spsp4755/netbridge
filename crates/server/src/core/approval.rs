use super::limits::ext_of;
use super::{enc, to_kst, Caller, Core, ScanResult};
use chrono::NaiveDate;
use netbridge_proto::*;
use rusqlite::{params, OptionalExtension};

/// First rule (by `order`) whose conditions all match; Pre when none does.
pub fn pick_mode(rules: &[ApprovalRule], size: u64, ext: &str, dept_id: Option<i64>) -> ApprovalMode {
    let mut sorted: Vec<&ApprovalRule> = rules.iter().collect();
    sorted.sort_by_key(|r| r.order);
    sorted
        .into_iter()
        .find(|r| {
            r.max_size.is_none_or(|m| size <= m)
                && (r.exts.is_empty() || r.exts.iter().any(|e| e.eq_ignore_ascii_case(ext)))
                && r.dept_id.is_none_or(|d| Some(d) == dept_id)
        })
        .map(|r| r.mode)
        .unwrap_or(ApprovalMode::Pre)
}

impl Core {
    fn today(&self) -> NaiveDate {
        to_kst(self.clock.now()).date_naive()
    }

    /// Some(as_proxy) when the user may decide this approval.
    pub(super) fn can_decide(&self, user_id: i64, approval_id: i64) -> Result<Option<bool>, ApiError> {
        let today = self.today().to_string();
        self.db.with(|c| {
            let approver: Option<i64> = c.query_row("SELECT approver_id FROM approvals WHERE id=?1", [approval_id], |r| r.get(0)).optional()?;
            let Some(approver) = approver else { return Ok(None) };
            if approver == user_id {
                return Ok(Some(false));
            }
            let proxy: Option<i64> = c
                .query_row("SELECT 1 FROM delegations WHERE approver_id=?1 AND proxy_id=?2 AND from_date<=?3 AND to_date>=?3", params![approver, user_id, today], |r| r.get(0))
                .optional()?;
            Ok(proxy.map(|_| true))
        })
    }

    /// Applies PII action and approval rules to a completed upload.
    pub(super) async fn route_transfer(&self, id: i64, scan: &ScanResult) -> Result<(), ApiError> {
        let global = self.db.policy()?;
        let t = self.transfer_info(id)?;
        let owner = self.transfer_owner(id)?;
        let route = self.route_policy(&t.route)?;
        let rules = route.effective_pii(&global.pii_rules);
        let action = netbridge_pii::decide(&scan.hits, scan.unscannable, &rules, route.unscannable_action);
        if action == Some(PiiAction::Block) {
            let mut items: Vec<String> = scan.hits.iter().map(|h| format!("{} {}건", h.name, h.count)).collect();
            if scan.unscannable {
                items.push("내용 검사 불가".into());
            }
            let reason = format!("개인정보 탐지로 차단: {}", items.join(", "));
            self.db.with(|c| c.execute("UPDATE transfers SET state='Blocked', block_reason=?2 WHERE id=?1", params![id, reason]))?;
            self.remove_at(&t.route.from, id).await;
            self.audit(Some((owner, &t.owner)), "transfer_blocked", Some(&t.sender_ip), &format!("#{id} {reason}"));
            self.push_user(owner, Event::TransferUpdated { transfer: self.transfer_info(id)? }).await;
            return Ok(());
        }
        let (approver, dept, restricted): (i64, Option<i64>, bool) =
            self.db.with(|c| c.query_row("SELECT approver_id, dept_id, post_restricted FROM users WHERE id=?1", [owner], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))))?;
        let mode = if action == Some(PiiAction::ForcePre) || restricted {
            ApprovalMode::Pre
        } else {
            pick_mode(&route.approval_rules, t.size, &ext_of(&t.file_name), dept)
        };
        let pii_forced = netbridge_pii::decide(&scan.hits, false, &rules, route.unscannable_action) == Some(PiiAction::ForcePre);
        if mode == ApprovalMode::Pre && pii_forced && t.reason.trim().is_empty() {
            // the approver needs to know why personal data is leaving; ask the sender first
            self.db.with(|c| c.execute("UPDATE transfers SET state='AwaitingReason', mode='Pre' WHERE id=?1", [id]))?;
            self.push_user(owner, Event::TransferUpdated { transfer: self.transfer_info(id)? }).await;
            return Ok(());
        }
        self.open_approval(id, approver, mode).await
    }

    async fn open_approval(&self, id: i64, approver: i64, mode: ApprovalMode) -> Result<(), ApiError> {
        let t = self.transfer_info(id)?;
        let now = self.clock.now();
        let approval_id = self.db.tx(|tx| {
            tx.execute("UPDATE transfers SET state='Pending', mode=?2 WHERE id=?1", params![id, enc(&mode)]).map_err(ApiError::internal)?;
            tx.execute("INSERT INTO approvals(transfer_id,mode,approver_id,status,created_at) VALUES(?1,?2,?3,'Pending',?4)", params![id, enc(&mode), approver, now])
                .map_err(ApiError::internal)?;
            Ok(tx.last_insert_rowid())
        })?;
        if mode == ApprovalMode::Post {
            if let Err(e) = self.deliver(id).await {
                tracing::warn!("transfer #{id} delivery deferred: {e}");
            }
        }
        self.notify_approvers(approver, approval_id, &t.owner, &t.file_name).await;
        Ok(())
    }

    pub(super) async fn submit_for_approval(&self, c: &Caller, id: i64, reason: &str) -> Result<TransferInfo, ApiError> {
        let t = self.transfer_info(id)?;
        let owner = self.transfer_owner(id)?;
        if owner != c.user_id || t.state != TransferState::AwaitingReason {
            return Err(ApiError::new(ErrorCode::Forbidden, "결재를 요청할 수 없는 전송입니다"));
        }
        if reason.trim().is_empty() {
            return Err(ApiError::bad("개인정보가 탐지된 파일은 사유를 입력해야 결재를 요청할 수 있습니다"));
        }
        let approver: Option<i64> = self.db.with(|db| db.query_row("SELECT approver_id FROM users WHERE id=?1", [owner], |r| r.get(0)))?;
        let approver = approver.ok_or_else(|| ApiError::bad("결재자가 지정되지 않았습니다. 관리자에게 결재자 지정을 요청하세요"))?;
        self.db.with(|db| db.execute("UPDATE transfers SET reason=?2 WHERE id=?1", params![id, reason.trim()]))?;
        self.audit(Some((c.user_id, &c.username)), "transfer", Some(&c.ip), &format!("#{id} {} 결재 요청 (사유 입력)", t.file_name));
        self.open_approval(id, approver, ApprovalMode::Pre).await?;
        self.transfer_info(id)
    }

    async fn notify_approvers(&self, approver: i64, approval_id: i64, from: &str, file_name: &str) {
        let ev = Event::ApprovalRequested { approval_id, from: from.to_string(), file_name: file_name.to_string() };
        self.push_user(approver, ev.clone()).await;
        let today = self.today().to_string();
        let proxy: Option<i64> = self
            .db
            .with(|c| c.query_row("SELECT proxy_id FROM delegations WHERE approver_id=?1 AND from_date<=?2 AND to_date>=?2", params![approver, today], |r| r.get(0)).optional())
            .ok()
            .flatten();
        if let Some(p) = proxy {
            self.push_user(p, ev).await;
        }
    }

    /// Moves the payload to the receiving network and makes it available.
    /// Moves the payload to the receiving network. Only the caller that claims the Pending row runs;
    /// a concurrent call (approval, post-approval, sweep retry) returns Ok without doing anything.
    pub async fn deliver(&self, id: i64) -> Result<(), ApiError> {
        let claimed = self.db.with(|c| c.execute("UPDATE transfers SET state='Delivering' WHERE id=?1 AND state='Pending'", [id]))?;
        if claimed == 0 {
            return Ok(());
        }
        if let Err(e) = self.copy_to_receiver(id).await {
            self.set_state(id, TransferState::Pending)?;
            return Err(e);
        }
        self.set_state(id, TransferState::Available)?;
        let owner = self.transfer_owner(id)?;
        self.push_user(owner, Event::TransferUpdated { transfer: self.transfer_info(id)? }).await;
        Ok(())
    }

    /// Moves the payload along its route: pulled to the central server, pushed from it,
    /// or sent node to node over their own link so it never passes through a third network.
    async fn copy_to_receiver(&self, id: i64) -> Result<(), ApiError> {
        let t = self.transfer_info(id)?;
        let (from, to) = (&t.route.from, &t.route.to);
        if self.is_local(to) {
            let tmp = self.files.path(id).with_extension("part");
            self.peer(from)?.fetch_file(id, &tmp).await?;
            let got = {
                use sha2::Digest;
                let mut h = sha2::Sha256::new();
                let mut f = std::fs::File::open(&tmp).map_err(ApiError::internal)?;
                std::io::copy(&mut f, &mut h).map_err(ApiError::internal)?;
                hex::encode(h.finalize())
            };
            if got != t.sha256 {
                let _ = std::fs::remove_file(&tmp);
                return Err(ApiError::internal("연계 구간에서 받은 파일의 해시가 다릅니다"));
            }
            std::fs::rename(&tmp, self.files.path(id)).map_err(ApiError::internal)?;
            let _ = self.peer(from)?.delete_file(id).await;
        } else if self.is_local(from) {
            self.peer(to)?.push_file(id, &self.files.path(id)).await?;
            self.files.remove(id);
        } else {
            self.peer(from)?.forward(id, to, &t.sha256).await?;
            let _ = self.peer(from)?.delete_file(id).await;
        }
        Ok(())
    }

    pub(super) async fn decide(&self, c: &Caller, approval_id: i64, approve: bool, comment: Option<String>) -> Result<(), ApiError> {
        let Some(as_proxy) = self.can_decide(c.user_id, approval_id)? else {
            return Err(ApiError::new(ErrorCode::Forbidden, "결재 권한이 없습니다"));
        };
        let (tid, mode, status): (i64, String, String) =
            self.db.with(|db| db.query_row("SELECT transfer_id, mode, status FROM approvals WHERE id=?1", [approval_id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))))?;
        if status != "Pending" {
            return Err(ApiError::bad("이미 처리된 결재입니다"));
        }
        let t = self.transfer_info(tid)?;
        if matches!(t.state, TransferState::Expired | TransferState::Blocked) {
            return Err(ApiError::bad("기간이 지났거나 차단된 전송입니다"));
        }
        let now = self.clock.now();
        let comment = comment.map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
        let new_status = if approve { "Approved" } else { "Rejected" };
        let changed = self.db.with(|db| {
            db.execute(
                "UPDATE approvals SET status=?2, decided_by=?3, by_proxy=?4, comment=?5, decided_at=?6 WHERE id=?1 AND status='Pending'",
                params![approval_id, new_status, c.user_id, as_proxy, comment, now],
            )
        })?;
        if changed == 0 {
            return Err(ApiError::bad("이미 처리된 결재입니다"));
        }
        let owner = self.transfer_owner(tid)?;
        let verb = if approve { "승인" } else { "반려" };
        self.audit(Some((c.user_id, &c.username)), "approval", Some(&c.ip), &format!("#{tid} {} {mode} {verb}{}", t.file_name, if as_proxy { " (대결)" } else { "" }));
        // deliver() already tells the owner when the file arrives
        let mut notified = false;
        match (mode.as_str(), approve) {
            ("Pre", true) => match self.deliver(tid).await {
                Ok(()) => notified = true,
                Err(e) => tracing::warn!("transfer #{tid} delivery deferred: {e}"),
            },
            ("Pre", false) => {
                self.set_state(tid, TransferState::Rejected)?;
                self.remove_at(&t.route.from, tid).await;
            }
            (_, false) => self.notify_admins(&format!("사후결재 반려: {} — {} ({})", t.owner, t.file_name, comment.as_deref().unwrap_or("의견 없음"))).await,
            _ => {}
        }
        self.lift_post_restriction(owner)?;
        if !notified {
            self.push_user(owner, Event::TransferUpdated { transfer: self.transfer_info(tid)? }).await;
        }
        Ok(())
    }

    fn lift_post_restriction(&self, uid: i64) -> Result<(), ApiError> {
        self.db.with(|c| {
            c.execute(
                "UPDATE users SET post_restricted=0 WHERE id=?1 AND post_restricted=1 AND NOT EXISTS (
                   SELECT 1 FROM approvals a JOIN transfers t ON t.id=a.transfer_id WHERE t.user_id=?1 AND a.status='Pending' AND a.overdue=1)",
                [uid],
            )
            .map(|_| ())
        })
    }

    pub(super) fn list_approvals(&self, c: &Caller) -> Result<Vec<ApprovalItem>, ApiError> {
        let today = self.today().to_string();
        let rows: Vec<(i64, i64)> = self.db.with(|db| {
            let mut st = db.prepare(
                "SELECT a.transfer_id, a.approver_id FROM approvals a WHERE
                   (a.status='Pending' AND (a.approver_id=?1 OR a.approver_id IN
                      (SELECT approver_id FROM delegations WHERE proxy_id=?1 AND from_date<=?2 AND to_date>=?2)))
                   OR a.decided_by=?1
                 ORDER BY a.status='Pending' DESC, a.id DESC LIMIT 300",
            )?;
            let v = st.query_map(params![c.user_id, today], |r| Ok((r.get(0)?, r.get(1)?)))?.collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(v)
        })?;
        rows.into_iter()
            .map(|(tid, approver)| {
                let transfer = self.transfer_info(tid)?;
                let approval = transfer.approval.clone().ok_or_else(|| ApiError::internal("approval missing"))?;
                Ok(ApprovalItem { approval, transfer, as_proxy: approver != c.user_id })
            })
            .collect()
    }

    pub(super) fn get_delegation(&self, uid: i64) -> Result<Option<Delegation>, ApiError> {
        self.db.with(|c| {
            c.query_row(
                "SELECT u.username, u.name, d.from_date, d.to_date FROM delegations d JOIN users u ON u.id=d.proxy_id WHERE d.approver_id=?1",
                [uid],
                |r| {
                    let parse = |s: String| s.parse::<NaiveDate>().unwrap_or_default();
                    Ok(Delegation { proxy_username: r.get(0)?, proxy_name: r.get(1)?, from: parse(r.get(2)?), to: parse(r.get(3)?) })
                },
            )
            .optional()
        })
    }

    pub(super) fn set_delegation(&self, c: &Caller, proxy: &str, from: NaiveDate, to: NaiveDate) -> Result<(), ApiError> {
        if from > to {
            return Err(ApiError::bad("시작일이 종료일보다 늦습니다"));
        }
        let pid: Option<i64> = self.db.with(|db| db.query_row("SELECT id FROM users WHERE username=?1", [proxy.trim()], |r| r.get(0)).optional())?;
        let pid = pid.ok_or_else(|| ApiError::bad("대리인 아이디를 찾을 수 없습니다"))?;
        if pid == c.user_id {
            return Err(ApiError::bad("본인을 대리인으로 지정할 수 없습니다"));
        }
        self.db.with(|db| {
            db.execute(
                "INSERT INTO delegations(approver_id,proxy_id,from_date,to_date) VALUES(?1,?2,?3,?4) ON CONFLICT(approver_id) DO UPDATE SET proxy_id=excluded.proxy_id, from_date=excluded.from_date, to_date=excluded.to_date",
                params![c.user_id, pid, from.to_string(), to.to_string()],
            )
        })?;
        self.audit(Some((c.user_id, &c.username)), "delegation", Some(&c.ip), &format!("대결 지정: {proxy} {from}~{to}"));
        Ok(())
    }

    pub(super) fn clear_delegation(&self, c: &Caller) -> Result<(), ApiError> {
        self.db.with(|db| db.execute("DELETE FROM delegations WHERE approver_id=?1", [c.user_id]))?;
        self.audit(Some((c.user_id, &c.username)), "delegation", Some(&c.ip), "대결 해제");
        Ok(())
    }

    /// Periodic housekeeping: overdue post-approvals, retention, retrying deliveries.
    pub async fn sweep(&self) {
        let now = self.clock.now();
        let Ok(policy) = self.db.policy() else { return };
        let deadline = now - policy.post_deadline_days as i64 * 86400;
        let overdue: Vec<(i64, i64, String, String)> = self
            .db
            .with(|c| {
                let mut st = c.prepare(
                    "SELECT a.id, t.user_id, u.name, t.file_name FROM approvals a JOIN transfers t ON t.id=a.transfer_id JOIN users u ON u.id=t.user_id
                     WHERE a.mode='Post' AND a.status='Pending' AND a.overdue=0 AND a.created_at<?1",
                )?;
                let v = st.query_map([deadline], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?.filter_map(|r| r.ok()).collect();
                Ok(v)
            })
            .unwrap_or_default();
        for (aid, uid, name, file) in overdue {
            let _ = self.db.with(|c| {
                c.execute("UPDATE approvals SET overdue=1 WHERE id=?1", [aid])?;
                c.execute("UPDATE users SET post_restricted=1 WHERE id=?1", [uid])
            });
            self.audit(Some((uid, &name)), "post_overdue", None, &format!("사후결재 기한 초과: {file}"));
            self.notify_admins(&format!("사후결재 기한 초과: {name} — {file}")).await;
            self.push_user(uid, Event::Notice { message: format!("사후결재 기한이 지났습니다: {file}. 결재가 끝날 때까지 사전결재로만 보낼 수 있습니다") }).await;
        }

        let cutoff = now - policy.file_retention_days as i64 * 86400;
        let expired: Vec<(i64, String)> = self
            .db
            .with(|c| {
                let mut st = c.prepare("SELECT id, from_net FROM transfers WHERE created_at<?1 AND state IN ('Uploading','AwaitingReason','Pending','Available','Downloaded')")?;
                let v = st.query_map([cutoff], |r| Ok((r.get(0)?, r.get(1)?)))?.filter_map(|r| r.ok()).collect();
                Ok(v)
            })
            .unwrap_or_default();
        for (id, from) in expired {
            // the payload sits on the sender's or the receiver's server; clear both
            self.files.remove(id);
            for p in self.peers.values() {
                let _ = p.delete_file(id).await;
            }
            let _ = from;
            let _ = self.set_state(id, TransferState::Expired);
        }
        let audit_cutoff = now - policy.audit_retention_days as i64 * 86400;
        let _ = self.db.with(|c| c.execute("DELETE FROM audit WHERE at<?1", [audit_cutoff]));

        let retry: Vec<i64> = self
            .db
            .with(|c| {
                let mut st = c.prepare(
                    "SELECT t.id FROM transfers t JOIN approvals a ON a.transfer_id=t.id WHERE t.state='Pending' AND (a.mode='Post' OR a.status='Approved')",
                )?;
                let v = st.query_map([], |r| r.get(0))?.filter_map(|r| r.ok()).collect();
                Ok(v)
            })
            .unwrap_or_default();
        for id in retry {
            if let Err(e) = self.deliver(id).await {
                tracing::warn!("retry delivery #{id}: {e}");
            }
        }
    }
}

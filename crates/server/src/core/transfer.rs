use super::{dec, enc, scan_path, CallCtx, Caller, Core, ScanResult};
use netbridge_proto::Route;
use netbridge_proto::*;
use rusqlite::{params, OptionalExtension, Row};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileOp {
    Upload,
    Download,
}

/// Permission to move bytes of one transfer through a server's /upload or /download.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FileGrant {
    pub id: i64,
    pub name: String,
    pub size: u64,
    pub sha256: String,
}

/// Keeps only the last path component and drops control characters.
pub fn sanitize_name(name: &str) -> String {
    let last = name.rsplit(['/', '\\']).next().unwrap_or("");
    let clean: String = last.chars().filter(|c| !c.is_control() && !"<>:\"|?*".contains(*c)).collect();
    // Windows drops trailing dots and spaces on save, so "a.exe." would land as "a.exe"
    let clean = clean.trim().trim_start_matches('.').trim_end_matches(['.', ' ']).trim().to_string();
    let clean: String = clean.chars().take(200).collect();
    if clean.is_empty() {
        return "file".into();
    }
    let stem = clean.split('.').next().unwrap_or("").to_ascii_uppercase();
    let reserved = matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL") || ((stem.starts_with("COM") || stem.starts_with("LPT")) && stem.len() == 4 && stem.as_bytes()[3].is_ascii_digit());
    if reserved {
        format!("_{clean}")
    } else {
        clean
    }
}

pub(super) const SELECT_TRANSFER: &str =
    "SELECT t.id, u.name, t.from_net || '>' || t.to_net, t.file_name, t.size, t.sha256, t.reason, t.state, t.mode, t.pii, t.unscannable, t.block_reason, t.sender_ip, t.receiver_ip, t.created_at,
  a.id, a.mode, a.status, ap.name, dby.name, a.by_proxy, a.comment, a.decided_at, a.overdue, t.user_id, t.threats
  FROM transfers t JOIN users u ON u.id=t.user_id LEFT JOIN approvals a ON a.transfer_id=t.id
  LEFT JOIN users ap ON ap.id=a.approver_id LEFT JOIN users dby ON dby.id=a.decided_by";

pub(super) fn row_transfer(r: &Row) -> rusqlite::Result<TransferInfo> {
    let approval = match r.get::<_, Option<i64>>(15)? {
        Some(id) => Some(ApprovalInfo {
            id,
            mode: dec(&r.get::<_, String>(16)?)?,
            status: dec(&r.get::<_, String>(17)?)?,
            approver: r.get(18)?,
            decided_by: r.get(19)?,
            by_proxy: r.get(20)?,
            comment: r.get(21)?,
            decided_at: r.get(22)?,
            overdue: r.get(23)?,
        }),
        None => None,
    };
    Ok(TransferInfo {
        id: r.get(0)?,
        owner: r.get(1)?,
        route: {
            // network ids never contain '>' (config ids are short names)
            let s = r.get::<_, String>(2)?;
            let (a, b) = s.split_once('>').unwrap_or((&s, ""));
            Route::new(NetId::new(a), NetId::new(b))
        },
        file_name: r.get(3)?,
        size: r.get::<_, i64>(4)? as u64,
        sha256: r.get(5)?,
        reason: r.get(6)?,
        state: dec(&r.get::<_, String>(7)?)?,
        mode: r.get::<_, Option<String>>(8)?.map(|s| dec(&s)).transpose()?,
        pii: serde_json::from_str(&r.get::<_, String>(9)?).unwrap_or_default(),
        unscannable: r.get(10)?,
        threats: serde_json::from_str(&r.get::<_, String>(25)?).unwrap_or_default(),
        block_reason: r.get(11)?,
        sender_ip: r.get(12)?,
        receiver_ip: r.get(13)?,
        created_at: r.get(14)?,
        approval,
    })
}

impl Core {
    pub fn transfer_info(&self, id: i64) -> Result<TransferInfo, ApiError> {
        self.db.with(|c| c.query_row(&format!("{SELECT_TRANSFER} WHERE t.id=?1"), [id], row_transfer).optional())?.ok_or_else(|| ApiError::new(ErrorCode::NotFound, "전송 건을 찾을 수 없습니다"))
    }

    pub(super) fn transfer_owner(&self, id: i64) -> Result<i64, ApiError> {
        self.db.with(|c| c.query_row("SELECT user_id FROM transfers WHERE id=?1", [id], |r| r.get(0)).optional())?.ok_or_else(|| ApiError::new(ErrorCode::NotFound, "전송 건을 찾을 수 없습니다"))
    }

    pub(super) fn set_state(&self, id: i64, state: TransferState) -> Result<(), ApiError> {
        self.db.with(|c| c.execute("UPDATE transfers SET state=?2 WHERE id=?1", params![id, enc(&state)]).map(|_| ()))
    }

    fn list(&self, where_: &str, uid: i64) -> Result<Vec<TransferInfo>, ApiError> {
        self.db.with(|c| {
            let mut st = c.prepare(&format!("{SELECT_TRANSFER} WHERE {where_} ORDER BY t.id DESC LIMIT 500"))?;
            let v = st.query_map([uid], row_transfer)?.collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(v)
        })
    }

    pub(super) fn create_transfers(&self, c: &Caller, to: &NetId, files: &[FileMeta], reason: &str) -> Result<Vec<i64>, ApiError> {
        if files.is_empty() {
            return Err(ApiError::bad("보낼 파일을 선택하세요"));
        }
        let route = self.user_route(c, to)?;
        let approver: Option<i64> = self.db.with(|db| db.query_row("SELECT approver_id FROM users WHERE id=?1", [c.user_id], |r| r.get(0)))?;
        if approver.is_none() {
            return Err(ApiError::bad("결재자가 지정되지 않았습니다. 관리자에게 결재자 지정을 요청하세요"));
        }
        let mut pending = 0;
        for f in files {
            self.check_file_with(c.user_id, &route, &sanitize_name(&f.name), f.size, pending)?;
            pending += f.size;
        }
        let now = self.clock.now();
        let (from, to) = (route.route.from.as_str(), route.route.to.as_str());
        self.db.tx(|tx| {
            let mut ids = vec![];
            for f in files {
                tx.execute(
                    "INSERT INTO transfers(user_id,direction,from_net,to_net,file_name,size,sha256,reason,state,sender_ip,created_at) VALUES(?1,'',?2,?3,?4,?5,?6,?7,'Uploading',?8,?9)",
                    params![c.user_id, from, to, sanitize_name(&f.name), f.size as i64, f.sha256.to_ascii_lowercase(), reason.trim(), c.ip, now],
                )
                .map_err(ApiError::internal)?;
                ids.push(tx.last_insert_rowid());
            }
            Ok(ids)
        })
    }

    /// Checks who may push or pull bytes of a transfer through the server the caller is connected to.
    pub async fn authorize_file(&self, ctx: &CallCtx, id: i64, op: FileOp) -> Result<FileGrant, ApiError> {
        let c = self.authenticate(ctx).await?;
        let t = self.transfer_info(id)?;
        let owner = self.transfer_owner(id)?;
        let from = t.route.from.clone();
        let forbidden = || ApiError::new(ErrorCode::Forbidden, "이 파일에 접근할 권한이 없습니다");
        let ok = match op {
            FileOp::Upload => owner == c.user_id && t.state == TransferState::Uploading && c.side == from,
            FileOp::Download => {
                let receiver = owner == c.user_id && matches!(t.state, TransferState::Available | TransferState::Downloaded) && c.side == t.route.to;
                // approvers preview a pre-approval file only on the sending network
                let preview = t.state == TransferState::Pending
                    && c.side == from
                    && match &t.approval {
                        Some(a) if a.status == ApprovalStatus::Pending => self.can_decide(c.user_id, a.id)?.is_some(),
                        _ => false,
                    };
                receiver || preview
            }
        };
        if !ok {
            return Err(forbidden());
        }
        Ok(FileGrant { id, name: t.file_name, size: t.size, sha256: t.sha256 })
    }

    pub(super) async fn complete_upload(&self, c: &Caller, id: i64) -> Result<TransferInfo, ApiError> {
        let t = self.transfer_info(id)?;
        if self.transfer_owner(id)? != c.user_id || t.state != TransferState::Uploading || t.route.from != c.side {
            return Err(ApiError::new(ErrorCode::Forbidden, "이 전송 건을 완료할 수 없습니다"));
        }
        // unfinished uploads do not count toward the day, so the limit is checked again here,
        // atomically with reserving this file's share so concurrent completions cannot both pass
        let l = self.effective_limits(c.user_id, &self.route_policy(&t.route)?)?;
        let start = self.kst_day_start();
        self.db.tx(|tx| {
            let used = super::limits::used_since(tx, c.user_id, start, &t.route).map_err(ApiError::internal)?;
            if used + t.size > l.daily_bytes {
                return Err(ApiError::new(
                    ErrorCode::LimitExceeded,
                    format!("{}: 하루 한도({})를 넘습니다. 오늘 남은 양: {}", t.file_name, super::limits::fmt_bytes(l.daily_bytes), super::limits::fmt_bytes(l.daily_bytes.saturating_sub(used))),
                ));
            }
            let n = tx.execute("UPDATE transfers SET reserved=1 WHERE id=?1 AND state='Uploading' AND reserved=0", [id]).map_err(ApiError::internal)?;
            if n == 0 {
                return Err(ApiError::new(ErrorCode::Conflict, "이미 완료 처리 중인 전송입니다"));
            }
            Ok(())
        })?;
        let res = self.finish_upload(c, id, &t).await;
        if res.is_err() {
            let _ = self.db.with(|db| db.execute("UPDATE transfers SET reserved=0 WHERE id=?1 AND state='Uploading'", [id]));
        }
        res
    }

    async fn finish_upload(&self, c: &Caller, id: i64, t: &TransferInfo) -> Result<TransferInfo, ApiError> {
        let global = self.db.policy()?;
        let route = self.route_policy(&t.route)?;
        // the sending network's server scans with this route's PII thresholds
        let policy = Policy { pii_rules: route.effective_pii(&global.pii_rules), ..global };
        let scan: ScanResult = if self.is_local(&c.side) {
            scan_path(&t.file_name, &self.files.path(id), &policy, &self.scanners).map_err(|_| ApiError::bad("올린 파일이 없습니다"))?
        } else {
            self.peer(&c.side)?.scan(id, &t.file_name, &policy).await?
        };
        if scan.size != t.size || scan.sha256 != t.sha256 {
            self.remove_at(&c.side, id).await;
            return Err(ApiError::new(ErrorCode::Conflict, "파일이 올바르게 올라가지 않았습니다. 다시 보내세요"));
        }
        let pii = serde_json::to_string(&scan.hits).map_err(ApiError::internal)?;
        let threats = serde_json::to_string(&scan.threats).map_err(ApiError::internal)?;
        self.db.with(|db| db.execute("UPDATE transfers SET pii=?2, unscannable=?3, threats=?4 WHERE id=?1", params![id, pii, scan.unscannable, threats]))?;
        if let Some((size, sha)) = &scan.cdr {
            // the receiver gets the rebuilt file; its hash is what delivery and download check
            self.db.with(|db| db.execute("UPDATE transfers SET size=?2, sha256=?3 WHERE id=?1", params![id, *size as i64, sha]))?;
            self.audit(Some((c.user_id, &c.username)), "transfer", Some(&c.ip), &format!("#{id} 무해화(CDR) 처리됨"));
        }
        self.audit(Some((c.user_id, &c.username)), "transfer", Some(&c.ip), &format!("#{id} {} {} ({}B)", t.route.label(&self.topo), t.file_name, t.size));
        self.route_transfer(id, &scan).await?;
        self.transfer_info(id)
    }

    pub(super) fn list_outgoing(&self, c: &Caller) -> Result<Vec<TransferInfo>, ApiError> {
        self.list("t.user_id=?1", c.user_id)
    }

    pub(super) fn list_incoming(&self, c: &Caller) -> Result<Vec<TransferInfo>, ApiError> {
        let to = c.side.as_str().replace('\'', "''");
        self.list(&format!("t.user_id=?1 AND t.to_net='{to}' AND t.state IN ('Available','Downloaded')"), c.user_id)
    }

    pub(super) fn mark_downloaded(&self, c: &Caller, id: i64) -> Result<(), ApiError> {
        let t = self.transfer_info(id)?;
        if self.transfer_owner(id)? != c.user_id || t.route.to != c.side || !matches!(t.state, TransferState::Available | TransferState::Downloaded) {
            return Err(ApiError::new(ErrorCode::Forbidden, "받을 수 없는 파일입니다"));
        }
        self.db.with(|db| db.execute("UPDATE transfers SET state='Downloaded', receiver_ip=?2 WHERE id=?1", params![id, c.ip]))?;
        self.audit(Some((c.user_id, &c.username)), "download", Some(&c.ip), &format!("#{id} {} 받음", t.file_name));
        Ok(())
    }
}

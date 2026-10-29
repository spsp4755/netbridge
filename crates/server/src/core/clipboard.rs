use super::{Caller, Core};
use netbridge_proto::*;

impl Core {
    /// Sends clipboard text to the caller's PC on network `to`. No approval; the route's PII rules apply.
    pub(super) async fn clipboard(&self, c: &Caller, to: &NetId, text: &str) -> ApiResult {
        let route = self.user_route(c, to)?;
        let label = route.route.label(&self.topo);
        if !route.clipboard {
            return Err(ApiError::new(ErrorCode::Forbidden, format!("{label} 통로는 클립보드 전송이 허용되지 않습니다")));
        }
        let p = self.db.policy()?;
        let rules = route.effective_pii(&p.pii_rules);
        if text.len() > p.clipboard_max_bytes as usize {
            return Err(ApiError::new(ErrorCode::LimitExceeded, format!("클립보드 한도({}KB)를 넘습니다", p.clipboard_max_bytes / 1024)));
        }
        if text.trim().is_empty() {
            return Err(ApiError::bad("클립보드에 보낼 텍스트가 없습니다"));
        }
        let hits = netbridge_pii::scan_text(text, &rules);
        let masked = netbridge_pii::mask_text(text, &rules);
        let user = Some((c.user_id, c.username.as_str()));
        // Clipboard has no approval step, so "force pre-approval" means block.
        if matches!(netbridge_pii::decide(&hits, false, &rules, route.unscannable()), Some(PiiAction::Block | PiiAction::ForcePre)) {
            let items: Vec<String> = hits.iter().map(|h| format!("{} {}건", h.name, h.count)).collect();
            self.audit(user, "clipboard_blocked", Some(&c.ip), &format!("{} | {}", items.join(", "), clip(&masked)));
            return Err(ApiError::new(ErrorCode::Blocked, format!("개인정보가 있어 보낼 수 없습니다: {}", items.join(", "))));
        }
        let peer = self.devices_of(c.user_id)?.into_iter().find(|(s, _)| s == to);
        let delivered = match peer {
            Some((side, dev)) => self.push(&side, dev, Event::Clipboard { text: text.to_string(), from_ip: c.ip.clone() }).await,
            None => false,
        };
        if !delivered {
            return Err(ApiError::new(ErrorCode::PeerOffline, format!("{} PC가 연결되어 있지 않습니다", self.topo.name(to))));
        }
        self.audit(user, "clipboard", Some(&c.ip), &format!("{label} {}자 | {}", text.chars().count(), clip(&masked)));
        Ok(ApiResponse::Ok)
    }
}

/// Audit rows keep at most 2000 characters of clipboard text.
fn clip(s: &str) -> String {
    let mut out: String = s.chars().take(2000).collect();
    if s.chars().count() > 2000 {
        out.push('…');
    }
    out
}

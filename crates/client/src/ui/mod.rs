pub mod admin;
pub mod approvals;
pub mod delegation;
pub mod history;
pub mod inbox;
pub mod login;
pub mod send;
pub mod settings;
pub mod setup;

pub use crate::theme::*;
use eframe::egui;
use netbridge_proto::*;

pub fn fmt_bytes(b: u64) -> String {
    const K: f64 = 1024.0;
    let f = b as f64;
    if f >= K * K * K {
        format!("{:.2} GB", f / (K * K * K))
    } else if f >= K * K {
        format!("{:.1} MB", f / (K * K))
    } else if f >= K {
        format!("{:.0} KB", f / K)
    } else {
        format!("{b} B")
    }
}

pub fn fmt_ts(ts: i64) -> String {
    let kst = chrono::FixedOffset::east_opt(9 * 3600).unwrap();
    chrono::DateTime::from_timestamp(ts, 0).map(|d| d.with_timezone(&kst).format("%Y-%m-%d %H:%M").to_string()).unwrap_or_default()
}

pub fn state_tone(s: TransferState) -> Tone {
    match s {
        TransferState::Available => Tone::Success,
        TransferState::Downloaded => Tone::Neutral,
        TransferState::Pending | TransferState::Uploading | TransferState::Delivering => Tone::Info,
        TransferState::AwaitingReason => Tone::Warn,
        TransferState::Rejected | TransferState::Blocked => Tone::Danger,
        TransferState::Expired => Tone::Neutral,
    }
}

pub fn state_pill(ui: &mut egui::Ui, s: TransferState) -> egui::Response {
    tone_pill(ui, s.label(), state_tone(s))
}

pub fn pii_summary(hits: &[PiiHit], unscannable: bool) -> String {
    let mut v: Vec<String> = hits.iter().map(|h| format!("{} {}건", h.name, h.count)).collect();
    if unscannable {
        v.push("내용 검사 불가".into());
    }
    if v.is_empty() {
        "-".into()
    } else {
        v.join(", ")
    }
}

pub fn approval_text(a: &Option<ApprovalInfo>) -> String {
    match a {
        None => "-".into(),
        Some(a) => {
            let who = a.decided_by.clone().unwrap_or_else(|| a.approver.clone());
            let proxy = if a.by_proxy { " (대결)" } else { "" };
            let overdue = if a.overdue { " · 기한 초과" } else { "" };
            format!("{} {} · {}{proxy}{overdue}", a.mode.label(), a.status.label(), who)
        }
    }
}

/// Edits a byte count in MB.
pub fn mb_edit(ui: &mut egui::Ui, bytes: &mut u64) -> egui::Response {
    let mut mb = *bytes as f64 / MIB as f64;
    let r = ui.add(egui::DragValue::new(&mut mb).range(0.0..=1_048_576.0).speed(1.0).suffix(" MB"));
    if r.changed() {
        *bytes = (mb * MIB as f64).round() as u64;
    }
    r
}

pub fn error_line(ui: &mut egui::Ui, e: &Option<String>) {
    if let Some(e) = e {
        banner(ui, Tone::Danger, e);
    }
}

/// Comma separated list editor for extensions.
pub fn exts_to_text(v: &[String]) -> String {
    v.join(", ")
}

pub fn text_to_exts(s: &str) -> Vec<String> {
    s.split([',', ' ', ';']).map(|e| e.trim().trim_start_matches('.').to_ascii_lowercase()).filter(|e| !e.is_empty()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn helpers() {
        assert_eq!(fmt_bytes(1536), "2 KB");
        assert_eq!(fmt_bytes(5 * MIB), "5.0 MB");
        assert_eq!(text_to_exts(".EXE, dll;  bat"), vec!["exe", "dll", "bat"]);
        assert_eq!(fmt_ts(1_800_000_000), "2027-01-15 17:00");
    }
}

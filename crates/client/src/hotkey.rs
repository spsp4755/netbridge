use eframe::egui::{Key, Modifiers};
use global_hotkey::hotkey::HotKey;
use std::str::FromStr;

use global_hotkey::{GlobalHotKeyEvent, GlobalHotKeyManager, HotKeyState};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

/// The registered clipboard shortcut.
pub struct Hotkeys {
    mgr: GlobalHotKeyManager,
    current: Option<HotKey>,
    pub id: Arc<AtomicU32>,
}

impl Hotkeys {
    pub fn new() -> Result<Hotkeys, String> {
        let mgr = GlobalHotKeyManager::new().map_err(|e| format!("단축키 기능을 사용할 수 없습니다: {e}"))?;
        Ok(Hotkeys { mgr, current: None, id: Arc::new(AtomicU32::new(0)) })
    }

    /// Registers the new shortcut before releasing the old one, so a failure keeps the old one working.
    pub fn set(&mut self, s: &str) -> Result<(), String> {
        let hk = parse(s)?;
        if self.current == Some(hk) {
            return Ok(());
        }
        self.mgr.register(hk).map_err(|_| "다른 프로그램이 사용 중인 단축키입니다".to_string())?;
        if let Some(old) = self.current.take() {
            let _ = self.mgr.unregister(old);
        }
        self.id.store(hk.id(), Ordering::SeqCst);
        self.current = Some(hk);
        Ok(())
    }

    /// Calls `on_press` (on the event-loop thread) when the current shortcut is pressed, even while the window is hidden.
    pub fn on_press(&self, on_press: impl Fn() + Send + Sync + 'static) {
        let id = self.id.clone();
        GlobalHotKeyEvent::set_event_handler(Some(move |e: GlobalHotKeyEvent| {
            if e.id == id.load(Ordering::SeqCst) && e.state == HotKeyState::Pressed {
                on_press();
            }
        }));
    }
}

/// Parses "Alt+F3" style shortcuts. Plain letters and digits need a modifier so typing is not hijacked.
pub fn parse(s: &str) -> Result<HotKey, String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("단축키를 입력하세요".into());
    }
    let parts: Vec<&str> = s.split('+').map(str::trim).collect();
    let key = parts.last().copied().unwrap_or("");
    let has_mod = parts.len() > 1;
    let is_fkey = key.len() >= 2 && key.starts_with(['F', 'f']) && key[1..].chars().all(|c| c.is_ascii_digit());
    if !has_mod && !is_fkey {
        return Err("Ctrl, Alt, Shift 중 하나와 함께 눌러야 합니다".into());
    }
    HotKey::from_str(s).map_err(|e| format!("단축키 형식 오류: {e}"))
}

/// Shortcut string for an egui key press, in the format `parse` accepts.
pub fn from_egui(m: Modifiers, key: Key) -> Option<String> {
    let name = match key {
        Key::Num0 => "0".to_string(),
        Key::Num1 => "1".into(),
        Key::Num2 => "2".into(),
        Key::Num3 => "3".into(),
        Key::Num4 => "4".into(),
        Key::Num5 => "5".into(),
        Key::Num6 => "6".into(),
        Key::Num7 => "7".into(),
        Key::Num8 => "8".into(),
        Key::Num9 => "9".into(),
        k => {
            let n = k.name();
            let ok = (n.len() == 1 && n.chars().all(|c| c.is_ascii_uppercase())) || (n.starts_with('F') && n[1..].chars().all(|c| c.is_ascii_digit()) && n.len() > 1);
            if !ok {
                return None;
            }
            n.to_string()
        }
    };
    let mut out = vec![];
    if m.ctrl || m.command && !cfg!(target_os = "macos") {
        out.push("Ctrl".to_string());
    }
    if m.alt {
        out.push("Alt".into());
    }
    if m.shift {
        out.push("Shift".into());
    }
    out.push(name);
    Some(out.join("+"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_common_shortcuts() {
        assert!(parse("Alt+F3").is_ok());
        assert!(parse("Ctrl+Shift+V").is_ok());
        assert!(parse("Ctrl+Alt+1").is_ok());
        assert!(parse("Nope").is_err());
        assert!(parse("").is_err());
    }

    #[test]
    fn letters_need_a_modifier() {
        assert!(parse("V").is_err());
        assert!(parse("F9").is_ok());
    }

    #[test]
    fn from_egui_formats_like_parse_expects() {
        let m = eframe::egui::Modifiers { alt: true, ..Default::default() };
        assert_eq!(from_egui(m, eframe::egui::Key::F3).as_deref(), Some("Alt+F3"));
        let m = eframe::egui::Modifiers { ctrl: true, shift: true, ..Default::default() };
        assert_eq!(from_egui(m, eframe::egui::Key::V).as_deref(), Some("Ctrl+Shift+V"));
        assert!(parse(&from_egui(m, eframe::egui::Key::Num1).unwrap()).is_ok());
    }
}

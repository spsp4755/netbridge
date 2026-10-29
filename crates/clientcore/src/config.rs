use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientConfig {
    /// e.g. https://10.0.0.1:8443 — this network's NetBridge server.
    pub server_url: String,
    pub ca_pem_path: PathBuf,
    pub hotkey: String,
    pub download_dir: PathBuf,
    #[serde(default = "yes")]
    pub start_minimized: bool,
    /// Device keys are per user; this picks the key used to wait for pushes before anyone logs in.
    #[serde(default)]
    pub last_user: Option<String>,
    /// Save incoming files to `download_dir` as soon as they are ready, while the app runs.
    #[serde(default = "yes")]
    pub auto_download: bool,
    /// Network the clipboard hotkey sends to (when this PC can reach several).
    #[serde(default)]
    pub clipboard_to: Option<netbridge_proto::NetId>,
}

fn yes() -> bool {
    true
}

pub const DEFAULT_HOTKEY: &str = "Alt+F3";

impl Default for ClientConfig {
    fn default() -> Self {
        ClientConfig {
            server_url: String::new(),
            ca_pem_path: default_ca(),
            hotkey: DEFAULT_HOTKEY.into(),
            download_dir: dirs::download_dir().unwrap_or_else(|| PathBuf::from(".")).join("NetBridge"),
            start_minimized: false,
            last_user: None,
            auto_download: true,
            clipboard_to: None,
        }
    }
}

/// `ca.pem` next to the executable (the installer copies it there).
pub fn default_ca() -> PathBuf {
    std::env::current_exe().ok().and_then(|p| p.parent().map(|d| d.join("ca.pem"))).unwrap_or_else(|| PathBuf::from("ca.pem"))
}

/// Server address deployed by IT next to the executable; when present users cannot change it.
pub const MANAGED_FILE: &str = "server.toml";

#[derive(Deserialize)]
struct Managed {
    server_url: String,
    #[serde(default)]
    ca_pem_path: Option<PathBuf>,
}

/// Folder holding the executable (where the installer puts server.toml and ca.pem).
pub fn exe_dir() -> PathBuf {
    std::env::current_exe().ok().and_then(|p| p.parent().map(|d| d.to_path_buf())).unwrap_or_else(|| PathBuf::from("."))
}

pub fn config_dir() -> PathBuf {
    dirs::config_dir().unwrap_or_else(|| PathBuf::from(".")).join("NetBridge")
}

impl ClientConfig {
    pub fn path() -> PathBuf {
        config_dir().join("config.toml")
    }

    /// Applies `dir/server.toml` if it exists; returns whether the server is managed.
    pub fn apply_managed(&mut self, dir: &std::path::Path) -> bool {
        let Some(m) = std::fs::read_to_string(dir.join(MANAGED_FILE)).ok().and_then(|t| toml::from_str::<Managed>(&t).ok()) else { return false };
        self.server_url = m.server_url.trim().trim_end_matches('/').to_string();
        self.ca_pem_path = match m.ca_pem_path {
            Some(p) if p.is_absolute() => p,
            Some(p) => dir.join(p),
            None => dir.join("ca.pem"),
        };
        true
    }

    /// None on first run.
    pub fn load() -> Option<ClientConfig> {
        let text = std::fs::read_to_string(Self::path()).ok()?;
        toml::from_str(&text).ok()
    }

    pub fn save(&self) -> anyhow::Result<()> {
        std::fs::create_dir_all(config_dir())?;
        std::fs::write(Self::path(), toml::to_string_pretty(self)?)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_defaults() {
        let c = ClientConfig { server_url: "https://1.2.3.4:8443".into(), ..Default::default() };
        let back: ClientConfig = toml::from_str(&toml::to_string(&c).unwrap()).unwrap();
        assert_eq!(back, c);
        assert_eq!(c.hotkey, "Alt+F3");
        // older config files without start_minimized still load
        let old: ClientConfig = toml::from_str("server_url='x'\nca_pem_path='c'\nhotkey='Alt+F3'\ndownload_dir='d'\n").unwrap();
        assert!(old.start_minimized);
        assert!(old.auto_download);
        assert!(c.auto_download);
    }

    #[test]
    fn managed_server_file_overrides_user_settings() {
        let dir = std::env::temp_dir().join(format!("nb-managed-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut c = ClientConfig { server_url: "https://user-typed:1".into(), ..Default::default() };
        assert!(!c.apply_managed(&dir));
        assert_eq!(c.server_url, "https://user-typed:1");
        std::fs::write(dir.join(MANAGED_FILE), "server_url = \"https://10.0.0.10:8443/\"\n").unwrap();
        assert!(c.apply_managed(&dir));
        assert_eq!(c.server_url, "https://10.0.0.10:8443");
        assert_eq!(c.ca_pem_path, dir.join("ca.pem"));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}

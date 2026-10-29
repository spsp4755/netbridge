//! Device key storage. On Windows the key is encrypted with DPAPI for the current user.
use std::path::{Path, PathBuf};

fn key_path(dir: &Path, server_url: &str) -> PathBuf {
    use sha2::Digest;
    let h = hex::encode(&sha2::Sha256::digest(server_url.as_bytes())[..8]);
    dir.join(format!("device-{h}.key"))
}

pub fn store_device_key(dir: &Path, server_url: &str, key: &str) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)?;
    let path = key_path(dir, server_url);
    std::fs::write(&path, protect(key.as_bytes())?)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

pub fn load_device_key(dir: &Path, server_url: &str) -> Option<String> {
    let data = std::fs::read(key_path(dir, server_url)).ok()?;
    String::from_utf8(unprotect(&data).ok()?).ok()
}

pub fn clear_device_key(dir: &Path, server_url: &str) {
    let _ = std::fs::remove_file(key_path(dir, server_url));
}

#[cfg(windows)]
fn protect(data: &[u8]) -> std::io::Result<Vec<u8>> {
    dpapi(data, true)
}

#[cfg(windows)]
fn unprotect(data: &[u8]) -> std::io::Result<Vec<u8>> {
    dpapi(data, false)
}

#[cfg(windows)]
fn dpapi(data: &[u8], encrypt: bool) -> std::io::Result<Vec<u8>> {
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Cryptography::{CryptProtectData, CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB};
    let input = CRYPT_INTEGER_BLOB { cbData: data.len() as u32, pbData: data.as_ptr() as *mut u8 };
    let mut out = CRYPT_INTEGER_BLOB { cbData: 0, pbData: std::ptr::null_mut() };
    // SAFETY: input points to `data` for the call; `out` is allocated by the API and freed with LocalFree.
    let ok = unsafe {
        if encrypt {
            CryptProtectData(&input, std::ptr::null(), std::ptr::null(), std::ptr::null(), std::ptr::null(), CRYPTPROTECT_UI_FORBIDDEN, &mut out)
        } else {
            CryptUnprotectData(&input, std::ptr::null_mut(), std::ptr::null(), std::ptr::null(), std::ptr::null(), CRYPTPROTECT_UI_FORBIDDEN, &mut out)
        }
    };
    if ok == 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: on success `out` holds cbData bytes owned by us.
    let v = unsafe { std::slice::from_raw_parts(out.pbData, out.cbData as usize).to_vec() };
    unsafe { LocalFree(out.pbData as _) };
    Ok(v)
}

// shortcut: non-Windows builds (development only) keep the key in a 0600 file without encryption.
#[cfg(not(windows))]
fn protect(data: &[u8]) -> std::io::Result<Vec<u8>> {
    Ok(data.to_vec())
}

#[cfg(not(windows))]
fn unprotect(data: &[u8]) -> std::io::Result<Vec<u8>> {
    Ok(data.to_vec())
}

/// Key slot for one user of one server (a PC may be shared, each user registers it separately).
pub fn slot(server_url: &str, username: &str) -> String {
    format!("{server_url}#{}", username.trim().to_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slots_are_per_user() {
        let d = tempfile::tempdir().unwrap();
        store_device_key(d.path(), &slot("https://a", "kim"), "k-kim").unwrap();
        store_device_key(d.path(), &slot("https://a", "admin"), "k-admin").unwrap();
        assert_eq!(load_device_key(d.path(), &slot("https://a", "Kim ")).as_deref(), Some("k-kim"));
        assert_eq!(load_device_key(d.path(), &slot("https://a", "admin")).as_deref(), Some("k-admin"));
    }

    #[test]
    fn store_load_clear_per_server() {
        let d = tempfile::tempdir().unwrap();
        store_device_key(d.path(), "https://a", "k1").unwrap();
        store_device_key(d.path(), "https://b", "k2").unwrap();
        assert_eq!(load_device_key(d.path(), "https://a").as_deref(), Some("k1"));
        assert_eq!(load_device_key(d.path(), "https://b").as_deref(), Some("k2"));
        clear_device_key(d.path(), "https://a");
        assert!(load_device_key(d.path(), "https://a").is_none());
    }
}

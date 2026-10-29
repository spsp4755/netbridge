mod api;
mod types;

pub use api::*;
pub use types::*;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn api_request_roundtrip() {
        let req = ApiRequest::Login { username: "a".into(), password: "p".into(), device_key: None };
        let s = serde_json::to_string(&req).unwrap();
        assert!(s.contains(r#""op":"Login""#), "{s}");
        let back: ApiRequest = serde_json::from_str(&s).unwrap();
        assert_eq!(back, req);
    }

    #[test]
    fn policy_default_matches_spec() {
        let p = Policy::default();
        assert_eq!(p.login_fail_lock, 5);
        assert_eq!(p.file_retention_days, 7);
        assert_eq!(p.audit_retention_days, 365);
        assert_eq!(p.post_deadline_days, 3);
        assert_eq!(p.pw_min_len, 9);
        assert!(p.blocked_exts.iter().any(|e| e == "exe"));
    }
}

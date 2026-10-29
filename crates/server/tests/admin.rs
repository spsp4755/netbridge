mod common;
use common::*;
use netbridge_proto::*;

async fn admin(k: &Kit) -> String {
    k.user("root", Role::Admin, None);
    k.login(Side::Internal, "root", None).await.0
}

async fn adm(k: &Kit, side: Side, token: &str, req: AdminRequest) -> ApiResult {
    k.call(side, Some(token), ApiRequest::Admin { req }).await
}

#[tokio::test]
async fn clipboard_pushed_to_peer_and_masked_in_audit() {
    let k = kit();
    k.user("a", Role::User, None);
    let (t, _) = k.login(Side::Internal, "a", None).await;
    let (_, ekey) = k.login(Side::External, "a", None).await;
    let eid = k.device_id(&ekey);
    k.peer.online.lock().unwrap().insert(eid);
    k.call(Side::Internal, Some(&t), ApiRequest::Clipboard { text: "연락처 010-1234-5678".into() }).await.unwrap();
    let pushed = k.pushed_external();
    assert!(pushed.iter().any(|(d, e)| *d == eid && matches!(e, Event::Clipboard { text, from_ip } if text == "연락처 010-1234-5678" && from_ip == "10.2.0.5")));
    let detail: String = k.core.db.with(|c| c.query_row("SELECT detail FROM audit WHERE kind='clipboard'", [], |r| r.get(0))).unwrap();
    assert!(detail.contains("010-1***-****"), "{detail}");
    assert!(!detail.contains("5678"), "{detail}");
}

#[tokio::test]
async fn clipboard_from_external_reaches_internal_hub() {
    let k = kit();
    k.user("a", Role::User, None);
    let (t, _) = k.login(Side::External, "a", None).await;
    let (_, ikey) = k.login(Side::Internal, "a", None).await;
    let mut rx = k.core.hub.register(k.device_id(&ikey));
    k.call(Side::External, Some(&t), ApiRequest::Clipboard { text: "hello".into() }).await.unwrap();
    assert!(matches!(rx.try_recv().unwrap(), Event::Clipboard { text, .. } if text == "hello"));
}

#[tokio::test]
async fn clipboard_peer_offline_errors() {
    let k = kit();
    k.user("a", Role::User, None);
    let (t, _) = k.login(Side::Internal, "a", None).await;
    // no external device registered at all
    assert_eq!(k.call(Side::Internal, Some(&t), ApiRequest::Clipboard { text: "x".into() }).await.unwrap_err().code, ErrorCode::PeerOffline);
    // registered but not connected
    k.login(Side::External, "a", None).await;
    assert_eq!(k.call(Side::Internal, Some(&t), ApiRequest::Clipboard { text: "x".into() }).await.unwrap_err().code, ErrorCode::PeerOffline);
}

#[tokio::test]
async fn clipboard_too_large() {
    let k = kit();
    k.user("a", Role::User, None);
    let (t, _) = k.login(Side::Internal, "a", None).await;
    let text = "a".repeat(100 * 1024 + 1);
    assert_eq!(k.call(Side::Internal, Some(&t), ApiRequest::Clipboard { text }).await.unwrap_err().code, ErrorCode::LimitExceeded);
}

#[tokio::test]
async fn clipboard_force_pre_pii_is_blocked() {
    let k = kit();
    k.user("a", Role::User, None);
    let (t, _) = k.login(Side::External, "a", None).await;
    let (_, ikey) = k.login(Side::Internal, "a", None).await;
    let _rx = k.core.hub.register(k.device_id(&ikey));
    let e = k.call(Side::External, Some(&t), ApiRequest::Clipboard { text: "900101-1234568".into() }).await.unwrap_err();
    assert_eq!(e.code, ErrorCode::Blocked);
    assert!(e.message.contains("주민"), "{}", e.message);
}

#[tokio::test]
async fn admin_forbidden_from_external_side() {
    let k = kit();
    k.user("root", Role::Admin, None);
    let (t, _) = k.login(Side::External, "root", None).await;
    assert_eq!(adm(&k, Side::External, &t, AdminRequest::ListUsers).await.unwrap_err().code, ErrorCode::Forbidden);
}

#[tokio::test]
async fn admin_forbidden_for_user_role() {
    let k = kit();
    k.user("a", Role::User, None);
    let (t, _) = k.login(Side::Internal, "a", None).await;
    assert_eq!(adm(&k, Side::Internal, &t, AdminRequest::ListUsers).await.unwrap_err().code, ErrorCode::Forbidden);
}

#[tokio::test]
async fn admin_manages_users_and_depts() {
    let k = kit();
    let t = admin(&k).await;
    let d = match adm(&k, Side::Internal, &t, AdminRequest::UpsertDept { id: None, name: "개발".into() }).await.unwrap() {
        ApiResponse::Id(id) => id,
        r => panic!("{r:?}"),
    };
    let u = UserInput { id: None, username: "kim".into(), name: "김".into(), dept_id: Some(d), role: Role::User, approver_id: Some(1), password: Some("Init1234!@".into()) };
    let uid = match adm(&k, Side::Internal, &t, AdminRequest::UpsertUser { user: u.clone() }).await.unwrap() {
        ApiResponse::Id(id) => id,
        r => panic!("{r:?}"),
    };
    adm(&k, Side::Internal, &t, AdminRequest::UpsertUser { user: UserInput { id: Some(uid), name: "김철수".into(), password: None, ..u } }).await.unwrap();
    let users = match adm(&k, Side::Internal, &t, AdminRequest::ListUsers).await.unwrap() {
        ApiResponse::Users(v) => v,
        r => panic!("{r:?}"),
    };
    let kim = users.iter().find(|x| x.username == "kim").unwrap();
    assert_eq!((kim.name.as_str(), kim.dept_id, kim.approver_id), ("김철수", Some(d), Some(1)));
    match k.call(Side::Internal, None, ApiRequest::Login { username: "kim".into(), password: "Init1234!@".into(), device_key: None }).await.unwrap() {
        ApiResponse::LoggedIn { me, .. } => assert!(me.must_change_password),
        r => panic!("{r:?}"),
    }
}

#[tokio::test]
async fn reset_password_and_unlock() {
    let k = kit();
    let t = admin(&k).await;
    let a = k.user("a", Role::User, None);
    for _ in 0..5 {
        let _ = k.call(Side::Internal, None, ApiRequest::Login { username: "a".into(), password: "bad".into(), device_key: None }).await;
    }
    adm(&k, Side::Internal, &t, AdminRequest::UnlockUser { user_id: a }).await.unwrap();
    k.login(Side::Internal, "a", None).await;
    adm(&k, Side::Internal, &t, AdminRequest::ResetPassword { user_id: a, new: "Reset123!@".into() }).await.unwrap();
    let r = k.call(Side::External, None, ApiRequest::Login { username: "a".into(), password: "Reset123!@".into(), device_key: None }).await.unwrap();
    match r {
        ApiResponse::LoggedIn { me, .. } => assert!(me.must_change_password),
        r => panic!("{r:?}"),
    }
}

#[tokio::test]
async fn release_device_allows_new_pc() {
    let k = kit();
    let t = admin(&k).await;
    let a = k.user("a", Role::User, None);
    k.login(Side::External, "a", None).await;
    let r = k.call(Side::External, None, ApiRequest::Login { username: "a".into(), password: PW.into(), device_key: None }).await;
    assert_eq!(r.unwrap_err().code, ErrorCode::DeviceMismatch);
    adm(&k, Side::Internal, &t, AdminRequest::ReleaseDevice { user_id: a, side: Side::External }).await.unwrap();
    k.login(Side::External, "a", None).await;
}

#[tokio::test]
async fn kill_session_pushes_session_ended() {
    let k = kit();
    let t = admin(&k).await;
    k.user("a", Role::User, None);
    let (ta, ikey) = k.login(Side::Internal, "a", None).await;
    let mut rx = k.core.hub.register(k.device_id(&ikey));
    let sessions = match adm(&k, Side::Internal, &t, AdminRequest::ListSessions).await.unwrap() {
        ApiResponse::Sessions(v) => v,
        r => panic!("{r:?}"),
    };
    let s = sessions.iter().find(|s| s.username == "a").unwrap();
    assert_eq!(s.online, vec![Side::Internal]);
    adm(&k, Side::Internal, &t, AdminRequest::KillSession { session_id: s.id }).await.unwrap();
    assert!(matches!(rx.try_recv().unwrap(), Event::SessionEnded { .. }));
    assert_eq!(k.call(Side::Internal, Some(&ta), ApiRequest::Me).await.unwrap_err().code, ErrorCode::SessionExpired);
}

#[tokio::test]
async fn audit_query_filters() {
    let k = kit();
    let t = admin(&k).await;
    k.user("a", Role::User, None);
    k.login(Side::Internal, "a", None).await;
    let q = |user: Option<&str>, kind: Option<&str>| AuditQuery { user: user.map(String::from), kind: kind.map(String::from), ..Default::default() };
    let rows = match adm(&k, Side::Internal, &t, AdminRequest::QueryAudit { query: q(Some("a"), Some("login")) }).await.unwrap() {
        ApiResponse::Audit(v) => v,
        r => panic!("{r:?}"),
    };
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].ip.as_deref(), Some("10.2.0.5"));
    let all = match adm(&k, Side::Internal, &t, AdminRequest::QueryAudit { query: q(None, Some("login")) }).await.unwrap() {
        ApiResponse::Audit(v) => v,
        r => panic!("{r:?}"),
    };
    assert_eq!(all.len(), 2);
    let none = match adm(&k, Side::Internal, &t, AdminRequest::QueryAudit { query: AuditQuery { from: Some(k.core.clock.now() + 10), ..Default::default() } }).await.unwrap() {
        ApiResponse::Audit(v) => v,
        r => panic!("{r:?}"),
    };
    assert!(none.is_empty());
}

#[tokio::test]
async fn limit_overrides_and_rules_roundtrip() {
    let k = kit();
    let t = admin(&k).await;
    let a = k.user("a", Role::User, None);
    let l = Limits { daily_bytes: 5, per_file_bytes: 3 };
    adm(&k, Side::Internal, &t, AdminRequest::SetLimitOverride { scope: LimitScope::User(a), limits: Some(l) }).await.unwrap();
    match adm(&k, Side::Internal, &t, AdminRequest::ListLimitOverrides).await.unwrap() {
        ApiResponse::LimitOverrides(v) => assert_eq!(v, vec![LimitOverride { scope: LimitScope::User(a), label: "a 님 (a)".into(), limits: l }]),
        r => panic!("{r:?}"),
    }
    let rules = vec![ApprovalRule { order: 0, direction: None, max_size: None, exts: vec!["TXT".into()], dept_id: None, mode: ApprovalMode::Post }];
    adm(&k, Side::Internal, &t, AdminRequest::SetApprovalRules { rules }).await.unwrap();
    match adm(&k, Side::Internal, &t, AdminRequest::ListApprovalRules).await.unwrap() {
        ApiResponse::ApprovalRules(v) => assert_eq!(v[0].exts, vec!["txt".to_string()]),
        r => panic!("{r:?}"),
    }
}

#[tokio::test]
async fn release_device_disconnects_it_and_ends_session() {
    let k = kit();
    let t = admin(&k).await;
    let a = k.user("a", Role::User, None);
    let (ta, ikey) = k.login(Side::Internal, "a", None).await;
    let (_, ekey) = k.login(Side::External, "a", None).await;
    let idev = k.device_id(&ikey);
    let edev = k.device_id(&ekey);
    let mut rx = k.core.hub.register(idev);
    adm(&k, Side::Internal, &t, AdminRequest::ReleaseDevice { user_id: a, side: Side::Internal }).await.unwrap();
    // the released PC's socket is closed (after any final events)
    let mut closed = false;
    for _ in 0..10 {
        match rx.try_recv() {
            Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => { closed = true; break; }
            _ => {}
        }
    }
    assert!(closed, "hub connection of the released device must be closed");
    assert_eq!(k.call(Side::External, Some(&ta), ApiRequest::Me).await.unwrap_err().code, ErrorCode::SessionExpired);
    adm(&k, Side::Internal, &t, AdminRequest::ReleaseDevice { user_id: a, side: Side::External }).await.unwrap();
    assert_eq!(k.peer.dropped.lock().unwrap().clone(), vec![edev]);
    // a new registration never reuses a released device id
    let (_, nkey) = k.login(Side::Internal, "a", None).await;
    assert_ne!(k.device_id(&nkey), idev);
}

#[tokio::test]
async fn reset_password_ends_existing_sessions() {
    let k = kit();
    let t = admin(&k).await;
    let a = k.user("a", Role::User, None);
    let (ta, ikey) = k.login(Side::Internal, "a", None).await;
    let mut rx = k.core.hub.register(k.device_id(&ikey));
    adm(&k, Side::Internal, &t, AdminRequest::ResetPassword { user_id: a, new: "Reset123!@".into() }).await.unwrap();
    assert!(matches!(rx.try_recv().unwrap(), Event::SessionEnded { .. }));
    assert_eq!(k.call(Side::Internal, Some(&ta), ApiRequest::Me).await.unwrap_err().code, ErrorCode::SessionExpired);
    // the admin's own session is untouched
    assert!(k.call(Side::Internal, Some(&t), ApiRequest::Me).await.is_ok());
}

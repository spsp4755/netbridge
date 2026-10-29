mod common;
use common::*;
use netbridge_proto::*;

#[tokio::test]
async fn login_registers_device_and_returns_key() {
    let k = kit();
    k.user("a", Role::User, None);
    let (token, key) = k.login(Side::External, "a", None).await;
    assert!(!token.is_empty() && key.len() >= 32);
    let d = k.core.device_auth(&key).unwrap();
    assert_eq!(d.side, Side::External);
    assert!(k.core.device_auth("bogus").is_none());
}

#[tokio::test]
async fn second_side_login_reuses_token() {
    let k = kit();
    k.user("a", Role::User, None);
    let (t1, _) = k.login(Side::External, "a", None).await;
    let (t2, _) = k.login(Side::Internal, "a", None).await;
    assert_eq!(t1, t2);
}

#[tokio::test]
async fn peer_device_gets_session_started() {
    let k = kit();
    k.user("a", Role::User, None);
    // internal PC registered earlier, then logged out
    let (t, ikey) = k.login(Side::Internal, "a", None).await;
    k.call(Side::Internal, Some(&t), ApiRequest::Logout).await.unwrap();
    let mut rx = k.core.hub.register(k.device_id(&ikey));
    let (t2, _) = k.login(Side::External, "a", None).await;
    match rx.try_recv().unwrap() {
        Event::SessionStarted { token, me } => {
            assert_eq!(token, t2);
            assert_eq!(me.side, Side::Internal);
        }
        e => panic!("{e:?}"),
    }
}

#[tokio::test]
async fn external_device_gets_session_started_via_peer() {
    let k = kit();
    k.user("a", Role::User, None);
    let (t, ekey) = k.login(Side::External, "a", None).await;
    k.call(Side::External, Some(&t), ApiRequest::Logout).await.unwrap();
    k.login(Side::Internal, "a", None).await;
    let eid = k.device_id(&ekey);
    assert!(k.pushed_external().iter().any(|(d, e)| *d == eid && matches!(e, Event::SessionStarted { .. })));
}

#[tokio::test]
async fn lock_after_five_failures() {
    let k = kit();
    k.user("a", Role::User, None);
    for _ in 0..5 {
        let r = k.call(Side::External, None, ApiRequest::Login { username: "a".into(), password: "wrong".into(), device_key: None }).await;
        assert!(r.is_err());
    }
    let r = k.call(Side::External, None, ApiRequest::Login { username: "a".into(), password: PW.into(), device_key: None }).await;
    assert_eq!(r.unwrap_err().code, ErrorCode::AccountLocked);
}

#[tokio::test]
async fn session_survives_until_logout() {
    let k = kit();
    k.user("a", Role::User, None);
    let (t, _) = k.login(Side::External, "a", None).await;
    k.core.clock.advance(30 * 86400);
    assert!(matches!(k.call(Side::External, Some(&t), ApiRequest::Me).await, Ok(ApiResponse::Me(_))));
}

#[tokio::test]
async fn session_max_minutes_enforced() {
    let k = kit();
    k.user("a", Role::User, None);
    let mut p = k.core.db.policy().unwrap();
    p.session_max_minutes = Some(60);
    k.core.store_policy(&p).unwrap();
    let (t, _) = k.login(Side::External, "a", None).await;
    k.core.clock.advance(61 * 60);
    assert_eq!(k.call(Side::External, Some(&t), ApiRequest::Me).await.unwrap_err().code, ErrorCode::SessionExpired);
}

#[tokio::test]
async fn logout_ends_both_sides() {
    let k = kit();
    k.user("a", Role::User, None);
    let (t, _) = k.login(Side::External, "a", None).await;
    let (_, ikey) = k.login(Side::Internal, "a", None).await;
    let mut rx = k.core.hub.register(k.device_id(&ikey));
    k.call(Side::External, Some(&t), ApiRequest::Logout).await.unwrap();
    assert_eq!(k.call(Side::Internal, Some(&t), ApiRequest::Me).await.unwrap_err().code, ErrorCode::SessionExpired);
    assert!(matches!(rx.try_recv().unwrap(), Event::SessionEnded { .. }));
}

#[tokio::test]
async fn device_mismatch_rejected() {
    let k = kit();
    k.user("a", Role::User, None);
    k.login(Side::External, "a", None).await;
    let r = k.call(Side::External, None, ApiRequest::Login { username: "a".into(), password: PW.into(), device_key: Some("other".into()) }).await;
    assert_eq!(r.unwrap_err().code, ErrorCode::DeviceMismatch);
    let r = k.call(Side::External, None, ApiRequest::Login { username: "a".into(), password: PW.into(), device_key: None }).await;
    assert_eq!(r.unwrap_err().code, ErrorCode::DeviceMismatch);
}

#[tokio::test]
async fn change_password_enforces_policy() {
    let k = kit();
    k.user("a", Role::User, None);
    let (t, _) = k.login(Side::External, "a", None).await;
    let r = k.call(Side::External, Some(&t), ApiRequest::ChangePassword { old: PW.into(), new: "short".into() }).await;
    assert_eq!(r.unwrap_err().code, ErrorCode::BadRequest);
    let r = k.call(Side::External, Some(&t), ApiRequest::ChangePassword { old: PW.into(), new: "alllowercase1".into() }).await;
    assert!(r.is_err());
    k.call(Side::External, Some(&t), ApiRequest::ChangePassword { old: PW.into(), new: "NewPassw0rd#".into() }).await.unwrap();
    assert!(k.call(Side::External, Some(&t), ApiRequest::Unlock { password: "NewPassw0rd#".into() }).await.is_ok());
}

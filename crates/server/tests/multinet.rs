//! Four networks A–D with the central server on B; links A-B, B-C, B-D, C-D.
mod common;
use common::*;
use netbridge_proto::*;

async fn approve_all(k: &Kit4, side: &str, token: &str) {
    let list = match k.call(side, Some(token), ApiRequest::ListApprovals).await.unwrap() {
        ApiResponse::Approvals(v) => v,
        r => panic!("{r:?}"),
    };
    for it in list.into_iter().filter(|i| i.approval.status == ApprovalStatus::Pending) {
        k.call(side, Some(token), ApiRequest::Decide { approval_id: it.approval.id, approve: true, comment: None }).await.unwrap();
    }
}

#[tokio::test]
async fn only_configured_routes_can_be_used() {
    let k = kit4();
    let boss = k.user("boss", None, &[]);
    k.user("u", Some(boss), &[]);
    let t = k.login("A", "u").await.unwrap();
    let e = k.send("A", "C", &t, "x.txt", b"hi").await.unwrap_err();
    assert_eq!(e.code, ErrorCode::Forbidden, "{e:?}");
    assert!(k.send("A", "B", &t, "x.txt", b"hi").await.is_ok());
    let tb = k.login("B", "u").await.unwrap();
    for to in ["A", "C", "D"] {
        assert!(k.send("B", to, &tb, "y.txt", b"hey").await.is_ok(), "B→{to}");
    }
    match k.call("A", Some(&t), ApiRequest::Me).await.unwrap() {
        ApiResponse::Me(me) => assert_eq!(me.routes.iter().map(|r| r.route.to.clone()).collect::<Vec<_>>(), vec![net("B")]),
        r => panic!("{r:?}"),
    }
}

/// C→D never touches the central server: C's node sends straight to D over their own link.
#[tokio::test]
async fn node_to_node_route_is_forwarded_directly() {
    let k = kit4();
    let boss = k.user("boss", None, &[]);
    k.user("u", Some(boss), &[]);
    k.post_rule();
    let t = k.login("C", "u").await.unwrap();
    let sent = k.send("C", "D", &t, "c2d.txt", b"from C").await.unwrap();
    assert_eq!(sent.route, Route::new(net("C"), net("D")));
    assert_eq!(k.core.transfer_info(sent.id).unwrap().state, TransferState::Available);
    assert_eq!(k.peers[&net("D")].files.lock().unwrap().get(&sent.id).map(|b| b.as_slice()), Some(&b"from C"[..]));
    assert!(k.peers[&net("C")].files.lock().unwrap().get(&sent.id).is_none());
    assert_eq!(*k.peers[&net("C")].forwards.lock().unwrap(), vec![(sent.id, net("D"))]);
    assert!(!k.core.files.path(sent.id).exists(), "payload passed through the central server");
    // listed as incoming only on D
    let td = k.login("D", "u").await.unwrap();
    match k.call("D", Some(&td), ApiRequest::ListIncoming).await.unwrap() {
        ApiResponse::Transfers(v) => assert_eq!(v.len(), 1),
        r => panic!("{r:?}"),
    }
}

#[tokio::test]
async fn pre_approved_hub_route_moves_after_decision() {
    let k = kit4();
    let boss = k.user("boss", None, &[]);
    k.user("u", Some(boss), &[]);
    let t = k.login("A", "u").await.unwrap();
    let sent = k.send("A", "B", &t, "a2b.txt", b"from A").await.unwrap();
    assert_eq!(sent.state, TransferState::Pending);
    let tb = k.login("B", "boss").await.unwrap();
    approve_all(&k, "B", &tb).await;
    assert_eq!(k.core.transfer_info(sent.id).unwrap().state, TransferState::Available);
    assert_eq!(std::fs::read(k.core.files.path(sent.id)).unwrap(), b"from A");
}

#[tokio::test]
async fn user_networks_limit_login_and_routes() {
    let k = kit4();
    let boss = k.user("boss", None, &[]);
    k.user("ab", Some(boss), &["A", "B"]);
    assert_eq!(k.login("C", "ab").await.unwrap_err().code, ErrorCode::Forbidden);
    let t = k.login("B", "ab").await.unwrap();
    assert_eq!(k.send("B", "C", &t, "n.txt", b"no").await.unwrap_err().code, ErrorCode::Forbidden);
    assert!(k.send("B", "A", &t, "y.txt", b"ok").await.is_ok());
}

/// One login opens the session on every network the user may use.
#[tokio::test]
async fn login_is_shared_with_all_allowed_networks() {
    let k = kit4();
    k.user("u", None, &[]);
    for side in ["A", "C", "D"] {
        let t = k.login(side, "u").await.unwrap();
        k.call(side, Some(&t), ApiRequest::Logout).await.unwrap();
    }
    for side in ["A", "C", "D"] {
        k.peers[&net(side)].pushed.lock().unwrap().clear();
    }
    k.login("B", "u").await.unwrap();
    for side in ["A", "C", "D"] {
        let pushed = k.peers[&net(side)].pushed.lock().unwrap().clone();
        let me = pushed.iter().find_map(|(_, e)| match e {
            Event::SessionStarted { me, .. } => Some(me.clone()),
            _ => None,
        });
        assert_eq!(me.map(|m| m.side), Some(net(side)), "no session push to {side}");
    }
}

#[tokio::test]
async fn disabled_route_and_clipboard_are_refused() {
    let k = kit4();
    let boss = k.user("boss", None, &[]);
    k.user("u", Some(boss), &[]);
    let mut p = k.core.route_policy(&Route::new(net("B"), net("C"))).unwrap();
    p.enabled = false;
    k.core.set_route_policy(&p).unwrap();
    let mut q = k.core.route_policy(&Route::new(net("B"), net("D"))).unwrap();
    q.clipboard = false;
    k.core.set_route_policy(&q).unwrap();
    let t = k.login("B", "u").await.unwrap();
    assert_eq!(k.send("B", "C", &t, "x.txt", b"x").await.unwrap_err().code, ErrorCode::Forbidden);
    let e = k.call("B", Some(&t), ApiRequest::Clipboard { to: net("D"), text: "hello".into() }).await.unwrap_err();
    assert_eq!(e.code, ErrorCode::Forbidden);
}

/// Each direction of each link has its own daily allowance and limits.
#[tokio::test]
async fn limits_are_per_route_direction() {
    let k = kit4();
    let boss = k.user("boss", None, &[]);
    k.user("u", Some(boss), &[]);
    let mut p = k.core.route_policy(&Route::new(net("A"), net("B"))).unwrap();
    p.limits = Some(Limits { daily_bytes: 10, per_file_bytes: 10 });
    k.core.set_route_policy(&p).unwrap();
    let ta = k.login("A", "u").await.unwrap();
    assert!(k.send("A", "B", &ta, "a.txt", b"12345678").await.is_ok());
    assert_eq!(k.send("A", "B", &ta, "b.txt", b"12345678").await.unwrap_err().code, ErrorCode::LimitExceeded);
    // the reverse direction uses the global default
    let tb = k.login("B", "u").await.unwrap();
    assert!(k.send("B", "A", &tb, "c.txt", b"123456789012345").await.is_ok());
    match k.call("A", Some(&ta), ApiRequest::Usage { to: net("B") }).await.unwrap() {
        ApiResponse::Usage(u) => assert_eq!((u.used_today, u.limits.daily_bytes), (8, 10)),
        r => panic!("{r:?}"),
    }
}

/// Narrowing a user's networks takes effect on open sessions, not only at the next login.
#[tokio::test]
async fn removing_a_network_cuts_open_sessions_there() {
    let k = kit4();
    let boss = k.user("boss", None, &[]);
    let u = k.user("u", Some(boss), &[]);
    let td = k.login("D", "u").await.unwrap();
    assert!(k.call("D", Some(&td), ApiRequest::ListIncoming).await.is_ok());
    let admin = k.core.create_user(&UserInput { id: None, username: "adm".into(), name: "adm".into(), dept_id: None, role: Role::Admin, approver_id: None, password: Some(PW.into()), networks: vec![] }).unwrap();
    k.core.clear_must_change(admin).unwrap();
    let ta = k.login("B", "adm").await.unwrap();
    let input = UserInput { id: Some(u), username: "u".into(), name: "u".into(), dept_id: None, role: Role::User, approver_id: Some(boss), password: None, networks: vec![net("A"), net("B")] };
    k.call("B", Some(&ta), ApiRequest::Admin { req: AdminRequest::UpsertUser { user: input } }).await.unwrap();
    let e = k.call("D", Some(&td), ApiRequest::ListIncoming).await.unwrap_err();
    assert!(matches!(e.code, ErrorCode::Forbidden | ErrorCode::SessionExpired), "{e:?}");
    assert!(k.send("D", "B", &td, "x.txt", b"x").await.is_err());
    // the same token still works on an allowed network
    assert!(k.call("B", Some(&td), ApiRequest::ListIncoming).await.is_ok());
}

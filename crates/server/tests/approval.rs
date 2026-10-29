mod common;
use common::*;
use netbridge_proto::*;
use netbridge_server::core::{pick_mode, FileOp};

fn rule(mode: ApprovalMode) -> ApprovalRule {
    ApprovalRule { order: 0, max_size: None, exts: vec![], dept_id: None, mode }
}

#[test]
fn no_rule_defaults_to_pre() {
    assert_eq!(pick_mode(&[], 1, "txt", None), ApprovalMode::Pre);
}

#[test]
fn first_matching_rule_wins() {
    let rules = vec![
        ApprovalRule { order: 2, max_size: Some(100), ..rule(ApprovalMode::Pre) },
        ApprovalRule { order: 1, exts: vec!["txt".into()], max_size: Some(10), ..rule(ApprovalMode::Post) },
    ];
    assert_eq!(pick_mode(&rules, 5, "txt", None), ApprovalMode::Post);
    assert_eq!(pick_mode(&rules, 50, "txt", None), ApprovalMode::Pre);
}

/// Rules live on each direction of a route: a post-approval rule for 업무망→인터넷망 does not apply the other way.
#[tokio::test]
async fn approval_rules_are_per_route_direction() {
    let k = kit();
    let (ta, _) = k.pair().await;
    k.set_route_rules(Kit::int_ext(), vec![rule(ApprovalMode::Post)]);
    let out = k.send(NetId::internal(), &ta, "o.txt", b"out").await.unwrap();
    assert_eq!(out.mode, Some(ApprovalMode::Post));
    let inn = k.send(NetId::external(), &ta, "i.txt", b"in").await.unwrap();
    assert_eq!(inn.mode, Some(ApprovalMode::Pre));
}

/// 0.3 databases kept one rule list with a direction field; it is copied onto the matching route once.
#[tokio::test]
async fn legacy_direction_rules_migrate_to_routes() {
    let dir = tempfile::tempdir().unwrap();
    let db = netbridge_server::db::Db::open_memory().unwrap();
    db.set_setting("approval_rules", r#"[{"order":0,"direction":"ToExternal","max_size":null,"exts":[],"dept_id":null,"mode":"Post"},{"order":1,"direction":null,"max_size":10,"exts":[],"dept_id":null,"mode":"Post"}]"#).unwrap();
    let core = netbridge_server::core::Core::two_network(db, dir.path().to_path_buf(), std::sync::Arc::new(FakePeer::default())).unwrap();
    assert_eq!(core.route_policy(&Kit::int_ext()).unwrap().approval_rules.len(), 2);
    assert_eq!(core.route_policy(&Kit::ext_in()).unwrap().approval_rules.len(), 1);
}

#[tokio::test]
async fn pre_not_visible_before_approval() {
    let k = kit();
    let (ta, tb) = k.pair().await;
    let t = k.send(NetId::external(), &ta, "a.txt", b"hi").await.unwrap();
    assert_eq!((t.state, t.mode), (TransferState::Pending, Some(ApprovalMode::Pre)));
    assert!(k.incoming(NetId::internal(), &ta).await.is_empty());
    // the file never reached the internal store
    assert!(!k.core.files.path(t.id).exists());
    // receiving side cannot download, sending side approver may preview
    assert!(k.core.authorize_file(&ctx(NetId::internal(), Some(&ta)), t.id, FileOp::Download).await.is_err());
    assert!(k.core.authorize_file(&ctx(NetId::internal(), Some(&tb)), t.id, FileOp::Download).await.is_err());
    assert!(k.core.authorize_file(&ctx(NetId::external(), Some(&tb)), t.id, FileOp::Download).await.is_ok());
}

#[tokio::test]
async fn pre_approve_delivers() {
    let k = kit();
    let (ta, tb) = k.pair().await;
    let t = k.send(NetId::external(), &ta, "a.txt", b"hi").await.unwrap();
    let items = k.approvals(NetId::internal(), &tb).await;
    assert_eq!(items.len(), 1);
    assert!(!items[0].as_proxy);
    k.call(NetId::internal(), Some(&tb), ApiRequest::Decide { approval_id: items[0].approval.id, approve: true, comment: None }).await.unwrap();
    let inc = k.incoming(NetId::internal(), &ta).await;
    assert_eq!(inc.len(), 1);
    assert_eq!(inc[0].approval.as_ref().unwrap().status, ApprovalStatus::Approved);
    assert_eq!(std::fs::read(k.core.files.path(t.id)).unwrap(), b"hi");
    assert!(k.core.authorize_file(&ctx(NetId::internal(), Some(&ta)), t.id, FileOp::Download).await.is_ok());
}

#[tokio::test]
async fn internal_to_external_delivery_pushes_file() {
    let k = kit();
    let (ta, tb) = k.pair().await;
    let t = k.send(NetId::internal(), &ta, "b.txt", b"yo").await.unwrap();
    assert_eq!(t.route, Kit::int_ext());
    let id = k.approvals(NetId::internal(), &tb).await[0].approval.id;
    k.call(NetId::external(), Some(&tb), ApiRequest::Decide { approval_id: id, approve: true, comment: None }).await.unwrap();
    assert_eq!(k.peer.files.lock().unwrap().get(&t.id).unwrap(), b"yo");
    assert_eq!(k.incoming(NetId::external(), &ta).await.len(), 1);
}

#[tokio::test]
async fn pre_reject_deletes_file() {
    let k = kit();
    let (ta, tb) = k.pair().await;
    let t = k.send(NetId::external(), &ta, "a.txt", b"hi").await.unwrap();
    let id = k.approvals(NetId::internal(), &tb).await[0].approval.id;
    k.call(NetId::internal(), Some(&tb), ApiRequest::Decide { approval_id: id, approve: false, comment: Some("불필요".into()) }).await.unwrap();
    assert!(k.peer.files.lock().unwrap().get(&t.id).is_none());
    let out = match k.call(NetId::external(), Some(&ta), ApiRequest::ListOutgoing).await.unwrap() {
        ApiResponse::Transfers(v) => v,
        r => panic!("{r:?}"),
    };
    assert_eq!(out[0].state, TransferState::Rejected);
    assert_eq!(out[0].approval.as_ref().unwrap().comment.as_deref(), Some("불필요"));
}

#[tokio::test]
async fn post_delivers_immediately_and_queues_approval() {
    let k = kit();
    let (ta, tb) = k.pair().await;
    k.set_rules(vec![rule(ApprovalMode::Post)]);
    let t = k.send(NetId::external(), &ta, "a.txt", b"hi").await.unwrap();
    assert_eq!((t.state, t.mode), (TransferState::Available, Some(ApprovalMode::Post)));
    assert_eq!(k.incoming(NetId::internal(), &ta).await.len(), 1);
    let items = k.approvals(NetId::internal(), &tb).await;
    assert_eq!(items[0].approval.status, ApprovalStatus::Pending);
    assert_eq!(items[0].approval.mode, ApprovalMode::Post);
}

#[tokio::test]
async fn post_overdue_restricts_user_to_pre() {
    let k = kit();
    let (ta, tb) = k.pair().await;
    k.set_rules(vec![rule(ApprovalMode::Post)]);
    k.send(NetId::external(), &ta, "a.txt", b"hi").await.unwrap();
    k.core.clock.advance(4 * 86400);
    k.core.sweep().await;
    let t2 = k.send(NetId::external(), &ta, "b.txt", b"hi").await.unwrap();
    assert_eq!(t2.mode, Some(ApprovalMode::Pre));
    // approving the overdue one lifts the restriction
    let overdue = k.approvals(NetId::internal(), &tb).await.into_iter().find(|i| i.approval.mode == ApprovalMode::Post).unwrap();
    assert!(overdue.approval.overdue);
    k.call(NetId::internal(), Some(&tb), ApiRequest::Decide { approval_id: overdue.approval.id, approve: true, comment: None }).await.unwrap();
    let t3 = k.send(NetId::external(), &ta, "c.txt", b"hi").await.unwrap();
    assert_eq!(t3.mode, Some(ApprovalMode::Post));
}

#[tokio::test]
async fn proxy_can_decide_within_period_only() {
    let k = kit();
    let (ta, tb) = k.pair().await;
    k.user("c", Role::User, None);
    let (tc, _) = k.login(NetId::internal(), "c", None).await;
    let today = netbridge_server::core::to_kst(k.core.clock.now()).date_naive();
    k.call(NetId::internal(), Some(&tb), ApiRequest::SetDelegation { proxy_username: "c".into(), from: today, to: today }).await.unwrap();
    k.send(NetId::external(), &ta, "a.txt", b"hi").await.unwrap();
    let items = k.approvals(NetId::internal(), &tc).await;
    assert_eq!(items.len(), 1);
    assert!(items[0].as_proxy);
    // after the period the proxy loses access
    k.core.clock.advance(86400);
    assert!(k.approvals(NetId::internal(), &tc).await.is_empty());
    let e = k.call(NetId::internal(), Some(&tc), ApiRequest::Decide { approval_id: items[0].approval.id, approve: true, comment: None }).await.unwrap_err();
    assert_eq!(e.code, ErrorCode::Forbidden);
    // back inside the period: decision is recorded as proxy
    k.core.clock.advance(-86400);
    k.call(NetId::internal(), Some(&tc), ApiRequest::Decide { approval_id: items[0].approval.id, approve: true, comment: None }).await.unwrap();
    let inc = k.incoming(NetId::internal(), &ta).await;
    let a = inc[0].approval.as_ref().unwrap();
    assert!(a.by_proxy);
    assert_eq!(a.decided_by.as_deref(), Some("c 님"));
}

#[tokio::test]
async fn pii_force_pre_overrides_post_rule() {
    let k = kit();
    let (ta, _) = k.pair().await;
    k.set_rules(vec![rule(ApprovalMode::Post)]);
    let t = k.send_with(NetId::external(), &ta, "a.txt", "주민 900101-1234568".as_bytes(), "고객 요청").await.unwrap();
    assert_eq!((t.state, t.mode), (TransferState::Pending, Some(ApprovalMode::Pre)));
    assert_eq!(t.pii[0].rule_id, "rrn");
}

#[tokio::test]
async fn pii_without_reason_waits_for_reason_before_approval() {
    let k = kit();
    let (ta, tb) = k.pair().await;
    let t = k.send(NetId::external(), &ta, "a.txt", "주민 900101-1234568".as_bytes()).await.unwrap();
    assert_eq!((t.state, t.mode), (TransferState::AwaitingReason, Some(ApprovalMode::Pre)));
    assert!(t.approval.is_none());
    assert!(k.approvals(NetId::internal(), &tb).await.is_empty());
    // an empty reason is refused
    let e = k.call(NetId::external(), Some(&ta), ApiRequest::SubmitForApproval { id: t.id, reason: " ".into() }).await.unwrap_err();
    assert_eq!(e.code, ErrorCode::BadRequest);
    // someone else cannot submit it
    assert_eq!(k.call(NetId::internal(), Some(&tb), ApiRequest::SubmitForApproval { id: t.id, reason: "x".into() }).await.unwrap_err().code, ErrorCode::Forbidden);
    let t2 = match k.call(NetId::external(), Some(&ta), ApiRequest::SubmitForApproval { id: t.id, reason: "고객 제출용".into() }).await.unwrap() {
        ApiResponse::Transfer(t) => t,
        r => panic!("{r:?}"),
    };
    assert_eq!(t2.state, TransferState::Pending);
    assert_eq!(t2.reason, "고객 제출용");
    let items = k.approvals(NetId::internal(), &tb).await;
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].transfer.reason, "고객 제출용");
}

#[tokio::test]
async fn rule_based_pre_needs_no_reason() {
    let k = kit();
    let (ta, tb) = k.pair().await;
    let t = k.send(NetId::external(), &ta, "a.txt", b"hello").await.unwrap();
    assert_eq!(t.state, TransferState::Pending);
    assert_eq!(k.approvals(NetId::internal(), &tb).await.len(), 1);
}

#[tokio::test]
async fn pii_block_blocks() {
    let k = kit();
    let (ta, _) = k.pair().await;
    let mut p = Policy::default();
    p.pii_rules.iter_mut().find(|r| r.id == "card").unwrap().action = PiiAction::Block;
    k.core.store_policy(&p).unwrap();
    let t = k.send(NetId::external(), &ta, "a.txt", b"4111-1111-1111-1111").await.unwrap();
    assert_eq!(t.state, TransferState::Blocked);
    assert!(t.block_reason.unwrap().contains("신용카드"));
    assert!(k.peer.files.lock().unwrap().get(&t.id).is_none());
}

#[tokio::test]
async fn unscannable_uses_policy_action() {
    let k = kit();
    let (ta, _) = k.pair().await;
    k.set_rules(vec![rule(ApprovalMode::Post)]);
    let t = k.send(NetId::external(), &ta, "a.png", b"\x89PNG").await.unwrap();
    assert!(t.unscannable);
    // no personal data was found, so no reason is demanded
    assert_eq!((t.state, t.mode), (TransferState::Pending, Some(ApprovalMode::Pre)));
}

#[tokio::test]
async fn retention_expires_files() {
    let k = kit();
    let (ta, _) = k.pair().await;
    k.set_rules(vec![rule(ApprovalMode::Post)]);
    let t = k.send(NetId::external(), &ta, "a.txt", b"hi").await.unwrap();
    assert!(k.core.files.path(t.id).exists());
    k.core.clock.advance(8 * 86400);
    k.core.sweep().await;
    assert!(!k.core.files.path(t.id).exists());
    let out = match k.call(NetId::external(), Some(&ta), ApiRequest::ListOutgoing).await.unwrap() {
        ApiResponse::Transfers(v) => v,
        r => panic!("{r:?}"),
    };
    assert_eq!(out[0].state, TransferState::Expired);
}

#[tokio::test]
async fn approver_gets_notified() {
    let k = kit();
    let (ta, _) = k.pair().await;
    // b was created first (id 1)
    let b_internal = k.core.devices_of(1).unwrap().into_iter().find(|(s, _)| *s == NetId::internal()).unwrap().1;
    let mut rx = k.core.hub.register(b_internal);
    k.send(NetId::external(), &ta, "a.txt", b"hi").await.unwrap();
    let mut got = false;
    while let Ok(ev) = rx.try_recv() {
        got |= matches!(ev, Event::ApprovalRequested { .. });
    }
    assert!(got);
}

#[tokio::test]
async fn approve_notifies_owner_once() {
    let k = kit();
    let (ta, tb) = k.pair().await;
    let t = k.send(NetId::external(), &ta, "a.txt", b"hi").await.unwrap();
    // a's internal PC (a was created second, id 2)
    let a_internal = k.core.devices_of(2).unwrap().into_iter().find(|(s, _)| *s == NetId::internal()).unwrap().1;
    let mut rx = k.core.hub.register(a_internal);
    let id = k.approvals(NetId::internal(), &tb).await[0].approval.id;
    k.call(NetId::internal(), Some(&tb), ApiRequest::Decide { approval_id: id, approve: true, comment: None }).await.unwrap();
    let mut n = 0;
    while let Ok(ev) = rx.try_recv() {
        if matches!(ev, Event::TransferUpdated { ref transfer } if transfer.id == t.id) {
            n += 1;
        }
    }
    assert_eq!(n, 1);
}

#[tokio::test]
async fn concurrent_deliveries_run_once() {
    let k = kit();
    let (ta, _) = k.pair().await;
    let t = k.send(NetId::external(), &ta, "a.txt", b"hi").await.unwrap();
    k.core.db.with(|c| c.execute("UPDATE approvals SET status='Approved'", [])).unwrap();
    let (a, b) = tokio::join!(k.core.deliver(t.id), k.core.deliver(t.id));
    assert!(a.is_ok() && b.is_ok());
    assert_eq!(k.peer.fetches.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert_eq!(k.incoming(NetId::internal(), &ta).await.len(), 1);
}

#[tokio::test]
async fn approver_and_proxy_cannot_both_decide() {
    let k = kit();
    let (ta, tb) = k.pair().await;
    k.user("c", Role::User, None);
    let (tc, _) = k.login(NetId::internal(), "c", None).await;
    let today = netbridge_server::core::to_kst(k.core.clock.now()).date_naive();
    k.call(NetId::internal(), Some(&tb), ApiRequest::SetDelegation { proxy_username: "c".into(), from: today, to: today }).await.unwrap();
    k.send(NetId::external(), &ta, "a.txt", b"hi").await.unwrap();
    let id = k.approvals(NetId::internal(), &tb).await[0].approval.id;
    let (r1, r2) = tokio::join!(
        k.call(NetId::internal(), Some(&tb), ApiRequest::Decide { approval_id: id, approve: true, comment: None }),
        k.call(NetId::internal(), Some(&tc), ApiRequest::Decide { approval_id: id, approve: false, comment: Some("x".into()) })
    );
    assert!(r1.is_ok() != r2.is_ok(), "exactly one decision wins: {r1:?} {r2:?}");
}

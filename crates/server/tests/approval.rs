mod common;
use common::*;
use netbridge_proto::*;
use netbridge_server::core::{pick_mode, FileOp};

fn rule(mode: ApprovalMode) -> ApprovalRule {
    ApprovalRule { order: 0, direction: None, max_size: None, exts: vec![], dept_id: None, mode }
}

#[test]
fn no_rule_defaults_to_pre() {
    assert_eq!(pick_mode(&[], Direction::ToInternal, 1, "txt", None), ApprovalMode::Pre);
}

#[test]
fn first_matching_rule_wins() {
    let rules = vec![
        ApprovalRule { order: 2, max_size: Some(100), ..rule(ApprovalMode::Pre) },
        ApprovalRule { order: 1, exts: vec!["txt".into()], max_size: Some(10), ..rule(ApprovalMode::Post) },
    ];
    assert_eq!(pick_mode(&rules, Direction::ToInternal, 5, "txt", None), ApprovalMode::Post);
    assert_eq!(pick_mode(&rules, Direction::ToInternal, 50, "txt", None), ApprovalMode::Pre);
    let dir = vec![ApprovalRule { direction: Some(Direction::ToExternal), ..rule(ApprovalMode::Post) }];
    assert_eq!(pick_mode(&dir, Direction::ToInternal, 1, "txt", None), ApprovalMode::Pre);
    assert_eq!(pick_mode(&dir, Direction::ToExternal, 1, "txt", None), ApprovalMode::Post);
}

#[tokio::test]
async fn pre_not_visible_before_approval() {
    let k = kit();
    let (ta, tb) = k.pair().await;
    let t = k.send(Side::External, &ta, "a.txt", b"hi").await.unwrap();
    assert_eq!((t.state, t.mode), (TransferState::Pending, Some(ApprovalMode::Pre)));
    assert!(k.incoming(Side::Internal, &ta).await.is_empty());
    // the file never reached the internal store
    assert!(!k.core.files.path(t.id).exists());
    // receiving side cannot download, sending side approver may preview
    assert!(k.core.authorize_file(&ctx(Side::Internal, Some(&ta)), t.id, FileOp::Download).await.is_err());
    assert!(k.core.authorize_file(&ctx(Side::Internal, Some(&tb)), t.id, FileOp::Download).await.is_err());
    assert!(k.core.authorize_file(&ctx(Side::External, Some(&tb)), t.id, FileOp::Download).await.is_ok());
}

#[tokio::test]
async fn pre_approve_delivers() {
    let k = kit();
    let (ta, tb) = k.pair().await;
    let t = k.send(Side::External, &ta, "a.txt", b"hi").await.unwrap();
    let items = k.approvals(Side::Internal, &tb).await;
    assert_eq!(items.len(), 1);
    assert!(!items[0].as_proxy);
    k.call(Side::Internal, Some(&tb), ApiRequest::Decide { approval_id: items[0].approval.id, approve: true, comment: None }).await.unwrap();
    let inc = k.incoming(Side::Internal, &ta).await;
    assert_eq!(inc.len(), 1);
    assert_eq!(inc[0].approval.as_ref().unwrap().status, ApprovalStatus::Approved);
    assert_eq!(std::fs::read(k.core.files.path(t.id)).unwrap(), b"hi");
    assert!(k.core.authorize_file(&ctx(Side::Internal, Some(&ta)), t.id, FileOp::Download).await.is_ok());
}

#[tokio::test]
async fn internal_to_external_delivery_pushes_file() {
    let k = kit();
    let (ta, tb) = k.pair().await;
    let t = k.send(Side::Internal, &ta, "b.txt", b"yo").await.unwrap();
    assert_eq!(t.direction, Direction::ToExternal);
    let id = k.approvals(Side::Internal, &tb).await[0].approval.id;
    k.call(Side::External, Some(&tb), ApiRequest::Decide { approval_id: id, approve: true, comment: None }).await.unwrap();
    assert_eq!(k.peer.files.lock().unwrap().get(&t.id).unwrap(), b"yo");
    assert_eq!(k.incoming(Side::External, &ta).await.len(), 1);
}

#[tokio::test]
async fn pre_reject_deletes_file() {
    let k = kit();
    let (ta, tb) = k.pair().await;
    let t = k.send(Side::External, &ta, "a.txt", b"hi").await.unwrap();
    let id = k.approvals(Side::Internal, &tb).await[0].approval.id;
    k.call(Side::Internal, Some(&tb), ApiRequest::Decide { approval_id: id, approve: false, comment: Some("불필요".into()) }).await.unwrap();
    assert!(k.peer.files.lock().unwrap().get(&t.id).is_none());
    let out = match k.call(Side::External, Some(&ta), ApiRequest::ListOutgoing).await.unwrap() {
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
    let t = k.send(Side::External, &ta, "a.txt", b"hi").await.unwrap();
    assert_eq!((t.state, t.mode), (TransferState::Available, Some(ApprovalMode::Post)));
    assert_eq!(k.incoming(Side::Internal, &ta).await.len(), 1);
    let items = k.approvals(Side::Internal, &tb).await;
    assert_eq!(items[0].approval.status, ApprovalStatus::Pending);
    assert_eq!(items[0].approval.mode, ApprovalMode::Post);
}

#[tokio::test]
async fn post_overdue_restricts_user_to_pre() {
    let k = kit();
    let (ta, tb) = k.pair().await;
    k.set_rules(vec![rule(ApprovalMode::Post)]);
    k.send(Side::External, &ta, "a.txt", b"hi").await.unwrap();
    k.core.clock.advance(4 * 86400);
    k.core.sweep().await;
    let t2 = k.send(Side::External, &ta, "b.txt", b"hi").await.unwrap();
    assert_eq!(t2.mode, Some(ApprovalMode::Pre));
    // approving the overdue one lifts the restriction
    let overdue = k.approvals(Side::Internal, &tb).await.into_iter().find(|i| i.approval.mode == ApprovalMode::Post).unwrap();
    assert!(overdue.approval.overdue);
    k.call(Side::Internal, Some(&tb), ApiRequest::Decide { approval_id: overdue.approval.id, approve: true, comment: None }).await.unwrap();
    let t3 = k.send(Side::External, &ta, "c.txt", b"hi").await.unwrap();
    assert_eq!(t3.mode, Some(ApprovalMode::Post));
}

#[tokio::test]
async fn proxy_can_decide_within_period_only() {
    let k = kit();
    let (ta, tb) = k.pair().await;
    k.user("c", Role::User, None);
    let (tc, _) = k.login(Side::Internal, "c", None).await;
    let today = netbridge_server::core::to_kst(k.core.clock.now()).date_naive();
    k.call(Side::Internal, Some(&tb), ApiRequest::SetDelegation { proxy_username: "c".into(), from: today, to: today }).await.unwrap();
    k.send(Side::External, &ta, "a.txt", b"hi").await.unwrap();
    let items = k.approvals(Side::Internal, &tc).await;
    assert_eq!(items.len(), 1);
    assert!(items[0].as_proxy);
    // after the period the proxy loses access
    k.core.clock.advance(86400);
    assert!(k.approvals(Side::Internal, &tc).await.is_empty());
    let e = k.call(Side::Internal, Some(&tc), ApiRequest::Decide { approval_id: items[0].approval.id, approve: true, comment: None }).await.unwrap_err();
    assert_eq!(e.code, ErrorCode::Forbidden);
    // back inside the period: decision is recorded as proxy
    k.core.clock.advance(-86400);
    k.call(Side::Internal, Some(&tc), ApiRequest::Decide { approval_id: items[0].approval.id, approve: true, comment: None }).await.unwrap();
    let inc = k.incoming(Side::Internal, &ta).await;
    let a = inc[0].approval.as_ref().unwrap();
    assert!(a.by_proxy);
    assert_eq!(a.decided_by.as_deref(), Some("c 님"));
}

#[tokio::test]
async fn pii_force_pre_overrides_post_rule() {
    let k = kit();
    let (ta, _) = k.pair().await;
    k.set_rules(vec![rule(ApprovalMode::Post)]);
    let t = k.send_with(Side::External, &ta, "a.txt", "주민 900101-1234568".as_bytes(), "고객 요청").await.unwrap();
    assert_eq!((t.state, t.mode), (TransferState::Pending, Some(ApprovalMode::Pre)));
    assert_eq!(t.pii[0].rule_id, "rrn");
}

#[tokio::test]
async fn pii_without_reason_waits_for_reason_before_approval() {
    let k = kit();
    let (ta, tb) = k.pair().await;
    let t = k.send(Side::External, &ta, "a.txt", "주민 900101-1234568".as_bytes()).await.unwrap();
    assert_eq!((t.state, t.mode), (TransferState::AwaitingReason, Some(ApprovalMode::Pre)));
    assert!(t.approval.is_none());
    assert!(k.approvals(Side::Internal, &tb).await.is_empty());
    // an empty reason is refused
    let e = k.call(Side::External, Some(&ta), ApiRequest::SubmitForApproval { id: t.id, reason: " ".into() }).await.unwrap_err();
    assert_eq!(e.code, ErrorCode::BadRequest);
    // someone else cannot submit it
    assert_eq!(k.call(Side::Internal, Some(&tb), ApiRequest::SubmitForApproval { id: t.id, reason: "x".into() }).await.unwrap_err().code, ErrorCode::Forbidden);
    let t2 = match k.call(Side::External, Some(&ta), ApiRequest::SubmitForApproval { id: t.id, reason: "고객 제출용".into() }).await.unwrap() {
        ApiResponse::Transfer(t) => t,
        r => panic!("{r:?}"),
    };
    assert_eq!(t2.state, TransferState::Pending);
    assert_eq!(t2.reason, "고객 제출용");
    let items = k.approvals(Side::Internal, &tb).await;
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].transfer.reason, "고객 제출용");
}

#[tokio::test]
async fn rule_based_pre_needs_no_reason() {
    let k = kit();
    let (ta, tb) = k.pair().await;
    let t = k.send(Side::External, &ta, "a.txt", b"hello").await.unwrap();
    assert_eq!(t.state, TransferState::Pending);
    assert_eq!(k.approvals(Side::Internal, &tb).await.len(), 1);
}

#[tokio::test]
async fn pii_block_blocks() {
    let k = kit();
    let (ta, _) = k.pair().await;
    let mut p = Policy::default();
    p.pii_rules.iter_mut().find(|r| r.id == "card").unwrap().action = PiiAction::Block;
    k.core.store_policy(&p).unwrap();
    let t = k.send(Side::External, &ta, "a.txt", b"4111-1111-1111-1111").await.unwrap();
    assert_eq!(t.state, TransferState::Blocked);
    assert!(t.block_reason.unwrap().contains("신용카드"));
    assert!(k.peer.files.lock().unwrap().get(&t.id).is_none());
}

#[tokio::test]
async fn unscannable_uses_policy_action() {
    let k = kit();
    let (ta, _) = k.pair().await;
    k.set_rules(vec![rule(ApprovalMode::Post)]);
    let t = k.send(Side::External, &ta, "a.png", b"\x89PNG").await.unwrap();
    assert!(t.unscannable);
    // no personal data was found, so no reason is demanded
    assert_eq!((t.state, t.mode), (TransferState::Pending, Some(ApprovalMode::Pre)));
}

#[tokio::test]
async fn retention_expires_files() {
    let k = kit();
    let (ta, _) = k.pair().await;
    k.set_rules(vec![rule(ApprovalMode::Post)]);
    let t = k.send(Side::External, &ta, "a.txt", b"hi").await.unwrap();
    assert!(k.core.files.path(t.id).exists());
    k.core.clock.advance(8 * 86400);
    k.core.sweep().await;
    assert!(!k.core.files.path(t.id).exists());
    let out = match k.call(Side::External, Some(&ta), ApiRequest::ListOutgoing).await.unwrap() {
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
    let b_internal = k.core.devices_of(1).unwrap().into_iter().find(|(s, _)| *s == Side::Internal).unwrap().1;
    let mut rx = k.core.hub.register(b_internal);
    k.send(Side::External, &ta, "a.txt", b"hi").await.unwrap();
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
    let t = k.send(Side::External, &ta, "a.txt", b"hi").await.unwrap();
    // a's internal PC (a was created second, id 2)
    let a_internal = k.core.devices_of(2).unwrap().into_iter().find(|(s, _)| *s == Side::Internal).unwrap().1;
    let mut rx = k.core.hub.register(a_internal);
    let id = k.approvals(Side::Internal, &tb).await[0].approval.id;
    k.call(Side::Internal, Some(&tb), ApiRequest::Decide { approval_id: id, approve: true, comment: None }).await.unwrap();
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
    let t = k.send(Side::External, &ta, "a.txt", b"hi").await.unwrap();
    k.core.db.with(|c| c.execute("UPDATE approvals SET status='Approved'", [])).unwrap();
    let (a, b) = tokio::join!(k.core.deliver(t.id), k.core.deliver(t.id));
    assert!(a.is_ok() && b.is_ok());
    assert_eq!(k.peer.fetches.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert_eq!(k.incoming(Side::Internal, &ta).await.len(), 1);
}

#[tokio::test]
async fn approver_and_proxy_cannot_both_decide() {
    let k = kit();
    let (ta, tb) = k.pair().await;
    k.user("c", Role::User, None);
    let (tc, _) = k.login(Side::Internal, "c", None).await;
    let today = netbridge_server::core::to_kst(k.core.clock.now()).date_naive();
    k.call(Side::Internal, Some(&tb), ApiRequest::SetDelegation { proxy_username: "c".into(), from: today, to: today }).await.unwrap();
    k.send(Side::External, &ta, "a.txt", b"hi").await.unwrap();
    let id = k.approvals(Side::Internal, &tb).await[0].approval.id;
    let (r1, r2) = tokio::join!(
        k.call(Side::Internal, Some(&tb), ApiRequest::Decide { approval_id: id, approve: true, comment: None }),
        k.call(Side::Internal, Some(&tc), ApiRequest::Decide { approval_id: id, approve: false, comment: Some("x".into()) })
    );
    assert!(r1.is_ok() != r2.is_ok(), "exactly one decision wins: {r1:?} {r2:?}");
}

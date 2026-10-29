mod common;
use common::*;
use netbridge_proto::*;

const MB: u64 = 1024 * 1024;

#[tokio::test]
async fn user_override_beats_dept_beats_default() {
    let k = kit();
    let d = k.dept("영업");
    let a = k.user("a", Role::User, None);
    k.core.db.with(|c| c.execute("UPDATE users SET dept_id=?1 WHERE id=?2", [d, a])).unwrap();
    assert_eq!(k.core.effective_limits(a, &k.core.route_policy(&Kit::ext_in()).unwrap()).unwrap(), Policy::default().default_limits);
    let dl = Limits { daily_bytes: 10 * MB, per_file_bytes: 5 * MB };
    k.core.set_limit_override(LimitScope::Dept(d), Some(dl)).unwrap();
    assert_eq!(k.core.effective_limits(a, &k.core.route_policy(&Kit::ext_in()).unwrap()).unwrap(), dl);
    let ul = Limits { daily_bytes: 20 * MB, per_file_bytes: 7 * MB };
    k.core.set_limit_override(LimitScope::User(a), Some(ul)).unwrap();
    assert_eq!(k.core.effective_limits(a, &k.core.route_policy(&Kit::ext_in()).unwrap()).unwrap(), ul);
    k.core.set_limit_override(LimitScope::User(a), None).unwrap();
    assert_eq!(k.core.effective_limits(a, &k.core.route_policy(&Kit::ext_in()).unwrap()).unwrap(), dl);
}

#[tokio::test]
async fn daily_usage_resets_at_kst_midnight() {
    let k = kit();
    let a = k.user("a", Role::User, None);
    // 2027-01-15 14:59Z = 23:59 KST, 15:01Z = 00:01 KST next day
    let before = 1_800_000_000 - 8 * 3600 + 14 * 3600 + 59 * 60; // 2027-01-15T14:59:00Z
    k.insert_transfer(a, 900 * MB, "Available", before);
    k.core.clock.set(before + 30);
    assert_eq!(k.core.used_today(a, &Kit::ext_in()).unwrap(), 900 * MB);
    assert!(k.core.check_file(a, &k.core.route_policy(&Kit::ext_in()).unwrap(), "b.txt", 100 * MB + 1).is_err());
    k.core.clock.set(before + 120);
    assert_eq!(k.core.used_today(a, &Kit::ext_in()).unwrap(), 0);
    k.core.check_file(a, &k.core.route_policy(&Kit::ext_in()).unwrap(), "b.txt", 100 * MB).unwrap();
}

#[tokio::test]
async fn per_file_limit_message_has_numbers() {
    let k = kit();
    let a = k.user("a", Role::User, None);
    let e = k.core.check_file(a, &k.core.route_policy(&Kit::ext_in()).unwrap(), "big.zip", 101 * MB).unwrap_err();
    assert_eq!(e.code, ErrorCode::LimitExceeded);
    assert!(e.message.contains("100"), "{}", e.message);
}

#[tokio::test]
async fn rejected_not_counted() {
    let k = kit();
    let a = k.user("a", Role::User, None);
    let now = k.core.clock.now();
    k.insert_transfer(a, 500 * MB, "Rejected", now);
    k.insert_transfer(a, 300 * MB, "Blocked", now);
    k.insert_transfer(a, 10 * MB, "Pending", now);
    assert_eq!(k.core.used_today(a, &Kit::ext_in()).unwrap(), 10 * MB);
}

#[tokio::test]
async fn allowed_exts_whitelist() {
    let k = kit();
    let a = k.user("a", Role::User, None);
    let mut p = Policy::default();
    p.allowed_exts = vec!["pdf".into()];
    k.core.store_policy(&p).unwrap();
    assert!(k.core.check_file(a, &k.core.route_policy(&Kit::ext_in()).unwrap(), "a.PDF", 1).is_ok());
    assert_eq!(k.core.check_file(a, &k.core.route_policy(&Kit::ext_in()).unwrap(), "a.txt", 1).unwrap_err().code, ErrorCode::Blocked);
}

#[tokio::test]
async fn set_policy_rejects_bad_regex() {
    let k = kit();
    let mut p = Policy::default();
    p.pii_rules.push(PiiRule { id: "x".into(), name: "x".into(), enabled: true, builtin: false, pattern: Some("(".into()), threshold: 1, action: PiiAction::Block });
    assert_eq!(k.core.set_policy(&p, None).await.unwrap_err().code, ErrorCode::BadRequest);
}

#[tokio::test]
async fn set_policy_pushes_and_audits() {
    let k = kit();
    k.user("a", Role::User, None);
    let (_, ikey) = k.login(NetId::internal(), "a", None).await;
    let mut rx = k.core.hub.register(k.device_id(&ikey));
    let mut p = Policy::default();
    p.idle_lock_minutes = Some(10);
    k.core.set_policy(&p, None).await.unwrap();
    assert_eq!(k.core.db.policy().unwrap().idle_lock_minutes, Some(10));
    assert!(matches!(rx.try_recv().unwrap(), Event::PolicyChanged { policy } if policy.idle_lock_minutes == Some(10)));
    let n: i64 = k.core.db.with(|c| c.query_row("SELECT COUNT(*) FROM audit WHERE kind='policy_change'", [], |r| r.get(0))).unwrap();
    assert_eq!(n, 1);
}

#[tokio::test]
async fn concurrent_completes_cannot_both_pass_daily_limit() {
    let k = kit();
    let (ta, _) = k.pair().await;
    let a = k.core.db.with(|c| c.query_row("SELECT id FROM users WHERE username='a'", [], |r| r.get::<_, i64>(0))).unwrap();
    k.core.set_limit_override(LimitScope::User(a), Some(Limits { daily_bytes: 10, per_file_bytes: 10 })).unwrap();
    let mut ids = vec![];
    for body in [b"aaaaaa", b"bbbbbb"] {
        let id = match k.create(NetId::external(), &ta, "f.txt", body).await.unwrap() {
            ApiResponse::Ids(v) => v[0],
            r => panic!("{r:?}"),
        };
        k.peer.files.lock().unwrap().insert(id, body.to_vec());
        ids.push(id);
    }
    let (r1, r2) = tokio::join!(k.call(NetId::external(), Some(&ta), ApiRequest::CompleteUpload { id: ids[0] }), k.call(NetId::external(), Some(&ta), ApiRequest::CompleteUpload { id: ids[1] }),);
    let ok = [&r1, &r2].iter().filter(|r| r.is_ok()).count();
    assert_eq!(ok, 1, "{r1:?} / {r2:?}");
    assert!(k.core.used_today(a, &Kit::ext_in()).unwrap() <= 10);
}

#[tokio::test]
async fn failed_complete_releases_reservation() {
    let k = kit();
    let (ta, _) = k.pair().await;
    let a = k.core.db.with(|c| c.query_row("SELECT id FROM users WHERE username='a'", [], |r| r.get::<_, i64>(0))).unwrap();
    let id = match k.create(NetId::external(), &ta, "f.txt", b"hello").await.unwrap() {
        ApiResponse::Ids(v) => v[0],
        r => panic!("{r:?}"),
    };
    k.peer.files.lock().unwrap().insert(id, b"corrupt".to_vec());
    let e = k.call(NetId::external(), Some(&ta), ApiRequest::CompleteUpload { id }).await.unwrap_err();
    assert_eq!(e.code, ErrorCode::Conflict);
    assert_eq!(k.core.used_today(a, &Kit::ext_in()).unwrap(), 0);
}

/// Daily 10, per file 2: five files of 1.9 sent in one batch all go through (9.5 of 10).
#[tokio::test]
async fn batch_of_large_files_within_daily_limit_is_allowed() {
    let k = kit();
    let b = k.user("b", Role::User, None);
    k.user("a", Role::User, Some(b));
    let (it, _) = k.login(NetId::internal(), "a", None).await;
    let limits = Limits { daily_bytes: 10 * MB, per_file_bytes: 2 * MB };
    let mut p = Policy::default();
    p.default_limits = limits;
    k.core.set_policy(&p, None).await.unwrap();
    let size = 19 * MB / 10;
    let bodies: Vec<Vec<u8>> = (0..5u8).map(|i| vec![b'a' + i; size as usize]).collect();
    let files = bodies.iter().enumerate().map(|(i, b)| FileMeta { name: format!("big{i}.bin"), size, sha256: sha_hex(b) }).collect();
    let ids = match k.call(NetId::internal(), Some(&it), ApiRequest::CreateTransfers { to: other(&NetId::internal()), files, reason: String::new() }).await.unwrap() {
        ApiResponse::Ids(ids) => ids,
        r => panic!("{r:?}"),
    };
    assert_eq!(ids.len(), 5);
    for (id, b) in ids.iter().zip(&bodies) {
        k.core.files.write_at(*id, 0, b).unwrap();
        let r = k.call(NetId::internal(), Some(&it), ApiRequest::CompleteUpload { id: *id }).await;
        assert!(r.is_ok(), "file {id}: {r:?}");
    }
    // a sixth 1.9 file would go over 10
    let extra = vec![b'z'; size as usize];
    let e = k.create(NetId::internal(), &it, "big5.bin", &extra).await.unwrap_err();
    assert_eq!(e.code, ErrorCode::LimitExceeded);
}

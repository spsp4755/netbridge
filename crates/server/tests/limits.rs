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
    assert_eq!(k.core.effective_limits(a).unwrap(), Policy::default().default_limits);
    let dl = Limits { daily_bytes: 10 * MB, per_file_bytes: 5 * MB };
    k.core.set_limit_override(LimitScope::Dept(d), Some(dl)).unwrap();
    assert_eq!(k.core.effective_limits(a).unwrap(), dl);
    let ul = Limits { daily_bytes: 20 * MB, per_file_bytes: 7 * MB };
    k.core.set_limit_override(LimitScope::User(a), Some(ul)).unwrap();
    assert_eq!(k.core.effective_limits(a).unwrap(), ul);
    k.core.set_limit_override(LimitScope::User(a), None).unwrap();
    assert_eq!(k.core.effective_limits(a).unwrap(), dl);
}

#[tokio::test]
async fn daily_usage_resets_at_kst_midnight() {
    let k = kit();
    let a = k.user("a", Role::User, None);
    // 2027-01-15 14:59Z = 23:59 KST, 15:01Z = 00:01 KST next day
    let before = 1_800_000_000 - 8 * 3600 + 14 * 3600 + 59 * 60; // 2027-01-15T14:59:00Z
    k.insert_transfer(a, 900 * MB, "Available", before);
    k.core.clock.set(before + 30);
    assert_eq!(k.core.used_today(a).unwrap(), 900 * MB);
    assert!(k.core.check_file(a, "b.txt", 100 * MB + 1).is_err());
    k.core.clock.set(before + 120);
    assert_eq!(k.core.used_today(a).unwrap(), 0);
    k.core.check_file(a, "b.txt", 100 * MB).unwrap();
}

#[tokio::test]
async fn per_file_limit_message_has_numbers() {
    let k = kit();
    let a = k.user("a", Role::User, None);
    let e = k.core.check_file(a, "big.zip", 101 * MB).unwrap_err();
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
    assert_eq!(k.core.used_today(a).unwrap(), 10 * MB);
}

#[tokio::test]
async fn allowed_exts_whitelist() {
    let k = kit();
    let a = k.user("a", Role::User, None);
    let mut p = Policy::default();
    p.allowed_exts = vec!["pdf".into()];
    k.core.store_policy(&p).unwrap();
    assert!(k.core.check_file(a, "a.PDF", 1).is_ok());
    assert_eq!(k.core.check_file(a, "a.txt", 1).unwrap_err().code, ErrorCode::Blocked);
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
    let (_, ikey) = k.login(Side::Internal, "a", None).await;
    let mut rx = k.core.hub.register(k.device_id(&ikey));
    let mut p = Policy::default();
    p.idle_lock_minutes = Some(10);
    k.core.set_policy(&p, None).await.unwrap();
    assert_eq!(k.core.db.policy().unwrap().idle_lock_minutes, Some(10));
    assert!(matches!(rx.try_recv().unwrap(), Event::PolicyChanged { policy } if policy.idle_lock_minutes == Some(10)));
    let n: i64 = k.core.db.with(|c| c.query_row("SELECT COUNT(*) FROM audit WHERE kind='policy_change'", [], |r| r.get(0))).unwrap();
    assert_eq!(n, 1);
}

mod common;
use common::*;
use netbridge_proto::*;
use netbridge_server::files::WriteError;

#[tokio::test]
async fn resume_upload_after_disconnect() {
    let k = kit();
    let (ta, _) = k.pair().await;
    let data: Vec<u8> = (0..10_000u32).map(|i| (i % 251) as u8).collect();
    let id = match k.create(Side::Internal, &ta, "a.txt", &data).await.unwrap() {
        ApiResponse::Ids(v) => v[0],
        r => panic!("{r:?}"),
    };
    assert_eq!(k.core.files.write_at(id, 0, &data[..4000]).unwrap(), 4000);
    // client restarts from 0 after a disconnect: server reports what it has
    assert!(matches!(k.core.files.write_at(id, 0, &data[..100]), Err(WriteError::Conflict { have: 4000 })));
    k.core.files.write_at(id, 4000, &data[4000..]).unwrap();
    let t = match k.call(Side::Internal, Some(&ta), ApiRequest::CompleteUpload { id }).await.unwrap() {
        ApiResponse::Transfer(t) => t,
        r => panic!("{r:?}"),
    };
    assert_eq!(t.sha256, sha_hex(&data));
    assert_eq!(t.state, TransferState::Pending);
}

#[tokio::test]
async fn hash_mismatch_rejected() {
    let k = kit();
    let (ta, _) = k.pair().await;
    let id = match k.create(Side::Internal, &ta, "a.txt", b"hello").await.unwrap() {
        ApiResponse::Ids(v) => v[0],
        r => panic!("{r:?}"),
    };
    k.core.files.write_at(id, 0, b"hellx").unwrap();
    let e = k.call(Side::Internal, Some(&ta), ApiRequest::CompleteUpload { id }).await.unwrap_err();
    assert_eq!(e.code, ErrorCode::Conflict);
    // the partial file is discarded so the app can upload again from 0
    assert_eq!(k.core.files.len(id), 0);
}

#[tokio::test]
async fn blocked_ext_case_and_double_ext() {
    let k = kit();
    let (ta, _) = k.pair().await;
    assert_eq!(k.create(Side::External, &ta, "A.EXE", b"x").await.unwrap_err().code, ErrorCode::Blocked);
    assert_eq!(k.create(Side::External, &ta, "a.txt.exe", b"x").await.unwrap_err().code, ErrorCode::Blocked);
    assert!(k.create(Side::External, &ta, "a.exe.txt", b"x").await.is_ok());
}

#[tokio::test]
async fn path_traversal_name_is_sanitized() {
    let k = kit();
    let (ta, _) = k.pair().await;
    let t = k.send(Side::External, &ta, "..\\..\\x.txt", b"x").await.unwrap();
    assert_eq!(t.file_name, "x.txt");
    let t = k.send(Side::External, &ta, "../../etc/y.txt", b"x").await.unwrap();
    assert_eq!(t.file_name, "y.txt");
}

#[tokio::test]
async fn reason_is_optional() {
    let k = kit();
    let (ta, _) = k.pair().await;
    let files = vec![FileMeta { name: "a.txt".into(), size: 1, sha256: sha_hex(b"x") }];
    assert!(k.call(Side::External, Some(&ta), ApiRequest::CreateTransfers { files, reason: "  ".into() }).await.is_ok());
}

#[tokio::test]
async fn no_approver_rejected_at_create() {
    let k = kit();
    k.user("solo", Role::User, None);
    let (t, _) = k.login(Side::External, "solo", None).await;
    let e = k.create(Side::External, &t, "a.txt", b"x").await.unwrap_err();
    assert!(e.message.contains("결재자"), "{}", e.message);
}

#[tokio::test]
async fn batch_counts_toward_daily_limit() {
    let k = kit();
    let (ta, _) = k.pair().await;
    let mut p = Policy::default();
    p.default_limits = Limits { daily_bytes: 10, per_file_bytes: 10 };
    k.core.store_policy(&p).unwrap();
    let files = vec![
        FileMeta { name: "a.txt".into(), size: 6, sha256: "x".into() },
        FileMeta { name: "b.txt".into(), size: 6, sha256: "x".into() },
    ];
    let e = k.call(Side::External, Some(&ta), ApiRequest::CreateTransfers { files, reason: "r".into() }).await.unwrap_err();
    assert_eq!(e.code, ErrorCode::LimitExceeded);
}

#[tokio::test]
async fn download_records_receiver_ip() {
    let k = kit();
    let (ta, _) = k.pair().await;
    k.set_rules(vec![ApprovalRule { order: 0, direction: None, max_size: None, exts: vec![], dept_id: None, mode: ApprovalMode::Post }]);
    let t = k.send(Side::External, &ta, "a.txt", b"hi").await.unwrap();
    assert_eq!(t.sender_ip, "10.1.0.5");
    let inc = k.incoming(Side::Internal, &ta).await;
    assert_eq!(inc.len(), 1);
    k.call(Side::Internal, Some(&ta), ApiRequest::MarkDownloaded { id: t.id }).await.unwrap();
    let inc = k.incoming(Side::Internal, &ta).await;
    assert_eq!(inc[0].state, TransferState::Downloaded);
    assert_eq!(inc[0].receiver_ip.as_deref(), Some("10.2.0.5"));
    // the sending side never lists it as incoming
    assert!(k.incoming(Side::External, &ta).await.is_empty());
}

#[tokio::test]
async fn trailing_dots_and_reserved_names_are_sanitized() {
    let k = kit();
    let (ta, _) = k.pair().await;
    assert_eq!(k.create(Side::External, &ta, "evil.exe.", b"x").await.unwrap_err().code, ErrorCode::Blocked);
    assert_eq!(k.create(Side::External, &ta, "evil.exe . .", b"x").await.unwrap_err().code, ErrorCode::Blocked);
    assert_eq!(netbridge_server::core::sanitize_name("CON.txt"), "_CON.txt");
    assert_eq!(netbridge_server::core::sanitize_name("nul"), "_nul");
}

#[tokio::test]
async fn unfinished_upload_does_not_use_daily_limit() {
    let k = kit();
    let (ta, _) = k.pair().await;
    let mut p = Policy::default();
    p.default_limits = Limits { daily_bytes: 10, per_file_bytes: 10 };
    k.core.store_policy(&p).unwrap();
    // an 8-byte upload that never completes
    k.create(Side::Internal, &ta, "x.txt", b"12345678").await.unwrap();
    // two uploads started together each fit on their own
    let ids: Vec<i64> = futures_ids(&k, &ta, &["a.txt", "b.txt"]).await;
    k.core.files.write_at(ids[0], 0, b"12345678").unwrap();
    let t = match k.call(Side::Internal, Some(&ta), ApiRequest::CompleteUpload { id: ids[0] }).await.unwrap() {
        ApiResponse::Transfer(t) => t,
        r => panic!("{r:?}"),
    };
    assert_eq!(t.state, TransferState::Pending);
    // but the second one no longer fits once the first is done
    k.core.files.write_at(ids[1], 0, b"12345678").unwrap();
    let e = k.call(Side::Internal, Some(&ta), ApiRequest::CompleteUpload { id: ids[1] }).await.unwrap_err();
    assert_eq!(e.code, ErrorCode::LimitExceeded);
}

async fn futures_ids(k: &Kit, token: &str, names: &[&str]) -> Vec<i64> {
    let mut out = vec![];
    for n in names {
        match k.create(Side::Internal, token, n, b"12345678").await.unwrap() {
            ApiResponse::Ids(v) => out.push(v[0]),
            r => panic!("{r:?}"),
        }
    }
    out
}

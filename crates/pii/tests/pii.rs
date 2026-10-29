use netbridge_pii::*;
use netbridge_proto::{PiiAction, PiiHit, PiiRule};
use std::io::Write;

fn count(text: &str, id: &str) -> u32 {
    scan_text(text, &builtin_rules()).into_iter().find(|h| h.rule_id == id).map(|h| h.count).unwrap_or(0)
}

#[test]
fn rrn_old_format_detected() {
    assert_eq!(count("주민 900101-1234568", "rrn"), 1);
}

#[test]
fn rrn_new_format_without_checksum_detected() {
    assert_eq!(count("0210153000000", "rrn"), 1);
}

#[test]
fn rrn_invalid_date_not_detected() {
    assert_eq!(count("991399-1234567", "rrn"), 0);
}

#[test]
fn card_luhn() {
    assert_eq!(count("4111-1111-1111-1111", "card"), 1);
    assert_eq!(count("4111-1111-1111-1112", "card"), 0);
}

#[test]
fn phone_and_email() {
    let t = "010-1234-5678 a.b@example.com";
    assert_eq!(count(t, "phone"), 1);
    assert_eq!(count(t, "email"), 1);
    // a phone number must not also count as an account number
    assert_eq!(count(t, "account"), 0);
}

#[test]
fn account_passport_driver() {
    assert_eq!(count("계좌 110-123-456789", "account"), 1);
    assert_eq!(count("여권 M12345678", "passport"), 1);
    assert_eq!(count("면허 11-23-123456-01", "driver"), 1);
}

#[test]
fn threshold_respected() {
    let mut rules = builtin_rules();
    rules.iter_mut().find(|r| r.id == "email").unwrap().threshold = 2;
    let hits = scan_text("a@b.co", &rules);
    assert!(hits.iter().all(|h| h.rule_id != "email"));
}

#[test]
fn disabled_rule_ignored() {
    let mut rules = builtin_rules();
    rules.iter_mut().find(|r| r.id == "email").unwrap().enabled = false;
    assert!(scan_text("a@b.co", &rules).is_empty());
}

#[test]
fn custom_rule() {
    let mut rules = builtin_rules();
    rules.push(PiiRule {
        id: "emp".into(),
        name: "사번".into(),
        enabled: true,
        builtin: false,
        pattern: Some(r"사번\d{6}".into()),
        threshold: 1,
        action: PiiAction::Block,
    });
    let hits = scan_text("사번123456", &rules);
    assert_eq!(hits, vec![PiiHit { rule_id: "emp".into(), name: "사번".into(), count: 1 }]);
    assert!(validate_custom("(").is_err());
}

#[test]
fn mask_rrn() {
    assert_eq!(mask_text("900101-1234568", &builtin_rules()), "900101-1******");
    assert_eq!(mask_text("메일 abc@example.com 끝", &builtin_rules()), "메일 ab*@example.com 끝");
}

#[test]
fn extract_docx() {
    let mut buf = std::io::Cursor::new(Vec::new());
    {
        let mut z = zip::ZipWriter::new(&mut buf);
        z.start_file("word/document.xml", zip::write::SimpleFileOptions::default()).unwrap();
        z.write_all(b"<w:document><w:body><w:p><w:r><w:t>010-1234-5678</w:t></w:r></w:p></w:body></w:document>").unwrap();
        z.finish().unwrap();
    }
    match extract_text("보고서.DOCX", buf.get_ref()) {
        Extracted::Text(t) => assert!(t.contains("010-1234-5678"), "{t}"),
        other => panic!("{other:?}"),
    }
}

#[test]
fn extract_euc_kr_text() {
    let (bytes, _, _) = encoding_rs::EUC_KR.encode("주민 900101-1234568");
    match extract_text("a.csv", &bytes) {
        Extracted::Text(t) => assert!(t.contains("주민"), "{t}"),
        other => panic!("{other:?}"),
    }
}

#[test]
fn extract_unknown_is_unscannable() {
    assert!(matches!(extract_text("a.png", b"\x89PNG"), Extracted::Unscannable(_)));
    assert!(matches!(extract_text("broken.pdf", b"not a pdf"), Extracted::Unscannable(_)));
}

#[test]
fn decide_strongest() {
    let mut rules = builtin_rules();
    rules.iter_mut().find(|r| r.id == "email").unwrap().action = PiiAction::LogOnly;
    rules.iter_mut().find(|r| r.id == "card").unwrap().action = PiiAction::Block;
    let hits = vec![
        PiiHit { rule_id: "email".into(), name: "".into(), count: 1 },
        PiiHit { rule_id: "card".into(), name: "".into(), count: 1 },
    ];
    assert_eq!(decide(&hits, false, &rules, PiiAction::ForcePre), Some(PiiAction::Block));
    assert_eq!(decide(&[], false, &rules, PiiAction::ForcePre), None);
    assert_eq!(decide(&[], true, &rules, PiiAction::ForcePre), Some(PiiAction::ForcePre));
}

#[test]
fn renamed_binary_is_not_read_as_text() {
    // a zip/xlsx renamed to .txt is examined by content, not by name
    let mut buf = std::io::Cursor::new(Vec::new());
    {
        let mut z = zip::ZipWriter::new(&mut buf);
        z.start_file("xl/sharedStrings.xml", zip::write::SimpleFileOptions::default()).unwrap();
        z.write_all(b"<sst><si><t>900101-1234568</t></si></sst>").unwrap();
        z.finish().unwrap();
    }
    match extract_text("list.txt", buf.get_ref()) {
        Extracted::Text(t) => assert!(t.contains("900101-1234568"), "{t}"),
        other => panic!("{other:?}"),
    }
    assert!(matches!(extract_text("a.txt", b"MZ\x90\x00\x03\x00\x00\x00"), Extracted::Unscannable(_)));
    assert!(matches!(extract_text("a.csv", b"%PDF-1.4 broken"), Extracted::Unscannable(_)));
}

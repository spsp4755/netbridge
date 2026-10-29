#![cfg(unix)]
use netbridge_scan::{run_external, ExternalScanner, ThreatKind};
use std::path::PathBuf;

fn file(tag: &str, body: &[u8]) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("nbscan-ext-{}-{tag}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let p = dir.join("in.dat");
    std::fs::write(&p, body).unwrap();
    p
}

fn sh(name: &str, script: &str) -> ExternalScanner {
    ExternalScanner { name: name.into(), command: vec!["sh".into(), "-c".into(), script.into(), "sh".into(), "{file}".into()], timeout_secs: 5, ..Default::default() }
}

#[test]
fn clean_exit_zero_has_no_findings() {
    let p = file("clean", b"x");
    let o = run_external(&p, &[sh("av", "test -f \"$1\"")]);
    assert_eq!(o.findings, vec![]);
    assert!(!o.replaced);
}

#[test]
fn infected_exit_one_reports_first_stdout_line() {
    let p = file("inf", b"x");
    let o = run_external(&p, &[sh("av", "echo 'Eicar-Test FOUND'; echo second; exit 1")]);
    assert_eq!(o.findings.len(), 1);
    assert_eq!(o.findings[0].kind, ThreatKind::AvInfected);
    assert!(o.findings[0].detail.contains("av") && o.findings[0].detail.contains("Eicar-Test FOUND"), "{:?}", o.findings);
    assert!(!o.findings[0].detail.contains("second"));
}

#[test]
fn unlisted_exit_code_is_scanner_error() {
    let p = file("err", b"x");
    let o = run_external(&p, &[sh("av", "exit 2")]);
    assert_eq!(o.findings[0].kind, ThreatKind::ScannerError);
}

#[test]
fn timeout_is_scanner_error() {
    let p = file("to", b"x");
    let mut s = sh("slow", "sleep 10");
    s.timeout_secs = 1;
    let t = std::time::Instant::now();
    let o = run_external(&p, &[s]);
    assert!(t.elapsed().as_secs() < 5);
    assert_eq!(o.findings[0].kind, ThreatKind::ScannerError);
}

#[test]
fn missing_program_is_scanner_error() {
    let p = file("missing", b"x");
    let s = ExternalScanner { name: "none".into(), command: vec!["/no/such/scanner".into(), "{file}".into()], ..Default::default() };
    let o = run_external(&p, &[s]);
    assert_eq!(o.findings[0].kind, ThreatKind::ScannerError);
}

#[test]
fn cdr_replaces_file() {
    let p = file("cdr", b"dirty");
    let s = ExternalScanner { name: "cdr".into(), cdr_command: vec!["sh".into(), "-c".into(), "printf clean > \"$2\"".into(), "sh".into(), "{file}".into(), "{out}".into()], ..Default::default() };
    let o = run_external(&p, &[s]);
    assert_eq!(o.findings, vec![]);
    assert!(o.replaced);
    assert_eq!(std::fs::read(&p).unwrap(), b"clean");
}

#[test]
fn cdr_failure_keeps_file_and_reports_error() {
    let p = file("cdrfail", b"dirty");
    let s = ExternalScanner { name: "cdr".into(), cdr_command: vec!["sh".into(), "-c".into(), "exit 3".into()], ..Default::default() };
    let o = run_external(&p, &[s]);
    assert!(!o.replaced);
    assert_eq!(o.findings[0].kind, ThreatKind::ScannerError);
    assert_eq!(std::fs::read(&p).unwrap(), b"dirty");
}

#[test]
fn deserialize_defaults() {
    let s: ExternalScanner = serde_json::from_str(r#"{"name":"av","command":["scan","{file}"]}"#).unwrap();
    assert_eq!(s.timeout_secs, 30);
    assert!(s.infected_exit_codes.is_empty() && s.cdr_command.is_empty());
}

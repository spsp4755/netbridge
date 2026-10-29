//! 파일 검사: 내장 내용 검사(확장자를 믿지 않음) + 외부 백신/CDR 연동.
//! 조치(차단·사전결재·기록만)는 통로 정책이 정한다. 여기서는 찾기만 한다.

mod archive;
mod external;
mod magic;

pub use external::{run_external, ExternalOutcome, ExternalScanner};

use std::io::{Read, Seek};

pub use netbridge_proto::{Finding, ThreatKind};

/// 스크립트로 보는 확장자(소문자). 실행 파일 확장자는 압축 안 이름 검사에만 쓴다.
pub const SCRIPT_EXTS: &[&str] = &["bat", "cmd", "ps1", "psm1", "vbs", "vbe", "js", "jse", "wsf", "wsh", "hta", "reg", "sh", "lnk"];
pub const EXEC_EXTS: &[&str] = &["exe", "dll", "scr", "com", "msi", "sys", "cpl", "pif"];

/// 압축 중첩 최대 깊이, 항목 수, 풀린 크기 합, 비율, 꺼내 검사할 항목 최대 크기.
pub const MAX_DEPTH: u32 = 3;
pub const MAX_ENTRIES: usize = 10_000;
pub const MAX_TOTAL_BYTES: u64 = 1 << 30;
pub const MAX_RATIO: u64 = 100;
pub const MAX_ENTRY_BYTES: u64 = 64 << 20;
/// PDF·OLE 내용 검색 상한.
pub const SEARCH_CAP: u64 = 64 << 20;

/// 내장 내용 검사. `name`은 원래 파일 이름(확장자 판단용).
pub fn scan_builtin(path: &std::path::Path, name: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    match std::fs::File::open(path) {
        Ok(mut f) => scan_reader(&mut f, name, 0, "", &mut out),
        Err(e) => out.push(Finding { kind: ThreatKind::ScannerError, detail: format!("파일을 열 수 없음: {e}") }),
    }
    let mut uniq: Vec<Finding> = Vec::new();
    for f in out {
        if !uniq.contains(&f) {
            uniq.push(f);
        }
    }
    uniq
}

/// `inner`는 압축 안 경로("" = 최상위). 내부 발견은 "압축 안 {inner}: …"로 적는다.
pub(crate) fn push(out: &mut Vec<Finding>, kind: ThreatKind, inner: &str, msg: &str) {
    let detail = if inner.is_empty() { msg.to_string() } else { format!("압축 안 {inner}: {msg}") };
    out.push(Finding { kind, detail });
}

pub(crate) fn ext_of(name: &str) -> String {
    let base = name.rsplit(['/', '\\']).next().unwrap_or(name);
    base.rsplit_once('.').map(|(_, e)| e.to_ascii_lowercase()).unwrap_or_default()
}

/// `depth` = 이 내용을 감싼 압축 수.
pub(crate) fn scan_reader<R: Read + Seek>(r: &mut R, name: &str, depth: u32, inner: &str, out: &mut Vec<Finding>) {
    if let Err(e) = scan_inner(r, name, depth, inner, out) {
        push(out, ThreatKind::ScannerError, inner, &format!("읽기 오류: {e}"));
    }
}

fn scan_inner<R: Read + Seek>(r: &mut R, name: &str, depth: u32, inner: &str, out: &mut Vec<Finding>) -> std::io::Result<()> {
    let head = magic::read_head(r)?;
    if magic::is_executable(&head, r)? {
        push(out, ThreatKind::Executable, inner, ThreatKind::Executable.label());
    }
    if SCRIPT_EXTS.contains(&ext_of(name).as_str()) || head.starts_with(b"#!") || head.starts_with(magic::LNK) {
        push(out, ThreatKind::Script, inner, ThreatKind::Script.label());
    }
    if head.starts_with(b"PK\x03\x04") {
        if depth >= MAX_DEPTH {
            push(out, ThreatKind::ArchiveDanger, inner, &format!("압축 중첩이 {MAX_DEPTH}단계를 넘음 — 내용 검사 불가"));
        } else {
            archive::scan_zip(r, depth, inner, out);
        }
    } else if head.starts_with(magic::OLE) {
        let names = magic::ole_macro_streams(r)?;
        if !names.is_empty() {
            push(out, ThreatKind::Macro, inner, &format!("{}: {}", ThreatKind::Macro.label(), names.join(", ")));
        }
    } else if head.starts_with(magic::SEVEN_Z) || head.starts_with(magic::RAR) {
        // shortcut: gzip/tar/cab 등 다른 압축 형식은 알아보지 않음, 필요해지면 magic 추가.
        push(out, ThreatKind::ArchiveDanger, inner, "열 수 없는 압축 형식(7z/RAR) — 내용 검사 불가");
    }
    if magic::contains(&head[..head.len().min(1024)], b"%PDF") {
        let names = magic::pdf_active(r)?;
        if !names.is_empty() {
            push(out, ThreatKind::PdfActive, inner, &format!("{}: {}", ThreatKind::PdfActive.label(), names.join(", ")));
        }
    }
    Ok(())
}

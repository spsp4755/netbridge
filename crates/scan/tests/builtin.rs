use netbridge_scan::{scan_builtin, Finding, ThreatKind};
use std::io::Write;
use std::path::PathBuf;

fn tmp(name: &str, bytes: &[u8]) -> PathBuf {
    static N: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("nbscan-{}-{n}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let p = dir.join(name);
    std::fs::write(&p, bytes).unwrap();
    p
}

fn scan(name: &str, bytes: &[u8]) -> Vec<Finding> {
    scan_builtin(&tmp(name, bytes), name)
}

fn kinds(f: &[Finding]) -> Vec<ThreatKind> {
    f.iter().map(|f| f.kind).collect()
}

fn zip_of(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut w = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    let opt = zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);
    for (n, b) in entries {
        w.start_file(*n, opt).unwrap();
        w.write_all(b).unwrap();
    }
    w.finish().unwrap().into_inner()
}

fn pe() -> Vec<u8> {
    let mut b = vec![0u8; 0x100];
    b[0..2].copy_from_slice(b"MZ");
    b[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
    b[0x80..0x84].copy_from_slice(b"PE\0\0");
    b
}

/// OLE 파일: 헤더 512바이트 + 128바이트 디렉터리 항목 하나(이름 UTF-16LE).
fn ole_with_entry(entry: &str) -> Vec<u8> {
    let mut b = vec![0u8; 1024];
    b[0..8].copy_from_slice(&[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1]);
    let name: Vec<u8> = entry.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
    b[512..512 + name.len()].copy_from_slice(&name);
    b[512 + 64..512 + 66].copy_from_slice(&((name.len() as u16) + 2).to_le_bytes());
    b[512 + 66] = 2; // stream
    b
}

const CT_DOCX: &[u8] = br#"<?xml version="1.0"?><Types><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>"#;
const CT_DOCM: &[u8] = br#"<?xml version="1.0"?><Types><Override PartName="/word/document.xml" ContentType="application/vnd.ms-word.document.macroEnabled.main+xml"/></Types>"#;

#[test]
fn clean_txt_and_docx_have_no_findings() {
    assert_eq!(scan("a.txt", b"hello world\n"), vec![]);
    let docx = zip_of(&[("[Content_Types].xml", CT_DOCX), ("word/document.xml", &b"<w:document>hi</w:document>".repeat(50))]);
    assert_eq!(scan("a.docx", &docx), vec![]);
}

#[test]
fn pe_elf_macho_are_executables_regardless_of_name() {
    assert_eq!(kinds(&scan("photo.jpg", &pe())), vec![ThreatKind::Executable]);
    assert_eq!(kinds(&scan("a.dat", b"\x7fELF\x02\x01\x01rest")), vec![ThreatKind::Executable]);
    assert_eq!(kinds(&scan("a.dat", &[0xCF, 0xFA, 0xED, 0xFE, 7, 0, 0, 1])), vec![ThreatKind::Executable]);
    // MZ alone without a PE signature is not an executable
    assert_eq!(scan("a.txt", b"MZ is just text here"), vec![]);
}

#[test]
fn scripts_by_extension_shebang_and_lnk() {
    assert_eq!(kinds(&scan("run.ps1", b"Write-Host hi")), vec![ThreatKind::Script]);
    assert_eq!(kinds(&scan("notes.txt", b"#!/bin/sh\nrm -rf /\n")), vec![ThreatKind::Script]);
    assert_eq!(kinds(&scan("doc.pdf", &[0x4C, 0, 0, 0, 1, 0x14, 2, 0, 0, 0])), vec![ThreatKind::Script]);
}

#[test]
fn ole_vba_and_hwp_scripts_are_macros() {
    assert_eq!(kinds(&scan("a.doc", &ole_with_entry("_VBA_PROJECT"))), vec![ThreatKind::Macro]);
    assert_eq!(kinds(&scan("a.hwp", &ole_with_entry("DefaultJScript"))), vec![ThreatKind::Macro]);
    assert_eq!(scan("a.doc", &ole_with_entry("WordDocument")), vec![]);
}

#[test]
fn ooxml_macros() {
    let with_bin = zip_of(&[("[Content_Types].xml", CT_DOCX), ("word/vbaProject.bin", &ole_with_entry("_VBA_PROJECT"))]);
    assert_eq!(kinds(&scan("a.docx", &with_bin)), vec![ThreatKind::Macro]);
    let docm = zip_of(&[("[Content_Types].xml", CT_DOCM), ("word/document.xml", b"<x/>")]);
    assert_eq!(kinds(&scan("a.docx", &docm)), vec![ThreatKind::Macro]);
    let hwpx = zip_of(&[("mimetype", b"application/hwp+zip"), ("Contents/content.hpf", b"<x/>"), ("Scripts/headerScripts", b"var x;")]);
    assert_eq!(kinds(&scan("a.hwpx", &hwpx)), vec![ThreatKind::Macro]);
}

#[test]
fn pdf_active_found_across_read_boundary() {
    let mut pdf = b"%PDF-1.7\n".to_vec();
    pdf.resize(64 * 1024 - 4, b' ');
    pdf.extend_from_slice(b"/JavaScript (app.alert(1))\n%%EOF");
    let f = scan("a.pdf", &pdf);
    assert_eq!(kinds(&f), vec![ThreatKind::PdfActive]);
    assert!(f[0].detail.contains("/JavaScript"), "{f:?}");
    assert_eq!(scan("b.pdf", b"%PDF-1.7\n1 0 obj << /Type /Catalog >> endobj\n%%EOF"), vec![]);
}

#[test]
fn zip_with_exe_inside_is_flagged_with_inner_path() {
    let z = zip_of(&[("docs/readme.txt", b"hi"), ("run.exe", b"not really pe"), ("tool.bin", &pe())]);
    let f = scan("a.zip", &z);
    assert!(f.contains(&Finding { kind: ThreatKind::Executable, detail: "압축 안 run.exe: 실행 파일".into() }), "{f:?}");
    assert!(f.contains(&Finding { kind: ThreatKind::Executable, detail: "압축 안 tool.bin: 실행 파일".into() }), "{f:?}");
    assert_eq!(f.len(), 2);
}

#[test]
fn nested_zip_findings_carry_full_path() {
    let inner = zip_of(&[("x.vbs", b"MsgBox 1")]);
    let f = scan("outer.zip", &zip_of(&[("in.zip", &inner)]));
    assert_eq!(f, vec![Finding { kind: ThreatKind::Script, detail: "압축 안 in.zip/x.vbs: 스크립트".into() }]);
}

#[test]
fn too_deep_nesting_is_archive_danger() {
    let mut z = zip_of(&[("a.txt", b"hi")]);
    for _ in 0..4 {
        z = zip_of(&[("n.zip", &z)]);
    }
    assert!(kinds(&scan("deep.zip", &z)).contains(&ThreatKind::ArchiveDanger));
    let mut ok = zip_of(&[("a.txt", b"hi")]);
    for _ in 0..2 {
        ok = zip_of(&[("n.zip", &ok)]);
    }
    assert_eq!(scan("ok.zip", &ok), vec![]);
}

#[test]
fn encrypted_entry_flag_is_detected() {
    let mut z = zip_of(&[("secret.txt", b"hello")]);
    // set general purpose bit 0 in the local header and the central directory
    z[6] |= 1;
    let cd = z.windows(4).position(|w| w == b"PK\x01\x02").unwrap();
    z[cd + 8] |= 1;
    assert_eq!(kinds(&scan("a.zip", &z)), vec![ThreatKind::Encrypted]);
}

#[test]
fn zip_bomb_and_traversal_are_archive_danger() {
    let bomb = zip_of(&[("zeros.bin", &vec![0u8; 4 * 1024 * 1024])]);
    let f = scan("bomb.zip", &bomb);
    assert_eq!(kinds(&f), vec![ThreatKind::ArchiveDanger], "{f:?}");
    assert_eq!(kinds(&scan("t.zip", &zip_of(&[("../../evil.txt", b"x")]))), vec![ThreatKind::ArchiveDanger]);
}

#[test]
fn unopenable_archive_formats() {
    let f = scan("a.7z", &[0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C, 0, 4]);
    assert_eq!(f, vec![Finding { kind: ThreatKind::ArchiveDanger, detail: "열 수 없는 압축 형식(7z/RAR) — 내용 검사 불가".into() }]);
    assert_eq!(kinds(&scan("a.bin", b"Rar!\x1a\x07\x01\x00")), vec![ThreatKind::ArchiveDanger]);
}

#[test]
fn labels_and_serde() {
    assert_eq!(ThreatKind::ALL.len(), 8);
    assert_eq!(ThreatKind::Macro.label(), "문서 매크로");
    assert_eq!(ThreatKind::ScannerError.label(), "검사기 오류");
    assert_eq!(serde_json::to_string(&ThreatKind::PdfActive).unwrap(), "\"PdfActive\"");
}

//! zip 안을 다시 검사한다. OOXML·HWPX도 zip이라 여기서 매크로를 본다.

use crate::{ext_of, push, scan_reader, ThreatKind, EXEC_EXTS, MAX_ENTRIES, MAX_ENTRY_BYTES, MAX_RATIO, MAX_TOTAL_BYTES};
use std::io::{Cursor, Read, Seek};

/// 비율 검사는 풀린 크기가 이보다 클 때만 한다(작은 XML은 비율이 커도 무해).
const RATIO_MIN_BYTES: u64 = 1 << 20;

fn escapes(name: &str) -> bool {
    let b = name.as_bytes();
    name.starts_with(['/', '\\']) || (b.len() > 1 && b[1] == b':') || name.split(['/', '\\']).any(|c| c == "..")
}

pub fn scan_zip<R: Read + Seek>(r: &mut R, depth: u32, inner: &str, out: &mut Vec<crate::Finding>) {
    let mut z = match r.rewind().map_err(zip::result::ZipError::from).and_then(|_| zip::ZipArchive::new(&mut *r)) {
        Ok(z) => z,
        Err(e) => return push(out, ThreatKind::ArchiveDanger, inner, &format!("압축을 열 수 없음({e}) — 내용 검사 불가")),
    };
    if z.len() > MAX_ENTRIES {
        return push(out, ThreatKind::ArchiveDanger, inner, &format!("압축 항목 {}개 — {MAX_ENTRIES}개 초과", z.len()));
    }
    let doc = z.index_for_name("[Content_Types].xml").is_some() || z.index_for_name("Contents/content.hpf").is_some();
    if let Ok(f) = z.by_name("[Content_Types].xml") {
        let mut ct = Vec::new();
        if f.take(1 << 20).read_to_end(&mut ct).is_ok() && crate::magic::contains(&ct, b"macroEnabled") {
            push(out, ThreatKind::Macro, inner, "매크로 사용 문서 형식(docm/xlsm/pptm)");
        }
    }
    let mut total = 0u64;
    for i in 0..z.len() {
        let (name, size, csize, encrypted, is_dir) = match z.by_index_raw(i) {
            Ok(f) => (f.name().to_string(), f.size(), f.compressed_size(), f.encrypted(), f.is_dir()),
            Err(e) => {
                push(out, ThreatKind::ArchiveDanger, inner, &format!("손상된 항목({e}) — 내용 검사 불가"));
                continue;
            }
        };
        let path = if inner.is_empty() { name.clone() } else { format!("{inner}/{name}") };
        if escapes(&name) {
            push(out, ThreatKind::ArchiveDanger, &path, "압축 밖을 가리키는 경로");
        }
        if is_dir {
            continue;
        }
        if encrypted {
            push(out, ThreatKind::Encrypted, &path, "암호 걸린 항목");
            continue;
        }
        total = total.saturating_add(size);
        if size > RATIO_MIN_BYTES && size > csize.saturating_mul(MAX_RATIO) {
            push(out, ThreatKind::ArchiveDanger, &path, &format!("압축 비율 {}배 — 압축 폭탄 의심", size / csize.max(1)));
        }
        let lower = name.to_ascii_lowercase();
        if doc && (lower.ends_with("vbaproject.bin") || lower.starts_with("scripts/")) {
            push(out, ThreatKind::Macro, &path, ThreatKind::Macro.label());
            continue;
        }
        if EXEC_EXTS.contains(&ext_of(&name).as_str()) {
            push(out, ThreatKind::Executable, &path, ThreatKind::Executable.label());
        }
        // shortcut: 64 MiB 넘는 항목은 이름만 보고 내용은 건너뜀, 필요하면 임시 파일로 풀어 검사.
        if size > MAX_ENTRY_BYTES {
            continue;
        }
        let mut buf = Vec::new();
        match z.by_index(i).map_err(std::io::Error::from).and_then(|f| f.take(MAX_ENTRY_BYTES).read_to_end(&mut buf)) {
            Ok(_) => scan_reader(&mut Cursor::new(buf), &name, depth + 1, &path, out),
            Err(e) => push(out, ThreatKind::ArchiveDanger, &path, &format!("풀 수 없는 항목({e}) — 내용 검사 불가")),
        }
    }
    if total > MAX_TOTAL_BYTES {
        push(out, ThreatKind::ArchiveDanger, inner, &format!("풀린 크기 합 {} MiB — 1 GiB 초과", total >> 20));
    }
}

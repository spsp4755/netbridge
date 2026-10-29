//! 매직 바이트와 제한된 범위의 내용 검색.

use crate::SEARCH_CAP;
use std::io::{self, Read, Seek, SeekFrom};

pub const LNK: &[u8] = &[0x4C, 0, 0, 0, 0x01, 0x14, 0x02, 0x00];
pub const OLE: &[u8] = &[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];
pub const SEVEN_Z: &[u8] = &[0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C];
pub const RAR: &[u8] = b"Rar!\x1a\x07";
/// Mach-O 32/64(양 엔디언)와 fat. fat(CAFEBABE)은 Java class와 겹치지만 둘 다 실행 코드라 그대로 둔다.
const MACHO: &[[u8; 4]] = &[[0xFE, 0xED, 0xFA, 0xCE], [0xFE, 0xED, 0xFA, 0xCF], [0xCE, 0xFA, 0xED, 0xFE], [0xCF, 0xFA, 0xED, 0xFE], [0xCA, 0xFE, 0xBA, 0xBE]];
/// OLE 디렉터리 항목 이름: VBA(Word/Excel/PowerPoint)와 HWP 스크립트.
// shortcut: 한글이 빈 Scripts 저장소를 기본으로 넣는 파일도 매크로로 잡힘, 오탐이 많으면 DefaultJScript 압축을 풀어 내용 유무 확인.
const OLE_MACRO_NAMES: &[&str] = &["_VBA_PROJECT", "_VBA_PROJECT_CUR", "Macros", "DefaultJScript", "Scripts"];
// shortcut: 이름이 #xx 로 이스케이프되거나 압축된 객체 스트림 안에 있으면 못 찾음, 필요하면 PDF 파서로 교체.
const PDF_NAMES: &[&str] = &["/JavaScript", "/JS", "/Launch", "/EmbeddedFile", "/RichMedia", "/XFA"];
const CHUNK: usize = 64 * 1024;

pub fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

/// 처음부터 최대 4 KiB.
pub fn read_head<R: Read + Seek>(r: &mut R) -> io::Result<Vec<u8>> {
    r.seek(SeekFrom::Start(0))?;
    let mut head = Vec::with_capacity(4096);
    r.take(4096).read_to_end(&mut head)?;
    Ok(head)
}

pub fn is_executable<R: Read + Seek>(head: &[u8], r: &mut R) -> io::Result<bool> {
    if head.starts_with(b"\x7fELF") || MACHO.iter().any(|m| head.starts_with(m)) {
        return Ok(true);
    }
    if !head.starts_with(b"MZ") || head.len() < 0x40 {
        return Ok(false);
    }
    let e_lfanew = u32::from_le_bytes(head[0x3c..0x40].try_into().unwrap()) as u64;
    r.seek(SeekFrom::Start(e_lfanew))?;
    let mut sig = [0u8; 4];
    Ok(r.read_exact(&mut sig).is_ok() && &sig == b"PE\0\0")
}

/// 512바이트부터 128바이트 단위 디렉터리 항목을 훑어 매크로 관련 이름을 찾는다.
/// 섹터 크기(512/4096)가 128의 배수라 항목은 항상 128 경계에 있다. 본문 글자와 헷갈리지 않도록 이름 길이 칸까지 맞춰 본다.
pub fn ole_macro_streams<R: Read + Seek>(r: &mut R) -> io::Result<Vec<&'static str>> {
    r.seek(SeekFrom::Start(512))?;
    let mut r = r.take(SEARCH_CAP);
    let mut found = Vec::new();
    let mut buf = vec![0u8; CHUNK];
    loop {
        let n = read_full(&mut r, &mut buf)?;
        for e in buf[..n].chunks_exact(128) {
            let len = u16::from_le_bytes([e[64], e[65]]) as usize;
            if !(4..=64).contains(&len) || !len.is_multiple_of(2) || !(1..=2).contains(&e[66]) {
                continue;
            }
            let units: Vec<u16> = e[..len - 2].chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
            let name = String::from_utf16_lossy(&units);
            if let Some(m) = OLE_MACRO_NAMES.iter().find(|m| **m == name) {
                if !found.contains(m) {
                    found.push(*m);
                }
            }
        }
        if n < buf.len() {
            return Ok(found);
        }
    }
}

/// PDF 동작 이름을 찾는다. 읽기 경계에 걸친 이름도 찾도록 앞 조각 끝을 겹쳐 둔다.
pub fn pdf_active<R: Read + Seek>(r: &mut R) -> io::Result<Vec<&'static str>> {
    r.seek(SeekFrom::Start(0))?;
    let mut r = r.take(SEARCH_CAP);
    let keep = PDF_NAMES.iter().map(|n| n.len()).max().unwrap() - 1;
    let mut hit = [false; PDF_NAMES.len()];
    let mut win: Vec<u8> = Vec::with_capacity(CHUNK + keep);
    let mut buf = vec![0u8; CHUNK];
    loop {
        let n = r.read(&mut buf)?;
        if n == 0 {
            break;
        }
        win.extend_from_slice(&buf[..n]);
        for (i, name) in PDF_NAMES.iter().enumerate() {
            hit[i] |= contains(&win, name.as_bytes());
        }
        win.drain(..win.len().saturating_sub(keep));
    }
    Ok(PDF_NAMES.iter().zip(hit).filter(|(_, h)| *h).map(|(n, _)| *n).collect())
}

fn read_full<R: Read>(r: &mut R, buf: &mut [u8]) -> io::Result<usize> {
    let mut n = 0;
    while n < buf.len() {
        match r.read(&mut buf[n..])? {
            0 => break,
            k => n += k,
        }
    }
    Ok(n)
}

use quick_xml::events::Event;
use std::io::Read;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Extracted {
    Text(String),
    Unscannable(String),
}

/// Upper bound on decompressed bytes read from an office archive (zip-bomb guard).
const MAX_UNZIPPED: u64 = 256 * 1024 * 1024;

pub fn extract_text(name: &str, bytes: &[u8]) -> Extracted {
    let ext = name.rsplit_once('.').map(|(_, e)| e.to_ascii_lowercase()).unwrap_or_default();
    match ext.as_str() {
        // a renamed binary must not pass as clean text: judge by content
        "txt" | "csv" | "log" | "json" | "xml" | "html" | "htm" | "md" | "tsv" if bytes.starts_with(b"PK\x03\x04") => office(bytes),
        "txt" | "csv" | "log" | "json" | "xml" | "html" | "htm" | "md" | "tsv" if bytes.starts_with(b"%PDF") => pdf(bytes),
        "txt" | "csv" | "log" | "json" | "xml" | "html" | "htm" | "md" | "tsv" if bytes.iter().take(8192).any(|b| *b == 0) => {
            Extracted::Unscannable("텍스트 확장자지만 내용이 텍스트가 아닙니다".into())
        }
        "txt" | "csv" | "log" | "json" | "xml" | "html" | "htm" | "md" | "tsv" => Extracted::Text(decode(bytes)),
        "docx" | "xlsx" | "pptx" | "hwpx" => office(bytes),
        "pdf" => pdf(bytes),
        "" => Extracted::Unscannable("확장자가 없어 검사할 수 없습니다".into()),
        other => Extracted::Unscannable(format!("{other} 형식은 내용을 검사할 수 없습니다")),
    }
}

fn decode(bytes: &[u8]) -> String {
    let b = bytes.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(bytes);
    match std::str::from_utf8(b) {
        Ok(s) => s.to_string(),
        Err(_) => encoding_rs::EUC_KR.decode_without_bom_handling(b).0.into_owned(),
    }
}

fn office(bytes: &[u8]) -> Extracted {
    let mut zip = match zip::ZipArchive::new(std::io::Cursor::new(bytes)) {
        Ok(z) => z,
        Err(_) => return Extracted::Unscannable("문서 파일이 손상되었거나 암호가 걸려 있습니다".into()),
    };
    let mut out = String::new();
    let mut budget = MAX_UNZIPPED;
    for i in 0..zip.len() {
        let Ok(entry) = zip.by_index(i) else { continue };
        if !entry.name().ends_with(".xml") {
            continue;
        }
        let mut xml = Vec::new();
        let read = entry.take(budget + 1).read_to_end(&mut xml);
        if read.is_err() {
            return Extracted::Unscannable("문서 파일을 읽을 수 없습니다".into());
        }
        if xml.len() as u64 > budget {
            return Extracted::Unscannable("압축을 풀면 너무 큰 문서입니다".into());
        }
        budget -= xml.len() as u64;
        let mut reader = quick_xml::Reader::from_reader(xml.as_slice());
        let mut buf = Vec::new();
        loop {
            match reader.read_event_into(&mut buf) {
                Ok(Event::Text(t)) => {
                    if let Ok(s) = t.unescape() {
                        out.push_str(&s);
                        out.push(' ');
                    }
                }
                Ok(Event::End(_)) => out.push(' '),
                Ok(Event::Eof) | Err(_) => break,
                _ => {}
            }
            buf.clear();
        }
    }
    Extracted::Text(out)
}

fn pdf(bytes: &[u8]) -> Extracted {
    // pdf-extract panics on some malformed files.
    let owned = bytes.to_vec();
    match std::panic::catch_unwind(move || pdf_extract::extract_text_from_mem(&owned)) {
        Ok(Ok(t)) => Extracted::Text(t),
        _ => Extracted::Unscannable("PDF 내용을 읽을 수 없습니다".into()),
    }
}

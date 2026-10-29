//! Files handed over by Explorer's "NetBridge로 자료전송": every launched process writes its paths here,
//! and the running window picks them up into the send list.
use std::path::{Path, PathBuf};

/// Writes one batch of paths as a new file in `dir`.
pub fn write(dir: &Path, paths: &[PathBuf]) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)?;
    let text: String = paths.iter().map(|p| format!("{}\n", p.display())).collect();
    // nanosecond name keeps arrival order; written under a temp name so a reader never sees half a batch
    let stamp = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_nanos();
    let name = format!("{stamp:032}-{}", std::process::id());
    let tmp = dir.join(format!("{name}.tmp"));
    std::fs::write(&tmp, text)?;
    std::fs::rename(&tmp, dir.join(format!("{name}.txt")))
}

/// Reads and removes every batch; paths come back once each, in arrival order.
pub fn take(dir: &Path) -> Vec<PathBuf> {
    let Ok(rd) = std::fs::read_dir(dir) else { return vec![] };
    let mut batches: Vec<PathBuf> = rd.filter_map(|e| e.ok()).map(|e| e.path()).filter(|p| p.extension().is_some_and(|x| x == "txt")).collect();
    batches.sort();
    let mut out: Vec<PathBuf> = vec![];
    for b in batches {
        if let Ok(text) = std::fs::read_to_string(&b) {
            for line in text.lines().map(str::trim).filter(|l| !l.is_empty()) {
                let p = PathBuf::from(line);
                if !out.contains(&p) {
                    out.push(p);
                }
            }
        }
        let _ = std::fs::remove_file(&b);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn batches_from_several_launches_are_collected_once() {
        let d = tempfile::tempdir().unwrap();
        let dir = d.path().join("outbox");
        write(&dir, &[PathBuf::from("C:/a.txt")]).unwrap();
        write(&dir, &[PathBuf::from("C:/b.txt"), PathBuf::from("C:/a.txt")]).unwrap();
        let got = take(&dir);
        assert_eq!(got, vec![PathBuf::from("C:/a.txt"), PathBuf::from("C:/b.txt")]);
        assert!(take(&dir).is_empty(), "batches must be removed after reading");
        assert!(take(&d.path().join("missing")).is_empty());
    }
}

use sha2::{Digest, Sha256};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::PathBuf;

/// Transfer payloads on local disk, stored by id only (never by the user's file name).
pub struct Files {
    root: PathBuf,
}

#[derive(Debug, PartialEq, Eq)]
pub enum WriteError {
    /// The client's offset does not match what is stored; resume from `have`.
    Conflict { have: u64 },
    TooLarge,
    Io(String),
}

impl Files {
    pub fn new(root: PathBuf) -> std::io::Result<Files> {
        std::fs::create_dir_all(&root)?;
        Ok(Files { root })
    }

    pub fn path(&self, id: i64) -> PathBuf {
        self.root.join(format!("{id}.bin"))
    }

    pub fn len(&self, id: i64) -> u64 {
        std::fs::metadata(self.path(id)).map(|m| m.len()).unwrap_or(0)
    }

    pub fn write_at(&self, id: i64, offset: u64, bytes: &[u8]) -> Result<u64, WriteError> {
        self.write_at_max(id, offset, bytes, u64::MAX)
    }

    /// Appends at `offset`, which must equal the current length.
    pub fn write_at_max(&self, id: i64, offset: u64, bytes: &[u8], max: u64) -> Result<u64, WriteError> {
        let have = self.len(id);
        if offset != have {
            return Err(WriteError::Conflict { have });
        }
        if have + bytes.len() as u64 > max {
            return Err(WriteError::TooLarge);
        }
        let io = |e: std::io::Error| WriteError::Io(e.to_string());
        let mut f = std::fs::OpenOptions::new().create(true).append(true).open(self.path(id)).map_err(io)?;
        f.write_all(bytes).map_err(io)?;
        f.flush().map_err(io)?;
        Ok(have + bytes.len() as u64)
    }

    pub fn sha256(&self, id: i64) -> std::io::Result<String> {
        let mut f = std::fs::File::open(self.path(id))?;
        let mut h = Sha256::new();
        let mut buf = vec![0u8; 1 << 20];
        loop {
            let n = f.read(&mut buf)?;
            if n == 0 {
                break;
            }
            h.update(&buf[..n]);
        }
        Ok(hex::encode(h.finalize()))
    }

    pub fn read_range(&self, id: i64, start: u64, len: usize) -> std::io::Result<Vec<u8>> {
        let mut f = std::fs::File::open(self.path(id))?;
        f.seek(SeekFrom::Start(start))?;
        let mut buf = vec![0u8; len];
        let n = f.read(&mut buf)?;
        buf.truncate(n);
        Ok(buf)
    }

    pub fn remove(&self, id: i64) {
        let _ = std::fs::remove_file(self.path(id));
    }
}

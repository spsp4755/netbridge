use netbridge_proto::{ApiError, ApprovalRule, Policy};
use rusqlite::{Connection, OptionalExtension};
use std::path::Path;
use std::sync::Mutex;

pub struct Db(Mutex<Connection>);

const SCHEMA: &str = r#"
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS depts(id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE);
CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY, username TEXT NOT NULL UNIQUE, name TEXT NOT NULL,
  dept_id INTEGER REFERENCES depts(id), role TEXT NOT NULL, approver_id INTEGER REFERENCES users(id),
  pw_hash TEXT NOT NULL, pw_changed_at INTEGER NOT NULL, must_change INTEGER NOT NULL DEFAULT 0,
  fail_count INTEGER NOT NULL DEFAULT 0, locked INTEGER NOT NULL DEFAULT 0,
  post_restricted INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS devices(
  id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL REFERENCES users(id), side TEXT NOT NULL,
  key_hash TEXT NOT NULL UNIQUE, created_at INTEGER NOT NULL, UNIQUE(user_id, side));
CREATE TABLE IF NOT EXISTS sessions(
  id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id), token TEXT NOT NULL UNIQUE,
  created_at INTEGER NOT NULL, last_seen INTEGER NOT NULL, ended_at INTEGER, end_reason TEXT);
CREATE TABLE IF NOT EXISTS transfers(
  id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id), direction TEXT NOT NULL,
  file_name TEXT NOT NULL, size INTEGER NOT NULL, sha256 TEXT NOT NULL, reason TEXT NOT NULL,
  state TEXT NOT NULL, mode TEXT, pii TEXT NOT NULL DEFAULT '[]', unscannable INTEGER NOT NULL DEFAULT 0,
  block_reason TEXT, sender_ip TEXT NOT NULL, receiver_ip TEXT, created_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS approvals(
  id INTEGER PRIMARY KEY, transfer_id INTEGER NOT NULL UNIQUE REFERENCES transfers(id), mode TEXT NOT NULL,
  approver_id INTEGER NOT NULL REFERENCES users(id), status TEXT NOT NULL, decided_by INTEGER,
  by_proxy INTEGER NOT NULL DEFAULT 0, comment TEXT, created_at INTEGER NOT NULL, decided_at INTEGER,
  overdue INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS delegations(
  approver_id INTEGER PRIMARY KEY REFERENCES users(id), proxy_id INTEGER NOT NULL REFERENCES users(id),
  from_date TEXT NOT NULL, to_date TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS limit_overrides(
  scope TEXT NOT NULL, scope_id INTEGER NOT NULL, daily_bytes INTEGER NOT NULL, per_file_bytes INTEGER NOT NULL,
  PRIMARY KEY(scope, scope_id));
CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS audit(
  id INTEGER PRIMARY KEY, at INTEGER NOT NULL, user_id INTEGER, username TEXT, kind TEXT NOT NULL,
  ip TEXT, detail TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS audit_at ON audit(at);
CREATE INDEX IF NOT EXISTS transfers_user ON transfers(user_id, created_at);
"#;

impl Db {
    pub fn open(path: &Path) -> anyhow::Result<Db> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let conn = Connection::open(path)?;
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        conn.execute_batch(SCHEMA)?;
        let db = Db(Mutex::new(conn));
        if db.setting("policy")?.is_none() {
            db.set_setting("policy", &serde_json::to_string(&Policy::default())?)?;
        }
        if db.setting("approval_rules")?.is_none() {
            db.set_setting("approval_rules", "[]")?;
        }
        Ok(db)
    }

    pub fn open_memory() -> anyhow::Result<Db> {
        let conn = Connection::open_in_memory()?;
        conn.execute_batch(SCHEMA)?;
        let db = Db(Mutex::new(conn));
        db.set_setting("policy", &serde_json::to_string(&Policy::default())?)?;
        db.set_setting("approval_rules", "[]")?;
        Ok(db)
    }

    /// Runs `f` with the connection; errors become an internal ApiError.
    pub fn with<T>(&self, f: impl FnOnce(&Connection) -> rusqlite::Result<T>) -> Result<T, ApiError> {
        let conn = self.0.lock().unwrap_or_else(|e| e.into_inner());
        f(&conn).map_err(ApiError::internal)
    }

    /// Runs `f` inside a transaction.
    pub fn tx<T>(&self, f: impl FnOnce(&rusqlite::Transaction) -> Result<T, ApiError>) -> Result<T, ApiError> {
        let mut conn = self.0.lock().unwrap_or_else(|e| e.into_inner());
        let tx = conn.transaction().map_err(ApiError::internal)?;
        let out = f(&tx)?;
        tx.commit().map_err(ApiError::internal)?;
        Ok(out)
    }

    pub fn setting(&self, key: &str) -> Result<Option<String>, ApiError> {
        self.with(|c| c.query_row("SELECT value FROM settings WHERE key=?1", [key], |r| r.get(0)).optional())
    }

    pub fn set_setting(&self, key: &str, value: &str) -> Result<(), ApiError> {
        self.with(|c| c.execute("INSERT INTO settings(key,value) VALUES(?1,?2) ON CONFLICT(key) DO UPDATE SET value=excluded.value", [key, value]).map(|_| ()))
    }

    pub fn policy(&self) -> Result<Policy, ApiError> {
        let s = self.setting("policy")?.unwrap_or_default();
        serde_json::from_str(&s).map_err(ApiError::internal)
    }

    pub fn approval_rules(&self) -> Result<Vec<ApprovalRule>, ApiError> {
        let s = self.setting("approval_rules")?.unwrap_or_else(|| "[]".into());
        serde_json::from_str(&s).map_err(ApiError::internal)
    }
}

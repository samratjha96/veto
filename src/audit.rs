//! SQLite append-only audit log.

use anyhow::{Context, Result};
use rusqlite::Connection;
use std::path::Path;
use std::sync::Mutex;

pub struct AuditLog {
    conn: Mutex<Connection>,
}

impl AuditLog {
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("create audit dir {}", parent.display()))?;
        }
        let conn = Connection::open(path)
            .with_context(|| format!("open audit db {}", path.display()))?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL DEFAULT (datetime('now')),
                hook_type TEXT NOT NULL,
                tool_name TEXT,
                action_summary TEXT,
                decision TEXT NOT NULL,
                policy_id TEXT,
                yara_categories TEXT,
                yara_severity TEXT
            );",
        )
        .context("create events table")?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    pub fn log_event(
        &self,
        hook_type: &str,
        tool_name: Option<&str>,
        action_summary: Option<&str>,
        decision: &str,
        policy_id: Option<&str>,
        yara_categories: Option<&str>,
        yara_severity: Option<&str>,
    ) -> Result<()> {
        let conn = self.conn.lock().map_err(|e| anyhow::anyhow!("{e}"))?;
        conn.execute(
            "INSERT INTO events (hook_type, tool_name, action_summary, decision, policy_id, yara_categories, yara_severity)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            rusqlite::params![
                hook_type,
                tool_name,
                action_summary,
                decision,
                policy_id,
                yara_categories,
                yara_severity,
            ],
        )
        .context("insert audit event")?;
        Ok(())
    }

    pub fn event_count(&self) -> Result<i64> {
        let conn = self.conn.lock().map_err(|e| anyhow::anyhow!("{e}"))?;
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM events", [], |row| row.get(0))
            .context("count events")?;
        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn temp_db() -> (AuditLog, PathBuf) {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let id = COUNTER.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!(
            "veto-test-{}-{}",
            std::process::id(),
            id
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("test_audit.db");
        let _ = std::fs::remove_file(&path);
        let log = AuditLog::open(&path).unwrap();
        (log, path)
    }

    #[test]
    fn creates_table_and_inserts() {
        let (log, _path) = temp_db();
        log.log_event(
            "pre-tool-use",
            Some("Bash"),
            Some("echo hello"),
            "allow",
            None,
            None,
            None,
        )
        .unwrap();
        assert_eq!(log.event_count().unwrap(), 1);
    }

    #[test]
    fn multiple_events() {
        let (log, _path) = temp_db();
        log.log_event("pre-tool-use", Some("Bash"), Some("ls"), "allow", None, None, None)
            .unwrap();
        log.log_event(
            "pre-tool-use",
            Some("Bash"),
            Some("rm -rf /"),
            "deny",
            Some("forbid-rm-root"),
            Some("destructive_ops"),
            Some("high"),
        )
        .unwrap();
        assert_eq!(log.event_count().unwrap(), 2);
    }
}

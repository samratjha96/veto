//! SQLite append-only audit log.

use anyhow::{Context, Result};
use rusqlite::Connection;
use serde::Serialize;
use std::path::Path;
use std::sync::Mutex;

/// A single audit event row.
#[derive(Debug, Clone, Serialize)]
pub struct AuditEvent {
    pub id: i64,
    pub timestamp: String,
    pub hook_type: String,
    pub tool_name: Option<String>,
    pub action_summary: Option<String>,
    pub decision: String,
    pub policy_id: Option<String>,
    pub yara_categories: Option<String>,
    pub yara_severity: Option<String>,
}

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
        // WAL mode: allows concurrent readers while writing
        conn.execute_batch("PRAGMA journal_mode=WAL;")?;
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

    /// Query recent events with optional filters. Returns newest first.
    pub fn query_events(
        &self,
        limit: usize,
        decision_filter: Option<&str>,
        hook_filter: Option<&str>,
    ) -> Result<Vec<AuditEvent>> {
        self.query_events_since(limit, decision_filter, hook_filter, None)
    }

    /// Query events with optional filters and a minimum ID (exclusive).
    /// When `after_id` is Some, only returns events with id > after_id.
    pub fn query_events_since(
        &self,
        limit: usize,
        decision_filter: Option<&str>,
        hook_filter: Option<&str>,
        after_id: Option<i64>,
    ) -> Result<Vec<AuditEvent>> {
        let conn = self.conn.lock().map_err(|e| anyhow::anyhow!("{e}"))?;

        let mut sql = String::from(
            "SELECT id, timestamp, hook_type, tool_name, action_summary, \
             decision, policy_id, yara_categories, yara_severity FROM events",
        );
        let mut conditions = Vec::new();
        let mut params: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();

        if let Some(d) = decision_filter {
            conditions.push(format!("decision = ?{}", params.len() + 1));
            params.push(Box::new(d.to_string()));
        }
        if let Some(h) = hook_filter {
            conditions.push(format!("hook_type = ?{}", params.len() + 1));
            params.push(Box::new(h.to_string()));
        }
        if let Some(id) = after_id {
            conditions.push(format!("id > ?{}", params.len() + 1));
            params.push(Box::new(id));
        }

        if !conditions.is_empty() {
            sql.push_str(" WHERE ");
            sql.push_str(&conditions.join(" AND "));
        }
        sql.push_str(" ORDER BY id DESC LIMIT ?");
        params.push(Box::new(limit as i64));

        let param_refs: Vec<&dyn rusqlite::types::ToSql> = params.iter().map(|p| p.as_ref()).collect();
        let mut stmt = conn.prepare(&sql).context("prepare query")?;
        let rows = stmt
            .query_map(param_refs.as_slice(), |row| {
                Ok(AuditEvent {
                    id: row.get(0)?,
                    timestamp: row.get(1)?,
                    hook_type: row.get(2)?,
                    tool_name: row.get(3)?,
                    action_summary: row.get(4)?,
                    decision: row.get(5)?,
                    policy_id: row.get(6)?,
                    yara_categories: row.get(7)?,
                    yara_severity: row.get(8)?,
                })
            })
            .context("query events")?;

        let mut events = Vec::new();
        for row in rows {
            events.push(row.context("read event row")?);
        }
        Ok(events)
    }

    /// Get the highest event ID, or 0 if no events exist.
    pub fn max_id(&self) -> Result<i64> {
        let conn = self.conn.lock().map_err(|e| anyhow::anyhow!("{e}"))?;
        let id: i64 = conn
            .query_row("SELECT COALESCE(MAX(id), 0) FROM events", [], |row| row.get(0))
            .context("max id")?;
        Ok(id)
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

    #[test]
    fn query_events_returns_recent() {
        let (log, _path) = temp_db();
        for i in 0..5 {
            log.log_event("pre-tool-use", Some("Bash"), Some(&format!("cmd-{i}")), "allow", None, None, None)
                .unwrap();
        }
        let events = log.query_events(3, None, None).unwrap();
        assert_eq!(events.len(), 3);
        // Newest first — id 5 before id 4
        assert!(events[0].id > events[1].id);
        assert_eq!(events[0].action_summary.as_deref(), Some("cmd-4"));
    }

    #[test]
    fn query_events_filters_by_decision() {
        let (log, _path) = temp_db();
        log.log_event("pre-tool-use", Some("Bash"), Some("ls"), "allow", None, None, None).unwrap();
        log.log_event("pre-tool-use", Some("Bash"), Some("rm /"), "deny", Some("p1"), None, None).unwrap();
        log.log_event("pre-tool-use", Some("Bash"), Some("cat /etc"), "deny", Some("p2"), None, None).unwrap();

        let denied = log.query_events(10, Some("deny"), None).unwrap();
        assert_eq!(denied.len(), 2);
        assert!(denied.iter().all(|e| e.decision == "deny"));

        let allowed = log.query_events(10, Some("allow"), None).unwrap();
        assert_eq!(allowed.len(), 1);
    }

    #[test]
    fn query_events_filters_by_hook_type() {
        let (log, _path) = temp_db();
        log.log_event("pre-tool-use", Some("Bash"), Some("ls"), "allow", None, None, None).unwrap();
        log.log_event("post-tool-use", Some("Bash"), Some("ls"), "allow", None, None, None).unwrap();

        let pre = log.query_events(10, None, Some("pre-tool-use")).unwrap();
        assert_eq!(pre.len(), 1);
        assert_eq!(pre[0].hook_type, "pre-tool-use");
    }

    #[test]
    fn query_events_empty_db() {
        let (log, _path) = temp_db();
        let events = log.query_events(10, None, None).unwrap();
        assert!(events.is_empty());
    }

    #[test]
    fn open_creates_parent_dirs() {
        let dir = std::env::temp_dir().join(format!(
            "veto-audit-nested-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let deep_path = dir.join("a").join("b").join("audit.db");
        let log = AuditLog::open(&deep_path).unwrap();
        log.log_event("test", None, None, "allow", None, None, None)
            .unwrap();
        assert_eq!(log.event_count().unwrap(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn query_events_since_filters_by_id() {
        let (log, _path) = temp_db();
        for i in 0..5 {
            log.log_event("pre-tool-use", Some("Bash"), Some(&format!("cmd-{i}")), "allow", None, None, None)
                .unwrap();
        }
        // Get events after id 3 — should get ids 4 and 5
        let events = log.query_events_since(10, None, None, Some(3)).unwrap();
        assert_eq!(events.len(), 2);
        assert!(events.iter().all(|e| e.id > 3));
    }

    #[test]
    fn max_id_empty_db() {
        let (log, _path) = temp_db();
        assert_eq!(log.max_id().unwrap(), 0);
    }

    #[test]
    fn max_id_after_inserts() {
        let (log, _path) = temp_db();
        for _ in 0..3 {
            log.log_event("test", None, None, "allow", None, None, None).unwrap();
        }
        assert_eq!(log.max_id().unwrap(), 3);
    }

    #[test]
    fn query_with_limit_zero_returns_nothing() {
        let (log, _path) = temp_db();
        log.log_event("pre-tool-use", Some("Bash"), Some("ls"), "allow", None, None, None)
            .unwrap();
        let events = log.query_events(0, None, None).unwrap();
        assert!(events.is_empty());
    }
}

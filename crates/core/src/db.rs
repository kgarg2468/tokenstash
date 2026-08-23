use anyhow::Result;
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::path::Path;

pub struct Db {
    pub conn: Connection,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretMeta {
    pub name: String,
    pub identity: String,
    pub provider: Option<String>,
    pub sensitive: bool,
    pub source_url: Option<String>,
    pub created: String,
    pub last_used: Option<String>,
    pub stale: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum TaskKind {
    Secret,
    Approval,
    Human,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum TaskStatus {
    Pending,
    Answered,
    Denied,
    Expired,
}

impl TaskStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            TaskStatus::Pending => "pending",
            TaskStatus::Answered => "answered",
            TaskStatus::Denied => "denied",
            TaskStatus::Expired => "expired",
        }
    }
    pub fn parse(s: &str) -> Self {
        match s {
            "answered" => TaskStatus::Answered,
            "denied" => TaskStatus::Denied,
            "expired" => TaskStatus::Expired,
            _ => TaskStatus::Pending,
        }
    }
}

impl TaskKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            TaskKind::Secret => "secret",
            TaskKind::Approval => "approval",
            TaskKind::Human => "human",
        }
    }
    pub fn parse(s: &str) -> Self {
        match s {
            "approval" => TaskKind::Approval,
            "human" => TaskKind::Human,
            _ => TaskKind::Secret,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Task {
    pub id: String,
    pub kind: TaskKind,
    pub project: String,
    pub agent: String,
    /// Secret name (secret tasks) or None.
    pub name: Option<String>,
    pub identity: String,
    pub title: String,
    pub why: Option<String>,
    pub url: Option<String>,
    pub steps: Vec<String>,
    /// "secret" | "confirm" | "text" | "choice"
    pub expects: String,
    pub pattern: Option<String>,
    /// For approval tasks: the names being gated.
    pub names: Vec<String>,
    pub status: TaskStatus,
    pub created: String,
    pub deadline: String,
    pub answered_at: Option<String>,
    pub note: Option<String>,
}

impl Db {
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let conn = Connection::open(path)?;
        conn.execute_batch(
            r#"
            PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS secrets (
                name TEXT NOT NULL, identity TEXT NOT NULL, provider TEXT,
                sensitive INTEGER NOT NULL DEFAULT 0, source_url TEXT,
                created TEXT NOT NULL, last_used TEXT, stale INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (name, identity)
            );
            CREATE TABLE IF NOT EXISTS tasks (
                id TEXT PRIMARY KEY, kind TEXT NOT NULL, project TEXT NOT NULL, agent TEXT NOT NULL,
                name TEXT, identity TEXT NOT NULL DEFAULT 'default', title TEXT NOT NULL,
                why TEXT, url TEXT, steps TEXT NOT NULL DEFAULT '[]', expects TEXT NOT NULL DEFAULT 'secret',
                pattern TEXT, names TEXT NOT NULL DEFAULT '[]', status TEXT NOT NULL DEFAULT 'pending',
                created TEXT NOT NULL, deadline TEXT NOT NULL, answered_at TEXT, note TEXT
            );
            CREATE TABLE IF NOT EXISTS approvals (
                project TEXT NOT NULL, name TEXT NOT NULL, created TEXT NOT NULL,
                PRIMARY KEY (project, name)
            );
            CREATE TABLE IF NOT EXISTS bindings (
                project TEXT NOT NULL, name TEXT NOT NULL, identity TEXT NOT NULL,
                PRIMARY KEY (project, name)
            );
            CREATE TABLE IF NOT EXISTS audit (
                id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, project TEXT, agent TEXT,
                action TEXT NOT NULL, name TEXT, identity TEXT, detail TEXT
            );
            "#,
        )?;
        Ok(Self { conn })
    }

    pub fn open_default() -> Result<Self> {
        Self::open(&crate::config::db_path())
    }

    // ---------- secrets index (metadata only; values live in the stash) ----------

    pub fn upsert_secret(&self, m: &SecretMeta) -> Result<()> {
        self.conn.execute(
            "INSERT INTO secrets (name, identity, provider, sensitive, source_url, created, last_used, stale)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8)
             ON CONFLICT(name, identity) DO UPDATE SET provider=excluded.provider, sensitive=excluded.sensitive,
               source_url=excluded.source_url, stale=excluded.stale",
            params![m.name, m.identity, m.provider, m.sensitive as i32, m.source_url, m.created, m.last_used, m.stale as i32],
        )?;
        Ok(())
    }

    pub fn get_secret(&self, name: &str, identity: &str) -> Result<Option<SecretMeta>> {
        Ok(self
            .conn
            .query_row(
                "SELECT name, identity, provider, sensitive, source_url, created, last_used, stale FROM secrets WHERE name=?1 AND identity=?2",
                params![name, identity],
                |r| {
                    Ok(SecretMeta {
                        name: r.get(0)?,
                        identity: r.get(1)?,
                        provider: r.get(2)?,
                        sensitive: r.get::<_, i32>(3)? != 0,
                        source_url: r.get(4)?,
                        created: r.get(5)?,
                        last_used: r.get(6)?,
                        stale: r.get::<_, i32>(7)? != 0,
                    })
                },
            )
            .optional()?)
    }

    pub fn list_secrets(&self) -> Result<Vec<SecretMeta>> {
        let mut st = self.conn.prepare(
            "SELECT name, identity, provider, sensitive, source_url, created, last_used, stale FROM secrets ORDER BY name, identity",
        )?;
        let rows = st.query_map([], |r| {
            Ok(SecretMeta {
                name: r.get(0)?,
                identity: r.get(1)?,
                provider: r.get(2)?,
                sensitive: r.get::<_, i32>(3)? != 0,
                source_url: r.get(4)?,
                created: r.get(5)?,
                last_used: r.get(6)?,
                stale: r.get::<_, i32>(7)? != 0,
            })
        })?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    pub fn touch_secret(&self, name: &str, identity: &str) -> Result<()> {
        self.conn.execute(
            "UPDATE secrets SET last_used=?3 WHERE name=?1 AND identity=?2",
            params![name, identity, crate::now()],
        )?;
        Ok(())
    }

    pub fn mark_stale(&self, name: &str, identity: &str, stale: bool) -> Result<()> {
        self.conn.execute(
            "UPDATE secrets SET stale=?3 WHERE name=?1 AND identity=?2",
            params![name, identity, stale as i32],
        )?;
        Ok(())
    }

    pub fn delete_secret(&self, name: &str, identity: &str) -> Result<bool> {
        Ok(self.conn.execute("DELETE FROM secrets WHERE name=?1 AND identity=?2", params![name, identity])? > 0)
    }

    // ---------- tasks ----------

    pub fn insert_task(&self, t: &Task) -> Result<()> {
        self.conn.execute(
            "INSERT INTO tasks (id, kind, project, agent, name, identity, title, why, url, steps, expects, pattern, names, status, created, deadline, answered_at, note)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18)",
            params![
                t.id, t.kind.as_str(), t.project, t.agent, t.name, t.identity, t.title, t.why, t.url,
                serde_json::to_string(&t.steps)?, t.expects, t.pattern, serde_json::to_string(&t.names)?,
                t.status.as_str(), t.created, t.deadline, t.answered_at, t.note
            ],
        )?;
        Ok(())
    }

    fn row_to_task(r: &rusqlite::Row) -> rusqlite::Result<Task> {
        let steps: String = r.get(9)?;
        let names: String = r.get(12)?;
        Ok(Task {
            id: r.get(0)?,
            kind: TaskKind::parse(&r.get::<_, String>(1)?),
            project: r.get(2)?,
            agent: r.get(3)?,
            name: r.get(4)?,
            identity: r.get(5)?,
            title: r.get(6)?,
            why: r.get(7)?,
            url: r.get(8)?,
            steps: serde_json::from_str(&steps).unwrap_or_default(),
            expects: r.get(10)?,
            pattern: r.get(11)?,
            names: serde_json::from_str(&names).unwrap_or_default(),
            status: TaskStatus::parse(&r.get::<_, String>(13)?),
            created: r.get(14)?,
            deadline: r.get(15)?,
            answered_at: r.get(16)?,
            note: r.get(17)?,
        })
    }

    const TASK_COLS: &'static str = "id, kind, project, agent, name, identity, title, why, url, steps, expects, pattern, names, status, created, deadline, answered_at, note";

    pub fn get_task(&self, id: &str) -> Result<Option<Task>> {
        let sql = format!("SELECT {} FROM tasks WHERE id=?1", Self::TASK_COLS);
        Ok(self.conn.query_row(&sql, params![id], Self::row_to_task).optional()?)
    }

    /// Resolve a task id prefix (e.g. "7fa2" or "t_7fa2").
    pub fn find_task(&self, id_or_prefix: &str) -> Result<Option<Task>> {
        if let Some(t) = self.get_task(id_or_prefix)? {
            return Ok(Some(t));
        }
        let sql = format!("SELECT {} FROM tasks WHERE id LIKE ?1 OR id LIKE ?2 ORDER BY created DESC", Self::TASK_COLS);
        let mut st = self.conn.prepare(&sql)?;
        let rows: Vec<Task> = st
            .query_map(params![format!("{}%", id_or_prefix), format!("%_{}%", id_or_prefix)], Self::row_to_task)?
            .collect::<std::result::Result<_, _>>()?;
        Ok(rows.into_iter().next())
    }

    pub fn list_tasks(&self, project: Option<&str>, only_open: bool) -> Result<Vec<Task>> {
        let mut sql = format!("SELECT {} FROM tasks WHERE 1=1", Self::TASK_COLS);
        if only_open {
            sql.push_str(" AND status='pending'");
        }
        if project.is_some() {
            sql.push_str(" AND project=?1");
        }
        sql.push_str(" ORDER BY created ASC");
        let mut st = self.conn.prepare(&sql)?;
        let rows: Vec<Task> = match project {
            Some(p) => st.query_map(params![p], Self::row_to_task)?.collect::<std::result::Result<_, _>>()?,
            None => st.query_map([], Self::row_to_task)?.collect::<std::result::Result<_, _>>()?,
        };
        Ok(rows)
    }

    /// Open secret task for this name+project, if any (avoid duplicate tasks).
    pub fn open_secret_task(&self, project: &str, name: &str) -> Result<Option<Task>> {
        let sql = format!(
            "SELECT {} FROM tasks WHERE kind='secret' AND status='pending' AND project=?1 AND name=?2 ORDER BY created DESC",
            Self::TASK_COLS
        );
        Ok(self.conn.query_row(&sql, params![project, name], Self::row_to_task).optional()?)
    }

    /// Most recent denied secret task for name+project, if denied after `since` (RFC3339).
    pub fn recent_denial(&self, project: &str, name: &str, since: &str) -> Result<Option<Task>> {
        let sql = format!(
            "SELECT {} FROM tasks WHERE kind='secret' AND status='denied' AND project=?1 AND name=?2 AND answered_at > ?3 ORDER BY answered_at DESC",
            Self::TASK_COLS
        );
        Ok(self.conn.query_row(&sql, params![project, name, since], Self::row_to_task).optional()?)
    }

    pub fn open_approval_task(&self, project: &str) -> Result<Option<Task>> {
        let sql = format!(
            "SELECT {} FROM tasks WHERE kind='approval' AND status='pending' AND project=?1 ORDER BY created DESC",
            Self::TASK_COLS
        );
        Ok(self.conn.query_row(&sql, params![project], Self::row_to_task).optional()?)
    }

    pub fn set_task_status(&self, id: &str, status: TaskStatus, note: Option<&str>) -> Result<()> {
        self.conn.execute(
            "UPDATE tasks SET status=?2, answered_at=?3, note=COALESCE(?4, note) WHERE id=?1",
            params![id, status.as_str(), crate::now(), note],
        )?;
        Ok(())
    }

    pub fn update_task_names(&self, id: &str, names: &[String]) -> Result<()> {
        self.conn.execute(
            "UPDATE tasks SET names=?2 WHERE id=?1",
            params![id, serde_json::to_string(names)?],
        )?;
        Ok(())
    }

    /// Mark pending tasks past their deadline as expired. Returns count.
    pub fn expire_overdue(&self) -> Result<usize> {
        Ok(self.conn.execute(
            "UPDATE tasks SET status='expired' WHERE status='pending' AND deadline < ?1",
            params![crate::now()],
        )?)
    }

    // ---------- approvals / bindings ----------

    pub fn is_approved(&self, project: &str, name: &str) -> Result<bool> {
        let n: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM approvals WHERE project=?1 AND (name=?2 OR name='*')",
            params![project, name],
            |r| r.get(0),
        )?;
        Ok(n > 0)
    }

    pub fn approve(&self, project: &str, name: &str) -> Result<()> {
        self.conn.execute(
            "INSERT OR IGNORE INTO approvals (project, name, created) VALUES (?1,?2,?3)",
            params![project, name, crate::now()],
        )?;
        Ok(())
    }

    pub fn binding(&self, project: &str, name: &str) -> Result<Option<String>> {
        Ok(self
            .conn
            .query_row(
                "SELECT identity FROM bindings WHERE project=?1 AND name=?2",
                params![project, name],
                |r| r.get(0),
            )
            .optional()?)
    }

    pub fn set_binding(&self, project: &str, name: &str, identity: &str) -> Result<()> {
        self.conn.execute(
            "INSERT INTO bindings (project, name, identity) VALUES (?1,?2,?3)
             ON CONFLICT(project, name) DO UPDATE SET identity=excluded.identity",
            params![project, name, identity],
        )?;
        Ok(())
    }

    // ---------- audit (never values) ----------

    pub fn audit(&self, project: Option<&str>, agent: Option<&str>, action: &str, name: Option<&str>, identity: Option<&str>, detail: Option<&str>) -> Result<()> {
        self.conn.execute(
            "INSERT INTO audit (ts, project, agent, action, name, identity, detail) VALUES (?1,?2,?3,?4,?5,?6,?7)",
            params![crate::now(), project, agent, action, name, identity, detail],
        )?;
        Ok(())
    }

    pub fn recent_audit(&self, limit: usize) -> Result<Vec<(String, Option<String>, Option<String>, String, Option<String>, Option<String>, Option<String>)>> {
        let mut st = self.conn.prepare(
            "SELECT ts, project, agent, action, name, identity, detail FROM audit ORDER BY id DESC LIMIT ?1",
        )?;
        let rows = st.query_map(params![limit as i64], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?))
        })?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }
}

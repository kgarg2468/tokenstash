use anyhow::Result;
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// (ts, project, agent, action, name, identity, detail) — never a value.
pub type AuditRow = (String, Option<String>, Option<String>, String, Option<String>, Option<String>, Option<String>);

pub struct Db {
    pub conn: Connection,
}

/// The index holds no values, but task/approval/binding metadata is still private.
#[cfg(unix)]
fn restrict_dir(p: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o700))?;
    Ok(())
}
#[cfg(unix)]
fn restrict_file(p: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    if p.exists() {
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}
#[cfg(not(unix))]
fn restrict_dir(_p: &Path) -> Result<()> { Ok(()) }
#[cfg(not(unix))]
fn restrict_file(_p: &Path) -> Result<()> { Ok(()) }

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
    /// Last time a liveness probe (paste-time or `check`) accepted this value.
    #[serde(default)]
    pub last_verified: Option<String>,
    /// Why it is stale: "rejected by X (HTTP n) on <date>, reported by <agent> in <project>",
    /// "you asked to rotate", ... Shown on the replacement card.
    #[serde(default)]
    pub stale_reason: Option<String>,
    /// Who set the stale flag: "rotate" (the human), "report" (an agent's report, probe-
    /// decided when a probe exists), "probe" (verify-on-use or `check`). State transitions
    /// key off this, never off the display text in `stale_reason`.
    #[serde(default)]
    pub stale_source: Option<String>,
    /// Do not probe before this time (RFC 3339). A lease: set before a probe goes on the
    /// wire so a concurrent process does not probe too, then extended by the result.
    #[serde(default)]
    pub next_probe: Option<String>,
    /// Verify-on-use is off for this key: the human stored it with --skip-check / --no-verify,
    /// so a probe that keeps saying "rejected" must not keep filing cards. Cleared by any
    /// probe that says Ok.
    #[serde(default)]
    pub verify_off: bool,
}

/// Values for `SecretMeta::stale_source`.
pub const STALE_ROTATE: &str = "rotate";
pub const STALE_REPORT: &str = "report";
pub const STALE_PROBE: &str = "probe";

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
            restrict_dir(parent)?;
        }
        let conn = Connection::open(path)?;
        restrict_file(path)?;
        // CLI, inbox and MCP server each hold their own connection; a write collision must
        // wait, not error.
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
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
        // Columns added after v0.1.0. SQLite has no ADD COLUMN IF NOT EXISTS; probe first.
        for (col, ddl) in [
            ("last_verified", "ALTER TABLE secrets ADD COLUMN last_verified TEXT"),
            ("stale_reason", "ALTER TABLE secrets ADD COLUMN stale_reason TEXT"),
            ("stale_source", "ALTER TABLE secrets ADD COLUMN stale_source TEXT"),
            ("next_probe", "ALTER TABLE secrets ADD COLUMN next_probe TEXT"),
            ("verify_off", "ALTER TABLE secrets ADD COLUMN verify_off INTEGER NOT NULL DEFAULT 0"),
        ] {
            let has: bool = conn.prepare("SELECT 1 FROM pragma_table_info('secrets') WHERE name=?1")?.exists([col])?;
            if !has {
                // Two processes (CLI + MCP server) can race here; the loser's ALTER fails
                // with "duplicate column", which is success.
                if let Err(e) = conn.execute_batch(ddl) {
                    if !e.to_string().contains("duplicate column") {
                        return Err(e.into());
                    }
                }
            }
        }
        // Rows marked stale before `stale_source` existed: the human's rotation is the only
        // one whose display text is a fixed constant, so it is the only one recoverable.
        conn.execute(
            "UPDATE secrets SET stale_source=?1 WHERE stale=1 AND stale_source IS NULL AND stale_reason LIKE ?2",
            params![STALE_ROTATE, format!("{}%", Self::ROTATE_REASON)],
        )?;
        conn.execute("UPDATE secrets SET stale_source=?1 WHERE stale=1 AND stale_source IS NULL", params![STALE_REPORT])?;
        Ok(Self { conn })
    }

    pub fn open_default() -> Result<Self> {
        Self::open(&crate::config::db_path())
    }

    // ---------- secrets index (metadata only; values live in the stash) ----------

    pub fn upsert_secret(&self, m: &SecretMeta) -> Result<()> {
        self.conn.execute(
            "INSERT INTO secrets (name, identity, provider, sensitive, source_url, created, last_used, stale, last_verified, stale_reason, stale_source, next_probe, verify_off)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)
             ON CONFLICT(name, identity) DO UPDATE SET provider=excluded.provider, sensitive=excluded.sensitive,
               source_url=excluded.source_url, stale=excluded.stale, last_verified=excluded.last_verified, stale_reason=excluded.stale_reason,
               stale_source=excluded.stale_source, next_probe=excluded.next_probe, verify_off=excluded.verify_off,
               created=excluded.created, last_used=COALESCE(excluded.last_used, secrets.last_used)",
            params![m.name, m.identity, m.provider, m.sensitive as i32, m.source_url, m.created, m.last_used, m.stale as i32, m.last_verified, m.stale_reason, m.stale_source, m.next_probe, m.verify_off as i32],
        )?;
        Ok(())
    }

    pub fn get_secret(&self, name: &str, identity: &str) -> Result<Option<SecretMeta>> {
        Ok(self
            .conn
            .query_row(
                "SELECT name, identity, provider, sensitive, source_url, created, last_used, stale, last_verified, stale_reason, stale_source, next_probe, verify_off FROM secrets WHERE name=?1 AND identity=?2",
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
                        last_verified: r.get(8)?,
                        stale_reason: r.get(9)?,
                        stale_source: r.get(10)?,
                        next_probe: r.get(11)?,
                        verify_off: r.get::<_, i32>(12)? != 0,
                    })
                },
            )
            .optional()?)
    }

    pub fn list_secrets(&self) -> Result<Vec<SecretMeta>> {
        let mut st = self.conn.prepare(
            "SELECT name, identity, provider, sensitive, source_url, created, last_used, stale, last_verified, stale_reason, stale_source, next_probe, verify_off FROM secrets ORDER BY name, identity",
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
                last_verified: r.get(8)?,
                stale_reason: r.get(9)?,
                stale_source: r.get(10)?,
                next_probe: r.get(11)?,
                verify_off: r.get::<_, i32>(12)? != 0,
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

    /// Mark a key stale (with the reason the replacement card will show, and who decided)
    /// or fresh again.
    pub fn mark_stale(&self, name: &str, identity: &str, stale: bool, reason: Option<&str>, source: Option<&str>) -> Result<()> {
        self.conn.execute(
            "UPDATE secrets SET stale=?3, stale_reason=?4, stale_source=?5 WHERE name=?1 AND identity=?2",
            params![name, identity, stale as i32, if stale { reason } else { None }, if stale { source } else { None }],
        )?;
        Ok(())
    }

    /// Display text for a stale set by the human (`rotate`).
    pub const ROTATE_REASON: &'static str = "you asked to rotate it";

    /// A probe accepted the stored value: record it, clear a probe- or report-set stale
    /// flag, release the probe lease, and re-enable verify-on-use. A rotation the human
    /// asked for survives: the old key is live by design until the new one lands.
    /// When the next routine probe is due follows from `last_verified` and the configured
    /// window, so a config change takes effect immediately; `next_probe` only ever holds a
    /// short lease or backoff.
    pub fn set_verified(&self, name: &str, identity: &str) -> Result<()> {
        self.conn.execute(
            "UPDATE secrets SET last_verified=?3, next_probe=NULL, verify_off=0,
                stale = CASE WHEN stale_source=?4 THEN stale ELSE 0 END,
                stale_reason = CASE WHEN stale_source=?4 THEN stale_reason ELSE NULL END,
                stale_source = CASE WHEN stale_source=?4 THEN stale_source ELSE NULL END
             WHERE name=?1 AND identity=?2",
            params![name, identity, crate::now(), STALE_ROTATE],
        )?;
        Ok(())
    }

    /// Lease / backoff for verify-on-use.
    pub fn set_next_probe(&self, name: &str, identity: &str, at: &str) -> Result<()> {
        self.conn.execute("UPDATE secrets SET next_probe=?3 WHERE name=?1 AND identity=?2", params![name, identity, at])?;
        Ok(())
    }

    /// Claim the right to probe now: succeeds only if no other process holds a live lease.
    /// Returns false when someone else got there first (or the key is gone).
    pub fn claim_probe(&self, name: &str, identity: &str, until: &str) -> Result<bool> {
        let now = crate::now();
        let n = self.conn.execute(
            "UPDATE secrets SET next_probe=?3 WHERE name=?1 AND identity=?2 AND (next_probe IS NULL OR next_probe <= ?4)",
            params![name, identity, until, now],
        )?;
        Ok(n == 1)
    }

    pub fn set_verify_off(&self, name: &str, identity: &str, off: bool) -> Result<()> {
        self.conn.execute("UPDATE secrets SET verify_off=?3 WHERE name=?1 AND identity=?2", params![name, identity, off as i32])?;
        Ok(())
    }

    /// Has this key ever been delivered (stored or injected) into this project? The audit
    /// log is the record. A report of "this key is dead" is only credible from a project
    /// that actually received it.
    pub fn has_delivered(&self, project: &str, name: &str, identity: &str) -> Result<bool> {
        let n: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM audit WHERE project=?1 AND name=?2 AND identity=?3 AND action IN ('inject','store')",
            params![project, name, identity],
            |r| r.get(0),
        )?;
        Ok(n > 0)
    }

    /// Was this key injected into this project by an approval answered at or after `since`?
    /// The audit row is written by `deliver` after the env file, so it is the proof that the
    /// delivery finished — a value already sitting in the file proves nothing.
    pub fn injected_after_approval_since(&self, project: &str, name: &str, identity: &str, since: &str) -> Result<bool> {
        let n: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM audit WHERE project=?1 AND name=?2 AND identity=?3 AND action='inject' AND detail='after-approval' AND ts >= ?4",
            params![project, name, identity, since],
            |r| r.get(0),
        )?;
        Ok(n > 0)
    }

    /// Projects that have ever had this key delivered. For re-injecting a rotated value.
    pub fn delivered_projects(&self, name: &str, identity: &str) -> Result<Vec<String>> {
        let mut st = self.conn.prepare("SELECT DISTINCT project FROM audit WHERE name=?1 AND identity=?2 AND action IN ('inject','store') AND project IS NOT NULL")?;
        let rows = st.query_map(params![name, identity], |r| r.get::<_, String>(0))?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    /// Most recent `report`/`false_report` audit row for (project, name, identity) after `since`.
    pub fn recent_report(&self, project: &str, name: &str, identity: &str, since: &str) -> Result<Option<String>> {
        Ok(self.conn.query_row(
            "SELECT action FROM audit WHERE project=?1 AND name=?2 AND identity=?3 AND action IN ('report','false_report','report.unverified') AND ts >= ?4 ORDER BY id DESC LIMIT 1",
            params![project, name, identity, since],
            |r| r.get::<_, String>(0),
        ).optional()?)
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

    /// Resolve a task id: exact match, else a prefix of the id with or without its kind
    /// prefix ("7fa2" and "t_7fa2" both resolve `t_7fa2xx`). An empty or ambiguous prefix
    /// is an error rather than a silent guess — callers answer, approve, or deny by id.
    pub fn find_task(&self, id_or_prefix: &str) -> Result<Option<Task>> {
        let q = id_or_prefix.trim();
        if q.is_empty() {
            anyhow::bail!("task id is empty");
        }
        if !q.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
            anyhow::bail!("task id '{q}' contains invalid characters");
        }
        if let Some(t) = self.get_task(q)? {
            return Ok(Some(t));
        }
        let sql = format!("SELECT {} FROM tasks ORDER BY created DESC", Self::TASK_COLS);
        let mut st = self.conn.prepare(&sql)?;
        let matches: Vec<Task> = st
            .query_map([], Self::row_to_task)?
            .collect::<std::result::Result<Vec<_>, _>>()?
            .into_iter()
            .filter(|t| t.id.starts_with(q) || t.id.get(2..).map(|rest| rest.starts_with(q)).unwrap_or(false))
            .collect();
        match matches.len() {
            0 => Ok(None),
            1 => Ok(matches.into_iter().next()),
            n => anyhow::bail!(
                "task id '{q}' is ambiguous ({n} matches: {}). Use a longer prefix.",
                matches.iter().take(5).map(|t| t.id.as_str()).collect::<Vec<_>>().join(", ")
            ),
        }
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

    /// Open secret task for this project+name+identity, if any (avoid duplicate tasks).
    /// Identity is part of the key: `OPENAI_API_KEY@work` and `@personal` are different
    /// requests and must never share a task.
    /// The open human task with this title in this project, if any: a blocking caller that
    /// re-issues its request must not file a second card.
    pub fn open_human_task(&self, project: &str, title: &str) -> Result<Option<Task>> {
        let sql = format!("SELECT {} FROM tasks WHERE kind='human' AND status='pending' AND project=?1 AND title=?2 ORDER BY created DESC", Self::TASK_COLS);
        Ok(self.conn.query_row(&sql, params![project, title], Self::row_to_task).optional()?)
    }

    pub fn open_secret_task(&self, project: &str, name: &str, identity: &str) -> Result<Option<Task>> {
        let sql = format!(
            "SELECT {} FROM tasks WHERE kind='secret' AND status='pending' AND project=?1 AND name=?2 AND identity=?3 ORDER BY created DESC",
            Self::TASK_COLS
        );
        Ok(self.conn.query_row(&sql, params![project, name, identity], Self::row_to_task).optional()?)
    }

    /// Most recent denied secret task for project+name+identity, if denied after `since`.
    pub fn recent_denial(&self, project: &str, name: &str, identity: &str, since: &str) -> Result<Option<Task>> {
        let sql = format!(
            "SELECT {} FROM tasks WHERE kind='secret' AND status='denied' AND project=?1 AND name=?2 AND identity=?3 AND answered_at > ?4 ORDER BY answered_at DESC",
            Self::TASK_COLS
        );
        Ok(self.conn.query_row(&sql, params![project, name, identity, since], Self::row_to_task).optional()?)
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

    pub fn set_task_expects(&self, id: &str, expects: &str) -> Result<()> {
        self.conn.execute("UPDATE tasks SET expects=?2 WHERE id=?1", params![id, expects])?;
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

    /// Approved by name, or by the project-wide `*` that "allow this project" records.
    /// Only for the LOCATION gate. Never for sensitive keys — see [`Self::is_approved_exact`].
    pub fn is_approved(&self, project: &str, name: &str) -> Result<bool> {
        let n: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM approvals WHERE project=?1 AND (name=?2 OR name='*')",
            params![project, name],
            |r| r.get(0),
        )?;
        Ok(n > 0)
    }

    /// Approved by this exact name only. A sensitive key is a per-key decision: the
    /// project-wide `*` from an "allow this project" card must not satisfy it, or an
    /// outside-root project becomes MORE permissive than a trusted one.
    pub fn is_approved_exact(&self, project: &str, name: &str) -> Result<bool> {
        let n: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM approvals WHERE project=?1 AND name=?2",
            params![project, name],
            |r| r.get(0),
        )?;
        Ok(n > 0)
    }

    /// Most recent denied approval task for a project after `since`. "Deny" on an approval
    /// card must mean something: without memory, a program failing in a loop files a fresh
    /// card each time until the human clicks through out of fatigue.
    pub fn recent_denied_approvals(&self, project: &str, since: &str) -> Result<Vec<Task>> {
        let sql = format!(
            "SELECT {} FROM tasks WHERE kind='approval' AND status='denied' AND project=?1 AND answered_at > ?2 ORDER BY answered_at DESC",
            Self::TASK_COLS
        );
        let mut st = self.conn.prepare(&sql)?;
        let rows = st.query_map(params![project, since], Self::row_to_task)?.collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
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

    pub fn list_bindings(&self) -> Result<Vec<(String, String, String)>> {
        let mut st = self.conn.prepare("SELECT project, name, identity FROM bindings ORDER BY project, name")?;
        let rows = st.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
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

    pub fn recent_audit(&self, limit: usize) -> Result<Vec<AuditRow>> {
        let mut st = self.conn.prepare(
            "SELECT ts, project, agent, action, name, identity, detail FROM audit ORDER BY id DESC LIMIT ?1",
        )?;
        let rows = st.query_map(params![limit as i64], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?))
        })?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }
}

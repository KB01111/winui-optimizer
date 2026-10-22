//! SQLite persistence for the AI Antivirus engine.
//!
//! Design notes:
//! - Every security event is stored as an immutable row whose full serialized
//!   payload lives in a JSON column, with indexed columns for the fields the UI
//!   filters on (timestamp, kind, severity, correlation id, pid, path, hash).
//! - Normalized `processes`, `files` and `detections` tables exist for timeline
//!   navigation and ancestry queries; the JSON payload remains the source of
//!   truth so schema evolution cannot lose evidence.
//! - File contents are never stored, only hashes and metadata.
//! - Schema versions are explicit (`schema_migrations` + `PRAGMA user_version`).

use rusqlite::{params, Connection, OptionalExtension};
use security_core::{
    DecisionResult, FileScanReport, ProviderHealth, ProviderStatus, QuarantineRecord,
    QuarantineStatus, ScanJobSummary, SecurityEvent, SecurityEventKind, Severity, TimestampMs,
};
use std::path::Path;
use std::sync::Mutex;

pub const CURRENT_SCHEMA_VERSION: u32 = 2;

/// Filter accepted by the timeline query layer.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EventFilter {
    #[serde(default = "default_limit")]
    pub limit: u32,
    #[serde(default)]
    pub offset: u32,
    #[serde(default)]
    pub severity: Option<Severity>,
    #[serde(default)]
    pub kind: Option<SecurityEventKind>,
    #[serde(default)]
    pub search: Option<String>,
    #[serde(default)]
    pub correlation_id: Option<String>,
    #[serde(default)]
    pub since_ms: Option<TimestampMs>,
}

fn default_limit() -> u32 {
    100
}

impl EventFilter {
    pub fn bounded(mut self) -> Self {
        self.limit = self.limit.clamp(1, 500);
        self
    }
}

/// One page of timeline results.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EventPage {
    pub items: Vec<SecurityEvent>,
    pub total: u64,
    pub next_offset: Option<u32>,
}

#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error("database error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("serialization error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("database lock poisoned")]
    Lock,
    #[error("migration error: {0}")]
    Migration(String),
    #[error("not found: {0}")]
    NotFound(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

impl<T> From<std::sync::PoisonError<T>> for StorageError {
    fn from(_: std::sync::PoisonError<T>) -> Self {
        StorageError::Lock
    }
}

/// Connection wrapper. The desktop app and the service each own one instance;
/// WAL mode allows the UI to read while the service writes when they share a
/// database file.
pub struct Database {
    conn: Mutex<Connection>,
}

impl Database {
    pub fn open(path: &Path) -> Result<Self, StorageError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let conn = Connection::open(path)?;
        // journal_mode returns a row, so query it explicitly.
        let _: String = conn.query_row("PRAGMA journal_mode=WAL", [], |row| row.get(0))?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        let db = Self {
            conn: Mutex::new(conn),
        };
        db.migrate()?;
        Ok(db)
    }

    pub fn open_in_memory() -> Result<Self, StorageError> {
        let conn = Connection::open_in_memory()?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        let db = Self {
            conn: Mutex::new(conn),
        };
        db.migrate()?;
        Ok(db)
    }

    pub fn schema_version(&self) -> Result<u32, StorageError> {
        let conn = self.conn.lock()?;
        let version: u32 = conn.query_row("PRAGMA user_version", [], |row| row.get(0))?;
        Ok(version)
    }

    fn migrate(&self) -> Result<(), StorageError> {
        let mut conn = self.conn.lock()?;
        let tx = conn.transaction()?;
        let version: u32 = tx.query_row("PRAGMA user_version", [], |row| row.get(0))?;
        if version < 1 {
            tx.execute_batch(SCHEMA_V1)?;
            tx.execute(
                "INSERT OR REPLACE INTO schema_migrations(version, applied_at_ms) VALUES (1, ?1)",
                params![now_ms()],
            )?;
            tx.pragma_update(None, "user_version", 1)?;
        }
        if version < 2 {
            tx.execute_batch(SCHEMA_V2)?;
            tx.execute(
                "INSERT OR REPLACE INTO schema_migrations(version, applied_at_ms) VALUES (2, ?1)",
                params![now_ms()],
            )?;
            tx.pragma_update(None, "user_version", 2)?;
        }
        tx.commit()?;
        Ok(())
    }

    // ----------------------------------------------------------------- events

    pub fn insert_event(&self, event: &SecurityEvent) -> Result<(), StorageError> {
        let conn = self.conn.lock()?;
        let payload = serde_json::to_string(event)?;
        let process_pid = event.process.as_ref().map(|p| p.pid as i64);
        let file_path = event.file.as_ref().map(|f| f.path.clone());
        let file_sha256 = event.file.as_ref().and_then(|f| f.sha256.clone());
        conn.execute(
            "INSERT OR REPLACE INTO security_events
             (id, timestamp_ms, kind, severity, source, title, description, correlation_id, process_pid, file_path, file_sha256, data)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)",
            params![
                event.id,
                event.timestamp_ms,
                event.kind.as_str(),
                event.severity.as_str(),
                serde_json::to_value(event.source)?,
                event.title,
                event.description,
                event.correlation_id,
                process_pid,
                file_path,
                file_sha256,
                payload,
            ],
        )?;

        if let Some(process) = &event.process {
            conn.execute(
                "INSERT INTO processes(event_id, pid, name, path, sha256, parent_pid, first_seen_ms, last_seen_ms)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?7)
                 ON CONFLICT(pid, sha256) DO UPDATE SET
                   last_seen_ms = excluded.last_seen_ms,
                   name = excluded.name,
                   path = COALESCE(excluded.path, processes.path)",
                params![
                    event.id,
                    process.pid as i64,
                    process.name,
                    process.path,
                    process.sha256,
                    process.parent_pid.map(|p| p as i64),
                    event.timestamp_ms,
                ],
            )?;
        }

        for detection in &event.detections {
            conn.execute(
                "INSERT OR REPLACE INTO detections
                 (id, event_id, rule_id, rule_name, source, severity, description, score, created_at_ms)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)",
                params![
                    detection.id,
                    event.id,
                    detection.rule_id,
                    detection.rule_name,
                    serde_json::to_value(detection.source)?,
                    detection.severity.as_str(),
                    detection.description,
                    detection.score_contribution as f64,
                    detection.created_at_ms,
                ],
            )?;
        }
        Ok(())
    }

    pub fn get_event(&self, id: &str) -> Result<Option<SecurityEvent>, StorageError> {
        let conn = self.conn.lock()?;
        let data: Option<String> = conn
            .query_row(
                "SELECT data FROM security_events WHERE id = ?1",
                params![id],
                |row| row.get(0),
            )
            .optional()?;
        match data {
            Some(json) => Ok(Some(serde_json::from_str(&json)?)),
            None => Ok(None),
        }
    }

    pub fn events_by_correlation(
        &self,
        correlation_id: &str,
    ) -> Result<Vec<SecurityEvent>, StorageError> {
        self.query_events(
            &EventFilter {
                correlation_id: Some(correlation_id.to_string()),
                limit: 200,
                ..Default::default()
            }
            .bounded(),
        )
        .map(|page| page.items)
    }

    pub fn query_events(&self, filter: &EventFilter) -> Result<EventPage, StorageError> {
        let filter = filter.clone().bounded();
        let conn = self.conn.lock()?;

        let mut where_parts = vec!["1=1".to_string()];
        let mut count_params: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();
        if let Some(severity) = &filter.severity {
            where_parts.push(format!("severity = ?{}", count_params.len() + 1));
            count_params.push(Box::new(severity.as_str().to_string()));
        }
        if let Some(kind) = &filter.kind {
            where_parts.push(format!("kind = ?{}", count_params.len() + 1));
            count_params.push(Box::new(kind.as_str().to_string()));
        }
        if let Some(correlation) = &filter.correlation_id {
            where_parts.push(format!("correlation_id = ?{}", count_params.len() + 1));
            count_params.push(Box::new(correlation.clone()));
        }
        if let Some(since) = filter.since_ms {
            where_parts.push(format!("timestamp_ms >= ?{}", count_params.len() + 1));
            count_params.push(Box::new(since));
        }
        if let Some(search) = &filter.search {
            if !search.trim().is_empty() {
                let idx = count_params.len() + 1;
                where_parts.push(format!(
                    "(title LIKE ?{idx} OR description LIKE ?{idx} OR file_path LIKE ?{idx} OR id LIKE ?{idx})"
                ));
                count_params.push(Box::new(format!("%{}%", search.trim())));
            }
        }
        let where_sql = where_parts.join(" AND ");
        let param_refs: Vec<&dyn rusqlite::ToSql> =
            count_params.iter().map(|b| b.as_ref()).collect();

        let total_i: i64 = conn.query_row(
            &format!("SELECT COUNT(*) FROM security_events WHERE {where_sql}"),
            param_refs.as_slice(),
            |row| row.get(0),
        )?;
        let total = total_i as u64;

        let mut page_params: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();
        for p in &count_params {
            page_params.push(Box::new(SqlFwd(p.as_ref())));
        }
        let limit_idx = page_params.len() + 1;
        page_params.push(Box::new(filter.limit as i64));
        let offset_idx = page_params.len() + 1;
        page_params.push(Box::new(filter.offset as i64));
        let page_refs: Vec<&dyn rusqlite::ToSql> = page_params.iter().map(|b| b.as_ref()).collect();

        let sql = format!(
            "SELECT data FROM security_events WHERE {where_sql}
             ORDER BY timestamp_ms DESC, id DESC LIMIT ?{limit_idx} OFFSET ?{offset_idx}"
        );
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map(page_refs.as_slice(), |row| row.get::<_, String>(0))?;
        let mut items = Vec::new();
        for row in rows {
            items.push(serde_json::from_str(&row?)?);
        }
        let next = if (filter.offset as u64 + items.len() as u64) < total {
            Some(filter.offset + items.len() as u32)
        } else {
            None
        };
        Ok(EventPage {
            items,
            total,
            next_offset: next,
        })
    }

    pub fn purge_events_older_than(&self, timestamp_ms: TimestampMs) -> Result<u64, StorageError> {
        let conn = self.conn.lock()?;
        let removed = conn.execute(
            "DELETE FROM security_events WHERE timestamp_ms < ?1",
            params![timestamp_ms],
        )?;
        conn.execute(
            "DELETE FROM detections WHERE event_id NOT IN (SELECT id FROM security_events)",
            [],
        )?;
        conn.execute(
            "DELETE FROM decision_results WHERE event_id IS NOT NULL AND event_id NOT IN (SELECT id FROM security_events)",
            [],
        )?;
        Ok(removed as u64)
    }

    // ------------------------------------------------------------- scan jobs

    pub fn insert_scan_job(&self, job: &ScanJobSummary) -> Result<(), StorageError> {
        let conn = self.conn.lock()?;
        let data = serde_json::to_string(job)?;
        conn.execute(
            "INSERT OR REPLACE INTO scan_jobs
             (id, path, recursive, state, started_at_ms, finished_at_ms, files_scanned, detections, errors, current_path, cancelled, data)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)",
            params![
                job.id,
                job.path,
                job.recursive as i64,
                serde_json::to_value(job.state)?,
                job.started_at_ms,
                job.finished_at_ms,
                job.files_scanned as i64,
                job.detections as i64,
                job.errors as i64,
                job.current_path,
                job.cancelled as i64,
                data,
            ],
        )?;
        Ok(())
    }

    pub fn update_scan_job(&self, job: &ScanJobSummary) -> Result<(), StorageError> {
        self.insert_scan_job(job)
    }

    pub fn list_scan_jobs(&self, limit: u32) -> Result<Vec<ScanJobSummary>, StorageError> {
        let conn = self.conn.lock()?;
        let mut stmt =
            conn.prepare("SELECT data FROM scan_jobs ORDER BY started_at_ms DESC LIMIT ?1")?;
        let rows = stmt.query_map(params![limit.clamp(1, 500) as i64], |row| {
            row.get::<_, String>(0)
        })?;
        let mut jobs = Vec::new();
        for row in rows {
            jobs.push(serde_json::from_str(&row?)?);
        }
        Ok(jobs)
    }

    pub fn get_scan_job(&self, id: &str) -> Result<Option<ScanJobSummary>, StorageError> {
        let conn = self.conn.lock()?;
        let data: Option<String> = conn
            .query_row(
                "SELECT data FROM scan_jobs WHERE id = ?1",
                params![id],
                |row| row.get(0),
            )
            .optional()?;
        Ok(match data {
            Some(json) => Some(serde_json::from_str(&json)?),
            None => None,
        })
    }

    pub fn insert_scan_result(
        &self,
        job_id: &str,
        report: &FileScanReport,
    ) -> Result<(), StorageError> {
        let conn = self.conn.lock()?;
        let data = serde_json::to_string(report)?;
        conn.execute(
            "INSERT OR REPLACE INTO scan_results
             (id, job_id, file_sha256, path, size, score, report, created_at_ms)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
            params![
                report.id,
                job_id,
                report.file.sha256,
                report.file.path,
                report.file.size as i64,
                report.assessment.score as f64,
                data,
                report.scanned_at_ms,
            ],
        )?;
        Ok(())
    }

    pub fn scan_results_for_job(
        &self,
        job_id: &str,
        limit: u32,
    ) -> Result<Vec<FileScanReport>, StorageError> {
        let conn = self.conn.lock()?;
        let mut stmt = conn.prepare(
            "SELECT report FROM scan_results WHERE job_id = ?1
             ORDER BY score DESC, created_at_ms DESC LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![job_id, limit.clamp(1, 2000) as i64], |row| {
            row.get::<_, String>(0)
        })?;
        let mut reports = Vec::new();
        for row in rows {
            reports.push(serde_json::from_str(&row?)?);
        }
        Ok(reports)
    }

    /// Cached scan report lookup by content identity. A report is reusable
    /// regardless of path because the hash and size identify the bytes.
    pub fn find_cached_report(
        &self,
        sha256: &str,
        size: u64,
    ) -> Result<Option<FileScanReport>, StorageError> {
        let conn = self.conn.lock()?;
        let data: Option<String> = conn
            .query_row(
                "SELECT report FROM scan_results WHERE file_sha256 = ?1 AND size = ?2
                 ORDER BY created_at_ms DESC LIMIT 1",
                params![sha256, size as i64],
                |row| row.get(0),
            )
            .optional()?;
        Ok(match data {
            Some(json) => Some(serde_json::from_str(&json)?),
            None => None,
        })
    }

    // -------------------------------------------------------------- decisions

    pub fn insert_decision(
        &self,
        event_id: Option<&str>,
        decision: &DecisionResult,
    ) -> Result<(), StorageError> {
        let conn = self.conn.lock()?;
        let data = serde_json::to_string(decision)?;
        conn.execute(
            "INSERT OR REPLACE INTO decision_results
             (id, event_id, provider, model, category, confidence, requires_investigation, data, created_at_ms)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)",
            params![
                decision.id,
                event_id,
                decision.provider,
                decision.model,
                serde_json::to_value(decision.category)?,
                decision.confidence as f64,
                decision.requires_investigation as i64,
                data,
                decision.timestamp_ms,
            ],
        )?;
        Ok(())
    }

    pub fn decisions_for_event(&self, event_id: &str) -> Result<Vec<DecisionResult>, StorageError> {
        let conn = self.conn.lock()?;
        let mut stmt = conn.prepare(
            "SELECT data FROM decision_results WHERE event_id = ?1 ORDER BY created_at_ms DESC",
        )?;
        let rows = stmt.query_map(params![event_id], |row| row.get::<_, String>(0))?;
        let mut decisions = Vec::new();
        for row in rows {
            decisions.push(serde_json::from_str(&row?)?);
        }
        Ok(decisions)
    }

    pub fn recent_decisions(&self, limit: u32) -> Result<Vec<DecisionResult>, StorageError> {
        let conn = self.conn.lock()?;
        let mut stmt =
            conn.prepare("SELECT data FROM decision_results ORDER BY created_at_ms DESC LIMIT ?1")?;
        let rows = stmt.query_map(params![limit.clamp(1, 500) as i64], |row| {
            row.get::<_, String>(0)
        })?;
        let mut decisions = Vec::new();
        for row in rows {
            decisions.push(serde_json::from_str(&row?)?);
        }
        Ok(decisions)
    }

    // ------------------------------------------------------------ quarantine

    pub fn insert_quarantine(&self, record: &QuarantineRecord) -> Result<(), StorageError> {
        let conn = self.conn.lock()?;
        let data = serde_json::to_string(record)?;
        conn.execute(
            "INSERT OR REPLACE INTO quarantine_records
             (id, original_path, original_name, stored_path, sha256, size, quarantined_at_ms, status, restored_at_ms, detection_id, reason, identity_verified, data)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)",
            params![
                record.id,
                record.original_path,
                record.original_name,
                record.stored_path,
                record.sha256,
                record.size as i64,
                record.quarantined_at_ms,
                serde_json::to_value(record.status)?,
                record.restored_at_ms,
                record.detection_id,
                record.reason,
                record.identity_verified as i64,
                data,
            ],
        )?;
        Ok(())
    }

    pub fn update_quarantine_status(
        &self,
        id: &str,
        status: QuarantineStatus,
        restored_at_ms: Option<TimestampMs>,
    ) -> Result<(), StorageError> {
        let mut conn = self.conn.lock()?;
        let tx = conn.transaction()?;
        let data: Option<String> = tx
            .query_row(
                "SELECT data FROM quarantine_records WHERE id = ?1",
                params![id],
                |row| row.get(0),
            )
            .optional()?;
        let Some(json) = data else {
            return Err(StorageError::NotFound(id.to_string()));
        };
        let mut record: QuarantineRecord = serde_json::from_str(&json)?;
        record.status = status;
        record.restored_at_ms = restored_at_ms.or(record.restored_at_ms);
        let updated = serde_json::to_string(&record)?;
        tx.execute(
            "UPDATE quarantine_records SET status = ?2, restored_at_ms = ?3, data = ?4 WHERE id = ?1",
            params![
                id,
                serde_json::to_value(status)?,
                record.restored_at_ms,
                updated
            ],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn get_quarantine(&self, id: &str) -> Result<Option<QuarantineRecord>, StorageError> {
        let conn = self.conn.lock()?;
        let mut stmt = conn.prepare("SELECT data FROM quarantine_records WHERE id = ?1 LIMIT 1")?;
        let mut rows = stmt.query_map(params![id], |row| row.get::<_, String>(0))?;
        match rows.next() {
            Some(row) => Ok(Some(serde_json::from_str(&row?)?)),
            None => Ok(None),
        }
    }

    pub fn list_quarantine(&self, limit: u32) -> Result<Vec<QuarantineRecord>, StorageError> {
        let conn = self.conn.lock()?;
        let mut stmt = conn.prepare(
            "SELECT data FROM quarantine_records ORDER BY quarantined_at_ms DESC LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![limit.clamp(1, 1000) as i64], |row| {
            row.get::<_, String>(0)
        })?;
        let mut records = Vec::new();
        for row in rows {
            records.push(serde_json::from_str(&row?)?);
        }
        Ok(records)
    }

    // ------------------------------------------------------------------- ai

    pub fn upsert_provider_health(&self, health: &ProviderHealth) -> Result<(), StorageError> {
        let conn = self.conn.lock()?;
        conn.execute(
            "INSERT OR REPLACE INTO provider_health
             (provider, model, status, successes, failures, last_latency_ms, last_error, total_cost_usd, requests, checked_at_ms)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
            params![
                health.provider,
                health.model,
                serde_json::to_value(health.status)?,
                health.successes as i64,
                health.failures as i64,
                health.last_latency_ms.map(|v| v as i64),
                health.last_error,
                health.total_cost_usd,
                health.requests as i64,
                health.checked_at_ms,
            ],
        )?;
        Ok(())
    }

    pub fn provider_health(&self) -> Result<Vec<ProviderHealth>, StorageError> {
        let conn = self.conn.lock()?;
        let mut stmt = conn.prepare(
            "SELECT provider, model, status, successes, failures, last_latency_ms, last_error,
                    total_cost_usd, requests, checked_at_ms
             FROM provider_health ORDER BY provider, model",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(ProviderHealth {
                provider: row.get(0)?,
                model: row.get(1)?,
                status: serde_json::from_str(
                    &row.get::<_, String>(2)
                        .unwrap_or_else(|_| "\"unknown\"".to_string()),
                )
                .unwrap_or(ProviderStatus::Unknown),
                successes: row.get::<_, i64>(3)? as u64,
                failures: row.get::<_, i64>(4)? as u64,
                last_latency_ms: row.get::<_, Option<i64>>(5)?.map(|v| v as u64),
                last_error: row.get(6)?,
                total_cost_usd: row.get(7)?,
                requests: row.get::<_, i64>(8)? as u64,
                checked_at_ms: row.get(9)?,
            })
        })?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    // -------------------------------------------------------------- settings

    pub fn get_setting(&self, key: &str) -> Result<Option<String>, StorageError> {
        let conn = self.conn.lock()?;
        let value = conn
            .query_row(
                "SELECT value FROM application_settings WHERE key = ?1",
                params![key],
                |row| row.get(0),
            )
            .optional()?;
        Ok(value)
    }

    pub fn set_setting(&self, key: &str, value: &str) -> Result<(), StorageError> {
        let conn = self.conn.lock()?;
        conn.execute(
            "INSERT OR REPLACE INTO application_settings(key, value, updated_at_ms) VALUES (?1, ?2, ?3)",
            params![key, value, now_ms()],
        )?;
        Ok(())
    }

    pub fn all_settings(&self) -> Result<std::collections::BTreeMap<String, String>, StorageError> {
        let conn = self.conn.lock()?;
        let mut stmt = conn.prepare("SELECT key, value FROM application_settings")?;
        let rows = stmt.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?;
        let mut map = std::collections::BTreeMap::new();
        for row in rows {
            let (key, value) = row?;
            map.insert(key, value);
        }
        Ok(map)
    }

    /// Recent counts for the overview page.
    pub fn stats(&self) -> Result<StorageStats, StorageError> {
        let conn = self.conn.lock()?;
        let events =
            conn.query_row::<i64, _, _>("SELECT COUNT(*) FROM security_events", [], |r| r.get(0))?
                as u64;
        let detections =
            conn.query_row::<i64, _, _>("SELECT COUNT(*) FROM detections", [], |r| r.get(0))?
                as u64;
        let quarantine = conn.query_row::<i64, _, _>(
            "SELECT COUNT(*) FROM quarantine_records WHERE status = 'quarantined'",
            [],
            |r| r.get(0),
        )? as u64;
        let scans =
            conn.query_row::<i64, _, _>("SELECT COUNT(*) FROM scan_jobs", [], |r| r.get(0))? as u64;
        Ok(StorageStats {
            events,
            detections,
            quarantined: quarantine,
            scans,
        })
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StorageStats {
    pub events: u64,
    pub detections: u64,
    pub quarantined: u64,
    pub scans: u64,
}

pub fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

/// Wrapper that lets a boxed `ToSql` be re-borrowed for a second statement.
struct SqlFwd<'a>(&'a dyn rusqlite::ToSql);

impl rusqlite::ToSql for SqlFwd<'_> {
    fn to_sql(&self) -> rusqlite::Result<rusqlite::types::ToSqlOutput<'_>> {
        self.0.to_sql()
    }
}

const SCHEMA_V2: &str = r#"
ALTER TABLE security_events ADD COLUMN description TEXT NOT NULL DEFAULT '';
"#;

const SCHEMA_V1: &str = r#"
CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY,
    applied_at_ms INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS security_events (
    id TEXT PRIMARY KEY,
    timestamp_ms INTEGER NOT NULL,
    kind TEXT NOT NULL,
    severity TEXT NOT NULL,
    source TEXT NOT NULL,
    title TEXT NOT NULL,
    correlation_id TEXT,
    process_pid INTEGER,
    file_path TEXT,
    file_sha256 TEXT,
    data TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON security_events(timestamp_ms DESC);
CREATE INDEX IF NOT EXISTS idx_events_kind ON security_events(kind);
CREATE INDEX IF NOT EXISTS idx_events_severity ON security_events(severity);
CREATE INDEX IF NOT EXISTS idx_events_correlation ON security_events(correlation_id);
CREATE INDEX IF NOT EXISTS idx_events_sha ON security_events(file_sha256);

CREATE TABLE IF NOT EXISTS processes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT NOT NULL,
    pid INTEGER NOT NULL,
    name TEXT NOT NULL,
    path TEXT,
    sha256 TEXT,
    parent_pid INTEGER,
    first_seen_ms INTEGER NOT NULL,
    last_seen_ms INTEGER NOT NULL,
    UNIQUE(pid, sha256)
);
CREATE INDEX IF NOT EXISTS idx_processes_pid ON processes(pid);
CREATE INDEX IF NOT EXISTS idx_processes_sha ON processes(sha256);

CREATE TABLE IF NOT EXISTS process_relationships (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    parent_pid INTEGER NOT NULL,
    child_pid INTEGER NOT NULL,
    event_id TEXT NOT NULL,
    created_at_ms INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_rel_parent ON process_relationships(parent_pid);
CREATE INDEX IF NOT EXISTS idx_rel_child ON process_relationships(child_pid);

CREATE TABLE IF NOT EXISTS files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sha256 TEXT NOT NULL,
    path TEXT,
    size INTEGER NOT NULL,
    first_seen_ms INTEGER NOT NULL,
    last_seen_ms INTEGER NOT NULL,
    UNIQUE(sha256, size)
);

CREATE TABLE IF NOT EXISTS scan_results (
    id TEXT PRIMARY KEY,
    job_id TEXT NOT NULL,
    file_sha256 TEXT,
    path TEXT NOT NULL,
    size INTEGER NOT NULL,
    score REAL NOT NULL,
    report TEXT NOT NULL,
    created_at_ms INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_results_sha ON scan_results(file_sha256, size);
CREATE INDEX IF NOT EXISTS idx_results_job ON scan_results(job_id);

CREATE TABLE IF NOT EXISTS detections (
    id TEXT PRIMARY KEY,
    event_id TEXT,
    rule_id TEXT NOT NULL,
    rule_name TEXT NOT NULL,
    source TEXT NOT NULL,
    severity TEXT NOT NULL,
    description TEXT NOT NULL,
    score REAL NOT NULL,
    created_at_ms INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_detections_event ON detections(event_id);
CREATE INDEX IF NOT EXISTS idx_detections_rule ON detections(rule_id);

CREATE TABLE IF NOT EXISTS decision_results (
    id TEXT PRIMARY KEY,
    event_id TEXT,
    provider TEXT NOT NULL,
    model TEXT NOT NULL,
    category TEXT NOT NULL,
    confidence REAL NOT NULL,
    requires_investigation INTEGER NOT NULL,
    data TEXT NOT NULL,
    created_at_ms INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_decisions_event ON decision_results(event_id);

CREATE TABLE IF NOT EXISTS quarantine_records (
    id TEXT PRIMARY KEY,
    original_path TEXT NOT NULL,
    original_name TEXT NOT NULL,
    stored_path TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    size INTEGER NOT NULL,
    quarantined_at_ms INTEGER NOT NULL,
    status TEXT NOT NULL,
    restored_at_ms INTEGER,
    detection_id TEXT,
    reason TEXT NOT NULL,
    identity_verified INTEGER NOT NULL,
    data TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_quarantine_status ON quarantine_records(status);

CREATE TABLE IF NOT EXISTS scan_jobs (
    id TEXT PRIMARY KEY,
    path TEXT NOT NULL,
    recursive INTEGER NOT NULL,
    state TEXT NOT NULL,
    started_at_ms INTEGER NOT NULL,
    finished_at_ms INTEGER,
    files_scanned INTEGER NOT NULL,
    detections INTEGER NOT NULL,
    errors INTEGER NOT NULL,
    current_path TEXT,
    cancelled INTEGER NOT NULL,
    data TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_jobs_started ON scan_jobs(started_at_ms DESC);

CREATE TABLE IF NOT EXISTS application_settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at_ms INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS provider_health (
    provider TEXT NOT NULL,
    model TEXT NOT NULL,
    status TEXT NOT NULL,
    successes INTEGER NOT NULL,
    failures INTEGER NOT NULL,
    last_latency_ms INTEGER,
    last_error TEXT,
    total_cost_usd REAL NOT NULL,
    requests INTEGER NOT NULL,
    checked_at_ms INTEGER NOT NULL,
    PRIMARY KEY (provider, model)
);
"#;

#[cfg(test)]
mod tests {
    use super::*;
    use security_core::{
        Detection, DetectionSource, ProcessRef, RiskAssessment, RiskSignals, ScanState,
        TelemetrySource,
    };

    fn sample_event() -> SecurityEvent {
        let mut event = SecurityEvent::new(
            SecurityEventKind::ProcessCreated,
            Severity::Medium,
            TelemetrySource::ProcessSnapshot,
            "unsigned.exe started",
        );
        event.description = "A test event".into();
        event.process = Some(ProcessRef {
            pid: 4242,
            name: "unsigned.exe".into(),
            path: Some(r"C:\Temp\unsigned.exe".into()),
            parent_pid: Some(1000),
            parent_name: Some("explorer.exe".into()),
            ..Default::default()
        });
        event.detections.push(Detection {
            id: security_core::new_id("det"),
            rule_id: "TEST_RULE".into(),
            rule_name: "Test rule".into(),
            source: DetectionSource::BehaviorRule,
            severity: Severity::Medium,
            description: "test detection".into(),
            score_contribution: 25.0,
            evidence: vec!["test".into()],
            created_at_ms: now_ms(),
        });
        event.assessment = Some(RiskAssessment::from_signals(RiskSignals {
            unsigned_executable: true,
            ..Default::default()
        }));
        event
    }

    #[test]
    fn migrates_and_reports_version() {
        let db = Database::open_in_memory().unwrap();
        assert_eq!(db.schema_version().unwrap(), CURRENT_SCHEMA_VERSION);
        // Re-running migration is a no-op.
        let db2 = Database::open_in_memory().unwrap();
        assert_eq!(db2.schema_version().unwrap(), CURRENT_SCHEMA_VERSION);
    }

    #[test]
    fn inserts_and_filters_events() {
        let db = Database::open_in_memory().unwrap();
        let event = sample_event();
        db.insert_event(&event).unwrap();
        let fetched = db.get_event(&event.id).unwrap().unwrap();
        assert_eq!(fetched.title, event.title);
        assert_eq!(fetched.process.unwrap().pid, 4242);

        let page = db
            .query_events(
                &EventFilter {
                    kind: Some(SecurityEventKind::ProcessCreated),
                    ..Default::default()
                }
                .bounded(),
            )
            .unwrap();
        assert_eq!(page.total, 1);
        assert_eq!(page.items.len(), 1);

        let empty = db
            .query_events(
                &EventFilter {
                    severity: Some(Severity::Critical),
                    ..Default::default()
                }
                .bounded(),
            )
            .unwrap();
        assert_eq!(empty.total, 0);

        let search = db
            .query_events(
                &EventFilter {
                    search: Some("unsigned".into()),
                    ..Default::default()
                }
                .bounded(),
            )
            .unwrap();
        assert_eq!(search.total, 1);
    }

    #[test]
    fn caches_scan_reports_by_hash() {
        let db = Database::open_in_memory().unwrap();
        let report = FileScanReport {
            id: security_core::new_id("scan"),
            file: security_core::FileRef {
                path: r"C:\Temp\a.bin".into(),
                name: "a.bin".into(),
                size: 10,
                sha256: Some("ab".repeat(32)),
                ..Default::default()
            },
            detections: vec![],
            assessment: RiskAssessment::from_signals(RiskSignals::default()),
            source: security_core::ScanSource::Manual,
            duration_ms: 3,
            scanned_at_ms: now_ms(),
            cache_hit: false,
            errors: vec![],
        };
        db.insert_scan_result("job1", &report).unwrap();
        let cached = db
            .find_cached_report(&"ab".repeat(32), 10)
            .unwrap()
            .unwrap();
        assert_eq!(cached.file.name, "a.bin");
        assert!(db
            .find_cached_report(&"cd".repeat(32), 10)
            .unwrap()
            .is_none());
    }

    #[test]
    fn jobs_settings_and_health() {
        let db = Database::open_in_memory().unwrap();
        let job = ScanJobSummary {
            id: "job1".into(),
            path: "C:\\".into(),
            recursive: true,
            state: ScanState::Running,
            started_at_ms: now_ms(),
            finished_at_ms: None,
            files_scanned: 0,
            detections: 0,
            errors: 0,
            current_path: None,
            cancelled: false,
        };
        db.insert_scan_job(&job).unwrap();
        let mut done = job.clone();
        done.state = ScanState::Completed;
        done.files_scanned = 12;
        db.update_scan_job(&done).unwrap();
        assert_eq!(db.list_scan_jobs(10).unwrap()[0].files_scanned, 12);

        db.set_setting("theme", "dark").unwrap();
        assert_eq!(db.get_setting("theme").unwrap().as_deref(), Some("dark"));

        let health = ProviderHealth {
            provider: "test".into(),
            model: "mock".into(),
            status: ProviderStatus::Healthy,
            successes: 1,
            failures: 0,
            last_latency_ms: Some(12),
            last_error: None,
            total_cost_usd: 0.0,
            requests: 1,
            checked_at_ms: now_ms(),
        };
        db.upsert_provider_health(&health).unwrap();
        assert_eq!(db.provider_health().unwrap().len(), 1);

        let stats = db.stats().unwrap();
        assert_eq!(stats.scans, 1);
    }

    #[test]
    fn purge_removes_old_events() {
        let db = Database::open_in_memory().unwrap();
        let mut event = sample_event();
        event.timestamp_ms = 1;
        db.insert_event(&event).unwrap();
        let removed = db.purge_events_older_than(1000).unwrap();
        assert_eq!(removed, 1);
        assert!(db.get_event(&event.id).unwrap().is_none());
    }
}

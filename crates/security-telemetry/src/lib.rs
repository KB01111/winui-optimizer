//! Telemetry collection and behavior correlation.
//!
//! Scope and honesty:
//! - `WindowsProcessSnapshot` observes process creation/termination by diffing
//!   Toolhelp32 snapshots. It is *observational*; it does not intercept or block
//!   process creation.
//! - `EventLogReader` reads documented Windows Event Log channels
//!   (PowerShell script-block logging and Defender operational events). Those
//!   channels are only present when the corresponding logging is enabled, so the
//!   reader reports `available() == false` instead of pretending coverage.
//! - `CorrelationEngine` is deterministic. It never calls AI and is fully
//!   unit-testable with synthetic events.

use security_core::{
    new_id, RiskAssessment, RiskLevel, RiskSignals, SecurityEvent, SecurityEventKind, Severity,
    TelemetrySource,
};
use std::collections::HashMap;

#[derive(Debug, thiserror::Error)]
pub enum TelemetryError {
    #[error("telemetry unsupported on this platform: {0}")]
    Unsupported(String),
    #[error("windows api error: {0}")]
    Windows(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

/// Where process snapshots come from. The Windows implementation is real; the
/// synthetic one exists for tests and for explicit demo mode.
pub trait ProcessSnapshotProvider: Send + Sync {
    fn snapshot(&self) -> Result<Vec<security_core::ProcessRef>, TelemetryError>;
    fn source_name(&self) -> &'static str;
}

/// Deterministic, scriptable provider used by tests and by the service when
/// running in `--console --synthetic` development mode.
#[derive(Debug, Default)]
pub struct SyntheticProcessSnapshot {
    processes: std::sync::Mutex<Vec<security_core::ProcessRef>>,
}

impl SyntheticProcessSnapshot {
    pub fn new(processes: Vec<security_core::ProcessRef>) -> Self {
        Self {
            processes: std::sync::Mutex::new(processes),
        }
    }

    pub fn set(&self, processes: Vec<security_core::ProcessRef>) {
        if let Ok(mut guard) = self.processes.lock() {
            *guard = processes;
        }
    }
}

impl ProcessSnapshotProvider for SyntheticProcessSnapshot {
    fn snapshot(&self) -> Result<Vec<security_core::ProcessRef>, TelemetryError> {
        Ok(self.processes.lock().map(|g| g.clone()).unwrap_or_default())
    }

    fn source_name(&self) -> &'static str {
        "synthetic"
    }
}

#[cfg(windows)]
mod win_snapshot {
    use super::*;
    use security_core::ProcessRef;
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
        TH32CS_SNAPPROCESS,
    };
    use windows::Win32::System::Threading::{
        OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_FORMAT,
        PROCESS_QUERY_LIMITED_INFORMATION,
    };

    /// Win32 `MAX_PATH` is not re-exported consistently across `windows` crate
    /// versions; we use the documented value (paths can be longer, so the
    /// buffer is deliberately generous).
    const MAX_PATH: usize = 260;

    pub struct WindowsProcessSnapshot;

    impl Default for WindowsProcessSnapshot {
        fn default() -> Self {
            Self
        }
    }

    impl WindowsProcessSnapshot {
        pub fn new() -> Self {
            Self
        }
    }

    impl ProcessSnapshotProvider for WindowsProcessSnapshot {
        fn snapshot(&self) -> Result<Vec<ProcessRef>, TelemetryError> {
            let mut processes = Vec::new();
            unsafe {
                let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
                    .map_err(|e| TelemetryError::Windows(e.to_string()))?;
                let mut entry = PROCESSENTRY32W {
                    dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
                    ..Default::default()
                };
                if Process32FirstW(snapshot, &mut entry).is_ok() {
                    loop {
                        let name = wide_to_string(&entry.szExeFile);
                        let mut path = None;
                        if let Ok(handle) = OpenProcess(
                            PROCESS_QUERY_LIMITED_INFORMATION,
                            false,
                            entry.th32ProcessID,
                        ) {
                            if !handle.is_invalid() {
                                path = query_image_path(handle);
                                let _ = CloseHandle(handle);
                            }
                        }
                        processes.push(ProcessRef {
                            pid: entry.th32ProcessID,
                            name,
                            path,
                            parent_pid: Some(entry.th32ParentProcessID),
                            ..Default::default()
                        });
                        if Process32NextW(snapshot, &mut entry).is_err() {
                            break;
                        }
                    }
                }
                let _ = CloseHandle(snapshot);
            }
            Ok(processes)
        }

        fn source_name(&self) -> &'static str {
            "windows-toolhelp32"
        }
    }

    fn wide_to_string(wide: &[u16]) -> String {
        let end = wide.iter().position(|c| *c == 0).unwrap_or(wide.len());
        String::from_utf16_lossy(&wide[..end])
    }

    fn query_image_path(handle: HANDLE) -> Option<String> {
        let mut buffer = vec![0u16; MAX_PATH * 4];
        let mut size = buffer.len() as u32;
        unsafe {
            QueryFullProcessImageNameW(
                handle,
                PROCESS_NAME_FORMAT(0),
                windows::core::PWSTR(buffer.as_mut_ptr()),
                &mut size,
            )
            .ok()?;
        }
        Some(wide_to_string(&buffer[..size as usize]))
    }
}

#[cfg(windows)]
pub use win_snapshot::WindowsProcessSnapshot;

/// Fallback provider for non-Windows builds and for tests on other platforms.
pub struct UnsupportedProcessSnapshot;

impl ProcessSnapshotProvider for UnsupportedProcessSnapshot {
    fn snapshot(&self) -> Result<Vec<security_core::ProcessRef>, TelemetryError> {
        Err(TelemetryError::Unsupported(
            "process snapshots require Windows".into(),
        ))
    }

    fn source_name(&self) -> &'static str {
        "unsupported"
    }
}

/// Diffs two snapshots and emits process lifecycle events.
pub struct ProcessMonitor {
    provider: Box<dyn ProcessSnapshotProvider>,
    known: HashMap<u32, security_core::ProcessRef>,
    primed: bool,
    dropped_observations: u64,
}

impl ProcessMonitor {
    pub fn new(provider: Box<dyn ProcessSnapshotProvider>) -> Self {
        Self {
            provider,
            known: HashMap::new(),
            primed: false,
            dropped_observations: 0,
        }
    }

    pub fn provider_name(&self) -> &'static str {
        self.provider.source_name()
    }

    pub fn dropped_observations(&self) -> u64 {
        self.dropped_observations
    }

    /// First poll primes the baseline and returns no events. Provider errors are
    /// counted, never propagated as panics.
    pub fn poll(&mut self) -> Vec<SecurityEvent> {
        let snapshot = match self.provider.snapshot() {
            Ok(snapshot) => snapshot,
            Err(error) => {
                self.dropped_observations = self.dropped_observations.saturating_add(1);
                tracing::debug!(%error, "process snapshot unavailable");
                return Vec::new();
            }
        };

        if !self.primed {
            self.known = snapshot.into_iter().map(|p| (p.pid, p)).collect();
            self.primed = true;
            return Vec::new();
        }

        let mut events = Vec::new();
        let mut seen = HashMap::new();
        for process in snapshot {
            if !self.known.contains_key(&process.pid) {
                let mut event = SecurityEvent::new(
                    SecurityEventKind::ProcessCreated,
                    Severity::Info,
                    TelemetrySource::ProcessSnapshot,
                    format!("Process created: {}", process.name),
                );
                event.description = format!(
                    "PID {} started{}",
                    process.pid,
                    process
                        .path
                        .as_deref()
                        .map(|p| format!(" from {p}"))
                        .unwrap_or_default()
                );
                event.process = Some(process.clone());
                let mut signals = RiskSignals::default();
                if process.signed == Some(false) {
                    signals.unsigned_executable = true;
                }
                if let Some(parent) = &process.parent_name {
                    if is_script_host(parent) {
                        signals.suspicious_parent = true;
                    }
                }
                if let Some(path) = &process.path {
                    if is_temp_path(path) {
                        signals.temp_execution = true;
                    }
                    let lower = process.name.to_ascii_lowercase();
                    if is_lolbin(&lower) {
                        signals.living_off_the_land_binary = true;
                    }
                }
                if let Some(assessment) = assessment_for(&signals) {
                    event.severity = severity_for(assessment.score);
                    event.assessment = Some(assessment);
                }
                events.push(event);
            }
            seen.insert(process.pid, process);
        }

        for (pid, process) in &self.known {
            if !seen.contains_key(pid) {
                let mut event = SecurityEvent::new(
                    SecurityEventKind::ProcessTerminated,
                    Severity::Info,
                    TelemetrySource::ProcessSnapshot,
                    format!("Process ended: {}", process.name),
                );
                event.description = format!("PID {pid} terminated");
                event.process = Some(process.clone());
                events.push(event);
            }
        }

        self.known = seen;
        events
    }
}

pub fn is_script_host(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "powershell.exe" | "pwsh.exe" | "wscript.exe" | "cscript.exe" | "mshta.exe"
    )
}

pub fn is_temp_path(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    lower.contains("\\appdata\\local\\temp")
        || lower.contains("\\windows\\temp")
        || lower.contains("\\temp\\")
        || lower.ends_with("\\temp")
}

pub fn is_lolbin(name: &str) -> bool {
    matches!(
        name,
        "powershell.exe"
            | "pwsh.exe"
            | "cmd.exe"
            | "mshta.exe"
            | "rundll32.exe"
            | "regsvr32.exe"
            | "certutil.exe"
            | "bitsadmin.exe"
            | "wmic.exe"
            | "curl.exe"
            | "installutil.exe"
    )
}

fn assessment_for(signals: &RiskSignals) -> Option<RiskAssessment> {
    if signals.deterministic_score() <= 0.0 {
        None
    } else {
        Some(RiskAssessment::from_signals(signals.clone()))
    }
}

fn severity_for(score: f32) -> Severity {
    match RiskLevel::from_score(score) {
        RiskLevel::Critical => Severity::Critical,
        RiskLevel::High => Severity::High,
        RiskLevel::Medium => Severity::Medium,
        RiskLevel::Low => Severity::Low,
        _ => Severity::Info,
    }
}

impl<T: ProcessSnapshotProvider + ?Sized> ProcessSnapshotProvider for std::sync::Arc<T> {
    fn snapshot(&self) -> Result<Vec<security_core::ProcessRef>, TelemetryError> {
        (**self).snapshot()
    }

    fn source_name(&self) -> &'static str {
        (**self).source_name()
    }
}

/// Reads documented Windows Event Log channels. Everything is read-only.
pub struct EventLogReader {
    available: bool,
    channels: Vec<&'static str>,
}

impl EventLogReader {
    pub fn new() -> Result<Self, TelemetryError> {
        Ok(Self {
            // `available` means "the platform exposes the Event Log API and
            // reads are attempted". Individual channels can still be absent or
            // disabled by policy; `poll` simply returns no events for them.
            available: cfg!(windows),
            channels: vec![
                "Microsoft-Windows-PowerShell/Operational",
                "Microsoft-Windows-Windows Defender/Operational",
            ],
        })
    }

    pub fn available(&self) -> bool {
        self.available
    }

    /// Poll new events. The Windows implementation queries the PowerShell
    /// script-block log (4104) and Defender operational log; on platforms where
    /// the API is unavailable this returns an empty vector and leaves
    /// `available()` false.
    pub fn poll(&self, since_ms: i64, max: usize) -> Result<Vec<SecurityEvent>, TelemetryError> {
        #[cfg(windows)]
        {
            win_events::poll_channels(&self.channels, since_ms, max)
        }
        #[cfg(not(windows))]
        {
            let _ = (since_ms, max);
            Err(TelemetryError::Unsupported(
                "Windows Event Log requires Windows".into(),
            ))
        }
    }
}

#[cfg(windows)]
mod win_events {
    use super::*;
    use windows::Win32::System::EventLog::{
        EvtClose, EvtNext, EvtQuery, EvtQueryChannelPath, EvtQueryReverseDirection, EvtRender,
        EvtRenderEventXml, EVT_HANDLE,
    };

    const MAX_RENDER_BYTES: usize = 256 * 1024;

    pub fn poll_channels(
        channels: &[&str],
        since_ms: i64,
        max: usize,
    ) -> Result<Vec<SecurityEvent>, TelemetryError> {
        let mut events = Vec::new();
        for channel in channels {
            let query = format!(
                "*[System[TimeCreated[timediff(@SystemTime) <= {}]]]",
                300_000
            );
            match query_channel(channel, &query, max.saturating_sub(events.len())) {
                Ok(mut found) => {
                    found.retain(|event| event.timestamp_ms >= since_ms || since_ms == 0);
                    events.extend(found);
                }
                Err(error) => {
                    tracing::debug!(channel, %error, "event log channel unavailable");
                }
            }
            if events.len() >= max {
                break;
            }
        }
        events.sort_by_key(|e| e.timestamp_ms);
        Ok(events)
    }

    fn query_channel(
        channel: &str,
        query: &str,
        max: usize,
    ) -> Result<Vec<SecurityEvent>, TelemetryError> {
        if max == 0 {
            return Ok(Vec::new());
        }
        let channel_wide = to_wide(channel);
        let query_wide = to_wide(query);
        unsafe {
            let result_set = EvtQuery(
                None,
                windows::core::PCWSTR(channel_wide.as_ptr()),
                windows::core::PCWSTR(query_wide.as_ptr()),
                EvtQueryChannelPath.0 | EvtQueryReverseDirection.0,
            )
            .map_err(|e| TelemetryError::Windows(e.to_string()))?;

            let mut handles = vec![0isize; max.min(32)];
            let mut returned = 0u32;
            if EvtNext(result_set, handles.as_mut_slice(), 1_000, 0, &mut returned).is_err() {
                let _ = EvtClose(result_set);
                return Ok(Vec::new());
            }

            let mut events = Vec::new();
            for raw in handles.into_iter().take(returned as usize) {
                let handle = EVT_HANDLE(raw);
                if let Some(xml) = render_event(handle) {
                    events.push(parse_event_xml(&xml));
                }
                let _ = EvtClose(handle);
            }
            let _ = EvtClose(result_set);
            Ok(events)
        }
    }

    unsafe fn render_event(handle: EVT_HANDLE) -> Option<String> {
        let mut used = 0u32;
        let mut props = 0u32;
        let mut buffer = vec![0u8; MAX_RENDER_BYTES];
        let ok = EvtRender(
            None,
            handle,
            EvtRenderEventXml.0,
            buffer.len() as u32,
            Some(buffer.as_mut_ptr() as *mut _),
            &mut used,
            &mut props,
        );
        if ok.is_err() {
            return None;
        }
        let wide = std::slice::from_raw_parts(buffer.as_ptr() as *const u16, used as usize / 2);
        Some(
            String::from_utf16_lossy(wide)
                .trim_end_matches('\0')
                .to_string(),
        )
    }

    fn parse_event_xml(xml: &str) -> SecurityEvent {
        let script = extract_data(xml, "ScriptBlockText")
            .or_else(|| extract_data(xml, "Payload"))
            .unwrap_or_default();
        let provider = extract_attribute(xml, "Provider", "Name").unwrap_or_default();
        let timestamp_ms = extract_attribute(xml, "TimeCreated", "SystemTime")
            .and_then(parse_timestamp)
            .unwrap_or_else(|| chrono::Utc::now().timestamp_millis());
        let id = extract_attribute(xml, "EventID", "qualifiers")
            .or_else(|| extract_tag_text(xml, "EventID"))
            .unwrap_or_default();

        let mut event = SecurityEvent::new(
            SecurityEventKind::ScriptActivity,
            Severity::Low,
            TelemetrySource::WindowsEventLog,
            format!("Script activity from {provider} (event {id})"),
        );
        event.timestamp_ms = timestamp_ms;
        event.description = "Windows Event Log script-block observation".into();

        let lower = script.to_ascii_lowercase();
        let mut signals = RiskSignals::default();
        if lower.contains("-enc")
            || lower.contains("frombase64string")
            || lower.contains("iex ")
            || lower.contains("invoke-expression")
            || lower.contains("downloadstring")
        {
            signals.obfuscated_script = true;
        }
        if lower.contains("appdata\\roaming\\microsoft\\windows\\start menu\\programs\\startup")
            || lower.contains("currentversion\\run")
            || lower.contains("schtasks /create")
        {
            signals.persistence_attempt = true;
        }
        if lower.contains("mimikatz")
            || lower.contains("lsass")
            || lower.contains("sekurlsa")
            || lower.contains("sam dump")
        {
            signals.credential_access_indicator = true;
        }
        event.evidence = serde_json::json!({
            "scriptBlockPreview": script.chars().take(500).collect::<String>(),
            "provider": provider,
            "eventId": id,
        });
        if let Some(assessment) = assessment_for(&signals) {
            event.severity = severity_for(assessment.score);
            event.assessment = Some(assessment);
        }
        event
    }

    fn extract_data(xml: &str, name: &str) -> Option<String> {
        let needle = format!("Name=\"{name}\"");
        let start = xml.find(&needle)?;
        let rest = &xml[start..];
        let close = rest.find('>')?;
        let content = &rest[close + 1..];
        let end = content.find("</Data>")?;
        Some(xml_unescape(&content[..end]))
    }

    fn extract_attribute(xml: &str, element: &str, attribute: &str) -> Option<String> {
        let element_start = xml.find(&format!("<{element}"))?;
        let rest = &xml[element_start..];
        let attr_start = rest.find(&format!("{attribute}="))?;
        let after = &rest[attr_start + attribute.len() + 1..];
        let quote = after.chars().next()?;
        if quote != '"' && quote != '\'' {
            return None;
        }
        let value = &after[1..];
        let end = value.find(quote)?;
        Some(xml_unescape(&value[..end]))
    }

    fn extract_tag_text(xml: &str, tag: &str) -> Option<String> {
        let start = xml.find(&format!("<{tag}>"))? + tag.len() + 2;
        let rest = &xml[start..];
        let end = rest.find(&format!("</{tag}>"))?;
        Some(xml_unescape(&rest[..end]))
    }

    fn xml_unescape(value: &str) -> String {
        value
            .replace("&lt;", "<")
            .replace("&gt;", ">")
            .replace("&quot;", "\"")
            .replace("&apos;", "'")
            .replace("&amp;", "&")
    }

    fn parse_timestamp(value: String) -> Option<i64> {
        chrono::DateTime::parse_from_rfc3339(&value)
            .ok()
            .map(|dt| dt.timestamp_millis())
    }

    fn to_wide(value: &str) -> Vec<u16> {
        value.encode_utf16().chain(std::iter::once(0)).collect()
    }
}

/// A correlated process chain shown in the Threat Intelligence page.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProcessChain {
    pub root_pid: u32,
    pub root_name: String,
    pub events: Vec<String>,
    pub signals: RiskSignals,
    pub correlation_id: String,
    pub first_seen_ms: i64,
    pub last_seen_ms: i64,
    pub emitted_score_band: u8,
}

/// Deterministic behavior correlation over observed events.
///
/// Example chain: unsigned executable -> creates PowerShell child ->
/// creates startup persistence -> unusual network activity => correlated
/// high-risk chain. Correlated events are emitted once per score band so a
/// noisy chain does not flood the timeline.
pub struct CorrelationEngine {
    chains: HashMap<u32, ProcessChain>,
    recent: Vec<ProcessChain>,
    window_ms: i64,
}

const BAND_CORRELATION: u8 = 1;
const BAND_ALERT: u8 = 2;
const BAND_CRITICAL: u8 = 3;
impl Default for CorrelationEngine {
    fn default() -> Self {
        Self::new(15 * 60 * 1000)
    }
}

impl CorrelationEngine {
    pub fn new(window_ms: i64) -> Self {
        Self {
            chains: HashMap::new(),
            recent: Vec::new(),
            window_ms,
        }
    }

    pub fn chains(&self) -> Vec<ProcessChain> {
        let mut chains: Vec<_> = self.chains.values().cloned().collect();
        chains.extend(self.recent.iter().cloned());
        chains.sort_by_key(|c| std::cmp::Reverse(c.last_seen_ms));
        chains.truncate(100);
        chains
    }

    pub fn ingest(&mut self, event: &SecurityEvent) -> Vec<SecurityEvent> {
        self.prune(event.timestamp_ms);
        let mut emitted = Vec::new();

        let pid = event.process.as_ref().map(|p| p.pid);
        if let Some(pid) = pid {
            let chain = self.chains.entry(pid).or_insert_with(|| ProcessChain {
                root_pid: pid,
                root_name: event
                    .process
                    .as_ref()
                    .map(|p| p.name.clone())
                    .unwrap_or_else(|| "unknown".into()),
                events: Vec::new(),
                signals: RiskSignals::default(),
                correlation_id: new_id("corr"),
                first_seen_ms: event.timestamp_ms,
                last_seen_ms: event.timestamp_ms,
                emitted_score_band: 0,
            });
            chain.last_seen_ms = event.timestamp_ms;
            chain.events.push(event.id.clone());
            if chain.events.len() > 200 {
                chain.events.drain(0..100);
            }

            apply_event_to_signals(&mut chain.signals, event);
            if let Some(assessment) = &event.assessment {
                merge_signals(&mut chain.signals, &assessment.signals);
            }

            let score = chain.signals.deterministic_score();
            let band = if score >= 80.0 {
                BAND_CRITICAL
            } else if score >= 45.0 {
                BAND_ALERT
            } else if score >= 20.0 {
                BAND_CORRELATION
            } else {
                0
            };

            if band > chain.emitted_score_band && band > 0 {
                chain.emitted_score_band = band;
                let correlation_id = chain.correlation_id.clone();
                let root_name = chain.root_name.clone();
                let signals = chain.signals.clone();
                let event_ids = chain.events.clone();
                let assessment = RiskAssessment::from_signals(signals.clone());
                let severity = severity_for(assessment.score);
                let mut correlated = SecurityEvent::new(
                    SecurityEventKind::Correlation,
                    severity,
                    TelemetrySource::Correlation,
                    format!("Correlated behavior chain: {root_name}"),
                );
                correlated.description = assessment.reasons.join("; ");
                correlated.process = event.process.clone();
                correlated.assessment = Some(assessment);
                correlated.correlation_id = Some(correlation_id.clone());
                correlated.labels = vec!["correlated".into(), format!("band-{band}")];
                correlated.evidence = serde_json::json!({
                    "chainEventIds": event_ids,
                    "rootPid": pid,
                    "rootName": root_name,
                });
                emitted.push(correlated);
            }
        }

        // A completed process moves its chain to `recent` so the UI keeps the
        // story after the process exits.
        if event.kind == SecurityEventKind::ProcessTerminated {
            if let Some(pid) = pid {
                if let Some(chain) = self.chains.remove(&pid) {
                    self.recent.push(chain);
                    if self.recent.len() > 200 {
                        self.recent.remove(0);
                    }
                }
            }
        }

        emitted
    }

    fn prune(&mut self, now_ms: i64) {
        let window = self.window_ms;
        self.chains
            .retain(|_, chain| now_ms - chain.last_seen_ms < window);
        self.recent
            .retain(|chain| now_ms - chain.last_seen_ms < window * 4);
    }
}

fn apply_event_to_signals(signals: &mut RiskSignals, event: &SecurityEvent) {
    match event.kind {
        SecurityEventKind::PersistenceIndicator => signals.persistence_attempt = true,
        SecurityEventKind::NetworkActivity => signals.unusual_network_activity = true,
        SecurityEventKind::ScriptActivity if event.labels.iter().any(|l| l == "obfuscated") => {
            signals.obfuscated_script = true;
        }
        SecurityEventKind::FileCreated | SecurityEventKind::FileModified => {
            if let Some(file) = &event.file {
                let lower = file.path.to_ascii_lowercase();
                if lower.contains("\\startup\\") || lower.contains("\\currentversion\\run") {
                    signals.startup_folder_write = true;
                }
            }
        }
        SecurityEventKind::Detection => {
            if let Some(assessment) = &event.assessment {
                merge_signals(signals, &assessment.signals);
            }
        }
        _ => {}
    }
    for label in event
        .labels
        .iter()
        .filter_map(|l| l.strip_prefix("signal:"))
    {
        match label {
            "persistence" => signals.persistence_attempt = true,
            "obfuscated_script" => signals.obfuscated_script = true,
            "network" => signals.unusual_network_activity = true,
            "credential_access" => signals.credential_access_indicator = true,
            "ransomware" => signals.ransomware_indicator = true,
            "startup_write" => signals.startup_folder_write = true,
            "unsigned" => signals.unsigned_executable = true,
            _ => {}
        }
    }
}

fn merge_signals(target: &mut RiskSignals, source: &RiskSignals) {
    target.known_malware_hash |= source.known_malware_hash;
    target.yara_matches = target.yara_matches.max(source.yara_matches);
    target.unsigned_executable |= source.unsigned_executable;
    target.invalid_signature |= source.invalid_signature;
    target.suspicious_imports |= source.suspicious_imports;
    target.persistence_attempt |= source.persistence_attempt;
    target.obfuscated_script |= source.obfuscated_script;
    target.unusual_network_activity |= source.unusual_network_activity;
    target.suspicious_parent |= source.suspicious_parent;
    target.high_entropy |= source.high_entropy;
    target.writable_executable_section |= source.writable_executable_section;
    target.credential_access_indicator |= source.credential_access_indicator;
    target.ransomware_indicator |= source.ransomware_indicator;
    target.startup_folder_write |= source.startup_folder_write;
    target.temp_execution |= source.temp_execution;
    target.living_off_the_land_binary |= source.living_off_the_land_binary;
}

#[cfg(test)]
mod tests {
    use super::*;
    use security_core::ProcessRef;

    fn process(pid: u32, name: &str, parent: &str) -> ProcessRef {
        ProcessRef {
            pid,
            name: name.into(),
            path: Some(format!(r"C:\Windows\System32\{name}")),
            parent_pid: Some(1),
            parent_name: Some(parent.into()),
            ..Default::default()
        }
    }

    #[test]
    fn monitor_emits_only_differences_after_priming() {
        let provider = std::sync::Arc::new(SyntheticProcessSnapshot::new(vec![process(
            1,
            "explorer.exe",
            "none",
        )]));
        let mut monitor = ProcessMonitor::new(Box::new(provider.clone()));
        assert!(monitor.poll().is_empty(), "first poll primes the baseline");

        provider.set(vec![
            process(1, "explorer.exe", "none"),
            process(2, "powershell.exe", "explorer.exe"),
        ]);
        let created = monitor.poll();
        assert_eq!(created.len(), 1);
        assert_eq!(created[0].kind, SecurityEventKind::ProcessCreated);
        assert_eq!(created[0].process.as_ref().unwrap().name, "powershell.exe");

        provider.set(vec![process(1, "explorer.exe", "none")]);
        let terminated = monitor.poll();
        assert_eq!(terminated.len(), 1);
        assert_eq!(terminated[0].kind, SecurityEventKind::ProcessTerminated);
        assert_eq!(terminated[0].process.as_ref().unwrap().pid, 2);
    }

    #[test]
    fn monitor_handles_provider_errors_without_panicking() {
        let mut monitor = ProcessMonitor::new(Box::new(UnsupportedProcessSnapshot));
        assert!(monitor.poll().is_empty());
        assert_eq!(monitor.dropped_observations(), 1);
    }

    #[test]
    fn correlation_flags_unsigned_script_persistence_network_chain() {
        let mut engine = CorrelationEngine::default();
        let mut created = SecurityEvent::new(
            SecurityEventKind::ProcessCreated,
            Severity::Info,
            TelemetrySource::ProcessSnapshot,
            "unsigned.exe",
        );
        created.process = Some(ProcessRef {
            pid: 700,
            name: "unsigned.exe".into(),
            path: Some(r"C:\Temp\unsigned.exe".into()),
            parent_name: Some("powershell.exe".into()),
            signed: Some(false),
            ..Default::default()
        });
        let assessment = RiskSignals {
            unsigned_executable: true,
            suspicious_parent: true,
            temp_execution: true,
            ..Default::default()
        };
        created.assessment = Some(RiskAssessment::from_signals(assessment));
        created.labels = vec!["signal:obfuscated_script".into()];
        let first = engine.ingest(&created);
        assert_eq!(
            first.len(),
            1,
            "combined signals cross the correlation band"
        );

        let mut persistence = SecurityEvent::new(
            SecurityEventKind::PersistenceIndicator,
            Severity::Medium,
            TelemetrySource::Correlation,
            "Startup folder write",
        );
        persistence.process = created.process.clone();
        persistence.labels = vec!["signal:persistence".into(), "signal:startup_write".into()];
        let second = engine.ingest(&persistence);
        assert_eq!(second.len(), 1, "higher band emits again");
        assert!(second[0].assessment.as_ref().unwrap().score >= 45.0);

        let mut network = SecurityEvent::new(
            SecurityEventKind::NetworkActivity,
            Severity::Medium,
            TelemetrySource::Correlation,
            "Unusual outbound connection",
        );
        network.process = created.process.clone();
        network.labels = vec!["signal:network".into()];
        let third = engine.ingest(&network);
        assert!(
            third.len() <= 1,
            "the same score band must not re-emit the whole chain"
        );
        let chains = engine.chains();
        let chain = chains
            .iter()
            .find(|c| c.root_pid == 700)
            .expect("chain exists");
        let signals = &chain.signals;
        assert!(signals.unsigned_executable);
        assert!(signals.persistence_attempt);
        assert!(signals.unusual_network_activity);
        assert!(signals.startup_folder_write);
    }

    #[test]
    fn benign_process_does_not_correlate() {
        let mut engine = CorrelationEngine::default();
        let mut event = SecurityEvent::new(
            SecurityEventKind::ProcessCreated,
            Severity::Info,
            TelemetrySource::ProcessSnapshot,
            "notepad.exe",
        );
        event.process = Some(process(10, "notepad.exe", "explorer.exe"));
        assert!(engine.ingest(&event).is_empty());
    }
}

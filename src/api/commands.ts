// Typed wrappers around every command in the "Desktop Tauri command
// contract" table (docs/CONTRACTS.md).
//
// All commands return `Result<T, String>` on the Rust side; `invoke` rejects
// with the printable error string, which callers surface verbatim.

import { invoke } from '@tauri-apps/api/core';
import type {
  AiConfigInput,
  AiStatus,
  DecisionResult,
  EngineState,
  EventFilter,
  EventPage,
  FileScanReport,
  HardwareProfile,
  NotificationOutcome,
  ProviderTestResult,
  QuarantineRecord,
  RestoreResult,
  ScanJobSummary,
  SecurityEvent,
  SecurityEventDetail,
  ServiceStatus,
  SystemStatus,
} from './types';

/**
 * Thrown when a command is issued outside of a Tauri webview (for example in
 * a plain browser during `vite dev`, or in unit tests).
 */
export class TauriUnavailableError extends Error {
  readonly command: string;

  constructor(command: string) {
    super(
      `Tauri backend is unavailable (command "${command}"). ` +
        'Run the dashboard through the desktop app to talk to the security engine.',
    );
    this.name = 'TauriUnavailableError';
    this.command = command;
  }
}

/** True when the page is running inside a Tauri webview. */
export function isTauriAvailable(): boolean {
  if (typeof window === 'undefined') {
    return false;
  }
  const candidate = window as unknown as Record<string, unknown>;
  const internals = candidate['__TAURI_INTERNALS__'];
  if (typeof internals === 'object' && internals !== null) {
    return true;
  }
  return typeof candidate['__TAURI__'] === 'object' && candidate['__TAURI__'] !== null;
}

async function call<T>(command: string, args?: Record<string, unknown>): Promise<T> {
  if (!isTauriAvailable()) {
    throw new TauriUnavailableError(command);
  }
  return invoke<T>(command, args);
}

// --- System -----------------------------------------------------------------

export const getSystemStatus = () => call<SystemStatus>('get_system_status');
export const getHardwareProfile = () => call<HardwareProfile>('get_hardware_profile');
export const getEngineState = () => call<EngineState>('get_engine_state');
export const startMonitoring = () => call<EngineState>('start_monitoring');
export const stopMonitoring = () => call<EngineState>('stop_monitoring');
export const getServiceStatus = () => call<ServiceStatus>('get_service_status');

// --- Scanning ---------------------------------------------------------------

export const scanPath = (path: string, recursive: boolean) =>
  call<ScanJobSummary>('scan_path', { request: { path, recursive } });
export const cancelScan = (jobId: string) => call<boolean>('cancel_scan', { jobId });
export const getScanResults = (jobId: string, limit = 500) =>
  call<FileScanReport[]>('get_scan_results', { jobId, limit });
export const listScanJobs = (limit = 50) => call<ScanJobSummary[]>('list_scan_jobs', { limit });

// --- Events -----------------------------------------------------------------

export const listEvents = (filter: EventFilter) => call<EventPage>('list_events', { filter });

export const getEvent = (eventId: string) =>
  call<SecurityEventDetail | SecurityEvent>('get_event', { eventId });

/**
 * `get_event` returns `src-tauri::SecurityEventDetail`. A bare event is still
 * accepted so a partially implemented backend cannot crash the drawer; all
 * missing collections are rendered as empty rather than fabricated.
 */
export function normalizeEventDetail(raw: SecurityEventDetail | SecurityEvent): SecurityEventDetail {
  const candidate = raw as Partial<SecurityEventDetail>;
  if (candidate && typeof candidate === 'object' && candidate.event && typeof candidate.event === 'object') {
    return {
      event: candidate.event,
      related: Array.isArray(candidate.related) ? candidate.related : [],
      decisions: Array.isArray(candidate.decisions) ? candidate.decisions : [],
      policy: candidate.policy && typeof candidate.policy === 'object' ? candidate.policy : null,
    };
  }
  return { event: raw as SecurityEvent, related: [], decisions: [], policy: null };
}

// --- Quarantine -------------------------------------------------------------

export const listQuarantine = () => call<QuarantineRecord[]>('list_quarantine');
export const quarantineFile = (path: string, reason: string) =>
  call<QuarantineRecord>('quarantine_file', { path, reason });
export const restoreQuarantine = (id: string) => call<RestoreResult>('restore_quarantine', { id });
export const deleteQuarantine = (id: string) => call<boolean>('delete_quarantine', { id });

// --- AI ---------------------------------------------------------------------

export const getAiStatus = () => call<AiStatus>('get_ai_status');
export const configureAi = (config: AiConfigInput) => call<AiStatus>('configure_ai', { config });
export const testAiProvider = (model: string) =>
  call<ProviderTestResult>('test_ai_provider', { model });
export const classifyEvent = (eventId: string) => call<DecisionResult | null>('classify_event', { eventId });

// --- Settings / misc --------------------------------------------------------

/** Open-ended on the Rust side; use `src/lib/settings.ts` to merge defaults. */
export const getSettings = () => call<Record<string, unknown>>('get_settings');
export const updateSettings = (patch: Record<string, unknown>) =>
  call<Record<string, unknown>>('update_settings', { patch });
export const sendTestNotification = () => call<NotificationOutcome>('send_test_notification');

/** Human-readable text for the backend `NotificationOutcome`. */
export function describeNotificationOutcome(outcome: NotificationOutcome): string {
  if (outcome === 'sent') {
    return 'Notification sent.';
  }
  if (outcome === 'no_package_identity') {
    return 'Notification not attempted: the app is running without package identity.';
  }
  if (outcome === 'unsupported') {
    return 'Notifications are not supported on this build.';
  }
  if (outcome && typeof outcome === 'object' && 'failed' in outcome) {
    return `Notification failed: ${outcome.failed}`;
  }
  return 'Notification backend returned an unknown outcome.';
}

// Presentation helpers for contract enums: stable ordering, labels and Fluent
// Badge colors. No fabricated values: unknown strings render verbatim.

import type {
  DecisionCategory,
  DetectionSource,
  PolicyOutcome,
  ProviderStatus,
  QuarantineStatus,
  RiskLevel,
  ScanState,
  SecurityEventKind,
  Severity,
  TelemetrySource,
} from '../api/types';

export type BadgeTone =
  | 'brand'
  | 'danger'
  | 'important'
  | 'informative'
  | 'severe'
  | 'subtle'
  | 'success'
  | 'warning';

/** Ascending order; index doubles as rank for filtering/sorting. */
export const SEVERITY_ORDER: readonly Severity[] = ['info', 'low', 'medium', 'high', 'critical'];

export function severityRank(severity: Severity): number {
  const index = SEVERITY_ORDER.indexOf(severity);
  return index < 0 ? 0 : index;
}

export function compareSeverityDesc(a: Severity, b: Severity): number {
  return severityRank(b) - severityRank(a);
}

export function severityTone(severity: Severity): BadgeTone {
  switch (severity) {
    case 'info':
      return 'informative';
    case 'low':
      return 'success';
    case 'medium':
      return 'warning';
    case 'high':
      return 'severe';
    case 'critical':
      return 'danger';
    default:
      return 'subtle';
  }
}

export function riskTone(level: RiskLevel): BadgeTone {
  switch (level) {
    case 'clean':
      return 'success';
    case 'low':
      return 'informative';
    case 'medium':
      return 'warning';
    case 'high':
      return 'severe';
    case 'critical':
      return 'danger';
    default:
      return 'subtle';
  }
}

export function scanStateTone(state: ScanState): BadgeTone {
  switch (state) {
    case 'running':
      return 'brand';
    case 'queued':
      return 'informative';
    case 'completed':
      return 'success';
    case 'failed':
      return 'danger';
    case 'cancelled':
      return 'subtle';
    default:
      return 'subtle';
  }
}

export function providerStatusTone(status: ProviderStatus): BadgeTone {
  switch (status) {
    case 'healthy':
      return 'success';
    case 'degraded':
      return 'warning';
    case 'unavailable':
      return 'danger';
    case 'offline':
      return 'subtle';
    default:
      return 'subtle';
  }
}

export function policyOutcomeTone(outcome: PolicyOutcome): BadgeTone {
  switch (outcome) {
    case 'allow':
      return 'success';
    case 'observe':
      return 'informative';
    case 'investigate':
      return 'warning';
    case 'alert':
      return 'severe';
    case 'quarantine':
      return 'danger';
    default:
      return 'subtle';
  }
}

export function decisionCategoryTone(category: DecisionCategory): BadgeTone {
  switch (category) {
    case 'benign':
      return 'success';
    case 'suspicious':
      return 'warning';
    case 'likely_malicious':
      return 'danger';
    default:
      return 'subtle';
  }
}

export function quarantineStatusTone(status: QuarantineStatus): BadgeTone {
  switch (status) {
    case 'quarantined':
      return 'severe';
    case 'restored':
      return 'success';
    case 'deleted':
      return 'subtle';
    default:
      return 'subtle';
  }
}

/** Turn an enum value into a sentence-cased label ("process_created" -> "Process created"). */
export function humanize(value: string): string {
  if (!value) {
    return 'Unknown';
  }
  const spaced = value.replace(/[_-]+/g, ' ').trim();
  return spaced.charAt(0).toUpperCase() + spaced.slice(1);
}

export const EVENT_KIND_LABELS: Record<SecurityEventKind, string> = {
  process_created: 'Process created',
  process_terminated: 'Process terminated',
  file_created: 'File created',
  file_modified: 'File modified',
  persistence_indicator: 'Persistence indicator',
  script_activity: 'Script activity',
  network_activity: 'Network activity',
  defender_status: 'Defender status',
  scan_started: 'Scan started',
  scan_completed: 'Scan completed',
  detection: 'Detection',
  policy_decision: 'Policy decision',
  ai_decision: 'AI decision',
  provider_health: 'Provider health',
  correlation: 'Correlation',
  engine_status: 'Engine status',
};

export const EVENT_KIND_ORDER: readonly SecurityEventKind[] = [
  'process_created',
  'process_terminated',
  'file_created',
  'file_modified',
  'persistence_indicator',
  'script_activity',
  'network_activity',
  'defender_status',
  'scan_started',
  'scan_completed',
  'detection',
  'policy_decision',
  'ai_decision',
  'provider_health',
  'correlation',
  'engine_status',
];

export const TELEMETRY_SOURCE_LABELS: Record<TelemetrySource, string> = {
  process_snapshot: 'Process snapshot',
  windows_event_log: 'Windows event log',
  file_scanner: 'File scanner',
  correlation: 'Correlation',
  defender: 'Defender (read-only)',
  engine: 'Engine',
};

export const DETECTION_SOURCE_LABELS: Record<DetectionSource, string> = {
  yara: 'YARA',
  known_hash: 'Known hash',
  pe_heuristic: 'PE heuristic',
  behavior_rule: 'Behavior rule',
  policy: 'Policy',
  defender: 'Defender',
};

export const SCAN_STATE_LABELS: Record<ScanState, string> = {
  queued: 'Queued',
  running: 'Running',
  completed: 'Completed',
  failed: 'Failed',
  cancelled: 'Cancelled',
};

export const PROVIDER_STATUS_LABELS: Record<ProviderStatus, string> = {
  unknown: 'Unknown',
  healthy: 'Healthy',
  degraded: 'Degraded',
  unavailable: 'Unavailable',
  offline: 'Offline',
};

export const POLICY_OUTCOME_LABELS: Record<PolicyOutcome, string> = {
  allow: 'Allow',
  observe: 'Observe',
  investigate: 'Investigate',
  alert: 'Alert',
  quarantine: 'Quarantine',
};

export const DECISION_CATEGORY_LABELS: Record<DecisionCategory, string> = {
  benign: 'Benign',
  suspicious: 'Suspicious',
  likely_malicious: 'Likely malicious',
  unknown: 'Unknown',
};

export const RISK_LEVEL_LABELS: Record<RiskLevel, string> = {
  unknown: 'Unknown',
  clean: 'Clean',
  low: 'Low',
  medium: 'Medium',
  high: 'High',
  critical: 'Critical',
};

export const QUARANTINE_STATUS_LABELS: Record<QuarantineStatus, string> = {
  quarantined: 'Quarantined',
  restored: 'Restored',
  deleted: 'Deleted',
};

export function kindLabel(kind: SecurityEventKind | string): string {
  const known = EVENT_KIND_LABELS[kind as SecurityEventKind];
  return known ?? humanize(kind);
}

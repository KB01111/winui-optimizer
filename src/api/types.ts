// TypeScript mirrors of the serialized Rust contracts.
//
// Source of truth (do not drift):
//   - docs/CONTRACTS.md ("Desktop Tauri command contract", "security-core (frozen)")
//   - crates/security-core/src/lib.rs
//
// All structs are `serde(rename_all = "camelCase")`; all enums are
// `serde(rename_all = "snake_case")` and serialize as plain strings.

export type TimestampMs = number;
export type RecordId = string;

// ---------------------------------------------------------------------------
// Enums
// ---------------------------------------------------------------------------

export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical';

export type RiskLevel = 'unknown' | 'clean' | 'low' | 'medium' | 'high' | 'critical';

export type SecurityEventKind =
  | 'process_created'
  | 'process_terminated'
  | 'file_created'
  | 'file_modified'
  | 'persistence_indicator'
  | 'script_activity'
  | 'network_activity'
  | 'defender_status'
  | 'scan_started'
  | 'scan_completed'
  | 'detection'
  | 'policy_decision'
  | 'ai_decision'
  | 'provider_health'
  | 'correlation'
  | 'engine_status';

export type TelemetrySource =
  | 'process_snapshot'
  | 'windows_event_log'
  | 'file_scanner'
  | 'correlation'
  | 'defender'
  | 'engine';

export type DetectionSource =
  | 'yara'
  | 'known_hash'
  | 'pe_heuristic'
  | 'behavior_rule'
  | 'policy'
  | 'defender';

export type ScanSource = 'manual' | 'scheduled' | 'realtime';

export type ScanState = 'queued' | 'running' | 'completed' | 'failed' | 'cancelled';

export type QuarantineStatus = 'quarantined' | 'restored' | 'deleted';

export type PolicyOutcome = 'allow' | 'observe' | 'investigate' | 'alert' | 'quarantine';

export type DecisionCategory = 'benign' | 'suspicious' | 'likely_malicious' | 'unknown';

export type ProviderStatus = 'unknown' | 'healthy' | 'degraded' | 'unavailable' | 'offline';

export type AiMode = 'offline' | 'cloud' | 'hybrid';

/** ai-local::RuntimeKind. */
export type RuntimeKind = 'cpu' | 'npu' | 'integrated_gpu' | 'discrete_gpu' | 'cloud';

export type DecisionRoute =
  | 'skipped_by_policy'
  | 'skipped_offline'
  | 'primary_only'
  | 'escalated'
  | 'failed_closed';

/**
 * `windows-integration::NotificationOutcome` (serde externally tagged enum).
 * Unit variants serialize as strings; `Failed(String)` serializes as
 * `{ "failed": "message" }`.
 */
export type NotificationOutcome =
  | 'sent'
  | 'no_package_identity'
  | 'unsupported'
  | { failed: string };

// ---------------------------------------------------------------------------
// security-core structs
// ---------------------------------------------------------------------------

export interface ProcessRef {
  pid: number;
  name: string;
  path?: string | null;
  commandLine?: string | null;
  parentPid?: number | null;
  parentName?: string | null;
  signed?: boolean | null;
  signer?: string | null;
  sha256?: string | null;
  user?: string | null;
  startedAtMs?: TimestampMs | null;
}

export interface PeSection {
  name: string;
  virtualSize: number;
  rawSize: number;
  entropy: number;
  executable: boolean;
  writable: boolean;
}

export interface PeImport {
  dll: string;
  functions: string[];
}

export interface PeMetadata {
  machine: string;
  subsystem: string;
  isDll: boolean;
  isDotnet: boolean;
  timestamp?: number | null;
  sections: PeSection[];
  imports: PeImport[];
  exports: string[];
  entryPoint?: number | null;
}

export interface SignatureInfo {
  present: boolean;
  status: string;
  signer?: string | null;
  issuer?: string | null;
  thumbprint?: string | null;
}

export interface FileRef {
  path: string;
  name: string;
  size: number;
  sha256?: string | null;
  entropy?: number | null;
  isPe: boolean;
  pe?: PeMetadata | null;
  signature?: SignatureInfo | null;
  createdAtMs?: TimestampMs | null;
  modifiedAtMs?: TimestampMs | null;
}

export interface Detection {
  id: RecordId;
  ruleId: string;
  ruleName: string;
  source: DetectionSource;
  severity: Severity;
  description: string;
  scoreContribution: number;
  evidence: string[];
  createdAtMs: TimestampMs;
}

export interface RiskSignals {
  knownMalwareHash: boolean;
  yaraMatches: number;
  unsignedExecutable: boolean;
  invalidSignature: boolean;
  suspiciousImports: boolean;
  persistenceAttempt: boolean;
  obfuscatedScript: boolean;
  unusualNetworkActivity: boolean;
  suspiciousParent: boolean;
  highEntropy: boolean;
  writableExecutableSection: boolean;
  credentialAccessIndicator: boolean;
  ransomwareIndicator: boolean;
  startupFolderWrite: boolean;
  tempExecution: boolean;
  livingOffTheLandBinary: boolean;
}

export interface RiskAssessment {
  score: number;
  level: RiskLevel;
  signals: RiskSignals;
  reasons: string[];
  /** True when the score came only from deterministic rules. */
  deterministic: boolean;
}

export interface SecurityEvent {
  id: RecordId;
  timestampMs: TimestampMs;
  kind: SecurityEventKind;
  severity: Severity;
  source: TelemetrySource;
  title: string;
  description: string;
  process?: ProcessRef | null;
  file?: FileRef | null;
  detections: Detection[];
  assessment?: RiskAssessment | null;
  correlationId?: RecordId | null;
  labels: string[];
  /** Bounded, structured evidence. Never contains file contents. */
  evidence: unknown;
}

export interface FileScanReport {
  id: RecordId;
  file: FileRef;
  detections: Detection[];
  assessment: RiskAssessment;
  source: ScanSource;
  durationMs: number;
  scannedAtMs: TimestampMs;
  cacheHit: boolean;
  errors: string[];
}

export interface ScanJobSummary {
  id: RecordId;
  path: string;
  recursive: boolean;
  state: ScanState;
  startedAtMs: TimestampMs;
  finishedAtMs?: TimestampMs | null;
  filesScanned: number;
  detections: number;
  errors: number;
  currentPath?: string | null;
  cancelled: boolean;
}

export interface ScanProgress {
  jobId: RecordId;
  state: ScanState;
  filesScanned: number;
  currentPath?: string | null;
  detections: number;
  errors: number;
}

export interface QuarantineRecord {
  id: RecordId;
  originalPath: string;
  originalName: string;
  storedPath: string;
  sha256: string;
  size: number;
  quarantinedAtMs: TimestampMs;
  status: QuarantineStatus;
  restoredAtMs?: TimestampMs | null;
  detectionId?: RecordId | null;
  reason: string;
  identityVerified: boolean;
}

export interface RestoreResult {
  id: RecordId;
  restoredPath?: string | null;
  success: boolean;
  message: string;
}

export interface PolicyDecision {
  id: RecordId;
  outcome: PolicyOutcome;
  reason: string;
  matchedRules: string[];
  requiresHumanApproval: boolean;
  quarantineAllowed: boolean;
  deterministic: boolean;
  createdAtMs: TimestampMs;
}

export interface DecisionResult {
  id: RecordId;
  provider: string;
  model: string;
  modelVersion?: string | null;
  category: DecisionCategory;
  probabilities: Record<string, number>;
  confidence: number;
  requiresInvestigation: boolean;
  suspiciousPersistence: boolean;
  credentialTheft: boolean;
  ransomware: boolean;
  latencyMs: number;
  timestampMs: TimestampMs;
  evidence: string[];
  costUsd?: number | null;
  escalated: boolean;
}

export interface ProviderHealth {
  provider: string;
  model: string;
  status: ProviderStatus;
  successes: number;
  failures: number;
  lastLatencyMs?: number | null;
  lastError?: string | null;
  totalCostUsd: number;
  requests: number;
  checkedAtMs: TimestampMs;
}

export interface GpuAdapter {
  name: string;
  vendor: string;
  dedicatedVramMb: number;
  isDiscrete: boolean;
  isSoftware: boolean;
}

export interface NpuInfo {
  name: string;
  available: boolean;
  driverHint?: string | null;
}

export interface BatteryState {
  present: boolean;
  percent?: number | null;
  acOnline: boolean;
  charging: boolean;
}

export interface HardwareProfile {
  cpuArch: string;
  cpuName?: string | null;
  logicalCores: number;
  physicalCores?: number | null;
  totalRamMb: number;
  availableRamMb: number;
  gpus: GpuAdapter[];
  npu?: NpuInfo | null;
  battery: BatteryState;
}

/** ai-local::InferenceRoute. */
export interface InferenceRoute {
  primary: RuntimeKind;
  fallback: RuntimeKind;
  reason: string;
  allowDiscreteGpu: boolean;
}

/** src-tauri LocalModelInfo. */
export interface LocalModelInfo {
  name: string;
  available: boolean;
  runtime: string;
  note: string;
}

/** src-tauri LocalAiStatus. */
export interface LocalAiStatus {
  hardware: HardwareProfile;
  route: InferenceRoute;
  model: LocalModelInfo;
}

// ---------------------------------------------------------------------------
// windows-integration structs
// ---------------------------------------------------------------------------

export interface PackageIdentityInfo {
  available: boolean;
  familyName?: string | null;
  fullName?: string | null;
  publisher?: string | null;
  version?: string | null;
  installLocation?: string | null;
  appUserModelId?: string | null;
}

export interface WindowsVersion {
  major: number;
  minor: number;
  build: number;
  revision: number;
  displayVersion: string;
  edition: string;
  architecture: string;
  isWindows11: boolean;
}

export interface ExecutionContext {
  packaged: boolean;
  elevated: boolean;
  userSid?: string | null;
  usernameRedacted?: string | null;
  processId: number;
  sessionId?: number | null;
}

export interface DefenderStatus {
  available: boolean;
  queryError?: string | null;
  realtimeEnabled: boolean;
  antivirusEnabled: boolean;
  antispywareEnabled: boolean;
  tamperProtected: boolean;
  engineVersion?: string | null;
  signatureVersion?: string | null;
  signatureAgeDays?: number | null;
  lastQuickScanMs?: TimestampMs | null;
  lastFullScanMs?: TimestampMs | null;
  threatsDetected?: number | null;
  definitionStatus?: string | null;
  checkedAtMs: TimestampMs;
}

// ---------------------------------------------------------------------------
// storage query types
// ---------------------------------------------------------------------------

export interface EventFilter {
  limit: number;
  offset: number;
  severity?: Severity | null;
  kind?: SecurityEventKind | null;
  search?: string | null;
  correlationId?: string | null;
  sinceMs?: TimestampMs | null;
}

export interface EventPage {
  items: SecurityEvent[];
  total: number;
  nextOffset?: number | null;
}

// ---------------------------------------------------------------------------
// Desktop aggregate types (src-tauri/src/types.rs, serde camelCase).
// ---------------------------------------------------------------------------

/** `get_service_status` — status of the privileged security service (named pipe). */
export interface ServiceStatus {
  available: boolean;
  pipeName: string;
  connected: boolean;
  version?: string | null;
  lastError?: string | null;
}

/** `get_engine_state` / `start_monitoring` / `stop_monitoring` / `engine://status`. */
export interface EngineState {
  running: boolean;
  startedAtMs?: TimestampMs | null;
  uptimeSecs: number;
  telemetrySource: string;
  telemetryAvailable: boolean;
  monitoringIsPreventive: boolean;
  eventsProcessed: number;
  correlatedChains: number;
  detections: number;
  scansCompleted: number;
  droppedEvents: number;
  mode: string;
}

/** `get_ai_status` / `configure_ai` / `engine://provider-health`. */
export interface AiStatus {
  mode: AiMode;
  configured: boolean;
  primaryModel: string;
  escalationModel: string;
  allowCloudState: boolean;
  offlineCapable: boolean;
  providers: ProviderHealth[];
  local: LocalAiStatus;
  totalCostUsd: number;
  requests: number;
  failures: number;
  avgLatencyMs?: number | null;
  lastRequestAtMs?: TimestampMs | null;
}

/**
 * `configure_ai { config }`. `apiKey` is write-only and never read back.
 * Omitting `apiKey` keeps the stored credential; `clearApiKey` deletes it.
 */
export interface AiConfigInput {
  mode: AiMode;
  apiKey?: string | null;
  clearApiKey?: boolean;
  primaryModel: string;
  escalationModel: string;
  timeoutMs: number;
  requestsPerMinute: number;
  dailyCostLimitUsd: number;
  allowCloudState: boolean;
}

/** `test_ai_provider { model }`. */
export interface ProviderTestResult {
  model: string;
  ok: boolean;
  latencyMs: number;
  category?: string | null;
  confidence?: number | null;
  costUsd?: number | null;
  error?: string | null;
}

/** `get_event { eventId }`. */
export interface SecurityEventDetail {
  event: SecurityEvent;
  related: SecurityEvent[];
  decisions: DecisionResult[];
  policy: PolicyDecision | null;
}

/** security-storage::StorageStats. */
export interface StorageStats {
  events: number;
  detections: number;
  quarantined: number;
  scans: number;
}

/** src-tauri PrivacyState. */
export interface PrivacyState {
  cloudAiEnabled: boolean;
  storeRawPaths: boolean;
  telemetryLocalOnly: boolean;
  notificationsEnabled: boolean;
  autoQuarantineEnabled: boolean;
}

/** `get_system_status`. */
export interface SystemStatus {
  productName: string;
  version: string;
  packageIdentity: PackageIdentityInfo;
  windows: WindowsVersion;
  execution: ExecutionContext;
  defender: DefenderStatus;
  engine: EngineState;
  ai: AiStatus;
  hardware: HardwareProfile;
  service: ServiceStatus;
  privacy: PrivacyState;
  storage: StorageStats;
}

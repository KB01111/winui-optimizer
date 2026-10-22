import type { SecurityEvent, SystemStatus } from '../../src/api/types';

export function makeSystemStatus(overrides: Partial<SystemStatus> = {}): SystemStatus {
  return {
    productName: 'AI Antivirus',
    version: '0.1.0',
    packageIdentity: {
      available: false,
      familyName: null,
      fullName: null,
      publisher: null,
      version: null,
      installLocation: null,
      appUserModelId: null,
    },
    windows: {
      major: 10,
      minor: 0,
      build: 26100,
      revision: 1,
      displayVersion: '24H2',
      edition: 'Professional',
      architecture: 'x86_64',
      isWindows11: true,
    },
    execution: {
      packaged: false,
      elevated: false,
      userSid: null,
      usernameRedacted: null,
      processId: 4242,
      sessionId: 1,
    },
    defender: {
      available: true,
      queryError: null,
      realtimeEnabled: true,
      antivirusEnabled: true,
      antispywareEnabled: true,
      tamperProtected: true,
      engineVersion: '1.1.24090.11',
      signatureVersion: '1.403.2212.0',
      signatureAgeDays: 1,
      lastQuickScanMs: 1710000000000,
      lastFullScanMs: null,
      threatsDetected: 0,
      definitionStatus: 'Up to date',
      checkedAtMs: 1710000000000,
    },
    engine: {
      running: true,
      startedAtMs: 1710000000000,
      uptimeSecs: 3600,
      telemetrySource: 'windows-toolhelp32',
      telemetryAvailable: true,
      monitoringIsPreventive: false,
      eventsProcessed: 42,
      correlatedChains: 3,
      detections: 1,
      scansCompleted: 2,
      droppedEvents: 0,
      mode: 'embedded',
    },
    ai: {
      mode: 'offline',
      configured: false,
      primaryModel: 'inception/mercury-decide',
      escalationModel: 'typesafe/jev-1.14',
      allowCloudState: false,
      offlineCapable: true,
      providers: [],
      local: {
        hardware: {
          cpuArch: 'x86_64',
          cpuName: 'Test CPU',
          logicalCores: 8,
          physicalCores: 4,
          totalRamMb: 16384,
          availableRamMb: 8192,
          gpus: [],
          npu: null,
          battery: { present: true, percent: 80, acOnline: true, charging: false },
        },
        route: {
          primary: 'cpu',
          fallback: 'cpu',
          reason: 'no validated local accelerator runtime is available; running on AC power',
          allowDiscreteGpu: false,
        },
        model: {
          name: 'rules-first-local',
          available: true,
          runtime: 'cpu',
          note: 'Deterministic rules run before any model.',
        },
      },
      totalCostUsd: 0,
      requests: 0,
      failures: 0,
      avgLatencyMs: null,
      lastRequestAtMs: null,
    },
    hardware: {
      cpuArch: 'x86_64',
      cpuName: 'Test CPU',
      logicalCores: 8,
      physicalCores: 4,
      totalRamMb: 16384,
      availableRamMb: 8192,
      gpus: [],
      npu: null,
      battery: { present: true, percent: 80, acOnline: true, charging: false },
    },
    service: {
      available: true,
      pipeName: String.raw`\\.\pipe\ai-antivirus-security`,
      connected: true,
      version: '0.1.0',
      lastError: null,
    },
    privacy: {
      cloudAiEnabled: false,
      storeRawPaths: false,
      telemetryLocalOnly: true,
      notificationsEnabled: true,
      autoQuarantineEnabled: false,
    },
    storage: {
      events: 12,
      detections: 1,
      quarantined: 0,
      scans: 2,
    },
    ...overrides,
  };
}

export function makeEvent(overrides: Partial<SecurityEvent> = {}): SecurityEvent {
  return {
    id: 'evt_test_1',
    timestampMs: 1710000000000,
    kind: 'process_created',
    severity: 'info',
    source: 'process_snapshot',
    title: 'Process created',
    description: '',
    process: null,
    file: null,
    detections: [],
    assessment: null,
    correlationId: null,
    labels: [],
    evidence: null,
    ...overrides,
  };
}

/**
 * Marks the jsdom window as a Tauri webview for command wrapper tests.
 *
 * Tauri plugins (for example `@tauri-apps/api/path`) call
 * `window.__TAURI_INTERNALS__.invoke` directly instead of importing
 * `@tauri-apps/api/core`, so an optional implementation can be installed here.
 */
export function setTauriAvailable(
  available: boolean,
  internalsInvoke?: (command: string, args?: Record<string, unknown>) => unknown,
): void {
  const target = window as unknown as Record<string, unknown>;
  if (available) {
    target['__TAURI_INTERNALS__'] = internalsInvoke ? { invoke: internalsInvoke } : {};
  } else {
    delete target['__TAURI_INTERNALS__'];
    delete target['__TAURI__'];
  }
}

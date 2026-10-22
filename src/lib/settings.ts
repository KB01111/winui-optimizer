// Client-side view of the settings document.
//
// `get_settings` / `update_settings` are open (`serde_json::Value`) in the
// contract. The desktop side merges stored overrides onto `default_settings()`
// (src-tauri/src/types.rs), so these defaults mirror that document and each
// nested value is validated before use.
//
// Privacy defaults mirror the Rust defaults:
//   - auto quarantine:            OFF
//   - auto quarantine known hash: required when the feature is enabled
//   - cloud AI / cloud state:     OFF
//   - store raw paths:            ON (backend default; exposed as a toggle)
//   - telemetry local only:       ON
//   - notifications:              ON

import type { AiMode } from '../api/types';

export interface PolicySettings {
  /** Auto-quarantine is opt-in and defaults to off. Only the Rust policy engine acts on it. */
  autoQuarantineEnabled: boolean;
  autoQuarantineMinScore: number;
  autoQuarantineRequiresKnownHash: boolean;
  investigateMinScore: number;
  alertMinScore: number;
}

export interface ScannerSettings {
  exclusions: string[];
}

export interface AiSettings {
  mode: AiMode;
  primaryModel: string;
  escalationModel: string;
  allowCloudState: boolean;
  dailyCostLimitUsd: number;
  requestsPerMinute: number;
  timeoutMs: number;
}

export interface PrivacySettings {
  cloudAiEnabled: boolean;
  storeRawPaths: boolean;
  telemetryLocalOnly: boolean;
  notificationsEnabled: boolean;
  autoQuarantineEnabled: boolean;
}

export interface EngineSettings {
  pollIntervalMs: number;
  eventRetentionDays: number;
}

export interface AppSettings {
  policy: PolicySettings;
  scanner: ScannerSettings;
  ai: AiSettings;
  privacy: PrivacySettings;
  engine: EngineSettings;
}

export const DEFAULT_SETTINGS: AppSettings = {
  policy: {
    autoQuarantineEnabled: false,
    autoQuarantineMinScore: 90,
    autoQuarantineRequiresKnownHash: true,
    investigateMinScore: 40,
    alertMinScore: 70,
  },
  scanner: {
    exclusions: [],
  },
  ai: {
    mode: 'offline',
    primaryModel: 'inception/mercury-decide',
    escalationModel: 'typesafe/jev-1.14',
    allowCloudState: false,
    dailyCostLimitUsd: 0.5,
    requestsPerMinute: 30,
    timeoutMs: 15000,
  },
  privacy: {
    cloudAiEnabled: false,
    storeRawPaths: true,
    telemetryLocalOnly: true,
    notificationsEnabled: true,
    autoQuarantineEnabled: false,
  },
  engine: {
    pollIntervalMs: 3000,
    eventRetentionDays: 30,
  },
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function readBoolean(source: Record<string, unknown>, key: string, fallback: boolean): boolean {
  const value = source[key];
  return typeof value === 'boolean' ? value : fallback;
}

function readNumber(source: Record<string, unknown>, key: string, fallback: number): number {
  const value = source[key];
  return typeof value === 'number' && Number.isFinite(value) ? value : fallback;
}

function readString(source: Record<string, unknown>, key: string, fallback: string): string {
  const value = source[key];
  return typeof value === 'string' ? value : fallback;
}

function readStringArray(source: Record<string, unknown>, key: string): string[] {
  const value = source[key];
  if (!Array.isArray(value)) {
    return [];
  }
  return value.filter((item): item is string => typeof item === 'string');
}

function section(source: Record<string, unknown>, key: string): Record<string, unknown> {
  const value = source[key];
  return isRecord(value) ? value : {};
}

const AI_MODES: readonly AiMode[] = ['offline', 'cloud', 'hybrid'];

function readAiMode(source: Record<string, unknown>, key: string, fallback: AiMode): AiMode {
  const value = source[key];
  return typeof value === 'string' && (AI_MODES as readonly string[]).includes(value)
    ? (value as AiMode)
    : fallback;
}

/** Merge the persisted (untrusted) settings document onto defaults. */
export function mergeSettings(raw: unknown): AppSettings {
  const root = isRecord(raw) ? raw : {};
  const policy = section(root, 'policy');
  const scanner = section(root, 'scanner');
  const ai = section(root, 'ai');
  const privacy = section(root, 'privacy');
  const engine = section(root, 'engine');

  return {
    policy: {
      autoQuarantineEnabled: readBoolean(
        policy,
        'autoQuarantineEnabled',
        DEFAULT_SETTINGS.policy.autoQuarantineEnabled,
      ),
      autoQuarantineMinScore: readNumber(
        policy,
        'autoQuarantineMinScore',
        DEFAULT_SETTINGS.policy.autoQuarantineMinScore,
      ),
      autoQuarantineRequiresKnownHash: readBoolean(
        policy,
        'autoQuarantineRequiresKnownHash',
        DEFAULT_SETTINGS.policy.autoQuarantineRequiresKnownHash,
      ),
      investigateMinScore: readNumber(
        policy,
        'investigateMinScore',
        DEFAULT_SETTINGS.policy.investigateMinScore,
      ),
      alertMinScore: readNumber(policy, 'alertMinScore', DEFAULT_SETTINGS.policy.alertMinScore),
    },
    scanner: {
      exclusions: readStringArray(scanner, 'exclusions'),
    },
    ai: {
      mode: readAiMode(ai, 'mode', DEFAULT_SETTINGS.ai.mode),
      primaryModel: readString(ai, 'primaryModel', DEFAULT_SETTINGS.ai.primaryModel),
      escalationModel: readString(ai, 'escalationModel', DEFAULT_SETTINGS.ai.escalationModel),
      allowCloudState: readBoolean(ai, 'allowCloudState', DEFAULT_SETTINGS.ai.allowCloudState),
      dailyCostLimitUsd: readNumber(
        ai,
        'dailyCostLimitUsd',
        DEFAULT_SETTINGS.ai.dailyCostLimitUsd,
      ),
      requestsPerMinute: readNumber(
        ai,
        'requestsPerMinute',
        DEFAULT_SETTINGS.ai.requestsPerMinute,
      ),
      timeoutMs: readNumber(ai, 'timeoutMs', DEFAULT_SETTINGS.ai.timeoutMs),
    },
    privacy: {
      cloudAiEnabled: readBoolean(privacy, 'cloudAiEnabled', DEFAULT_SETTINGS.privacy.cloudAiEnabled),
      storeRawPaths: readBoolean(privacy, 'storeRawPaths', DEFAULT_SETTINGS.privacy.storeRawPaths),
      telemetryLocalOnly: readBoolean(
        privacy,
        'telemetryLocalOnly',
        DEFAULT_SETTINGS.privacy.telemetryLocalOnly,
      ),
      notificationsEnabled: readBoolean(
        privacy,
        'notificationsEnabled',
        DEFAULT_SETTINGS.privacy.notificationsEnabled,
      ),
      autoQuarantineEnabled: readBoolean(
        privacy,
        'autoQuarantineEnabled',
        DEFAULT_SETTINGS.privacy.autoQuarantineEnabled,
      ),
    },
    engine: {
      pollIntervalMs: readNumber(engine, 'pollIntervalMs', DEFAULT_SETTINGS.engine.pollIntervalMs),
      eventRetentionDays: readNumber(
        engine,
        'eventRetentionDays',
        DEFAULT_SETTINGS.engine.eventRetentionDays,
      ),
    },
  };
}

/** Build the `update_settings` patch for everything except the AI provider form. */
export function settingsToPatch(settings: AppSettings): Record<string, unknown> {
  return {
    policy: { ...settings.policy },
    scanner: { ...settings.scanner },
    privacy: { ...settings.privacy },
    engine: { ...settings.engine },
  };
}

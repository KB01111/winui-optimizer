import { beforeEach, afterEach, describe, expect, it, vi } from 'vitest';
import { invoke } from '@tauri-apps/api/core';

vi.mock('@tauri-apps/api/core', () => ({
  invoke: vi.fn(),
}));

import {
  TauriUnavailableError,
  cancelScan,
  configureAi,
  describeNotificationOutcome,
  getEvent,
  getSystemStatus,
  isTauriAvailable,
  listEvents,
  normalizeEventDetail,
  quarantineFile,
  scanPath,
  testAiProvider,
  updateSettings,
} from '../../src/api/commands';
import type { AiConfigInput, EventFilter } from '../../src/api/types';
import { setTauriAvailable } from './fixtures';

const invokeMock = vi.mocked(invoke);

beforeEach(() => {
  invokeMock.mockReset();
  invokeMock.mockResolvedValue(undefined);
  setTauriAvailable(true);
});

afterEach(() => {
  setTauriAvailable(false);
});

describe('command wrappers', () => {
  it('scan_path wraps the request object', async () => {
    await scanPath(String.raw`C:\Users\test\Downloads`, true);
    expect(invokeMock).toHaveBeenCalledTimes(1);
    expect(invokeMock).toHaveBeenCalledWith('scan_path', {
      request: { path: String.raw`C:\Users\test\Downloads`, recursive: true },
    });
  });

  it('cancel_scan passes camelCase jobId', async () => {
    await cancelScan('job_123');
    expect(invokeMock).toHaveBeenCalledWith('cancel_scan', { jobId: 'job_123' });
  });

  it('list_events passes the full EventFilter untouched', async () => {
    const filter: EventFilter = {
      limit: 100,
      offset: 200,
      severity: 'high',
      kind: 'detection',
      search: 'powershell',
      sinceMs: 1710000000000,
    };
    await listEvents(filter);
    expect(invokeMock).toHaveBeenCalledWith('list_events', { filter });
  });

  it('get_event passes camelCase eventId', async () => {
    await getEvent('evt_42');
    expect(invokeMock).toHaveBeenCalledWith('get_event', { eventId: 'evt_42' });
  });

  it('quarantine_file sends path and reason as top-level args', async () => {
    await quarantineFile(String.raw`C:\Temp\evil.exe`, 'Known malware hash');
    expect(invokeMock).toHaveBeenCalledWith('quarantine_file', {
      path: String.raw`C:\Temp\evil.exe`,
      reason: 'Known malware hash',
    });
  });

  it('configure_ai wraps the config object', async () => {
    const config: AiConfigInput = {
      mode: 'hybrid',
      primaryModel: 'inception/mercury-decide',
      escalationModel: 'typesafe/jev-1.14',
      timeoutMs: 15000,
      requestsPerMinute: 30,
      dailyCostLimitUsd: 0.5,
      allowCloudState: false,
      clearApiKey: false,
      apiKey: 'secret-key',
    };
    await configureAi(config);
    expect(invokeMock).toHaveBeenCalledWith('configure_ai', { config });
  });

  it('test_ai_provider passes the model', async () => {
    await testAiProvider('inception/mercury-decide');
    expect(invokeMock).toHaveBeenCalledWith('test_ai_provider', {
      model: 'inception/mercury-decide',
    });
  });

  it('update_settings wraps the patch', async () => {
    await updateSettings({ policy: { autoQuarantineEnabled: false } });
    expect(invokeMock).toHaveBeenCalledWith('update_settings', {
      patch: { policy: { autoQuarantineEnabled: false } },
    });
  });

  it('normalizes the pinned event detail envelope', () => {
    const event = { id: 'evt_1' } as never;
    expect(normalizeEventDetail({ event, related: [], decisions: [], policy: null })).toEqual({
      event,
      related: [],
      decisions: [],
      policy: null,
    });
  });

  it('describes the backend NotificationOutcome enum', () => {
    expect(describeNotificationOutcome('sent')).toBe('Notification sent.');
    expect(describeNotificationOutcome('no_package_identity')).toContain('package identity');
    expect(describeNotificationOutcome({ failed: 'toast blocked' })).toBe(
      'Notification failed: toast blocked',
    );
  });

  it('does not invoke the backend outside a Tauri webview', async () => {
    setTauriAvailable(false);
    expect(isTauriAvailable()).toBe(false);
    await expect(getSystemStatus()).rejects.toBeInstanceOf(TauriUnavailableError);
    expect(invokeMock).not.toHaveBeenCalled();
  });
});

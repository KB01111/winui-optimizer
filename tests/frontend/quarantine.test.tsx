import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi, type Mock } from 'vitest';
import { FluentProvider, webLightTheme } from '@fluentui/react-components';
import { invoke } from '@tauri-apps/api/core';

vi.mock('@tauri-apps/api/core', () => ({
  invoke: vi.fn(),
}));

vi.mock('@tauri-apps/api/event', () => ({
  listen: vi.fn(async () => () => undefined),
}));

import type {
  FileScanReport,
  QuarantineRecord,
  RestoreResult,
  ScanJobSummary,
  SecurityEventDetail,
} from '../../src/api/types';
import { EventDetailPanel } from '../../src/components/EventDetailPanel';
import { QuarantinePage } from '../../src/pages/QuarantinePage';
import { ScanCenterPage } from '../../src/pages/ScanCenterPage';
import { QuarantineProvider } from '../../src/state/QuarantineProvider';
import { ScanJobsProvider } from '../../src/state/ScanJobsProvider';
import { makeEvent, setTauriAvailable } from './fixtures';

const invokeMock = invoke as unknown as Mock;

const HASH_A = 'a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90';
const HASH_B = '0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0';

function makeQuarantineRecord(overrides: Partial<QuarantineRecord> = {}): QuarantineRecord {
  return {
    id: 'qar_1',
    originalPath: String.raw`C:\Users\test\Downloads\suspicious.exe`,
    originalName: 'suspicious.exe',
    storedPath: String.raw`C:\Users\test\AppData\Local\AIAntivirus\quarantine\a1b2c3d4-1710000000000-suspicious.exe`,
    sha256: HASH_A,
    size: 2048,
    quarantinedAtMs: 1710000000000,
    status: 'quarantined',
    restoredAtMs: null,
    detectionId: null,
    reason: 'Manual quarantine from scan: yara-suspicious-dropper',
    identityVerified: true,
    ...overrides,
  };
}

function renderPage() {
  return render(
    <FluentProvider theme={webLightTheme}>
      <QuarantineProvider>
        <QuarantinePage />
      </QuarantineProvider>
    </FluentProvider>,
  );
}

function renderScanCenter() {
  return render(
    <FluentProvider theme={webLightTheme}>
      <ScanJobsProvider>
        <QuarantineProvider>
          <ScanCenterPage />
        </QuarantineProvider>
      </ScanJobsProvider>
    </FluentProvider>,
  );
}

function makeScanReport(overrides: Partial<FileScanReport> = {}): FileScanReport {
  return {
    id: 'rep_1',
    file: {
      path: String.raw`C:\Users\test\Downloads\evil.exe`,
      name: 'evil.exe',
      size: 1024,
      sha256: HASH_A,
      isPe: false,
    },
    detections: [
      {
        id: 'det_1',
        ruleId: 'yara-suspicious-dropper',
        ruleName: 'Suspicious dropper',
        source: 'yara',
        severity: 'high',
        description: 'Matched a suspicious dropper rule.',
        scoreContribution: 40,
        evidence: [],
        createdAtMs: 1710000000000,
      },
    ],
    assessment: {
      score: 80,
      level: 'high',
      signals: {
        knownMalwareHash: false,
        yaraMatches: 1,
        unsignedExecutable: false,
        invalidSignature: false,
        suspiciousImports: false,
        persistenceAttempt: false,
        obfuscatedScript: false,
        unusualNetworkActivity: false,
        suspiciousParent: false,
        highEntropy: false,
        writableExecutableSection: false,
        credentialAccessIndicator: false,
        ransomwareIndicator: false,
        startupFolderWrite: false,
        tempExecution: false,
        livingOffTheLandBinary: false,
      },
      reasons: [],
      deterministic: true,
    },
    source: 'manual',
    durationMs: 12,
    scannedAtMs: 1710000000000,
    cacheHit: false,
    errors: [],
    ...overrides,
  };
}

function makeScanJob(overrides: Partial<ScanJobSummary> = {}): ScanJobSummary {
  return {
    id: 'job_1',
    path: String.raw`C:\Users\test\Downloads`,
    recursive: true,
    state: 'completed',
    startedAtMs: 1710000000000,
    finishedAtMs: 1710000005000,
    filesScanned: 1,
    detections: 1,
    errors: 0,
    cancelled: false,
    ...overrides,
  };
}

/** Installs a command handler that answers the quarantine commands. */
function mockCommands(handlers: Record<string, (args?: Record<string, unknown>) => unknown>) {
  invokeMock.mockImplementation(async (command: string, args?: Record<string, unknown>) => {
    const handler = handlers[command];
    if (!handler) {
      return undefined;
    }
    return handler(args);
  });
}

beforeEach(() => {
  invokeMock.mockReset();
  setTauriAvailable(true, invokeMock);
});

afterEach(() => {
  setTauriAvailable(false);
});

describe('QuarantinePage', () => {
  it('shows the explicit empty state when the vault holds no copies', async () => {
    mockCommands({ list_quarantine: () => [] });

    renderPage();

    expect(await screen.findByText('No files are quarantined')).toBeInTheDocument();
    // The copy-only contract is stated on the page.
    expect(screen.getByText(/The original file is never deleted/)).toBeInTheDocument();
    // No fabricated rows.
    expect(screen.queryAllByRole('gridcell')).toHaveLength(0);
  });

  it('renders one row per record with its status label and SHA-256', async () => {
    const records: QuarantineRecord[] = [
      makeQuarantineRecord(),
      makeQuarantineRecord({
        id: 'qar_2',
        originalName: 'second.exe',
        originalPath: String.raw`C:\Users\test\Downloads\second.exe`,
        sha256: HASH_B,
        status: 'restored',
        restoredAtMs: 1710000100000,
        identityVerified: false,
      }),
    ];
    mockCommands({ list_quarantine: () => records });

    renderPage();

    expect(await screen.findByText('suspicious.exe')).toBeInTheDocument();
    expect(screen.getByText('second.exe')).toBeInTheDocument();

    const dataRows = screen
      .getAllByRole('row')
      .filter(
        (row) =>
          within(row).queryAllByRole('columnheader').length === 0 &&
          within(row).queryAllByRole('gridcell').length > 0,
      );
    expect(dataRows).toHaveLength(records.length);

    // Status labels come from the contract enum, not from invented text.
    expect(within(dataRows[0]).getByText('Quarantined')).toBeInTheDocument();
    expect(within(dataRows[1]).getByText('Restored')).toBeInTheDocument();

    // The hash is truncated in the cell but the full value stays reachable.
    const hashCell = screen.getByTitle(HASH_A);
    expect(hashCell).toHaveTextContent(`${HASH_A.slice(0, 16)}…`);
    expect(screen.getByTitle(HASH_B)).toBeInTheDocument();
  });

  it('restores a record and surfaces the message returned by the backend', async () => {
    const record = makeQuarantineRecord();
    const restoredPath = String.raw`C:\Users\test\Downloads\suspicious.exe`;
    const restoreResult: RestoreResult = {
      id: record.id,
      restoredPath,
      success: true,
      message: 'Quarantine restored',
    };
    mockCommands({
      list_quarantine: () => [record],
      restore_quarantine: (args) => {
        expect(args).toEqual({ id: 'qar_1' });
        return restoreResult;
      },
    });

    renderPage();

    const restoreButton = await screen.findByRole('button', { name: 'Restore' });
    fireEvent.click(restoreButton);

    await waitFor(() => {
      expect(invokeMock).toHaveBeenCalledWith('restore_quarantine', { id: 'qar_1' });
    });
    const message = await screen.findByText(/Quarantine restored/);
    expect(message).toHaveTextContent(restoredPath);
  });

  it('requires an explicit confirmation before the vault copy is deleted', async () => {
    const record = makeQuarantineRecord();
    mockCommands({
      list_quarantine: () => [record],
      delete_quarantine: () => true,
    });

    renderPage();

    const deleteButton = await screen.findByRole('button', { name: 'Delete' });
    fireEvent.click(deleteButton);

    // The confirmation dialog explains the destructive scope.
    const confirmButton = await screen.findByRole('button', { name: 'Delete copy permanently' });
    expect(screen.getByText(/permanently removes the vault copy/)).toBeInTheDocument();
    expect(screen.getByText(/original file location is not touched/)).toBeInTheDocument();

    // Nothing is deleted until the confirmation is accepted.
    expect(invokeMock).not.toHaveBeenCalledWith('delete_quarantine', expect.anything());

    fireEvent.click(confirmButton);

    await waitFor(() => {
      expect(invokeMock).toHaveBeenCalledWith('delete_quarantine', { id: 'qar_1' });
    });
  });

  it('surfaces a backend failure as an error banner instead of an empty table', async () => {
    mockCommands({
      list_quarantine: () => {
        throw new Error('database is locked: could not read quarantine_records');
      },
    });

    renderPage();

    expect(await screen.findByText('Could not load quarantined files')).toBeInTheDocument();
    expect(
      screen.getByText('database is locked: could not read quarantine_records'),
    ).toBeInTheDocument();
    expect(screen.queryByText('No files are quarantined')).not.toBeInTheDocument();
    expect(screen.queryAllByRole('gridcell')).toHaveLength(0);
  });

  it('reports the backend error when a manual quarantine is rejected', async () => {
    mockCommands({
      list_quarantine: () => [],
      quarantine_file: () => {
        throw new Error('file does not exist: C:\\missing.exe');
      },
    });

    renderPage();

    await screen.findByText('No files are quarantined');

    fireEvent.change(screen.getByPlaceholderText('C:\\Users\\you\\Downloads\\suspicious.exe'), {
      target: { value: String.raw`C:\missing.exe` },
    });
    fireEvent.change(screen.getByPlaceholderText('Manual quarantine from the dashboard'), {
      target: { value: 'Manual quarantine from the dashboard' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Quarantine file' }));

    expect(await screen.findByText('Quarantine failed')).toBeInTheDocument();
    expect(screen.getByText('file does not exist: C:\\missing.exe')).toBeInTheDocument();
    expect(invokeMock).toHaveBeenCalledWith('quarantine_file', {
      path: String.raw`C:\missing.exe`,
      reason: 'Manual quarantine from the dashboard',
    });
  });

  it('rejects an empty manual quarantine before calling the backend', async () => {
    mockCommands({ list_quarantine: () => [] });

    renderPage();

    await screen.findByText('No files are quarantined');

    fireEvent.click(screen.getByRole('button', { name: 'Quarantine file' }));

    expect(await screen.findByText('Path and reason are required')).toBeInTheDocument();
    expect(invokeMock).not.toHaveBeenCalledWith('quarantine_file', expect.anything());
  });

  it('quarantines a detected file from the scan center results drawer', async () => {
    const report = makeScanReport();
    mockCommands({
      list_quarantine: () => [],
      list_scan_jobs: () => [makeScanJob()],
      get_scan_results: () => [report],
      quarantine_file: (args) => {
        expect(args).toEqual({
          path: String.raw`C:\Users\test\Downloads\evil.exe`,
          reason: 'Manual quarantine from scan: yara-suspicious-dropper',
        });
        return makeQuarantineRecord({
          id: 'qar_9',
          originalPath: String.raw`C:\Users\test\Downloads\evil.exe`,
          originalName: 'evil.exe',
          sha256: HASH_A,
          reason: 'Manual quarantine from scan: yara-suspicious-dropper',
        });
      },
    });

    renderScanCenter();

    fireEvent.click(await screen.findByRole('button', { name: 'Results' }));

    const quarantineButton = await screen.findByRole('button', { name: 'Quarantine' });
    fireEvent.click(quarantineButton);

    await waitFor(() => {
      expect(invokeMock).toHaveBeenCalledWith('quarantine_file', {
        path: String.raw`C:\Users\test\Downloads\evil.exe`,
        reason: 'Manual quarantine from scan: yara-suspicious-dropper',
      });
    });
    expect(await screen.findByText(/Stored a copy in the local vault as qar_9/)).toBeInTheDocument();
  });

  it('offers a quarantine action in the shared event detail panel', async () => {
    mockCommands({
      list_quarantine: () => [],
      quarantine_file: () => makeQuarantineRecord({ id: 'qar_7' }),
    });

    const detail: SecurityEventDetail = {
      event: makeEvent({
        id: 'evt_7',
        kind: 'detection',
        file: {
          path: String.raw`C:\Users\test\Downloads\evil.exe`,
          name: 'evil.exe',
          size: 1024,
          sha256: HASH_A,
          isPe: false,
        },
        detections: [
          {
            id: 'det_7',
            ruleId: 'yara-suspicious-dropper',
            ruleName: 'Suspicious dropper',
            source: 'yara',
            severity: 'high',
            description: 'Matched a suspicious dropper rule.',
            scoreContribution: 40,
            evidence: [],
            createdAtMs: 1710000000000,
          },
        ],
      }),
      related: [],
      decisions: [],
      policy: null,
    };

    render(
      <FluentProvider theme={webLightTheme}>
        <QuarantineProvider>
          <EventDetailPanel detail={detail} />
        </QuarantineProvider>
      </FluentProvider>,
    );

    fireEvent.click(await screen.findByRole('button', { name: 'Quarantine file' }));

    await waitFor(() => {
      expect(invokeMock).toHaveBeenCalledWith('quarantine_file', {
        path: String.raw`C:\Users\test\Downloads\evil.exe`,
        reason: 'Manual quarantine from Detection event: yara-suspicious-dropper',
      });
    });
    expect(
      await screen.findByText(/A copy was stored in the local quarantine vault/),
    ).toBeInTheDocument();
  });
});

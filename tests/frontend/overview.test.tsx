import { render, screen } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi, type Mock } from 'vitest';
import { FluentProvider, webLightTheme } from '@fluentui/react-components';
import { invoke } from '@tauri-apps/api/core';

vi.mock('@tauri-apps/api/core', () => ({
  invoke: vi.fn(),
}));

vi.mock('@tauri-apps/api/event', () => ({
  listen: vi.fn(async () => () => undefined),
}));

import { OverviewPage } from '../../src/pages/OverviewPage';
import { ScanJobsProvider } from '../../src/state/ScanJobsProvider';
import { SystemStatusProvider } from '../../src/state/SystemStatusProvider';
import { makeSystemStatus, setTauriAvailable } from './fixtures';

const invokeMock = invoke as unknown as Mock;

function renderOverview() {
  return render(
    <FluentProvider theme={webLightTheme}>
      <SystemStatusProvider>
        <ScanJobsProvider>
          <OverviewPage />
        </ScanJobsProvider>
      </SystemStatusProvider>
    </FluentProvider>,
  );
}

beforeEach(() => {
  invokeMock.mockReset();
  setTauriAvailable(true);
  invokeMock.mockImplementation(async (command: string) => {
    switch (command) {
      case 'get_system_status':
        return makeSystemStatus();
      case 'list_scan_jobs':
        return [];
      case 'list_events':
        return { items: [], total: 0, nextOffset: null };
      default:
        return undefined;
    }
  });
});

afterEach(() => {
  setTauriAvailable(false);
});

describe('OverviewPage', () => {
  it('renders Defender and engine data from get_system_status', async () => {
    renderOverview();

    // Defender card values (from the mocked command payload).
    expect(await screen.findByText('1.1.24090.11')).toBeInTheDocument();
    expect(screen.getByText('1.403.2212.0')).toBeInTheDocument();
    expect(screen.getByText('Up to date')).toBeInTheDocument();

    // Engine card values.
    expect(screen.getByText('windows-toolhelp32')).toBeInTheDocument();
    expect(screen.getByText('Engine running')).toBeInTheDocument();
    expect(screen.getByText('Events processed')).toBeInTheDocument();

    // Protection summary derives "Protected" from engine + Defender.
    expect(screen.getByText('Protected')).toBeInTheDocument();
    expect(invokeMock).toHaveBeenCalledWith('get_system_status', undefined);
  });

  it('shows explicit empty states for detections and active scans', async () => {
    renderOverview();

    expect(await screen.findByText('No detections recorded')).toBeInTheDocument();
    expect(screen.getByText('No scan is running')).toBeInTheDocument();
  });

  it('shows the backend error instead of inventing status data', async () => {
    invokeMock.mockImplementation(async (command: string) => {
      if (command === 'get_system_status') {
        throw 'Access is denied while querying Defender.';
      }
      if (command === 'list_scan_jobs') {
        return [];
      }
      return { items: [], total: 0, nextOffset: null };
    });

    renderOverview();

    expect(await screen.findByText('Engine status unavailable')).toBeInTheDocument();
    expect(screen.getByText('Access is denied while querying Defender.')).toBeInTheDocument();
    expect(screen.queryByText('Protected')).not.toBeInTheDocument();
  });
});

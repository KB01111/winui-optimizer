import { fireEvent, render, screen } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi, type Mock } from 'vitest';
import { FluentProvider, webLightTheme } from '@fluentui/react-components';
import { invoke } from '@tauri-apps/api/core';

vi.mock('@tauri-apps/api/core', () => ({
  invoke: vi.fn(),
}));

vi.mock('@tauri-apps/api/event', () => ({
  listen: vi.fn(async () => () => undefined),
}));

import { App } from '../../src/App';
import { LiveEventsProvider } from '../../src/state/LiveEventsProvider';
import { ScanJobsProvider } from '../../src/state/ScanJobsProvider';
import { SystemStatusProvider } from '../../src/state/SystemStatusProvider';
import { makeSystemStatus, setTauriAvailable } from './fixtures';

const invokeMock = invoke as unknown as Mock;

function renderApp() {
  return render(
    <FluentProvider theme={webLightTheme}>
      <SystemStatusProvider>
        <LiveEventsProvider>
          <ScanJobsProvider>
            <App />
          </ScanJobsProvider>
        </LiveEventsProvider>
      </SystemStatusProvider>
    </FluentProvider>,
  );
}

beforeEach(() => {
  invokeMock.mockReset();
  setTauriAvailable(true, invokeMock);
  invokeMock.mockImplementation(async (command: string) => {
    if (command.startsWith('plugin:path|')) {
      return String.raw`C:\Users\test`;
    }
    switch (command) {
      case 'get_system_status':
        return makeSystemStatus();
      case 'get_settings':
        return {};
      case 'list_scan_jobs':
        return [];
      case 'list_quarantine':
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

describe('App shell', () => {
  it('navigates every page and keeps real-data empty states', async () => {
    renderApp();

    // Header derives protection from the reported engine + Defender state.
    // ("Protected" also appears in the Overview protection card.)
    expect((await screen.findAllByText('Protected')).length).toBeGreaterThan(0);
    expect(screen.getAllByText('AI Antivirus').length).toBeGreaterThan(0);

    fireEvent.click(screen.getByRole('tab', { name: /live activity/i }));
    expect(await screen.findByText('No events yet')).toBeInTheDocument();

    fireEvent.click(screen.getByRole('tab', { name: /threat intelligence/i }));
    expect(await screen.findByText('No events match the filters')).toBeInTheDocument();

    fireEvent.click(screen.getByRole('tab', { name: /scan center/i }));
    expect(await screen.findByRole('button', { name: /user profile/i })).toBeInTheDocument();
    expect(await screen.findByText('No scan jobs yet')).toBeInTheDocument();

    fireEvent.click(screen.getByRole('tab', { name: /ai intelligence/i }));
    expect(await screen.findByText('No providers configured')).toBeInTheDocument();

    fireEvent.click(screen.getByRole('tab', { name: /quarantine/i }));
    expect(await screen.findByText('No files are quarantined')).toBeInTheDocument();

    fireEvent.click(screen.getByRole('tab', { name: /settings/i }));
    expect(await screen.findByText('Policy thresholds')).toBeInTheDocument();
    expect(await screen.findByRole('switch', { name: /auto-quarantine/i })).not.toBeChecked();
  });
});

import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi, type Mock } from 'vitest';
import { FluentProvider, webLightTheme } from '@fluentui/react-components';
import { invoke } from '@tauri-apps/api/core';

vi.mock('@tauri-apps/api/core', () => ({
  invoke: vi.fn(),
}));

vi.mock('@tauri-apps/api/event', () => ({
  listen: vi.fn(async () => () => undefined),
}));

import { SettingsPage } from '../../src/pages/SettingsPage';
import { SystemStatusProvider } from '../../src/state/SystemStatusProvider';
import { makeSystemStatus, setTauriAvailable } from './fixtures';

const invokeMock = invoke as unknown as Mock;

function renderSettings() {
  return render(
    <FluentProvider theme={webLightTheme}>
      <SystemStatusProvider>
        <SettingsPage />
      </SystemStatusProvider>
    </FluentProvider>,
  );
}

beforeEach(() => {
  invokeMock.mockReset();
  setTauriAvailable(true);
  invokeMock.mockImplementation(async (command: string) => {
    switch (command) {
      case 'get_settings':
        // Persisted document intentionally empty: defaults must be safe.
        return {};
      case 'get_system_status':
        return makeSystemStatus();
      case 'update_settings':
      case 'configure_ai':
        return {};
      default:
        return undefined;
    }
  });
});

afterEach(() => {
  setTauriAvailable(false);
});

describe('SettingsPage', () => {
  it('renders auto-quarantine off by default when no setting is stored', async () => {
    renderSettings();

    const autoQuarantine = await screen.findByRole('switch', { name: /auto-quarantine/i });
    expect(autoQuarantine).not.toBeChecked();
    expect(screen.getByText('No exclusions configured')).toBeInTheDocument();
  });

  it('persists policy defaults with auto-quarantine still disabled', async () => {
    renderSettings();

    const saveButton = await screen.findByRole('button', { name: /save thresholds/i });
    fireEvent.click(saveButton);

    await waitFor(() => {
      expect(invokeMock).toHaveBeenCalledWith(
        'update_settings',
        expect.objectContaining({
          patch: expect.objectContaining({
            policy: expect.objectContaining({
              autoQuarantineEnabled: false,
              autoQuarantineMinScore: 90,
              autoQuarantineRequiresKnownHash: true,
            }),
          }),
        }),
      );
    });
  });

  it('keeps the API key write-only (password field starts empty)', async () => {
    renderSettings();

    const apiKey = await screen.findByPlaceholderText('Enter a new key to replace the stored one');
    expect(apiKey).toHaveValue('');
    expect(apiKey).toHaveAttribute('type', 'password');
  });
});

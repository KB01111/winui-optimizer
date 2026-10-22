// Known-folder resolution for the Quick Scan buttons.
//
// The contract has no command that returns user profile folders, so quick
// targets are resolved through the Tauri path API instead. When that is not
// available (unpackaged/dev builds without the path permissions), the buttons
// stay disabled and the page says why: no path is ever guessed.

import { downloadDir, homeDir, tempDir } from '@tauri-apps/api/path';
import { isTauriAvailable } from '../api/commands';
import { describeError } from './errors';

export interface QuickScanTarget {
  id: 'home' | 'downloads' | 'temp';
  label: string;
  path: string;
}

export interface QuickScanTargetsResult {
  targets: QuickScanTarget[];
  error: string | null;
}

export async function resolveQuickScanTargets(): Promise<QuickScanTargetsResult> {
  if (!isTauriAvailable()) {
    return {
      targets: [],
      error: 'Quick scan targets need the desktop backend (Tauri path resolution is unavailable here).',
    };
  }
  try {
    const [home, downloads, temp] = await Promise.all([homeDir(), downloadDir(), tempDir()]);
    const targets: QuickScanTarget[] = [
      { id: 'home', label: 'User profile', path: home },
      { id: 'downloads', label: 'Downloads', path: downloads },
      { id: 'temp', label: 'Temporary files', path: temp },
    ];
    return { targets, error: null };
  } catch (error) {
    return {
      targets: [],
      error: `Could not resolve user profile folders: ${describeError(error)}`,
    };
  }
}

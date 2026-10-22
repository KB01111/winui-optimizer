// Typed `listen()` wrappers for the events emitted by the Tauri backend
// (docs/CONTRACTS.md "Desktop Tauri command contract").
//
// Every subscription returns an unsubscribe function. When the webview is not
// running inside Tauri the callers surface a `TauriUnavailableError` instead of
// silently pretending the engine is connected.

import { listen, type UnlistenFn } from '@tauri-apps/api/event';
import { isTauriAvailable, TauriUnavailableError } from './commands';
import type { EngineState, ProviderHealth, ScanProgress, SecurityEvent } from './types';

export type Unsubscribe = () => void;

export const ENGINE_EVENT = 'engine://event';
export const ENGINE_SCAN_PROGRESS = 'engine://scan-progress';
export const ENGINE_PROVIDER_HEALTH = 'engine://provider-health';
export const ENGINE_STATUS = 'engine://status';

async function subscribe<T>(eventName: string, handler: (payload: T) => void): Promise<Unsubscribe> {
  if (!isTauriAvailable()) {
    throw new TauriUnavailableError(`listen(${eventName})`);
  }
  const unlisten: UnlistenFn = await listen<T>(eventName, (event) => {
    handler(event.payload);
  });
  return () => {
    unlisten();
  };
}

/** `engine://event` -> `SecurityEvent` (live feed). */
export function onEngineEvent(handler: (event: SecurityEvent) => void): Promise<Unsubscribe> {
  return subscribe<SecurityEvent>(ENGINE_EVENT, handler);
}

/** `engine://scan-progress` -> `ScanProgress`. */
export function onScanProgress(handler: (progress: ScanProgress) => void): Promise<Unsubscribe> {
  return subscribe<ScanProgress>(ENGINE_SCAN_PROGRESS, handler);
}

/** `engine://provider-health` -> `ProviderHealth`. */
export function onProviderHealth(handler: (health: ProviderHealth) => void): Promise<Unsubscribe> {
  return subscribe<ProviderHealth>(ENGINE_PROVIDER_HEALTH, handler);
}

/** `engine://status` -> `EngineState`. */
export function onEngineStatus(handler: (state: EngineState) => void): Promise<Unsubscribe> {
  return subscribe<EngineState>(ENGINE_STATUS, handler);
}

/**
 * Subscribe to every engine channel at once. If one subscription fails the
 * already-registered listeners are removed before the error is re-thrown, so
 * the caller never leaks half-registered handles.
 */
export async function subscribeEngineEvents(handlers: {
  onEvent?: (event: SecurityEvent) => void;
  onScanProgress?: (progress: ScanProgress) => void;
  onProviderHealth?: (health: ProviderHealth) => void;
  onStatus?: (state: EngineState) => void;
}): Promise<Unsubscribe> {
  const active: Unsubscribe[] = [];
  try {
    if (handlers.onEvent) {
      active.push(await onEngineEvent(handlers.onEvent));
    }
    if (handlers.onScanProgress) {
      active.push(await onScanProgress(handlers.onScanProgress));
    }
    if (handlers.onProviderHealth) {
      active.push(await onProviderHealth(handlers.onProviderHealth));
    }
    if (handlers.onStatus) {
      active.push(await onEngineStatus(handlers.onStatus));
    }
  } catch (error) {
    for (const unsubscribe of active) {
      unsubscribe();
    }
    throw error;
  }
  return () => {
    for (const unsubscribe of active) {
      unsubscribe();
    }
  };
}

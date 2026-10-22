import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from 'react';
import { getSystemStatus, isTauriAvailable } from '../api/commands';
import { onEngineStatus, type Unsubscribe } from '../api/events';
import type { SystemStatus } from '../api/types';
import { describeError } from '../lib/errors';

/** The contract expects 5s polling; never poll faster than 2s. */
export const DEFAULT_POLL_INTERVAL_MS = 5000;
export const MIN_POLL_INTERVAL_MS = 2000;

export interface SystemStatusContextValue {
  status: SystemStatus | null;
  error: string | null;
  loading: boolean;
  lastUpdatedMs: number | null;
  tauriAvailable: boolean;
  refresh: () => Promise<void>;
}

const SystemStatusContext = createContext<SystemStatusContextValue | null>(null);

export interface SystemStatusProviderProps {
  children: ReactNode;
  pollIntervalMs?: number;
}

export function SystemStatusProvider({
  children,
  pollIntervalMs = DEFAULT_POLL_INTERVAL_MS,
}: SystemStatusProviderProps) {
  const interval = Math.max(MIN_POLL_INTERVAL_MS, pollIntervalMs);
  const [status, setStatus] = useState<SystemStatus | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [lastUpdatedMs, setLastUpdatedMs] = useState<number | null>(null);

  const mountedRef = useRef(true);
  const inFlightRef = useRef(false);

  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
    };
  }, []);

  const load = useCallback(async () => {
    if (inFlightRef.current || !mountedRef.current) {
      return;
    }
    inFlightRef.current = true;
    try {
      const next = await getSystemStatus();
      if (mountedRef.current) {
        setStatus(next);
        setError(null);
        setLastUpdatedMs(Date.now());
      }
    } catch (loadError) {
      if (mountedRef.current) {
        setError(describeError(loadError));
      }
    } finally {
      inFlightRef.current = false;
      if (mountedRef.current) {
        setLoading(false);
      }
    }
  }, []);

  // Initial load + 5s polling, only while the window is visible.
  useEffect(() => {
    void load();
    let timer: ReturnType<typeof setInterval> | null = null;

    const stop = () => {
      if (timer !== null) {
        window.clearInterval(timer);
        timer = null;
      }
    };
    const start = () => {
      stop();
      if (document.visibilityState === 'visible') {
        timer = window.setInterval(() => {
          void load();
        }, interval);
      }
    };

    const onVisibilityChange = () => {
      if (document.visibilityState === 'visible') {
        void load();
        start();
      } else {
        stop();
      }
    };

    start();
    document.addEventListener('visibilitychange', onVisibilityChange);
    return () => {
      stop();
      document.removeEventListener('visibilitychange', onVisibilityChange);
    };
  }, [interval, load]);

  // engine://status pushes keep the engine card current between polls.
  useEffect(() => {
    let disposed = false;
    let unsubscribe: Unsubscribe | null = null;
    onEngineStatus((engine) => {
      setStatus((previous) => (previous ? { ...previous, engine } : previous));
    })
      .then((cleanup) => {
        if (disposed) {
          cleanup();
        } else {
          unsubscribe = cleanup;
        }
      })
      .catch(() => {
        // Polling already surfaces engine unavailability; nothing to add here.
      });
    return () => {
      disposed = true;
      unsubscribe?.();
    };
  }, []);

  const value = useMemo<SystemStatusContextValue>(
    () => ({
      status,
      error,
      loading,
      lastUpdatedMs,
      tauriAvailable: isTauriAvailable(),
      refresh: load,
    }),
    [status, error, loading, lastUpdatedMs, load],
  );

  return <SystemStatusContext.Provider value={value}>{children}</SystemStatusContext.Provider>;
}

export function useSystemStatus(): SystemStatusContextValue {
  const context = useContext(SystemStatusContext);
  if (!context) {
    throw new Error('useSystemStatus must be used inside <SystemStatusProvider>');
  }
  return context;
}

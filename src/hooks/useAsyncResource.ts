import { useCallback, useEffect, useRef, useState } from 'react';
import { describeError } from '../lib/errors';
import { useDocumentVisible } from './useDocumentVisible';

export interface AsyncResource<T> {
  data: T | null;
  loading: boolean;
  error: string | null;
  reload: () => void;
}

/**
 * Loads a command once and exposes explicit loading/error state. Failed
 * commands keep the previous data and surface the printable Rust error.
 *
 * `pollWhileVisibleMs` re-runs the loader on an interval, but only while the
 * window is visible; values below 2000ms are clamped.
 */
export function useAsyncResource<T>(
  loader: () => Promise<T>,
  deps: readonly unknown[],
  pollWhileVisibleMs?: number,
): AsyncResource<T> {
  const [data, setData] = useState<T | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [nonce, setNonce] = useState(0);
  const loaderRef = useRef(loader);
  const visible = useDocumentVisible();

  const depsKey = JSON.stringify(deps);

  // Keep the latest loader in a ref without writing to it during render.
  // This effect is declared before the loading effect so the ref is always
  // up to date by the time the loader runs.
  useEffect(() => {
    loaderRef.current = loader;
  });

  useEffect(() => {
    let disposed = false;
    setLoading(true);
    void (async () => {
      try {
        const result = await loaderRef.current();
        if (!disposed) {
          setData(result);
          setError(null);
          setLoading(false);
        }
      } catch (loadError) {
        if (!disposed) {
          setError(describeError(loadError));
          setLoading(false);
        }
      }
    })();
    return () => {
      disposed = true;
    };
    // depsKey captures `deps`; the loader itself is read through a ref.
  }, [depsKey, nonce]);

  const reload = useCallback(() => {
    setNonce((current) => current + 1);
  }, []);

  useEffect(() => {
    if (!pollWhileVisibleMs || !visible) {
      return;
    }
    const interval = Math.max(2000, pollWhileVisibleMs);
    const timer = window.setInterval(() => {
      reload();
    }, interval);
    return () => {
      window.clearInterval(timer);
    };
  }, [pollWhileVisibleMs, visible, reload]);

  return { data, loading, error, reload };
}

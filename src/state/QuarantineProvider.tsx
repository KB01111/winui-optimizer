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
import { deleteQuarantine, listQuarantine, quarantineFile, restoreQuarantine } from '../api/commands';
import type { QuarantineRecord, RestoreResult } from '../api/types';
import { describeError } from '../lib/errors';

export interface QuarantineContextValue {
  /** Records as reported by the backend vault. Never fabricated. */
  records: QuarantineRecord[];
  loading: boolean;
  error: string | null;
  /** Re-reads the vault listing. */
  refresh: () => Promise<void>;
  /** Copies a file into the vault and refreshes the listing. */
  quarantine: (path: string, reason: string) => Promise<QuarantineRecord>;
  /** Restores a vault copy to its recorded original path and refreshes. */
  restore: (id: string) => Promise<RestoreResult>;
  /** Permanently removes the vault copy and refreshes. */
  remove: (id: string) => Promise<boolean>;
}

const QuarantineContext = createContext<QuarantineContextValue | null>(null);

export interface QuarantineProviderProps {
  children: ReactNode;
}

/**
 * State for the quarantine vault.
 *
 * The backend stores a *copy* of a file in the vault; the original file is
 * never removed automatically. Every command error is normalised through
 * `describeError` and rethrown so callers can surface the verbatim Rust
 * message.
 */
export function QuarantineProvider({ children }: QuarantineProviderProps) {
  const [records, setRecords] = useState<QuarantineRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const mountedRef = useRef(true);
  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
    };
  }, []);

  const refresh = useCallback(async () => {
    try {
      const list = await listQuarantine();
      if (mountedRef.current) {
        setRecords(Array.isArray(list) ? list : []);
        setError(null);
      }
    } catch (refreshError) {
      if (mountedRef.current) {
        setError(describeError(refreshError));
      }
    } finally {
      if (mountedRef.current) {
        setLoading(false);
      }
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const quarantine = useCallback(
    async (path: string, reason: string) => {
      let record: QuarantineRecord;
      try {
        record = await quarantineFile(path, reason);
      } catch (quarantineError) {
        throw new Error(describeError(quarantineError));
      }
      await refresh();
      return record;
    },
    [refresh],
  );

  const restore = useCallback(
    async (id: string) => {
      let result: RestoreResult;
      try {
        result = await restoreQuarantine(id);
      } catch (restoreError) {
        throw new Error(describeError(restoreError));
      }
      await refresh();
      return result;
    },
    [refresh],
  );

  const remove = useCallback(
    async (id: string) => {
      let deleted: boolean;
      try {
        deleted = await deleteQuarantine(id);
      } catch (deleteError) {
        throw new Error(describeError(deleteError));
      }
      await refresh();
      return deleted;
    },
    [refresh],
  );

  const value = useMemo<QuarantineContextValue>(
    () => ({
      records,
      loading,
      error,
      refresh,
      quarantine,
      restore,
      remove,
    }),
    [records, loading, error, refresh, quarantine, restore, remove],
  );

  return <QuarantineContext.Provider value={value}>{children}</QuarantineContext.Provider>;
}

/** Quarantine state. Throws when used outside of `<QuarantineProvider>`. */
export function useQuarantine(): QuarantineContextValue {
  const context = useContext(QuarantineContext);
  if (!context) {
    throw new Error('useQuarantine must be used inside <QuarantineProvider>');
  }
  return context;
}

/**
 * Quarantine state for components that may legitimately render outside of the
 * provider (for example shared panels used by other pages).
 */
export function useOptionalQuarantine(): QuarantineContextValue | null {
  return useContext(QuarantineContext);
}

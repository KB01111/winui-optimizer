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
import {
  cancelScan,
  getScanResults,
  isTauriAvailable,
  listScanJobs,
  scanPath,
} from '../api/commands';
import { onScanProgress, type Unsubscribe } from '../api/events';
import type { FileScanReport, ScanJobSummary, ScanProgress, ScanState } from '../api/types';
import { describeError } from '../lib/errors';

const DEFAULT_JOB_LIMIT = 50;
const RESULTS_LIMIT = 500;

export interface ScanResultsState {
  jobId: string | null;
  items: FileScanReport[];
  loading: boolean;
  error: string | null;
}

export interface ScanJobsContextValue {
  jobs: ScanJobSummary[];
  progressByJob: Record<string, ScanProgress>;
  loading: boolean;
  error: string | null;
  refresh: () => Promise<void>;
  startScan: (path: string, recursive: boolean) => Promise<ScanJobSummary>;
  cancel: (jobId: string) => Promise<boolean>;
  activeJobIds: string[];
  results: ScanResultsState;
  loadResults: (jobId: string) => Promise<void>;
  clearResults: () => void;
}

const INITIAL_RESULTS: ScanResultsState = { jobId: null, items: [], loading: false, error: null };

const ScanJobsContext = createContext<ScanJobsContextValue | null>(null);

const TERMINAL_STATES: readonly ScanState[] = ['completed', 'failed', 'cancelled'];

export function isTerminalScanState(state: ScanState): boolean {
  return TERMINAL_STATES.includes(state);
}

export interface ScanJobsProviderProps {
  children: ReactNode;
  jobLimit?: number;
}

export function ScanJobsProvider({ children, jobLimit = DEFAULT_JOB_LIMIT }: ScanJobsProviderProps) {
  const [jobs, setJobs] = useState<ScanJobSummary[]>([]);
  const [progressByJob, setProgressByJob] = useState<Record<string, ScanProgress>>({});
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [results, setResults] = useState<ScanResultsState>(INITIAL_RESULTS);

  const mountedRef = useRef(true);
  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
    };
  }, []);

  const refresh = useCallback(async () => {
    try {
      const list = await listScanJobs(jobLimit);
      if (mountedRef.current) {
        setJobs(Array.isArray(list) ? list : []);
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
  }, [jobLimit]);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  // Live progress keeps counts honest between list refreshes.
  useEffect(() => {
    let disposed = false;
    let unsubscribe: Unsubscribe | null = null;
    onScanProgress((progress) => {
      setProgressByJob((previous) => ({ ...previous, [progress.jobId]: progress }));
      setJobs((previous) =>
        previous.map((job) =>
          job.id === progress.jobId
            ? {
                ...job,
                state: progress.state,
                filesScanned: progress.filesScanned,
                detections: progress.detections,
                errors: progress.errors,
                currentPath: progress.currentPath ?? job.currentPath,
              }
            : job,
        ),
      );
      if (isTerminalScanState(progress.state)) {
        void refresh();
      }
    })
      .then((cleanup) => {
        if (disposed) {
          cleanup();
        } else {
          unsubscribe = cleanup;
        }
      })
      .catch(() => {
        // refresh() already reports connection problems.
      });
    return () => {
      disposed = true;
      unsubscribe?.();
    };
  }, [refresh]);

  const startScan = useCallback(
    async (path: string, recursive: boolean) => {
      const job = await scanPath(path, recursive);
      if (mountedRef.current) {
        setJobs((previous) => [job, ...previous.filter((existing) => existing.id !== job.id)]);
        setError(null);
      }
      return job;
    },
    [],
  );

  const cancel = useCallback(
    async (jobId: string) => {
      const cancelled = await cancelScan(jobId);
      if (cancelled) {
        await refresh();
      }
      return cancelled;
    },
    [refresh],
  );

  const loadResults = useCallback(async (jobId: string) => {
    setResults({ jobId, items: [], loading: true, error: null });
    try {
      const items = await getScanResults(jobId, RESULTS_LIMIT);
      if (mountedRef.current) {
        setResults({ jobId, items: Array.isArray(items) ? items : [], loading: false, error: null });
      }
    } catch (loadError) {
      if (mountedRef.current) {
        setResults({ jobId, items: [], loading: false, error: describeError(loadError) });
      }
    }
  }, []);

  const clearResults = useCallback(() => {
    setResults(INITIAL_RESULTS);
  }, []);

  const activeJobIds = useMemo(() => {
    const ids = new Set<string>();
    for (const job of jobs) {
      if (!isTerminalScanState(job.state)) {
        ids.add(job.id);
      }
    }
    for (const [jobId, progress] of Object.entries(progressByJob)) {
      if (!isTerminalScanState(progress.state)) {
        ids.add(jobId);
      }
    }
    return Array.from(ids);
  }, [jobs, progressByJob]);

  const value = useMemo<ScanJobsContextValue>(
    () => ({
      jobs,
      progressByJob,
      loading,
      error,
      refresh,
      startScan,
      cancel,
      activeJobIds,
      results,
      loadResults,
      clearResults,
    }),
    [jobs, progressByJob, loading, error, refresh, startScan, cancel, activeJobIds, results, loadResults, clearResults],
  );

  return <ScanJobsContext.Provider value={value}>{children}</ScanJobsContext.Provider>;
}

export function useScanJobs(): ScanJobsContextValue {
  const context = useContext(ScanJobsContext);
  if (!context) {
    throw new Error('useScanJobs must be used inside <ScanJobsProvider>');
  }
  return context;
}

/** Convenience for callers that only need the availability flag. */
export { isTauriAvailable };

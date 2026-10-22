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
import { isTauriAvailable, listEvents } from '../api/commands';
import { onEngineEvent, type Unsubscribe } from '../api/events';
import type { SecurityEvent } from '../api/types';
import { describeError } from '../lib/errors';
import { RingBuffer } from './ringBuffer';

/** Bounded live feed: the newest `capacity` events are kept, oldest dropped. */
export const DEFAULT_EVENT_CAPACITY = 500;
const SEED_LIMIT = 200;

export interface LiveEventsContextValue {
  /** Newest first; frozen while paused. */
  events: SecurityEvent[];
  /** Newest first; always current, even while paused. */
  bufferedEvents: SecurityEvent[];
  capacity: number;
  paused: boolean;
  setPaused: (paused: boolean) => void;
  connectionError: string | null;
  lastEventAtMs: number | null;
  clear: () => void;
}

const LiveEventsContext = createContext<LiveEventsContextValue | null>(null);

export interface LiveEventsProviderProps {
  children: ReactNode;
  capacity?: number;
}

export function LiveEventsProvider({
  children,
  capacity = DEFAULT_EVENT_CAPACITY,
}: LiveEventsProviderProps) {
  const bufferRef = useRef<RingBuffer<SecurityEvent>>(new RingBuffer<SecurityEvent>(capacity));
  const seenIdsRef = useRef<Set<string>>(new Set());
  const [bufferedEvents, setBufferedEvents] = useState<SecurityEvent[]>([]);
  const [paused, setPausedState] = useState(false);
  const [snapshot, setSnapshot] = useState<SecurityEvent[] | null>(null);
  const [connectionError, setConnectionError] = useState<string | null>(null);
  const [lastEventAtMs, setLastEventAtMs] = useState<number | null>(null);

  const pushEvent = useCallback(
    (event: SecurityEvent) => {
      if (!event || typeof event !== 'object') {
        return;
      }
      const id = typeof event.id === 'string' ? event.id : null;
      const seen = seenIdsRef.current;
      if (id !== null) {
        if (seen.has(id)) {
          return;
        }
        seen.add(id);
        if (seen.size > capacity * 4) {
          // Bound the dedupe set; losing it only re-allows at most one copy
          // of a long-evicted event.
          seen.clear();
        }
      }
      bufferRef.current.push(event);
      // The ring buffer stays the source of truth for capacity; the rendered
      // snapshot is mirrored into state so the render path never reads a ref.
      setBufferedEvents(bufferRef.current.toReversedArray());
      setLastEventAtMs(typeof event.timestampMs === 'number' ? event.timestampMs : Date.now());
    },
    [capacity],
  );

  // Seed the feed from storage so the first paint shows real history.
  useEffect(() => {
    if (!isTauriAvailable()) {
      return;
    }
    let disposed = false;
    void (async () => {
      try {
        const page = await listEvents({ limit: SEED_LIMIT, offset: 0 });
        if (disposed) {
          return;
        }
        const items = [...(page.items ?? [])].sort(
          (a, b) => (a.timestampMs ?? 0) - (b.timestampMs ?? 0),
        );
        for (const item of items) {
          pushEvent(item);
        }
      } catch {
        // The subscription effect below reports the connection state.
      }
    })();
    return () => {
      disposed = true;
    };
  }, [pushEvent]);

  useEffect(() => {
    let disposed = false;
    let unsubscribe: Unsubscribe | null = null;
    onEngineEvent(pushEvent)
      .then((cleanup) => {
        if (disposed) {
          cleanup();
        } else {
          unsubscribe = cleanup;
          setConnectionError(null);
        }
      })
      .catch((error: unknown) => {
        if (!disposed) {
          setConnectionError(describeError(error));
        }
      });
    return () => {
      disposed = true;
      unsubscribe?.();
    };
  }, [pushEvent]);

  const setPaused = useCallback((next: boolean) => {
    setPausedState(next);
    setSnapshot(next ? bufferRef.current.toReversedArray() : null);
  }, []);

  const clear = useCallback(() => {
    bufferRef.current.clear();
    seenIdsRef.current.clear();
    setBufferedEvents([]);
    setSnapshot(paused ? [] : null);
  }, [paused]);

  const events = useMemo(
    () => (paused ? (snapshot ?? []) : bufferedEvents),
    [paused, snapshot, bufferedEvents],
  );

  const value = useMemo<LiveEventsContextValue>(
    () => ({
      events,
      bufferedEvents,
      capacity,
      paused,
      setPaused,
      connectionError,
      lastEventAtMs,
      clear,
    }),
    [events, bufferedEvents, capacity, paused, setPaused, connectionError, lastEventAtMs, clear],
  );

  return <LiveEventsContext.Provider value={value}>{children}</LiveEventsContext.Provider>;
}

export function useLiveEvents(): LiveEventsContextValue {
  const context = useContext(LiveEventsContext);
  if (!context) {
    throw new Error('useLiveEvents must be used inside <LiveEventsProvider>');
  }
  return context;
}

import { useEffect, useState } from 'react';

/**
 * A clock that ticks on an interval.
 *
 * Relative timestamps ("updated 2 minutes ago") are otherwise computed with
 * `Date.now()` during render, which is an impure read: the value changes on
 * every render and the React Compiler lint rules reject it. This hook keeps
 * the timestamp in state and refreshes it on a timer, so the rendered text is
 * stable within a render and still ages on its own.
 *
 * `intervalMs` is clamped to at least one second.
 */
export function useNow(intervalMs = 30_000): number {
  const [now, setNow] = useState(() => Date.now());

  useEffect(() => {
    const period = Math.max(1000, intervalMs);
    const timer = window.setInterval(() => {
      setNow(Date.now());
    }, period);
    return () => {
      window.clearInterval(timer);
    };
  }, [intervalMs]);

  return now;
}

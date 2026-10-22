// Pure filter logic for the event feed and the threat table. Kept free of
// React/Fluent so the behaviour is unit-testable and identical on both pages.

import type { SecurityEvent, Severity, SecurityEventKind } from '../api/types';

export interface EventFilterState {
  severities: Severity[];
  kinds: SecurityEventKind[];
  /** Free-text search over title, description, paths, process names, rules and labels. */
  search: string;
  /** Only events at or above this severity ("minimum severity"). */
  minSeverity: Severity | null;
}

export const EMPTY_EVENT_FILTER: EventFilterState = {
  severities: [],
  kinds: [],
  search: '',
  minSeverity: null,
};

export function matchesSeverityFilter(event: SecurityEvent, filter: EventFilterState): boolean {
  if (filter.severities.length > 0 && !filter.severities.includes(event.severity)) {
    return false;
  }
  if (filter.minSeverity !== null && severityAtLeast(event.severity, filter.minSeverity) === false) {
    return false;
  }
  return true;
}

export function matchesKindFilter(event: SecurityEvent, filter: EventFilterState): boolean {
  if (filter.kinds.length === 0) {
    return true;
  }
  return filter.kinds.includes(event.kind);
}

const SEVERITY_INDEX: Severity[] = ['info', 'low', 'medium', 'high', 'critical'];

export function severityAtLeast(severity: Severity, minimum: Severity): boolean {
  return SEVERITY_INDEX.indexOf(severity) >= SEVERITY_INDEX.indexOf(minimum);
}

function haystack(event: SecurityEvent): string[] {
  const parts: string[] = [event.title ?? '', event.description ?? '', event.kind, event.severity];
  if (event.process) {
    parts.push(event.process.name ?? '');
    if (event.process.path) {
      parts.push(event.process.path);
    }
    if (event.process.commandLine) {
      parts.push(event.process.commandLine);
    }
  }
  if (event.file) {
    parts.push(event.file.name ?? '', event.file.path ?? '');
    if (event.file.sha256) {
      parts.push(event.file.sha256);
    }
  }
  if (event.correlationId) {
    parts.push(event.correlationId);
  }
  for (const label of event.labels ?? []) {
    parts.push(label);
  }
  for (const detection of event.detections ?? []) {
    parts.push(detection.ruleId, detection.ruleName, detection.description);
  }
  return parts;
}

export function matchesSearch(event: SecurityEvent, search: string): boolean {
  const needle = search.trim().toLowerCase();
  if (!needle) {
    return true;
  }
  return haystack(event).some((part) => part.toLowerCase().includes(needle));
}

export function matchesEventFilter(event: SecurityEvent, filter: EventFilterState): boolean {
  return (
    matchesSeverityFilter(event, filter) &&
    matchesKindFilter(event, filter) &&
    matchesSearch(event, filter.search)
  );
}

export function filterEvents(events: SecurityEvent[], filter: EventFilterState): SecurityEvent[] {
  return events.filter((event) => matchesEventFilter(event, filter));
}

export function countBySeverity(events: SecurityEvent[]): Record<Severity, number> {
  const counts: Record<Severity, number> = { info: 0, low: 0, medium: 0, high: 0, critical: 0 };
  for (const event of events) {
    if (event.severity in counts) {
      counts[event.severity] += 1;
    }
  }
  return counts;
}

/** Newest first, stable for equal timestamps (input order preserved). */
export function sortByTimestampDesc(events: SecurityEvent[]): SecurityEvent[] {
  return events
    .map((event, index) => ({ event, index }))
    .sort((a, b) => {
      const delta = (b.event.timestampMs ?? 0) - (a.event.timestampMs ?? 0);
      return delta !== 0 ? delta : a.index - b.index;
    })
    .map((entry) => entry.event);
}

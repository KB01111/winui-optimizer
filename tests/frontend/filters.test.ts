import { describe, expect, it } from 'vitest';
import {
  EMPTY_EVENT_FILTER,
  countBySeverity,
  filterEvents,
  matchesEventFilter,
  matchesSearch,
  severityAtLeast,
  sortByTimestampDesc,
} from '../../src/lib/filters';
import { makeEvent } from './fixtures';

describe('event filters', () => {
  it('filters by explicit severity list', () => {
    const high = makeEvent({ id: 'a', severity: 'high' });
    const info = makeEvent({ id: 'b', severity: 'info' });
    const critical = makeEvent({ id: 'c', severity: 'critical' });
    const result = filterEvents([high, info, critical], {
      ...EMPTY_EVENT_FILTER,
      severities: ['high', 'critical'],
    });
    expect(result.map((event) => event.id)).toEqual(['a', 'c']);
  });

  it('filters by minimum severity', () => {
    const events = [
      makeEvent({ id: 'info', severity: 'info' }),
      makeEvent({ id: 'medium', severity: 'medium' }),
      makeEvent({ id: 'critical', severity: 'critical' }),
    ];
    const result = filterEvents(events, { ...EMPTY_EVENT_FILTER, minSeverity: 'medium' });
    expect(result.map((event) => event.id)).toEqual(['medium', 'critical']);
    expect(severityAtLeast('high', 'medium')).toBe(true);
    expect(severityAtLeast('low', 'medium')).toBe(false);
  });

  it('filters by kind', () => {
    const detection = makeEvent({ id: 'detection', kind: 'detection', severity: 'high' });
    const process = makeEvent({ id: 'process', kind: 'process_created' });
    const result = filterEvents([detection, process], {
      ...EMPTY_EVENT_FILTER,
      kinds: ['detection'],
    });
    expect(result.map((event) => event.id)).toEqual(['detection']);
  });

  it('searches title, paths, process names and detection rules', () => {
    const event = makeEvent({
      title: 'Suspicious PowerShell spawn',
      process: {
        pid: 10,
        name: 'powershell.exe',
        path: String.raw`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
      },
      detections: [
        {
          id: 'det_1',
          ruleId: 'yara_encrypted_script',
          ruleName: 'Encrypted script payload',
          source: 'yara',
          severity: 'high',
          description: 'Encoded command',
          scoreContribution: 45,
          evidence: [],
          createdAtMs: 1710000000000,
        },
      ],
    });
    expect(matchesSearch(event, 'POWERSHELL')).toBe(true);
    expect(matchesSearch(event, 'yara_encrypted_script')).toBe(true);
    expect(matchesSearch(event, 'c:\\windows\\system32')).toBe(true);
    expect(matchesSearch(event, 'definitely-not-present')).toBe(false);
    expect(matchesSearch(event, '   ')).toBe(true);
  });

  it('applies combined severity, kind and search filters', () => {
    const matching = makeEvent({
      id: 'matching',
      kind: 'detection',
      severity: 'critical',
      title: 'Known malware hash',
    });
    const wrongSeverity = makeEvent({
      id: 'wrong-severity',
      kind: 'detection',
      severity: 'low',
      title: 'Known malware hash',
    });
    const wrongKind = makeEvent({
      id: 'wrong-kind',
      kind: 'process_created',
      severity: 'critical',
      title: 'Known malware hash',
    });
    const filter = {
      ...EMPTY_EVENT_FILTER,
      severities: ['critical'] as const,
      kinds: ['detection'] as const,
      search: 'malware',
    };
    const combined = { ...filter, severities: [...filter.severities], kinds: [...filter.kinds] };
    expect(matchesEventFilter(matching, combined)).toBe(true);
    expect(matchesEventFilter(wrongSeverity, combined)).toBe(false);
    expect(matchesEventFilter(wrongKind, combined)).toBe(false);
  });

  it('counts severities and sorts newest first', () => {
    const events = [
      makeEvent({ id: 'old', timestampMs: 1000, severity: 'info' }),
      makeEvent({ id: 'new', timestampMs: 3000, severity: 'critical' }),
      makeEvent({ id: 'mid', timestampMs: 2000, severity: 'critical' }),
    ];
    expect(countBySeverity(events)).toEqual({ info: 1, low: 0, medium: 0, high: 0, critical: 2 });
    expect(sortByTimestampDesc(events).map((event) => event.id)).toEqual(['new', 'mid', 'old']);
  });
});

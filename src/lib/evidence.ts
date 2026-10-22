// Defensive readers for `SecurityEvent.evidence`, which is an open
// `serde_json::Value` in the contract. Nothing is fabricated: when the shape is
// not recognised the UI says so explicitly.

export interface AncestryEntry {
  pid: number | null;
  name: string;
  path: string | null;
  signed: boolean | null;
}

const ANCESTRY_KEYS = [
  'processAncestry',
  'ancestry',
  'processChain',
  'chain',
  'parentChain',
  'parentProcesses',
  'parents',
] as const;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function toAncestryEntry(value: unknown): AncestryEntry | null {
  if (!isRecord(value)) {
    return null;
  }
  const name = typeof value.name === 'string' ? value.name : null;
  const pid = typeof value.pid === 'number' && Number.isFinite(value.pid) ? value.pid : null;
  if (name === null && pid === null) {
    return null;
  }
  return {
    pid,
    name: name ?? `pid ${pid}`,
    path: typeof value.path === 'string' ? value.path : null,
    signed: typeof value.signed === 'boolean' ? value.signed : null,
  };
}

/**
 * Extract a process ancestry chain from evidence, if the backend recorded one.
 * Returns an empty array when no recognised shape is present.
 */
export function extractAncestry(evidence: unknown): AncestryEntry[] {
  const candidateArrays: unknown[] = [];
  if (Array.isArray(evidence)) {
    candidateArrays.push(evidence);
  } else if (isRecord(evidence)) {
    for (const key of ANCESTRY_KEYS) {
      const value = evidence[key];
      if (Array.isArray(value)) {
        candidateArrays.push(value);
        break;
      }
      if (isRecord(value) && (Array.isArray(value.events) || Array.isArray(value.entries))) {
        const nested = (value.events ?? value.entries) as unknown[];
        candidateArrays.push(nested);
        break;
      }
    }
  }

  for (const array of candidateArrays) {
    if (!Array.isArray(array)) {
      continue;
    }
    const entries = array
      .map((entry: unknown) => toAncestryEntry(entry))
      .filter((entry): entry is AncestryEntry => entry !== null);
    if (entries.length > 0) {
      return entries;
    }
  }
  return [];
}

/** Flat string list of evidence facts, when the backend stored string arrays. */
export function extractEvidenceStrings(evidence: unknown): string[] {
  if (!isRecord(evidence)) {
    return [];
  }
  const facts = evidence.facts ?? evidence.items ?? evidence.details;
  if (Array.isArray(facts)) {
    return facts.filter((item): item is string => typeof item === 'string');
  }
  return [];
}

/** Bounded, pretty-printed evidence for the raw JSON viewer. */
export function stringifyEvidence(evidence: unknown, maxLength = 4000): string {
  if (evidence === null || evidence === undefined) {
    return '';
  }
  let text: string;
  try {
    text = JSON.stringify(evidence, null, 2) ?? '';
  } catch {
    text = String(evidence);
  }
  if (text.length > maxLength) {
    return `${text.slice(0, maxLength)}\n… (truncated)`;
  }
  return text;
}

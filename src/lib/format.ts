// Deterministic, locale-independent formatting helpers.

const numberFormat = new Intl.NumberFormat('en-US');

export function formatNumber(value: number | null | undefined): string {
  if (value === null || value === undefined || !Number.isFinite(value)) {
    return '—';
  }
  return numberFormat.format(value);
}

export function formatBytes(bytes: number | null | undefined, fractionDigits = 1): string {
  if (bytes === null || bytes === undefined || !Number.isFinite(bytes) || bytes < 0) {
    return '—';
  }
  if (bytes < 1024) {
    return `${bytes} B`;
  }
  const units = ['KiB', 'MiB', 'GiB', 'TiB', 'PiB'];
  let value = bytes;
  let unitIndex = -1;
  while (value >= 1024 && unitIndex < units.length - 1) {
    value /= 1024;
    unitIndex += 1;
  }
  return `${value.toFixed(fractionDigits)} ${units[unitIndex]}`;
}

export function formatMegabytesToBytes(mb: number | null | undefined): number | null {
  if (mb === null || mb === undefined || !Number.isFinite(mb)) {
    return null;
  }
  return mb * 1024 * 1024;
}

export function formatDurationMs(ms: number | null | undefined): string {
  if (ms === null || ms === undefined || !Number.isFinite(ms) || ms < 0) {
    return '—';
  }
  if (ms < 1000) {
    return `${Math.round(ms)} ms`;
  }
  const seconds = ms / 1000;
  if (seconds < 60) {
    return `${seconds.toFixed(1)} s`;
  }
  const minutes = Math.floor(seconds / 60);
  const remainingSeconds = Math.round(seconds % 60);
  if (minutes < 60) {
    return `${minutes} min ${remainingSeconds} s`;
  }
  const hours = Math.floor(minutes / 60);
  return `${hours} h ${minutes % 60} min`;
}

export function formatUptime(seconds: number | null | undefined): string {
  if (seconds === null || seconds === undefined || !Number.isFinite(seconds) || seconds < 0) {
    return '—';
  }
  const total = Math.floor(seconds);
  const days = Math.floor(total / 86400);
  const hours = Math.floor((total % 86400) / 3600);
  const minutes = Math.floor((total % 3600) / 60);
  if (days > 0) {
    return `${days} d ${hours} h`;
  }
  if (hours > 0) {
    return `${hours} h ${minutes} min`;
  }
  return `${minutes} min`;
}

export function formatTimestamp(ms: number | null | undefined): string {
  if (ms === null || ms === undefined || !Number.isFinite(ms) || ms <= 0) {
    return '—';
  }
  const date = new Date(ms);
  return date.toLocaleString(undefined, {
    year: 'numeric',
    month: 'short',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  });
}

export function formatDateOnly(ms: number | null | undefined): string {
  if (ms === null || ms === undefined || !Number.isFinite(ms) || ms <= 0) {
    return '—';
  }
  return new Date(ms).toLocaleDateString(undefined, {
    year: 'numeric',
    month: 'short',
    day: '2-digit',
  });
}

export function formatRelative(ms: number | null | undefined, nowMs: number): string {
  if (ms === null || ms === undefined || !Number.isFinite(ms) || ms <= 0) {
    return '—';
  }
  const delta = nowMs - ms;
  if (delta < 0) {
    return formatTimestamp(ms);
  }
  const seconds = Math.floor(delta / 1000);
  if (seconds < 5) {
    return 'just now';
  }
  if (seconds < 60) {
    return `${seconds}s ago`;
  }
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) {
    return `${minutes} min ago`;
  }
  const hours = Math.floor(minutes / 60);
  if (hours < 24) {
    return `${hours} h ago`;
  }
  const days = Math.floor(hours / 24);
  if (days < 30) {
    return `${days} d ago`;
  }
  return formatDateOnly(ms);
}

export function formatPercent(value: number | null | undefined, fractionDigits = 0): string {
  if (value === null || value === undefined || !Number.isFinite(value)) {
    return '—';
  }
  return `${value.toFixed(fractionDigits)}%`;
}

/** `probability` fields are model-reported fractions in [0,1]. */
export function formatProbability(value: number | null | undefined): string {
  if (value === null || value === undefined || !Number.isFinite(value)) {
    return '—';
  }
  return `${(value * 100).toFixed(1)}%`;
}

export function formatUsd(value: number | null | undefined): string {
  if (value === null || value === undefined || !Number.isFinite(value)) {
    return '—';
  }
  return `$${value.toFixed(4)}`;
}

export function formatScore(value: number | null | undefined): string {
  if (value === null || value === undefined || !Number.isFinite(value)) {
    return '—';
  }
  return value.toFixed(1);
}

/** Wall-clock time for "saved at" style inline confirmations. */
export function timestamp(date: Date = new Date()): string {
  return date.toLocaleTimeString();
}

// Human-readable error text. Tauri commands reject with a printable string;
// local errors are `Error` instances; anything else is shown as-is.

export function describeError(error: unknown): string {
  if (typeof error === 'string') {
    return error;
  }
  if (error instanceof Error) {
    return error.message;
  }
  if (error === null || error === undefined) {
    return 'Unknown error';
  }
  try {
    return JSON.stringify(error);
  } catch {
    return String(error);
  }
}

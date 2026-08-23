/**
 * Lightweight deterministic formatters for traffic analytics metrics.
 */

/**
 * Format byte count into human-readable binary units (B, KiB, MiB, GiB).
 * Always represents Observed Frame Bytes.
 */
export function formatObservedBytes(bytes: number | null | undefined): string {
  if (bytes === null || bytes === undefined || isNaN(bytes)) {
    return '—';
  }
  if (bytes < 1024) {
    return `${bytes} B`;
  }
  if (bytes < 1024 * 1024) {
    return `${(bytes / 1024).toFixed(2)} KiB`;
  }
  if (bytes < 1024 * 1024 * 1024) {
    return `${(bytes / (1024 * 1024)).toFixed(2)} MiB`;
  }
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GiB`;
}

/**
 * Format packet count with standard digit grouping.
 */
export function formatObservedPackets(packets: number | null | undefined): string {
  if (packets === null || packets === undefined || isNaN(packets)) {
    return '—';
  }
  return packets.toLocaleString('en-US');
}

/**
 * Format epoch timestamp (seconds) into deterministic ISO-8601 string.
 */
export function formatEpochSeconds(epochSeconds: number | null | undefined): string {
  if (epochSeconds === null || epochSeconds === undefined || isNaN(epochSeconds)) {
    return '—';
  }
  return new Date(epochSeconds * 1000).toISOString();
}

/**
 * Format observation window duration in seconds.
 */
export function formatObservationWindow(windowSeconds: number | null | undefined): string {
  if (windowSeconds === null || windowSeconds === undefined || isNaN(windowSeconds)) {
    return '—';
  }
  if (windowSeconds < 1) {
    return `${(windowSeconds * 1000).toFixed(0)} ms`;
  }
  return `${windowSeconds.toFixed(2)}s`;
}

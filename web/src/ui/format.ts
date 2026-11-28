export function formatBytes(bytes?: number): string {
  const val = Math.max(0, Number(bytes) || 0);
  const KB = 1024;
  const MB = 1024 * KB;
  const GB = 1024 * MB;
  const TB = 1024 * GB;
  if (val >= TB) return `${(val / TB).toFixed(2)} TB`;
  if (val >= GB) return `${(val / GB).toFixed(2)} GB`;
  if (val >= MB) return `${(val / MB).toFixed(1)} MB`;
  if (val >= KB) return `${(val / KB).toFixed(1)} KB`;
  return `${Math.round(val)} B`;
}

export function formatSocketBytes(bytes?: number): string {
  const val = Math.max(0, Number(bytes) || 0);
  if (val === 0) return '-';
  const KB = 1024;
  const MB = 1024 * KB;
  if (val >= MB) {
    return val % MB === 0 ? `${val / MB} MB` : `${(val / MB).toFixed(1)} MB`;
  }
  if (val >= KB) {
    return `${Math.round(val / KB)} KB`;
  }
  return `${Math.round(val)} B`;
}

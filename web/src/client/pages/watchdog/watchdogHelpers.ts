export const DEFAULT_FO_GROUPS = ['Proxy', 'AI', '#VPS'];

export const DEFAULT_FO_URLS = [
  'https://www.gstatic.com/generate_204',
  'https://cp.cloudflare.com/generate_204',
];

export function parseClampedInt(raw: string, fallback: number, minVal: number, maxVal: number): number {
  const n = Number.parseInt(raw.trim(), 10);
  if (!Number.isFinite(n)) return fallback;
  return Math.min(maxVal, Math.max(minVal, n));
}

export function sanitizeDigits(raw: string): string {
  return raw.replace(/[^\d]/g, '');
}

export function fmtKB(bytes: number): string {
  const n = Number(bytes) || 0;
  if (n < 1024) return `${n} B`;
  return `${(n / 1024).toFixed(1)} KB`;
}

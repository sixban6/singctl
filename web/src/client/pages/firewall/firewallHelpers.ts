import { maskFullIP } from '../../lib/privacyMask';

export type BanScopeFilter = 'all' | 'dynamic_v4' | 'dynamic_v6' | 'forever';
export type RuleTabKey = 'bans' | 'whitelist' | 'ports';

export const DEFAULT_FALLBACK_PORTS = [
  20, 21, 22, 23, 25, 110, 465, 587, 993, 995, 1433, 1434, 1521, 3306, 3389, 6379,
];

export function fmtNum(n?: number): string {
  return Number(n || 0).toLocaleString('en-US');
}

export function formatRemainingTTL(sec?: number): string {
  const s = Number(sec || 0);
  if (s <= 0) return '永久';
  const days = Math.floor(s / 86400);
  const hours = Math.floor((s % 86400) / 3600);
  const mins = Math.floor((s % 3600) / 60);
  if (days > 0) return `${days}天${hours}小时`;
  if (hours > 0) return `${hours}小时${mins}分`;
  return `${Math.max(1, mins)}分钟`;
}

export function maskDisplayIP(raw: string, privacyMask: boolean): string {
  if (!privacyMask || !raw) return raw;
  return maskFullIP(raw);
}

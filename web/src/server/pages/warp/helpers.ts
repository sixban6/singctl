import { WarpRoutingConfig } from '../../types';

export const routingCacheKeyForNode = (node: string) => `server:warp:routing:${node || 'local'}`;
export const connsCacheKeyForNode = (node: string) => `server:warp:conns:${node || 'local'}`;

export const DEFAULT_ROUTING: WarpRoutingConfig = {
  mode: 'split',
  presets: {},
  warpDomains: [],
  warpCidrs: [],
  directDomains: [],
  directCidrs: [],
};

export function isLikelyIPOrCIDR(raw: string): boolean {
  const s = raw.trim();
  if (!s) return false;
  if (/^\d{1,3}(\.\d{1,3}){3}(\/\d{1,2})?$/.test(s)) return true;
  if (s.includes(':') && !s.includes('://') && !s.startsWith('full:') && !s.startsWith('keyword:')) return true;
  return false;
}

export function previewCleanRuleTarget(raw: string): { kind: 'cidr' | 'domain'; value: string } | null {
  const trimmed = raw.trim();
  if (!trimmed) return null;
  if (isLikelyIPOrCIDR(trimmed)) {
    return { kind: 'cidr', value: trimmed.includes('/') ? trimmed : trimmed };
  }
  const lower = trimmed.toLowerCase();
  if (lower.startsWith('full:') || lower.startsWith('keyword:')) {
    return { kind: 'domain', value: lower };
  }
  let s = lower.startsWith('domain:') ? lower.slice(7) : lower;
  if (s.includes('://')) {
    try {
      const u = new URL(s);
      s = u.hostname;
    } catch {
      return null;
    }
  } else {
    s = s.split(/[/?#]/)[0] || '';
  }
  const atIdx = s.lastIndexOf('@');
  if (atIdx >= 0) s = s.slice(atIdx + 1);
  if (s.includes(':') && !s.endsWith(']')) {
    s = s.slice(0, s.lastIndexOf(':'));
  }
  s = s.replace(/^\*\./, '').replace(/^\.+|\.+$/g, '');
  if (!s) return null;
  return { kind: 'domain', value: s };
}

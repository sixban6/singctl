import { SbProxyGroup, SbProxyNodeMeta } from '../../types';

const EXPANDED_STORAGE_KEY = 'sc:sb:expandedGroups';

export function loadExpandedPrefs(): Record<string, boolean> {
  if (typeof window === 'undefined') return {};
  try {
    const raw = localStorage.getItem(EXPANDED_STORAGE_KEY);
    if (!raw) return {};
    const parsed = JSON.parse(raw);
    return parsed && typeof parsed === 'object' ? parsed : {};
  } catch {
    return {};
  }
}

export function saveExpandedPrefs(next: Record<string, boolean>): void {
  try {
    localStorage.setItem(EXPANDED_STORAGE_KEY, JSON.stringify(next));
  } catch {
    // ignore storage errors
  }
}

export function defaultExpandedForGroup(g: SbProxyGroup): boolean {
  return (
    g.name === 'Proxy' ||
    g.name === 'AI' ||
    g.name === '#VPS' ||
    g.name === 'GLOBAL' ||
    Boolean(g.failedOver)
  );
}

export function groupDisplayRank(g: SbProxyGroup, mode?: string): number {
  const n = g.name.trim().toLowerCase();
  if (n === 'global') return mode === 'global' ? 0 : 50;
  if (g.type === 'Selector') {
    if (n === 'proxy') return 1;
    if (n === 'ai') return 2;
    if (n === '#vps') return 3;
    if (n === '#nodes') return 4;
    return 10;
  }
  if (g.name === '#Auto') return 20;
  return 30;
}

export function isDirectOrUtilityNode(name: string, meta?: SbProxyNodeMeta): boolean {
  const lower = name.trim().toLowerCase();
  const typeLower = (meta?.type || '').trim().toLowerCase();
  return (
    lower === '#dc' ||
    lower === 'direct' ||
    lower === 'directconn' ||
    lower === 'direct-out' ||
    lower === 'block' ||
    lower === 'block-out' ||
    lower === 'reject' ||
    typeLower === 'direct' ||
    typeLower === 'block' ||
    typeLower === 'dns'
  );
}

export function isGroupOutbound(meta?: SbProxyNodeMeta): boolean {
  const t = (meta?.type || '').trim().toLowerCase();
  return t === 'selector' || t === 'urltest' || t === 'fallback' || t === 'loadbalance';
}

export function delayToneClasses(delay: number, tested?: boolean): { text: string; badge: string } {
  if (delay > 0) {
    if (delay <= 120) {
      return {
        text: `${delay} ms`,
        badge: 'text-emerald-300 bg-emerald-500/15 border-emerald-500/30 hover:bg-emerald-500/25',
      };
    }
    if (delay <= 350) {
      return {
        text: `${delay} ms`,
        badge: 'text-amber-300 bg-amber-500/15 border-amber-500/30 hover:bg-amber-500/25',
      };
    }
    return {
      text: `${delay} ms`,
      badge: 'text-orange-300 bg-orange-500/15 border-orange-500/30 hover:bg-orange-500/25',
    };
  }
  if (tested) {
    return {
      text: '超时',
      badge: 'text-rose-300/90 bg-rose-500/10 border-rose-500/25 hover:bg-rose-500/20',
    };
  }
  return {
    text: '测速',
    badge: 'text-muted bg-surface1 border-subtle hover:text-primary hover:border-strong',
  };
}

export function formatProtocolLabel(name: string, meta?: SbProxyNodeMeta): string {
  if (isDirectOrUtilityNode(name, meta)) {
    const t = (meta?.type || '').toLowerCase();
    if (t === 'block' || name.toLowerCase().includes('block')) return 'Block';
    return 'Direct';
  }
  const rawType = (meta?.type || '').trim();
  if (!rawType || rawType === 'Unknown') return 'Proxy';
  return rawType;
}

export function resolveGroupChainOptimistically(
  groupName: string,
  byName: Map<string, SbProxyGroup>,
  nodes: Record<string, SbProxyNodeMeta>,
) {
  const chain: string[] = [];
  const visited = new Set<string>();
  let curName = groupName;
  while (curName && !visited.has(curName)) {
    visited.add(curName);
    const grp = byName.get(curName);
    if (!grp || !grp.now) break;
    chain.push(grp.now);
    if (!byName.has(grp.now)) break;
    curName = grp.now;
  }
  const leaf = chain.length > 0 ? chain[chain.length - 1] : undefined;
  const leafDelay = leaf ? nodes[leaf]?.delay ?? 0 : 0;
  return { resolvedChain: chain, resolvedNode: leaf, resolvedDelay: leafDelay };
}

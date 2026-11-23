import {
  ClientDNSStatusSummary,
  ClientStatusResponse,
  DNSCapabilities,
  DNSEngineID,
  DNSEngineOption,
  DNSOverviewSnapshot,
  DNSUpstreamMode,
} from '../../types';

export function formatNumber(n: number): string {
  if (!Number.isFinite(n)) return '0';
  return n.toLocaleString('zh-CN');
}

export function formatDurationSec(totalSec: number): string {
  const s = Math.max(0, Math.floor(totalSec));
  const m = Math.floor(s / 60);
  const rem = s % 60;
  if (m >= 60) {
    const h = Math.floor(m / 60);
    const rm = m % 60;
    return `${h} 小时 ${rm} 分 ${rem} 秒`;
  }
  if (m > 0) return `${m} 分 ${rem.toString().padStart(2, '0')} 秒`;
  return `${rem} 秒`;
}

export function getStatusDNS(status?: ClientStatusResponse | null): ClientDNSStatusSummary | undefined {
  return status?.dns ?? status?.adguard;
}

export function getEngineDisplayName(engine?: string, label?: string): string {
  if (label && label.trim()) return label.trim();
  switch (engine) {
    case 'smartdns':
      return 'SmartDNS';
    case 'adguard':
      return 'AdGuard Home';
    default:
      return '防劫持 DNS';
  }
}

export function getEngineShortName(engine?: string): string {
  switch (engine) {
    case 'smartdns':
      return 'SmartDNS';
    case 'adguard':
      return 'AdGuard Home';
    default:
      return '加密 DNS';
  }
}

export function resolveActiveEngine(snap: DNSOverviewSnapshot | null): DNSEngineID {
  if (snap?.activeEngine === 'smartdns' || snap?.activeEngine === 'adguard') {
    return snap.activeEngine;
  }
  if (snap?.recommendedEngine === 'smartdns' || snap?.recommendedEngine === 'adguard') {
    return snap.recommendedEngine;
  }
  return 'smartdns';
}

export function resolveRecommendedEngine(snap: DNSOverviewSnapshot | null): DNSEngineID {
  if (snap?.recommendedEngine === 'smartdns' || snap?.recommendedEngine === 'adguard') {
    return snap.recommendedEngine;
  }
  const marked = snap?.engines?.find(
    (item) => item.recommended && (item.id === 'smartdns' || item.id === 'adguard'),
  );
  return marked?.id === 'adguard' ? 'adguard' : 'smartdns';
}

export function resolveEngineOptions(snap: DNSOverviewSnapshot | null): DNSEngineOption[] {
  const active = resolveActiveEngine(snap);
  const rec = resolveRecommendedEngine(snap);
  const fromSnap = (snap?.engines || []).filter(
    (opt): opt is DNSEngineOption => opt.id === 'smartdns' || opt.id === 'adguard',
  );
  if (fromSnap.length > 0) return fromSnap;

  return [
    {
      id: 'smartdns',
      name: 'SmartDNS',
      tagline: '轻量极速并发测速 · ~3 MB 闪存 / ~10 MB 内存',
      installed: active === 'smartdns' && Boolean(snap?.installed),
      active: active === 'smartdns',
      recommended: rec === 'smartdns',
      eligible: Boolean(snap?.supported !== false),
      diskHint: '~3 MB',
      ramHint: '~10 MB',
    },
    {
      id: 'adguard',
      name: 'AdGuard Home',
      tagline: '全功能可视化与海量规则 · ~80 MB 闪存',
      installed: active === 'adguard' && Boolean(snap?.installed),
      active: active === 'adguard',
      recommended: rec === 'adguard',
      eligible: Boolean(snap?.supported !== false && !snap?.lowMemoryBlocked),
      blockedReason: snap?.lowMemoryBlocked ? snap.lowMemoryWarning : undefined,
      diskHint: '~80 MB',
      ramHint: '~100 MB',
    },
  ];
}

export function resolveDNSCapabilities(snap: DNSOverviewSnapshot | null): DNSCapabilities {
  if (snap?.capabilities) return snap.capabilities;
  const engine = resolveActiveEngine(snap);
  if (engine === 'smartdns') {
    return {
      hasNativeWebPanel: false,
      hasConfigPreview: true,
      hasQueryStats: true,
      hasFilterLists: true,
      hasCustomFilterURL: true,
      hasPauseProtection: true,
      canClearCache: true,
      canUninstall: true,
    };
  }
  return {
    hasNativeWebPanel: true,
    hasConfigPreview: true,
    hasQueryStats: true,
    hasFilterLists: true,
    hasCustomFilterURL: true,
    hasPauseProtection: true,
    canClearCache: true,
    canUninstall: true,
  };
}

export function canMutateEngine(snap: DNSOverviewSnapshot | null): boolean {
  if (!snap || !snap.installed) return false;
  const engine = resolveActiveEngine(snap);
  if (engine === 'smartdns') return true;
  return Boolean(snap.webHealthy);
}

export function canClearEngineCache(snap: DNSOverviewSnapshot | null, caps: DNSCapabilities): boolean {
  if (!snap || !snap.installed || !caps.canClearCache) return false;
  const engine = resolveActiveEngine(snap);
  if (engine === 'adguard') return Boolean(snap.webHealthy);
  return Boolean(snap.dnsHealthy);
}

export function isDiskOrPlatformBlocked(reason?: string): boolean {
  if (!reason) return false;
  return /闪存|磁盘|存储|空间不足|空间不够|overlay|disk|flash|storage|不支持|仅支持|非\s*Linux/i.test(
    reason,
  );
}

export function isMemoryOnlyBlocked(opt: DNSEngineOption): boolean {
  if (opt.eligible) return false;
  const reason = opt.blockedReason || '';
  if (!reason || isDiskOrPlatformBlocked(reason)) return false;
  return /内存|RAM|OOM|MiB|MB/i.test(reason);
}

export interface UpstreamModeOption {
  key: DNSUpstreamMode;
  label: string;
  shortDesc: string;
}

export const UPSTREAM_MODE_OPTIONS: UpstreamModeOption[] = [
  { key: 'parallel', label: '并行竞速 (推荐)', shortDesc: '同时请求全部上游，每次自动采用最快返回' },
  { key: 'fastest_addr', label: '最快 IP 优选', shortDesc: '并发查询并优选网络延迟最低的目标地址' },
  { key: 'load_balance', label: '负载均衡', shortDesc: '按响应质量在多条加密上游间动态分摊' },
];

export function getUpstreamModeOptions(engine: DNSEngineID): UpstreamModeOption[] {
  if (engine === 'adguard') return UPSTREAM_MODE_OPTIONS;
  return [
    {
      key: 'fastest_ip',
      label: '最快 IP 优选 (推荐)',
      shortDesc: '并发查询全上游并实测响应延迟，自动返回最快目标 IP',
    },
    {
      key: 'parallel',
      label: '并行竞速',
      shortDesc: '同时请求全部加密上游，优先采用最快返回的解析结果',
    },
    {
      key: 'load_balance',
      label: '负载均衡',
      shortDesc: '在多条加密上游间均衡分担解析负载',
    },
  ];
}

const IPV4_LITERAL_RE = /^(?:\d{1,3}\.){3}\d{1,3}$/;
const IPV6_BRACKET_RE = /^\[[0-9a-fA-F:]+\]$/;

export function isPureIPUpstreamAddress(addr: string): boolean {
  const trimmed = addr.trim();
  if (!trimmed) return false;
  try {
    const parsed = new URL(trimmed);
    const host = parsed.hostname;
    return IPV4_LITERAL_RE.test(host) || IPV6_BRACKET_RE.test(host) || host.includes(':');
  } catch {
    return false;
  }
}

export function normalizeUpstreamMode(engine: DNSEngineID, mode?: DNSUpstreamMode): DNSUpstreamMode {
  if (!mode) return engine === 'adguard' ? 'parallel' : 'fastest_ip';
  if (engine === 'adguard' && mode === 'fastest_ip') return 'fastest_addr';
  if (engine === 'smartdns' && mode === 'fastest_addr') return 'fastest_ip';
  return mode;
}

export function getUpstreamModeBadgeText(engine: DNSEngineID, mode?: DNSUpstreamMode): string {
  const m = normalizeUpstreamMode(engine, mode);
  if (m === 'fastest_ip' || m === 'fastest_addr') return '当前模式：最快 IP 优选';
  if (m === 'load_balance') return '当前模式：负载均衡';
  return '当前模式：并行竞速 (谁快用谁)';
}

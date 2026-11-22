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
    case 'singbox':
      return 'sing-box 加强版';
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
    case 'singbox':
      return 'sing-box';
    case 'smartdns':
      return 'SmartDNS';
    case 'adguard':
      return 'AdGuard Home';
    default:
      return '加密 DNS';
  }
}

export function resolveActiveEngine(snap: DNSOverviewSnapshot | null): DNSEngineID {
  if (snap?.activeEngine === 'singbox' || snap?.activeEngine === 'smartdns' || snap?.activeEngine === 'adguard') {
    return snap.activeEngine;
  }
  return snap?.installed ? 'adguard' : 'singbox';
}

export function resolveDNSCapabilities(snap: DNSOverviewSnapshot | null): DNSCapabilities {
  if (snap?.capabilities) return snap.capabilities;
  const engine = resolveActiveEngine(snap);
  if (engine === 'singbox') {
    return {
      hasNativeWebPanel: false,
      hasConfigPreview: true,
      hasQueryStats: true,
      hasFilterLists: true,
      hasCustomFilterURL: false,
      hasPauseProtection: true,
      hasBlockAAAA: true,
      canClearCache: true,
      canUninstall: false,
    };
  }
  if (engine === 'smartdns') {
    return {
      hasNativeWebPanel: false,
      hasConfigPreview: true,
      hasQueryStats: true,
      hasFilterLists: true,
      hasCustomFilterURL: true,
      hasPauseProtection: true,
      hasBlockAAAA: true,
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
    hasBlockAAAA: false,
    canClearCache: true,
    canUninstall: true,
  };
}

export function canMutateEngine(snap: DNSOverviewSnapshot | null): boolean {
  if (!snap) return false;
  const engine = resolveActiveEngine(snap);
  if (engine === 'singbox') return true;
  if (engine === 'smartdns') return Boolean(snap.installed);
  return Boolean(snap.webHealthy);
}

export function canClearEngineCache(snap: DNSOverviewSnapshot | null, caps: DNSCapabilities): boolean {
  if (!snap || !caps.canClearCache) return false;
  const engine = resolveActiveEngine(snap);
  if (engine === 'adguard') return Boolean(snap.webHealthy);
  return Boolean(snap.dnsHealthy || engine === 'singbox');
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
  if (engine === 'smartdns') {
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
        shortDesc: '在多条纯 IP 加密上游间均衡分担解析负载',
      },
    ];
  }
  return [
    {
      key: 'fastest_ip',
      label: '实测最快优选 (推荐)',
      shortDesc: '自动选用实测最快加密上游，看门狗巡检失活时自动热切备用',
    },
    {
      key: 'parallel',
      label: '顺位热备',
      shortDesc: '优先使用首位加密上游，异常时由守护进程自动切至备用上游',
    },
    {
      key: 'load_balance',
      label: '多上游备用池',
      shortDesc: '维护多条纯 IP 加密上游池供实测择优与容灾切换',
    },
  ];
}

export function normalizeUpstreamMode(engine: DNSEngineID, mode?: DNSUpstreamMode): DNSUpstreamMode {
  if (!mode) return engine === 'adguard' ? 'parallel' : 'fastest_ip';
  if (engine === 'adguard' && mode === 'fastest_ip') return 'fastest_addr';
  if (engine !== 'adguard' && mode === 'fastest_addr') return 'fastest_ip';
  return mode;
}

export function getUpstreamModeBadgeText(engine: DNSEngineID, mode?: DNSUpstreamMode): string {
  const m = normalizeUpstreamMode(engine, mode);
  if (m === 'fastest_ip') {
    return engine === 'singbox' ? '当前模式：实测最快优选 + 故障热切' : '当前模式：最快 IP 优选';
  }
  if (m === 'fastest_addr') return '当前模式：最快 IP 优选';
  if (m === 'load_balance') return '当前模式：负载均衡';
  return engine === 'singbox' ? '当前模式：顺位热备' : '当前模式：并行竞速 (谁快用谁)';
}

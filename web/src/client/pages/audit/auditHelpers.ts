import { AuditAIReview, AuditFlowRecord } from '../../types';

export const AUDIT_AI_STORAGE_KEY = 'sc_audit_ai_cache_v2';
export const AUDIT_AI_ENABLE_KEY = 'sc_audit_ai_enable';
export const FLOW_RENDER_STEP = 80;

export type {
  AuditFlowTelemetry,
  AuditPresetCounts,
  AuditPresetFilter,
  AuditRefreshCadence,
  AuditSelectedDevice,
  AuditSortKey,
  AuditTargetGroup,
  AuditViewMode,
} from './auditFlowModel';

export interface SubnetBlockConfirmState {
  cidr: string;
  sourceIp: string;
  deviceLabel: string;
  uniqueIps: number;
  reason: string;
}

export const PRESET_RULESETS: { label: string; url: string; reason: string }[] = [
  {
    label: '🛡️ 防 PCDN 偷跑与卡顿节点 (内置精校 · 零外网依赖)',
    url: 'ruleset:block-builtin-pcdn',
    reason: '内置默认防 PCDN 偷跑与卡顿节点规则集',
  },
  {
    label: '🎮 王者荣耀 (hok.srs)',
    url: 'https://github.com/sixban6/singctl/releases/download/rulesets-latest/hok.srs',
    reason: '规则集封禁: 🎮 王者荣耀 (hok.srs)',
  },
  {
    label: '🎮 腾讯游戏全家桶 (tencent-games.srs)',
    url: 'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/tencent-games.srs',
    reason: '规则集封禁: 🎮 腾讯游戏全家桶',
  },
  {
    label: '🎮 米哈游 原神/崩铁 (mihoyo.srs)',
    url: 'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/mihoyo.srs',
    reason: '规则集封禁: 🎮 米哈游 (原神/崩铁/绝区零)',
  },
  {
    label: '🎮 网易游戏 (netease.srs)',
    url: 'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/netease.srs',
    reason: '规则集封禁: 🎮 网易游戏',
  },
  {
    label: '🎮 Roblox 罗布乐思 (roblox.srs)',
    url: 'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/roblox.srs',
    reason: '规则集封禁: 🎮 Roblox 罗布乐思',
  },
  {
    label: '🎮 Supercell 部落冲突 (supercell.srs)',
    url: 'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/supercell.srs',
    reason: '规则集封禁: 🎮 Supercell 部落冲突/荒野乱斗',
  },
  {
    label: '🎮 拳头 LOL/无畏契约 (riot.srs)',
    url: 'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/riot.srs',
    reason: '规则集封禁: 🎮 拳头游戏 (LOL/无畏契约)',
  },
  {
    label: '🎮 暴雪战网 (blizzard.srs)',
    url: 'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/blizzard.srs',
    reason: '规则集封禁: 🎮 暴雪战网',
  },
  {
    label: '🎮 Steam 平台 (steam.srs)',
    url: 'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/steam.srs',
    reason: '规则集封禁: 🎮 Steam 平台',
  },
  {
    label: '🎮 Epic Games (epicgames.srs)',
    url: 'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/epicgames.srs',
    reason: '规则集封禁: 🎮 Epic Games',
  },
  {
    label: '🎮 Nintendo Switch (nintendo.srs)',
    url: 'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/nintendo.srs',
    reason: '规则集封禁: 🎮 Nintendo Switch',
  },
  {
    label: '🎮 国内主流游戏合集 (category-games-cn.srs)',
    url: 'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/category-games-cn.srs',
    reason: '规则集封禁: 🎮 国内主流网游/手游合集',
  },
  {
    label: '📱 抖音短视频 (douyin.srs)',
    url: 'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/douyin.srs',
    reason: '规则集封禁: 📱 抖音短视频 (douyin.srs)',
  },
  {
    label: '📱 微信视频号 (wx_video.srs)',
    url: 'https://github.com/sixban6/singctl/releases/download/rulesets-latest/wx_video.srs',
    reason: '规则集封禁: 📱 微信视频号 (wx_video.srs)',
  },
];

const PROTECTED_BOOTSTRAP_DOMAINS = [
  'cloudflare-ech.com',
  'cloudflare-dns.com',
  'one.one.one.one',
  'dns.google',
  'dns.alidns.com',
  'doh.pub',
  'dot.pub',
];

const PROTECTED_BOOTSTRAP_IPS = new Set([
  '127.0.0.1',
  '::1',
  '0.0.0.0',
  '223.5.5.5',
  '223.6.6.6',
  '119.29.29.29',
  '1.12.12.12',
  '120.53.53.53',
  '1.1.1.1',
  '8.8.8.8',
]);

export function isProtectedBootstrapTarget(raw: string): boolean {
  const t = String(raw || '').trim().toLowerCase().replace(/\.$/, '');
  if (!t) return false;
  if (PROTECTED_BOOTSTRAP_IPS.has(t)) return true;
  return PROTECTED_BOOTSTRAP_DOMAINS.some((d) => t === d || t.endsWith('.' + d));
}

export function isUserWhitelistedTarget(raw: string, whitelist: string[]): boolean {
  const t = String(raw || '').trim().toLowerCase().replace(/\.$/, '');
  if (!t || !whitelist.length) return false;
  return whitelist.some((w) => {
    const nw = String(w || '').trim().toLowerCase().replace(/\/(32|128)$/, '').replace(/\.$/, '');
    return Boolean(nw && (t === nw || t.endsWith('.' + nw)));
  });
}

export function getFlowCacheKey(f: AuditFlowRecord): string {
  return f.key || f.id || `${f.deviceIp}|${f.target}|${f.network}`;
}

export function getFlowTargetKey(f: AuditFlowRecord): string {
  return (f.target || getFlowCacheKey(f)).toLowerCase();
}

export const NONLINEAR_FACTOR_LABELS: Record<string, string> = {
  upload_asymmetry: '上/下行流量倒挂',
  direct_ip_upload: '绕过 DNS 纯 IP 外发',
  direct_ip_subnet_cluster: '同网段裸 IP 聚集外连',
  pcdn_swarm: 'PCDN/P2P 跨网段裸 IP 蜂群',
  beacon_heartbeat: '规律定时信标心跳',
  domain_entropy: '高熵随机域名特征',
  telemetry_fingerprint: '遥测 / PCDN 指纹命中',
  privacy_axis_extra: '暗夜作息 / 明文隐私附加',
};

export function formatDeviceRoleLabel(role?: string): string {
  switch (role) {
    case 'iot':
      return '智能家居 / IoT';
    case 'mobile':
      return '移动终端';
    case 'desktop':
      return '电脑 / 工作站';
    case 'router':
      return '下级路由';
    default:
      return '局域网终端';
  }
}

export function formatOutboundMeta(outbound?: string): {
  label: string;
  tone: 'neutral' | 'ok' | 'danger' | 'accent';
} {
  const raw = String(outbound || '').trim();
  const lower = raw.toLowerCase();
  if (!raw || lower === 'direct' || raw === '直连') {
    return { label: '直连 DIRECT', tone: 'neutral' };
  }
  if (lower === 'block' || lower === 'reject' || raw === '拦截') {
    return { label: '阻断 BLOCK', tone: 'danger' };
  }
  return { label: raw, tone: 'ok' };
}

export function formatFlowChainPath(f: AuditFlowRecord): string {
  if (f.chains && f.chains.length > 0) {
    return f.chains.join(' → ');
  }
  return f.outbound || 'DIRECT';
}

export function formatRelativeSeen(seenStr?: string): string {
  if (!seenStr) return '';
  const normalized = seenStr.includes('T') ? seenStr : seenStr.replace(' ', 'T');
  const ts = Date.parse(normalized);
  if (!Number.isFinite(ts)) {
    return seenStr.length >= 16 ? seenStr.slice(5, 16) : seenStr;
  }
  const diffSec = Math.max(0, Math.floor((Date.now() - ts) / 1000));
  if (diffSec < 15) return '刚刚';
  if (diffSec < 60) return `${diffSec}秒前`;
  const mins = Math.floor(diffSec / 60);
  if (mins < 60) return `${mins}分前`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}小时前`;
  return seenStr.length >= 16 ? seenStr.slice(5, 16) : seenStr;
}

export function fmtBps(bps?: number): string {
  const v = Number(bps || 0);
  if (!Number.isFinite(v) || v <= 0) return '0 B/s';
  if (v < 1024) return `${Math.round(v)} B/s`;
  if (v < 1024 * 1024) return `${(v / 1024).toFixed(1)} KB/s`;
  return `${(v / (1024 * 1024)).toFixed(2)} MB/s`;
}

export function fmtDurationSpan(sec?: number): string {
  const s = Number(sec || 0);
  if (!Number.isFinite(s) || s <= 0) return '—';
  if (s < 3600) return `${Math.max(1, Math.round(s / 60))} 分钟`;
  if (s < 86400) return `${(s / 3600).toFixed(1)} 小时`;
  return `${(s / 86400).toFixed(1)} 天`;
}

export function threatRank(t?: string): number {
  if (t === 'high_risk') return 3;
  if (t === 'suspicious') return 2;
  if (t === 'notice') return 1;
  return 0;
}

export function stateRank(s?: string): number {
  if (s === 'blocked') return 1;
  if (s === 'whitelisted') return 0;
  return 2;
}

export function applyLiveAIDampingToFlow(
  f: AuditFlowRecord,
  aiRev: AuditAIReview | null | undefined,
): AuditFlowRecord {
  if (!aiRev || f.state === 'blocked' || f.state === 'whitelisted') return f;
  if (aiRev.verdict !== 'do_not_block') return f;
  if (!aiRev.source || aiRev.source === 'builtin_expert' || aiRev.source === 'trusted_baseline') {
    return f;
  }

  const port = Number(f.destPort || 0);
  const isNonStdPort = port > 0 && port !== 80 && port !== 443 && port !== 53 && port !== 123;
  const isUploadDom = (f.uploadBytes || 0) >= 262144 && (f.uploadRatio || 0) >= 1.8;
  const isPcdnHard = f.pcdnKind === 'upload' || f.pcdnKind === 'swarm';
  const isHardAnomaly =
    Boolean(f.isDirectIp && isNonStdPort && isUploadDom) ||
    isPcdnHard ||
    ((f.uploadBytes || 0) >= 104857600 && (f.uploadRatio || 0) >= 4.0);
  if (isHardAnomaly) return f;

  const clone: AuditFlowRecord = {
    ...f,
    reasons: Array.isArray(f.reasons) ? [...f.reasons] : [],
  };
  if ((clone.riskScore || 0) > 28) {
    clone.riskScore = Math.min(28, Math.round((clone.riskScore || 0) * 0.32));
    clone.securityScore = Math.min(24, Math.round((clone.securityScore || 0) * 0.32));
    clone.privacyScore = Math.min(24, Math.round((clone.privacyScore || 0) * 0.32));
    clone.threat = 'normal';
    clone.threatLabel = '正常';
  }
  const dampNote = 'AI 深度复核确认正常业务 (已自动降权)';
  if (clone.reasons && !clone.reasons.some((r) => String(r).includes('AI 深度复核确认正常业务'))) {
    const firstOrig = clone.reasons[0] ? [`原启发式观察: ${clone.reasons[0]}`] : [];
    clone.reasons = [dampNote, ...firstOrig];
  }
  return clone;
}

export function checkIsDualAlert(f: AuditFlowRecord, rev: AuditAIReview | null | undefined): boolean {
  if (!f || f.state === 'blocked' || f.state === 'whitelisted') return false;
  if (!rev || rev.verdict !== 'safe_to_block') return false;
  return (
    (f.riskScore || 0) >= 45 ||
    f.threat === 'high_risk' ||
    f.threat === 'suspicious' ||
    (f.securityScore || 0) >= 40 ||
    (f.privacyScore || 0) >= 40
  );
}

export function loadSavedAICache(): Map<string, AuditAIReview> {
  const map = new Map<string, AuditAIReview>();
  try {
    const raw = localStorage.getItem(AUDIT_AI_STORAGE_KEY);
    if (raw) {
      const obj = JSON.parse(raw) as Record<string, AuditAIReview>;
      if (obj && typeof obj === 'object') {
        for (const [tgt, rev] of Object.entries(obj)) {
          if (rev && rev.source && rev.source !== 'builtin_expert') {
            map.set(`tgt:${tgt.toLowerCase()}`, rev);
          }
        }
      }
    }
  } catch {
    // ignore
  }
  return map;
}

export function persistAICache(map: Map<string, AuditAIReview>): void {
  try {
    const obj: Record<string, AuditAIReview> = {};
    let count = 0;
    const entries = Array.from(map.entries()).reverse();
    for (const [k, rev] of entries) {
      if (!k.startsWith('tgt:')) continue;
      if (!rev || !rev.source || rev.source === 'builtin_expert') continue;
      const tgt = k.slice(4);
      if (!obj[tgt]) {
        obj[tgt] = rev;
        if (++count >= 500) break;
      }
    }
    localStorage.setItem(AUDIT_AI_STORAGE_KEY, JSON.stringify(obj));
  } catch {
    // ignore
  }
}

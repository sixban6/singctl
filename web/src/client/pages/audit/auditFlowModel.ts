import { AuditAIReview, AuditFlowRecord, AuditReport } from '../../types';
import {
  applyLiveAIDampingToFlow,
  getFlowCacheKey,
  isUserWhitelistedTarget,
  stateRank,
  threatRank,
} from './auditHelpers';

export type AuditSortKey =
  | 'latest'
  | 'live_total'
  | 'live_up'
  | 'live_down'
  | 'active'
  | 'risk'
  | 'total'
  | 'upload'
  | 'download'
  | 'ratio';

export type AuditPresetFilter = 'all' | 'actionable' | 'uploading' | 'direct_ip' | 'pcdn';
export type AuditViewMode = 'list' | 'grouped';
export type AuditRefreshCadence = 2000 | 3000 | 5000 | 0;

export interface AuditSelectedDevice {
  ip: string;
  label: string;
  mac?: string;
}

export interface AuditPresetCounts {
  all: number;
  actionable: number;
  uploading: number;
  direct_ip: number;
  pcdn: number;
}

export interface AuditFlowTelemetry {
  count: number;
  activeFlowCount: number;
  activeConnCount: number;
  liveUploadBps: number;
  liveDownloadBps: number;
  uploadBytes: number;
  downloadBytes: number;
  directIpCount: number;
  whitelistedCount: number;
}

export interface AuditTargetGroup {
  targetKey: string;
  target: string;
  sampleFlow: AuditFlowRecord;
  flows: AuditFlowRecord[];
  deviceCount: number;
  deviceLabels: string[];
  activeConns: number;
  connCount: number;
  uploadBytes: number;
  downloadBytes: number;
  currentUploadBps: number;
  currentDownloadBps: number;
  maxRiskScore: number;
  maxThreat: string;
  maxThreatLabel: string;
  isDirectIp: boolean;
  appName: string;
  pcdnKind: string;
  allWhitelisted: boolean;
  lastSeenUnix: number;
  lastSeen: string;
}

export const AUDIT_SORT_OPTIONS: { value: AuditSortKey; label: string }[] = [
  { value: 'active', label: '综合活跃与风险' },
  { value: 'latest', label: '最新活跃' },
  { value: 'live_total', label: '实时总速率最快' },
  { value: 'live_up', label: '实时上行最快' },
  { value: 'live_down', label: '实时下行最快' },
  { value: 'risk', label: '风险评分最高' },
  { value: 'total', label: '累计总流量最多' },
  { value: 'upload', label: '累计上传最多' },
  { value: 'download', label: '累计下载最多' },
  { value: 'ratio', label: '上/下比最高' },
];

export function formatShortDuration(sec?: number): string {
  const s = Math.max(0, Math.floor(Number(sec || 0)));
  if (!Number.isFinite(s) || s <= 0) return '0s';
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  const remS = s % 60;
  if (m < 60) return remS > 0 ? `${m}m${String(remS).padStart(2, '0')}s` : `${m}m`;
  const h = Math.floor(m / 60);
  const remM = m % 60;
  if (h < 24) return remM > 0 ? `${h}h${String(remM).padStart(2, '0')}m` : `${h}h`;
  const d = Math.floor(h / 24);
  const remH = h % 24;
  return remH > 0 ? `${d}d${String(remH).padStart(2, '0')}h` : `${d}d`;
}

export function formatCompactRule(rule?: string): string {
  const raw = String(rule || '').trim();
  if (!raw) return 'default';
  const cleaned = raw
    .replace(/^rule_set=/i, '集:')
    .replace(/^domain_suffix=/i, '域:')
    .replace(/^domain=/i, '域:')
    .replace(/^ip_cidr=/i, 'IP:')
    .replace(/^protocol=/i, '协议:');
  return cleaned.length > 26 ? `${cleaned.slice(0, 24)}…` : cleaned;
}

export function getFlowSeenTimestamp(f: AuditFlowRecord): number {
  if (f.lastSeenUnix && f.lastSeenUnix > 0) return f.lastSeenUnix;
  if (!f.lastSeen) return 0;
  const norm = f.lastSeen.includes('T') ? f.lastSeen : f.lastSeen.replace(' ', 'T');
  const ts = Date.parse(norm);
  return Number.isFinite(ts) ? Math.floor(ts / 1000) : 0;
}

export function isActionableFlow(f: AuditFlowRecord): boolean {
  if (f.state === 'blocked' || f.state === 'whitelisted') return false;
  return f.threat === 'high_risk' || f.threat === 'suspicious' || (f.riskScore || 0) >= 45;
}

export function isUploadingFlow(f: AuditFlowRecord): boolean {
  if ((f.currentUploadBps || 0) > 0) return true;
  return (f.uploadRatio || 0) >= 1.5 && (f.uploadBytes || 0) >= 65536;
}

export function isPcdnOrClusterFlow(f: AuditFlowRecord): boolean {
  return Boolean(f.pcdnKind || f.subnetCluster?.suspicious || f.pcdnSwarm?.suspicious);
}

export function normalizeAuditFlows(
  report: AuditReport | null,
  getCachedReview: (f: AuditFlowRecord) => AuditAIReview | null,
): AuditFlowRecord[] {
  const raw = report?.flows || [];
  const whitelist = report?.whitelist || [];
  const out: AuditFlowRecord[] = [];
  for (const f of raw) {
    if (!f || f.state === 'blocked') continue;
    const rev = getCachedReview(f);
    const damped = applyLiveAIDampingToFlow(f, rev);
    if (damped.state !== 'blocked' && isUserWhitelistedTarget(damped.target, whitelist)) {
      out.push({ ...damped, state: 'whitelisted' });
    } else {
      out.push(damped);
    }
  }
  return out;
}

export interface AuditFilterOptions {
  searchQuery: string;
  selectedDevice: AuditSelectedDevice | null;
  selectedChain: string;
  networkFilter: '' | 'tcp' | 'udp';
  onlyActive: boolean;
  axisFilter: '' | 'security' | 'privacy';
  preset: AuditPresetFilter;
  hideWhitelisted: boolean;
  sortBy: AuditSortKey;
  sortDir: 'asc' | 'desc';
}

function matchesBaseFilters(
  f: AuditFlowRecord,
  opts: Omit<AuditFilterOptions, 'preset' | 'sortBy' | 'sortDir'>,
  matchedDevMACs: Set<string>,
): boolean {
  if (opts.onlyActive && (f.activeConns || 0) <= 0) return false;
  if (opts.hideWhitelisted && f.state === 'whitelisted') return false;
  if (opts.networkFilter && (f.network || '').toLowerCase() !== opts.networkFilter) return false;

  if (opts.selectedDevice) {
    const devIp = opts.selectedDevice.ip.toLowerCase();
    const devMac = (opts.selectedDevice.mac || '').toLowerCase();
    const ipHit = (f.deviceIp || '').toLowerCase() === devIp;
    const macHit = Boolean(devMac && (f.deviceMac || '').toLowerCase() === devMac);
    if (!ipHit && !macHit) return false;
  }

  if (opts.selectedChain) {
    const targetChain = opts.selectedChain.toLowerCase();
    const outLower = (f.outbound || 'DIRECT').toLowerCase();
    const chainsHit = (f.chains || []).some((c) => c.toLowerCase() === targetChain);
    if (outLower !== targetChain && !chainsHit) return false;
  }

  const q = opts.searchQuery.trim().toLowerCase();
  if (q) {
    const macLower = (f.deviceMac || '').toLowerCase();
    const hit =
      (f.target || '').toLowerCase().includes(q) ||
      (f.destIp || '').toLowerCase().includes(q) ||
      (f.subnetCluster?.cidr || '').toLowerCase().includes(q) ||
      (f.destPort ? String(f.destPort).includes(q) : false) ||
      (f.deviceIp || '').toLowerCase().includes(q) ||
      (f.deviceName || '').toLowerCase().includes(q) ||
      macLower.includes(q) ||
      (macLower !== '' && matchedDevMACs.has(macLower)) ||
      (f.outbound || '').toLowerCase().includes(q) ||
      (f.chains || []).some((c) => c.toLowerCase().includes(q)) ||
      (f.rule || '').toLowerCase().includes(q) ||
      (f.appName || '').toLowerCase().includes(q) ||
      (f.network || '').toLowerCase().includes(q);
    if (!hit) return false;
  }

  if (opts.axisFilter === 'security') {
    return (f.securityScore || 0) >= 15 || f.dominantAxis === 'security' || f.dominantAxis === 'both';
  }
  if (opts.axisFilter === 'privacy') {
    return (f.privacyScore || 0) >= 15 || f.dominantAxis === 'privacy' || f.dominantAxis === 'both';
  }
  return true;
}

export function matchesPresetFilter(f: AuditFlowRecord, preset: AuditPresetFilter): boolean {
  switch (preset) {
    case 'actionable':
      return isActionableFlow(f);
    case 'uploading':
      return isUploadingFlow(f);
    case 'direct_ip':
      return Boolean(f.isDirectIp);
    case 'pcdn':
      return isPcdnOrClusterFlow(f);
    default:
      return true;
  }
}

export function computeFlowPresetCounts(flows: AuditFlowRecord[]): AuditPresetCounts {
  const counts: AuditPresetCounts = {
    all: flows.length,
    actionable: 0,
    uploading: 0,
    direct_ip: 0,
    pcdn: 0,
  };
  for (const f of flows) {
    if (isActionableFlow(f)) counts.actionable++;
    if (isUploadingFlow(f)) counts.uploading++;
    if (f.isDirectIp) counts.direct_ip++;
    if (isPcdnOrClusterFlow(f)) counts.pcdn++;
  }
  return counts;
}

export function computeFlowsTelemetry(flows: AuditFlowRecord[]): AuditFlowTelemetry {
  let activeFlowCount = 0;
  let activeConnCount = 0;
  let liveUploadBps = 0;
  let liveDownloadBps = 0;
  let uploadBytes = 0;
  let downloadBytes = 0;
  let directIpCount = 0;
  let whitelistedCount = 0;

  for (const f of flows) {
    const act = Number(f.activeConns || 0);
    if (act > 0) {
      activeFlowCount++;
      activeConnCount += act;
      liveUploadBps += Number(f.currentUploadBps || 0);
      liveDownloadBps += Number(f.currentDownloadBps || 0);
    }
    uploadBytes += Number(f.uploadBytes || 0);
    downloadBytes += Number(f.downloadBytes || 0);
    if (f.isDirectIp) directIpCount++;
    if (f.state === 'whitelisted') whitelistedCount++;
  }

  return {
    count: flows.length,
    activeFlowCount,
    activeConnCount,
    liveUploadBps,
    liveDownloadBps,
    uploadBytes,
    downloadBytes,
    directIpCount,
    whitelistedCount,
  };
}

function compareRiskHierarchy(a: AuditFlowRecord, b: AuditFlowRecord): number {
  let c = stateRank(b.state) - stateRank(a.state);
  if (c === 0) c = threatRank(b.threat) - threatRank(a.threat);
  if (c === 0) c = (b.riskScore || 0) - (a.riskScore || 0);
  if (c === 0) c = (b.activeConns || 0) - (a.activeConns || 0);
  if (c === 0) c = (b.uploadBytes || 0) - (a.uploadBytes || 0);
  return c;
}

export function sortAuditFlows(
  flows: AuditFlowRecord[],
  sortBy: AuditSortKey,
  sortDir: 'asc' | 'desc',
): AuditFlowRecord[] {
  const out = [...flows];
  const sign = sortDir === 'asc' ? -1 : 1;
  out.sort((a, b) => {
    if (sortBy === 'latest') {
      const c = (getFlowSeenTimestamp(b) - getFlowSeenTimestamp(a)) * sign;
      if (c !== 0) return c;
      return ((b.activeConns || 0) - (a.activeConns || 0)) || getFlowCacheKey(a).localeCompare(getFlowCacheKey(b));
    }
    if (sortBy === 'live_total') {
      const aRate = (a.currentUploadBps || 0) + (a.currentDownloadBps || 0);
      const bRate = (b.currentUploadBps || 0) + (b.currentDownloadBps || 0);
      const c = (bRate - aRate) * sign;
      if (c !== 0) return c;
      const bTot = (b.uploadBytes || 0) + (b.downloadBytes || 0);
      const aTot = (a.uploadBytes || 0) + (a.downloadBytes || 0);
      return (bTot - aTot) * sign;
    }
    if (sortBy === 'live_up') {
      const c = ((b.currentUploadBps || 0) - (a.currentUploadBps || 0)) * sign;
      if (c !== 0) return c;
      return ((b.uploadBytes || 0) - (a.uploadBytes || 0)) * sign;
    }
    if (sortBy === 'live_down') {
      const c = ((b.currentDownloadBps || 0) - (a.currentDownloadBps || 0)) * sign;
      if (c !== 0) return c;
      return ((b.downloadBytes || 0) - (a.downloadBytes || 0)) * sign;
    }
    if (sortBy === 'total') {
      const aTot = (a.uploadBytes || 0) + (a.downloadBytes || 0);
      const bTot = (b.uploadBytes || 0) + (b.downloadBytes || 0);
      const c = (bTot - aTot) * sign;
      if (c !== 0) return c;
      return (b.riskScore || 0) - (a.riskScore || 0);
    }
    if (sortBy === 'upload') {
      const c = ((b.uploadBytes || 0) - (a.uploadBytes || 0)) * sign;
      if (c !== 0) return c;
      return (b.riskScore || 0) - (a.riskScore || 0);
    }
    if (sortBy === 'download') {
      const c = ((b.downloadBytes || 0) - (a.downloadBytes || 0)) * sign;
      if (c !== 0) return c;
      return (b.riskScore || 0) - (a.riskScore || 0);
    }
    if (sortBy === 'ratio') {
      const c = ((b.uploadRatio || 0) - (a.uploadRatio || 0)) * sign;
      if (c !== 0) return c;
      return (b.uploadBytes || 0) - (a.uploadBytes || 0);
    }
    if (sortBy === 'risk') {
      return compareRiskHierarchy(a, b) * sign;
    }
    const aAct = (a.activeConns || 0) > 0 ? 1 : 0;
    const bAct = (b.activeConns || 0) > 0 ? 1 : 0;
    let c = bAct - aAct;
    if (c === 0) c = compareRiskHierarchy(a, b);
    return c * sign;
  });
  return out;
}

export function filterAndSortAuditFlows(
  normalizedFlows: AuditFlowRecord[],
  report: AuditReport | null,
  opts: AuditFilterOptions,
): { baseFlows: AuditFlowRecord[]; filteredFlows: AuditFlowRecord[]; presetCounts: AuditPresetCounts } {
  const q = opts.searchQuery.trim().toLowerCase();
  const matchedDevMACs = new Set<string>();
  if (q) {
    for (const d of report?.devices || []) {
      if (d.deviceMac && d.deviceIp.toLowerCase() === q) {
        matchedDevMACs.add(d.deviceMac.toLowerCase());
      }
    }
  }

  const baseFlows = normalizedFlows.filter((f) => matchesBaseFilters(f, opts, matchedDevMACs));
  const presetCounts = computeFlowPresetCounts(baseFlows);
  const afterPreset =
    opts.preset === 'all' ? baseFlows : baseFlows.filter((f) => matchesPresetFilter(f, opts.preset));
  const filteredFlows = sortAuditFlows(afterPreset, opts.sortBy, opts.sortDir);
  return { baseFlows, filteredFlows, presetCounts };
}

export function groupFlowsByTarget(
  flows: AuditFlowRecord[],
  sortBy: AuditSortKey,
  sortDir: 'asc' | 'desc',
): AuditTargetGroup[] {
  const map = new Map<string, AuditTargetGroup>();
  for (const f of flows) {
    const key = (f.target || getFlowCacheKey(f)).toLowerCase();
    let g = map.get(key);
    if (!g) {
      g = {
        targetKey: key,
        target: f.target,
        sampleFlow: f,
        flows: [],
        deviceCount: 0,
        deviceLabels: [],
        activeConns: 0,
        connCount: 0,
        uploadBytes: 0,
        downloadBytes: 0,
        currentUploadBps: 0,
        currentDownloadBps: 0,
        maxRiskScore: f.riskScore || 0,
        maxThreat: f.threat || 'normal',
        maxThreatLabel: f.threatLabel || '正常',
        isDirectIp: Boolean(f.isDirectIp),
        appName: f.appName || '',
        pcdnKind: f.pcdnKind || '',
        allWhitelisted: f.state === 'whitelisted',
        lastSeenUnix: getFlowSeenTimestamp(f),
        lastSeen: f.lastSeen || '',
      };
      map.set(key, g);
    }
    g.flows.push(f);
    g.activeConns += Number(f.activeConns || 0);
    g.connCount += Math.max(Number(f.activeConns || 0), Number(f.connCount || 1));
    g.uploadBytes += Number(f.uploadBytes || 0);
    g.downloadBytes += Number(f.downloadBytes || 0);
    g.currentUploadBps += Number(f.currentUploadBps || 0);
    g.currentDownloadBps += Number(f.currentDownloadBps || 0);
    if (f.state !== 'whitelisted') g.allWhitelisted = false;
    if (!g.appName && f.appName) g.appName = f.appName;
    if (!g.pcdnKind && f.pcdnKind) g.pcdnKind = f.pcdnKind;
    const ts = getFlowSeenTimestamp(f);
    if (ts > g.lastSeenUnix) {
      g.lastSeenUnix = ts;
      g.lastSeen = f.lastSeen || g.lastSeen;
    }
    if (
      threatRank(f.threat) > threatRank(g.maxThreat) ||
      (threatRank(f.threat) === threatRank(g.maxThreat) && (f.riskScore || 0) > g.maxRiskScore)
    ) {
      g.maxRiskScore = f.riskScore || 0;
      g.maxThreat = f.threat || 'normal';
      g.maxThreatLabel = f.threatLabel || '正常';
      g.sampleFlow = f;
    }
  }

  const groups = Array.from(map.values());
  for (const g of groups) {
    const devMap = new Map<string, string>();
    for (const f of g.flows) {
      const id = f.deviceIp || f.deviceMac || 'unknown';
      if (!devMap.has(id)) {
        devMap.set(id, f.deviceName || f.deviceIp || '未知设备');
      }
    }
    g.deviceCount = devMap.size;
    g.deviceLabels = Array.from(devMap.values());
  }

  const sign = sortDir === 'asc' ? -1 : 1;
  groups.sort((a, b) => {
    if (sortBy === 'latest') return (b.lastSeenUnix - a.lastSeenUnix) * sign;
    if (sortBy === 'live_up') return (b.currentUploadBps - a.currentUploadBps || b.uploadBytes - a.uploadBytes) * sign;
    if (sortBy === 'live_down') return (b.currentDownloadBps - a.currentDownloadBps || b.downloadBytes - a.downloadBytes) * sign;
    if (sortBy === 'upload') return (b.uploadBytes - a.uploadBytes) * sign;
    if (sortBy === 'download') return (b.downloadBytes - a.downloadBytes) * sign;
    if (sortBy === 'ratio') {
      const ra = a.uploadBytes / Math.max(1, a.downloadBytes);
      const rb = b.uploadBytes / Math.max(1, b.downloadBytes);
      return (rb - ra) * sign;
    }
    if (sortBy === 'risk') {
      const c = (threatRank(b.maxThreat) - threatRank(a.maxThreat)) || (b.maxRiskScore - a.maxRiskScore);
      return (c || b.uploadBytes - a.uploadBytes) * sign;
    }
    const actCmp = (b.activeConns > 0 ? 1 : 0) - (a.activeConns > 0 ? 1 : 0);
    if (actCmp !== 0) return actCmp * sign;
    const riskCmp = (threatRank(b.maxThreat) - threatRank(a.maxThreat)) || (b.maxRiskScore - a.maxRiskScore);
    if (riskCmp !== 0) return riskCmp * sign;
    return (b.deviceCount - a.deviceCount || b.uploadBytes - a.uploadBytes) * sign;
  });

  return groups;
}

import React, { useState, useEffect, useCallback, useMemo, useRef } from 'react';
import {
  ShieldAlert,
  Ban,
  Bot,
  Download,
  RefreshCw,
  Search,
  ShieldCheck,
  AlertTriangle,
  RotateCw,
  Trash2,
  Plus,
  X,
  Laptop,
  Network,
} from 'lucide-react';
import {
  Badge,
  Button,
  DataColumn,
  DataTable,
  PageHeader,
  SectionCard,
  SlideDrawer,
  useToast,
} from '../../ui';
import {
  CLIENT_INVALIDATE_EVENT,
  ClientInvalidateScope,
  emitClientInvalidate,
  peekCachedQuery,
  writeCachedQuery,
} from '../../hooks';
import { clientApi } from '../api';
import {
  AuditAIConfig,
  AuditAIReview,
  AuditBlockRule,
  AuditDeviceSummary,
  AuditFlowRecord,
  AuditReport,
} from '../types';

const AUDIT_AI_STORAGE_KEY = 'sc_audit_ai_cache_v2';
const AUDIT_AI_ENABLE_KEY = 'sc_audit_ai_enable';

const PRESET_RULESETS: { label: string; url: string; reason: string }[] = [
  {
    label: '🎮 王者荣耀 (hok.srs)',
    url: 'https://raw.githubusercontent.com/sixban6/rulesets/main/rule/hok.srs',
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
    url: 'https://raw.githubusercontent.com/sixban6/rulesets/main/rule/douyin.srs',
    reason: '规则集封禁: 📱 抖音短视频 (douyin.srs)',
  },
  {
    label: '📱 微信视频号 (wx_shortvideo.srs)',
    url: 'https://raw.githubusercontent.com/sixban6/rulesets/main/rule/wx_shortvideo.srs',
    reason: '规则集封禁: 📱 微信视频号 (wx_shortvideo.srs)',
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

function isProtectedBootstrapTarget(raw: string): boolean {
  const t = String(raw || '').trim().toLowerCase().replace(/\.$/, '');
  if (!t) return false;
  if (PROTECTED_BOOTSTRAP_IPS.has(t)) return true;
  return PROTECTED_BOOTSTRAP_DOMAINS.some((d) => t === d || t.endsWith('.' + d));
}

function isUserWhitelistedTarget(raw: string, whitelist: string[]): boolean {
  const t = String(raw || '').trim().toLowerCase().replace(/\.$/, '');
  if (!t || !whitelist.length) return false;
  return whitelist.some((w) => {
    const nw = String(w || '').trim().toLowerCase().replace(/\/(32|128)$/, '').replace(/\.$/, '');
    return Boolean(nw && (t === nw || t.endsWith('.' + nw)));
  });
}

function getFlowCacheKey(f: AuditFlowRecord): string {
  return f.key || f.id || `${f.deviceIp}|${f.target}|${f.network}`;
}

function getFlowTargetKey(f: AuditFlowRecord): string {
  return (f.target || getFlowCacheKey(f)).toLowerCase();
}

function fmtBytes(n?: number): string {
  const v = Number(n || 0);
  if (v < 1024) return `${v} B`;
  if (v < 1024 * 1024) return `${(v / 1024).toFixed(1)} KB`;
  if (v < 1024 * 1024 * 1024) return `${(v / (1024 * 1024)).toFixed(1)} MB`;
  return `${(v / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}

const NONLINEAR_FACTOR_LABELS: Record<string, string> = {
  upload_asymmetry: '上/下行流量倒挂',
  direct_ip_upload: '绕过 DNS 纯 IP 外发',
  beacon_heartbeat: '规律定时信标心跳',
  domain_entropy: '高熵随机域名特征',
  telemetry_fingerprint: '遥测 / PCDN 指纹命中',
  privacy_axis_extra: '暗夜作息 / 明文隐私附加',
};

function formatDeviceRoleLabel(role?: string): string {
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

function formatOutboundMeta(outbound?: string): {
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

function formatRelativeSeen(seenStr?: string): string {
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

function threatRank(t?: string): number {
  if (t === 'high_risk') return 3;
  if (t === 'suspicious') return 2;
  if (t === 'notice') return 1;
  return 0;
}

function stateRank(s?: string): number {
  if (s === 'blocked') return 1;
  if (s === 'whitelisted') return 0;
  return 2;
}

function applyLiveAIDampingToFlow(
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
  const lowerTgt = String(f.target || '').toLowerCase();
  const hasPcdnKw = ['pcdn', 'xycdn', 'onething', 'szbdyd', 'mcdn', 'bcdn', 'uhabo', 'stun.'].some((k) =>
    lowerTgt.includes(k),
  );
  const isHardAnomaly =
    Boolean(f.isDirectIp && isNonStdPort && isUploadDom) ||
    hasPcdnKw ||
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

function loadSavedAICache(): Map<string, AuditAIReview> {
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

function persistAICache(map: Map<string, AuditAIReview>) {
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

export const AUDIT_DEFAULT_CACHE_KEY = 'client:audit:default';
const FLOW_RENDER_STEP = 80;

export interface AuditPageProps {
  active?: boolean;
}

export const AuditPage: React.FC<AuditPageProps> = ({ active = true }) => {
  const { success, error, toast } = useToast();

  // Filters & controls
  const [deviceFilter, setDeviceFilter] = useState('');
  const [axisFilter, setAxisFilter] = useState<'' | 'security' | 'privacy'>('');
  const [onlySuspect, setOnlySuspect] = useState(false);
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [aiEnabled, setAiEnabled] = useState<boolean>(() => {
    try {
      return localStorage.getItem(AUDIT_AI_ENABLE_KEY) !== '0';
    } catch {
      return true;
    }
  });
  const [sortBy, setSortBy] = useState<'active' | 'risk' | 'upload' | 'download' | 'ratio'>('active');
  const [sortDir, setSortDir] = useState<'asc' | 'desc'>('desc');
  const [visibleLimit, setVisibleLimit] = useState(FLOW_RENDER_STEP);

  // Data state (initialized synchronously from SWR cache for 0ms instant open)
  const [report, setReport] = useState<AuditReport | null>(
    () => peekCachedQuery<AuditReport>(AUDIT_DEFAULT_CACHE_KEY) ?? null,
  );
  const [loading, setLoading] = useState<boolean>(
    () => !peekCachedQuery<AuditReport>(AUDIT_DEFAULT_CACHE_KEY),
  );
  const [refreshing, setRefreshing] = useState(false);
  const [filterTransitioning, setFilterTransitioning] = useState(false);
  const [lastUpdated, setLastUpdated] = useState('');
  const requestSeqRef = useRef(0);
  const abortCtrlRef = useRef<AbortController | null>(null);

  // AI cache + reactive version counter
  const aiCacheRef = useRef<Map<string, AuditAIReview>>(loadSavedAICache());
  const [aiRevTick, setAiRevTick] = useState(0);
  const [pendingTargets, setPendingTargets] = useState<Set<string>>(() => new Set());
  const [aiStatusText, setAiStatusText] = useState('');
  const aiInFlightRef = useRef(false);
  const aiRescheduleRef = useRef(false);

  // Concurrency guards for auto refresh
  const actionInFlightRef = useRef(0);
  const pointerDownUntilRef = useRef(0);

  // Drawers & Modals
  const [blockDrawerOpen, setBlockDrawerOpen] = useState(false);
  const [aiCfgOpen, setAiCfgOpen] = useState(false);
  const [detailFlowKey, setDetailFlowKey] = useState<string | null>(null);

  // Manual block / whitelist drawer inputs
  const [presetUrl, setPresetUrl] = useState('');
  const [presetReason, setPresetReason] = useState('');
  const [manualTarget, setManualTarget] = useState('');
  const [manualDevice, setManualDevice] = useState('');
  const [blockBusy, setBlockBusy] = useState(false);
  const [busyFlowKeys, setBusyFlowKeys] = useState<Set<string>>(() => new Set());

  // AI config drawer inputs
  const [aiConfig, setAiConfig] = useState<AuditAIConfig>({
    baseUrl: '',
    apiKey: '',
    model: 'antigravity/gemini-3.8-flash',
  });
  const [aiCfgSaving, setAiCfgSaving] = useState(false);
  const [aiModels, setAiModels] = useState<string[]>([]);
  const [aiModelsLoading, setAiModelsLoading] = useState(false);
  const [aiModelsHint, setAiModelsHint] = useState<string>('');
  const [manualModelInput, setManualModelInput] = useState(false);
  const lastFetchedSigRef = useRef<string>('');

  const tableContainerRef = useRef<HTMLDivElement>(null);
  const flowScrollRef = useRef<HTMLDivElement>(null);

  const setCachedReview = useCallback(
    (flowOrKey: AuditFlowRecord | string, target: string, rev: AuditAIReview, skipStorage = false) => {
      if (!rev) return;
      const cache = aiCacheRef.current;
      const k = typeof flowOrKey === 'string' ? flowOrKey : getFlowCacheKey(flowOrKey);
      const tgt = (target || '').toLowerCase();
      const prev = cache.get(k) || (tgt ? cache.get(`tgt:${tgt}`) : undefined);
      const isNewLLM = Boolean(rev.source && rev.source !== 'builtin_expert');
      const hadPrevLLM = Boolean(prev && prev.source && prev.source !== 'builtin_expert');
      if (isNewLLM || !hadPrevLLM) {
        cache.set(k, rev);
        if (tgt) cache.set(`tgt:${tgt}`, rev);
        if (isNewLLM && !skipStorage) {
          persistAICache(cache);
        }
      }
    },
    [],
  );

  const getCachedReview = useCallback(
    (f: AuditFlowRecord): AuditAIReview | null => {
      void aiRevTick;
      const cache = aiCacheRef.current;
      const k = getFlowCacheKey(f);
      const tgt = (f.target || '').toLowerCase();
      return cache.get(k) || (tgt ? cache.get(`tgt:${tgt}`) : undefined) || f.aiReview || null;
    },
    [aiRevTick],
  );

  const hasLoadedReportRef = useRef<boolean>(Boolean(peekCachedQuery(AUDIT_DEFAULT_CACHE_KEY)));

  const loadAudit = useCallback(
    async (silent = false) => {
      if (silent && (actionInFlightRef.current > 0 || Date.now() < pointerDownUntilRef.current)) {
        return;
      }

      abortCtrlRef.current?.abort();
      const ctrl = new AbortController();
      abortCtrlRef.current = ctrl;
      const seq = ++requestSeqRef.current;

      if (!silent) {
        if (!hasLoadedReportRef.current) {
          setLoading(true);
        } else {
          setFilterTransitioning(true);
        }
      }
      setRefreshing(true);

      const trimDev = deviceFilter.trim();
      const qs = new URLSearchParams();
      if (trimDev) qs.set('device', trimDev);
      if (onlySuspect) qs.set('suspicious', '1');
      if (sortBy) qs.set('sort', sortBy);
      if (sortDir) qs.set('dir', sortDir);
      const isDefaultQuery = !trimDev && !onlySuspect && sortBy === 'active' && sortDir === 'desc';

      try {
        const rep = await clientApi.getAudit(qs, ctrl.signal);
        if (ctrl.signal.aborted || seq !== requestSeqRef.current) {
          return;
        }
        if (silent && (actionInFlightRef.current > 0 || Date.now() < pointerDownUntilRef.current)) {
          return;
        }
        let synced = false;
        (rep.flows || []).forEach((f) => {
          if (f.aiReview) {
            setCachedReview(f, f.target, f.aiReview, true);
            synced = true;
          }
        });
        if (synced) persistAICache(aiCacheRef.current);
        hasLoadedReportRef.current = true;
        if (isDefaultQuery) {
          writeCachedQuery(AUDIT_DEFAULT_CACHE_KEY, rep);
        }
        setReport(rep);
        setLastUpdated(new Date().toLocaleTimeString());
        if (synced) setAiRevTick((t) => t + 1);
      } catch (e) {
        if (ctrl.signal.aborted || (e as Error)?.name === 'AbortError') {
          return;
        }
        if (!silent) {
          error((e as Error).message || '加载审计数据失败');
        }
      } finally {
        if (seq === requestSeqRef.current) {
          setLoading(false);
          setRefreshing(false);
          setFilterTransitioning(false);
        }
      }
    },
    [deviceFilter, onlySuspect, sortBy, sortDir, setCachedReview, error],
  );

  // Initial & filter/sort change fetch (instant cached frame + immediate background sync)
  useEffect(() => {
    void loadAudit(hasLoadedReportRef.current && !deviceFilter.trim() && !onlySuspect && sortBy === 'risk' && sortDir === 'desc');
    return () => {
      abortCtrlRef.current?.abort();
    };
  }, [loadAudit, deviceFilter, onlySuspect, sortBy, sortDir]);

  // Tab activation sync: 0ms instant view + 0ms unconditional background revalidation
  const prevActiveRef = useRef<boolean>(active);
  useEffect(() => {
    const becameActive = !prevActiveRef.current && active;
    prevActiveRef.current = active;
    if (becameActive) {
      void loadAudit(true);
    }
  }, [active, loadAudit]);

  // Cross-page invalidation listener (e.g. Console task or Config save)
  useEffect(() => {
    const onInvalidate = (ev: Event) => {
      const scope = (ev as CustomEvent<ClientInvalidateScope>).detail;
      if (!scope || scope === 'all' || scope === 'audit') {
        void loadAudit(true);
      }
    };
    window.addEventListener(CLIENT_INVALIDATE_EVENT, onInvalidate);
    return () => window.removeEventListener(CLIENT_INVALIDATE_EVENT, onInvalidate);
  }, [loadAudit]);

  useEffect(() => {
    if (!active || !autoRefresh) return;
    const timer = window.setInterval(() => {
      if (document.visibilityState === 'visible') {
        void loadAudit(true);
      }
    }, 5000);
    return () => window.clearInterval(timer);
  }, [active, autoRefresh, loadAudit]);

  const fetchAIModels = useCallback(
    async (baseUrl: string, apiKey: string, silent = false) => {
      const cleanBase = (baseUrl || '').trim();
      const cleanKey = (apiKey || '').trim();
      lastFetchedSigRef.current = `${cleanBase}|${cleanKey}`;
      setAiModelsLoading(true);
      try {
        const res = await clientApi.fetchAuditAIModels({
          baseUrl: cleanBase,
          apiKey: cleanKey,
        });
        if (res.ok && res.models && res.models.length > 0) {
          setAiModels(res.models);
          setAiModelsHint('');
          setManualModelInput(false);
          setAiConfig((prev) => {
            const cur = (prev.model || '').trim();
            if (!cur) {
              return { ...prev, model: res.models[0] };
            }
            return prev;
          });
          if (!silent) {
            success(`已从网关拉取 ${res.models.length} 个可用模型`);
          }
        } else {
          setAiModels([]);
          setManualModelInput(true);
          setAiModelsHint(res.error || '网关未返回模型列表');
          if (!silent) {
            error(`${res.error || '未能拉取到模型列表'}，请手动填写模型名称`);
          }
        }
      } catch (e) {
        const msg = (e as Error).message || '连接网关失败';
        setAiModels([]);
        setManualModelInput(true);
        setAiModelsHint(msg);
        if (!silent) {
          error(`拉取模型失败（${msg}），请手动填写`);
        }
      } finally {
        setAiModelsLoading(false);
      }
    },
    [success, error],
  );

  const loadAIConfig = useCallback(async () => {
    try {
      const cfg = await clientApi.getAuditAIConfig();
      const nextCfg: AuditAIConfig = {
        baseUrl: cfg.baseUrl || '',
        apiKey: cfg.apiKey || '',
        model: cfg.model || 'antigravity/gemini-3.8-flash',
        suggestedLanUrl: cfg.suggestedLanUrl,
      };
      setAiConfig(nextCfg);
      void fetchAIModels(nextCfg.baseUrl, nextCfg.apiKey, true);
    } catch (e) {
      error((e as Error).message || '读取 AI 网关配置失败');
    }
  }, [error, fetchAIModels]);

  const openAIConfigDrawer = useCallback(() => {
    setAiCfgOpen(true);
    loadAIConfig();
  }, [loadAIConfig]);

  const handleSaveAIConfig = async () => {
    setAiCfgSaving(true);
    try {
      const res = await clientApi.saveAuditAIConfig({
        baseUrl: aiConfig.baseUrl.trim(),
        apiKey: aiConfig.apiKey.trim(),
        model: aiConfig.model.trim() || 'antigravity/gemini-3.8-flash',
      });
      success(res.message || 'AI 网关配置已保存');
      setAiCfgOpen(false);
    } catch (e) {
      error((e as Error).message || '保存 AI 网关配置失败');
    } finally {
      setAiCfgSaving(false);
    }
  };

  // Filtered, damped, and sorted flows
  const processedFlows = useMemo(() => {
    const raw = report?.flows || [];
    const whitelist = report?.whitelist || [];
    const damped = raw
      .filter((f) => {
        if (!f || f.state === 'blocked') return false;
        if (axisFilter === 'security') {
          return (f.securityScore || 0) >= 15 || f.dominantAxis === 'security' || f.dominantAxis === 'both';
        }
        if (axisFilter === 'privacy') {
          return (f.privacyScore || 0) >= 15 || f.dominantAxis === 'privacy' || f.dominantAxis === 'both';
        }
        return true;
      })
      .map((f) => {
        const rev = getCachedReview(f);
        const withDamp = applyLiveAIDampingToFlow(f, rev);
        // Preserve whitelist reflection cleanly
        if (withDamp.state !== 'blocked' && isUserWhitelistedTarget(withDamp.target, whitelist)) {
          return { ...withDamp, state: 'whitelisted' };
        }
        return withDamp;
      });

    const compareRiskHierarchy = (a: AuditFlowRecord, b: AuditFlowRecord): number => {
      let c = stateRank(b.state) - stateRank(a.state);
      if (c === 0) c = threatRank(b.threat) - threatRank(a.threat);
      if (c === 0) c = (b.riskScore || 0) - (a.riskScore || 0);
      if (c === 0) c = (b.activeConns || 0) - (a.activeConns || 0);
      if (c === 0) c = (b.uploadBytes || 0) - (a.uploadBytes || 0);
      return c;
    };

    const sign = sortDir === 'asc' ? -1 : 1;
    damped.sort((a, b) => {
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
      // 默认 sortBy === 'active'：当前活跃连接置顶 -> 组内按风险评分层级从高到低排序
      const aAct = (a.activeConns || 0) > 0 ? 1 : 0;
      const bAct = (b.activeConns || 0) > 0 ? 1 : 0;
      let c = bAct - aAct;
      if (c === 0) c = compareRiskHierarchy(a, b);
      return c * sign;
    });
    return damped;
  }, [report, axisFilter, sortBy, sortDir, getCachedReview]);

  const activeFlowCount = useMemo(
    () => processedFlows.reduce((acc, f) => acc + ((f.activeConns || 0) > 0 ? 1 : 0), 0),
    [processedFlows],
  );

  // 仅当用户主动改变筛选条件或排序维度时重置渲染游标并回到顶部（5s 静默刷新不打断当前滚动位置）
  useEffect(() => {
    setVisibleLimit(FLOW_RENDER_STEP);
    if (flowScrollRef.current) {
      flowScrollRef.current.scrollTop = 0;
    }
  }, [deviceFilter, axisFilter, onlySuspect, sortBy, sortDir]);

  const visibleFlows = useMemo(
    () => processedFlows.slice(0, visibleLimit),
    [processedFlows, visibleLimit],
  );

  // 超宽屏 / 大视口下若初始批次未填满滚动区，自动补齐下一批确保出现滚动条
  useEffect(() => {
    const el = flowScrollRef.current;
    if (!el || visibleLimit >= processedFlows.length) return;
    if (el.scrollHeight - el.scrollTop - el.clientHeight < 200) {
      setVisibleLimit((prev) => Math.min(processedFlows.length, prev + FLOW_RENDER_STEP));
    }
  }, [visibleLimit, processedFlows.length]);

  const handleFlowTableScroll = useCallback(
    (e: React.UIEvent<HTMLDivElement>) => {
      pointerDownUntilRef.current = Math.max(pointerDownUntilRef.current, Date.now() + 500);
      const el = e.currentTarget;
      if (
        visibleLimit < processedFlows.length &&
        el.scrollHeight - el.scrollTop - el.clientHeight < 280
      ) {
        setVisibleLimit((prev) => Math.min(processedFlows.length, prev + FLOW_RENDER_STEP));
      }
    },
    [visibleLimit, processedFlows.length],
  );

  const isDualAlert = useCallback(
    (f: AuditFlowRecord): boolean => {
      if (!f || f.state === 'blocked' || f.state === 'whitelisted') return false;
      const rev = getCachedReview(f);
      if (!rev || rev.verdict !== 'safe_to_block') return false;
      return (
        (f.riskScore || 0) >= 45 ||
        f.threat === 'high_risk' ||
        f.threat === 'suspicious' ||
        (f.securityScore || 0) >= 40 ||
        (f.privacyScore || 0) >= 40
      );
    },
    [getCachedReview],
  );

  // Progressive P0/P1 AI prefetch scheduler
  const scheduleAIPrefetch = useCallback(async () => {
    if (!aiEnabled || !processedFlows.length) {
      setAiStatusText('');
      return;
    }
    if (aiInFlightRef.current) {
      aiRescheduleRef.current = true;
      return;
    }

    // Compute visible P0 slice and P1 2x lookahead (intersection of scroll container & window viewport)
    const vh = window.innerHeight || document.documentElement.clientHeight || 800;
    const containerEl = flowScrollRef.current;
    const bounds = containerEl ? containerEl.getBoundingClientRect() : null;
    const viewTop = bounds ? Math.max(0, bounds.top) : 0;
    const viewBottom = bounds ? Math.min(vh, bounds.bottom) : vh;
    const rows = (containerEl || tableContainerRef.current)?.querySelectorAll('tbody tr') || [];
    let firstVis = -1;
    let lastVis = -1;
    rows.forEach((tr, idx) => {
      const rect = tr.getBoundingClientRect();
      if (rect.height === 0) return;
      if (rect.bottom >= viewTop - 40 && rect.top <= viewBottom + 40) {
        if (firstVis === -1) firstVis = idx;
        lastVis = idx;
      }
    });
    if (firstVis === -1) {
      firstVis = 0;
      lastVis = Math.min(processedFlows.length - 1, 14);
    }
    const visCount = Math.max(12, lastVis - firstVis + 1);
    const prefetchEnd = Math.min(processedFlows.length - 1, lastVis + visCount * 2);

    const pickBatch = (start: number, end: number, max: number) => {
      const seen = new Set<string>();
      const out: AuditFlowRecord[] = [];
      for (let i = start; i <= end; i++) {
        const f = processedFlows[i];
        if (!f) continue;
        const tk = getFlowTargetKey(f);
        if (seen.has(tk) || getCachedReview(f)) continue;
        seen.add(tk);
        out.push(f);
        if (out.length >= max) break;
      }
      return out;
    };

    let batch = pickBatch(firstVis, lastVis, 8);
    let label = '可视区';
    if (!batch.length) {
      batch = pickBatch(lastVis + 1, prefetchEnd, 10);
      label = '预取区';
    }
    if (!batch.length) {
      setAiStatusText('');
      return;
    }

    aiInFlightRef.current = true;
    aiRescheduleRef.current = false;
    const targets = batch.map(getFlowTargetKey);
    if (label === '可视区') {
      setPendingTargets((prev) => {
        const next = new Set(prev);
        targets.forEach((t) => next.add(t));
        return next;
      });
    }
    setAiStatusText(`${label} ${batch.length} 条…`);

    try {
      const res = await clientApi.reviewAuditBatch(batch, false);
      if (res && res.results) {
        let updated = false;
        batch.forEach((f) => {
          const fk = getFlowCacheKey(f);
          const tk = getFlowTargetKey(f);
          const rev = res.results[fk] || res.results[f.target] || res.results[tk];
          if (rev) {
            setCachedReview(f, f.target, rev, true);
            updated = true;
          }
        });
        if (updated) {
          persistAICache(aiCacheRef.current);
          setAiRevTick((t) => t + 1);
        }
      }
    } catch {
      // silent prefetch fallback
    } finally {
      aiInFlightRef.current = false;
      setPendingTargets((prev) => {
        const next = new Set(prev);
        targets.forEach((t) => next.delete(t));
        return next;
      });
      setAiStatusText('');
      if (aiRescheduleRef.current) {
        window.setTimeout(() => scheduleAIPrefetch(), 80);
      }
    }
  }, [aiEnabled, processedFlows, getCachedReview, setCachedReview]);

  useEffect(() => {
    if (!active || !aiEnabled) {
      if (!aiEnabled) setAiStatusText('');
      return;
    }
    const timer = window.setTimeout(() => {
      scheduleAIPrefetch();
    }, 180);
    return () => window.clearTimeout(timer);
  }, [active, aiEnabled, processedFlows.length, lastUpdated, scheduleAIPrefetch]);

  useEffect(() => {
    if (!active || !aiEnabled) return;
    let timer: number | null = null;
    const onScroll = () => {
      if (timer) window.clearTimeout(timer);
      timer = window.setTimeout(() => scheduleAIPrefetch(), 180);
    };
    const scrollEl = flowScrollRef.current;
    window.addEventListener('scroll', onScroll, { passive: true });
    scrollEl?.addEventListener('scroll', onScroll, { passive: true });
    return () => {
      window.removeEventListener('scroll', onScroll);
      scrollEl?.removeEventListener('scroll', onScroll);
      if (timer) window.clearTimeout(timer);
    };
  }, [active, aiEnabled, visibleFlows.length, scheduleAIPrefetch]);

  const handleToggleAI = (checked: boolean) => {
    setAiEnabled(checked);
    try {
      localStorage.setItem(AUDIT_AI_ENABLE_KEY, checked ? '1' : '0');
    } catch {
      // ignore
    }
  };

  const reviewSingleFlow = async (f: AuditFlowRecord, force = false) => {
    const tk = getFlowTargetKey(f);
    setPendingTargets((prev) => new Set(prev).add(tk));
    try {
      const res = await clientApi.reviewAuditBatch([f], force);
      const fk = getFlowCacheKey(f);
      const rev = res.results?.[fk] || res.results?.[f.target] || res.results?.[tk];
      if (rev) {
        setCachedReview(f, f.target, rev, false);
        setAiRevTick((t) => t + 1);
        success(res.usedRemote ? 'AI 深度研判已更新' : '已使用内置离线知识库研判');
      }
    } catch (e) {
      error((e as Error).message || 'AI 研判失败');
    } finally {
      setPendingTargets((prev) => {
        const next = new Set(prev);
        next.delete(tk);
        return next;
      });
    }
  };

  const handleBlockFlow = async (f: AuditFlowRecord, deviceOnly = false) => {
    if (isProtectedBootstrapTarget(f.target)) {
      toast('受核心防断网基础设施保护，禁止拉黑此目标', 'info');
      return;
    }
    const fk = getFlowCacheKey(f);
    const scopedSource =
      deviceOnly && f.deviceIp && f.deviceIp !== '127.0.0.1' ? f.deviceIp : '';
    actionInFlightRef.current++;
    setBusyFlowKeys((prev) => new Set(prev).add(fk));
    try {
      const reason = (f.reasons && f.reasons[0]) || 'WebUI 安全审计拉黑';
      const res = await clientApi.blockAuditTarget(f.target, scopedSource, reason);
      success(
        res.message ||
          (scopedSource ? `已仅针对 ${scopedSource} 阻断 ${f.target}` : `已全局拉黑 ${f.target}`),
      );
      if (detailFlowKey === fk) {
        setDetailFlowKey(null);
      }
      emitClientInvalidate('adguard');
      await loadAudit(false);
    } catch (e) {
      error((e as Error).message || '拉黑失败');
    } finally {
      actionInFlightRef.current = Math.max(0, actionInFlightRef.current - 1);
      setBusyFlowKeys((prev) => {
        const next = new Set(prev);
        next.delete(fk);
        return next;
      });
    }
  };

  const handleManualBlock = async (overrideTarget?: string, overrideReason?: string) => {
    const target = (overrideTarget ?? manualTarget).trim();
    if (!target) {
      toast('请输入域名、IP 或 .srs/.json 规则集 URL', 'info');
      return;
    }
    if (isProtectedBootstrapTarget(target)) {
      toast('受核心防断网基础设施保护，禁止拉黑此目标', 'info');
      return;
    }
    setBlockBusy(true);
    actionInFlightRef.current++;
    try {
      const isRuleset = /^https?:\/\//i.test(target) || /\.(srs|json)(\?|#|$)/i.test(target);
      const reason = overrideReason || presetReason || (isRuleset ? 'WebUI 规则集整包导入' : 'WebUI 手动拉黑');
      const res = await clientApi.blockAuditTarget(target, manualDevice.trim(), reason);
      success(res.message || '已添加封禁规则');
      if (!overrideTarget) {
        setManualTarget('');
        setManualDevice('');
        setPresetUrl('');
        setPresetReason('');
      }
      emitClientInvalidate('adguard');
      await loadAudit(false);
    } catch (e) {
      error((e as Error).message || '添加拉黑规则失败');
    } finally {
      setBlockBusy(false);
      actionInFlightRef.current = Math.max(0, actionInFlightRef.current - 1);
    }
  };

  const handleUnblock = async (r: AuditBlockRule) => {
    actionInFlightRef.current++;
    try {
      const res = await clientApi.unblockAuditTarget(r.target, r.source_ip || '');
      success(res.message || `已解封 ${r.target}`);
      emitClientInvalidate('adguard');
      await loadAudit(false);
    } catch (e) {
      error((e as Error).message || '解封失败');
    } finally {
      actionInFlightRef.current = Math.max(0, actionInFlightRef.current - 1);
    }
  };

  const handleWhitelist = async (action: 'add' | 'remove', rawTarget?: string) => {
    const target = (rawTarget ?? manualTarget).trim();
    if (!target) {
      toast('请输入要加入白名单的域名或 IP', 'info');
      return;
    }
    actionInFlightRef.current++;
    try {
      const res = await clientApi.whitelistAuditTarget(action, target);
      success(res.message || (action === 'add' ? '已加入白名单' : '已移出白名单'));
      if (action === 'add' && !rawTarget) setManualTarget('');
      emitClientInvalidate('adguard');
      await loadAudit(false);
    } catch (e) {
      error((e as Error).message || '白名单操作失败');
    } finally {
      actionInFlightRef.current = Math.max(0, actionInFlightRef.current - 1);
    }
  };

  const handleExportCSV = async () => {
    try {
      const qs = new URLSearchParams();
      if (deviceFilter.trim()) qs.set('device', deviceFilter.trim());
      if (onlySuspect) qs.set('suspicious', '1');
      if (sortBy) qs.set('sort', sortBy);
      if (sortDir) qs.set('dir', sortDir);
      qs.set('format', 'csv');
      const csv = await clientApi.downloadAuditCSV(qs);
      const blob = new Blob([csv], { type: 'text/csv;charset=utf-8' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `singctl-audit-${new Date().toISOString().slice(0, 19).replace(/[:T]/g, '-')}.csv`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
      success('CSV 导出已触发下载');
    } catch (e) {
      error((e as Error).message || '导出 CSV 失败');
    }
  };

  const handleSort = (key: string) => {
    const k = key as 'active' | 'risk' | 'upload' | 'download' | 'ratio';
    if (sortBy !== k) {
      setSortBy(k);
      setSortDir('desc');
    } else if (sortDir === 'desc') {
      setSortDir('asc');
    } else {
      setSortBy('active');
      setSortDir('desc');
    }
  };

  // NAT sub-router aggregation check
  const natSubRouter = useMemo(() => {
    const total = Number(report?.totalFlows || 0);
    if (total < 20 || !report?.devices) return null;
    return (
      report.devices.find(
        (d) =>
          d.deviceRole === 'router' &&
          d.deviceIp !== '127.0.0.1' &&
          (d.flowCount || 0) / total >= 0.7,
      ) || null
    );
  }, [report]);

  const blockCount = report?.blockedCount ?? report?.blockRules?.length ?? 0;
  const whitelist = report?.whitelist || [];
  const whitelistCount = report?.whitelistCount ?? whitelist.length;

  const detailFlow = useMemo(
    () => processedFlows.find((f) => getFlowCacheKey(f) === detailFlowKey) || null,
    [processedFlows, detailFlowKey],
  );

  const flowColumns: DataColumn<AuditFlowRecord>[] = [
    {
      key: 'target',
      header: '目标域 / IP 与来源设备',
      render: (f) => {
        const protectedTarget = isProtectedBootstrapTarget(f.target);
        return (
          <div className="min-w-0 max-w-xs sm:max-w-sm">
            <div className="flex items-center gap-1.5 flex-wrap">
              <span className="font-mono text-xs font-semibold text-primary break-all">{f.target}</span>
              {f.destPort ? (
                <span className="font-mono text-[10.5px] text-muted">:{f.destPort}</span>
              ) : null}
              {f.appName && <Badge tone="accent">{f.appName}</Badge>}
              {protectedTarget && <Badge tone="neutral">核心保护</Badge>}
            </div>
            <div className="mt-1 flex items-center gap-2 flex-wrap text-[11px] text-muted">
              <span className="font-medium text-secondary">{f.deviceName || f.deviceIp}</span>
              <span className="font-mono">{f.deviceIp}</span>
              <span className="uppercase">{f.network}</span>
              {!f.isDirectIp && f.destIp && f.destIp !== f.target && (
                <span className="font-mono text-[10.5px] text-muted/80 truncate max-w-[130px]" title={`解析目的 IP: ${f.destIp}`}>
                  → {f.destIp}
                </span>
              )}
            </div>
          </div>
        );
      },
    },
    {
      key: 'route',
      header: '链路 / 活跃度',
      sortKey: 'active',
      render: (f) => {
        const outMeta = formatOutboundMeta(f.outbound);
        const activeCnt = Number(f.activeConns || 0);
        const totalCnt = Math.max(activeCnt, Number(f.connCount || 1));
        const relSeen = formatRelativeSeen(f.lastSeen);
        const routeTip = `实际出站: ${f.outbound || 'DIRECT'}${f.rule ? ` · 命中规则: ${f.rule}` : ''}`;
        return (
          <div className="space-y-1 whitespace-nowrap" title={routeTip}>
            <div className="flex items-center gap-1.5">
              <Badge tone={outMeta.tone}>
                <span className="max-w-[120px] truncate inline-block align-bottom">{outMeta.label}</span>
              </Badge>
            </div>
            <div className="flex items-center gap-1.5 text-[10.5px] font-mono tnum text-muted">
              <span
                className={`inline-block w-1.5 h-1.5 rounded-full shrink-0 ${
                  activeCnt > 0 ? 'bg-emerald-400 animate-pulse' : 'bg-slate-600'
                }`}
              />
              {activeCnt > 0 ? (
                <span className="text-emerald-400 font-semibold">{activeCnt}活跃</span>
              ) : (
                <span>历史</span>
              )}
              <span>/{totalCnt}次</span>
              {relSeen && <span>· {relSeen}</span>}
            </div>
          </div>
        );
      },
    },
    {
      key: 'traffic',
      header: '上传 ↑ / 下载 ↓',
      sortKey: 'upload',
      align: 'right',
      render: (f) => (
        <div className="text-right font-mono tnum text-xs whitespace-nowrap">
          <div className="text-primary font-semibold">↑ {fmtBytes(f.uploadBytes)}</div>
          <div className="text-[11px] text-muted">↓ {fmtBytes(f.downloadBytes)}</div>
        </div>
      ),
    },
    {
      key: 'ratio',
      header: '上/下比',
      sortKey: 'ratio',
      align: 'right',
      render: (f) => (
        <span
          className={`font-mono tnum text-xs font-semibold ${
            (f.uploadRatio || 0) >= 3 ? 'text-rose-400' : (f.uploadRatio || 0) >= 1.5 ? 'text-amber-400' : 'text-secondary'
          }`}
        >
          {Number(f.uploadRatio || 0).toFixed(1)}x
        </span>
      ),
    },
    {
      key: 'score',
      header: '风险评分',
      sortKey: 'risk',
      render: (f) => {
        const dual = isDualAlert(f);
        const tone =
          f.state === 'blocked'
            ? 'neutral'
            : f.state === 'whitelisted'
            ? 'ok'
            : f.threat === 'high_risk'
            ? 'danger'
            : f.threat === 'suspicious'
            ? 'warn'
            : f.threat === 'notice'
            ? 'accent'
            : 'ok';
        const label =
          f.state === 'blocked'
            ? '已拉黑'
            : f.state === 'whitelisted'
            ? '已放行'
            : f.threatLabel || '正常';
        return (
          <div className="space-y-1 whitespace-nowrap">
            <Badge tone={tone} dot={f.threat === 'high_risk' || f.threat === 'suspicious'}>
              {label} · {f.riskScore || 0}分
            </Badge>
            <div className="text-[10.5px] font-mono tnum text-muted">
              安:{f.securityScore || 0} · 隐:{f.privacyScore || 0}
            </div>
            {dual && <Badge tone="danger">双重高危确诊</Badge>}
          </div>
        );
      },
    },
    {
      key: 'ai',
      header: 'AI 深度研判',
      render: (f) => {
        const tk = getFlowTargetKey(f);
        const rev = getCachedReview(f);
        const pending = pendingTargets.has(tk);
        if (rev) {
          const isReal = Boolean(rev.source && rev.source !== 'builtin_expert');
          const vTone =
            rev.verdict === 'safe_to_block'
              ? 'danger'
              : rev.verdict === 'caution'
              ? 'warn'
              : 'accent';
          return (
            <div
              className="max-w-xs space-y-1"
              onClick={(e) => e.stopPropagation()}
            >
              <div className="flex items-center gap-1.5 flex-wrap">
                <Badge tone={vTone}>{rev.verdictText}</Badge>
                <span className="text-[11px] font-medium text-primary">{rev.category}</span>
                <button
                  type="button"
                  onClick={() => reviewSingleFlow(f, true)}
                  disabled={pending}
                  title={isReal ? '重新调用 AI 研判' : '重试真实远程 AI 研判'}
                  className="text-[10.5px] text-accent hover:underline cursor-pointer"
                >
                  {isReal ? '重判' : '重试AI'}
                </button>
              </div>
              <div className="text-[11px] text-muted line-clamp-2" title={rev.impact}>
                {rev.impact}
              </div>
            </div>
          );
        }
        if (pending) {
          return (
            <div className="flex items-center gap-1.5 text-[11px] text-muted">
              <RefreshCw className="w-3 h-3 animate-spin text-accent" />
              <span>AI 研判中…</span>
            </div>
          );
        }
        return (
          <div onClick={(e) => e.stopPropagation()}>
            <Button
              size="xs"
              variant="secondary"
              icon={<Bot className="w-3 h-3" />}
              onClick={() => reviewSingleFlow(f, false)}
            >
              研判此条
            </Button>
          </div>
        );
      },
    },
    {
      key: 'actions',
      header: '处置',
      align: 'right',
      render: (f) => {
        const fk = getFlowCacheKey(f);
        if (isProtectedBootstrapTarget(f.target)) {
          return <Badge tone="neutral">受保护</Badge>;
        }
        const dual = isDualAlert(f);
        const isBusy = busyFlowKeys.has(fk);
        return (
          <div
            className="flex justify-end gap-1.5 whitespace-nowrap"
            onPointerDown={() => {
              pointerDownUntilRef.current = Date.now() + 1200;
            }}
            onClick={(e) => e.stopPropagation()}
          >
            <Button
              size="xs"
              variant="secondary"
              disabled={isBusy || filterTransitioning}
              onClick={() => handleWhitelist('add', f.target)}
            >
              白名单
            </Button>
            <Button
              size="xs"
              variant="danger"
              loading={isBusy}
              disabled={filterTransitioning}
              className={dual ? 'animate-pulse' : ''}
              onClick={() => handleBlockFlow(f)}
            >
              {dual ? '立即拉黑' : '一键拉黑'}
            </Button>
          </div>
        );
      },
    },
  ];

  const deviceColumns: DataColumn<AuditDeviceSummary>[] = [
    {
      key: 'device',
      header: '局域网设备',
      render: (d) => (
        <div>
          <div className="font-semibold text-xs text-primary">{d.deviceName || d.deviceIp}</div>
          <div className="font-mono text-[11px] text-muted">
            {d.deviceIp}
            {d.deviceMac ? ` · ${d.deviceMac}` : ''}
          </div>
        </div>
      ),
    },
    {
      key: 'role',
      header: '角色 / 活跃',
      render: (d) => (
        <div className="space-y-0.5 whitespace-nowrap">
          <Badge tone="neutral">{formatDeviceRoleLabel(d.deviceRole)}</Badge>
          <div className="text-[10.5px] font-mono tnum text-muted">
            {d.activeConns ? `${d.activeConns} 活跃 / ` : ''}
            {d.flowCount || 0} 条流
          </div>
        </div>
      ),
    },
    {
      key: 'up',
      header: '累计上传 ↑',
      align: 'right',
      render: (d) => <span className="font-mono tnum text-xs">{fmtBytes(d.uploadBytes)}</span>,
    },
    {
      key: 'down',
      header: '累计下载 ↓',
      align: 'right',
      render: (d) => <span className="font-mono tnum text-xs text-secondary">{fmtBytes(d.downloadBytes)}</span>,
    },
    {
      key: 'ratio',
      header: '上/下比',
      align: 'right',
      render: (d) => (
        <span className="font-mono tnum text-xs">{Number(d.uploadRatio || 0).toFixed(1)}x</span>
      ),
    },
    {
      key: 'susp',
      header: '可疑连接',
      align: 'right',
      render: (d) => (
        <span className="font-mono tnum text-xs font-semibold">
          {(d.suspiciousCount || 0) + (d.highRiskCount || 0)}
        </span>
      ),
    },
    {
      key: 'risk',
      header: '最高评分',
      render: (d) => {
        const tone =
          d.maxRiskScore >= 80
            ? 'danger'
            : d.maxRiskScore >= 60
            ? 'warn'
            : d.maxRiskScore >= 35
            ? 'accent'
            : 'ok';
        return (
          <div className="space-y-0.5 whitespace-nowrap">
            <Badge tone={tone}>总 {d.maxRiskScore || 0} 分</Badge>
            <div className="text-[10.5px] font-mono tnum text-muted">
              安:{d.maxSecurityScore || 0} · 隐:{d.maxPrivacyScore || 0}
            </div>
          </div>
        );
      },
    },
    {
      key: 'filter',
      header: '操作',
      align: 'right',
      render: (d) => {
        const active = deviceFilter.trim() === d.deviceIp;
        return (
          <Button
            size="xs"
            variant={active ? 'primary' : 'secondary'}
            onClick={() => setDeviceFilter(active ? '' : d.deviceIp)}
          >
            {active ? '取消筛选' : '只看此设备'}
          </Button>
        );
      },
    },
  ];

  return (
    <div className="space-y-5">
      <PageHeader
        title="设备行为审计与智能封禁"
        description={
          report
            ? `总流 ${report.totalFlows || 0} 条 · 待关注 ${report.suspiciousFlows || 0} 条 · 已封禁 ${blockCount} 条${
                whitelistCount > 0 ? ` · 已放行 ${whitelistCount} 条` : ''
              }${lastUpdated ? ` · 更新于 ${lastUpdated}` : ''}`
            : '自动识别内网设备的安全异常与隐私追踪行为，一键在 sing-box 与 AdGuard Home 双端同步阻断'
        }
        badge={
          aiStatusText ? (
            <Badge tone="accent" dot>
              AI {aiStatusText}
            </Badge>
          ) : null
        }
        actions={
          <div className="flex flex-wrap items-center gap-2">
            <Button
              size="sm"
              variant="secondary"
              icon={<Ban className="w-3.5 h-3.5" />}
              onClick={() => setBlockDrawerOpen(true)}
            >
              黑名单 ({blockCount})
            </Button>
            <Button
              size="sm"
              variant="secondary"
              icon={<Bot className="w-3.5 h-3.5" />}
              onClick={openAIConfigDrawer}
            >
              AI 网关配置
            </Button>
            <Button
              size="sm"
              variant="secondary"
              icon={<Download className="w-3.5 h-3.5" />}
              onClick={handleExportCSV}
            >
              导出 CSV
            </Button>
            <Button
              size="sm"
              variant="primary"
              icon={<RefreshCw className={`w-3.5 h-3.5 ${loading || refreshing ? 'animate-spin' : ''}`} />}
              onClick={() => loadAudit(false)}
            >
              刷新
            </Button>
          </div>
        }
      />

      {/* Filter & Toggle Strip */}
      <SectionCard>
        <div className="flex flex-wrap items-center gap-2.5">
          <div className="relative flex-1 min-w-[180px] max-w-xs">
            <Search className="w-3.5 h-3.5 text-muted absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none" />
            <input
              type="text"
              value={deviceFilter}
              onChange={(e) => setDeviceFilter(e.target.value)}
              placeholder="过滤设备名或内网 IP…"
              className="sc-input w-full pl-8 pr-7 py-1.5 text-xs"
            />
            {deviceFilter && (
              <button
                type="button"
                onClick={() => setDeviceFilter('')}
                className="absolute right-2 top-1/2 -translate-y-1/2 text-muted hover:text-primary cursor-pointer"
              >
                <X className="w-3.5 h-3.5" />
              </button>
            )}
          </div>

          <select
            value={axisFilter}
            onChange={(e) => setAxisFilter(e.target.value as '' | 'security' | 'privacy')}
            className="sc-input px-2.5 py-1.5 text-xs"
          >
            <option value="">全部类型 (安全 + 隐私)</option>
            <option value="security">仅看安全异常</option>
            <option value="privacy">仅看隐私追踪</option>
          </select>

          <label className="inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-xl border border-subtle bg-surface2 text-xs text-secondary cursor-pointer select-none">
            <input
              type="checkbox"
              checked={onlySuspect}
              onChange={(e) => setOnlySuspect(e.target.checked)}
              className="accent-emerald-500"
            />
            仅看关注/高危
          </label>

          <label className="inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-xl border border-subtle bg-surface2 text-xs text-secondary cursor-pointer select-none">
            <input
              type="checkbox"
              checked={autoRefresh}
              onChange={(e) => setAutoRefresh(e.target.checked)}
              className="accent-emerald-500"
            />
            自动刷新 (5s)
          </label>

          <label className="inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-xl border border-subtle bg-surface2 text-xs text-secondary cursor-pointer select-none">
            <input
              type="checkbox"
              checked={aiEnabled}
              onChange={(e) => handleToggleAI(e.target.checked)}
              className="accent-emerald-500"
            />
            AI 深度研判
          </label>
        </div>
      </SectionCard>

      {/* NAT Sub-Router Aggregation Alert */}
      {natSubRouter && (
        <div className="rounded-2xl border border-amber-500/30 bg-amber-500/10 p-4 flex items-start gap-3">
          <Network className="w-5 h-5 text-amber-400 shrink-0 mt-0.5" />
          <div className="text-xs leading-relaxed text-secondary">
            <strong className="text-primary">下级路由 NAT 汇聚提示：</strong>
            检测到下级路由{' '}
            <span className="font-semibold text-primary">
              {natSubRouter.deviceName || natSubRouter.deviceIp} ({natSubRouter.deviceIp})
            </span>{' '}
            汇聚了全网{' '}
            <strong className="text-amber-300">
              {Math.round(((natSubRouter.flowCount || 0) / (report?.totalFlows || 1)) * 100)}%
            </strong>{' '}
            的连接（{natSubRouter.flowCount}/{report?.totalFlows} 条）。若需精准区分终端设备并按设备拉黑，建议将下级路由切换为{' '}
            <strong>AP（无线交换机 / 桥接）模式</strong>。
          </div>
        </div>
      )}

      {/* LAN Devices Ranking */}
      <SectionCard
        title="局域网设备活跃排行"
        subtitle={`共 ${report?.devices?.length || 0} 台活跃设备，默认展示前 12 台`}
        icon={<Laptop className="w-4 h-4" />}
        collapsible
        defaultOpen
        noPadding
      >
        <DataTable
          columns={deviceColumns}
          rows={(report?.devices || []).slice(0, 12)}
          rowKey={(d) => d.deviceIp}
          loading={loading}
          emptyText="暂无局域网设备活跃流量"
          compact
        />
      </SectionCard>

      {/* Audit Flows Table */}
      <SectionCard
        title="连接行为与可疑上传明细"
        subtitle={
          processedFlows.length > 0
            ? `共 ${processedFlows.length} 条记录（当前活跃 ${activeFlowCount} 条）· 点击任意行查看完整诊断详情`
            : report?.message || '等待数据采集中'
        }
        icon={<ShieldAlert className="w-4 h-4" />}
        noPadding
      >
        <div
          ref={tableContainerRef}
          className={`transition-opacity duration-150 ${filterTransitioning ? 'opacity-70' : 'opacity-100'}`}
        >
          <DataTable
            columns={flowColumns}
            rows={visibleFlows}
            rowKey={(f) => getFlowCacheKey(f)}
            loading={loading}
            emptyText={report?.message || '暂无符合过滤条件的流量记录'}
            sortBy={sortBy}
            sortDir={sortDir}
            onSort={handleSort}
            onRowClick={(f) => setDetailFlowKey(getFlowCacheKey(f))}
            maxHeightClassName="max-h-[68vh] min-h-[420px] overflow-y-auto overscroll-contain"
            stickyHeader
            scrollContainerRef={flowScrollRef}
            onContainerScroll={handleFlowTableScroll}
            rowClassName={(f) =>
              isDualAlert(f) ? 'bg-rose-500/[0.06] hover:bg-rose-500/[0.11]' : ''
            }
            footerSlot={
              processedFlows.length > 0 ? (
                <div className="border-t border-subtle bg-surface2/40 px-4 py-2.5 text-center text-[11px] text-muted flex items-center justify-center gap-3">
                  {visibleFlows.length < processedFlows.length ? (
                    <>
                      <span>
                        已展示 {visibleFlows.length} / {processedFlows.length} 条明细，继续向下滚动自动加载…
                      </span>
                      <button
                        type="button"
                        onClick={() => setVisibleLimit(processedFlows.length)}
                        className="text-accent hover:underline font-medium cursor-pointer"
                      >
                        立即展开全部
                      </button>
                    </>
                  ) : (
                    <span>已到底部 · 共 {processedFlows.length} 条连接明细</span>
                  )}
                </div>
              ) : null
            }
          />
        </div>
      </SectionCard>

      {/* Blacklist & Ruleset Drawer */}
      <SlideDrawer
        open={blockDrawerOpen}
        onClose={() => setBlockDrawerOpen(false)}
        size="lg"
        title="黑名单、规则集与白名单管理"
        subtitle="支持单条域名 / IP / CIDR 与 sing-box .srs / .json 远程规则集整包挂载阻断"
      >
        <div className="space-y-5">
          {/* Quick Preset Rulesets + Manual Add */}
          <div className="rounded-xl border border-subtle bg-surface2/60 p-4 space-y-3">
            <div className="text-xs font-semibold text-primary">添加封禁规则或规则集</div>
            <select
              value={presetUrl}
              onChange={(e) => {
                const url = e.target.value;
                setPresetUrl(url);
                const found = PRESET_RULESETS.find((p) => p.url === url);
                setManualTarget(url);
                setPresetReason(found?.reason || '');
              }}
              className="sc-input w-full px-3 py-2 text-xs"
            >
              <option value="">常用 GitHub 规则集快捷导入…</option>
              {PRESET_RULESETS.map((p) => (
                <option key={p.url} value={p.url}>
                  {p.label}
                </option>
              ))}
            </select>

            <div className="grid grid-cols-1 sm:grid-cols-3 gap-2">
              <input
                type="text"
                value={manualTarget}
                onChange={(e) => setManualTarget(e.target.value)}
                placeholder="域名 / IP / .srs 或 .json URL…"
                className="sc-input sm:col-span-2 px-3 py-2 text-xs font-mono"
              />
              <input
                type="text"
                value={manualDevice}
                onChange={(e) => setManualDevice(e.target.value)}
                placeholder="限定设备 IP (可留空=全局)"
                className="sc-input px-3 py-2 text-xs font-mono"
              />
            </div>

            <div className="flex flex-wrap gap-2">
              <Button
                size="sm"
                variant="danger"
                loading={blockBusy}
                icon={<Plus className="w-3.5 h-3.5" />}
                onClick={() => handleManualBlock()}
              >
                导入 / 拉黑
              </Button>
              <Button
                size="sm"
                variant="secondary"
                icon={<ShieldCheck className="w-3.5 h-3.5" />}
                onClick={() => handleWhitelist('add')}
              >
                加入信任白名单
              </Button>
            </div>
          </div>

          {/* Active Blacklist Rules */}
          <div className="space-y-2.5">
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold text-primary">
                当前生效黑名单 ({report?.blockRules?.length || 0})
              </span>
            </div>

            {!report?.blockRules?.length ? (
              <div className="py-6 text-center text-xs text-muted border border-subtle rounded-xl">
                当前暂无封禁规则
              </div>
            ) : (
              <div className="divide-y divide-subtle border border-subtle rounded-xl overflow-hidden">
                {report.blockRules.map((r, idx) => {
                  const isRS = String(r.target || '').toLowerCase().startsWith('ruleset:');
                  const rsTag = isRS ? String(r.target).slice(8) : r.target;
                  return (
                    <div
                      key={`${r.target}-${r.source_ip || 'global'}-${idx}`}
                      className="p-3 bg-surface1 flex items-start justify-between gap-3"
                    >
                      <div className="min-w-0 space-y-1">
                        <div className="flex items-center gap-2 flex-wrap">
                          <span className="font-mono text-xs font-semibold text-primary break-all">
                            {isRS ? `规则集: ${rsTag}` : rsTag}
                          </span>
                          {isRS && (
                            <Badge tone="accent">
                              {r.rule_count ? `含 ${r.rule_count} 条` : '原生 .srs'}
                            </Badge>
                          )}
                          <Badge tone="neutral">{r.source_ip || '全局'}</Badge>
                        </div>
                        {r.reason && <div className="text-[11px] text-secondary">{r.reason}</div>}
                        {isRS && r.ruleset_url && (
                          <div className="font-mono text-[10.5px] text-muted truncate max-w-md" title={r.ruleset_url}>
                            {r.ruleset_url}
                          </div>
                        )}
                        {isRS && r.preview && (
                          <div className="font-mono text-[10.5px] text-muted truncate max-w-md" title={r.preview}>
                            摘要: {r.preview}
                          </div>
                        )}
                      </div>
                      <div className="flex items-center gap-1.5 shrink-0">
                        {isRS && r.ruleset_url && (
                          <Button
                            size="xs"
                            variant="secondary"
                            title="重新拉取远程规则集"
                            icon={<RotateCw className="w-3 h-3" />}
                            onClick={() => handleManualBlock(r.ruleset_url, r.reason || '刷新规则集')}
                          >
                            更新
                          </Button>
                        )}
                        <Button
                          size="xs"
                          variant="ghost"
                          className="text-rose-400"
                          icon={<Trash2 className="w-3 h-3" />}
                          onClick={() => handleUnblock(r)}
                        >
                          解封
                        </Button>
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </div>

          {/* Whitelist Chips */}
          <div className="space-y-2">
            <div className="text-xs font-semibold text-primary">
              已配置放行白名单 ({whitelist.length})
            </div>
            {whitelist.length === 0 ? (
              <div className="text-xs text-muted">暂无手动白名单条目</div>
            ) : (
              <div className="flex flex-wrap gap-1.5">
                {whitelist.map((w) => (
                  <span
                    key={w}
                    className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-mono bg-emerald-500/10 text-emerald-400 border border-emerald-500/25"
                  >
                    <span>{w}</span>
                    <button
                      type="button"
                      onClick={() => handleWhitelist('remove', w)}
                      className="hover:text-rose-400 cursor-pointer"
                      title="移出白名单"
                    >
                      <X className="w-3 h-3" />
                    </button>
                  </span>
                ))}
              </div>
            )}
          </div>
        </div>
      </SlideDrawer>

      {/* AI Gateway Configuration Drawer */}
      <SlideDrawer
        open={aiCfgOpen}
        onClose={() => setAiCfgOpen(false)}
        size="md"
        title="AI 审计网关配置"
        subtitle="支持本地 Magpie 反代网关或任意 OpenAI Compatible 接口"
        footer={
          <div className="flex justify-end gap-2">
            <Button variant="secondary" onClick={() => setAiCfgOpen(false)}>
              取消
            </Button>
            <Button variant="primary" loading={aiCfgSaving} onClick={handleSaveAIConfig}>
              保存配置
            </Button>
          </div>
        }
      >
        <div className="space-y-4">
          {aiConfig.suggestedLanUrl && (
            <div className="rounded-xl border border-emerald-500/25 bg-emerald-500/10 p-3 flex items-center justify-between gap-2">
              <div className="text-xs text-secondary">
                检测到局域网 Magpie 候选地址：
                <span className="font-mono text-primary ml-1">{aiConfig.suggestedLanUrl}</span>
              </div>
              <Button
                size="xs"
                variant="secondary"
                onClick={() => {
                  const nextUrl = aiConfig.suggestedLanUrl || aiConfig.baseUrl;
                  setAiConfig((prev) => ({ ...prev, baseUrl: nextUrl }));
                  void fetchAIModels(nextUrl, aiConfig.apiKey, false);
                }}
              >
                一键填入并拉取模型
              </Button>
            </div>
          )}

          <div>
            <label className="block text-xs font-semibold text-secondary mb-1.5">
              网关请求地址 (BaseURL)
            </label>
            <input
              type="text"
              value={aiConfig.baseUrl}
              onChange={(e) => setAiConfig({ ...aiConfig, baseUrl: e.target.value })}
              onBlur={() => {
                const sig = `${aiConfig.baseUrl.trim()}|${aiConfig.apiKey.trim()}`;
                if (sig !== lastFetchedSigRef.current) {
                  void fetchAIModels(aiConfig.baseUrl, aiConfig.apiKey, true);
                }
              }}
              placeholder="http://127.0.0.1:3425/v1 (留空自动探测 :3425)"
              className="sc-input w-full px-3 py-2 text-xs font-mono"
            />
          </div>

          <div>
            <label className="block text-xs font-semibold text-secondary mb-1.5">
              网关密钥 (API Key)
            </label>
            <input
              type="password"
              autoComplete="new-password"
              value={aiConfig.apiKey}
              onChange={(e) => setAiConfig({ ...aiConfig, apiKey: e.target.value })}
              onBlur={() => {
                const sig = `${aiConfig.baseUrl.trim()}|${aiConfig.apiKey.trim()}`;
                if (sig !== lastFetchedSigRef.current) {
                  void fetchAIModels(aiConfig.baseUrl, aiConfig.apiKey, true);
                }
              }}
              placeholder="sk-magpie-key-... (同机 127.0.0.1 可留空)"
              className="sc-input w-full px-3 py-2 text-xs font-mono"
            />
          </div>

          <div className="space-y-1.5">
            <div className="flex items-center justify-between gap-2">
              <label className="block text-xs font-semibold text-secondary">
                访问模型 (Model)
              </label>
              <div className="flex items-center gap-1.5">
                {aiModels.length > 0 && (
                  <button
                    type="button"
                    onClick={() => setManualModelInput((v) => !v)}
                    className="text-[11px] text-emerald-400 hover:text-emerald-300 underline cursor-pointer"
                  >
                    {manualModelInput ? `切换下拉选择 (${aiModels.length})` : '手动输入'}
                  </button>
                )}
                <Button
                  size="xs"
                  variant="ghost"
                  loading={aiModelsLoading}
                  icon={<RefreshCw className="w-3 h-3" />}
                  onClick={() => void fetchAIModels(aiConfig.baseUrl, aiConfig.apiKey, false)}
                >
                  拉取模型
                </Button>
              </div>
            </div>

            {aiModels.length > 0 && !manualModelInput ? (
              <select
                aria-label="选择访问模型"
                value={aiConfig.model}
                onChange={(e) => {
                  const val = e.target.value;
                  if (val === '__manual__') {
                    setManualModelInput(true);
                    return;
                  }
                  setAiConfig({ ...aiConfig, model: val });
                }}
                className="sc-input w-full h-9 px-3 text-xs font-mono text-primary"
              >
                {aiConfig.model && !aiModels.includes(aiConfig.model) && (
                  <option value={aiConfig.model}>{aiConfig.model} (当前已配置)</option>
                )}
                {aiModels.map((m) => (
                  <option key={m} value={m}>
                    {m}
                  </option>
                ))}
                <option value="__manual__">✍️ 手动填写其他模型名称…</option>
              </select>
            ) : (
              <input
                type="text"
                value={aiConfig.model}
                onChange={(e) => setAiConfig({ ...aiConfig, model: e.target.value })}
                placeholder="antigravity/gemini-3.8-flash"
                className="sc-input w-full px-3 py-2 text-xs font-mono"
              />
            )}

            {aiModelsLoading ? (
              <div className="text-[11px] text-muted">正在从网关拉取可用模型列表…</div>
            ) : aiModels.length > 0 && !manualModelInput ? (
              <div className="text-[11px] text-emerald-400">
                已自动从网关拉取 {aiModels.length} 个可用模型，可直接下拉选择或切换手动输入。
              </div>
            ) : aiModelsHint ? (
              <div className="text-[11px] text-muted">
                未能自动拉取模型列表（{aiModelsHint}），可直接手动填写模型名称。
              </div>
            ) : null}
          </div>

          <p className="text-xs text-muted leading-relaxed">
            默认使用 <code className="text-primary">antigravity/gemini-3.8-flash</code>。若留空 BaseURL，系统将按「配置网关 → 127.0.0.1:3425 → 当前电脑局域网 IP:3425 → 离线专家库」顺序自动探测。
          </p>
        </div>
      </SlideDrawer>

      {/* Row Flow Detail Drawer */}
      <SlideDrawer
        open={Boolean(detailFlow)}
        onClose={() => setDetailFlowKey(null)}
        size="md"
        title={detailFlow?.target || '连接行为详情'}
        subtitle={
          detailFlow
            ? `${detailFlow.deviceName || detailFlow.deviceIp} (${detailFlow.deviceIp}) · ${detailFlow.network.toUpperCase()}${
                detailFlow.destPort ? `:${detailFlow.destPort}` : ''
              }`
            : ''
        }
        footer={
          detailFlow ? (
            <div className="flex flex-wrap items-center justify-between gap-2">
              <Button
                size="sm"
                variant="secondary"
                icon={<Bot className="w-3.5 h-3.5" />}
                onClick={() => reviewSingleFlow(detailFlow, true)}
              >
                重新 AI 研判
              </Button>
              <div className="flex flex-wrap gap-2">
                <Button
                  size="sm"
                  variant="secondary"
                  icon={<ShieldCheck className="w-3.5 h-3.5" />}
                  onClick={() => handleWhitelist('add', detailFlow.target)}
                >
                  加入白名单
                </Button>
                {!isProtectedBootstrapTarget(detailFlow.target) &&
                  detailFlow.deviceIp &&
                  detailFlow.deviceIp !== '127.0.0.1' && (
                    <Button
                      size="sm"
                      variant="secondary"
                      className="border-rose-500/35 text-rose-300 hover:bg-rose-500/15"
                      icon={<Ban className="w-3.5 h-3.5" />}
                      onClick={() => handleBlockFlow(detailFlow, true)}
                    >
                      仅阻断此设备
                    </Button>
                  )}
                {!isProtectedBootstrapTarget(detailFlow.target) && (
                  <Button
                    size="sm"
                    variant="danger"
                    icon={<Ban className="w-3.5 h-3.5" />}
                    onClick={() => handleBlockFlow(detailFlow, false)}
                  >
                    全局拉黑
                  </Button>
                )}
              </div>
            </div>
          ) : null
        }
      >
        {detailFlow && (
          <div className="space-y-4">
            {/* 4-Card Core Telemetry Strip */}
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-2.5">
              <div className="rounded-xl border border-subtle bg-surface2/60 p-3">
                <div className="text-[11px] text-muted">累计上传 ↑</div>
                <div className="mt-1 font-mono tnum text-sm font-bold text-primary">
                  {fmtBytes(detailFlow.uploadBytes)}
                </div>
              </div>
              <div className="rounded-xl border border-subtle bg-surface2/60 p-3">
                <div className="text-[11px] text-muted">累计下载 ↓</div>
                <div className="mt-1 font-mono tnum text-sm font-bold text-primary">
                  {fmtBytes(detailFlow.downloadBytes)}
                </div>
                <div className="text-[10.5px] font-mono text-muted mt-0.5">
                  上/下比 {Number(detailFlow.uploadRatio || 0).toFixed(2)}x
                </div>
              </div>
              <div className="rounded-xl border border-subtle bg-surface2/60 p-3">
                <div className="text-[11px] text-muted">安全 / 隐私轴</div>
                <div className="mt-1 font-mono tnum text-sm font-bold text-primary">
                  {detailFlow.securityScore || 0} / {detailFlow.privacyScore || 0}
                </div>
                <div className="text-[10.5px] text-muted mt-0.5">
                  {detailFlow.dominantAxis === 'security'
                    ? '安全风险主导'
                    : detailFlow.dominantAxis === 'privacy'
                    ? '隐私追踪主导'
                    : detailFlow.dominantAxis === 'both'
                    ? '双轴并发风险'
                    : '基线平稳'}
                </div>
              </div>
              <div className="rounded-xl border border-subtle bg-surface2/60 p-3">
                <div className="text-[11px] text-muted">综合风险分</div>
                <div className="mt-1 font-mono tnum text-sm font-bold text-primary">
                  {detailFlow.riskScore || 0} 分
                </div>
                <div className="text-[10.5px] text-muted mt-0.5">
                  {detailFlow.threatLabel || '正常'}
                </div>
              </div>
            </div>

            {/* Route & Endpoint Identity Card */}
            <div className="rounded-xl border border-subtle bg-surface2/50 p-3.5 space-y-2.5">
              <div className="text-xs font-semibold text-primary">网络分流链路与终端画像</div>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-x-4 gap-y-2 text-xs">
                <div className="flex items-center justify-between gap-2 border-b border-subtle/60 pb-1.5">
                  <span className="text-muted">来源终端</span>
                  <span className="font-medium text-primary truncate">
                    {detailFlow.deviceName || detailFlow.deviceIp}
                  </span>
                </div>
                <div className="flex items-center justify-between gap-2 border-b border-subtle/60 pb-1.5">
                  <span className="text-muted">终端类型 / MAC</span>
                  <span className="font-mono text-[11px] text-secondary truncate">
                    {formatDeviceRoleLabel(detailFlow.deviceRole)}
                    {detailFlow.deviceMac ? ` · ${detailFlow.deviceMac}` : ''}
                  </span>
                </div>
                <div className="flex items-center justify-between gap-2 border-b border-subtle/60 pb-1.5">
                  <span className="text-muted">目的地址</span>
                  <span className="font-mono text-[11px] text-primary truncate">
                    {detailFlow.destIp || detailFlow.target}
                    {detailFlow.destPort ? `:${detailFlow.destPort}` : ''} ({detailFlow.network.toUpperCase()})
                  </span>
                </div>
                <div className="flex items-center justify-between gap-2 border-b border-subtle/60 pb-1.5">
                  <span className="text-muted">访问方式</span>
                  <span>
                    {detailFlow.isDirectIp ? (
                      <Badge tone="warn">绕过 DNS 纯 IP 直连</Badge>
                    ) : (
                      <Badge tone="ok">标准域名解析{detailFlow.appName ? ` · ${detailFlow.appName}` : ''}</Badge>
                    )}
                  </span>
                </div>
                <div className="flex items-center justify-between gap-2">
                  <span className="text-muted">实际出站 (Outbound)</span>
                  <Badge tone={formatOutboundMeta(detailFlow.outbound).tone}>
                    {formatOutboundMeta(detailFlow.outbound).label}
                  </Badge>
                </div>
                <div className="flex items-center justify-between gap-2">
                  <span className="text-muted">命中规则 (Rule)</span>
                  <span className="font-mono text-[11px] text-secondary truncate max-w-[180px]" title={detailFlow.rule || 'final / 默认路由'}>
                    {detailFlow.rule || 'final / 默认路由'}
                  </span>
                </div>
              </div>
            </div>

            {/* Temporal & Behavioral Forensics Card */}
            <div className="rounded-xl border border-subtle bg-surface2/50 p-3.5 space-y-2.5">
              <div className="text-xs font-semibold text-primary">时间跨度与连接节律特征</div>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-x-4 gap-y-2 text-xs">
                <div className="flex items-center justify-between gap-2 border-b border-subtle/60 pb-1.5">
                  <span className="text-muted">连接活跃态</span>
                  <span className="font-mono tnum text-primary">
                    <strong className={(detailFlow.activeConns || 0) > 0 ? 'text-emerald-400' : 'text-secondary'}>
                      {detailFlow.activeConns || 0} 活跃
                    </strong>{' '}
                    / 累计 {detailFlow.connCount || 1} 次
                  </span>
                </div>
                <div className="flex items-center justify-between gap-2 border-b border-subtle/60 pb-1.5">
                  <span className="text-muted">凌晨暗夜活跃</span>
                  <span className="font-mono tnum">
                    {(detailFlow.nightHits || 0) > 0 ? (
                      <span className="text-amber-400 font-semibold">01:00–05:59 捕获 {detailFlow.nightHits} 次</span>
                    ) : (
                      <span className="text-muted">0 次 (无夜间异动)</span>
                    )}
                  </span>
                </div>
                <div className="flex items-center justify-between gap-2 border-b border-subtle/60 pb-1.5">
                  <span className="text-muted">首次观测</span>
                  <span className="font-mono text-[11px] text-secondary">{detailFlow.firstSeen || '—'}</span>
                </div>
                <div className="flex items-center justify-between gap-2 border-b border-subtle/60 pb-1.5">
                  <span className="text-muted">最近活跃</span>
                  <span className="font-mono text-[11px] text-secondary">{detailFlow.lastSeen || '—'}</span>
                </div>
                <div className="flex items-center justify-between gap-2">
                  <span className="text-muted">心跳变异系数 (CV)</span>
                  <span className="font-mono text-[11px] text-secondary">
                    {typeof detailFlow.intervalCv === 'number' && detailFlow.intervalCv > 0
                      ? `${detailFlow.intervalCv.toFixed(2)} (${detailFlow.intervalCv < 0.35 ? '疑似定时脚本心跳' : '自然离散'})`
                      : '样本不足'}
                  </span>
                </div>
                <div className="flex items-center justify-between gap-2">
                  <span className="text-muted">域名信息熵</span>
                  <span className="font-mono text-[11px] text-secondary">
                    {detailFlow.isDirectIp
                      ? '纯 IP (无域名)'
                      : `${Number(detailFlow.domainEntropy || 0).toFixed(2)} bits${
                          (detailFlow.domainEntropy || 0) >= 3.65 ? ' (偏高随机性)' : ''
                        }`}
                  </span>
                </div>
              </div>
            </div>

            {/* Nonlinear Factor Breakdown Bars (when triggered) */}
            {(() => {
              const rawFactors = detailFlow.nonlinearFactors || {};
              const activeFactors = Object.entries(NONLINEAR_FACTOR_LABELS)
                .map(([k, label]) => ({ key: k, label, score: Number(rawFactors[k] || 0) }))
                .filter((item) => item.score > 0)
                .sort((a, b) => b.score - a.score);
              if (activeFactors.length === 0) return null;
              return (
                <div className="rounded-xl border border-subtle bg-surface2/50 p-3.5 space-y-2.5">
                  <div className="text-xs font-semibold text-primary">非线性风险算子分量拆解</div>
                  <div className="space-y-2">
                    {activeFactors.map((item) => {
                      const pct = Math.min(100, Math.max(6, Math.round((item.score / 50) * 100)));
                      return (
                        <div key={item.key} className="space-y-1">
                          <div className="flex items-center justify-between text-[11px]">
                            <span className="text-secondary">{item.label}</span>
                            <span className="font-mono tnum text-primary">+{item.score.toFixed(1)}</span>
                          </div>
                          <div className="h-1.5 rounded-full bg-slate-800 overflow-hidden">
                            <div
                              className="h-full rounded-full bg-gradient-to-r from-amber-500/80 to-rose-500"
                              style={{ width: `${pct}%` }}
                            />
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </div>
              );
            })()}

            {(() => {
              const rev = getCachedReview(detailFlow);
              if (!rev) return null;
              return (
                <div className="rounded-xl border border-subtle bg-surface2/60 p-3.5 space-y-1.5">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-semibold text-primary">AI 深度研判结论</span>
                    <Badge
                      tone={
                        rev.verdict === 'safe_to_block'
                          ? 'danger'
                          : rev.verdict === 'caution'
                          ? 'warn'
                          : 'accent'
                      }
                    >
                      {rev.verdictText} · {rev.category}
                    </Badge>
                  </div>
                  <p className="text-xs text-secondary leading-relaxed">{rev.impact}</p>
                  {rev.source && (
                    <div className="text-[11px] font-mono text-muted">来源: {rev.source}</div>
                  )}
                </div>
              );
            })()}

            <div className="space-y-2">
              <div className="text-xs font-semibold text-primary flex items-center gap-1.5">
                <AlertTriangle className="w-3.5 h-3.5 text-amber-400" />
                启发式风险依据
              </div>
              {detailFlow.reasons && detailFlow.reasons.length > 0 ? (
                <ul className="space-y-1.5 text-xs text-secondary">
                  {detailFlow.reasons.map((r, i) => (
                    <li key={i} className="rounded-lg bg-surface2/70 border border-subtle px-3 py-2">
                      {r}
                    </li>
                  ))}
                </ul>
              ) : (
                <div className="text-xs text-muted">未触发异常启发式特征</div>
              )}
            </div>
          </div>
        )}
      </SlideDrawer>
    </div>
  );
};

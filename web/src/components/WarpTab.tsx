import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  ActiveDestinationGroup,
  WarpPresetItem,
  WarpRoutingConfig,
  WarpRoutingMode,
  WarpRoutingStatusResponse,
} from '../types';
import { api } from '../api';
import { useToast } from './Toast';
import {
  AlertTriangle,
  Bot,
  CheckCircle2,
  Film,
  Globe,
  PauseCircle,
  Plus,
  RefreshCw,
  RotateCcw,
  Search,
  Shield,
  ShieldCheck,
  Sparkles,
  Split,
  Trash2,
  Users,
  Wrench,
  Zap,
} from 'lucide-react';

interface WarpTabProps {
  onRefreshParent?: () => void;
}

const DEFAULT_ROUTING: WarpRoutingConfig = {
  mode: 'split',
  presets: {},
  warpDomains: [],
  warpCidrs: [],
  directDomains: [],
  directCidrs: [],
};

function formatBytes(bytes: number): string {
  const val = Math.max(0, bytes);
  const KB = 1024;
  const MB = 1024 * KB;
  const GB = 1024 * MB;
  if (val >= GB) return `${(val / GB).toFixed(2)} GB`;
  if (val >= MB) return `${(val / MB).toFixed(1)} MB`;
  if (val >= KB) return `${(val / KB).toFixed(1)} KB`;
  return `${Math.round(val)} B`;
}

function isLikelyIPOrCIDR(raw: string): boolean {
  const s = raw.trim();
  if (!s) return false;
  if (/^\d{1,3}(\.\d{1,3}){3}(\/\d{1,2})?$/.test(s)) return true;
  if (s.includes(':') && !s.includes('://') && !s.startsWith('full:') && !s.startsWith('keyword:')) return true;
  return false;
}

function previewCleanRuleTarget(raw: string): { kind: 'cidr' | 'domain'; value: string } | null {
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

export const WarpTab: React.FC<WarpTabProps> = ({ onRefreshParent }) => {
  const { success, error } = useToast();

  const [data, setData] = useState<WarpRoutingStatusResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [acting, setActing] = useState<'rekey' | 'ensure' | null>(null);

  // Active live connections state
  const [connEnabled, setConnEnabled] = useState(true);
  const [connMsg, setConnMsg] = useState('');
  const [connections, setConnections] = useState<ActiveDestinationGroup[]>([]);
  const [connQuery, setConnQuery] = useState('');
  const [connFilter, setConnFilter] = useState<'all' | 'DC' | 'WARP'>('all');
  const [autoRefreshConn, setAutoRefreshConn] = useState(true);
  const [loadingConn, setLoadingConn] = useState(false);
  const [switchingTarget, setSwitchingTarget] = useState<string | null>(null);

  // Custom rule inputs
  const [warpInput, setWarpInput] = useState('');
  const [directInput, setDirectInput] = useState('');

  // Debounce timer for rapid preset toggles
  const debounceTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const rollbackSnapshotRef = useRef<WarpRoutingStatusResponse | null>(null);

  const loadRouting = useCallback(async (forceRefresh = false) => {
    try {
      const res = await api.getWarpRouting(forceRefresh);
      setData(res);
    } catch (err: any) {
      error(err.message || '获取 WARP 分流配置失败');
    } finally {
      setLoading(false);
    }
  }, [error]);

  const loadConnections = useCallback(async () => {
    setLoadingConn(true);
    try {
      const res = await api.getWarpConnections(connQuery, connFilter);
      setConnEnabled(res.enabled);
      setConnMsg(res.message || '');
      setConnections(res.destinations || []);
    } catch {
      // Keep quiet on background poll error
    } finally {
      setLoadingConn(false);
    }
  }, [connQuery, connFilter]);

  useEffect(() => {
    loadRouting(false);
  }, [loadRouting]);

  useEffect(() => {
    loadConnections();
  }, [loadConnections]);

  useEffect(() => {
    if (!autoRefreshConn) return;
    const timer = setInterval(() => {
      loadConnections();
    }, 5000);
    return () => clearInterval(timer);
  }, [autoRefreshConn, loadConnections]);

  useEffect(() => {
    return () => {
      if (debounceTimerRef.current) clearTimeout(debounceTimerRef.current);
    };
  }, []);

  const commitRoutingUpdate = useCallback(
    async (nextRouting: WarpRoutingConfig, snapshotForRollback: WarpRoutingStatusResponse | null) => {
      setSaving(true);
      try {
        const res = await api.updateWarpRouting(nextRouting);
        setData({
          daemon: res.daemon,
          routing: res.routing,
          presets: res.presets,
          dcConnCount: res.dcConnCount,
          warpConnCount: res.warpConnCount,
        });
        rollbackSnapshotRef.current = null;
        success(res.message);
        loadConnections();
      } catch (err: any) {
        if (snapshotForRollback) {
          setData(snapshotForRollback);
        }
        rollbackSnapshotRef.current = null;
        error(err.message || '更新 WARP 分流配置失败');
      } finally {
        setSaving(false);
      }
    },
    [error, loadConnections, success]
  );

  const scheduleOptimisticUpdate = (
    mutator: (prev: WarpRoutingStatusResponse) => {
      nextRouting: WarpRoutingConfig;
      nextPresets: WarpPresetItem[];
    },
    immediate = false
  ) => {
    if (!data) return;
    if (!rollbackSnapshotRef.current) {
      rollbackSnapshotRef.current = data;
    }
    const { nextRouting, nextPresets } = mutator(data);
    setData({
      ...data,
      routing: nextRouting,
      presets: nextPresets,
    });

    if (debounceTimerRef.current) {
      clearTimeout(debounceTimerRef.current);
      debounceTimerRef.current = null;
    }

    if (immediate) {
      const snap = rollbackSnapshotRef.current;
      void commitRoutingUpdate(nextRouting, snap);
    } else {
      debounceTimerRef.current = setTimeout(() => {
        const snap = rollbackSnapshotRef.current;
        void commitRoutingUpdate(nextRouting, snap);
      }, 250);
    }
  };

  const handleModeChange = (mode: WarpRoutingMode) => {
    if (!data || data.routing.mode === mode) return;
    scheduleOptimisticUpdate(
      (prev) => ({
        nextRouting: { ...prev.routing, mode },
        nextPresets: prev.presets,
      }),
      true
    );
  };

  const handleTogglePreset = (presetId: string) => {
    scheduleOptimisticUpdate((prev) => {
      const currentPresetsMap = { ...(prev.routing.presets || {}) };
      const targetItem = prev.presets.find((p) => p.id === presetId);
      const nextVal = targetItem ? !targetItem.enabled : !currentPresetsMap[presetId];
      currentPresetsMap[presetId] = nextVal;

      const nextPresets = prev.presets.map((p) => (p.id === presetId ? { ...p, enabled: nextVal } : p));
      return {
        nextRouting: {
          ...prev.routing,
          presets: currentPresetsMap,
        },
        nextPresets,
      };
    });
  };

  const handleAddRules = (bucket: 'warp' | 'direct', rawText: string) => {
    if (!data || !rawText.trim()) return;
    const tokens = rawText
      .split(/[\s,;，；\n]+/)
      .map((t) => t.trim())
      .filter(Boolean);
    if (tokens.length === 0) return;

    const nextRouting: WarpRoutingConfig = {
      ...data.routing,
      warpDomains: [...(data.routing.warpDomains || [])],
      warpCidrs: [...(data.routing.warpCidrs || [])],
      directDomains: [...(data.routing.directDomains || [])],
      directCidrs: [...(data.routing.directCidrs || [])],
    };

    for (const token of tokens) {
      const parsed = previewCleanRuleTarget(token);
      const targetVal = parsed ? parsed.value : token;
      const isCIDR = parsed?.kind === 'cidr' || isLikelyIPOrCIDR(token);
      if (bucket === 'warp') {
        if (isCIDR) {
          nextRouting.directCidrs = nextRouting.directCidrs.filter((x) => x !== targetVal);
          if (!nextRouting.warpCidrs.includes(targetVal)) nextRouting.warpCidrs.push(targetVal);
        } else {
          nextRouting.directDomains = nextRouting.directDomains.filter((x) => x !== targetVal);
          if (!nextRouting.warpDomains.includes(targetVal)) nextRouting.warpDomains.push(targetVal);
        }
      } else {
        if (isCIDR) {
          nextRouting.warpCidrs = nextRouting.warpCidrs.filter((x) => x !== targetVal);
          if (!nextRouting.directCidrs.includes(targetVal)) nextRouting.directCidrs.push(targetVal);
        } else {
          nextRouting.warpDomains = nextRouting.warpDomains.filter((x) => x !== targetVal);
          if (!nextRouting.directDomains.includes(targetVal)) nextRouting.directDomains.push(targetVal);
        }
      }
    }

    if (bucket === 'warp') setWarpInput('');
    else setDirectInput('');

    scheduleOptimisticUpdate(
      (prev) => ({
        nextRouting,
        nextPresets: prev.presets,
      }),
      true
    );
  };

  const handleRemoveRule = (bucket: 'warp' | 'direct', kind: 'domain' | 'cidr', value: string) => {
    if (!data) return;
    const nextRouting: WarpRoutingConfig = {
      ...data.routing,
      warpDomains: [...(data.routing.warpDomains || [])],
      warpCidrs: [...(data.routing.warpCidrs || [])],
      directDomains: [...(data.routing.directDomains || [])],
      directCidrs: [...(data.routing.directCidrs || [])],
    };
    if (bucket === 'warp' && kind === 'domain') {
      nextRouting.warpDomains = nextRouting.warpDomains.filter((x) => x !== value);
    } else if (bucket === 'warp' && kind === 'cidr') {
      nextRouting.warpCidrs = nextRouting.warpCidrs.filter((x) => x !== value);
    } else if (bucket === 'direct' && kind === 'domain') {
      nextRouting.directDomains = nextRouting.directDomains.filter((x) => x !== value);
    } else {
      nextRouting.directCidrs = nextRouting.directCidrs.filter((x) => x !== value);
    }
    scheduleOptimisticUpdate(
      (prev) => ({
        nextRouting,
        nextPresets: prev.presets,
      }),
      true
    );
  };

  const handleQuickSwitch = async (target: string, outbound: 'WARP' | 'DC') => {
    setSwitchingTarget(target);
    try {
      const res = await api.quickSwitchWarpTarget(target, outbound);
      setData({
        daemon: res.daemon,
        routing: res.routing,
        presets: res.presets,
        dcConnCount: res.dcConnCount,
        warpConnCount: res.warpConnCount,
      });
      success(res.message);
      loadConnections();
    } catch (err: any) {
      error(err.message || '切换失败');
    } finally {
      setSwitchingTarget(null);
    }
  };

  const handleWarpAction = async (action: 'rekey' | 'ensure') => {
    setActing(action);
    try {
      const res = await api.runWarpAction(action);
      success(res.message);
      await loadRouting(true);
      onRefreshParent?.();
    } catch (err: any) {
      error(err.message || 'WARP 操作执行失败');
    } finally {
      setActing(null);
    }
  };

  const handleEnableTelemetry = async () => {
    try {
      const res = await api.enableTelemetry();
      success(res.message || '实时流量遥测已开启');
      loadConnections();
    } catch (err: any) {
      error(err.message || '开启实时遥测失败');
    }
  };

  const routing = data?.routing || DEFAULT_ROUTING;
  const daemon = data?.daemon;
  const presets = data?.presets || [];

  const groupedPresets = useMemo(() => {
    const groups: { key: string; label: string; icon: React.ReactNode; items: WarpPresetItem[] }[] = [
      { key: 'ai', label: 'AI 大模型', icon: <Bot className="w-4 h-4 text-emerald-400" />, items: [] },
      { key: 'streaming', label: '流媒体与成人内容', icon: <Film className="w-4 h-4 text-amber-400" />, items: [] },
      { key: 'social', label: '社交与防风控', icon: <Users className="w-4 h-4 text-sky-400" />, items: [] },
    ];
    for (const p of presets) {
      const g = groups.find((x) => x.key === p.group);
      if (g) g.items.push(p);
      else groups[2].items.push(p);
    }
    return groups.filter((g) => g.items.length > 0);
  }, [presets]);

  const warpPreview = useMemo(() => previewCleanRuleTarget(warpInput), [warpInput]);
  const directPreview = useMemo(() => previewCleanRuleTarget(directInput), [directInput]);

  if (loading && !data) {
    return (
      <div className="p-10 rounded-2xl glass-card flex items-center justify-center gap-3 text-slate-400 text-xs font-mono">
        <RefreshCw className="w-4 h-4 animate-spin text-amber-400" />
        <span>正在加载 WARP 智能分流控制中心...</span>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* 1. 隧道 offline/未安装 防黑洞引导横幅 */}
      {daemon && !daemon.tunnelHealthy && (
        <div className="p-4 sm:p-5 rounded-2xl border border-amber-500/40 bg-amber-950/25 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div className="flex items-start gap-3">
            <div className="p-2 rounded-xl bg-amber-500/15 text-amber-400 border border-amber-500/30 shrink-0">
              <AlertTriangle className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-sm font-bold text-amber-200">
                本地 WARP 隧道 (127.0.0.1:40000) 当前未就绪
              </h3>
              <p className="text-xs text-amber-200/80 mt-1">
                {daemon.error || 'wireproxy 尚未安装或已停止运行'}。为防止流量切换后断网，系统已自动开启防黑洞保护，请先一键部署或拉起 WARP 服务。
              </p>
            </div>
          </div>
          <button
            type="button"
            onClick={() => handleWarpAction('ensure')}
            disabled={acting === 'ensure'}
            className="flex items-center justify-center gap-1.5 px-4 py-2.5 rounded-xl bg-amber-500 hover:bg-amber-400 text-slate-950 font-semibold text-xs transition-all shrink-0 disabled:opacity-50"
          >
            <Wrench className={`w-3.5 h-3.5 ${acting === 'ensure' ? 'animate-spin' : ''}`} />
            <span>{acting === 'ensure' ? '正在部署修复...' : '一键部署 / 修复 WARP 隧道'}</span>
          </button>
        </div>
      )}

      {/* 2. 顶部双出口态势与全局分流模式 Hero Bar */}
      <div className="p-5 rounded-2xl glass-card space-y-5">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          {/* 左侧：WARP 隧道信息与换 IP 操作 */}
          <div className="space-y-2.5">
            <div className="flex flex-wrap items-center gap-2.5">
              <div className="p-2 rounded-xl bg-amber-500/10 text-amber-400 border border-amber-500/20">
                <Split className="w-5 h-5" />
              </div>
              <div>
                <h2 className="text-lg font-semibold text-white tracking-tight flex items-center gap-2 flex-wrap">
                  <span>WARP 智能分流中心</span>
                  <span
                    className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-[11px] font-mono border ${
                      daemon?.tunnelHealthy
                        ? 'bg-emerald-500/10 text-emerald-300 border-emerald-500/25'
                        : 'bg-rose-500/10 text-rose-300 border-rose-500/25'
                    }`}
                  >
                    <span
                      className={`w-1.5 h-1.5 rounded-full ${
                        daemon?.tunnelHealthy ? 'bg-emerald-400 animate-pulse' : 'bg-rose-400'
                      }`}
                    />
                    {daemon?.tunnelHealthy ? '127.0.0.1:40000 就绪' : '隧道未连通'}
                  </span>
                  {saving && (
                    <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[11px] font-mono bg-sky-500/10 text-sky-300 border border-sky-500/25">
                      <RefreshCw className="w-3 h-3 animate-spin" />
                      正在热更新...
                    </span>
                  )}
                </h2>
                <p className="text-xs text-slate-400 mt-0.5">
                  采用 SIGHUP 零断流热重载 + 逐流精准切换，修改域名/预设后毫秒级生效且不影响其它活跃连接
                </p>
              </div>
            </div>

            <div className="flex flex-wrap items-center gap-2 text-xs font-mono">
              <span className="px-2.5 py-1 rounded-lg bg-slate-950/70 border border-slate-800 text-amber-300">
                WARP 出口: {daemon?.warpIp ? `${daemon.warpIp}${daemon.warpLoc ? ` (${daemon.warpLoc})` : ''}` : '待探测'}
              </span>
              <span className="px-2.5 py-1 rounded-lg bg-slate-950/70 border border-slate-800 text-sky-300">
                直出 DC: {data?.dcConnCount ?? 0} 连
              </span>
              <span className="px-2.5 py-1 rounded-lg bg-slate-950/70 border border-slate-800 text-amber-300">
                WARP 分流: {data?.warpConnCount ?? 0} 连
              </span>
              <button
                type="button"
                onClick={() => handleWarpAction('rekey')}
                disabled={acting !== null || !daemon?.installed}
                className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-700/70 text-slate-200 transition-colors disabled:opacity-40"
                title="重新注册 WireGuard 身份以更换全新 Cloudflare WARP 出口 IP（失败自动回滚）"
              >
                <RotateCcw className={`w-3 h-3 text-amber-400 ${acting === 'rekey' ? 'animate-spin' : ''}`} />
                <span>{acting === 'rekey' ? '正在换 IP...' : '更换 WARP IP'}</span>
              </button>
              <button
                type="button"
                onClick={() => loadRouting(true)}
                className="inline-flex items-center gap-1 px-2.5 py-1 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-700/70 text-slate-300 transition-colors"
              >
                <RefreshCw className="w-3 h-3" />
                <span>刷新</span>
              </button>
            </div>
          </div>

          {/* 右侧：三段式全局分流模式切换器 */}
          <div className="flex flex-col items-stretch sm:items-end gap-2 shrink-0">
            <div className="inline-flex flex-wrap sm:flex-nowrap p-1 rounded-xl bg-slate-950/90 border border-slate-800 gap-1">
              <button
                type="button"
                onClick={() => handleModeChange('split')}
                className={`flex items-center justify-center gap-1.5 px-3 py-2 rounded-lg text-xs font-semibold transition-all ${
                  routing.mode === 'split'
                    ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/35 shadow-sm'
                    : 'text-slate-400 hover:text-slate-200 border border-transparent'
                }`}
              >
                <Split className="w-3.5 h-3.5" />
                <span>原生优先 · 按需分流</span>
              </button>
              <button
                type="button"
                onClick={() => handleModeChange('global_warp')}
                className={`flex items-center justify-center gap-1.5 px-3 py-2 rounded-lg text-xs font-semibold transition-all ${
                  routing.mode === 'global_warp'
                    ? 'bg-amber-500/20 text-amber-300 border border-amber-500/35 shadow-sm'
                    : 'text-slate-400 hover:text-slate-200 border border-transparent'
                }`}
              >
                <Shield className="w-3.5 h-3.5" />
                <span>全局 WARP 接管</span>
              </button>
              <button
                type="button"
                onClick={() => handleModeChange('bypass')}
                className={`flex items-center justify-center gap-1.5 px-3 py-2 rounded-lg text-xs font-semibold transition-all ${
                  routing.mode === 'bypass'
                    ? 'bg-rose-500/20 text-rose-300 border border-rose-500/35 shadow-sm'
                    : 'text-slate-400 hover:text-slate-200 border border-transparent'
                }`}
              >
                <PauseCircle className="w-3.5 h-3.5" />
                <span>紧急全直出旁路</span>
              </button>
            </div>
            <p className="text-[11px] text-slate-400 text-left sm:text-right">
              {routing.mode === 'split' && '未命中 WARP 规则的流量默认走 VPS 原生直出，兼顾速度与关键服务解锁'}
              {routing.mode === 'global_warp' && '除右下方「强制直出白名单」外，全站出站流量默认经 WARP 隐匿源站 IP'}
              {routing.mode === 'bypass' && '紧急旁路中：所有 WARP 分流规则已临时挂起（配置安全保留，可随时一键恢复）'}
            </p>
          </div>
        </div>
      </div>

      {/* 3. 15 项场景化预设矩阵 */}
      <div className="space-y-4">
        {groupedPresets.map((group) => (
          <div key={group.key} className="p-5 rounded-2xl glass-card space-y-3.5">
            <div className="flex items-center justify-between pb-2.5 border-b border-slate-800/80">
              <div className="flex items-center gap-2">
                {group.icon}
                <h3 className="text-sm font-semibold text-white">{group.label}</h3>
                <span className="px-2 py-0.5 rounded-md bg-slate-900 border border-slate-800 text-[10px] font-mono text-slate-400">
                  {group.items.filter((i) => i.enabled).length} / {group.items.length} 走 WARP
                </span>
              </div>
              {routing.mode === 'bypass' && (
                <span className="text-[11px] font-mono text-rose-300">旁路模式生效中</span>
              )}
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-3">
              {group.items.map((preset) => {
                const isMissAV = preset.id === 'missav';
                const active = preset.enabled;
                return (
                  <div
                    key={preset.id}
                    className={`p-3.5 rounded-xl border transition-all flex flex-col justify-between gap-3 ${
                      active
                        ? 'bg-amber-500/8 border-amber-500/35 shadow-sm shadow-amber-500/5'
                        : 'bg-slate-950/55 border-slate-800/80 hover:border-slate-700'
                    }`}
                  >
                    <div className="space-y-1.5">
                      <div className="flex items-start justify-between gap-2">
                        <div>
                          <div className="flex items-center gap-1.5 flex-wrap">
                            <span className="text-sm font-semibold text-white">{preset.name}</span>
                            {isMissAV && (
                              <span className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-amber-500/15 text-amber-300 border border-amber-500/30">
                                6 域全覆盖
                              </span>
                            )}
                          </div>
                          <p className="text-[11px] text-slate-400 mt-0.5 leading-relaxed">
                            {preset.description}
                          </p>
                        </div>

                        <button
                          type="button"
                          role="switch"
                          aria-checked={active}
                          onClick={() => handleTogglePreset(preset.id)}
                          className={`relative inline-flex h-6 w-11 shrink-0 cursor-pointer rounded-full border transition-colors duration-200 focus:outline-none ${
                            active
                              ? 'bg-amber-500 border-amber-400'
                              : 'bg-slate-800 border-slate-700'
                          }`}
                          title={active ? '点击切换回原生直出' : '点击切走 WARP 出口'}
                        >
                          <span
                            className={`pointer-events-none inline-block h-5 w-5 transform rounded-full bg-white shadow transition duration-200 ${
                              active ? 'translate-x-5' : 'translate-x-0'
                            }`}
                          />
                        </button>
                      </div>
                    </div>

                    <div className="flex items-center justify-between gap-2 pt-2 border-t border-slate-800/60 text-[10px] font-mono">
                      <span className="text-slate-500 truncate" title={preset.domainsSummary}>
                        {preset.domainsSummary}
                      </span>
                      <span
                        className={`px-1.5 py-0.5 rounded shrink-0 border ${
                          routing.mode === 'bypass'
                            ? 'bg-slate-900 text-slate-500 border-slate-800'
                            : active
                            ? 'bg-amber-500/15 text-amber-300 border-amber-500/30'
                            : 'bg-sky-500/10 text-sky-300 border-sky-500/25'
                        }`}
                      >
                        {routing.mode === 'bypass' ? '已旁路' : active ? '⚡ WARP' : '原生直出'}
                      </span>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        ))}
      </div>

      {/* 4. 实时活跃连接透视与行内秒切面板 */}
      <div className="p-5 rounded-2xl glass-card space-y-4">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-3 pb-3 border-b border-slate-800/80">
          <div className="flex items-center gap-2.5">
            <div className="p-1.5 rounded-xl bg-purple-500/10 text-purple-400 border border-purple-500/20">
              <Globe className="w-4 h-4" />
            </div>
            <div>
              <h3 className="text-sm font-semibold text-white flex items-center gap-2">
                <span>实时活跃连接透视与行内秒切</span>
                <span className="px-2 py-0.5 rounded-full bg-slate-900 border border-slate-800 text-[10px] font-mono text-slate-400">
                  {connections.length} 个活跃目标
                </span>
              </h3>
              <p className="text-[11px] text-slate-400">
                实时追踪当前节点访问的远端站点与出口（不展示客户端源 IP），发现卡顿/弹验证可直接点选切走 WARP
              </p>
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <div className="relative">
              <Search className="w-3.5 h-3.5 text-slate-500 absolute left-2.5 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                value={connQuery}
                onChange={(e) => setConnQuery(e.target.value)}
                placeholder="筛选域名 / IP / 规则..."
                className="bg-slate-950 border border-slate-800 rounded-xl pl-8 pr-3 py-1.5 text-xs text-slate-200 placeholder:text-slate-500 focus:outline-none focus:border-amber-500/50 w-44 sm:w-56"
              />
            </div>

            <div className="inline-flex rounded-xl bg-slate-950 p-0.5 border border-slate-800 text-[11px]">
              {(['all', 'DC', 'WARP'] as const).map((f) => (
                <button
                  key={f}
                  type="button"
                  onClick={() => setConnFilter(f)}
                  className={`px-2.5 py-1 rounded-lg font-medium transition-colors ${
                    connFilter === f
                      ? 'bg-slate-800 text-white'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  {f === 'all' ? '全部' : f === 'DC' ? '直出 DC' : 'WARP'}
                </button>
              ))}
            </div>

            <button
              type="button"
              onClick={() => setAutoRefreshConn((v) => !v)}
              className={`px-2.5 py-1.5 rounded-xl border text-[11px] font-mono transition-colors ${
                autoRefreshConn
                  ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-300'
                  : 'bg-slate-900 border-slate-800 text-slate-400'
              }`}
            >
              {autoRefreshConn ? '5s 自动刷新' : '已暂停刷新'}
            </button>

            <button
              type="button"
              onClick={loadConnections}
              className="p-1.5 rounded-xl bg-slate-900 hover:bg-slate-800 border border-slate-800 text-slate-300"
              title="立即刷新活跃连接"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${loadingConn ? 'animate-spin' : ''}`} />
            </button>
          </div>
        </div>

        {!connEnabled ? (
          <div className="p-5 rounded-xl bg-slate-950/60 border border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <div className="text-xs text-slate-300">
              {connMsg || '当前 sing-box 尚未开启本地回环遥测接口 (127.0.0.1:9099)，无法透视实时连接。'}
            </div>
            <button
              type="button"
              onClick={handleEnableTelemetry}
              className="px-3.5 py-2 rounded-xl bg-emerald-500 hover:bg-emerald-600 text-slate-950 font-semibold text-xs shrink-0"
            >
              一键开启本地遥测
            </button>
          </div>
        ) : connections.length === 0 ? (
          <div className="py-8 text-center text-xs font-mono text-slate-500">
            当前无符合条件的活跃目标连接，客户端发起访问后将实时出现在此处
          </div>
        ) : (
          <div className="space-y-2 max-h-96 overflow-y-auto pr-1">
            {connections.map((item) => {
              const isWarp = item.outbound === 'WARP';
              const showRootBtn = !item.isIP && item.rootDomain && item.rootDomain !== item.target;
              const primaryTarget = showRootBtn ? item.rootDomain : item.target;
              const busyPrimary = switchingTarget === primaryTarget;
              const busyExact = switchingTarget === item.target;

              return (
                <div
                  key={`${item.target}-${item.outbound}`}
                  className="px-3.5 py-2.5 rounded-xl bg-slate-950/65 border border-slate-800/80 flex flex-col sm:flex-row sm:items-center justify-between gap-2.5 text-xs"
                >
                  <div className="min-w-0 flex-1 space-y-1">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="font-mono font-semibold text-slate-100 truncate" title={item.target}>
                        {item.target}
                      </span>
                      {showRootBtn && (
                        <span className="px-1.5 py-0.5 rounded bg-slate-900 border border-slate-800 text-[10px] font-mono text-slate-400">
                          主域 {item.rootDomain}
                        </span>
                      )}
                      <span className="px-1.5 py-0.5 rounded bg-slate-900 border border-slate-800 text-[10px] font-mono text-purple-300">
                        {item.protocol}
                      </span>
                      <span
                        className={`px-1.5 py-0.5 rounded text-[10px] font-mono border ${
                          isWarp
                            ? 'bg-amber-500/15 text-amber-300 border-amber-500/30'
                            : 'bg-sky-500/15 text-sky-300 border-sky-500/30'
                        }`}
                      >
                        {isWarp ? 'WARP' : '直出 DC'}
                      </span>
                    </div>
                    <div className="flex items-center gap-3 text-[11px] font-mono text-slate-400 flex-wrap">
                      <span>{item.connections} 条连接</span>
                      <span>累计 {formatBytes(item.totalBytes)}</span>
                      {item.rule && <span className="text-slate-500 truncate">命中: {item.rule}</span>}
                    </div>
                  </div>

                  <div className="flex items-center gap-1.5 shrink-0">
                    <button
                      type="button"
                      disabled={busyPrimary || routing.mode === 'bypass'}
                      onClick={() => handleQuickSwitch(primaryTarget, isWarp ? 'DC' : 'WARP')}
                      className={`inline-flex items-center gap-1 px-2.5 py-1.5 rounded-lg text-[11px] font-semibold border transition-colors disabled:opacity-45 ${
                        isWarp
                          ? 'bg-sky-500/10 hover:bg-sky-500/20 text-sky-300 border-sky-500/30'
                          : 'bg-amber-500/15 hover:bg-amber-500/25 text-amber-300 border-amber-500/35'
                      }`}
                    >
                      <Zap className={`w-3 h-3 ${busyPrimary ? 'animate-spin' : ''}`} />
                      <span>
                        {showRootBtn
                          ? isWarp
                            ? `主域切回直出`
                            : `主域切 WARP`
                          : isWarp
                          ? '切回直出'
                          : '切走 WARP'}
                      </span>
                    </button>

                    {showRootBtn && (
                      <button
                        type="button"
                        disabled={busyExact || routing.mode === 'bypass'}
                        onClick={() => handleQuickSwitch(`full:${item.target}`, isWarp ? 'DC' : 'WARP')}
                        className="px-2 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-700/70 text-[10px] font-mono text-slate-300 disabled:opacity-45"
                        title={`仅对精确域名 ${item.target} 进行分流`}
                      >
                        仅此子域
                      </button>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* 5. 自定义域名 / 网址 / IP-CIDR 规则仓 */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
        {/* 强制走 WARP 名单 */}
        <div className="p-5 rounded-2xl glass-card space-y-4">
          <div className="flex items-center justify-between pb-3 border-b border-slate-800/80">
            <div className="flex items-center gap-2">
              <Sparkles className="w-4 h-4 text-amber-400" />
              <div>
                <h3 className="text-sm font-semibold text-white">强制走 WARP 名单</h3>
                <p className="text-[11px] text-slate-400">
                  支持直接粘贴完整网址（自动提取域名）、<code className="text-amber-300">full:</code>、<code className="text-amber-300">keyword:</code> 或 IP/CIDR
                </p>
              </div>
            </div>
            <span className="px-2 py-0.5 rounded-md bg-amber-500/10 border border-amber-500/25 text-[11px] font-mono text-amber-300">
              {(routing.warpDomains?.length || 0) + (routing.warpCidrs?.length || 0)} 项
            </span>
          </div>

          <div className="space-y-2">
            <div className="flex gap-2">
              <input
                type="text"
                value={warpInput}
                onChange={(e) => setWarpInput(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter') {
                    e.preventDefault();
                    handleAddRules('warp', warpInput);
                  }
                }}
                placeholder="例如: missav.ws 或粘贴 https://missav.ws/dm13/... 或 198.51.100.0/24"
                className="flex-1 bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-xs font-mono text-slate-100 placeholder:text-slate-500 focus:outline-none focus:border-amber-500/60"
              />
              <button
                type="button"
                onClick={() => handleAddRules('warp', warpInput)}
                disabled={!warpInput.trim()}
                className="inline-flex items-center gap-1 px-3.5 py-2 rounded-xl bg-amber-500 hover:bg-amber-400 text-slate-950 font-semibold text-xs disabled:opacity-40 shrink-0"
              >
                <Plus className="w-3.5 h-3.5" />
                <span>添加</span>
              </button>
            </div>
            {warpPreview && (
              <div className="text-[11px] font-mono text-amber-300/90 flex items-center gap-1.5">
                <CheckCircle2 className="w-3 h-3" />
                <span>
                  将添加{warpPreview.kind === 'cidr' ? ' IP/CIDR 规则' : '域名规则'}: <strong>{warpPreview.value}</strong>
                </span>
              </div>
            )}
          </div>

          <div className="flex flex-wrap gap-1.5 min-h-[44px] items-start">
            {(routing.warpDomains || []).map((d) => (
              <span
                key={`wd-${d}`}
                className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-amber-500/10 border border-amber-500/30 text-xs font-mono text-amber-200"
              >
                <span>{d}</span>
                <button
                  type="button"
                  onClick={() => handleRemoveRule('warp', 'domain', d)}
                  className="text-amber-300/70 hover:text-rose-300"
                  title="移除规则"
                >
                  <Trash2 className="w-3 h-3" />
                </button>
              </span>
            ))}
            {(routing.warpCidrs || []).map((c) => (
              <span
                key={`wc-${c}`}
                className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-orange-500/10 border border-orange-500/30 text-xs font-mono text-orange-200"
              >
                <span>CIDR {c}</span>
                <button
                  type="button"
                  onClick={() => handleRemoveRule('warp', 'cidr', c)}
                  className="text-orange-300/70 hover:text-rose-300"
                  title="移除规则"
                >
                  <Trash2 className="w-3 h-3" />
                </button>
              </span>
            ))}
            {(routing.warpDomains?.length || 0) + (routing.warpCidrs?.length || 0) === 0 && (
              <span className="text-xs font-mono text-slate-500">暂无自定义 WARP 规则</span>
            )}
          </div>
        </div>

        {/* 强制原生直出白名单 */}
        <div className="p-5 rounded-2xl glass-card space-y-4">
          <div className="flex items-center justify-between pb-3 border-b border-slate-800/80">
            <div className="flex items-center gap-2">
              <ShieldCheck className="w-4 h-4 text-sky-400" />
              <div>
                <h3 className="text-sm font-semibold text-white">强制原生直出白名单 (最高优先级)</h3>
                <p className="text-[11px] text-slate-400">
                  优先于全局 WARP 与预设规则执行，适合国内直连服务、银行或内部接口放行原生出口
                </p>
              </div>
            </div>
            <span className="px-2 py-0.5 rounded-md bg-sky-500/10 border border-sky-500/25 text-[11px] font-mono text-sky-300">
              {(routing.directDomains?.length || 0) + (routing.directCidrs?.length || 0)} 项
            </span>
          </div>

          <div className="space-y-2">
            <div className="flex gap-2">
              <input
                type="text"
                value={directInput}
                onChange={(e) => setDirectInput(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter') {
                    e.preventDefault();
                    handleAddRules('direct', directInput);
                  }
                }}
                placeholder="例如: direct.example.com 或 203.0.113.0/24"
                className="flex-1 bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-xs font-mono text-slate-100 placeholder:text-slate-500 focus:outline-none focus:border-sky-500/60"
              />
              <button
                type="button"
                onClick={() => handleAddRules('direct', directInput)}
                disabled={!directInput.trim()}
                className="inline-flex items-center gap-1 px-3.5 py-2 rounded-xl bg-sky-500 hover:bg-sky-400 text-slate-950 font-semibold text-xs disabled:opacity-40 shrink-0"
              >
                <Plus className="w-3.5 h-3.5" />
                <span>添加</span>
              </button>
            </div>
            {directPreview && (
              <div className="text-[11px] font-mono text-sky-300/90 flex items-center gap-1.5">
                <CheckCircle2 className="w-3 h-3" />
                <span>
                  将添加{directPreview.kind === 'cidr' ? ' IP/CIDR 白名单' : '直出域名白名单'}: <strong>{directPreview.value}</strong>
                </span>
              </div>
            )}
          </div>

          <div className="flex flex-wrap gap-1.5 min-h-[44px] items-start">
            {(routing.directDomains || []).map((d) => (
              <span
                key={`dd-${d}`}
                className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-sky-500/10 border border-sky-500/30 text-xs font-mono text-sky-200"
              >
                <span>{d}</span>
                <button
                  type="button"
                  onClick={() => handleRemoveRule('direct', 'domain', d)}
                  className="text-sky-300/70 hover:text-rose-300"
                  title="移除白名单"
                >
                  <Trash2 className="w-3 h-3" />
                </button>
              </span>
            ))}
            {(routing.directCidrs || []).map((c) => (
              <span
                key={`dc-${c}`}
                className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-cyan-500/10 border border-cyan-500/30 text-xs font-mono text-cyan-200"
              >
                <span>CIDR {c}</span>
                <button
                  type="button"
                  onClick={() => handleRemoveRule('direct', 'cidr', c)}
                  className="text-cyan-300/70 hover:text-rose-300"
                  title="移除白名单"
                >
                  <Trash2 className="w-3 h-3" />
                </button>
              </span>
            ))}
            {(routing.directDomains?.length || 0) + (routing.directCidrs?.length || 0) === 0 && (
              <span className="text-xs font-mono text-slate-500">暂无强制直出白名单</span>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

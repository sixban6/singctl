import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  ActiveDestinationGroup,
  WarpPresetItem,
  WarpRoutingConfig,
  WarpRoutingMode,
  WarpRoutingStatusResponse,
} from '../types';
import { api } from '../api';
import {
  Badge,
  Button,
  CardSkeleton,
  PageHeader,
  SectionCard,
  SegmentedTabs,
  useToast,
} from '../ui';
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
    return { kind: 'cidr', value: trimmed };
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

  const [connEnabled, setConnEnabled] = useState(true);
  const [connMsg, setConnMsg] = useState('');
  const [connections, setConnections] = useState<ActiveDestinationGroup[]>([]);
  const [connQuery, setConnQuery] = useState('');
  const [connFilter, setConnFilter] = useState<'all' | 'DC' | 'WARP'>('all');
  const [autoRefreshConn, setAutoRefreshConn] = useState(true);
  const [loadingConn, setLoadingConn] = useState(false);
  const [switchingTarget, setSwitchingTarget] = useState<string | null>(null);

  const [warpInput, setWarpInput] = useState('');
  const [directInput, setDirectInput] = useState('');

  const debounceTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const rollbackSnapshotRef = useRef<WarpRoutingStatusResponse | null>(null);

  const loadRouting = useCallback(
    async (forceRefresh = false) => {
      try {
        const res = await api.getWarpRouting(forceRefresh);
        setData(res);
      } catch (err: unknown) {
        error(err instanceof Error ? err.message : '获取 WARP 分流配置失败');
      } finally {
        setLoading(false);
      }
    },
    [error],
  );

  const loadConnections = useCallback(async () => {
    setLoadingConn(true);
    try {
      const res = await api.getWarpConnections(connQuery, connFilter);
      setConnEnabled(res.enabled);
      setConnMsg(res.message || '');
      setConnections(res.destinations || []);
    } catch {
      // ignore background poll error
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
    const timer = window.setInterval(() => {
      loadConnections();
    }, 5000);
    return () => window.clearInterval(timer);
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
      } catch (err: unknown) {
        if (snapshotForRollback) setData(snapshotForRollback);
        rollbackSnapshotRef.current = null;
        error(err instanceof Error ? err.message : '更新 WARP 分流配置失败');
      } finally {
        setSaving(false);
      }
    },
    [error, loadConnections, success],
  );

  const scheduleOptimisticUpdate = (
    mutator: (prev: WarpRoutingStatusResponse) => {
      nextRouting: WarpRoutingConfig;
      nextPresets: WarpPresetItem[];
    },
    immediate = false,
  ) => {
    if (!data) return;
    if (!rollbackSnapshotRef.current) rollbackSnapshotRef.current = data;
    const { nextRouting, nextPresets } = mutator(data);
    setData({ ...data, routing: nextRouting, presets: nextPresets });

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
      true,
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
        nextRouting: { ...prev.routing, presets: currentPresetsMap },
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
      true,
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
      true,
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
    } catch (err: unknown) {
      error(err instanceof Error ? err.message : '切换失败');
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
    } catch (err: unknown) {
      error(err instanceof Error ? err.message : 'WARP 操作执行失败');
    } finally {
      setActing(null);
    }
  };

  const handleEnableTelemetry = async () => {
    try {
      const res = await api.enableTelemetry();
      success(res.message || '实时流量遥测已开启');
      loadConnections();
    } catch (err: unknown) {
      error(err instanceof Error ? err.message : '开启实时遥测失败');
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
      <div className="space-y-4">
        <CardSkeleton />
        <CardSkeleton />
      </div>
    );
  }

  return (
    <div className="space-y-5">
      {/* Anti-blackhole protection banner */}
      {daemon && !daemon.tunnelHealthy && (
        <div className="rounded-2xl border border-amber-500/40 bg-amber-500/10 p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div className="flex items-start gap-3">
            <AlertTriangle className="w-5 h-5 text-amber-400 shrink-0 mt-0.5" />
            <div>
              <h3 className="text-sm font-bold text-primary">
                本地 WARP 隧道 (127.0.0.1:40000) 当前未就绪
              </h3>
              <p className="text-xs text-secondary mt-1">
                {daemon.error || 'wireproxy 尚未安装或已停止运行'}。为防止流量切换后断网，系统已启用防黑洞保护。
              </p>
            </div>
          </div>
          <Button
            size="sm"
            variant="primary"
            loading={acting === 'ensure'}
            icon={<Wrench className="w-3.5 h-3.5" />}
            onClick={() => handleWarpAction('ensure')}
          >
            {acting === 'ensure' ? '部署修复中…' : '一键部署 / 修复 WARP'}
          </Button>
        </div>
      )}

      <PageHeader
        title="WARP 智能分流中心"
        description="采用 SIGHUP 零断流热重载 + 逐流精准切换，修改预设或自定义域名后毫秒级生效且不影响其它活跃连接"
        badge={
          <div className="flex items-center gap-1.5">
            <Badge tone={daemon?.tunnelHealthy ? 'ok' : 'danger'} dot pulse={daemon?.tunnelHealthy}>
              {daemon?.tunnelHealthy ? '127.0.0.1:40000 就绪' : '隧道未连通'}
            </Badge>
            {saving && <Badge tone="accent">热更新中…</Badge>}
          </div>
        }
        actions={
          <div className="flex flex-wrap items-center gap-2">
            <Button
              size="sm"
              variant="secondary"
              loading={acting === 'rekey'}
              disabled={acting !== null || !daemon?.installed}
              icon={<RotateCcw className="w-3.5 h-3.5" />}
              onClick={() => handleWarpAction('rekey')}
              title="重新注册 WireGuard 身份更换 Cloudflare WARP 出口 IP"
            >
              {acting === 'rekey' ? '换 IP 中…' : '更换 WARP IP'}
            </Button>
            <Button
              size="sm"
              variant="secondary"
              icon={<RefreshCw className="w-3.5 h-3.5" />}
              onClick={() => loadRouting(true)}
            >
              刷新
            </Button>
          </div>
        }
      />

      {/* Global Mode & Daemon Telemetry */}
      <SectionCard>
        <div className="flex flex-col xl:flex-row xl:items-center justify-between gap-4">
          <div className="flex flex-wrap items-center gap-2 text-xs font-mono tnum">
            <Badge tone="warn">
              WARP 出口: {daemon?.warpIp ? `${daemon.warpIp}${daemon.warpLoc ? ` (${daemon.warpLoc})` : ''}` : '待探测'}
            </Badge>
            <Badge tone="accent">直出 DC: {data?.dcConnCount ?? 0} 连</Badge>
            <Badge tone="ok">WARP 分流: {data?.warpConnCount ?? 0} 连</Badge>
          </div>

          <div className="flex flex-col sm:items-end gap-1.5">
            <SegmentedTabs
              value={routing.mode}
              onChange={(m) => handleModeChange(m as WarpRoutingMode)}
              items={[
                { key: 'split', label: '原生优先 · 按需分流', icon: <Split className="w-3.5 h-3.5" /> },
                { key: 'global_warp', label: '全局 WARP 接管', icon: <Shield className="w-3.5 h-3.5" /> },
                { key: 'bypass', label: '紧急全直出旁路', icon: <PauseCircle className="w-3.5 h-3.5" /> },
              ]}
            />
            <p className="text-[11px] text-muted">
              {routing.mode === 'split' && '未命中 WARP 规则的流量默认走 VPS 原生直出，兼顾速度与关键服务解锁'}
              {routing.mode === 'global_warp' && '除「强制原生直出白名单」外，全站出站默认经 WARP 隐匿源站 IP'}
              {routing.mode === 'bypass' && '紧急旁路中：所有 WARP 分流规则已临时挂起（配置保留，可随时恢复）'}
            </p>
          </div>
        </div>
      </SectionCard>

      {/* Preset Matrix */}
      <div className="space-y-4">
        {groupedPresets.map((group) => (
          <SectionCard
            key={group.key}
            title={group.label}
            icon={group.icon}
            badge={
              <Badge tone="neutral">
                {group.items.filter((i) => i.enabled).length} / {group.items.length} 走 WARP
              </Badge>
            }
            actions={
              routing.mode === 'bypass' ? <Badge tone="danger">旁路模式生效中</Badge> : undefined
            }
          >
            <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-3">
              {group.items.map((preset) => {
                const isMissAV = preset.id === 'missav';
                const active = preset.enabled;
                return (
                  <div
                    key={preset.id}
                    className={`p-3.5 rounded-xl border transition-colors flex flex-col justify-between gap-3 ${
                      active
                        ? 'bg-amber-500/10 border-amber-500/35'
                        : 'bg-surface2/60 border-subtle'
                    }`}
                  >
                    <div className="flex items-start justify-between gap-2.5">
                      <div className="min-w-0">
                        <div className="flex items-center gap-1.5 flex-wrap">
                          <span className="text-sm font-semibold text-primary">{preset.name}</span>
                          {isMissAV && <Badge tone="warn">6 域全覆盖</Badge>}
                        </div>
                        <p className="text-[11px] text-secondary mt-1 leading-relaxed">
                          {preset.description}
                        </p>
                      </div>

                      <button
                        type="button"
                        role="switch"
                        aria-checked={active}
                        onClick={() => handleTogglePreset(preset.id)}
                        className={`relative inline-flex h-6 w-11 shrink-0 cursor-pointer rounded-full border transition-colors duration-200 ${
                          active ? 'bg-amber-500 border-amber-400' : 'bg-surface2 border-strong'
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

                    <div className="flex items-center justify-between gap-2 pt-2 border-t border-subtle text-[10.5px] font-mono">
                      <span className="text-muted truncate" title={preset.domainsSummary}>
                        {preset.domainsSummary}
                      </span>
                      <Badge
                        tone={routing.mode === 'bypass' ? 'neutral' : active ? 'warn' : 'accent'}
                      >
                        {routing.mode === 'bypass' ? '已旁路' : active ? 'WARP' : '直出'}
                      </Badge>
                    </div>
                  </div>
                );
              })}
            </div>
          </SectionCard>
        ))}
      </div>

      {/* Live Connections & Inline Quick Switch */}
      <SectionCard
        title="实时活跃连接透视与行内秒切"
        subtitle="实时追踪当前节点访问的远端站点与出口，发现卡顿或验证可立即切换出口"
        icon={<Globe className="w-4 h-4" />}
        badge={<Badge tone="neutral">{connections.length} 活跃目标</Badge>}
        actions={
          <div className="flex flex-wrap items-center gap-2">
            <div className="relative">
              <Search className="w-3.5 h-3.5 text-muted absolute left-2.5 top-1/2 -translate-y-1/2 pointer-events-none" />
              <input
                type="text"
                value={connQuery}
                onChange={(e) => setConnQuery(e.target.value)}
                placeholder="筛选域名 / IP / 规则…"
                className="sc-input pl-8 pr-3 py-1.5 text-xs w-40 sm:w-52"
              />
            </div>

            <SegmentedTabs
              value={connFilter}
              onChange={(v) => setConnFilter(v as 'all' | 'DC' | 'WARP')}
              items={[
                { key: 'all', label: '全部' },
                { key: 'DC', label: '直出 DC' },
                { key: 'WARP', label: 'WARP' },
              ]}
            />

            <Button
              size="xs"
              variant={autoRefreshConn ? 'primary' : 'secondary'}
              onClick={() => setAutoRefreshConn((v) => !v)}
            >
              {autoRefreshConn ? '5s 自动刷新' : '已暂停'}
            </Button>

            <Button
              size="xs"
              variant="secondary"
              loading={loadingConn}
              icon={<RefreshCw className="w-3.5 h-3.5" />}
              onClick={loadConnections}
            />
          </div>
        }
      >
        {!connEnabled ? (
          <div className="p-4 rounded-xl bg-surface2/60 border border-subtle flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <div className="text-xs text-secondary">
              {connMsg || '当前 sing-box 尚未开启本地回环遥测接口 (127.0.0.1:9099)，无法透视实时连接。'}
            </div>
            <Button size="sm" variant="primary" onClick={handleEnableTelemetry}>
              一键开启本地遥测
            </Button>
          </div>
        ) : connections.length === 0 ? (
          <div className="py-8 text-center text-xs font-mono text-muted">
            当前无符合条件的活跃目标连接，客户端发起访问后将实时出现在此处
          </div>
        ) : (
          <div className="space-y-2 max-h-96 overflow-y-auto pr-1">
            {connections.map((item) => {
              const isWarp = item.outbound === 'WARP';
              const showRootBtn = Boolean(!item.isIP && item.rootDomain && item.rootDomain !== item.target);
              const primaryTarget = showRootBtn ? item.rootDomain : item.target;
              const busyPrimary = switchingTarget === primaryTarget;
              const busyExact = switchingTarget === item.target;

              return (
                <div
                  key={`${item.target}-${item.outbound}`}
                  className="px-3.5 py-2.5 rounded-xl bg-surface2/60 border border-subtle flex flex-col sm:flex-row sm:items-center justify-between gap-2.5 text-xs"
                >
                  <div className="min-w-0 flex-1 space-y-1">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="font-mono font-semibold text-primary truncate" title={item.target}>
                        {item.target}
                      </span>
                      {showRootBtn && <Badge tone="neutral">主域 {item.rootDomain}</Badge>}
                      <Badge tone="neutral">{item.protocol}</Badge>
                      <Badge tone={isWarp ? 'warn' : 'accent'}>{isWarp ? 'WARP' : '直出 DC'}</Badge>
                    </div>
                    <div className="flex items-center gap-3 text-[11px] font-mono tnum text-muted flex-wrap">
                      <span>{item.connections} 条连接</span>
                      <span>累计 {formatBytes(item.totalBytes)}</span>
                      {item.rule && <span className="truncate">命中: {item.rule}</span>}
                    </div>
                  </div>

                  <div className="flex items-center gap-1.5 shrink-0">
                    <Button
                      size="xs"
                      variant="secondary"
                      loading={busyPrimary}
                      disabled={routing.mode === 'bypass'}
                      icon={<Zap className="w-3 h-3" />}
                      onClick={() => handleQuickSwitch(primaryTarget, isWarp ? 'DC' : 'WARP')}
                    >
                      {showRootBtn
                        ? isWarp
                          ? '主域切回直出'
                          : '主域切 WARP'
                        : isWarp
                        ? '切回直出'
                        : '切走 WARP'}
                    </Button>
                    {showRootBtn && (
                      <Button
                        size="xs"
                        variant="ghost"
                        loading={busyExact}
                        disabled={routing.mode === 'bypass'}
                        onClick={() => handleQuickSwitch(`full:${item.target}`, isWarp ? 'DC' : 'WARP')}
                      >
                        仅此子域
                      </Button>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </SectionCard>

      {/* Custom Domain / CIDR Rules */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
        <SectionCard
          title="强制走 WARP 名单"
          subtitle="支持粘贴网址自动提取域名、full:、keyword: 或 IP/CIDR"
          icon={<Sparkles className="w-4 h-4" />}
          badge={
            <Badge tone="warn">
              {(routing.warpDomains?.length || 0) + (routing.warpCidrs?.length || 0)} 项
            </Badge>
          }
        >
          <div className="space-y-3">
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
                placeholder="例如: missav.ws 或 198.51.100.0/24"
                className="sc-input flex-1 px-3 py-2 text-xs font-mono"
              />
              <Button
                size="sm"
                variant="primary"
                disabled={!warpInput.trim()}
                icon={<Plus className="w-3.5 h-3.5" />}
                onClick={() => handleAddRules('warp', warpInput)}
              >
                添加
              </Button>
            </div>
            {warpPreview && (
              <div className="text-[11px] font-mono text-amber-400 flex items-center gap-1.5">
                <CheckCircle2 className="w-3 h-3" />
                <span>
                  将添加{warpPreview.kind === 'cidr' ? ' IP/CIDR' : '域名'}: <strong>{warpPreview.value}</strong>
                </span>
              </div>
            )}

            <div className="flex flex-wrap gap-1.5 min-h-[40px] items-start">
              {(routing.warpDomains || []).map((d) => (
                <span
                  key={`wd-${d}`}
                  className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-amber-500/12 border border-amber-500/25 text-xs font-mono text-amber-300"
                >
                  <span>{d}</span>
                  <button
                    type="button"
                    onClick={() => handleRemoveRule('warp', 'domain', d)}
                    className="hover:text-rose-400 cursor-pointer"
                  >
                    <Trash2 className="w-3 h-3" />
                  </button>
                </span>
              ))}
              {(routing.warpCidrs || []).map((c) => (
                <span
                  key={`wc-${c}`}
                  className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-orange-500/12 border border-orange-500/25 text-xs font-mono text-orange-300"
                >
                  <span>CIDR {c}</span>
                  <button
                    type="button"
                    onClick={() => handleRemoveRule('warp', 'cidr', c)}
                    className="hover:text-rose-400 cursor-pointer"
                  >
                    <Trash2 className="w-3 h-3" />
                  </button>
                </span>
              ))}
              {(routing.warpDomains?.length || 0) + (routing.warpCidrs?.length || 0) === 0 && (
                <span className="text-xs font-mono text-muted">暂无自定义 WARP 规则</span>
              )}
            </div>
          </div>
        </SectionCard>

        <SectionCard
          title="强制原生直出白名单 (最高优先级)"
          subtitle="优先于全局 WARP 与预设规则执行，适合国内服务或银行站点直连"
          icon={<ShieldCheck className="w-4 h-4" />}
          badge={
            <Badge tone="accent">
              {(routing.directDomains?.length || 0) + (routing.directCidrs?.length || 0)} 项
            </Badge>
          }
        >
          <div className="space-y-3">
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
                className="sc-input flex-1 px-3 py-2 text-xs font-mono"
              />
              <Button
                size="sm"
                variant="primary"
                disabled={!directInput.trim()}
                icon={<Plus className="w-3.5 h-3.5" />}
                onClick={() => handleAddRules('direct', directInput)}
              >
                添加
              </Button>
            </div>
            {directPreview && (
              <div className="text-[11px] font-mono text-accent flex items-center gap-1.5">
                <CheckCircle2 className="w-3 h-3" />
                <span>
                  将添加{directPreview.kind === 'cidr' ? ' IP/CIDR 白名单' : '直出域名白名单'}:{' '}
                  <strong>{directPreview.value}</strong>
                </span>
              </div>
            )}

            <div className="flex flex-wrap gap-1.5 min-h-[40px] items-start">
              {(routing.directDomains || []).map((d) => (
                <span
                  key={`dd-${d}`}
                  className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-sky-500/12 border border-sky-500/25 text-xs font-mono text-accent"
                >
                  <span>{d}</span>
                  <button
                    type="button"
                    onClick={() => handleRemoveRule('direct', 'domain', d)}
                    className="hover:text-rose-400 cursor-pointer"
                  >
                    <Trash2 className="w-3 h-3" />
                  </button>
                </span>
              ))}
              {(routing.directCidrs || []).map((c) => (
                <span
                  key={`dc-${c}`}
                  className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-cyan-500/12 border border-cyan-500/25 text-xs font-mono text-cyan-400"
                >
                  <span>CIDR {c}</span>
                  <button
                    type="button"
                    onClick={() => handleRemoveRule('direct', 'cidr', c)}
                    className="hover:text-rose-400 cursor-pointer"
                  >
                    <Trash2 className="w-3 h-3" />
                  </button>
                </span>
              ))}
              {(routing.directDomains?.length || 0) + (routing.directCidrs?.length || 0) === 0 && (
                <span className="text-xs font-mono text-muted">暂无强制直出白名单</span>
              )}
            </div>
          </div>
        </SectionCard>
      </div>
    </div>
  );
};

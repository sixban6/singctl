import React, { useState, useEffect, useCallback } from 'react';
import {
  Dog,
  RefreshCw,
  Zap,
  ShieldCheck,
  GitBranch,
  RotateCcw,
  Clock,
  Settings2,
} from 'lucide-react';
import { Badge, Button, PageHeader, SectionCard, Skeleton, useToast } from '../../ui';
import { clientApi } from '../api';
import { ClientHealthResponse, WatchdogReport } from '../types';

const DEFAULT_FO_GROUPS = ['#VPS', 'Game-TCP', 'Game-UDP', 'Game', 'Proxy', 'AI'];
const DEFAULT_FO_URLS = [
  'https://www.gstatic.com/generate_204',
  'http://cp.cloudflare.com/generate_204',
];

function fmtKB(bytes: number): string {
  const n = Number(bytes) || 0;
  if (n < 1024) return `${n} B`;
  return `${(n / 1024).toFixed(1)} KB`;
}

export interface WatchdogPageProps {
  busy: boolean;
  onAction: (name: string, params?: Record<string, unknown>, confirmMsg?: string) => void;
  onRefreshStatus: () => void;
  onOpenEventsLog: () => void;
}

export const WatchdogPage: React.FC<WatchdogPageProps> = ({
  busy,
  onAction,
  onRefreshStatus,
  onOpenEventsLog,
}) => {
  const { success, error, toast } = useToast();
  const [report, setReport] = useState<WatchdogReport | null>(null);
  const [loading, setLoading] = useState(true);
  const [patrolling, setPatrolling] = useState(false);
  const [savingFO, setSavingFO] = useState(false);
  const [savingBasic, setSavingBasic] = useState(false);
  const [healthChecking, setHealthChecking] = useState(false);
  const [healthRes, setHealthRes] = useState<ClientHealthResponse | null>(null);

  // Failover form state
  const [foEnabled, setFoEnabled] = useState(true);
  const [selectedGroups, setSelectedGroups] = useState<string[]>(DEFAULT_FO_GROUPS);
  const [customGroupInput, setCustomGroupInput] = useState('');
  const [patrolInterval, setPatrolInterval] = useState(30);
  const [probeTimeoutMs, setProbeTimeoutMs] = useState(2800);
  const [confirmRetries, setConfirmRetries] = useState(1);
  const [autoFailback, setAutoFailback] = useState(true);
  const [cooldownSec, setCooldownSec] = useState(180);
  const [maxFailbackDelayMs, setMaxFailbackDelayMs] = useState(600);
  const [probeUrlsText, setProbeUrlsText] = useState(DEFAULT_FO_URLS.join('\n'));
  const [showAdvURLs, setShowAdvURLs] = useState(false);

  // Basic watchdog form state
  const [wdInterval, setWdInterval] = useState(180);
  const [wdConfirmWait, setWdConfirmWait] = useState(30);
  const [wdMaxRestarts, setWdMaxRestarts] = useState(3);
  const [wdSubSyncEnabled, setWdSubSyncEnabled] = useState(true);
  const [wdSubSyncInterval, setWdSubSyncInterval] = useState(600);

  const [dirty, setDirty] = useState(false);

  const applyReport = useCallback(
    (data: WatchdogReport, preserveForm: boolean) => {
      setReport(data);
      const cfg = data.config;
      const fo = cfg.failover;
      if (!preserveForm || !dirty) {
        setFoEnabled(fo.enabled !== false);
        setSelectedGroups(fo.groups?.length ? [...fo.groups] : [...DEFAULT_FO_GROUPS]);
        setPatrolInterval(fo.patrol_interval || 30);
        setProbeTimeoutMs(fo.probe_timeout_ms || 2800);
        setConfirmRetries(fo.confirm_retries ?? 1);
        setAutoFailback(fo.auto_failback !== false);
        setCooldownSec(fo.failback_cooldown || 180);
        setMaxFailbackDelayMs(fo.max_failback_delay_ms || 600);
        setProbeUrlsText((fo.probe_urls?.length ? fo.probe_urls : DEFAULT_FO_URLS).join('\n'));

        setWdInterval(cfg.interval || 180);
        setWdConfirmWait(cfg.confirm_wait || 30);
        setWdMaxRestarts(cfg.max_restarts || 3);
        setWdSubSyncEnabled(cfg.sub_sync_enabled !== false);
        setWdSubSyncInterval(cfg.sub_sync_interval || 600);
        setDirty(false);
      }
    },
    [dirty],
  );

  const loadWatchdog = useCallback(
    async (preserveForm = false) => {
      try {
        const data = await clientApi.getWatchdog();
        applyReport(data, preserveForm);
      } catch (err: unknown) {
        if (!preserveForm) error(err instanceof Error ? err.message : '加载看门狗状态失败');
      } finally {
        setLoading(false);
      }
    },
    [applyReport, error],
  );

  useEffect(() => {
    void loadWatchdog(false);
  }, [loadWatchdog]);

  const handleImmediateHealth = async () => {
    setHealthChecking(true);
    try {
      setHealthRes(await clientApi.getHealth());
    } catch (err: unknown) {
      setHealthRes({
        healthy: false,
        dnsOK: false,
        details: err instanceof Error ? err.message : '健康检测失败',
        checkTime: new Date().toLocaleTimeString(),
      });
    } finally {
      setHealthChecking(false);
    }
  };

  const handleImmediatePatrol = async () => {
    setPatrolling(true);
    try {
      const res = await clientApi.runWatchdogPatrol();
      if (res.report) applyReport(res.report, true);
      else await loadWatchdog(true);
      const evs = res.events || [];
      if (evs.length > 0) {
        toast(`线路巡检完成：${evs.map((e) => e.summary).join('；')}`, 'warn', 5500);
      } else {
        success(res.message || '线路巡检完成：所有受保护策略组当前节点均健康');
      }
    } catch (err: unknown) {
      error(`线路巡检失败：${err instanceof Error ? err.message : '未知错误'}`);
    } finally {
      setPatrolling(false);
    }
  };

  const handleToggleFailover = async (next: boolean) => {
    setFoEnabled(next);
    try {
      const res = await clientApi.updateWatchdogConfig({ failover: { enabled: next } });
      success(res.message || (next ? '已开启策略组自动故障切换（已热生效）' : '已关闭策略组自动故障切换（已热生效）'));
      if (res.daemon || res.config) {
        applyReport((res.report || res) as WatchdogReport, true);
      }
      onRefreshStatus();
    } catch (err: unknown) {
      setFoEnabled(!next);
      error(`切换失败：${err instanceof Error ? err.message : '未知错误'}`);
    }
  };

  const toggleGroupChip = (name: string) => {
    setSelectedGroups((prev) => {
      if (prev.includes(name)) {
        if (prev.length === 1) {
          toast('至少保留 1 个受保护策略组；如需停用请关闭右上角总开关', 'warn');
          return prev;
        }
        setDirty(true);
        return prev.filter((g) => g !== name);
      }
      setDirty(true);
      return [...prev, name];
    });
  };

  const addCustomGroup = () => {
    const val = customGroupInput.trim();
    if (!val) return;
    if (selectedGroups.includes(val)) {
      toast(`分组「${val}」已在受保护列表中`, 'info');
    } else {
      setSelectedGroups((prev) => [...prev, val]);
      setDirty(true);
      success(`已添加受保护策略组：${val}`);
    }
    setCustomGroupInput('');
  };

  const saveFailover = async (overridePayload?: Record<string, unknown>) => {
    setSavingFO(true);
    try {
      const urls = probeUrlsText
        .split(/[\n,]+/)
        .map((s) => s.trim())
        .filter(Boolean);
      const failoverPayload = overridePayload || {
        enabled: foEnabled,
        groups: selectedGroups,
        has_groups: true,
        patrol_interval: patrolInterval,
        probe_timeout_ms: probeTimeoutMs,
        confirm_retries: confirmRetries,
        auto_failback: autoFailback,
        failback_cooldown: cooldownSec,
        max_failback_delay_ms: maxFailbackDelayMs,
        probe_urls: urls,
        has_probe_urls: true,
      };
      const res = await clientApi.updateWatchdogConfig({ failover: failoverPayload });
      setDirty(false);
      if (res.daemon || res.config) applyReport((res.report || res) as WatchdogReport, false);
      onRefreshStatus();
      success(res.message || '故障切换策略已保存并热生效');
    } catch (err: unknown) {
      error(`保存失败：${err instanceof Error ? err.message : '未知错误'}`);
    } finally {
      setSavingFO(false);
    }
  };

  const resetAllFailover = async () => {
    setFoEnabled(true);
    setSelectedGroups([...DEFAULT_FO_GROUPS]);
    setPatrolInterval(30);
    setProbeTimeoutMs(2800);
    setConfirmRetries(1);
    setAutoFailback(true);
    setCooldownSec(180);
    setMaxFailbackDelayMs(600);
    setProbeUrlsText(DEFAULT_FO_URLS.join('\n'));
    await saveFailover({
      enabled: true,
      groups: [...DEFAULT_FO_GROUPS],
      has_groups: true,
      patrol_interval: 30,
      probe_timeout_ms: 2800,
      confirm_retries: 1,
      auto_failback: true,
      failback_cooldown: 180,
      max_failback_delay_ms: 600,
      probe_urls: [...DEFAULT_FO_URLS],
      has_probe_urls: true,
    });
  };

  const saveBasicConfig = async () => {
    setSavingBasic(true);
    try {
      const res = await clientApi.updateWatchdogConfig({
        interval: wdInterval,
        confirm_wait: wdConfirmWait,
        max_restarts: wdMaxRestarts,
        sub_sync_enabled: wdSubSyncEnabled,
        sub_sync_interval: wdSubSyncInterval,
      });
      setDirty(false);
      if (res.daemon || res.config) applyReport((res.report || res) as WatchdogReport, false);
      onRefreshStatus();
      success(res.message || '基础守护参数已保存并热生效');
    } catch (err: unknown) {
      error(`保存失败：${err instanceof Error ? err.message : '未知错误'}`);
    } finally {
      setSavingBasic(false);
    }
  };

  if (loading && !report) {
    return (
      <div className="space-y-4">
        <PageHeader title="看门狗与容灾自愈" description="加载守护进程运行快照…" />
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          <Skeleton className="h-52 rounded-2xl" />
          <Skeleton className="h-52 rounded-2xl" />
        </div>
      </div>
    );
  }

  const dm = report?.daemon;
  const cfg = report?.config;
  const rt = report?.runtime;
  const agh = report?.adguard;
  const activeFO = rt?.activeFailovers || [];
  const events = [...(rt?.recentEvents || [])].reverse().slice(0, 15);

  const liveGroupMap = new Map((report?.selectorGroups || []).map((g) => [g.name, g]));
  const orderedGroupNames = Array.from(
    new Set([
      ...(report?.selectorGroups || []).map((g) => g.name).filter(Boolean),
      ...selectedGroups,
      ...(selectedGroups.length === 0 ? DEFAULT_FO_GROUPS : []),
    ]),
  );

  return (
    <div className="space-y-5">
      <PageHeader
        title="看门狗与容灾自愈"
        description="7×24 进程保活、策略组无缝切备、订阅静默热同步"
        badge={
          <Badge tone={dm?.running ? 'ok' : 'neutral'} dot={dm?.running} pulse={dm?.running}>
            {dm?.running ? `守护运行中${dm.pid ? ` · PID ${dm.pid}` : ''}` : '守护未运行'}
          </Badge>
        }
        actions={
          <>
            <Button size="sm" loading={healthChecking} onClick={handleImmediateHealth} icon={<Zap className="w-3.5 h-3.5" />}>
              立即健康检测
            </Button>
            <Button size="sm" onClick={() => loadWatchdog(false)} icon={<RefreshCw className="w-3.5 h-3.5" />}>
              刷新
            </Button>
            <Button size="sm" variant="ghost" onClick={onOpenEventsLog}>
              完整事件日志
            </Button>
          </>
        }
      />

      {dm?.versionMismatch && (
        <div
          className="console-card rounded-2xl p-4 flex flex-wrap items-center justify-between gap-3 border"
          style={{
            borderColor: 'var(--status-warn)',
            backgroundColor: 'var(--status-warn-soft)',
          }}
        >
          <div className="text-xs sm:text-sm">
            <div className="font-semibold text-primary">检测到看门狗进程仍运行旧版本二进制</div>
            <div className="text-secondary mt-0.5">
              平滑重启守护进程即可热加载最新代码与磁盘配置（{dm.daemonVersion ? `v${dm.daemonVersion} → ` : ''}v
              {String(dm.singctlVersion || '').replace(/^v/, '')}），全程零断网。
            </div>
          </div>
          <Button size="sm" variant="primary" disabled={busy} onClick={() => onAction('dm-restart')}>
            立即平滑重启
          </Button>
        </div>
      )}

      {healthRes && (
        <div
          className="console-card rounded-2xl p-3.5 text-xs sm:text-sm border animate-sc-in"
          style={{
            borderColor: healthRes.healthy ? 'var(--status-ok)' : 'var(--status-danger)',
            backgroundColor: healthRes.healthy ? 'var(--status-ok-soft)' : 'var(--status-danger-soft)',
          }}
        >
          <span className="font-semibold text-primary">
            {healthRes.healthy ? '✓ 健康 — ' : '✗ 异常 — '}
          </span>
          <span className="text-secondary">{healthRes.details || healthRes.failedReason}</span>
          <span className="text-[11px] font-mono text-muted ml-2 tnum">({healthRes.checkTime})</span>
        </div>
      )}

      {/* Top 2 Cards: Daemon Console & 5-Layer Defense */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <SectionCard
          title="守护进程控制台"
          icon={<Dog className="w-4 h-4" />}
          actions={
            <div className="flex items-center gap-2">
              {dm?.running ? (
                <>
                  <Button size="xs" disabled={busy} onClick={() => onAction('dm-restart')}>
                    平滑重启
                  </Button>
                  <Button
                    size="xs"
                    variant="danger"
                    disabled={busy}
                    onClick={() => onAction('dm-stop', {}, '确认停止看门狗守护进程？')}
                  >
                    停止
                  </Button>
                </>
              ) : (
                <Button size="xs" variant="primary" disabled={busy} onClick={() => onAction('dm-start')}>
                  启动守护
                </Button>
              )}
            </div>
          }
        >
          <div className="divide-y divide-[var(--border-subtle)] text-xs sm:text-sm">
            <div className="flex items-center justify-between py-2.5 gap-3">
              <span className="text-secondary">进程状态</span>
              <span className="font-mono text-primary tnum">
                {dm?.running ? `运行中 (PID ${dm.pid || '-'}${dm.daemonVersion ? ` · v${dm.daemonVersion.replace(/^v/, '')}` : ''})` : '未运行'}
              </span>
            </div>
            <div className="flex items-center justify-between py-2.5 gap-3">
              <span className="text-secondary">上次健康巡检</span>
              <span className="font-mono text-primary tnum text-right">
                {rt?.lastHealthAt
                  ? `${rt.lastHealthOK ? '✓ 正常' : '✗ 异常'}${rt.lastHealthDelayMs ? ` (${rt.lastHealthDelayMs}ms)` : ''} · ${rt.lastHealthAt}`
                  : '等待首轮巡检'}
              </span>
            </div>
            <div className="flex items-center justify-between py-2.5 gap-3">
              <span className="text-secondary">熔断与重启统计</span>
              <span className="font-mono text-primary tnum">
                1h: {dm?.restarts || 0}/{dm?.maxRestarts || 3} · 累计: {dm?.totalRestarts || 0} 次
              </span>
            </div>
            <div className="flex items-center justify-between py-2.5 gap-3">
              <span className="text-secondary">守护日志占用</span>
              <span className="font-mono text-muted truncate max-w-[260px] tnum" title={dm?.logPath}>
                {fmtKB(dm?.logSizeBytes || 0)} / {fmtKB(dm?.logMaxBytes || 524288)}
              </span>
            </div>
          </div>
        </SectionCard>

        <SectionCard title="五大自愈防线" icon={<ShieldCheck className="w-4 h-4" />} subtitle="7×24 全自动无人值守保护">
          <div className="space-y-2.5">
            {[
              {
                title: '① 进程与内部 DNS 自愈',
                desc: `每 ${cfg?.interval || 180}s 检测进程与解析，异常 ${cfg?.confirm_wait || 30}s 复核拉起`,
                badge: dm?.running ? <Badge tone="ok">守护中</Badge> : <Badge>未运行</Badge>,
              },
              {
                title: '② 策略组自动故障切换',
                desc: cfg?.failover.enabled
                  ? `每 ${cfg.failover.patrol_interval || 30}s 巡检 ${(cfg.failover.groups || DEFAULT_FO_GROUPS).length} 组 · 复测 ${cfg.failover.confirm_retries ?? 1} 次`
                  : '已手动关闭策略组节点容灾切换',
                badge: !cfg?.failover.enabled ? (
                  <Badge>已关闭</Badge>
                ) : activeFO.length > 0 ? (
                  <Badge tone="warn">{activeFO.length} 组容灾中</Badge>
                ) : (
                  <Badge tone={dm?.running ? 'ok' : 'neutral'}>{dm?.running ? '巡检中' : '待启动'}</Badge>
                ),
              },
              {
                title: '③ 订阅节点无感热同步',
                desc: cfg?.sub_sync_enabled
                  ? `每 ${Math.round((cfg.sub_sync_interval || 600) / 60)} 分钟静默比对订阅并 SIGHUP 重载`
                  : '已关闭后台订阅自动同步',
                badge: !cfg?.sub_sync_enabled ? <Badge>已关闭</Badge> : <Badge tone={dm?.running ? 'ok' : 'neutral'}>{dm?.running ? '已启用' : '待启动'}</Badge>,
              },
              {
                title: '④ 规则集 (.srs) 静默刷新',
                desc: `每 24 小时校准本地规则集${rt?.lastRuleSetAt ? ` · 上次: ${rt.lastRuleSetAt}` : ''}`,
                badge: <Badge tone={dm?.running ? 'ok' : 'neutral'}>{dm?.running ? '定时守护' : '待启动'}</Badge>,
              },
              {
                title: '⑤ 本地 AdGuard DNS 保活',
                desc: agh?.supported ? '联动巡检 53 端口解析器，异常自动重启' : '当前非 Linux 网关，自动跳过',
                badge: !agh?.supported ? (
                  <Badge>仅 Linux</Badge>
                ) : !agh.enabled ? (
                  <Badge>已禁用</Badge>
                ) : agh.healthy ? (
                  <Badge tone="ok">健康</Badge>
                ) : (
                  <Badge tone="warn">待自愈</Badge>
                ),
              },
            ].map((item) => (
              <div
                key={item.title}
                className="flex items-center justify-between gap-3 px-3 py-2 rounded-xl bg-surface2"
              >
                <div className="min-w-0">
                  <div className="text-xs font-semibold text-primary">{item.title}</div>
                  <div className="text-[11px] text-secondary truncate">{item.desc}</div>
                </div>
                {item.badge}
              </div>
            ))}
          </div>
        </SectionCard>
      </div>

      {/* Group Failover Config Card */}
      <SectionCard
        title="策略组自动故障切换（容灾自愈）"
        icon={<GitBranch className="w-4 h-4" />}
        badge={
          <Badge tone={!foEnabled ? 'neutral' : activeFO.length > 0 ? 'warn' : 'ok'}>
            {!foEnabled ? '已关闭' : activeFO.length > 0 ? `${activeFO.length} 组接管中` : '默认开启'}
          </Badge>
        }
        actions={
          <div className="flex items-center gap-3 flex-wrap">
            <label className="inline-flex items-center gap-2 cursor-pointer text-xs font-medium text-primary select-none">
              <input
                type="checkbox"
                checked={foEnabled}
                onChange={(e) => void handleToggleFailover(e.target.checked)}
                className="w-4 h-4 accent-[var(--accent)]"
              />
              <span>{foEnabled ? '已开启故障切换' : '已关闭故障切换'}</span>
            </label>
            <Button size="xs" loading={patrolling} onClick={handleImmediatePatrol} icon={<Zap className="w-3 h-3" />}>
              立即巡检线路
            </Button>
          </div>
        }
      >
        <div className="space-y-4">
          {activeFO.length > 0 && (
            <div
              className="p-3.5 rounded-xl border text-xs space-y-1"
              style={{
                borderColor: 'var(--status-warn)',
                backgroundColor: 'var(--status-warn-soft)',
              }}
            >
              <div className="font-semibold text-primary">
                当前有 {activeFO.length} 个策略组正由备用健康节点容灾接管：
              </div>
              {activeFO.map((item) => (
                <div key={item.group} className="text-secondary font-mono tnum">
                  • <strong>{item.group}</strong>：{item.origin} → {item.current}
                  {item.lastDelayMs ? ` (${item.lastDelayMs}ms)` : ''}
                  {item.since ? ` · ${item.since}` : ''}
                </div>
              ))}
            </div>
          )}

          <div className={foEnabled ? 'space-y-4' : 'space-y-4 opacity-50 pointer-events-none'}>
            {/* Chips */}
            <div className="space-y-2.5">
              <div className="flex items-center justify-between gap-2 flex-wrap">
                <span className="text-xs font-semibold text-primary">
                  受保护策略组（已启用 {selectedGroups.length} 个）
                </span>
                <Button
                  size="xs"
                  variant="ghost"
                  onClick={() => {
                    setSelectedGroups([...DEFAULT_FO_GROUPS]);
                    setDirty(true);
                  }}
                >
                  恢复默认分组
                </Button>
              </div>
              <div className="flex flex-wrap gap-2">
                {orderedGroupNames.map((name) => {
                  const sel = selectedGroups.includes(name);
                  const live = liveGroupMap.get(name);
                  return (
                    <button
                      key={name}
                      type="button"
                      onClick={() => toggleGroupChip(name)}
                      style={
                        sel
                          ? {
                              backgroundColor: 'var(--accent-soft)',
                              borderColor: 'var(--accent)',
                              color: 'var(--accent)',
                            }
                          : undefined
                      }
                      className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-xs font-medium border transition-colors cursor-pointer ${
                        sel ? '' : 'bg-surface2 border-subtle text-secondary hover:text-primary'
                      }`}
                    >
                      <span>{sel ? '✓' : '+'}</span>
                      <span>{name}</span>
                      {live?.now && <span className="text-[11px] opacity-75 font-mono">→ {live.now}</span>}
                      {live?.failedOver && <Badge tone="warn">容灾中</Badge>}
                    </button>
                  );
                })}
              </div>
              <div className="flex gap-2 max-w-md">
                <input
                  type="text"
                  value={customGroupInput}
                  onChange={(e) => setCustomGroupInput(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter') {
                      e.preventDefault();
                      addCustomGroup();
                    }
                  }}
                  placeholder="自定义 Selector 组名（如 Streaming / Telegram）"
                  className="flex-1 h-8 px-3 rounded-lg bg-surface2 border border-subtle text-xs text-primary focus:outline-none focus:border-strong"
                />
                <Button size="xs" onClick={addCustomGroup}>
                  添加分组
                </Button>
              </div>
            </div>

            {/* Sensitivity Grid */}
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3.5">
              <label className="block space-y-1 text-xs">
                <span className="text-secondary">巡检间隔（秒，默认 30）</span>
                <input
                  type="number"
                  min={10}
                  max={3600}
                  step={5}
                  value={patrolInterval}
                  onChange={(e) => {
                    setPatrolInterval(Number(e.target.value));
                    setDirty(true);
                  }}
                  className="w-full h-9 px-3 rounded-xl bg-surface2 border border-subtle text-primary font-mono tnum focus:outline-none focus:border-strong"
                />
              </label>

              <label className="block space-y-1 text-xs">
                <span className="text-secondary">单次探测超时（毫秒，默认 2800）</span>
                <input
                  type="number"
                  min={500}
                  max={15000}
                  step={100}
                  value={probeTimeoutMs}
                  onChange={(e) => {
                    setProbeTimeoutMs(Number(e.target.value));
                    setDirty(true);
                  }}
                  className="w-full h-9 px-3 rounded-xl bg-surface2 border border-subtle text-primary font-mono tnum focus:outline-none focus:border-strong"
                />
              </label>

              <label className="block space-y-1 text-xs">
                <span className="text-secondary">切备前复测次数</span>
                <select
                  value={confirmRetries}
                  onChange={(e) => {
                    setConfirmRetries(Number(e.target.value));
                    setDirty(true);
                  }}
                  className="w-full h-9 px-3 rounded-xl bg-surface2 border border-subtle text-primary focus:outline-none focus:border-strong"
                >
                  <option value={0}>0 次（首次超时立即切换）</option>
                  <option value={1}>1 次（间隔 1.5s 复测确认，推荐）</option>
                  <option value={2}>2 次（连续 3 次超时才切换）</option>
                  <option value={3}>3 次（高容忍度）</option>
                </select>
              </label>

              <label className="block space-y-1 text-xs">
                <span className="text-secondary">原节点恢复自动回切</span>
                <div className="h-9 px-3 rounded-xl bg-surface2 border border-subtle flex items-center gap-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={autoFailback}
                    onChange={(e) => {
                      setAutoFailback(e.target.checked);
                      setDirty(true);
                    }}
                    className="accent-[var(--accent)]"
                  />
                  <span className="text-primary">{autoFailback ? '自动切回稳定主节点' : '保持备用节点'}</span>
                </div>
              </label>

              <label className="block space-y-1 text-xs">
                <span className="text-secondary">回切冷却期（秒，默认 180）</span>
                <input
                  type="number"
                  min={10}
                  max={86400}
                  step={10}
                  disabled={!autoFailback}
                  value={cooldownSec}
                  onChange={(e) => {
                    setCooldownSec(Number(e.target.value));
                    setDirty(true);
                  }}
                  className="w-full h-9 px-3 rounded-xl bg-surface2 border border-subtle text-primary font-mono tnum disabled:opacity-50 focus:outline-none focus:border-strong"
                />
              </label>

              <label className="block space-y-1 text-xs">
                <span className="text-secondary">允许回切最高延迟（ms，默认 600）</span>
                <input
                  type="number"
                  min={100}
                  max={5000}
                  step={50}
                  disabled={!autoFailback}
                  value={maxFailbackDelayMs}
                  onChange={(e) => {
                    setMaxFailbackDelayMs(Number(e.target.value));
                    setDirty(true);
                  }}
                  className="w-full h-9 px-3 rounded-xl bg-surface2 border border-subtle text-primary font-mono tnum disabled:opacity-50 focus:outline-none focus:border-strong"
                />
              </label>
            </div>

            <div>
              <Button size="xs" variant="ghost" onClick={() => setShowAdvURLs((v) => !v)}>
                {showAdvURLs ? '收起探测目标 URL ▲' : '自定义探测目标 URL ▼'}
              </Button>
              {showAdvURLs && (
                <div className="mt-2 space-y-2">
                  <textarea
                    rows={3}
                    value={probeUrlsText}
                    onChange={(e) => {
                      setProbeUrlsText(e.target.value);
                      setDirty(true);
                    }}
                    className="w-full p-3 rounded-xl bg-surface2 border border-subtle font-mono text-xs text-primary focus:outline-none focus:border-strong"
                  />
                  <Button
                    size="xs"
                    onClick={() => {
                      setProbeUrlsText(DEFAULT_FO_URLS.join('\n'));
                      setDirty(true);
                    }}
                  >
                    恢复默认探测 URL
                  </Button>
                </div>
              )}
            </div>

            <div className="flex flex-wrap items-center gap-2.5 pt-2 border-t border-subtle">
              <Button variant="primary" loading={savingFO} onClick={() => saveFailover()}>
                保存故障切换配置
              </Button>
              <Button disabled={savingFO} onClick={resetAllFailover} icon={<RotateCcw className="w-3.5 h-3.5" />}>
                恢复全部默认值
              </Button>
            </div>
          </div>
        </div>
      </SectionCard>

      {/* Collapsible Basic Config */}
      <SectionCard title="基础守护与订阅热同步参数" icon={<Settings2 className="w-4 h-4" />} collapsible defaultOpen={false}>
        <div className="space-y-4">
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3.5 text-xs">
            <label className="block space-y-1">
              <span className="text-secondary">健康检查间隔（秒，默认 180）</span>
              <input
                type="number"
                min={15}
                max={86400}
                step={15}
                value={wdInterval}
                onChange={(e) => {
                  setWdInterval(Number(e.target.value));
                  setDirty(true);
                }}
                className="w-full h-9 px-3 rounded-xl bg-surface2 border border-subtle text-primary font-mono tnum"
              />
            </label>
            <label className="block space-y-1">
              <span className="text-secondary">异常二次确认等待（秒，默认 30）</span>
              <input
                type="number"
                min={5}
                max={600}
                step={5}
                value={wdConfirmWait}
                onChange={(e) => {
                  setWdConfirmWait(Number(e.target.value));
                  setDirty(true);
                }}
                className="w-full h-9 px-3 rounded-xl bg-surface2 border border-subtle text-primary font-mono tnum"
              />
            </label>
            <label className="block space-y-1">
              <span className="text-secondary">每小时最大自愈重启次数（默认 3）</span>
              <input
                type="number"
                min={1}
                max={50}
                value={wdMaxRestarts}
                onChange={(e) => {
                  setWdMaxRestarts(Number(e.target.value));
                  setDirty(true);
                }}
                className="w-full h-9 px-3 rounded-xl bg-surface2 border border-subtle text-primary font-mono tnum"
              />
            </label>
            <label className="block space-y-1">
              <span className="text-secondary">订阅无感热同步</span>
              <div className="h-9 px-3 rounded-xl bg-surface2 border border-subtle flex items-center gap-2 cursor-pointer">
                <input
                  type="checkbox"
                  checked={wdSubSyncEnabled}
                  onChange={(e) => {
                    setWdSubSyncEnabled(e.target.checked);
                    setDirty(true);
                  }}
                  className="accent-[var(--accent)]"
                />
                <span className="text-primary">后台比对并热重载节点</span>
              </div>
            </label>
            <label className="block space-y-1">
              <span className="text-secondary">订阅同步间隔（秒，默认 600）</span>
              <input
                type="number"
                min={60}
                max={86400}
                step={60}
                disabled={!wdSubSyncEnabled}
                value={wdSubSyncInterval}
                onChange={(e) => {
                  setWdSubSyncInterval(Number(e.target.value));
                  setDirty(true);
                }}
                className="w-full h-9 px-3 rounded-xl bg-surface2 border border-subtle text-primary font-mono tnum disabled:opacity-50"
              />
            </label>
          </div>
          <Button size="sm" variant="primary" loading={savingBasic} onClick={saveBasicConfig}>
            保存基础守护参数
          </Button>
        </div>
      </SectionCard>

      {/* Events Timeline */}
      <SectionCard
        title="最近看门狗与容灾事件"
        icon={<Clock className="w-4 h-4" />}
        actions={
          <Button size="xs" onClick={onOpenEventsLog}>
            查看完整日志
          </Button>
        }
      >
        {events.length === 0 ? (
          <div className="py-6 text-center text-xs text-muted">近期运行平稳，暂无故障切备或异常自愈事件</div>
        ) : (
          <div className="divide-y divide-[var(--border-subtle)] text-xs">
            {events.map((ev, i) => {
              const tone =
                ev.action === 'GROUP_FAILOVER' || !ev.healthy
                  ? 'warn'
                  : ev.action === 'CHECK_FAIL' || ev.action === 'RESTART_FAIL' || ev.action === 'CIRCUIT_BREAK' || ev.action === 'SKIP_RESTART'
                  ? 'danger'
                  : ev.action === 'SUB_SYNC' || ev.action === 'RULESET' || ev.action === 'RULESET_REFRESH'
                  ? 'accent'
                  : 'ok';
              return (
                <div key={i} className="flex flex-wrap items-center gap-2.5 py-2.5">
                  <span className="font-mono text-muted tnum shrink-0">{ev.time || '-'}</span>
                  <Badge tone={tone}>{ev.action || '事件'}</Badge>
                  <span className="text-primary break-words">{ev.summary}</span>
                </div>
              );
            })}
          </div>
        )}
      </SectionCard>
    </div>
  );
};

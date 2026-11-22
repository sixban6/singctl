import React, { useState, useEffect, useCallback, useRef } from 'react';
import { RefreshCw, Zap } from 'lucide-react';
import { Badge, Button, PageHeader, Skeleton, useToast } from '../../ui';
import { clientApi } from '../api';
import { CacheResponse, ClientHealthResponse, WatchdogReport } from '../types';
import {
  WatchdogBasicConfigCard,
  WatchdogFailoverCard,
} from './watchdog/WatchdogFailoverCard';
import { DEFAULT_FO_GROUPS, DEFAULT_FO_URLS, parseClampedInt } from './watchdog/watchdogHelpers';
import {
  WatchdogEventsTimelineCard,
  WatchdogTopCards,
} from './watchdog/WatchdogOverviewCards';

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
  const [cacheSummary, setCacheSummary] = useState<CacheResponse | null>(null);

  // Failover form state
  const [foEnabled, setFoEnabled] = useState(true);
  const [selectedGroups, setSelectedGroups] = useState<string[]>(DEFAULT_FO_GROUPS);
  const [patrolInterval, setPatrolInterval] = useState('300');
  const [probeTimeoutMs, setProbeTimeoutMs] = useState('5000');
  const [confirmRetries, setConfirmRetries] = useState(2);
  const [autoFailback, setAutoFailback] = useState(true);
  const [cooldownSec, setCooldownSec] = useState('180');
  const [maxFailbackDelayMs, setMaxFailbackDelayMs] = useState('600');
  const [probeUrlsText, setProbeUrlsText] = useState(DEFAULT_FO_URLS.join('\n'));

  // Basic watchdog form state
  const [wdInterval, setWdInterval] = useState('180');
  const [wdConfirmWait, setWdConfirmWait] = useState('30');
  const [wdMaxRestarts, setWdMaxRestarts] = useState('3');
  const [wdSubSyncEnabled, setWdSubSyncEnabled] = useState(true);
  const [wdSubSyncInterval, setWdSubSyncInterval] = useState('600');

  const [dirty, setDirty] = useState(false);
  const dirtyRef = useRef(false);
  const markDirty = useCallback((next: boolean) => {
    dirtyRef.current = next;
    setDirty(next);
  }, []);

  const applyReport = useCallback(
    (data: WatchdogReport, preserveForm: boolean) => {
      setReport(data);
      const cfg = data.config;
      const fo = cfg.failover;
      if (!preserveForm || !dirtyRef.current) {
        setFoEnabled(fo.enabled !== false);
        setSelectedGroups(fo.groups?.length ? [...fo.groups] : [...DEFAULT_FO_GROUPS]);
        setPatrolInterval(String(fo.patrol_interval || 300));
        setProbeTimeoutMs(String(fo.probe_timeout_ms || 5000));
        setConfirmRetries(fo.confirm_retries ?? 2);
        setAutoFailback(fo.auto_failback !== false);
        setCooldownSec(String(fo.failback_cooldown || 180));
        setMaxFailbackDelayMs(String(fo.max_failback_delay_ms || 600));
        setProbeUrlsText((fo.probe_urls?.length ? fo.probe_urls : DEFAULT_FO_URLS).join('\n'));

        setWdInterval(String(cfg.interval || 180));
        setWdConfirmWait(String(cfg.confirm_wait || 30));
        setWdMaxRestarts(String(cfg.max_restarts || 3));
        setWdSubSyncEnabled(cfg.sub_sync_enabled !== false);
        setWdSubSyncInterval(String(cfg.sub_sync_interval || 600));
        markDirty(false);
      }
    },
    [markDirty],
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

  const loadCacheSummary = useCallback(async () => {
    try {
      setCacheSummary(await clientApi.getCache());
    } catch {
      // 规则集摘要属辅助信息，失败时不阻塞看门狗主体展示
    }
  }, []);

  useEffect(() => {
    void loadWatchdog(false);
    void loadCacheSummary();
  }, [loadWatchdog, loadCacheSummary]);

  const prevBusyRef = useRef(busy);
  useEffect(() => {
    if (prevBusyRef.current && !busy) {
      void loadCacheSummary();
      void loadWatchdog(true);
    }
    prevBusyRef.current = busy;
  }, [busy, loadCacheSummary, loadWatchdog]);

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
        markDirty(true);
        return prev.filter((g) => g !== name);
      }
      markDirty(true);
      return [...prev, name];
    });
  };

  const addCustomGroup = (val: string) => {
    if (selectedGroups.includes(val)) {
      toast(`分组「${val}」已在受保护列表中`, 'info');
    } else {
      setSelectedGroups((prev) => [...prev, val]);
      markDirty(true);
      success(`已添加受保护策略组：${val}`);
    }
  };

  const saveFailover = async (overridePayload?: Record<string, unknown>) => {
    setSavingFO(true);
    try {
      const nextPatrol = parseClampedInt(patrolInterval, 300, 10, 3600);
      const nextTimeout = parseClampedInt(probeTimeoutMs, 5000, 500, 15000);
      const nextCooldown = parseClampedInt(cooldownSec, 180, 10, 86400);
      const nextMaxDelay = parseClampedInt(maxFailbackDelayMs, 600, 100, 5000);
      setPatrolInterval(String(nextPatrol));
      setProbeTimeoutMs(String(nextTimeout));
      setCooldownSec(String(nextCooldown));
      setMaxFailbackDelayMs(String(nextMaxDelay));

      const urls = probeUrlsText
        .split(/[\n,]+/)
        .map((s) => s.trim())
        .filter(Boolean);
      const failoverPayload = overridePayload || {
        enabled: foEnabled,
        groups: selectedGroups,
        has_groups: true,
        patrol_interval: nextPatrol,
        probe_timeout_ms: nextTimeout,
        confirm_retries: confirmRetries,
        auto_failback: autoFailback,
        failback_cooldown: nextCooldown,
        max_failback_delay_ms: nextMaxDelay,
        probe_urls: urls,
        has_probe_urls: true,
      };
      const res = await clientApi.updateWatchdogConfig({ failover: failoverPayload });
      markDirty(false);
      if (res.daemon || res.config) applyReport((res.report || res) as WatchdogReport, false);
      onRefreshStatus();
      success(res.message || '故障切换策略已保存并热生效');
    } catch (err: unknown) {
      error(`保存失败：${err instanceof Error ? err.message : '未知错误'}`);
    } finally {
      setSavingFO(false);
    }
  };

  const defaultGroupList = report?.config?.failover?.default_groups?.length
    ? report.config.failover.default_groups
    : DEFAULT_FO_GROUPS;

  const resetAllFailover = async () => {
    setFoEnabled(true);
    setSelectedGroups([...defaultGroupList]);
    setPatrolInterval('300');
    setProbeTimeoutMs('5000');
    setConfirmRetries(2);
    setAutoFailback(true);
    setCooldownSec('180');
    setMaxFailbackDelayMs('600');
    setProbeUrlsText(DEFAULT_FO_URLS.join('\n'));
    await saveFailover({
      enabled: true,
      groups: [...defaultGroupList],
      has_groups: true,
      patrol_interval: 300,
      probe_timeout_ms: 5000,
      confirm_retries: 2,
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
      const nextInterval = parseClampedInt(wdInterval, 180, 15, 86400);
      const nextConfirm = parseClampedInt(wdConfirmWait, 30, 5, 600);
      const nextMaxRestarts = parseClampedInt(wdMaxRestarts, 3, 1, 50);
      const nextSubSync = parseClampedInt(wdSubSyncInterval, 600, 60, 86400);
      setWdInterval(String(nextInterval));
      setWdConfirmWait(String(nextConfirm));
      setWdMaxRestarts(String(nextMaxRestarts));
      setWdSubSyncInterval(String(nextSubSync));

      const res = await clientApi.updateWatchdogConfig({
        interval: nextInterval,
        confirm_wait: nextConfirm,
        max_restarts: nextMaxRestarts,
        sub_sync_enabled: wdSubSyncEnabled,
        sub_sync_interval: nextSubSync,
      });
      markDirty(false);
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
  const rt = report?.runtime;
  const activeFO = rt?.activeFailovers || [];
  const events = [...(rt?.recentEvents || [])].reverse().slice(0, 15);
  const liveSelectors = report?.selectorGroups || [];
  const liveGroupSet = new Set(liveSelectors.map((g) => g.name));

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
            <Button size="sm" loading={healthChecking} onClick={() => void handleImmediateHealth()} icon={<Zap className="w-3.5 h-3.5" />}>
              立即健康检测
            </Button>
            <Button size="sm" onClick={() => void loadWatchdog(false)} icon={<RefreshCw className="w-3.5 h-3.5" />}>
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

      <WatchdogTopCards
        report={report}
        cacheSummary={cacheSummary}
        busy={busy}
        onAction={onAction}
      />

      <WatchdogFailoverCard
        foEnabled={foEnabled}
        activeFO={activeFO}
        patrolling={patrolling}
        savingFO={savingFO}
        dirty={dirty}
        selectedGroups={selectedGroups}
        defaultGroupList={defaultGroupList}
        liveSelectors={liveSelectors}
        patrolInterval={patrolInterval}
        setPatrolInterval={setPatrolInterval}
        probeTimeoutMs={probeTimeoutMs}
        setProbeTimeoutMs={setProbeTimeoutMs}
        confirmRetries={confirmRetries}
        setConfirmRetries={setConfirmRetries}
        autoFailback={autoFailback}
        setAutoFailback={setAutoFailback}
        cooldownSec={cooldownSec}
        setCooldownSec={setCooldownSec}
        maxFailbackDelayMs={maxFailbackDelayMs}
        setMaxFailbackDelayMs={setMaxFailbackDelayMs}
        probeUrlsText={probeUrlsText}
        setProbeUrlsText={setProbeUrlsText}
        onMarkDirty={() => markDirty(true)}
        onToggleFailover={(next) => void handleToggleFailover(next)}
        onImmediatePatrol={() => void handleImmediatePatrol()}
        onToggleGroupChip={toggleGroupChip}
        onAddCustomGroup={addCustomGroup}
        onClearStaleGroups={() => {
          setSelectedGroups((prev) => prev.filter((g) => liveGroupSet.has(g)));
          markDirty(true);
        }}
        onRestoreDefaultGroups={() => {
          setSelectedGroups([...defaultGroupList]);
          markDirty(true);
        }}
        onSaveFailover={() => void saveFailover()}
        onResetAllFailover={() => void resetAllFailover()}
      />

      <WatchdogBasicConfigCard
        wdInterval={wdInterval}
        setWdInterval={setWdInterval}
        wdConfirmWait={wdConfirmWait}
        setWdConfirmWait={setWdConfirmWait}
        wdMaxRestarts={wdMaxRestarts}
        setWdMaxRestarts={setWdMaxRestarts}
        wdSubSyncEnabled={wdSubSyncEnabled}
        setWdSubSyncEnabled={setWdSubSyncEnabled}
        wdSubSyncInterval={wdSubSyncInterval}
        setWdSubSyncInterval={setWdSubSyncInterval}
        savingBasic={savingBasic}
        onMarkDirty={() => markDirty(true)}
        onSaveBasic={() => void saveBasicConfig()}
      />

      <WatchdogEventsTimelineCard events={events} onOpenEventsLog={onOpenEventsLog} />
    </div>
  );
};

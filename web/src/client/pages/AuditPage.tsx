import React, { useState, useEffect, useCallback, useMemo, useRef } from 'react';
import {
  AlertTriangle,
  Ban,
  Bot,
  Download,
  RefreshCw,
  ShieldCheck,
} from 'lucide-react';
import { Badge, Button, ConfirmDialog, PageHeader, useToast } from '../../ui';
import {
  CLIENT_INVALIDATE_EVENT,
  ClientInvalidateScope,
  peekCachedQuery,
  useVisibilityInterval,
  writeCachedQuery,
} from '../../hooks';
import { clientApi } from '../api';
import { AUDIT_DEFAULT_CACHE_KEY } from '../cacheKeys';
import { AuditReport } from '../types';
import { AuditAIConfigDrawer } from './audit/AuditAIConfigDrawer';
import { AuditBlacklistDrawer } from './audit/AuditBlacklistDrawer';
import { AuditDevicesAndBanners } from './audit/AuditDevicesAndBanners';
import { AuditFlowDetailDrawer } from './audit/AuditFlowDetailDrawer';
import { AuditFlowsSection } from './audit/AuditFlowsSection';
import {
  AuditSortKey,
  filterAndSortAuditFlows,
  FLOW_RENDER_STEP,
  getFlowCacheKey,
} from './audit/auditHelpers';
import { useAuditActions } from './audit/useAuditActions';
import { useAuditAICache, useAuditViewportPrefetch } from './audit/useAuditAIPrefetch';

export interface AuditPageProps {
  active?: boolean;
}

export const AuditPage: React.FC<AuditPageProps> = ({ active = true }) => {
  const { error } = useToast();

  // Filters & controls
  const [deviceFilter, setDeviceFilter] = useState('');
  const [networkFilter, setNetworkFilter] = useState<'' | 'tcp' | 'udp'>('');
  const [axisFilter, setAxisFilter] = useState<'' | 'security' | 'privacy'>('');
  const [onlySuspect, setOnlySuspect] = useState(false);
  const [onlyActive, setOnlyActive] = useState(true);
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [sortBy, setSortBy] = useState<AuditSortKey>('active');
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

  // Concurrency guards for auto refresh
  const actionInFlightRef = useRef(0);
  const pointerDownUntilRef = useRef(0);

  // Drawers
  const [blockDrawerOpen, setBlockDrawerOpen] = useState(false);
  const [aiCfgOpen, setAiCfgOpen] = useState(false);
  const [detailFlowKey, setDetailFlowKey] = useState<string | null>(null);
  const [pcdnBannerDismissed, setPcdnBannerDismissed] = useState(false);

  const tableContainerRef = useRef<HTMLDivElement>(null);
  const flowScrollRef = useRef<HTMLDivElement>(null);

  const {
    aiEnabled,
    handleToggleAI,
    setCachedReview,
    getCachedReview,
    flushCachedReviews,
    pendingTargets: singlePendingTargets,
    reviewSingleFlow,
  } = useAuditAICache();

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

      const qs = new URLSearchParams();
      if (onlySuspect) qs.set('suspicious', '1');
      if (sortBy) qs.set('sort', sortBy);
      if (sortDir) qs.set('dir', sortDir);
      const isDefaultQuery = !onlySuspect && sortBy === 'active' && sortDir === 'desc';

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
        if (synced) flushCachedReviews();
        hasLoadedReportRef.current = true;
        if (isDefaultQuery) {
          writeCachedQuery(AUDIT_DEFAULT_CACHE_KEY, rep);
        }
        setReport(rep);
        setLastUpdated(new Date().toLocaleTimeString());
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
    [onlySuspect, sortBy, sortDir, setCachedReview, flushCachedReviews, error],
  );

  useEffect(() => {
    void loadAudit(hasLoadedReportRef.current && !onlySuspect && sortBy === 'active' && sortDir === 'desc');
    return () => {
      abortCtrlRef.current?.abort();
    };
  }, [loadAudit, onlySuspect, sortBy, sortDir]);

  const prevActiveRef = useRef<boolean>(active);
  useEffect(() => {
    const becameActive = !prevActiveRef.current && active;
    prevActiveRef.current = active;
    if (becameActive) {
      void loadAudit(true);
    }
  }, [active, loadAudit]);

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

  useVisibilityInterval(
    () => {
      void loadAudit(true);
    },
    active && autoRefresh ? 5000 : null,
  );

  const {
    blockBusy,
    pcdnToggleBusy,
    throttleBusy,
    busyFlowKeys,
    closingAll,
    closeAllConfirmOpen,
    setCloseAllConfirmOpen,
    subnetBlockConfirm,
    setSubnetBlockConfirm,
    subnetBlocking,
    handleBlockFlow,
    handleManualBlock,
    handleConfirmSubnetBlock,
    handleUnblock,
    handleWhitelist,
    handleTogglePCDNBlock,
    handleSetThrottle,
    handleCloseFlowConnections,
    handleCloseAllConnections,
    handleExportCSV,
  } = useAuditActions({
    report,
    deviceFilter,
    onlySuspect,
    sortBy,
    sortDir,
    detailFlowKey,
    setDetailFlowKey,
    setPcdnBannerDismissed,
    actionInFlightRef,
    loadAudit,
  });

  const processedFlows = useMemo(
    () =>
      filterAndSortAuditFlows(report, {
        deviceFilter,
        networkFilter,
        onlyActive,
        axisFilter,
        sortBy,
        sortDir,
        getCachedReview,
      }),
    [report, deviceFilter, networkFilter, onlyActive, axisFilter, sortBy, sortDir, getCachedReview],
  );

  const activeFlowCount = useMemo(
    () => processedFlows.reduce((acc, f) => acc + ((f.activeConns || 0) > 0 ? 1 : 0), 0),
    [processedFlows],
  );

  useEffect(() => {
    setVisibleLimit(FLOW_RENDER_STEP);
    if (flowScrollRef.current) {
      flowScrollRef.current.scrollTop = 0;
    }
  }, [deviceFilter, networkFilter, onlyActive, axisFilter, onlySuspect, sortBy, sortDir]);

  const visibleFlows = useMemo(
    () => processedFlows.slice(0, visibleLimit),
    [processedFlows, visibleLimit],
  );

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

  const { pendingPrefetchTargets, prefetchStatusText } = useAuditViewportPrefetch({
    active,
    aiEnabled,
    processedFlows,
    visibleFlowsCount: visibleFlows.length,
    lastUpdated,
    flowScrollRef,
    tableContainerRef,
    getCachedReview,
    setCachedReview,
    flushCachedReviews,
  });

  const mergedPendingTargets = useMemo(() => {
    if (singlePendingTargets.size === 0) return pendingPrefetchTargets;
    if (pendingPrefetchTargets.size === 0) return singlePendingTargets;
    const merged = new Set(pendingPrefetchTargets);
    singlePendingTargets.forEach((t) => merged.add(t));
    return merged;
  }, [singlePendingTargets, pendingPrefetchTargets]);

  const handleSort = (key: string) => {
    const k = key as AuditSortKey;
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

  const blockCount = report?.blockedCount ?? report?.blockRules?.length ?? 0;
  const whitelist = report?.whitelist || [];
  const whitelistCount = report?.whitelistCount ?? whitelist.length;
  const pcdnOn = report?.pcdnBlockEnabled ?? true;

  const detailFlow = useMemo(
    () => processedFlows.find((f) => getFlowCacheKey(f) === detailFlowKey) || null,
    [processedFlows, detailFlowKey],
  );

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
          prefetchStatusText ? (
            <Badge tone="accent" dot>
              AI {prefetchStatusText}
            </Badge>
          ) : null
        }
        actions={
          <div className="flex flex-wrap items-center gap-2">
            <Button
              size="sm"
              variant="secondary"
              loading={pcdnToggleBusy}
              icon={
                pcdnOn ? (
                  <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
                ) : (
                  <AlertTriangle className="w-3.5 h-3.5 text-amber-400" />
                )
              }
              className={
                pcdnOn
                  ? 'border-emerald-500/35 bg-emerald-500/10 text-emerald-300 hover:bg-emerald-500/20'
                  : 'border-amber-500/35 bg-amber-500/10 text-amber-300 hover:bg-amber-500/20'
              }
              title={`内置精校防 PCDN 规则集（${report?.pcdnRuleCount || 0} 组调度与拉流域名），点击切换开关`}
              onClick={() => void handleTogglePCDNBlock(!pcdnOn)}
            >
              {pcdnOn ? '防 PCDN: 已开启' : '防 PCDN: 已关闭'}
            </Button>
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
              onClick={() => setAiCfgOpen(true)}
            >
              AI 网关配置
            </Button>
            <Button
              size="sm"
              variant="secondary"
              icon={<Download className="w-3.5 h-3.5" />}
              onClick={() => void handleExportCSV()}
            >
              导出 CSV
            </Button>
            <Button
              size="sm"
              variant="primary"
              icon={<RefreshCw className={`w-3.5 h-3.5 ${loading || refreshing ? 'animate-spin' : ''}`} />}
              onClick={() => void loadAudit(false)}
            >
              刷新
            </Button>
          </div>
        }
      />

      <AuditDevicesAndBanners
        report={report}
        loading={loading}
        deviceFilter={deviceFilter}
        onDeviceFilterChange={setDeviceFilter}
        networkFilter={networkFilter}
        onNetworkFilterChange={setNetworkFilter}
        axisFilter={axisFilter}
        onAxisFilterChange={setAxisFilter}
        onlyActive={onlyActive}
        onOnlyActiveChange={setOnlyActive}
        onlySuspect={onlySuspect}
        onOnlySuspectChange={setOnlySuspect}
        autoRefresh={autoRefresh}
        onAutoRefreshChange={setAutoRefresh}
        aiEnabled={aiEnabled}
        onToggleAI={handleToggleAI}
        pcdnToggleBusy={pcdnToggleBusy}
        pcdnBannerDismissed={pcdnBannerDismissed}
        onDismissPcdnBanner={() => setPcdnBannerDismissed(true)}
        onEnablePCDNBlock={() => void handleTogglePCDNBlock(true)}
      />

      <AuditFlowsSection
        report={report}
        processedFlows={processedFlows}
        visibleFlows={visibleFlows}
        activeFlowCount={activeFlowCount}
        loading={loading}
        onlyActive={onlyActive}
        filterTransitioning={filterTransitioning}
        closingAll={closingAll}
        sortBy={sortBy}
        sortDir={sortDir}
        busyFlowKeys={busyFlowKeys}
        pendingTargets={mergedPendingTargets}
        tableContainerRef={tableContainerRef}
        flowScrollRef={flowScrollRef}
        onTableScroll={handleFlowTableScroll}
        onSort={handleSort}
        onExpandAllVisible={() => setVisibleLimit(processedFlows.length)}
        onSelectFlowDetail={setDetailFlowKey}
        onOpenCloseAllConfirm={() => setCloseAllConfirmOpen(true)}
        onMarkPointerInteraction={() => {
          pointerDownUntilRef.current = Date.now() + 1200;
        }}
        getCachedReview={getCachedReview}
        onReviewSingleFlow={(f, force) => void reviewSingleFlow(f, force)}
        onCloseFlowConnections={(f) => void handleCloseFlowConnections(f)}
        onWhitelistAdd={(target) => void handleWhitelist('add', target)}
        onBlockFlow={(f) => void handleBlockFlow(f)}
      />

      <AuditBlacklistDrawer
        open={blockDrawerOpen}
        blockRules={report?.blockRules || []}
        whitelist={whitelist}
        blockBusy={blockBusy}
        onClose={() => setBlockDrawerOpen(false)}
        onManualBlock={handleManualBlock}
        onUnblock={(r) => void handleUnblock(r)}
        onWhitelist={handleWhitelist}
      />

      <AuditAIConfigDrawer open={aiCfgOpen} onClose={() => setAiCfgOpen(false)} />

      <AuditFlowDetailDrawer
        detailFlow={detailFlow}
        throttleBusy={throttleBusy}
        getCachedReview={getCachedReview}
        onClose={() => setDetailFlowKey(null)}
        onReviewSingleFlow={(f, force) => void reviewSingleFlow(f, force)}
        onCloseFlowConnections={(f) => void handleCloseFlowConnections(f)}
        onWhitelistAdd={(target) => void handleWhitelist('add', target)}
        onBlockFlow={(f, deviceOnly) => void handleBlockFlow(f, deviceOnly)}
        onSetThrottle={(f, rate) => void handleSetThrottle(f, rate)}
        onFilterBySubnet={(cidr) => {
          setDeviceFilter(cidr);
          setDetailFlowKey(null);
        }}
        onRequestSubnetBlock={setSubnetBlockConfirm}
      />

      <ConfirmDialog
        open={closeAllConfirmOpen}
        title="断开全部活跃连接"
        description="确认立即断开当前所有活跃连接？正在加载的网页或下载会瞬时重新握手并自动应用最新选路/分组规则，不会拉黑任何域名。"
        confirmText="确认断开"
        loading={closingAll}
        onConfirm={() => void handleCloseAllConnections()}
        onCancel={() => setCloseAllConfirmOpen(false)}
      />

      <ConfirmDialog
        open={Boolean(subnetBlockConfirm)}
        title={
          subnetBlockConfirm
            ? `仅针对设备封禁网段 ${subnetBlockConfirm.cidr}`
            : '确认按设备封禁网段'
        }
        description={
          subnetBlockConfirm ? (
            <div className="space-y-2 text-xs leading-relaxed">
              <p>
                将向 <span className="font-mono font-semibold text-primary">{subnetBlockConfirm.cidr}</span> 添加路由{' '}
                <code>reject</code> 规则，且<strong>仅作用于来源设备</strong>{' '}
                <span className="font-semibold text-primary">
                  {subnetBlockConfirm.deviceLabel} ({subnetBlockConfirm.sourceIp})
                </span>
                ，不会影响局域网内其他设备，并立即断开该设备落入此网段的活跃连接。
              </p>
              <p className="text-amber-300/90">
                提示：若目标网段属于云厂商 / CDN 共享 IP 池，可能影响该设备访问同网段下的其他业务；如有误伤，可随时在「规则黑名单」中一键解除。
              </p>
            </div>
          ) : (
            ''
          )
        }
        confirmText="确认按设备封禁网段"
        loading={subnetBlocking}
        onConfirm={() => void handleConfirmSubnetBlock()}
        onCancel={() => setSubnetBlockConfirm(null)}
      />
    </div>
  );
};

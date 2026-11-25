import React, { useMemo, useState } from 'react';
import {
  AlertTriangle,
  Ban,
  Bot,
  Download,
  RefreshCw,
  ShieldCheck,
} from 'lucide-react';
import { Badge, Button, ConfirmDialog, PageHeader, useToast } from '../../ui';
import { clientApi } from '../api';
import { AuditDeviceSummary, ClientStatusResponse, HomeDomainDeviceUpsertPayload } from '../types';
import { DeviceEditDrawer, DeviceEditInitial } from './network/homedomain/DeviceEditDrawer';
import { AuditAIConfigDrawer } from './audit/AuditAIConfigDrawer';
import { AuditBlacklistDrawer } from './audit/AuditBlacklistDrawer';
import { AuditDevicesAndBanners } from './audit/AuditDevicesAndBanners';
import { AuditFlowDetailDrawer } from './audit/AuditFlowDetailDrawer';
import { AuditFlowsSection } from './audit/AuditFlowsSection';
import { AuditSelectedDevice } from './audit/auditFlowModel';
import { getFlowCacheKey } from './audit/auditHelpers';
import { useAuditActions } from './audit/useAuditActions';
import { useAuditAICache, useAuditViewportPrefetch } from './audit/useAuditAIPrefetch';
import { useAuditFlowsController } from './audit/useAuditFlowsController';

export interface AuditPageProps {
  active?: boolean;
  status?: ClientStatusResponse | null;
  onRefreshStatus?: () => void;
}

export const AuditPage: React.FC<AuditPageProps> = ({
  active = true,
  status,
}) => {
  const { success, error } = useToast();
  const [blockDrawerOpen, setBlockDrawerOpen] = useState(false);
  const [aiCfgOpen, setAiCfgOpen] = useState(false);
  const [pcdnBannerDismissed, setPcdnBannerDismissed] = useState(false);
  const [renameDrawerOpen, setRenameDrawerOpen] = useState(false);
  const [renameInit, setRenameInit] = useState<DeviceEditInitial | null>(null);
  const [renameSuffix, setRenameSuffix] = useState('home');
  const [renameSaving, setRenameSaving] = useState(false);

  const {
    aiEnabled,
    handleToggleAI,
    setCachedReview,
    getCachedReview,
    flushCachedReviews,
    pendingTargets: singlePendingTargets,
    reviewSingleFlow,
    reviewBatchFlows,
  } = useAuditAICache();

  const ctrl = useAuditFlowsController({
    active,
    drawerBlockingRefresh: blockDrawerOpen || aiCfgOpen || renameDrawerOpen,
    setCachedReview,
    getCachedReview,
    flushCachedReviews,
  });

  const actions = useAuditActions({
    report: ctrl.report,
    searchQuery: ctrl.searchQuery,
    selectedDevice: ctrl.selectedDevice,
    onlySuspect: ctrl.preset === 'actionable',
    sortBy: ctrl.sortBy,
    sortDir: ctrl.sortDir,
    detailFlowKey: ctrl.detailFlowKey,
    setDetailFlowKey: ctrl.setDetailFlowKey,
    setPcdnBannerDismissed,
    actionInFlightRef: ctrl.actionInFlightRef,
    loadAudit: ctrl.loadAudit,
  });

  const { pendingPrefetchTargets, prefetchStatusText } = useAuditViewportPrefetch({
    active,
    aiEnabled,
    processedFlows: ctrl.processedFlows,
    visibleFlowsCount: ctrl.visibleFlows.length,
    lastUpdated: ctrl.lastUpdated,
    flowScrollRef: ctrl.flowScrollRef,
    tableContainerRef: ctrl.tableContainerRef,
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

  const handleSelectDeviceFromRanking = (dev: AuditSelectedDevice | null) => {
    ctrl.setSelectedDevice(dev);
    if (dev) {
      ctrl.sectionAnchorRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
  };

  const handleOpenRenameDevice = async (dev: AuditDeviceSummary) => {
    let suffix = renameSuffix;
    let existingAlias: string | undefined;
    let existingDisplay = dev.deviceName && dev.deviceName !== dev.deviceIp ? dev.deviceName : '';
    let existingWildcard = false;
    let existingServices = undefined;
    try {
      const hd = await clientApi.getHomeDomain();
      suffix = hd.suffix || 'home';
      setRenameSuffix(suffix);
      const macNorm = (dev.deviceMac || '').trim().toLowerCase();
      const matched = hd.devices.find(
        (x) =>
          (macNorm && (x.mac || '').trim().toLowerCase() === macNorm) || x.ip === dev.deviceIp,
      );
      if (matched) {
        existingAlias = matched.alias;
        existingDisplay = matched.displayName || existingDisplay;
        existingWildcard = Boolean(matched.wildcard);
        existingServices = matched.services;
      }
    } catch {
      // ignore prefill lookup failure; fallback to basic LAN prefill
    }
    const cleanSuggested = (existingAlias || dev.deviceName || '')
      .toLowerCase()
      .replace(/\.[^.]+$/, '')
      .replace(/[^a-z0-9-]+/g, '-')
      .replace(/^-+|-+$/g, '');
    setRenameInit({
      originalAlias: existingAlias,
      alias: existingAlias || cleanSuggested,
      displayName: existingDisplay.replace(/\s*\([^)]+\)\s*$/, ''),
      ip: dev.deviceIp,
      mac: dev.deviceMac || '',
      source: 'lan',
      wildcard: existingWildcard,
      services: existingServices,
    });
    setRenameDrawerOpen(true);
  };

  const handleSubmitRenameDevice = async (payload: HomeDomainDeviceUpsertPayload): Promise<boolean> => {
    setRenameSaving(true);
    try {
      const res = await clientApi.upsertHomeDomainDevice(payload);
      success(`已绑定 ${payload.alias}.${res.suffix}，审计页设备名将立即更新`);
      void ctrl.loadAudit(false);
      return true;
    } catch (err) {
      error((err as Error)?.message || '保存设备昵称失败');
      return false;
    } finally {
      setRenameSaving(false);
    }
  };

  const blockCount = ctrl.report?.blockedCount ?? ctrl.report?.blockRules?.length ?? 0;
  const whitelist = ctrl.report?.whitelist || [];
  const whitelistCount = ctrl.report?.whitelistCount ?? whitelist.length;
  const pcdnOn = ctrl.report?.pcdnBlockEnabled ?? true;
  const isAuditOnlyMode = status?.gateway?.effectiveWorkMode === 'audit';
  const isDelegatedMode = status?.gateway?.effectiveWorkMode === 'delegated';
  const sideRouterIP = status?.gateway?.sideRouterIP?.trim() || '';

  return (
    <div className="space-y-5">
      <PageHeader
        title="设备行为审计与智能封禁"
        description={
          ctrl.report
            ? `总流 ${ctrl.report.totalFlows || 0} 条 · 活跃 ${ctrl.totalActiveFlows} 条 · 待关注 ${ctrl.report.suspiciousFlows || 0} 条 · 已封禁 ${blockCount} 条${
                whitelistCount > 0 ? ` · 已放行 ${whitelistCount} 条` : ''
              }${ctrl.lastUpdated ? ` · 更新于 ${ctrl.lastUpdated}` : ''}`
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
              loading={actions.pcdnToggleBusy}
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
              title={`内置精校防 PCDN 规则集（${ctrl.report?.pcdnRuleCount || 0} 组调度与拉流域名），点击切换开关`}
              onClick={() => void actions.handleTogglePCDNBlock(!pcdnOn)}
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
              onClick={() => void actions.handleExportCSV()}
            >
              导出 CSV
            </Button>
            <Button
              size="sm"
              variant="primary"
              icon={
                <RefreshCw
                  className={`w-3.5 h-3.5 ${ctrl.loading || ctrl.refreshing ? 'animate-spin' : ''}`}
                />
              }
              onClick={() => void ctrl.loadAudit(false)}
            >
              刷新
            </Button>
          </div>
        }
      />

      <AuditDevicesAndBanners
        report={ctrl.report}
        loading={ctrl.loading}
        selectedDevice={ctrl.selectedDevice}
        onSelectDevice={handleSelectDeviceFromRanking}
        onRenameDevice={(d) => void handleOpenRenameDevice(d)}
        isAuditOnlyMode={isAuditOnlyMode}
        isDelegatedMode={isDelegatedMode}
        sideRouterIP={sideRouterIP}
        busyDeviceIps={actions.busyDeviceIps}
        onToggleDeviceOverseas={(d, next) => void actions.handleToggleDeviceOverseas(d, next)}
        pcdnToggleBusy={actions.pcdnToggleBusy}
        pcdnBannerDismissed={pcdnBannerDismissed}
        onDismissPcdnBanner={() => setPcdnBannerDismissed(true)}
        onEnablePCDNBlock={() => void actions.handleTogglePCDNBlock(true)}
      />

      <AuditFlowsSection
        report={ctrl.report}
        processedFlows={ctrl.processedFlows}
        visibleFlows={ctrl.visibleFlows}
        targetGroups={ctrl.targetGroups}
        telemetry={ctrl.telemetry}
        totalActiveFlows={ctrl.totalActiveFlows}
        totalAllFlows={ctrl.totalAllFlows}
        presetCounts={ctrl.presetCounts}
        loading={ctrl.loading}
        onlyActive={ctrl.onlyActive}
        onOnlyActiveChange={ctrl.setOnlyActive}
        viewMode={ctrl.viewMode}
        onViewModeChange={ctrl.setViewMode}
        preset={ctrl.preset}
        onPresetChange={ctrl.setPreset}
        searchQuery={ctrl.searchQuery}
        onSearchQueryChange={ctrl.setSearchQuery}
        selectedDevice={ctrl.selectedDevice}
        onSelectDevice={ctrl.setSelectedDevice}
        selectedChain={ctrl.selectedChain}
        onSelectChain={ctrl.setSelectedChain}
        networkFilter={ctrl.networkFilter}
        onNetworkFilterChange={ctrl.setNetworkFilter}
        axisFilter={ctrl.axisFilter}
        onAxisFilterChange={ctrl.setAxisFilter}
        hideWhitelisted={ctrl.hideWhitelisted}
        onHideWhitelistedChange={ctrl.setHideWhitelisted}
        sortBy={ctrl.sortBy}
        onSortByChange={(k) => {
          ctrl.setSortBy(k);
          ctrl.setSortDir('desc');
        }}
        sortDir={ctrl.sortDir}
        onToggleSortDir={() => ctrl.setSortDir((d) => (d === 'desc' ? 'asc' : 'desc'))}
        onSort={ctrl.handleSort}
        refreshMs={ctrl.refreshMs}
        onRefreshMsChange={ctrl.setRefreshMs}
        refreshAutoPausedReason={ctrl.refreshAutoPausedReason}
        aiEnabled={aiEnabled}
        onToggleAI={handleToggleAI}
        hasAnyFilter={ctrl.hasAnyFilter}
        onResetAllFilters={ctrl.handleResetAllFilters}
        isAuditOnlyMode={isAuditOnlyMode}
        filterTransitioning={ctrl.filterTransitioning}
        closingAll={actions.closingAll}
        batchBusy={actions.batchBusy}
        busyFlowKeys={actions.busyFlowKeys}
        pendingTargets={mergedPendingTargets}
        selectedKeys={ctrl.selectedKeys}
        selectedActiveCount={ctrl.selectedActiveCount}
        onToggleSelectKey={ctrl.handleToggleSelectKey}
        onToggleSelectAllVisible={ctrl.handleToggleSelectAllVisible}
        onSelectAllVisible={() =>
          ctrl.setSelectedKeys(new Set(ctrl.visibleFlows.map(getFlowCacheKey)))
        }
        onClearSelection={() => ctrl.setSelectedKeys(new Set())}
        onBlockBatch={(deviceOnly) =>
          void actions.handleBlockBatch(ctrl.selectedFlows, deviceOnly).then((ok) => {
            if (ok) ctrl.setSelectedKeys(new Set());
          })
        }
        onWhitelistBatch={() =>
          void actions.handleWhitelistBatch(ctrl.selectedFlows).then((ok) => {
            if (ok) ctrl.setSelectedKeys(new Set());
          })
        }
        onReviewBatch={() => void reviewBatchFlows(ctrl.selectedFlows, true)}
        onCloseBatchConnections={() =>
          void actions.handleCloseFilteredConnections(ctrl.selectedFlows)
        }
        onHoverTableChange={ctrl.setHoverPaused}
        sectionAnchorRef={ctrl.sectionAnchorRef}
        tableContainerRef={ctrl.tableContainerRef}
        flowScrollRef={ctrl.flowScrollRef}
        onTableScroll={ctrl.handleFlowTableScroll}
        onExpandAllVisible={() => ctrl.setVisibleLimit(ctrl.processedFlows.length)}
        onSelectFlowDetail={ctrl.setDetailFlowKey}
        onOpenDisconnectConfirm={() => actions.setCloseAllConfirmOpen(true)}
        onMarkPointerInteraction={() => {
          ctrl.pointerDownUntilRef.current = Date.now() + 1200;
        }}
        getCachedReview={getCachedReview}
        onReviewSingleFlow={(f, force) => void reviewSingleFlow(f, force)}
        onCloseFlowConnections={(f) => void actions.handleCloseFlowConnections(f)}
        onWhitelistAction={(act, target) => void actions.handleWhitelist(act, target)}
        onBlockFlow={(f, deviceOnly) => void actions.handleBlockFlow(f, deviceOnly)}
        onSetThrottle={(f, rate) => void actions.handleSetThrottle(f, rate)}
        onCopyText={(text, label) => void actions.handleCopyText(text, label)}
      />

      <AuditBlacklistDrawer
        open={blockDrawerOpen}
        blockRules={ctrl.report?.blockRules || []}
        whitelist={whitelist}
        blockBusy={actions.blockBusy}
        onClose={() => setBlockDrawerOpen(false)}
        onManualBlock={actions.handleManualBlock}
        onUnblock={(r) => void actions.handleUnblock(r)}
        onWhitelist={actions.handleWhitelist}
      />

      <AuditAIConfigDrawer open={aiCfgOpen} onClose={() => setAiCfgOpen(false)} />

      <DeviceEditDrawer
        open={renameDrawerOpen}
        suffix={renameSuffix}
        saving={renameSaving}
        initial={renameInit}
        onClose={() => setRenameDrawerOpen(false)}
        onSubmit={handleSubmitRenameDevice}
      />

      <AuditFlowDetailDrawer
        detailFlow={ctrl.detailFlow}
        detailIndex={ctrl.detailIndex}
        totalCount={ctrl.processedFlows.length}
        throttleBusy={actions.throttleBusy}
        getCachedReview={getCachedReview}
        onClose={() => ctrl.setDetailFlowKey(null)}
        onNavigatePrev={() => {
          if (ctrl.detailIndex > 0) {
            ctrl.setDetailFlowKey(getFlowCacheKey(ctrl.processedFlows[ctrl.detailIndex - 1]));
          }
        }}
        onNavigateNext={() => {
          if (ctrl.detailIndex >= 0 && ctrl.detailIndex < ctrl.processedFlows.length - 1) {
            ctrl.setDetailFlowKey(getFlowCacheKey(ctrl.processedFlows[ctrl.detailIndex + 1]));
          }
        }}
        onCopyText={(text, label) => void actions.handleCopyText(text, label)}
        onReviewSingleFlow={(f, force) => void reviewSingleFlow(f, force)}
        onCloseFlowConnections={(f) => void actions.handleCloseFlowConnections(f)}
        onCloseSingleSubConn={(id, label) => actions.handleCloseSingleSubConn(id, label)}
        onWhitelistAction={(act, target) => void actions.handleWhitelist(act, target)}
        onBlockFlow={(f, deviceOnly) => void actions.handleBlockFlow(f, deviceOnly)}
        onSetThrottle={(f, rate) => void actions.handleSetThrottle(f, rate)}
        onFilterByDevice={(f) =>
          ctrl.setSelectedDevice({
            ip: f.deviceIp,
            label: f.deviceName || f.deviceIp,
            mac: f.deviceMac,
          })
        }
        onFilterByChain={ctrl.setSelectedChain}
        onFilterBySubnet={(cidr) => {
          ctrl.setSearchQuery(cidr);
          ctrl.setDetailFlowKey(null);
        }}
        onRequestSubnetBlock={actions.setSubnetBlockConfirm}
      />

      <ConfirmDialog
        open={actions.closeAllConfirmOpen}
        title={
          ctrl.hasAnyFilter
            ? `断开当前命中的 ${ctrl.telemetry.activeFlowCount} 条活跃连接`
            : '断开全部活跃连接'
        }
        description={
          ctrl.hasAnyFilter
            ? `仅断开当前筛选条件命中的 ${ctrl.telemetry.activeFlowCount} 条活跃流（共 ${ctrl.telemetry.activeConnCount} 条句柄），不影响未命中连接，也不会拉黑任何域名。`
            : '确认立即断开当前所有活跃连接？正在加载的网页或下载会瞬时重新握手并自动应用最新选路/分组规则，不会拉黑任何域名。'
        }
        confirmText={ctrl.hasAnyFilter ? '确认断开命中连接' : '确认断开全部'}
        loading={actions.closingAll}
        onConfirm={() =>
          void (ctrl.hasAnyFilter
            ? actions.handleCloseFilteredConnections(ctrl.processedFlows)
            : actions.handleCloseAllConnections())
        }
        onCancel={() => actions.setCloseAllConfirmOpen(false)}
      />

      <ConfirmDialog
        open={Boolean(actions.subnetBlockConfirm)}
        title={
          actions.subnetBlockConfirm
            ? `仅针对设备封禁网段 ${actions.subnetBlockConfirm.cidr}`
            : '确认按设备封禁网段'
        }
        description={
          actions.subnetBlockConfirm ? (
            <div className="space-y-2 text-xs leading-relaxed">
              <p>
                将向{' '}
                <span className="font-mono font-semibold text-primary">
                  {actions.subnetBlockConfirm.cidr}
                </span>{' '}
                添加路由 <code>reject</code> 规则，且<strong>仅作用于来源设备</strong>{' '}
                <span className="font-semibold text-primary">
                  {actions.subnetBlockConfirm.deviceLabel} ({actions.subnetBlockConfirm.sourceIp})
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
        loading={actions.subnetBlocking}
        onConfirm={() => void actions.handleConfirmSubnetBlock()}
        onCancel={() => actions.setSubnetBlockConfirm(null)}
      />
    </div>
  );
};

import React, { useMemo } from 'react';
import { ShieldAlert, Unplug } from 'lucide-react';
import { Button, DataTable, SectionCard } from '../../../ui';
import { AuditAIReview, AuditFlowRecord, AuditReport } from '../../types';
import { AuditBulkBar } from './AuditBulkBar';
import { AuditFlowMobileCards } from './AuditFlowMobileCards';
import {
  AuditFlowTelemetry,
  AuditPresetCounts,
  AuditPresetFilter,
  AuditRefreshCadence,
  AuditSelectedDevice,
  AuditSortKey,
  AuditTargetGroup,
  AuditViewMode,
} from './auditFlowModel';
import { checkIsDualAlert, getFlowCacheKey } from './auditHelpers';
import { AuditTargetGroupList } from './AuditTargetGroupList';
import { AuditToolbarAndPresets } from './AuditToolbarAndPresets';
import { buildAuditFlowColumns } from './buildAuditFlowColumns';

export interface AuditFlowsSectionProps {
  report: AuditReport | null;
  processedFlows: AuditFlowRecord[];
  visibleFlows: AuditFlowRecord[];
  targetGroups: AuditTargetGroup[];
  telemetry: AuditFlowTelemetry;
  totalActiveFlows: number;
  totalAllFlows: number;
  presetCounts: AuditPresetCounts;
  loading: boolean;
  onlyActive: boolean;
  onOnlyActiveChange: (v: boolean) => void;
  viewMode: AuditViewMode;
  onViewModeChange: (v: AuditViewMode) => void;
  preset: AuditPresetFilter;
  onPresetChange: (v: AuditPresetFilter) => void;
  searchQuery: string;
  onSearchQueryChange: (v: string) => void;
  selectedDevice: AuditSelectedDevice | null;
  onSelectDevice: (d: AuditSelectedDevice | null) => void;
  selectedChain: string;
  onSelectChain: (chain: string) => void;
  networkFilter: '' | 'tcp' | 'udp';
  onNetworkFilterChange: (v: '' | 'tcp' | 'udp') => void;
  axisFilter: '' | 'security' | 'privacy';
  onAxisFilterChange: (v: '' | 'security' | 'privacy') => void;
  hideWhitelisted: boolean;
  onHideWhitelistedChange: (v: boolean) => void;
  sortBy: AuditSortKey;
  onSortByChange: (v: AuditSortKey) => void;
  sortDir: 'asc' | 'desc';
  onToggleSortDir: () => void;
  onSort: (key: string) => void;
  refreshMs: AuditRefreshCadence;
  onRefreshMsChange: (v: AuditRefreshCadence) => void;
  refreshAutoPausedReason: string;
  aiEnabled: boolean;
  onToggleAI: (v: boolean) => void;
  hasAnyFilter: boolean;
  onResetAllFilters: () => void;
  isAuditOnlyMode: boolean;
  filterTransitioning: boolean;
  closingAll: boolean;
  batchBusy: boolean;
  busyFlowKeys: Set<string>;
  pendingTargets: Set<string>;
  selectedKeys: Set<string>;
  selectedActiveCount: number;
  onToggleSelectKey: (fk: string) => void;
  onToggleSelectAllVisible: () => void;
  onSelectAllVisible: () => void;
  onClearSelection: () => void;
  onBlockBatch: (deviceOnly: boolean) => void;
  onWhitelistBatch: () => void;
  onReviewBatch: () => void;
  onCloseBatchConnections: () => void;
  onHoverTableChange: (hovering: boolean) => void;
  sectionAnchorRef: React.RefObject<HTMLDivElement>;
  tableContainerRef: React.RefObject<HTMLDivElement>;
  flowScrollRef: React.RefObject<HTMLDivElement>;
  onTableScroll: (e: React.UIEvent<HTMLDivElement>) => void;
  onExpandAllVisible: () => void;
  onSelectFlowDetail: (flowKey: string) => void;
  onOpenDisconnectConfirm: () => void;
  onMarkPointerInteraction: () => void;
  getCachedReview: (f: AuditFlowRecord) => AuditAIReview | null;
  onReviewSingleFlow: (f: AuditFlowRecord, force: boolean) => void;
  onCloseFlowConnections: (f: AuditFlowRecord) => void;
  onWhitelistAction: (action: 'add' | 'remove', target: string) => void;
  onBlockFlow: (f: AuditFlowRecord, deviceOnly: boolean) => void;
  onSetThrottle: (f: AuditFlowRecord, rateKbps: number) => void;
  onCopyText: (text: string, label?: string) => void;
}

export const AuditFlowsSection: React.FC<AuditFlowsSectionProps> = ({
  report,
  processedFlows,
  visibleFlows,
  targetGroups,
  telemetry,
  totalActiveFlows,
  totalAllFlows,
  presetCounts,
  loading,
  onlyActive,
  onOnlyActiveChange,
  viewMode,
  onViewModeChange,
  preset,
  onPresetChange,
  searchQuery,
  onSearchQueryChange,
  selectedDevice,
  onSelectDevice,
  selectedChain,
  onSelectChain,
  networkFilter,
  onNetworkFilterChange,
  axisFilter,
  onAxisFilterChange,
  hideWhitelisted,
  onHideWhitelistedChange,
  sortBy,
  onSortByChange,
  sortDir,
  onToggleSortDir,
  onSort,
  refreshMs,
  onRefreshMsChange,
  refreshAutoPausedReason,
  aiEnabled,
  onToggleAI,
  hasAnyFilter,
  onResetAllFilters,
  isAuditOnlyMode,
  filterTransitioning,
  closingAll,
  batchBusy,
  busyFlowKeys,
  pendingTargets,
  selectedKeys,
  selectedActiveCount,
  onToggleSelectKey,
  onToggleSelectAllVisible,
  onSelectAllVisible,
  onClearSelection,
  onBlockBatch,
  onWhitelistBatch,
  onReviewBatch,
  onCloseBatchConnections,
  onHoverTableChange,
  sectionAnchorRef,
  tableContainerRef,
  flowScrollRef,
  onTableScroll,
  onExpandAllVisible,
  onSelectFlowDetail,
  onOpenDisconnectConfirm,
  onMarkPointerInteraction,
  getCachedReview,
  onReviewSingleFlow,
  onCloseFlowConnections,
  onWhitelistAction,
  onBlockFlow,
  onSetThrottle,
  onCopyText,
}) => {
  const allVisibleSelected =
    visibleFlows.length > 0 && visibleFlows.every((f) => selectedKeys.has(getFlowCacheKey(f)));

  const handleFilterDeviceFromFlow = (f: AuditFlowRecord) => {
    if (!f.deviceIp) return;
    onSelectDevice({
      ip: f.deviceIp,
      label: f.deviceName || f.deviceIp,
      mac: f.deviceMac,
    });
  };

  const emptyText =
    onlyActive && totalAllFlows > 0 && processedFlows.length === 0
      ? '当前条件下暂无活跃连接（可切换到「全部历史」或重置筛选条件）'
      : report?.message || '暂无符合筛选条件的连接记录';

  const flowColumns = useMemo(
    () =>
      buildAuditFlowColumns({
        allVisibleSelected,
        selectedKeys,
        busyFlowKeys,
        pendingTargets,
        filterTransitioning,
        isAuditOnlyMode,
        getCachedReview,
        onToggleSelectAllVisible,
        onToggleSelectKey,
        onFilterByDevice: handleFilterDeviceFromFlow,
        onSelectChain,
        onSearchQueryChange,
        onMarkPointerInteraction,
        onReviewSingleFlow,
        onBlockFlow,
        onWhitelistAction,
        onCloseFlowConnections,
        onSetThrottle,
        onCopyText,
      }),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [
      allVisibleSelected,
      selectedKeys,
      busyFlowKeys,
      pendingTargets,
      filterTransitioning,
      isAuditOnlyMode,
      getCachedReview,
    ],
  );

  return (
    <div ref={sectionAnchorRef}>
      <SectionCard
        title="连接行为与可疑上传明细"
        subtitle={
          processedFlows.length > 0
            ? '点击任意行打开实时子连接显微镜与诊断抽屉 · 悬停表格自动暂缓刷新'
            : report?.message || '等待实时流量采样中'
        }
        icon={<ShieldAlert className="w-4 h-4" />}
        actions={
          telemetry.activeFlowCount > 0 ? (
            <Button
              size="xs"
              variant="secondary"
              disabled={closingAll}
              icon={<Unplug className="w-3 h-3" />}
              onClick={onOpenDisconnectConfirm}
              title={
                hasAnyFilter
                  ? '仅断开当前筛选命中的活跃连接，不影响其他连接'
                  : '断开当前全部活跃连接以强制重连'
              }
            >
              {hasAnyFilter
                ? `断开当前命中 (${telemetry.activeFlowCount})`
                : `断开全部活跃 (${telemetry.activeFlowCount})`}
            </Button>
          ) : undefined
        }
        noPadding
        className="audit-flows-card"
      >
        <AuditToolbarAndPresets
          onlyActive={onlyActive}
          onOnlyActiveChange={onOnlyActiveChange}
          totalActiveFlows={totalActiveFlows}
          totalAllFlows={totalAllFlows}
          viewMode={viewMode}
          onViewModeChange={onViewModeChange}
          preset={preset}
          onPresetChange={onPresetChange}
          presetCounts={presetCounts}
          searchQuery={searchQuery}
          onSearchQueryChange={onSearchQueryChange}
          selectedDevice={selectedDevice}
          onClearSelectedDevice={() => onSelectDevice(null)}
          selectedChain={selectedChain}
          onClearSelectedChain={() => onSelectChain('')}
          networkFilter={networkFilter}
          onNetworkFilterChange={onNetworkFilterChange}
          axisFilter={axisFilter}
          onAxisFilterChange={onAxisFilterChange}
          hideWhitelisted={hideWhitelisted}
          onHideWhitelistedChange={onHideWhitelistedChange}
          sortBy={sortBy}
          onSortByChange={onSortByChange}
          sortDir={sortDir}
          onToggleSortDir={onToggleSortDir}
          refreshMs={refreshMs}
          onRefreshMsChange={onRefreshMsChange}
          refreshAutoPausedReason={refreshAutoPausedReason}
          aiEnabled={aiEnabled}
          onToggleAI={onToggleAI}
          telemetry={telemetry}
          hasAnyFilter={hasAnyFilter}
          onResetAllFilters={onResetAllFilters}
        />

        <div
          ref={tableContainerRef}
          onPointerEnter={(e) => {
            if (e.pointerType === 'mouse') onHoverTableChange(true);
          }}
          onPointerLeave={(e) => {
            if (e.pointerType === 'mouse') onHoverTableChange(false);
          }}
          onTouchStart={onMarkPointerInteraction}
          onTouchMove={onMarkPointerInteraction}
          className={`transition-opacity duration-150 ${filterTransitioning ? 'opacity-70' : 'opacity-100'}`}
        >
          {viewMode === 'grouped' ? (
            <AuditTargetGroupList
              groups={targetGroups}
              busyFlowKeys={busyFlowKeys}
              getCachedReview={getCachedReview}
              onSelectFlowDetail={onSelectFlowDetail}
              onBlockGlobal={(sample) => onBlockFlow(sample, false)}
              onWhitelistAction={onWhitelistAction}
              onCopyTarget={(t) => onCopyText(t, '目标')}
              emptyText={emptyText}
            />
          ) : (
            <>
              <div className="hidden md:block">
                <DataTable
                  columns={flowColumns}
                  rows={visibleFlows}
                  rowKey={(f) => getFlowCacheKey(f)}
                  loading={loading}
                  emptyText={emptyText}
                  sortBy={sortBy}
                  sortDir={sortDir}
                  onSort={onSort}
                  onRowClick={(f) => onSelectFlowDetail(getFlowCacheKey(f))}
                  maxHeightClassName="max-h-[68vh] min-h-[380px] overflow-y-auto overscroll-contain"
                  stickyHeader
                  compact
                  scrollContainerRef={flowScrollRef}
                  onContainerScroll={onTableScroll}
                  rowClassName={(f) => {
                    const fk = getFlowCacheKey(f);
                    if (checkIsDualAlert(f, getCachedReview(f))) {
                      return 'bg-rose-500/[0.06] hover:bg-rose-500/[0.11]';
                    }
                    if (selectedKeys.has(fk)) {
                      return 'bg-accent/[0.06] hover:bg-accent/[0.10]';
                    }
                    return '';
                  }}
                  footerSlot={
                    processedFlows.length > 0 ? (
                      <div className="border-t border-subtle bg-surface2/40 px-4 py-2.5 text-center text-[11px] text-muted flex items-center justify-center gap-3">
                        {visibleFlows.length < processedFlows.length ? (
                          <>
                            <span>
                              已展示 {visibleFlows.length} / {processedFlows.length} 条明细，继续滚动自动加载…
                            </span>
                            <button
                              type="button"
                              onClick={onExpandAllVisible}
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

              <div className="md:hidden">
                <AuditFlowMobileCards
                  flows={visibleFlows}
                  selectedKeys={selectedKeys}
                  busyFlowKeys={busyFlowKeys}
                  pendingTargets={pendingTargets}
                  filterTransitioning={filterTransitioning}
                  isAuditOnlyMode={isAuditOnlyMode}
                  getCachedReview={getCachedReview}
                  onToggleSelect={onToggleSelectKey}
                  onSelectFlowDetail={onSelectFlowDetail}
                  onMarkPointerInteraction={onMarkPointerInteraction}
                  onReviewSingleFlow={onReviewSingleFlow}
                  onBlockFlow={onBlockFlow}
                  onWhitelistAction={onWhitelistAction}
                  onCloseFlowConnections={onCloseFlowConnections}
                  onSetThrottle={onSetThrottle}
                  onFilterByDevice={handleFilterDeviceFromFlow}
                  onFilterByChain={onSelectChain}
                  onFilterBySubnet={onSearchQueryChange}
                  onCopyTarget={(t) => onCopyText(t, '目标')}
                  emptyText={emptyText}
                />
                {visibleFlows.length < processedFlows.length && (
                  <div className="border-t border-subtle p-3 text-center">
                    <Button size="xs" variant="secondary" onClick={onExpandAllVisible}>
                      展开剩余 {processedFlows.length - visibleFlows.length} 条
                    </Button>
                  </div>
                )}
              </div>
            </>
          )}
        </div>

        <AuditBulkBar
          selectedCount={selectedKeys.size}
          selectedActiveCount={selectedActiveCount}
          visibleCount={visibleFlows.length}
          busy={batchBusy}
          onSelectAllVisible={onSelectAllVisible}
          onClearSelection={onClearSelection}
          onBlockBatch={onBlockBatch}
          onWhitelistBatch={onWhitelistBatch}
          onReviewBatch={onReviewBatch}
          onCloseBatchConnections={onCloseBatchConnections}
        />
      </SectionCard>
    </div>
  );
};

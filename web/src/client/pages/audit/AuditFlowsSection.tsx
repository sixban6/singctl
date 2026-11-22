import React from 'react';
import { Bot, RefreshCw, ShieldAlert, Unplug } from 'lucide-react';
import {
  Badge,
  Button,
  DataColumn,
  DataTable,
  SectionCard,
  formatBytes as fmtBytes,
} from '../../../ui';
import { AuditAIReview, AuditFlowRecord, AuditReport } from '../../types';
import {
  AuditSortKey,
  checkIsDualAlert,
  fmtBps,
  formatFlowChainPath,
  formatOutboundMeta,
  formatRelativeSeen,
  getFlowCacheKey,
  getFlowTargetKey,
  isProtectedBootstrapTarget,
} from './auditHelpers';

export interface AuditFlowsSectionProps {
  report: AuditReport | null;
  processedFlows: AuditFlowRecord[];
  visibleFlows: AuditFlowRecord[];
  activeFlowCount: number;
  loading: boolean;
  onlyActive: boolean;
  filterTransitioning: boolean;
  closingAll: boolean;
  sortBy: AuditSortKey;
  sortDir: 'asc' | 'desc';
  busyFlowKeys: Set<string>;
  pendingTargets: Set<string>;
  tableContainerRef: React.RefObject<HTMLDivElement>;
  flowScrollRef: React.RefObject<HTMLDivElement>;
  onTableScroll: (e: React.UIEvent<HTMLDivElement>) => void;
  onSort: (key: string) => void;
  onExpandAllVisible: () => void;
  onSelectFlowDetail: (flowKey: string) => void;
  onOpenCloseAllConfirm: () => void;
  onMarkPointerInteraction: () => void;
  getCachedReview: (f: AuditFlowRecord) => AuditAIReview | null;
  onReviewSingleFlow: (f: AuditFlowRecord, force: boolean) => void;
  onCloseFlowConnections: (f: AuditFlowRecord) => void;
  onWhitelistAdd: (target: string) => void;
  onBlockFlow: (f: AuditFlowRecord) => void;
}

export const AuditFlowsSection: React.FC<AuditFlowsSectionProps> = ({
  report,
  processedFlows,
  visibleFlows,
  activeFlowCount,
  loading,
  onlyActive,
  filterTransitioning,
  closingAll,
  sortBy,
  sortDir,
  busyFlowKeys,
  pendingTargets,
  tableContainerRef,
  flowScrollRef,
  onTableScroll,
  onSort,
  onExpandAllVisible,
  onSelectFlowDetail,
  onOpenCloseAllConfirm,
  onMarkPointerInteraction,
  getCachedReview,
  onReviewSingleFlow,
  onCloseFlowConnections,
  onWhitelistAdd,
  onBlockFlow,
}) => {
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
              {f.pcdnKind === 'upload' && <Badge tone="danger">PCDN 偷跑</Badge>}
              {f.pcdnKind === 'swarm' && <Badge tone="danger">PCDN 蜂群</Badge>}
              {f.pcdnKind === 'download' && (
                <Badge tone={f.state === 'blocked' ? 'neutral' : 'warn'}>
                  {f.state === 'blocked' ? 'PCDN 已拦截' : 'PCDN 拉流'}
                </Badge>
              )}
              {f.subnetCluster?.suspicious && (
                <Badge tone="warn">同段×{f.subnetCluster.uniqueIps}</Badge>
              )}
              {(f.throttledRateKbps || 0) > 0 && (
                <Badge tone="accent">限速 {f.throttledRateKbps} KB/s</Badge>
              )}
              {protectedTarget && <Badge tone="neutral">核心保护</Badge>}
            </div>
            <div className="mt-1 flex items-center gap-2 flex-wrap text-[11px] text-muted">
              <span className="font-medium text-secondary">{f.deviceName || f.deviceIp}</span>
              <span className="font-mono">{f.deviceIp}</span>
              <span className="uppercase">{f.network}</span>
              {!f.isDirectIp && f.destIp && f.destIp !== f.target && (
                <span
                  className="font-mono text-[10.5px] text-muted/80 truncate max-w-[130px]"
                  title={`解析目的 IP: ${f.destIp}`}
                >
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
        const chainPath = formatFlowChainPath(f);
        const hasChainHops = Boolean(f.chains && f.chains.length > 1);
        const compactChainLabel = hasChainHops
          ? `${f.chains![0]} → ${f.chains![f.chains!.length - 1]}`
          : outMeta.label;
        const routeTip = `完整分流链: ${chainPath}${f.rule ? ` · 命中规则: ${f.rule}` : ''}`;
        return (
          <div className="space-y-1 whitespace-nowrap" title={routeTip}>
            <div className="flex items-center gap-1.5">
              <Badge tone={outMeta.tone}>
                <span className="max-w-[168px] truncate inline-block align-bottom">
                  {compactChainLabel}
                </span>
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
      key: 'upload',
      header: '上传 ↑',
      sortKey: 'upload',
      align: 'right',
      render: (f) => (
        <div className="text-right font-mono tnum text-xs whitespace-nowrap">
          <div className="text-primary font-semibold">↑ {fmtBytes(f.uploadBytes)}</div>
          {(f.avgUploadBps || 0) > 0 && (f.activeSpanSec || 0) >= 300 && (
            <div className="text-[10.5px] text-muted">均速 {fmtBps(f.avgUploadBps)}</div>
          )}
        </div>
      ),
    },
    {
      key: 'download',
      header: '下载 ↓',
      sortKey: 'download',
      align: 'right',
      render: (f) => (
        <div className="text-right font-mono tnum text-xs whitespace-nowrap">
          <div className="text-secondary font-medium">↓ {fmtBytes(f.downloadBytes)}</div>
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
        const rev = getCachedReview(f);
        const dual = checkIsDualAlert(f, rev);
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
            <div className="max-w-xs space-y-1" onClick={(e) => e.stopPropagation()}>
              <div className="flex items-center gap-1.5 flex-wrap">
                <Badge tone={vTone}>{rev.verdictText}</Badge>
                <span className="text-[11px] font-medium text-primary">{rev.category}</span>
                <button
                  type="button"
                  onClick={() => onReviewSingleFlow(f, true)}
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
              onClick={() => onReviewSingleFlow(f, false)}
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
        const hasActive = (f.activeConns || 0) > 0;
        const isBusy = busyFlowKeys.has(fk);
        if (isProtectedBootstrapTarget(f.target)) {
          return (
            <div
              className="flex justify-end items-center gap-1.5 whitespace-nowrap"
              onPointerDown={onMarkPointerInteraction}
              onClick={(e) => e.stopPropagation()}
            >
              {hasActive && (
                <Button
                  size="xs"
                  variant="secondary"
                  loading={isBusy}
                  disabled={filterTransitioning}
                  onClick={() => onCloseFlowConnections(f)}
                  title="仅断开活跃连接强制重连，不影响访问"
                >
                  断开
                </Button>
              )}
              <Badge tone="neutral">受保护</Badge>
            </div>
          );
        }
        const dual = checkIsDualAlert(f, getCachedReview(f));
        return (
          <div
            className="flex justify-end gap-1.5 whitespace-nowrap"
            onPointerDown={onMarkPointerInteraction}
            onClick={(e) => e.stopPropagation()}
          >
            {hasActive && (
              <Button
                size="xs"
                variant="secondary"
                disabled={isBusy || filterTransitioning}
                onClick={() => onCloseFlowConnections(f)}
                title="断开当前活跃连接以切换节点或重新握手"
              >
                断开
              </Button>
            )}
            <Button
              size="xs"
              variant="secondary"
              disabled={isBusy || filterTransitioning}
              onClick={() => onWhitelistAdd(f.target)}
            >
              白名单
            </Button>
            <Button
              size="xs"
              variant="danger"
              loading={isBusy}
              disabled={filterTransitioning}
              className={dual ? 'animate-pulse' : ''}
              onClick={() => onBlockFlow(f)}
            >
              {dual ? '立即拉黑' : '一键拉黑'}
            </Button>
          </div>
        );
      },
    },
  ];

  return (
    <SectionCard
      title="连接行为与可疑上传明细"
      subtitle={
        processedFlows.length > 0
          ? `共 ${processedFlows.length} 条记录（当前活跃 ${activeFlowCount} 条）· 点击任意行查看完整诊断详情`
          : report?.message || '等待数据采集中'
      }
      icon={<ShieldAlert className="w-4 h-4" />}
      actions={
        activeFlowCount > 0 ? (
          <Button
            size="xs"
            variant="secondary"
            disabled={closingAll}
            icon={<Unplug className="w-3 h-3" />}
            onClick={onOpenCloseAllConfirm}
          >
            断开全部活跃 ({activeFlowCount})
          </Button>
        ) : undefined
      }
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
          emptyText={
            onlyActive && (report?.flows?.length || 0) > 0 && processedFlows.length === 0
              ? '当前暂无活跃连接（取消勾选「仅看当前活跃」可查看历史记录）'
              : report?.message || '暂无符合过滤条件的流量记录'
          }
          sortBy={sortBy}
          sortDir={sortDir}
          onSort={onSort}
          onRowClick={(f) => onSelectFlowDetail(getFlowCacheKey(f))}
          maxHeightClassName="max-h-[68vh] min-h-[420px] overflow-y-auto overscroll-contain"
          stickyHeader
          scrollContainerRef={flowScrollRef}
          onContainerScroll={onTableScroll}
          rowClassName={(f) =>
            checkIsDualAlert(f, getCachedReview(f)) ? 'bg-rose-500/[0.06] hover:bg-rose-500/[0.11]' : ''
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
    </SectionCard>
  );
};

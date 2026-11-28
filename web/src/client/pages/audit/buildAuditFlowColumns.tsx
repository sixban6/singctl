import { Bot, Copy, RefreshCw } from 'lucide-react';
import { Badge, DataColumn, formatBytes as fmtBytes } from '../../../ui';
import {
  AuditAIReview,
  AuditFlowRecord,
  AuditRouteRuleDeleteRequest,
  AuditRouteRuleUpsertRequest,
  ClientRoutingReport,
} from '../../types';
import { AuditActionCell } from './AuditActionCell';
import { formatCompactRule } from './auditFlowModel';
import { findMatchingCustomRule } from './AuditRouteRulePopover';
import {
  checkIsDualAlert,
  fmtBps,
  formatFlowChainPath,
  formatOutboundMeta,
  formatRelativeSeen,
  getFlowCacheKey,
  getFlowTargetKey,
  isProtectedBootstrapTarget,
} from './auditHelpers';

export interface BuildAuditFlowColumnsParams {
  allVisibleSelected: boolean;
  selectedKeys: Set<string>;
  busyFlowKeys: Set<string>;
  pendingTargets: Set<string>;
  filterTransitioning: boolean;
  isAuditOnlyMode: boolean;
  routingReport?: ClientRoutingReport | null;
  getCachedReview: (f: AuditFlowRecord) => AuditAIReview | null;
  onToggleSelectAllVisible: () => void;
  onToggleSelectKey: (fk: string) => void;
  onFilterByDevice: (f: AuditFlowRecord) => void;
  onSelectChain: (chain: string) => void;
  onSearchQueryChange: (q: string) => void;
  onMarkPointerInteraction: () => void;
  onReviewSingleFlow: (f: AuditFlowRecord, force: boolean) => void;
  onBlockFlow: (f: AuditFlowRecord, deviceOnly: boolean) => void;
  onWhitelistAction: (action: 'add' | 'remove', target: string) => void;
  onCloseFlowConnections: (f: AuditFlowRecord) => void;
  onSetThrottle: (f: AuditFlowRecord, rateKbps: number) => void;
  onUpsertRouteRule?: (req: AuditRouteRuleUpsertRequest) => void;
  onDeleteRouteRule?: (req: AuditRouteRuleDeleteRequest) => void;
  onCopyText: (text: string, label?: string) => void;
}

export function buildAuditFlowColumns({
  allVisibleSelected,
  selectedKeys,
  busyFlowKeys,
  pendingTargets,
  filterTransitioning,
  isAuditOnlyMode,
  routingReport = null,
  getCachedReview,
  onToggleSelectAllVisible,
  onToggleSelectKey,
  onFilterByDevice,
  onSelectChain,
  onSearchQueryChange,
  onMarkPointerInteraction,
  onReviewSingleFlow,
  onBlockFlow,
  onWhitelistAction,
  onCloseFlowConnections,
  onSetThrottle,
  onUpsertRouteRule,
  onDeleteRouteRule,
  onCopyText,
}: BuildAuditFlowColumnsParams): DataColumn<AuditFlowRecord>[] {
  return [
    {
      key: 'target',
      header: (
        <div className="flex items-center gap-2">
          <input
            type="checkbox"
            checked={allVisibleSelected}
            onChange={onToggleSelectAllVisible}
            className="accent-emerald-500 cursor-pointer"
            aria-label="全选当前可见连接"
            title="全选/取消当前可见连接"
          />
          <span>目标、规则与来源</span>
        </div>
      ),
      render: (f) => {
        const fk = getFlowCacheKey(f);
        const checked = selectedKeys.has(fk);
        const protectedTarget = isProtectedBootstrapTarget(f.target);
        const activeCnt = Number(f.activeConns || 0);
        const relSeen = formatRelativeSeen(f.lastSeen);

        return (
          <div className="flex items-start gap-2.5 min-w-0 max-w-[360px] group/row">
            <input
              type="checkbox"
              checked={checked}
              onClick={(e) => e.stopPropagation()}
              onChange={() => onToggleSelectKey(fk)}
              className="mt-1 accent-emerald-500 shrink-0 cursor-pointer"
              aria-label={`选择 ${f.target}`}
            />
            <div className="min-w-0 flex-1 space-y-1">
              <div className="flex items-center gap-1.5 flex-wrap">
                <span className="font-mono text-xs font-semibold text-primary break-all">
                  {f.target}
                </span>
                {f.destPort ? (
                  <span className="font-mono text-[10.5px] text-muted">:{f.destPort}</span>
                ) : null}
                <button
                  type="button"
                  onClick={(e) => {
                    e.stopPropagation();
                    onCopyText(f.target, '目标');
                  }}
                  className="opacity-0 group-hover/row:opacity-100 focus:opacity-100 text-muted hover:text-primary transition-opacity p-0.5 cursor-pointer"
                  title="复制目标地址"
                >
                  <Copy className="w-3 h-3" />
                </button>
                {f.appName && <Badge tone="accent">{f.appName}</Badge>}
                {f.pcdnKind === 'upload' && <Badge tone="danger">PCDN 偷跑</Badge>}
                {f.pcdnKind === 'swarm' && <Badge tone="danger">PCDN 蜂群</Badge>}
                {f.pcdnKind === 'download' && <Badge tone="warn">PCDN 拉流</Badge>}
                {(f.throttledRateKbps || 0) > 0 && (
                  <Badge tone="accent">限速 {f.throttledRateKbps}K</Badge>
                )}
                {protectedTarget && <Badge tone="neutral">核心保护</Badge>}
              </div>

              <div className="flex items-center gap-1.5 flex-wrap text-[11px] text-muted">
                <button
                  type="button"
                  onClick={(e) => {
                    e.stopPropagation();
                    onFilterByDevice(f);
                  }}
                  className="font-medium text-secondary hover:text-accent hover:underline cursor-pointer truncate max-w-[140px]"
                  title={`点击仅查看 ${f.deviceName || f.deviceIp} (${f.deviceIp})`}
                >
                  {f.deviceName || f.deviceIp}
                </button>
                <span className="uppercase font-mono text-[10px] px-1 rounded bg-surface2/80 border border-subtle">
                  {f.network}
                </span>
                {f.rule && (
                  <span
                    className="font-mono text-[10px] px-1.5 py-0.2 rounded bg-surface2/70 border border-subtle text-secondary truncate max-w-[145px]"
                    title={`命中规则: ${f.rule}`}
                  >
                    {formatCompactRule(f.rule)}
                  </span>
                )}
                <span className="inline-flex items-center gap-1 font-mono tnum text-[10.5px]">
                  <span
                    className={`w-1.5 h-1.5 rounded-full ${
                      activeCnt > 0 ? 'bg-emerald-400 animate-pulse' : 'bg-slate-600'
                    }`}
                  />
                  {relSeen || (activeCnt > 0 ? '活跃中' : '历史')}
                </span>
              </div>
            </div>
          </div>
        );
      },
    },
    {
      key: 'route',
      header: '出站链路',
      sortKey: 'active',
      render: (f) => {
        const outMeta = formatOutboundMeta(f.outbound);
        const activeCnt = Number(f.activeConns || 0);
        const totalCnt = Math.max(activeCnt, Number(f.connCount || 1));
        const chainPath = formatFlowChainPath(f);
        const hasHops = Boolean(f.chains && f.chains.length > 1);
        const compactLabel = hasHops
          ? `${f.chains![0]} → ${f.chains![f.chains!.length - 1]}`
          : outMeta.label;
        const dimDirect = isAuditOnlyMode && outMeta.tone === 'neutral';
        const customMatch = !isAuditOnlyMode ? findMatchingCustomRule(f, routingReport?.customRules) : null;

        return (
          <div
            className={`space-y-1 whitespace-nowrap ${dimDirect ? 'opacity-65' : ''}`}
            title={`完整分流链: ${chainPath}${f.rule ? ` · 规则: ${f.rule}` : ''}\n点击筛选同链路`}
          >
            <div className="flex items-center gap-1">
              <button
                type="button"
                onClick={(e) => {
                  e.stopPropagation();
                  onSelectChain(f.outbound || 'DIRECT');
                }}
                className="cursor-pointer hover:opacity-90 text-left"
              >
                <Badge tone={outMeta.tone}>
                  <span className="max-w-[155px] truncate inline-block align-bottom">
                    {compactLabel}
                  </span>
                </Badge>
              </button>
              {customMatch && (
                <span
                  className="text-[10px] px-1 py-0.5 rounded bg-accent/15 border border-accent/35 text-accent"
                  title={`已固定出口规则: ${customMatch.target} → ${customMatch.outbound}`}
                >
                  固定
                </span>
              )}
            </div>
            <div className="text-[10.5px] font-mono tnum text-muted">
              {activeCnt > 0 ? (
                <span className="text-emerald-400 font-semibold">{activeCnt} 活跃</span>
              ) : (
                <span>历史</span>
              )}
              <span> / {totalCnt} 次</span>
            </div>
          </div>
        );
      },
    },
    {
      key: 'live_speed',
      header: '实时速率',
      sortKey: 'live_total',
      align: 'right',
      render: (f) => {
        const activeCnt = Number(f.activeConns || 0);
        const upBps = Number(f.currentUploadBps || 0);
        const downBps = Number(f.currentDownloadBps || 0);

        if (activeCnt > 0 && (upBps > 0 || downBps > 0)) {
          return (
            <div className="text-right font-mono tnum whitespace-nowrap leading-tight space-y-0.5 text-[11px]">
              <div className={upBps > 0 ? 'text-emerald-400 font-semibold' : 'text-muted'}>
                ↑ {fmtBps(upBps)}
              </div>
              <div className={downBps > 0 ? 'text-sky-400 font-medium' : 'text-muted'}>
                ↓ {fmtBps(downBps)}
              </div>
            </div>
          );
        }

        return (
          <div className="text-right font-mono tnum whitespace-nowrap text-[11px] text-muted">
            {activeCnt > 0 ? '空闲' : '—'}
          </div>
        );
      },
    },
    {
      key: 'cumulative_traffic',
      header: '累计流量',
      sortKey: 'total',
      align: 'right',
      render: (f) => {
        const totalBytes = Math.max(1, (f.uploadBytes || 0) + (f.downloadBytes || 0));
        const upPct = Math.min(100, Math.round(((f.uploadBytes || 0) / totalBytes) * 100));
        const ratio = Number(f.uploadRatio || 0);

        return (
          <div className="text-right font-mono tnum whitespace-nowrap space-y-1">
            <div className="text-xs">
              <span className="text-primary font-semibold">↑{fmtBytes(f.uploadBytes)}</span>{' '}
              <span className="text-secondary font-normal">↓{fmtBytes(f.downloadBytes)}</span>
            </div>

            <div className="flex items-center justify-end gap-1.5 text-[10.5px]">
              <div
                className="w-12 h-1.5 rounded-full bg-sky-500/35 overflow-hidden shrink-0"
                title={`上行占比 ${upPct}% · 上/下比 ${ratio.toFixed(1)}x`}
              >
                <div className="h-full bg-emerald-400" style={{ width: `${upPct}%` }} />
              </div>
              <span
                className={`font-semibold ${
                  ratio >= 3 ? 'text-rose-400' : ratio >= 1.5 ? 'text-amber-400' : 'text-muted'
                }`}
              >
                {ratio.toFixed(1)}x
              </span>
            </div>
          </div>
        );
      },
    },
    {
      key: 'risk_ai',
      header: '风险与 AI 研判',
      sortKey: 'risk',
      render: (f) => {
        const tk = getFlowTargetKey(f);
        const rev = getCachedReview(f);
        const dual = checkIsDualAlert(f, rev);
        const pending = pendingTargets.has(tk);
        const riskTone =
          f.state === 'whitelisted'
            ? 'ok'
            : f.threat === 'high_risk'
              ? 'danger'
              : f.threat === 'suspicious'
                ? 'warn'
                : f.threat === 'notice'
                  ? 'accent'
                  : 'ok';
        const riskLabel = f.state === 'whitelisted' ? '已放行' : f.threatLabel || '正常';
        const firstReason = f.reasons?.[0] || '';

        return (
          <div className="max-w-[280px] space-y-1" onClick={(e) => e.stopPropagation()}>
            <div className="flex items-center gap-1.5 flex-wrap">
              <Badge tone={riskTone} dot={f.threat === 'high_risk' || f.threat === 'suspicious'}>
                {riskLabel} · {f.riskScore || 0}
              </Badge>
              {dual && <Badge tone="danger">双重高危</Badge>}
              {rev ? (
                <>
                  <Badge
                    tone={
                      rev.verdict === 'safe_to_block'
                        ? 'danger'
                        : rev.verdict === 'caution'
                          ? 'warn'
                          : 'accent'
                    }
                  >
                    {rev.verdictText}
                  </Badge>
                  <button
                    type="button"
                    onClick={() => onReviewSingleFlow(f, true)}
                    disabled={pending}
                    title={pending ? '正在重新 AI 分析…' : '重新 AI 分析'}
                    aria-label={pending ? '正在重新 AI 分析' : '重新 AI 分析'}
                    className={`w-5 h-5 inline-flex items-center justify-center rounded-md border transition-all ${
                      pending
                        ? 'opacity-100 bg-accent/15 border-accent/40 text-accent cursor-wait'
                        : 'opacity-100 sm:opacity-0 sm:group-hover/row:opacity-100 focus-visible:opacity-100 bg-surface2/80 border-subtle/80 text-muted hover:text-accent hover:border-accent/40 hover:bg-accent/10 cursor-pointer'
                    }`}
                  >
                    <RefreshCw className={`w-3 h-3 ${pending ? 'animate-spin' : ''}`} />
                  </button>
                </>
              ) : pending ? (
                <span className="inline-flex items-center gap-1 text-[10.5px] text-accent">
                  <RefreshCw className="w-2.5 h-2.5 animate-spin" />
                  AI 分析中
                </span>
              ) : (
                <button
                  type="button"
                  onClick={() => onReviewSingleFlow(f, false)}
                  className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded bg-surface2 border border-subtle text-[10.5px] text-secondary hover:text-primary cursor-pointer"
                >
                  <Bot className="w-2.5 h-2.5" />
                  AI 分析
                </button>
              )}
            </div>

            {rev ? (
              <div
                className="text-[11px] text-muted truncate"
                title={`${rev.category}: ${rev.impact}${firstReason ? `\n风险依据: ${firstReason}` : ''}`}
              >
                <span className="text-secondary font-medium">{rev.category}</span>
                {rev.impact ? ` · ${rev.impact}` : ''}
              </div>
            ) : firstReason ? (
              <div className="text-[11px] text-secondary truncate" title={firstReason}>
                {firstReason}
              </div>
            ) : (
              <div className="text-[10.5px] font-mono tnum text-muted">
                安:{f.securityScore || 0} · 隐:{f.privacyScore || 0}
              </div>
            )}
          </div>
        );
      },
    },
    {
      key: 'actions',
      header: '安全处置',
      align: 'right',
      render: (f) => (
        <AuditActionCell
          flow={f}
          isBusy={busyFlowKeys.has(getFlowCacheKey(f))}
          isDualAlert={checkIsDualAlert(f, getCachedReview(f))}
          disabled={filterTransitioning}
          isAuditOnlyMode={isAuditOnlyMode}
          routingReport={routingReport}
          onMarkPointerInteraction={onMarkPointerInteraction}
          onBlockFlow={onBlockFlow}
          onWhitelistAction={onWhitelistAction}
          onCloseFlowConnections={onCloseFlowConnections}
          onSetThrottle={onSetThrottle}
          onUpsertRouteRule={onUpsertRouteRule}
          onDeleteRouteRule={onDeleteRouteRule}
          onFilterByDevice={onFilterByDevice}
          onFilterBySubnet={onSearchQueryChange}
          onCopyTarget={(t) => onCopyText(t, '目标')}
        />
      ),
    },
  ];
}

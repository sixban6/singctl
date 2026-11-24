import React from 'react';
import { Bot, Copy } from 'lucide-react';
import { Badge, Button, formatBytes as fmtBytes } from '../../../ui';
import { AuditAIReview, AuditFlowRecord } from '../../types';
import { AuditActionCell } from './AuditActionCell';
import { formatCompactRule } from './auditFlowModel';
import {
  checkIsDualAlert,
  fmtBps,
  formatOutboundMeta,
  formatRelativeSeen,
  getFlowCacheKey,
  getFlowTargetKey,
} from './auditHelpers';

export interface AuditFlowMobileCardsProps {
  flows: AuditFlowRecord[];
  selectedKeys: Set<string>;
  busyFlowKeys: Set<string>;
  pendingTargets: Set<string>;
  filterTransitioning: boolean;
  isAuditOnlyMode: boolean;
  getCachedReview: (f: AuditFlowRecord) => AuditAIReview | null;
  onToggleSelect: (fk: string) => void;
  onSelectFlowDetail: (fk: string) => void;
  onMarkPointerInteraction: () => void;
  onReviewSingleFlow: (f: AuditFlowRecord, force: boolean) => void;
  onBlockFlow: (f: AuditFlowRecord, deviceOnly: boolean) => void;
  onWhitelistAction: (action: 'add' | 'remove', target: string) => void;
  onCloseFlowConnections: (f: AuditFlowRecord) => void;
  onSetThrottle: (f: AuditFlowRecord, rateKbps: number) => void;
  onFilterByDevice: (f: AuditFlowRecord) => void;
  onFilterByChain: (chain: string) => void;
  onFilterBySubnet: (cidr: string) => void;
  onCopyTarget: (target: string) => void;
  emptyText: string;
}

export const AuditFlowMobileCards: React.FC<AuditFlowMobileCardsProps> = ({
  flows,
  selectedKeys,
  busyFlowKeys,
  pendingTargets,
  filterTransitioning,
  isAuditOnlyMode,
  getCachedReview,
  onToggleSelect,
  onSelectFlowDetail,
  onMarkPointerInteraction,
  onReviewSingleFlow,
  onBlockFlow,
  onWhitelistAction,
  onCloseFlowConnections,
  onSetThrottle,
  onFilterByDevice,
  onFilterByChain,
  onFilterBySubnet,
  onCopyTarget,
  emptyText,
}) => {
  if (!flows.length) {
    return <div className="py-12 px-4 text-center text-xs text-muted">{emptyText}</div>;
  }

  return (
    <div className="divide-y divide-[var(--border-subtle)]">
      {flows.map((f) => {
        const fk = getFlowCacheKey(f);
        const tk = getFlowTargetKey(f);
        const rev = getCachedReview(f);
        const dual = checkIsDualAlert(f, rev);
        const checked = selectedKeys.has(fk);
        const outMeta = formatOutboundMeta(f.outbound);
        const activeCnt = Number(f.activeConns || 0);
        const totalBytes = Math.max(1, (f.uploadBytes || 0) + (f.downloadBytes || 0));
        const upPct = Math.min(100, Math.round(((f.uploadBytes || 0) / totalBytes) * 100));
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

        return (
          <div
            key={fk}
            data-audit-flow-row="1"
            onClick={() => onSelectFlowDetail(fk)}
            className={`audit-mobile-card p-3.5 space-y-2.5 transition-colors cursor-pointer ${
              dual ? 'bg-rose-500/[0.06]' : checked ? 'bg-accent/[0.06]' : ''
            }`}
          >
            {/* Header row: checkbox + target + copy + risk badge */}
            <div className="flex items-start justify-between gap-2">
              <div className="flex items-start gap-2 min-w-0 flex-1">
                <input
                  type="checkbox"
                  checked={checked}
                  onClick={(e) => e.stopPropagation()}
                  onChange={() => onToggleSelect(fk)}
                  className="mt-1 accent-emerald-500 shrink-0"
                  aria-label={`选择 ${f.target}`}
                />
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-1 flex-wrap">
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
                        onCopyTarget(f.target);
                      }}
                      className="text-muted hover:text-primary p-0.5"
                      title="复制目标"
                    >
                      <Copy className="w-3 h-3" />
                    </button>
                  </div>
                  <div className="mt-1 flex items-center gap-1.5 flex-wrap text-[11px] text-muted">
                    <button
                      type="button"
                      onClick={(e) => {
                        e.stopPropagation();
                        onFilterByDevice(f);
                      }}
                      className="font-medium text-secondary hover:text-accent"
                    >
                      {f.deviceName || f.deviceIp}
                    </button>
                    <span className="uppercase font-mono text-[10px]">{f.network}</span>
                    {f.rule && (
                      <span className="px-1.5 py-0.5 rounded bg-surface2 border border-subtle font-mono text-[10px]">
                        {formatCompactRule(f.rule)}
                      </span>
                    )}
                    {!(isAuditOnlyMode && outMeta.tone === 'neutral') && (
                      <button
                        type="button"
                        onClick={(e) => {
                          e.stopPropagation();
                          onFilterByChain(f.outbound || 'DIRECT');
                        }}
                      >
                        <Badge tone={outMeta.tone}>{outMeta.label}</Badge>
                      </button>
                    )}
                  </div>
                </div>
              </div>

              <Badge tone={riskTone} dot={f.threat === 'high_risk' || f.threat === 'suspicious'}>
                {f.state === 'whitelisted' ? '已放行' : `${f.threatLabel || '正常'} · ${f.riskScore || 0}`}
              </Badge>
            </div>

            {/* Traffic & speed row */}
            <div className="rounded-xl bg-surface2/55 border border-subtle/80 px-2.5 py-2 space-y-1.5">
              <div className="flex items-center justify-between gap-2 font-mono tnum text-[11px]">
                <div className="flex items-center gap-2">
                  <span
                    className={`w-1.5 h-1.5 rounded-full ${
                      activeCnt > 0 ? 'bg-emerald-400 animate-pulse' : 'bg-slate-600'
                    }`}
                  />
                  {activeCnt > 0 ? (
                    <span>
                      <span className="text-emerald-400 font-semibold">
                        ↑{fmtBps(f.currentUploadBps)}
                      </span>{' '}
                      <span className="text-sky-400">↓{fmtBps(f.currentDownloadBps)}</span>
                    </span>
                  ) : (
                    <span className="text-muted">历史 · {formatRelativeSeen(f.lastSeen)}</span>
                  )}
                </div>
                <span className="text-secondary">
                  ↑{fmtBytes(f.uploadBytes)} / ↓{fmtBytes(f.downloadBytes)}
                </span>
              </div>
              <div className="h-1 rounded-full bg-sky-500/35 overflow-hidden">
                <div className="h-full bg-emerald-400" style={{ width: `${upPct}%` }} />
              </div>
            </div>

            {/* Reason + AI summary */}
            {(f.reasons?.[0] || rev) && (
              <div className="text-[11px] space-y-1">
                {f.reasons?.[0] && <div className="text-secondary line-clamp-1">{f.reasons[0]}</div>}
                {rev ? (
                  <div className="flex items-center gap-1.5 flex-wrap">
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
                    <span className="text-muted line-clamp-1">{rev.category} · {rev.impact}</span>
                  </div>
                ) : (
                  !pendingTargets.has(tk) && (
                    <div onClick={(e) => e.stopPropagation()}>
                      <Button
                        size="xs"
                        variant="ghost"
                        icon={<Bot className="w-3 h-3" />}
                        onClick={() => onReviewSingleFlow(f, false)}
                      >
                        AI 研判
                      </Button>
                    </div>
                  )
                )}
              </div>
            )}

            {/* Action bar */}
            <div className="pt-0.5 flex items-center justify-between gap-2">
              <div className="flex items-center gap-1 flex-wrap">
                {f.pcdnKind === 'upload' && <Badge tone="danger">PCDN 偷跑</Badge>}
                {f.pcdnKind === 'swarm' && <Badge tone="danger">PCDN 蜂群</Badge>}
                {(f.throttledRateKbps || 0) > 0 && (
                  <Badge tone="accent">限速 {f.throttledRateKbps}K</Badge>
                )}
              </div>
              <AuditActionCell
                flow={f}
                isBusy={busyFlowKeys.has(fk)}
                isDualAlert={dual}
                disabled={filterTransitioning}
                onMarkPointerInteraction={onMarkPointerInteraction}
                onBlockFlow={onBlockFlow}
                onWhitelistAction={onWhitelistAction}
                onCloseFlowConnections={onCloseFlowConnections}
                onSetThrottle={onSetThrottle}
                onFilterByDevice={onFilterByDevice}
                onFilterBySubnet={onFilterBySubnet}
                onCopyTarget={onCopyTarget}
              />
            </div>
          </div>
        );
      })}
    </div>
  );
};

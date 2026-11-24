import React, { useState } from 'react';
import {
  Ban,
  ChevronDown,
  ChevronRight,
  Copy,
  Laptop,
  ShieldCheck,
  ShieldOff,
} from 'lucide-react';
import { Badge, Button, formatBytes as fmtBytes } from '../../../ui';
import { AuditAIReview, AuditFlowRecord } from '../../types';
import { AuditTargetGroup } from './auditFlowModel';
import {
  fmtBps,
  formatOutboundMeta,
  formatRelativeSeen,
  getFlowCacheKey,
  isProtectedBootstrapTarget,
} from './auditHelpers';

export interface AuditTargetGroupListProps {
  groups: AuditTargetGroup[];
  busyFlowKeys: Set<string>;
  getCachedReview: (f: AuditFlowRecord) => AuditAIReview | null;
  onSelectFlowDetail: (flowKey: string) => void;
  onBlockGlobal: (sampleFlow: AuditFlowRecord) => void;
  onWhitelistAction: (action: 'add' | 'remove', target: string) => void;
  onCopyTarget: (target: string) => void;
  emptyText: string;
}

export const AuditTargetGroupList: React.FC<AuditTargetGroupListProps> = ({
  groups,
  busyFlowKeys,
  getCachedReview,
  onSelectFlowDetail,
  onBlockGlobal,
  onWhitelistAction,
  onCopyTarget,
  emptyText,
}) => {
  const [expanded, setExpanded] = useState<Set<string>>(() => new Set());

  const toggleExpand = (k: string) => {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(k)) next.delete(k);
      else next.add(k);
      return next;
    });
  };

  if (!groups.length) {
    return <div className="py-12 px-4 text-center text-xs sm:text-sm text-muted">{emptyText}</div>;
  }

  return (
    <div className="divide-y divide-[var(--border-subtle)] md:max-h-[68vh] md:min-h-[360px] md:overflow-y-auto md:overscroll-contain">
      {groups.map((g) => {
        const isOpen = expanded.has(g.targetKey);
        const rev = getCachedReview(g.sampleFlow);
        const protectedTarget = isProtectedBootstrapTarget(g.target);
        const busy = g.flows.some((f) => busyFlowKeys.has(getFlowCacheKey(f)));
        const riskTone = g.allWhitelisted
          ? 'ok'
          : g.maxThreat === 'high_risk'
            ? 'danger'
            : g.maxThreat === 'suspicious'
              ? 'warn'
              : g.maxThreat === 'notice'
                ? 'accent'
                : 'ok';

        return (
          <div key={g.targetKey} className="bg-transparent">
            <div
              onClick={() => toggleExpand(g.targetKey)}
              className="px-3.5 sm:px-5 py-3 hover:bg-surfaceHover/55 transition-colors cursor-pointer flex flex-wrap items-center justify-between gap-3"
            >
              <div className="flex items-start gap-2.5 min-w-0 flex-1">
                <span className="mt-0.5 text-muted shrink-0">
                  {isOpen ? <ChevronDown className="w-4 h-4" /> : <ChevronRight className="w-4 h-4" />}
                </span>
                <div className="min-w-0 flex-1 space-y-1">
                  <div className="flex items-center gap-1.5 flex-wrap">
                    <span className="font-mono text-xs font-semibold text-primary break-all">
                      {g.target}
                    </span>
                    <button
                      type="button"
                      onClick={(e) => {
                        e.stopPropagation();
                        onCopyTarget(g.target);
                      }}
                      className="text-muted hover:text-primary p-0.5 cursor-pointer"
                      title="复制目标"
                    >
                      <Copy className="w-3 h-3" />
                    </button>
                    <Badge tone="neutral">
                      <span className="inline-flex items-center gap-1">
                        <Laptop className="w-2.5 h-2.5" />
                        {g.deviceCount} 台设备
                      </span>
                    </Badge>
                    {g.appName && <Badge tone="accent">{g.appName}</Badge>}
                    {g.pcdnKind === 'upload' && <Badge tone="danger">PCDN 偷跑</Badge>}
                    {g.pcdnKind === 'swarm' && <Badge tone="danger">PCDN 蜂群</Badge>}
                    <Badge tone={riskTone}>
                      {g.allWhitelisted ? '已放行' : `${g.maxThreatLabel} · ${g.maxRiskScore}分`}
                    </Badge>
                    {rev && (
                      <Badge
                        tone={
                          rev.verdict === 'safe_to_block'
                            ? 'danger'
                            : rev.verdict === 'caution'
                              ? 'warn'
                              : 'accent'
                        }
                      >
                        AI: {rev.verdictText}
                      </Badge>
                    )}
                  </div>
                  <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-[11px] text-muted">
                    <span className="truncate max-w-md">
                      涉及设备: {g.deviceLabels.slice(0, 4).join('、')}
                      {g.deviceLabels.length > 4 ? ` 等 ${g.deviceLabels.length} 台` : ''}
                    </span>
                    <span className="font-mono tnum">
                      {g.activeConns > 0 ? (
                        <span className="text-emerald-400 font-semibold">{g.activeConns} 活跃</span>
                      ) : (
                        '历史'
                      )}{' '}
                      / {g.connCount} 次 · {formatRelativeSeen(g.lastSeen)}
                    </span>
                  </div>
                </div>
              </div>

              <div className="flex items-center gap-3 shrink-0" onClick={(e) => e.stopPropagation()}>
                <div className="text-right font-mono tnum text-[11px] whitespace-nowrap">
                  {(g.currentUploadBps > 0 || g.currentDownloadBps > 0) && (
                    <div>
                      <span className="text-emerald-400 font-semibold">↑{fmtBps(g.currentUploadBps)}</span>{' '}
                      <span className="text-sky-400">↓{fmtBps(g.currentDownloadBps)}</span>
                    </div>
                  )}
                  <div className="text-secondary">
                    ↑{fmtBytes(g.uploadBytes)} / ↓{fmtBytes(g.downloadBytes)}
                  </div>
                </div>

                {!protectedTarget ? (
                  <div className="flex items-center gap-1.5">
                    <Button
                      size="xs"
                      variant="danger"
                      loading={busy}
                      icon={<Ban className="w-3 h-3" />}
                      onClick={() => onBlockGlobal(g.sampleFlow)}
                    >
                      全屋拉黑
                    </Button>
                    {g.allWhitelisted ? (
                      <Button
                        size="xs"
                        variant="ghost"
                        disabled={busy}
                        icon={<ShieldOff className="w-3 h-3" />}
                        onClick={() => onWhitelistAction('remove', g.target)}
                      >
                        移出
                      </Button>
                    ) : (
                      <Button
                        size="xs"
                        variant="secondary"
                        disabled={busy}
                        icon={<ShieldCheck className="w-3 h-3" />}
                        onClick={() => onWhitelistAction('add', g.target)}
                      >
                        放行
                      </Button>
                    )}
                  </div>
                ) : (
                  <Badge tone="neutral">核心保护</Badge>
                )}
              </div>
            </div>

            {isOpen && (
              <div className="bg-surface2/45 border-t border-subtle/70 divide-y divide-[var(--border-subtle)]/60">
                {g.flows.map((f) => {
                  const fk = getFlowCacheKey(f);
                  const outMeta = formatOutboundMeta(f.outbound);
                  return (
                    <div
                      key={fk}
                      onClick={() => onSelectFlowDetail(fk)}
                      className="pl-10 pr-4 py-2 hover:bg-surfaceHover/50 transition-colors cursor-pointer flex flex-wrap items-center justify-between gap-2 text-xs"
                    >
                      <div className="flex flex-wrap items-center gap-2 min-w-0">
                        <span className="font-medium text-primary">{f.deviceName || f.deviceIp}</span>
                        <span className="font-mono text-[11px] text-muted">{f.deviceIp}</span>
                        <span className="uppercase font-mono text-[10.5px] text-muted">
                          {f.network}
                          {f.destPort ? `:${f.destPort}` : ''}
                        </span>
                        <Badge tone={outMeta.tone}>{outMeta.label}</Badge>
                        {f.rule && (
                          <span className="font-mono text-[10.5px] text-muted truncate max-w-[180px]">
                            {f.rule}
                          </span>
                        )}
                      </div>
                      <div className="flex items-center gap-3 font-mono tnum text-[11px] text-secondary">
                        {(f.activeConns || 0) > 0 && (
                          <span className="text-emerald-400">
                            {f.activeConns}活跃 · ↑{fmtBps(f.currentUploadBps)}
                          </span>
                        )}
                        <span>
                          ↑{fmtBytes(f.uploadBytes)} / ↓{fmtBytes(f.downloadBytes)}
                        </span>
                        <span className="text-accent">详情 →</span>
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
};

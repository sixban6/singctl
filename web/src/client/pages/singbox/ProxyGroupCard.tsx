import React from 'react';
import {
  AlertTriangle,
  Check,
  ChevronDown,
  ChevronRight,
  Gauge,
  RefreshCw,
  Sparkles,
} from 'lucide-react';
import { Badge, Button } from '../../../ui';
import { SbProxyGroup, SbProxyNodeMeta } from '../../types';
import {
  delayToneClasses,
  formatProtocolLabel,
  isDirectOrUtilityNode,
  isGroupOutbound,
} from './proxyNodesHelpers';

export interface ProxyGroupCardProps {
  group: SbProxyGroup;
  candidates: string[];
  nodesMap: Record<string, SbProxyNodeMeta>;
  isExpanded: boolean;
  isHighlighted: boolean;
  isGroupTesting: boolean;
  testingAll: boolean;
  testingNodes: Record<string, boolean>;
  switchingKey: string | null;
  cardRef: (el: HTMLDivElement | null) => void;
  onToggleExpanded: () => void;
  onTestGroup: (e: React.MouseEvent) => void;
  onSelectNode: (nodeName: string) => void;
  onTestNode: (nodeName: string, e: React.MouseEvent) => void;
}

export const ProxyGroupCard: React.FC<ProxyGroupCardProps> = ({
  group,
  candidates,
  nodesMap,
  isExpanded,
  isHighlighted,
  isGroupTesting,
  testingAll,
  testingNodes,
  switchingKey,
  cardRef,
  onToggleExpanded,
  onTestGroup,
  onSelectNode,
  onTestNode,
}) => {
  const resolvedChainText =
    group.resolvedChain && group.resolvedChain.length > 0
      ? group.resolvedChain.join(' ➔ ')
      : group.now || '未选择';
  const chainTone = delayToneClasses(group.resolvedDelay || 0, (group.resolvedDelay || 0) > 0);

  return (
    <div
      ref={cardRef}
      className={`rounded-2xl border transition-all bg-surface1 overflow-hidden ${
        isHighlighted
          ? 'border-emerald-400/70 ring-2 ring-emerald-400/25'
          : 'border-subtle'
      }`}
    >
      <div
        role="button"
        tabIndex={0}
        onClick={onToggleExpanded}
        onKeyDown={(e) => {
          if (e.key === 'Enter' || e.key === ' ') {
            e.preventDefault();
            onToggleExpanded();
          }
        }}
        className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 px-4 py-3.5 bg-surface2/45 hover:bg-surface2/75 transition-colors cursor-pointer select-none"
      >
        <div className="min-w-0 space-y-1">
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-muted">
              {isExpanded ? <ChevronDown className="w-4 h-4" /> : <ChevronRight className="w-4 h-4" />}
            </span>
            <span className="text-sm font-bold text-primary font-mono">{group.name}</span>
            <Badge tone={group.canSelect ? 'ok' : 'accent'}>
              {group.canSelect ? '手动选择' : `${group.type} · 自动优选`}
            </Badge>
            <span className="text-[11px] font-mono text-muted tnum">
              {group.all.length} 个候选
            </span>
            {group.failedOver && (
              <Badge tone="warn">
                <span className="inline-flex items-center gap-1">
                  <AlertTriangle className="w-3 h-3" />
                  看门狗容灾中 · 原 {group.failoverFrom || '-'}
                </span>
              </Badge>
            )}
          </div>

          <div className="flex flex-wrap items-center gap-x-3 gap-y-1 pl-6 text-xs">
            <span className="text-secondary truncate max-w-full">
              当前生效：<span className="font-mono text-primary">{resolvedChainText}</span>
            </span>
            {(group.resolvedDelay || 0) > 0 && (
              <span
                className={`text-[11px] font-mono px-1.5 py-0.5 rounded border tnum ${chainTone.badge}`}
              >
                {group.resolvedDelay} ms
              </span>
            )}
          </div>

          {group.usedBy && group.usedBy.length > 0 && (
            <div className="pl-6 flex items-center gap-1.5 text-[11px] text-muted">
              <Sparkles className="w-3 h-3 text-emerald-400/80 shrink-0" />
              <span className="truncate">
                分流承接：{group.usedBy.slice(0, 4).join(' · ')}
                {group.usedBy.length > 4 ? ` 等 ${group.usedBy.length} 项` : ''}
              </span>
            </div>
          )}
        </div>

        <div className="flex items-center justify-end gap-2 pl-6 sm:pl-0 shrink-0">
          <Button
            size="xs"
            variant="secondary"
            loading={isGroupTesting}
            disabled={testingAll || group.all.length === 0}
            onClick={onTestGroup}
            icon={<Gauge className="w-3 h-3" />}
          >
            测速本组
          </Button>
        </div>
      </div>

      {isExpanded && (
        <div className="p-3.5 border-t border-subtle bg-surface1/60 space-y-3">
          {!group.canSelect && (
            <div className="rounded-xl bg-surface2/70 border border-subtle px-3 py-2 text-[11px] text-secondary">
              「{group.name}」由内核根据探测延迟自动切选最优线路（不可手动固定）；如需固定某台节点，请在{' '}
              <code className="font-mono text-primary">Proxy</code> 分组中直接选择。
            </div>
          )}

          {candidates.length === 0 ? (
            <div className="py-6 text-center text-xs text-muted">当前过滤条件下无节点</div>
          ) : (
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-2.5">
              {candidates.map((nodeName) => {
                const meta = nodesMap[nodeName];
                const selected = group.now === nodeName;
                const isDirect = isDirectOrUtilityNode(nodeName, meta);
                const isSubGroup = isGroupOutbound(meta);
                const isNodeTesting = Boolean(testingNodes[nodeName]);
                const isSwitching = switchingKey === `${group.name}:${nodeName}`;
                const tone = delayToneClasses(meta?.delay || 0, meta?.tested);

                return (
                  <div
                    key={nodeName}
                    role={group.canSelect ? 'button' : undefined}
                    tabIndex={group.canSelect ? 0 : undefined}
                    onClick={() => {
                      if (group.canSelect) onSelectNode(nodeName);
                    }}
                    onKeyDown={(e) => {
                      if (group.canSelect && (e.key === 'Enter' || e.key === ' ')) {
                        e.preventDefault();
                        onSelectNode(nodeName);
                      }
                    }}
                    className={`group relative rounded-xl border p-3 transition-all flex flex-col justify-between gap-2.5 ${
                      selected
                        ? 'border-emerald-400/70 bg-emerald-500/12 shadow-[0_0_20px_-6px_rgba(16,185,129,0.45)]'
                        : group.canSelect
                          ? 'border-subtle bg-surface2/55 hover:border-strong hover:bg-surface2 cursor-pointer'
                          : 'border-subtle bg-surface2/35'
                    } ${isSwitching ? 'opacity-70' : ''}`}
                  >
                    <div className="flex items-start justify-between gap-2">
                      <div className="text-xs font-semibold text-primary leading-snug line-clamp-2 break-words">
                        {nodeName}
                      </div>
                      {selected && (
                        <span
                          aria-label="当前选中"
                          className="w-5 h-5 rounded-full bg-emerald-500/20 border border-emerald-400/50 text-emerald-300 flex items-center justify-center shrink-0"
                        >
                          <Check className="w-3 h-3" />
                        </span>
                      )}
                    </div>

                    <div className="flex items-center justify-between gap-2 pt-1">
                      <div className="flex items-center gap-1 min-w-0">
                        <span
                          className={`text-[10px] font-mono px-1.5 py-0.5 rounded border truncate ${
                            isSubGroup
                              ? 'bg-cyan-500/10 text-cyan-300 border-cyan-500/25'
                              : isDirect
                                ? 'bg-slate-500/10 text-slate-300 border-slate-500/25'
                                : 'bg-surface1 text-secondary border-subtle'
                          }`}
                        >
                          {formatProtocolLabel(nodeName, meta)}
                        </span>
                        {meta?.udp && !isDirect && !isSubGroup && (
                          <span className="text-[10px] font-mono px-1 py-0.5 rounded bg-surface1 text-muted border border-subtle">
                            UDP
                          </span>
                        )}
                      </div>

                      {isDirect ? (
                        <span className="text-[11px] font-mono text-muted">直连</span>
                      ) : (
                        <button
                          type="button"
                          disabled={isNodeTesting}
                          onClick={(e) => onTestNode(nodeName, e)}
                          title={`单独测速「${nodeName}」`}
                          className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-md text-[11px] font-mono border transition-colors cursor-pointer tnum disabled:opacity-60 ${tone.badge}`}
                        >
                          {isNodeTesting ? (
                            <RefreshCw className="w-3 h-3 animate-spin" />
                          ) : null}
                          <span>{isNodeTesting ? '测速中' : tone.text}</span>
                        </button>
                      )}
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      )}
    </div>
  );
};

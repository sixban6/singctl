import React, { useMemo, useState } from 'react';
import {
  AlertTriangle,
  ArrowRight,
  CheckCircle2,
  ChevronDown,
  ChevronUp,
  ShieldCheck,
} from 'lucide-react';
import { Badge } from '../../../ui';
import { GroupsPreviewReport } from '../../types';

export interface GroupsLivePreviewPaneProps {
  preview: GroupsPreviewReport | null;
  hasLiveConfig: boolean;
  isDirty: boolean;
  onJumpToGroup: (groupName: string) => void;
  onJumpToRouting: () => void;
}

export const GroupsLivePreviewPane: React.FC<GroupsLivePreviewPaneProps> = ({
  preview,
  hasLiveConfig,
  isDirty,
  onJumpToGroup,
  onJumpToRouting,
}) => {
  const [showLeafPool, setShowLeafPool] = useState(false);

  const groupNameSet = useMemo(() => {
    const s = new Set<string>(['#DC']);
    for (const g of preview?.groups || []) {
      s.add(g.name);
    }
    return s;
  }, [preview]);

  return (
    <div className="lg:col-span-6 space-y-2.5">
      <div className="flex flex-wrap items-center justify-between gap-2 px-0.5">
        <div className="flex items-center gap-2 text-xs">
          <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
          <span className="font-medium text-secondary">实时节点命中预览</span>
          {preview && (
            <span className="text-muted">
              模式 <code className="font-mono text-primary">{preview.mode}</code> ·{' '}
              <strong className="text-primary">{preview.groups?.length || 0}</strong> 组
            </span>
          )}
        </div>

        {preview && preview.totalLeafNodes > 0 && (
          <button
            type="button"
            onClick={() => setShowLeafPool((v) => !v)}
            className="inline-flex items-center gap-1 text-xs text-[var(--accent)] hover:underline"
          >
            底层节点池 ({preview.totalLeafNodes})
            {showLeafPool ? (
              <ChevronUp className="w-3.5 h-3.5" />
            ) : (
              <ChevronDown className="w-3.5 h-3.5" />
            )}
          </button>
        )}
      </div>

      {hasLiveConfig && preview && (
        <div className="flex flex-wrap items-center gap-x-4 gap-y-1 px-3 py-1.5 rounded-xl bg-surface2 border border-subtle text-[11px] text-secondary">
          <span>
            未匹配规则默认兜底：
            <code className="font-mono font-semibold text-primary">
              {preview.defaultOutbound || 'Proxy'}
            </code>
          </span>
          <span>
            海外 DNS (<code className="font-mono">dns_proxy</code>) 出口：
            <code className="font-mono font-semibold text-primary">
              {preview.dnsDetour || '#VPS'}
            </code>
          </span>
        </div>
      )}

      {showLeafPool && preview && preview.leafNodes?.length > 0 && (
        <div className="p-3 rounded-xl bg-surface2 border border-subtle space-y-2 max-h-44 overflow-y-auto">
          <div className="text-[11px] text-muted flex flex-wrap items-center justify-between gap-1">
            <span>当前订阅解析出的全部真实节点（可用于核对关键字 / 协议 / 订阅名）：</span>
            {preview.subNames && preview.subNames.length > 0 && (
              <span>
                订阅源：<code className="font-mono text-primary">{preview.subNames.join(', ')}</code>
              </span>
            )}
          </div>
          <div className="flex flex-wrap gap-1.5">
            {preview.leafNodes.map((n) => (
              <span
                key={n.tag}
                className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md bg-surface1 border border-subtle text-[11px] font-mono text-primary"
              >
                <span>{n.tag}</span>
                <span className="text-[10px] text-muted uppercase">{n.type}</span>
                {n.subs && n.subs.length > 0 && (
                  <span className="text-[10px] text-[var(--accent)]">@{n.subs.join('/')}</span>
                )}
              </span>
            ))}
          </div>
        </div>
      )}

      {preview?.warnings && preview.warnings.length > 0 && (
        <div className="p-2.5 rounded-xl bg-amber-500/10 border border-amber-500/30 space-y-1 text-xs text-amber-200">
          {preview.warnings.map((w, idx) => (
            <div key={idx} className="flex items-start gap-1.5">
              <AlertTriangle className="w-3.5 h-3.5 shrink-0 mt-0.5 text-amber-400" />
              <span>{w}</span>
            </div>
          ))}
        </div>
      )}

      {!hasLiveConfig ? (
        <div className="p-6 rounded-xl bg-surface2 border border-subtle text-center text-xs text-muted">
          当前尚未生成本地 <code className="font-mono">config.json</code>。你仍可先编写并保存{' '}
          <code className="font-mono">groups.yaml</code>，下次启动或更新配置时将自动生效。
        </div>
      ) : (
        <div className="space-y-2 max-h-[464px] overflow-y-auto pr-0.5">
          {(preview?.groups || []).map((g) => {
            const isCustom = g.customized || !g.builtin;
            return (
              <div
                key={g.name}
                className={`p-3 rounded-xl border transition-colors ${
                  isCustom
                    ? 'bg-surface2/90 border-[var(--accent)]/35'
                    : 'bg-surface2/50 border-subtle'
                }`}
              >
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="flex flex-wrap items-center gap-1.5">
                    <span className="font-mono text-sm font-semibold text-primary">
                      {g.name}
                    </span>
                    <Badge tone={g.type === 'urltest' ? 'accent' : 'neutral'}>
                      {g.type === 'urltest' ? '自动测速 urltest' : '手动选择 selector'}
                    </Badge>
                    {!g.builtin ? (
                      <Badge tone="ok">新增分组</Badge>
                    ) : g.customized ? (
                      <Badge tone="accent">内置·已定制</Badge>
                    ) : (
                      <Badge tone="neutral">内置</Badge>
                    )}
                    {g.failover && (
                      <Badge tone="ok">
                        <ShieldCheck className="w-3 h-3 inline mr-0.5" />
                        看门狗容灾
                      </Badge>
                    )}
                    {g.fallbackUsed && (
                      <Badge tone="warn">0节点兜底 → {g.fallbackTag}</Badge>
                    )}
                  </div>

                  <div className="flex items-center gap-2 text-[11px]">
                    <span className="text-muted font-mono">{g.totalCount} 项</span>
                    {!isDirty && (
                      <>
                        <button
                          type="button"
                          onClick={() => onJumpToGroup(g.name)}
                          className="inline-flex items-center gap-0.5 text-secondary hover:text-primary"
                          title="跳转至节点选择查看该策略组"
                        >
                          选节点
                          <ArrowRight className="w-3 h-3" />
                        </button>
                        <button
                          type="button"
                          onClick={onJumpToRouting}
                          className="inline-flex items-center gap-0.5 text-[var(--accent)] hover:underline"
                          title="前往智能分流开关中心将业务流量绑定到此分组"
                        >
                          绑分流
                          <ArrowRight className="w-3 h-3" />
                        </button>
                      </>
                    )}
                  </div>
                </div>

                {(g.attachedTo?.length || g.default) && (
                  <div className="mt-1.5 flex flex-wrap items-center gap-3 text-[11px] text-muted">
                    {g.attachedTo && g.attachedTo.length > 0 && (
                      <span>
                        挂载至：<code className="font-mono text-secondary">{g.attachedTo.join(', ')}</code>
                      </span>
                    )}
                    {g.default && (
                      <span>
                        默认首选：<code className="font-mono text-secondary">{g.default}</code>
                      </span>
                    )}
                  </div>
                )}

                <div className="mt-2 flex flex-wrap gap-1.5">
                  {g.members.slice(0, 28).map((m) => {
                    const isSubGroup = groupNameSet.has(m);
                    return (
                      <span
                        key={m}
                        className={`px-2 py-0.5 rounded-md text-[11px] font-mono border ${
                          isSubGroup
                            ? 'bg-[var(--accent)]/10 border-[var(--accent)]/30 text-[var(--accent)]'
                            : 'bg-surface1 border-subtle text-secondary'
                        }`}
                      >
                        {m}
                      </span>
                    );
                  })}
                  {g.members.length > 28 && (
                    <span className="px-2 py-0.5 rounded-md text-[11px] text-muted bg-surface1 border border-subtle">
                      +{g.members.length - 28} 更多…
                    </span>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
};

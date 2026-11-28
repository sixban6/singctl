import React, { useEffect, useMemo, useState } from 'react';
import { RefreshCw, RotateCcw, Search, SlidersHorizontal, X } from 'lucide-react';
import { Badge, Button, SectionCard } from '../../../ui';
import {
  AuditRouteRuleDeleteRequest,
  AuditRouteRuleUpsertRequest,
  ClientRoutingPresetState,
  ClientRoutingReport,
  SbProxiesSnapshot,
  SbProxyGroup,
} from '../../types';
import { SmartRoutingCustomRulesCard } from './SmartRoutingCustomRulesCard';

export interface SmartRoutingSectionProps {
  routing: ClientRoutingReport | null;
  routingLoading: boolean;
  sbRunning: boolean;
  proxiesSnap: SbProxiesSnapshot | null;
  savingId: string | null;
  resetting: boolean;
  customRuleBusy?: boolean;
  onReload: () => void;
  onOpenResetConfirm: () => void;
  onUpdatePreset: (
    item: ClientRoutingPresetState,
    nextEnabled: boolean,
    nextOutbound?: string,
    toastLabel?: string,
  ) => void;
  onUpsertCustomRule?: (req: AuditRouteRuleUpsertRequest) => void;
  onDeleteCustomRule?: (req: AuditRouteRuleDeleteRequest) => void;
  onJumpToGroup: (groupTag: string) => void;
}

export const SmartRoutingSection: React.FC<SmartRoutingSectionProps> = ({
  routing,
  routingLoading,
  sbRunning,
  proxiesSnap,
  savingId,
  resetting,
  customRuleBusy = false,
  onReload,
  onOpenResetConfirm,
  onUpdatePreset,
  onUpsertCustomRule,
  onDeleteCustomRule,
  onJumpToGroup,
}) => {
  const [activeCategory, setActiveCategory] = useState<string>('ai');
  const [searchQuery, setSearchQuery] = useState('');

  useEffect(() => {
    if (
      activeCategory !== 'all' &&
      routing?.categories &&
      routing.categories.length > 0 &&
      !routing.categories.some((c) => c.id === activeCategory)
    ) {
      setActiveCategory(routing.categories[0].id);
    }
  }, [routing, activeCategory]);

  const categoryCounts = useMemo(() => {
    const counts: Record<string, number> = {};
    for (const item of routing?.items || []) {
      counts[item.category] = (counts[item.category] || 0) + 1;
    }
    return counts;
  }, [routing]);

  const groupMap = useMemo(() => {
    const map = new Map<string, SbProxyGroup>();
    for (const g of proxiesSnap?.groups || []) {
      map.set(g.name, g);
    }
    return map;
  }, [proxiesSnap]);

  const filteredItems = useMemo(() => {
    const items = routing?.items || [];
    const q = searchQuery.trim().toLowerCase();
    return items.filter((it) => {
      if (!q && activeCategory !== 'all' && it.category !== activeCategory) return false;
      if (!q) return true;
      return (
        it.name.toLowerCase().includes(q) ||
        it.id.toLowerCase().includes(q) ||
        it.description.toLowerCase().includes(q) ||
        it.domainsSummary.toLowerCase().includes(q) ||
        it.effectiveDest.toLowerCase().includes(q) ||
        it.categoryLabel.toLowerCase().includes(q)
      );
    });
  }, [routing, activeCategory, searchQuery]);

  const isCrossCategoryView = activeCategory === 'all' || Boolean(searchQuery.trim());
  const directLabel = routing?.directTag || '#DC';

  return (
    <SectionCard
      title="智能分流开关中心"
      icon={<SlidersHorizontal className="w-4 h-4" />}
      subtitle={
        routing
          ? `已开启 ${routing.enabledCount}/${routing.totalCount} 项代理分流 · 关闭默认直连 (${routing.directTag}) · 切换后即时热生效`
          : '加载分流规则列表…'
      }
      actions={
        <div className="flex flex-wrap items-center gap-2">
          {routing && routing.customCount > 0 && (
            <Badge tone="accent">已自定义 {routing.customCount} 项</Badge>
          )}
          <Button
            size="xs"
            loading={routingLoading}
            onClick={onReload}
            icon={<RefreshCw className="w-3 h-3" />}
          >
            刷新
          </Button>
          <Button
            size="xs"
            variant="ghost"
            disabled={!routing || resetting || !!savingId}
            onClick={onOpenResetConfirm}
            icon={<RotateCcw className="w-3 h-3" />}
          >
            恢复推荐默认
          </Button>
        </div>
      }
    >
      <div className="space-y-4">
        {routing && !routing.hasConfig && (
          <div className="rounded-xl border border-amber-500/30 bg-amber-500/10 px-3.5 py-2.5 text-xs text-amber-200">
            尚未检测到 <code className="font-mono">config.json</code>，当前预设策略将预先保存，点击上方「从订阅生成配置」或启动内核时自动生效。
          </div>
        )}

        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-3">
          <div className="flex items-center gap-1.5 overflow-x-auto no-scrollbar pb-1 sm:pb-0 sm:flex-wrap">
            {(routing?.categories || []).map((cat) => (
              <button
                key={cat.id}
                type="button"
                onClick={() => setActiveCategory(cat.id)}
                className={`px-3 py-1.5 rounded-lg text-xs font-medium whitespace-nowrap shrink-0 transition-colors cursor-pointer ${
                  !searchQuery.trim() && activeCategory === cat.id
                    ? 'bg-[var(--accent)] text-white shadow-sm'
                    : 'bg-surface2 text-secondary hover:text-primary border border-subtle'
                }`}
              >
                {cat.label} ({categoryCounts[cat.id] || 0})
              </button>
            ))}
            <button
              type="button"
              onClick={() => setActiveCategory('all')}
              className={`px-3 py-1.5 rounded-lg text-xs font-medium whitespace-nowrap shrink-0 transition-colors cursor-pointer ${
                !searchQuery.trim() && activeCategory === 'all'
                  ? 'bg-[var(--accent)] text-white shadow-sm'
                  : 'bg-surface2 text-secondary hover:text-primary border border-subtle'
              }`}
            >
              全部 ({routing?.items.length ?? 0})
            </button>
          </div>

          <div className="relative w-full lg:w-64 shrink-0">
            <Search className="w-3.5 h-3.5 text-muted absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="搜索服务或域名…"
              className="sc-input w-full h-8 pl-8 pr-7 text-xs"
            />
            {searchQuery && (
              <button
                type="button"
                onClick={() => setSearchQuery('')}
                aria-label="清空搜索"
                className="absolute right-2 top-1/2 -translate-y-1/2 text-muted hover:text-primary cursor-pointer"
              >
                <X className="w-3.5 h-3.5" />
              </button>
            )}
          </div>
        </div>

        {!searchQuery.trim() && activeCategory !== 'all' && routing?.categories && (
          <div className="rounded-xl bg-surface2/70 border border-subtle px-3.5 py-2 text-xs text-secondary">
            {routing.categories.find((c) => c.id === activeCategory)?.description}
          </div>
        )}

        {routingLoading && !routing ? (
          <div className="py-10 text-center text-xs text-muted">正在加载分流规则…</div>
        ) : filteredItems.length === 0 ? (
          <div className="py-10 text-center text-xs text-muted">
            未找到匹配「{searchQuery}」的分流服务
          </div>
        ) : (
          <div className="divide-y divide-subtle rounded-xl border border-subtle bg-surface1 overflow-hidden">
            {filteredItems.map((item) => {
              const isSaving = savingId === item.id;
              const groupOptions = routing?.groups || [];
              const hasSelectedInOptions = groupOptions.some((g) => g.tag === item.selectedGroup);
              const liveGroup = item.enabled ? groupMap.get(item.effectiveDest) : undefined;
              const resolvedLeaf = liveGroup?.resolvedNode || liveGroup?.now;

              return (
                <div
                  key={item.id}
                  className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 px-4 py-3 hover:bg-surface2/40 transition-colors"
                >
                  <div className="min-w-0 space-y-1">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="text-sm font-semibold text-primary">{item.name}</span>
                      {isCrossCategoryView && (
                        <span className="text-[11px] px-2 py-0.5 rounded-md bg-surface2 text-secondary border border-subtle">
                          {item.categoryLabel}
                        </span>
                      )}
                      {item.enabled ? (
                        <Badge
                          tone={
                            item.effectiveDest === '#VPS' || item.effectiveDest === 'AI'
                              ? 'accent'
                              : 'ok'
                          }
                        >
                          走 {item.effectiveDest}
                        </Badge>
                      ) : (
                        <Badge tone="neutral">直连 {directLabel}</Badge>
                      )}
                      {item.enabled && sbRunning && resolvedLeaf && (
                        <button
                          type="button"
                          onClick={() => onJumpToGroup(item.effectiveDest)}
                          title={`点击前往「节点选择」切换 ${item.effectiveDest} 的具体节点`}
                          className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md text-[11px] font-mono bg-surface2/80 border border-subtle text-secondary hover:text-primary hover:border-strong transition-colors cursor-pointer max-w-[240px]"
                        >
                          <span className="truncate">
                            → {resolvedLeaf}
                            {(liveGroup?.resolvedDelay || 0) > 0 ? ` (${liveGroup?.resolvedDelay}ms)` : ''}
                          </span>
                        </button>
                      )}
                      {item.customized && (
                        <span className="text-[10px] font-medium px-1.5 py-0.5 rounded bg-amber-500/15 text-amber-400 border border-amber-500/20">
                          已自定义
                        </span>
                      )}
                    </div>
                    <p className="text-xs text-secondary leading-relaxed">{item.description}</p>
                    <div className="text-[11px] font-mono text-muted truncate">{item.domainsSummary}</div>
                  </div>

                  <div className="flex items-center justify-between sm:justify-end gap-3 w-full sm:w-auto shrink-0 pt-1 sm:pt-0">
                    <div className="flex items-center gap-1.5 flex-1 min-w-0 sm:flex-initial">
                      <span className="text-[11px] text-muted hidden md:inline">节点组</span>
                      <select
                        aria-label={`${item.name} 目标策略组`}
                        value={item.selectedGroup}
                        disabled={isSaving || resetting || groupOptions.length === 0}
                        onChange={(e) => {
                          const nextGroup = e.target.value;
                          if (!nextGroup) return;
                          const toastText = item.enabled
                            ? `「${item.name}」分流组已切换至 ${nextGroup}（${routing?.hasConfig ? '已热生效' : '已保存'}）`
                            : `已开启「${item.name}」并指派至 ${nextGroup}（${routing?.hasConfig ? '已热生效' : '已保存'}）`;
                          onUpdatePreset(item, true, nextGroup, toastText);
                        }}
                        title={
                          item.enabled
                            ? `当前流量路由至 ${item.selectedGroup}，可独立切换其他分组`
                            : `当前直连 ${routing?.directTag || '#DC'}，选择分组或开启右侧开关后即刻代理`
                        }
                        className={`sc-input h-8 px-2.5 text-xs font-mono w-full sm:w-auto min-w-[104px] transition-opacity ${
                          item.enabled ? 'text-primary' : 'text-muted opacity-70'
                        }`}
                      >
                        {!hasSelectedInOptions && item.selectedGroup && (
                          <option value={item.selectedGroup}>{item.selectedGroup}</option>
                        )}
                        {groupOptions.map((g) => (
                          <option key={g.tag} value={g.tag}>
                            {g.tag}
                            {g.tag === item.defaultOutbound ? ' (推荐)' : ''}
                          </option>
                        ))}
                      </select>
                    </div>

                    <button
                      type="button"
                      role="switch"
                      aria-checked={item.enabled}
                      aria-label={`切换 ${item.name} 分流开关`}
                      disabled={isSaving || resetting}
                      onClick={() => onUpdatePreset(item, !item.enabled)}
                      className={`relative inline-flex h-6 w-11 shrink-0 cursor-pointer items-center rounded-full border transition-colors focus:outline-none disabled:opacity-50 ${
                        item.enabled
                          ? 'bg-[var(--accent)] border-transparent'
                          : 'bg-surface2 border-strong'
                      }`}
                    >
                      <span
                        className={`inline-block h-4 w-4 transform rounded-full bg-white shadow transition-transform ${
                          item.enabled ? 'translate-x-5' : 'translate-x-1'
                        }`}
                      />
                    </button>
                  </div>
                </div>
              );
            })}
          </div>
        )}

        {routing && onUpsertCustomRule && onDeleteCustomRule && (
          <SmartRoutingCustomRulesCard
            routing={routing}
            busy={customRuleBusy || resetting}
            onChangeOutbound={onUpsertCustomRule}
            onDeleteRule={onDeleteCustomRule}
          />
        )}
      </div>
    </SectionCard>
  );
};

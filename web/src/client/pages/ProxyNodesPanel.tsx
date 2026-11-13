import React, { useEffect, useMemo, useRef, useState } from 'react';
import {
  Activity,
  AlertTriangle,
  ArrowUpDown,
  Check,
  ChevronDown,
  ChevronRight,
  Cpu,
  Filter,
  Gauge,
  Play,
  RefreshCw,
  Search,
  Sparkles,
  X,
} from 'lucide-react';
import { Badge, Button, SectionCard, useToast } from '../../ui';
import { clientApi } from '../api';
import { SbProxiesSnapshot, SbProxyGroup, SbProxyNodeMeta } from '../types';

const EXPANDED_STORAGE_KEY = 'sc:sb:expandedGroups';

export interface ProxyNodesPanelProps {
  running: boolean;
  busy: boolean;
  snapshot: SbProxiesSnapshot | null;
  loading: boolean;
  focusGroup: string | null;
  onClearFocusGroup: () => void;
  onRefresh: () => Promise<void>;
  onSnapshotChange: (next: SbProxiesSnapshot) => void;
  onStartCore: () => void;
}

function loadExpandedPrefs(): Record<string, boolean> {
  if (typeof window === 'undefined') return {};
  try {
    const raw = localStorage.getItem(EXPANDED_STORAGE_KEY);
    if (!raw) return {};
    const parsed = JSON.parse(raw);
    return parsed && typeof parsed === 'object' ? parsed : {};
  } catch {
    return {};
  }
}

function saveExpandedPrefs(next: Record<string, boolean>) {
  try {
    localStorage.setItem(EXPANDED_STORAGE_KEY, JSON.stringify(next));
  } catch {
    // ignore storage errors
  }
}

function defaultExpandedForGroup(g: SbProxyGroup): boolean {
  return (
    g.name === 'Proxy' ||
    g.name === '#VPS' ||
    g.name === 'GLOBAL' ||
    Boolean(g.failedOver)
  );
}

function isDirectOrUtilityNode(name: string, meta?: SbProxyNodeMeta): boolean {
  const lower = name.trim().toLowerCase();
  const typeLower = (meta?.type || '').trim().toLowerCase();
  return (
    lower === '#dc' ||
    lower === 'direct' ||
    lower === 'directconn' ||
    lower === 'direct-out' ||
    lower === 'block' ||
    lower === 'block-out' ||
    lower === 'reject' ||
    typeLower === 'direct' ||
    typeLower === 'block' ||
    typeLower === 'dns'
  );
}

function isGroupOutbound(meta?: SbProxyNodeMeta): boolean {
  const t = (meta?.type || '').trim().toLowerCase();
  return t === 'selector' || t === 'urltest' || t === 'fallback' || t === 'loadbalance';
}

function delayToneClasses(delay: number, tested?: boolean): { text: string; badge: string } {
  if (delay > 0) {
    if (delay <= 120) {
      return {
        text: `${delay} ms`,
        badge: 'text-emerald-300 bg-emerald-500/15 border-emerald-500/30 hover:bg-emerald-500/25',
      };
    }
    if (delay <= 350) {
      return {
        text: `${delay} ms`,
        badge: 'text-amber-300 bg-amber-500/15 border-amber-500/30 hover:bg-amber-500/25',
      };
    }
    return {
      text: `${delay} ms`,
      badge: 'text-orange-300 bg-orange-500/15 border-orange-500/30 hover:bg-orange-500/25',
    };
  }
  if (tested) {
    return {
      text: '超时',
      badge: 'text-rose-300/90 bg-rose-500/10 border-rose-500/25 hover:bg-rose-500/20',
    };
  }
  return {
    text: '测速',
    badge: 'text-muted bg-surface1 border-subtle hover:text-primary hover:border-strong',
  };
}

function formatProtocolLabel(name: string, meta?: SbProxyNodeMeta): string {
  if (isDirectOrUtilityNode(name, meta)) {
    const t = (meta?.type || '').toLowerCase();
    if (t === 'block' || name.toLowerCase().includes('block')) return 'Block';
    return 'Direct';
  }
  const rawType = (meta?.type || '').trim();
  if (!rawType || rawType === 'Unknown') return 'Proxy';
  return rawType;
}

export const ProxyNodesPanel: React.FC<ProxyNodesPanelProps> = ({
  running,
  busy,
  snapshot,
  loading,
  focusGroup,
  onClearFocusGroup,
  onRefresh,
  onSnapshotChange,
  onStartCore,
}) => {
  const { success, error } = useToast();

  const [expandedMap, setExpandedMap] = useState<Record<string, boolean>>(() => loadExpandedPrefs());
  const [searchQuery, setSearchQuery] = useState('');
  const [sortByDelay, setSortByDelay] = useState(false);
  const [onlyAvailable, setOnlyAvailable] = useState(false);

  const [testingAll, setTestingAll] = useState(false);
  const [testingGroups, setTestingGroups] = useState<Record<string, boolean>>({});
  const [testingNodes, setTestingNodes] = useState<Record<string, boolean>>({});
  const [switchingKey, setSwitchingKey] = useState<string | null>(null);
  const [highlightedGroup, setHighlightedGroup] = useState<string | null>(null);

  const cardRefs = useRef<Record<string, HTMLDivElement | null>>({});

  useEffect(() => {
    if (!focusGroup || !snapshot?.running) return;
    setExpandedMap((prev) => {
      const next = { ...prev, [focusGroup]: true };
      saveExpandedPrefs(next);
      return next;
    });
    setHighlightedGroup(focusGroup);

    const scrollTimer = window.setTimeout(() => {
      cardRefs.current[focusGroup]?.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    }, 80);
    const clearTimer = window.setTimeout(() => {
      setHighlightedGroup((cur) => (cur === focusGroup ? null : cur));
    }, 2000);
    onClearFocusGroup();

    return () => {
      window.clearTimeout(scrollTimer);
      window.clearTimeout(clearTimer);
    };
  }, [focusGroup, snapshot?.running, onClearFocusGroup]);

  const toggleGroupExpanded = (groupName: string, currentExpanded: boolean) => {
    setExpandedMap((prev) => {
      const next = { ...prev, [groupName]: !currentExpanded };
      saveExpandedPrefs(next);
      return next;
    });
  };

  const setAllGroupsExpanded = (expand: boolean) => {
    if (!snapshot?.groups?.length) return;
    const next: Record<string, boolean> = { ...expandedMap };
    for (const g of snapshot.groups) {
      next[g.name] = expand;
    }
    setExpandedMap(next);
    saveExpandedPrefs(next);
  };

  const resolveGroupChainOptimistically = (
    groupName: string,
    byName: Map<string, SbProxyGroup>,
    nodes: Record<string, SbProxyNodeMeta>,
  ) => {
    const chain: string[] = [];
    const visited = new Set<string>();
    let curName = groupName;
    while (curName && !visited.has(curName)) {
      visited.add(curName);
      const grp = byName.get(curName);
      if (!grp || !grp.now) break;
      chain.push(grp.now);
      if (!byName.has(grp.now)) break;
      curName = grp.now;
    }
    const leaf = chain.length > 0 ? chain[chain.length - 1] : undefined;
    const leafDelay = leaf ? nodes[leaf]?.delay ?? 0 : 0;
    return { resolvedChain: chain, resolvedNode: leaf, resolvedDelay: leafDelay };
  };

  const handleSelectNode = async (group: SbProxyGroup, target: string) => {
    if (!group.canSelect || group.now === target || switchingKey) return;
    const prevSnapshot = snapshot;

    // 乐观切换：同步递归解析当前分组与引用该分组的上层父分组链表
    if (snapshot) {
      const staged = snapshot.groups.map((g) =>
        g.name === group.name
          ? {
              ...g,
              now: target,
              failedOver: false,
              failoverFrom: undefined,
              failoverSince: undefined,
            }
          : g,
      );
      const byName = new Map(staged.map((g) => [g.name, g]));
      const updatedGroups = staged.map((g) => {
        if (g.name !== group.name && g.now !== group.name && !g.resolvedChain?.includes(group.name)) {
          return g;
        }
        return {
          ...g,
          ...resolveGroupChainOptimistically(g.name, byName, snapshot.nodes),
        };
      });
      onSnapshotChange({ ...snapshot, groups: updatedGroups });
    }

    setSwitchingKey(`${group.name}:${target}`);
    try {
      const res = await clientApi.switchSbProxy(group.name, target);
      if (res.snapshot) {
        onSnapshotChange(res.snapshot);
      }
      success(res.message || `已将「${group.name}」切换至 ${target}`);
    } catch (err: unknown) {
      if (prevSnapshot) onSnapshotChange(prevSnapshot);
      error(`切换失败：${err instanceof Error ? err.message : '未知错误'}`);
    } finally {
      setSwitchingKey(null);
    }
  };

  const applyDelaysOptimistically = (delays: Record<string, number>) => {
    if (!snapshot) return;
    const nextNodes: Record<string, SbProxyNodeMeta> = { ...snapshot.nodes };
    for (const [name, delay] of Object.entries(delays)) {
      const existing = nextNodes[name] || { name, type: 'Proxy', delay: 0 };
      nextNodes[name] = {
        ...existing,
        delay,
        tested: true,
      };
    }
    onSnapshotChange({ ...snapshot, nodes: nextNodes });
  };

  const handleTestAll = async () => {
    if (testingAll) return;
    setTestingAll(true);
    try {
      const res = await clientApi.testSbProxyDelay({ group: '__all__' });
      if (res.snapshot) {
        onSnapshotChange(res.snapshot);
      } else if (res.delays) {
        applyDelaysOptimistically(res.delays);
      }
      success(`全量测速完成：${res.okCount}/${res.testedCount} 个节点可达`);
    } catch (err: unknown) {
      error(`全部测速失败：${err instanceof Error ? err.message : '未知错误'}`);
    } finally {
      setTestingAll(false);
    }
  };

  const handleTestGroup = async (groupName: string, e: React.MouseEvent) => {
    e.stopPropagation();
    if (testingGroups[groupName] || testingAll) return;
    setTestingGroups((prev) => ({ ...prev, [groupName]: true }));
    try {
      const res = await clientApi.testSbProxyDelay({ group: groupName });
      if (res.snapshot) {
        onSnapshotChange(res.snapshot);
      } else if (res.delays) {
        applyDelaysOptimistically(res.delays);
      }
      success(`「${groupName}」测速完成：${res.okCount}/${res.testedCount} 个可用`);
    } catch (err: unknown) {
      error(`测速「${groupName}」失败：${err instanceof Error ? err.message : '未知错误'}`);
    } finally {
      setTestingGroups((prev) => ({ ...prev, [groupName]: false }));
    }
  };

  const handleTestNode = async (nodeName: string, e: React.MouseEvent) => {
    e.stopPropagation();
    if (testingNodes[nodeName]) return;
    setTestingNodes((prev) => ({ ...prev, [nodeName]: true }));
    try {
      const res = await clientApi.testSbProxyDelay({ node: nodeName });
      if (res.snapshot) {
        onSnapshotChange(res.snapshot);
      } else if (res.delays) {
        applyDelaysOptimistically(res.delays);
      }
      const d = res.delays?.[nodeName] ?? 0;
      if (d > 0) {
        success(`「${nodeName}」当前延迟 ${d} ms`);
      } else {
        error(`「${nodeName}」测速超时或不可达`);
      }
    } catch (err: unknown) {
      error(`测速「${nodeName}」失败：${err instanceof Error ? err.message : '未知错误'}`);
    } finally {
      setTestingNodes((prev) => ({ ...prev, [nodeName]: false }));
    }
  };

  const filteredGroups = useMemo(() => {
    const groups = snapshot?.groups || [];
    const nodesMap = snapshot?.nodes || {};
    const q = searchQuery.trim().toLowerCase();

    return groups
      .map((group) => {
        const groupMatched = q !== '' && group.name.toLowerCase().includes(q);
        let candidates = [...group.all];

        if (q && !groupMatched) {
          candidates = candidates.filter((n) => n.toLowerCase().includes(q));
        }

        if (onlyAvailable) {
          candidates = candidates.filter((n) => {
            if (n === group.now || isDirectOrUtilityNode(n, nodesMap[n])) return true;
            const meta = nodesMap[n];
            if (!meta?.tested) return true;
            return meta.delay > 0;
          });
        }

        if (sortByDelay) {
          candidates.sort((a, b) => {
            const metaA = nodesMap[a];
            const metaB = nodesMap[b];
            const rank = (name: string, meta?: SbProxyNodeMeta): number => {
              if (meta && meta.delay > 0) return meta.delay;
              if (isDirectOrUtilityNode(name, meta)) return 90000;
              if (!meta?.tested) return 95000;
              return 99999; // tested timeout
            };
            const diff = rank(a, metaA) - rank(b, metaB);
            return diff !== 0 ? diff : a.localeCompare(b);
          });
        }

        return {
          group,
          candidates,
          searchAutoExpand: q !== '' && (groupMatched || candidates.length > 0),
        };
      })
      .filter(({ group, candidates }) => {
        if (!q) return true;
        return group.name.toLowerCase().includes(q) || candidates.length > 0;
      });
  }, [snapshot, searchQuery, onlyAvailable, sortByDelay]);

  if (!running) {
    return (
      <SectionCard
        title="策略组与节点选择"
        icon={<Cpu className="w-4 h-4" />}
        subtitle="实时节点延迟探测与出站切换"
      >
        <div className="py-12 px-4 text-center space-y-3">
          <div className="w-11 h-11 rounded-2xl bg-surface2 border border-subtle flex items-center justify-center mx-auto text-muted">
            <Activity className="w-5 h-5" />
          </div>
          <div className="text-sm font-semibold text-primary">sing-box 核心当前未运行</div>
          <p className="text-xs text-secondary max-w-md mx-auto leading-relaxed">
            启动核心后，即可在此直接查看所有策略组、测试订阅节点延迟并一键切换出口线路，无需额外打开外部面板。
          </p>
          <div className="pt-1">
            <Button variant="primary" size="sm" disabled={busy} onClick={onStartCore} icon={<Play className="w-3.5 h-3.5" />}>
              立即启动 sing-box
            </Button>
          </div>
        </div>
      </SectionCard>
    );
  }

  const groupsCount = snapshot?.groups?.length ?? 0;

  return (
    <div className="space-y-4">
      <SectionCard
        title="策略组与节点选择"
        icon={<Cpu className="w-4 h-4" />}
        subtitle={
          snapshot?.running
            ? `共 ${groupsCount} 个策略组${
                snapshot.primaryGroup && snapshot.primaryNode
                  ? ` · 主出口 ${snapshot.primaryGroup} → ${snapshot.primaryNode}${
                      snapshot.primaryDelay ? ` (${snapshot.primaryDelay}ms)` : ''
                    }`
                  : ''
              }`
            : '正在读取运行态策略组…'
        }
        actions={
          <div className="flex flex-wrap items-center gap-2">
            <Button
              size="xs"
              variant="secondary"
              loading={loading}
              onClick={() => void onRefresh()}
              icon={<RefreshCw className="w-3 h-3" />}
            >
              刷新
            </Button>
            <Button
              size="xs"
              variant="primary"
              loading={testingAll}
              disabled={!snapshot?.running || groupsCount === 0}
              onClick={() => void handleTestAll()}
              icon={<Gauge className="w-3 h-3" />}
            >
              全部测速
            </Button>
          </div>
        }
      >
        <div className="space-y-4">
          {/* 搜索与排序工具栏 */}
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-2.5">
            <div className="relative flex-1 max-w-sm">
              <Search className="w-3.5 h-3.5 text-muted absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none" />
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="搜索分组或节点名称（如 香港 / JP / VPS）…"
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

            <div className="flex flex-wrap items-center gap-1.5">
              <button
                type="button"
                onClick={() => setSortByDelay((v) => !v)}
                className={`inline-flex items-center gap-1.5 h-8 px-2.5 rounded-lg text-xs border transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                  sortByDelay
                    ? 'bg-[var(--accent-soft)] text-emerald-300 border-emerald-500/35'
                    : 'bg-surface2 text-secondary border-subtle hover:text-primary'
                }`}
              >
                <ArrowUpDown className="w-3 h-3" />
                <span>按延迟升序</span>
              </button>

              <button
                type="button"
                onClick={() => setOnlyAvailable((v) => !v)}
                className={`inline-flex items-center gap-1.5 h-8 px-2.5 rounded-lg text-xs border transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                  onlyAvailable
                    ? 'bg-[var(--accent-soft)] text-emerald-300 border-emerald-500/35'
                    : 'bg-surface2 text-secondary border-subtle hover:text-primary'
                }`}
              >
                <Filter className="w-3 h-3" />
                <span>仅看可用</span>
              </button>

              {groupsCount > 1 && !searchQuery && (
                <>
                  <button
                    type="button"
                    onClick={() => setAllGroupsExpanded(true)}
                    className="h-8 px-2.5 rounded-lg text-xs bg-surface2 text-secondary border border-subtle hover:text-primary transition-colors whitespace-nowrap shrink-0 cursor-pointer"
                  >
                    全部展开
                  </button>
                  <button
                    type="button"
                    onClick={() => setAllGroupsExpanded(false)}
                    className="h-8 px-2.5 rounded-lg text-xs bg-surface2 text-secondary border border-subtle hover:text-primary transition-colors whitespace-nowrap shrink-0 cursor-pointer"
                  >
                    收起
                  </button>
                </>
              )}
            </div>
          </div>

          {loading && !snapshot ? (
            <div className="py-10 text-center text-xs text-muted">正在加载策略组与节点列表…</div>
          ) : snapshot?.error && groupsCount === 0 ? (
            <div className="rounded-xl border border-amber-500/30 bg-amber-500/10 px-4 py-3 text-xs text-amber-200 flex flex-col sm:flex-row sm:items-center justify-between gap-2">
              <span>{snapshot.error}</span>
              <Button size="xs" onClick={() => void onRefresh()}>
                重试
              </Button>
            </div>
          ) : filteredGroups.length === 0 ? (
            <div className="py-10 text-center text-xs text-muted">
              {searchQuery ? `未找到匹配「${searchQuery}」的策略组或节点` : '当前配置未包含可管理的策略组'}
            </div>
          ) : (
            <div className="space-y-3">
              {filteredGroups.map(({ group, candidates, searchAutoExpand }) => {
                const isExpanded = searchAutoExpand || (expandedMap[group.name] ?? defaultExpandedForGroup(group));
                const isGroupTesting = Boolean(testingGroups[group.name]);
                const nodesMap = snapshot?.nodes || {};
                const resolvedChainText =
                  group.resolvedChain && group.resolvedChain.length > 0
                    ? group.resolvedChain.join(' ➔ ')
                    : group.now || '未选择';
                const chainTone = delayToneClasses(group.resolvedDelay || 0, (group.resolvedDelay || 0) > 0);
                const isHighlighted = highlightedGroup === group.name;

                return (
                  <div
                    key={group.name}
                    ref={(el) => {
                      cardRefs.current[group.name] = el;
                    }}
                    className={`rounded-2xl border transition-all bg-surface1 overflow-hidden ${
                      isHighlighted
                        ? 'border-emerald-400/70 ring-2 ring-emerald-400/25'
                        : 'border-subtle'
                    }`}
                  >
                    {/* 策略组头部（可点击展开/收起） */}
                    <div
                      role="button"
                      tabIndex={0}
                      onClick={() => toggleGroupExpanded(group.name, isExpanded)}
                      onKeyDown={(e) => {
                        if (e.key === 'Enter' || e.key === ' ') {
                          e.preventDefault();
                          toggleGroupExpanded(group.name, isExpanded);
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
                          onClick={(e) => void handleTestGroup(group.name, e)}
                          icon={<Gauge className="w-3 h-3" />}
                        >
                          测速本组
                        </Button>
                      </div>
                    </div>

                    {/* 展开的节点网格 */}
                    {isExpanded && (
                      <div className="p-3.5 border-t border-subtle bg-surface1/60 space-y-3">
                        {!group.canSelect && (
                          <div className="rounded-xl bg-surface2/70 border border-subtle px-3 py-2 text-[11px] text-secondary">
                            「{group.name}」由内核根据探测延迟自动切选最优线路（不可手动固定）；如需固定某台节点，请在 <code className="font-mono text-primary">Proxy</code> 分组中直接选择。
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
                                    if (group.canSelect) void handleSelectNode(group, nodeName);
                                  }}
                                  onKeyDown={(e) => {
                                    if (group.canSelect && (e.key === 'Enter' || e.key === ' ')) {
                                      e.preventDefault();
                                      void handleSelectNode(group, nodeName);
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
                                        onClick={(e) => void handleTestNode(nodeName, e)}
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
              })}
            </div>
          )}
        </div>
      </SectionCard>
    </div>
  );
};

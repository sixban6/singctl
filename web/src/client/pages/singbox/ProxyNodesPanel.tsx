import React, { useEffect, useMemo, useRef, useState } from 'react';
import {
  Activity,
  ArrowUpDown,
  Cpu,
  Filter,
  Gauge,
  Play,
  RefreshCw,
  Search,
  X,
} from 'lucide-react';
import { Button, SectionCard, useToast } from '../../../ui';
import { clientApi } from '../../api';
import { SbProxiesSnapshot, SbProxyGroup, SbProxyNodeMeta } from '../../types';
import { ProxyGroupCard } from './ProxyGroupCard';
import {
  defaultExpandedForGroup,
  groupDisplayRank,
  isDirectOrUtilityNode,
  loadExpandedPrefs,
  resolveGroupChainOptimistically,
  saveExpandedPrefs,
} from './proxyNodesHelpers';

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

  const handleSelectNode = async (group: SbProxyGroup, target: string) => {
    if (!group.canSelect || group.now === target || switchingKey) return;
    const prevSnapshot = snapshot;

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
    const mode = snapshot?.mode;
    const groups = [...(snapshot?.groups || [])].sort((a, b) => {
      const diff = groupDisplayRank(a, mode) - groupDisplayRank(b, mode);
      return diff !== 0 ? diff : a.name.localeCompare(b.name);
    });
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
              return 99999;
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
            <Button
              variant="primary"
              size="sm"
              disabled={busy}
              onClick={onStartCore}
              icon={<Play className="w-3.5 h-3.5" />}
            >
              立即启动 sing-box
            </Button>
          </div>
        </div>
      </SectionCard>
    );
  }

  const groupsCount = snapshot?.groups?.length ?? 0;
  const nodesMap = snapshot?.nodes || {};

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
                return (
                  <ProxyGroupCard
                    key={group.name}
                    group={group}
                    candidates={candidates}
                    nodesMap={nodesMap}
                    isExpanded={isExpanded}
                    isHighlighted={highlightedGroup === group.name}
                    isGroupTesting={Boolean(testingGroups[group.name])}
                    testingAll={testingAll}
                    testingNodes={testingNodes}
                    switchingKey={switchingKey}
                    cardRef={(el) => {
                      cardRefs.current[group.name] = el;
                    }}
                    onToggleExpanded={() => toggleGroupExpanded(group.name, isExpanded)}
                    onTestGroup={(e) => void handleTestGroup(group.name, e)}
                    onSelectNode={(nodeName) => void handleSelectNode(group, nodeName)}
                    onTestNode={(nodeName, e) => void handleTestNode(nodeName, e)}
                  />
                );
              })}
            </div>
          )}
        </div>
      </SectionCard>
    </div>
  );
};

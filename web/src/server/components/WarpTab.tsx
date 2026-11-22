import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  ActiveDestinationGroup,
  WarpConnectionsResponse,
  WarpNodeSummary,
  WarpPresetItem,
  WarpRoutingConfig,
  WarpRoutingMode,
  WarpRoutingStatusResponse,
} from '../types';
import { api } from '../api';
import { WARP_CONNS_CACHE_KEY, WARP_ROUTING_CACHE_KEY } from '../prefetch';
import { peekCachedQuery, useVisibilityInterval, writeCachedQuery } from '../../hooks';
import { useToast } from '../../ui';
import { RefreshCw } from 'lucide-react';
import {
  connsCacheKeyForNode,
  DEFAULT_ROUTING,
  isLikelyIPOrCIDR,
  previewCleanRuleTarget,
  routingCacheKeyForNode,
} from './warp/helpers';
import { ClusterOverviewBar } from './warp/ClusterOverviewBar';
import { WarpHeroAndPresets } from './warp/WarpHeroAndPresets';
import { LiveConnectionsPanel } from './warp/LiveConnectionsPanel';
import { CustomRulesBuckets } from './warp/CustomRulesBuckets';

export interface WarpTabProps {
  active?: boolean;
  onRefreshParent?: () => void;
}

export const WarpTab: React.FC<WarpTabProps> = ({ active = true, onRefreshParent }) => {
  const { success, error } = useToast();

  const [selectedNode, setSelectedNode] = useState<string>('local');
  const [syncCluster, setSyncCluster] = useState<boolean>(false);
  const [switchingNode, setSwitchingNode] = useState<boolean>(false);
  const [actingNodeKey, setActingNodeKey] = useState<string | null>(null);

  const cachedConns = peekCachedQuery<WarpConnectionsResponse>(WARP_CONNS_CACHE_KEY);
  const [data, setData] = useState<WarpRoutingStatusResponse | null>(
    () => peekCachedQuery<WarpRoutingStatusResponse>(WARP_ROUTING_CACHE_KEY) ?? null,
  );
  const [loading, setLoading] = useState(() => !peekCachedQuery(WARP_ROUTING_CACHE_KEY));
  const [saving, setSaving] = useState(false);
  const [acting, setActing] = useState<'rekey' | 'ensure' | 'enable_telemetry' | null>(null);

  // Active live connections state
  const [connEnabled, setConnEnabled] = useState(() => cachedConns?.enabled ?? true);
  const [connMsg, setConnMsg] = useState(() => cachedConns?.message ?? '');
  const [connections, setConnections] = useState<ActiveDestinationGroup[]>(
    () => cachedConns?.destinations ?? [],
  );
  const [connQuery, setConnQuery] = useState('');
  const [connFilter, setConnFilter] = useState<'all' | 'DC' | 'WARP'>('all');
  const [autoRefreshConn, setAutoRefreshConn] = useState(true);
  const [loadingConn, setLoadingConn] = useState(false);
  const [switchingTarget, setSwitchingTarget] = useState<string | null>(null);

  // Debounce timer for rapid preset toggles
  const debounceTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const rollbackSnapshotRef = useRef<WarpRoutingStatusResponse | null>(null);

  const loadRouting = useCallback(
    async (forceRefresh = false, nodeTarget = selectedNode) => {
      try {
        const res = await api.getWarpRouting(forceRefresh, nodeTarget);
        setData(res);
        writeCachedQuery(routingCacheKeyForNode(nodeTarget), res);
      } catch (err: any) {
        error(err.message || '获取 WARP 分流配置失败');
      } finally {
        setLoading(false);
        setSwitchingNode(false);
      }
    },
    [error, selectedNode],
  );

  const loadConnections = useCallback(
    async (nodeTarget = selectedNode) => {
      if (nodeTarget === 'all') {
        setConnEnabled(true);
        setConnMsg('');
        setConnections([]);
        return;
      }
      setLoadingConn(true);
      try {
        const res = await api.getWarpConnections(connQuery, connFilter, nodeTarget);
        setConnEnabled(res.enabled);
        setConnMsg(res.message || '');
        setConnections(res.destinations || []);
        if (!connQuery && connFilter === 'all') {
          writeCachedQuery(connsCacheKeyForNode(nodeTarget), res);
        }
      } catch {
        // Keep quiet on background poll error
      } finally {
        setLoadingConn(false);
      }
    },
    [connQuery, connFilter, selectedNode],
  );

  const handleSelectNode = useCallback(
    (nextNode: string) => {
      if (nextNode === selectedNode) return;
      if (debounceTimerRef.current) {
        clearTimeout(debounceTimerRef.current);
        debounceTimerRef.current = null;
      }
      rollbackSnapshotRef.current = null;
      setSelectedNode(nextNode);
      const cachedR = peekCachedQuery<WarpRoutingStatusResponse>(routingCacheKeyForNode(nextNode));
      if (cachedR) {
        setData((prev) => ({
          ...cachedR,
          nodes: cachedR.nodes && cachedR.nodes.length > 0 ? cachedR.nodes : prev?.nodes,
        }));
      } else {
        setSwitchingNode(true);
      }
      const cachedC = peekCachedQuery<WarpConnectionsResponse>(connsCacheKeyForNode(nextNode));
      if (cachedC && nextNode !== 'all') {
        setConnEnabled(cachedC.enabled);
        setConnMsg(cachedC.message || '');
        setConnections(cachedC.destinations || []);
      } else {
        setConnections([]);
      }
      void loadRouting(false, nextNode);
      void loadConnections(nextNode);
    },
    [loadConnections, loadRouting, selectedNode],
  );

  useEffect(() => {
    if (!active) return;
    void loadRouting(false, selectedNode);
    void loadConnections(selectedNode);
  }, [active, selectedNode, loadRouting, loadConnections]);

  useVisibilityInterval(
    () => {
      void loadConnections(selectedNode);
    },
    active && autoRefreshConn && selectedNode !== 'all' ? 5000 : null,
  );

  useEffect(() => {
    return () => {
      if (debounceTimerRef.current) clearTimeout(debounceTimerRef.current);
    };
  }, []);

  const commitRoutingUpdate = useCallback(
    async (nextRouting: WarpRoutingConfig, snapshotForRollback: WarpRoutingStatusResponse | null) => {
      setSaving(true);
      const targetScope = selectedNode === 'all' ? 'all' : selectedNode;
      try {
        const res = await api.updateWarpRouting(nextRouting, {
          node: targetScope,
          viewNode: selectedNode,
          syncCluster: selectedNode === 'all' || syncCluster,
        });
        const nextData: WarpRoutingStatusResponse = {
          selectedNode: res.selectedNode || selectedNode,
          nodes: res.nodes || snapshotForRollback?.nodes,
          daemon: res.daemon,
          routing: res.routing,
          presets: res.presets,
          dcConnCount: res.dcConnCount,
          warpConnCount: res.warpConnCount,
        };
        setData(nextData);
        writeCachedQuery(routingCacheKeyForNode(selectedNode), nextData);
        rollbackSnapshotRef.current = null;
        success(res.message);
        void loadConnections(selectedNode);
      } catch (err: any) {
        if (snapshotForRollback) {
          setData(snapshotForRollback);
        }
        rollbackSnapshotRef.current = null;
        error(err.message || '更新 WARP 分流配置失败');
      } finally {
        setSaving(false);
      }
    },
    [error, loadConnections, selectedNode, success, syncCluster],
  );

  const scheduleOptimisticUpdate = (
    mutator: (prev: WarpRoutingStatusResponse) => {
      nextRouting: WarpRoutingConfig;
      nextPresets: WarpPresetItem[];
    },
    immediate = false,
  ) => {
    if (!data) return;
    if (!rollbackSnapshotRef.current) {
      rollbackSnapshotRef.current = data;
    }
    const { nextRouting, nextPresets } = mutator(data);
    setData({
      ...data,
      routing: nextRouting,
      presets: nextPresets,
    });

    if (debounceTimerRef.current) {
      clearTimeout(debounceTimerRef.current);
      debounceTimerRef.current = null;
    }

    if (immediate) {
      const snap = rollbackSnapshotRef.current;
      void commitRoutingUpdate(nextRouting, snap);
    } else {
      debounceTimerRef.current = setTimeout(() => {
        const snap = rollbackSnapshotRef.current;
        void commitRoutingUpdate(nextRouting, snap);
      }, 250);
    }
  };

  const handleModeChange = (mode: WarpRoutingMode) => {
    if (!data || data.routing.mode === mode) return;
    scheduleOptimisticUpdate(
      (prev) => ({
        nextRouting: { ...prev.routing, mode },
        nextPresets: prev.presets,
      }),
      true,
    );
  };

  const handleTogglePreset = (presetId: string) => {
    scheduleOptimisticUpdate((prev) => {
      const currentPresetsMap = { ...(prev.routing.presets || {}) };
      const targetItem = prev.presets.find((p) => p.id === presetId);
      const nextVal = targetItem ? !targetItem.enabled : !currentPresetsMap[presetId];
      currentPresetsMap[presetId] = nextVal;

      const nextPresets = prev.presets.map((p) => (p.id === presetId ? { ...p, enabled: nextVal } : p));
      return {
        nextRouting: {
          ...prev.routing,
          presets: currentPresetsMap,
        },
        nextPresets,
      };
    });
  };

  const handleAddRules = (bucket: 'warp' | 'direct', rawText: string) => {
    if (!data || !rawText.trim()) return;
    const tokens = rawText
      .split(/[\s,;，；\n]+/)
      .map((t) => t.trim())
      .filter(Boolean);
    if (tokens.length === 0) return;

    const nextRouting: WarpRoutingConfig = {
      ...data.routing,
      warpDomains: [...(data.routing.warpDomains || [])],
      warpCidrs: [...(data.routing.warpCidrs || [])],
      directDomains: [...(data.routing.directDomains || [])],
      directCidrs: [...(data.routing.directCidrs || [])],
    };

    for (const token of tokens) {
      const parsed = previewCleanRuleTarget(token);
      const targetVal = parsed ? parsed.value : token;
      const isCIDR = parsed?.kind === 'cidr' || isLikelyIPOrCIDR(token);
      if (bucket === 'warp') {
        if (isCIDR) {
          nextRouting.directCidrs = nextRouting.directCidrs.filter((x) => x !== targetVal);
          if (!nextRouting.warpCidrs.includes(targetVal)) nextRouting.warpCidrs.push(targetVal);
        } else {
          nextRouting.directDomains = nextRouting.directDomains.filter((x) => x !== targetVal);
          if (!nextRouting.warpDomains.includes(targetVal)) nextRouting.warpDomains.push(targetVal);
        }
      } else {
        if (isCIDR) {
          nextRouting.warpCidrs = nextRouting.warpCidrs.filter((x) => x !== targetVal);
          if (!nextRouting.directCidrs.includes(targetVal)) nextRouting.directCidrs.push(targetVal);
        } else {
          nextRouting.warpDomains = nextRouting.warpDomains.filter((x) => x !== targetVal);
          if (!nextRouting.directDomains.includes(targetVal)) nextRouting.directDomains.push(targetVal);
        }
      }
    }

    scheduleOptimisticUpdate(
      (prev) => ({
        nextRouting,
        nextPresets: prev.presets,
      }),
      true,
    );
  };

  const handleRemoveRule = (bucket: 'warp' | 'direct', kind: 'domain' | 'cidr', value: string) => {
    if (!data) return;
    const nextRouting: WarpRoutingConfig = {
      ...data.routing,
      warpDomains: [...(data.routing.warpDomains || [])],
      warpCidrs: [...(data.routing.warpCidrs || [])],
      directDomains: [...(data.routing.directDomains || [])],
      directCidrs: [...(data.routing.directCidrs || [])],
    };
    if (bucket === 'warp' && kind === 'domain') {
      nextRouting.warpDomains = nextRouting.warpDomains.filter((x) => x !== value);
    } else if (bucket === 'warp' && kind === 'cidr') {
      nextRouting.warpCidrs = nextRouting.warpCidrs.filter((x) => x !== value);
    } else if (bucket === 'direct' && kind === 'domain') {
      nextRouting.directDomains = nextRouting.directDomains.filter((x) => x !== value);
    } else {
      nextRouting.directCidrs = nextRouting.directCidrs.filter((x) => x !== value);
    }
    scheduleOptimisticUpdate(
      (prev) => ({
        nextRouting,
        nextPresets: prev.presets,
      }),
      true,
    );
  };

  const handleQuickSwitch = async (target: string, outbound: 'WARP' | 'DC') => {
    setSwitchingTarget(target);
    try {
      const res = await api.quickSwitchWarpTarget(target, outbound, {
        node: selectedNode,
        viewNode: selectedNode,
        syncCluster: selectedNode === 'all' || syncCluster,
      });
      const nextData: WarpRoutingStatusResponse = {
        selectedNode: res.selectedNode || selectedNode,
        nodes: res.nodes || data?.nodes,
        daemon: res.daemon,
        routing: res.routing,
        presets: res.presets,
        dcConnCount: res.dcConnCount,
        warpConnCount: res.warpConnCount,
      };
      setData(nextData);
      writeCachedQuery(routingCacheKeyForNode(selectedNode), nextData);
      success(res.message);
      void loadConnections(selectedNode);
    } catch (err: any) {
      error(err.message || '切换失败');
    } finally {
      setSwitchingTarget(null);
    }
  };

  const handleWarpAction = async (action: 'rekey' | 'ensure', nodeOverride?: string) => {
    const targetNode = nodeOverride || selectedNode;
    if (nodeOverride) {
      setActingNodeKey(`${nodeOverride}:${action}`);
    } else {
      setActing(action);
    }
    try {
      const res = await api.runWarpAction(action, targetNode);
      if (!nodeOverride) {
        setData((prev) => (prev ? { ...prev, daemon: res.daemon } : prev));
      }
      success(res.message);
      await loadRouting(true, selectedNode);
      void loadConnections(selectedNode);
      onRefreshParent?.();
    } catch (err: any) {
      error(err.message || 'WARP 操作执行失败');
    } finally {
      if (nodeOverride) {
        setActingNodeKey(null);
      } else {
        setActing(null);
      }
    }
  };

  const handleEnableTelemetry = async () => {
    setActing('enable_telemetry');
    try {
      const res =
        selectedNode === 'local'
          ? await api.enableTelemetry()
          : await api.runWarpAction('enable_telemetry', selectedNode);
      success(res.message || '实时流量遥测已开启');
      void loadConnections(selectedNode);
    } catch (err: any) {
      error(err.message || '开启实时遥测失败');
    } finally {
      setActing(null);
    }
  };

  const clusterNodes: WarpNodeSummary[] = data?.nodes || [];
  const hasCluster = clusterNodes.length > 1;
  const activeNodeMeta = useMemo(
    () => clusterNodes.find((n) => n.id === selectedNode),
    [clusterNodes, selectedNode],
  );
  const healthyNodeCount = useMemo(
    () => clusterNodes.filter((n) => n.daemon?.tunnelHealthy).length,
    [clusterNodes],
  );

  const routing = data?.routing || DEFAULT_ROUTING;
  const daemon = data?.daemon;
  const presets = data?.presets || [];

  if (loading && !data) {
    return (
      <div className="p-10 rounded-2xl glass-card flex items-center justify-center gap-3 text-slate-400 text-xs font-mono">
        <RefreshCw className="w-4 h-4 animate-spin text-amber-400" />
        <span>正在加载 WARP 智能分流控制中心...</span>
      </div>
    );
  }

  const currentScopeLabel =
    selectedNode === 'all'
      ? `全集群总览 (${clusterNodes.length} 台)`
      : activeNodeMeta?.name || (selectedNode === 'local' ? '主控本机' : selectedNode);

  return (
    <div className="space-y-6">
      <ClusterOverviewBar
        clusterNodes={clusterNodes}
        healthyNodeCount={healthyNodeCount}
        selectedNode={selectedNode}
        syncCluster={syncCluster}
        setSyncCluster={setSyncCluster}
        switchingNode={switchingNode}
        actingNodeKey={actingNodeKey}
        acting={acting}
        onSelectNode={handleSelectNode}
        onWarpAction={handleWarpAction}
      />

      <WarpHeroAndPresets
        daemon={daemon}
        routing={routing}
        presets={presets}
        dcConnCount={data?.dcConnCount ?? 0}
        warpConnCount={data?.warpConnCount ?? 0}
        selectedNode={selectedNode}
        hasCluster={hasCluster}
        syncCluster={syncCluster}
        currentScopeLabel={currentScopeLabel}
        saving={saving}
        acting={acting}
        onModeChange={handleModeChange}
        onTogglePreset={handleTogglePreset}
        onWarpAction={(action) => void handleWarpAction(action)}
        onRefreshRouting={() => void loadRouting(true, selectedNode)}
      />

      <LiveConnectionsPanel
        selectedNode={selectedNode}
        clusterNodes={clusterNodes}
        connEnabled={connEnabled}
        connMsg={connMsg}
        connections={connections}
        connQuery={connQuery}
        setConnQuery={setConnQuery}
        connFilter={connFilter}
        setConnFilter={setConnFilter}
        autoRefreshConn={autoRefreshConn}
        setAutoRefreshConn={setAutoRefreshConn}
        loadingConn={loadingConn}
        switchingTarget={switchingTarget}
        routingMode={routing.mode}
        enablingTelemetry={acting === 'enable_telemetry'}
        onSelectNode={handleSelectNode}
        onRefreshConnections={() => void loadConnections(selectedNode)}
        onEnableTelemetry={handleEnableTelemetry}
        onQuickSwitch={handleQuickSwitch}
      />

      <CustomRulesBuckets
        routing={routing}
        onAddRules={handleAddRules}
        onRemoveRule={handleRemoveRule}
      />
    </div>
  );
};

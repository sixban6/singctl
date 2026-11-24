import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  CLIENT_INVALIDATE_EVENT,
  ClientInvalidateScope,
  peekCachedQuery,
  useVisibilityInterval,
  writeCachedQuery,
} from '../../../hooks';
import { useToast } from '../../../ui';
import { clientApi } from '../../api';
import { AUDIT_DEFAULT_CACHE_KEY } from '../../cacheKeys';
import { AuditAIReview, AuditFlowRecord, AuditReport } from '../../types';
import {
  AuditPresetFilter,
  AuditRefreshCadence,
  AuditSelectedDevice,
  AuditSortKey,
  AuditViewMode,
  computeFlowsTelemetry,
  filterAndSortAuditFlows,
  groupFlowsByTarget,
  normalizeAuditFlows,
} from './auditFlowModel';
import { FLOW_RENDER_STEP, getFlowCacheKey } from './auditHelpers';

export interface UseAuditFlowsControllerParams {
  active: boolean;
  drawerBlockingRefresh: boolean;
  setCachedReview: (
    flowOrKey: AuditFlowRecord | string,
    target: string,
    rev: AuditAIReview,
    skipStorage?: boolean,
  ) => void;
  getCachedReview: (f: AuditFlowRecord) => AuditAIReview | null;
  flushCachedReviews: () => void;
}

export function useAuditFlowsController({
  active,
  drawerBlockingRefresh,
  setCachedReview,
  getCachedReview,
  flushCachedReviews,
}: UseAuditFlowsControllerParams) {
  const { error } = useToast();

  // Filters, presets & view controls
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedDevice, setSelectedDevice] = useState<AuditSelectedDevice | null>(null);
  const [selectedChain, setSelectedChain] = useState('');
  const [networkFilter, setNetworkFilter] = useState<'' | 'tcp' | 'udp'>('');
  const [axisFilter, setAxisFilter] = useState<'' | 'security' | 'privacy'>('');
  const [onlyActive, setOnlyActive] = useState(true);
  const [preset, setPreset] = useState<AuditPresetFilter>('all');
  const [hideWhitelisted, setHideWhitelisted] = useState(false);
  const [viewMode, setViewMode] = useState<AuditViewMode>('list');
  const [refreshMs, setRefreshMs] = useState<AuditRefreshCadence>(2000);
  const [sortBy, setSortBy] = useState<AuditSortKey>('active');
  const [sortDir, setSortDir] = useState<'asc' | 'desc'>('desc');
  const [visibleLimit, setVisibleLimit] = useState(FLOW_RENDER_STEP);

  // Interaction & selection states
  const [hoverPaused, setHoverPaused] = useState(false);
  const [selectedKeys, setSelectedKeys] = useState<Set<string>>(() => new Set());
  const [detailFlowKey, setDetailFlowKey] = useState<string | null>(null);

  // Data state (SWR cache hydrated synchronously)
  const [report, setReport] = useState<AuditReport | null>(
    () => peekCachedQuery<AuditReport>(AUDIT_DEFAULT_CACHE_KEY) ?? null,
  );
  const [loading, setLoading] = useState<boolean>(
    () => !peekCachedQuery<AuditReport>(AUDIT_DEFAULT_CACHE_KEY),
  );
  const [refreshing, setRefreshing] = useState(false);
  const [filterTransitioning, setFilterTransitioning] = useState(false);
  const [lastUpdated, setLastUpdated] = useState('');

  const requestSeqRef = useRef(0);
  const abortCtrlRef = useRef<AbortController | null>(null);
  const actionInFlightRef = useRef(0);
  const pointerDownUntilRef = useRef(0);
  const hasLoadedReportRef = useRef<boolean>(Boolean(peekCachedQuery(AUDIT_DEFAULT_CACHE_KEY)));

  const sectionAnchorRef = useRef<HTMLDivElement>(null);
  const tableContainerRef = useRef<HTMLDivElement>(null);
  const flowScrollRef = useRef<HTMLDivElement>(null);

  const loadAudit = useCallback(
    async (silent = false) => {
      if (silent && (actionInFlightRef.current > 0 || Date.now() < pointerDownUntilRef.current)) {
        return;
      }

      abortCtrlRef.current?.abort();
      const ctrl = new AbortController();
      abortCtrlRef.current = ctrl;
      const seq = ++requestSeqRef.current;

      if (!silent) {
        if (!hasLoadedReportRef.current) {
          setLoading(true);
        } else {
          setFilterTransitioning(true);
        }
      }
      setRefreshing(true);

      const qs = new URLSearchParams();
      qs.set('sort', 'active');
      qs.set('dir', 'desc');

      try {
        const rep = await clientApi.getAudit(qs, ctrl.signal);
        if (ctrl.signal.aborted || seq !== requestSeqRef.current) return;
        if (silent && (actionInFlightRef.current > 0 || Date.now() < pointerDownUntilRef.current)) {
          return;
        }
        let synced = false;
        (rep.flows || []).forEach((f) => {
          if (f.aiReview) {
            setCachedReview(f, f.target, f.aiReview, true);
            synced = true;
          }
        });
        if (synced) flushCachedReviews();
        hasLoadedReportRef.current = true;
        writeCachedQuery(AUDIT_DEFAULT_CACHE_KEY, rep);
        setReport(rep);
        setLastUpdated(new Date().toLocaleTimeString());
      } catch (e) {
        if (ctrl.signal.aborted || (e as Error)?.name === 'AbortError') return;
        if (!silent) {
          error((e as Error).message || '加载审计数据失败');
        }
      } finally {
        if (seq === requestSeqRef.current) {
          setLoading(false);
          setRefreshing(false);
          setFilterTransitioning(false);
        }
      }
    },
    [setCachedReview, flushCachedReviews, error],
  );

  useEffect(() => {
    void loadAudit(hasLoadedReportRef.current);
    return () => {
      abortCtrlRef.current?.abort();
    };
  }, [loadAudit]);

  const prevActiveRef = useRef<boolean>(active);
  useEffect(() => {
    const becameActive = !prevActiveRef.current && active;
    prevActiveRef.current = active;
    if (becameActive) {
      void loadAudit(true);
    }
  }, [active, loadAudit]);

  useEffect(() => {
    const onInvalidate = (ev: Event) => {
      const scope = (ev as CustomEvent<ClientInvalidateScope>).detail;
      if (!scope || scope === 'all' || scope === 'audit') {
        void loadAudit(true);
      }
    };
    window.addEventListener(CLIENT_INVALIDATE_EVENT, onInvalidate);
    return () => window.removeEventListener(CLIENT_INVALIDATE_EVENT, onInvalidate);
  }, [loadAudit]);

  const refreshAutoPausedReason = useMemo(() => {
    if (selectedKeys.size > 0) return '勾选批处理中已暂缓刷新';
    if (detailFlowKey) return '详情抽屉打开中已暂缓刷新';
    if (hoverPaused) return '阅读中已暂缓重排';
    return '';
  }, [selectedKeys.size, detailFlowKey, hoverPaused]);

  const effectiveInterval =
    active && refreshMs > 0 && !refreshAutoPausedReason && !drawerBlockingRefresh
      ? refreshMs
      : null;

  useVisibilityInterval(() => {
    void loadAudit(true);
  }, effectiveInterval);

  const normalizedFlows = useMemo(
    () => normalizeAuditFlows(report, getCachedReview),
    [report, getCachedReview],
  );

  const totalAllFlows = normalizedFlows.length;
  const totalActiveFlows = useMemo(
    () => normalizedFlows.reduce((acc, f) => acc + ((f.activeConns || 0) > 0 ? 1 : 0), 0),
    [normalizedFlows],
  );

  const { filteredFlows: processedFlows, presetCounts } = useMemo(
    () =>
      filterAndSortAuditFlows(normalizedFlows, report, {
        searchQuery,
        selectedDevice,
        selectedChain,
        networkFilter,
        onlyActive,
        axisFilter,
        preset,
        hideWhitelisted,
        sortBy,
        sortDir,
      }),
    [
      normalizedFlows,
      report,
      searchQuery,
      selectedDevice,
      selectedChain,
      networkFilter,
      onlyActive,
      axisFilter,
      preset,
      hideWhitelisted,
      sortBy,
      sortDir,
    ],
  );

  const telemetry = useMemo(() => computeFlowsTelemetry(processedFlows), [processedFlows]);

  const targetGroups = useMemo(
    () => (viewMode === 'grouped' ? groupFlowsByTarget(processedFlows, sortBy, sortDir) : []),
    [viewMode, processedFlows, sortBy, sortDir],
  );

  const hasAnyFilter = Boolean(
    searchQuery.trim() ||
      selectedDevice ||
      selectedChain ||
      networkFilter ||
      axisFilter ||
      preset !== 'all' ||
      hideWhitelisted,
  );

  const handleResetAllFilters = useCallback(() => {
    setSearchQuery('');
    setSelectedDevice(null);
    setSelectedChain('');
    setNetworkFilter('');
    setAxisFilter('');
    setPreset('all');
    setHideWhitelisted(false);
  }, []);

  useEffect(() => {
    setVisibleLimit(FLOW_RENDER_STEP);
    setSelectedKeys(new Set());
    if (flowScrollRef.current) {
      flowScrollRef.current.scrollTop = 0;
    }
  }, [
    searchQuery,
    selectedDevice,
    selectedChain,
    networkFilter,
    onlyActive,
    axisFilter,
    preset,
    hideWhitelisted,
    sortBy,
    sortDir,
  ]);

  const visibleFlows = useMemo(
    () => processedFlows.slice(0, visibleLimit),
    [processedFlows, visibleLimit],
  );

  useEffect(() => {
    const el = flowScrollRef.current;
    if (!el || visibleLimit >= processedFlows.length) return;
    if (el.scrollHeight - el.scrollTop - el.clientHeight < 200) {
      setVisibleLimit((prev) => Math.min(processedFlows.length, prev + FLOW_RENDER_STEP));
    }
  }, [visibleLimit, processedFlows.length]);

  const handleFlowTableScroll = useCallback(
    (e: React.UIEvent<HTMLDivElement>) => {
      pointerDownUntilRef.current = Math.max(pointerDownUntilRef.current, Date.now() + 500);
      const el = e.currentTarget;
      if (
        visibleLimit < processedFlows.length &&
        el.scrollHeight - el.scrollTop - el.clientHeight < 280
      ) {
        setVisibleLimit((prev) => Math.min(processedFlows.length, prev + FLOW_RENDER_STEP));
      }
    },
    [visibleLimit, processedFlows.length],
  );

  const handleSort = (key: string) => {
    const k = key as AuditSortKey;
    if (sortBy !== k) {
      setSortBy(k);
      setSortDir('desc');
    } else if (sortDir === 'desc') {
      setSortDir('asc');
    } else {
      setSortBy('active');
      setSortDir('desc');
    }
  };

  const selectedFlows = useMemo(() => {
    if (selectedKeys.size === 0) return [];
    return processedFlows.filter((f) => selectedKeys.has(getFlowCacheKey(f)));
  }, [processedFlows, selectedKeys]);

  const selectedActiveCount = useMemo(
    () => selectedFlows.reduce((acc, f) => acc + ((f.activeConns || 0) > 0 ? 1 : 0), 0),
    [selectedFlows],
  );

  const handleToggleSelectKey = (fk: string) => {
    setSelectedKeys((prev) => {
      const next = new Set(prev);
      if (next.has(fk)) next.delete(fk);
      else next.add(fk);
      return next;
    });
  };

  const handleToggleSelectAllVisible = () => {
    const allSelected =
      visibleFlows.length > 0 && visibleFlows.every((f) => selectedKeys.has(getFlowCacheKey(f)));
    if (allSelected) {
      setSelectedKeys(new Set());
    } else {
      setSelectedKeys(new Set(visibleFlows.map(getFlowCacheKey)));
    }
  };

  const detailIndex = useMemo(
    () => (detailFlowKey ? processedFlows.findIndex((f) => getFlowCacheKey(f) === detailFlowKey) : -1),
    [processedFlows, detailFlowKey],
  );
  const detailFlow = detailIndex >= 0 ? processedFlows[detailIndex] : null;

  return {
    report,
    loading,
    refreshing,
    filterTransitioning,
    lastUpdated,
    loadAudit,
    actionInFlightRef,
    pointerDownUntilRef,
    sectionAnchorRef,
    tableContainerRef,
    flowScrollRef,
    searchQuery,
    setSearchQuery,
    selectedDevice,
    setSelectedDevice,
    selectedChain,
    setSelectedChain,
    networkFilter,
    setNetworkFilter,
    axisFilter,
    setAxisFilter,
    onlyActive,
    setOnlyActive,
    preset,
    setPreset,
    hideWhitelisted,
    setHideWhitelisted,
    viewMode,
    setViewMode,
    refreshMs,
    setRefreshMs,
    sortBy,
    setSortBy,
    sortDir,
    setSortDir,
    setVisibleLimit,
    setHoverPaused,
    selectedKeys,
    setSelectedKeys,
    selectedFlows,
    selectedActiveCount,
    detailFlowKey,
    setDetailFlowKey,
    detailIndex,
    detailFlow,
    refreshAutoPausedReason,
    totalAllFlows,
    totalActiveFlows,
    processedFlows,
    visibleFlows,
    presetCounts,
    telemetry,
    targetGroups,
    hasAnyFilter,
    handleResetAllFilters,
    handleFlowTableScroll,
    handleSort,
    handleToggleSelectKey,
    handleToggleSelectAllVisible,
  };
}

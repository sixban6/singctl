import React, { useCallback, useEffect, useRef, useState } from 'react';
import { useToast } from '../../../ui';
import { clientApi } from '../../api';
import { AuditAIReview, AuditFlowRecord } from '../../types';
import {
  AUDIT_AI_ENABLE_KEY,
  getFlowCacheKey,
  getFlowTargetKey,
  loadSavedAICache,
  persistAICache,
} from './auditHelpers';

export interface UseAuditAICacheResult {
  aiEnabled: boolean;
  handleToggleAI: (checked: boolean) => void;
  setCachedReview: (
    flowOrKey: AuditFlowRecord | string,
    target: string,
    rev: AuditAIReview,
    skipStorage?: boolean,
  ) => void;
  getCachedReview: (f: AuditFlowRecord) => AuditAIReview | null;
  flushCachedReviews: () => void;
  pendingTargets: Set<string>;
  aiStatusText: string;
  reviewSingleFlow: (f: AuditFlowRecord, force?: boolean) => Promise<void>;
  reviewBatchFlows: (flows: AuditFlowRecord[], force?: boolean) => Promise<void>;
}

export function useAuditAICache(): UseAuditAICacheResult {
  const { success, error } = useToast();
  const [aiEnabled, setAiEnabled] = useState<boolean>(() => {
    try {
      return localStorage.getItem(AUDIT_AI_ENABLE_KEY) !== '0';
    } catch {
      return true;
    }
  });
  const aiCacheRef = useRef<Map<string, AuditAIReview>>(loadSavedAICache());
  const [aiRevTick, setAiRevTick] = useState(0);
  const [pendingTargets, setPendingTargets] = useState<Set<string>>(() => new Set());
  const [aiStatusText, setAiStatusText] = useState('');

  const handleToggleAI = useCallback((checked: boolean) => {
    setAiEnabled(checked);
    if (!checked) setAiStatusText('');
    try {
      localStorage.setItem(AUDIT_AI_ENABLE_KEY, checked ? '1' : '0');
    } catch {
      // ignore
    }
  }, []);

  const setCachedReview = useCallback(
    (flowOrKey: AuditFlowRecord | string, target: string, rev: AuditAIReview, skipStorage = false) => {
      if (!rev) return;
      const cache = aiCacheRef.current;
      const k = typeof flowOrKey === 'string' ? flowOrKey : getFlowCacheKey(flowOrKey);
      const tgt = (target || '').toLowerCase();
      const prev = cache.get(k) || (tgt ? cache.get(`tgt:${tgt}`) : undefined);
      const isNewLLM = Boolean(rev.source && rev.source !== 'builtin_expert');
      const hadPrevLLM = Boolean(prev && prev.source && prev.source !== 'builtin_expert');
      if (isNewLLM || !hadPrevLLM) {
        cache.set(k, rev);
        if (tgt) cache.set(`tgt:${tgt}`, rev);
        if (isNewLLM && !skipStorage) {
          persistAICache(cache);
        }
      }
    },
    [],
  );

  const flushCachedReviews = useCallback(() => {
    persistAICache(aiCacheRef.current);
    setAiRevTick((t) => t + 1);
  }, []);

  const getCachedReview = useCallback(
    (f: AuditFlowRecord): AuditAIReview | null => {
      void aiRevTick;
      const cache = aiCacheRef.current;
      const k = getFlowCacheKey(f);
      const tgt = (f.target || '').toLowerCase();
      return cache.get(k) || (tgt ? cache.get(`tgt:${tgt}`) : undefined) || f.aiReview || null;
    },
    [aiRevTick],
  );

  const reviewSingleFlow = useCallback(
    async (f: AuditFlowRecord, force = false) => {
      const tk = getFlowTargetKey(f);
      setPendingTargets((prev) => new Set(prev).add(tk));
      try {
        const res = await clientApi.reviewAuditBatch([f], force);
        const fk = getFlowCacheKey(f);
        const rev = res.results?.[fk] || res.results?.[f.target] || res.results?.[tk];
        if (rev) {
          setCachedReview(f, f.target, rev, false);
          setAiRevTick((t) => t + 1);
          success(res.usedRemote ? 'AI 深度研判已更新' : '已使用内置离线知识库研判');
        }
      } catch (e) {
        error((e as Error).message || 'AI 研判失败');
      } finally {
        setPendingTargets((prev) => {
          const next = new Set(prev);
          next.delete(tk);
          return next;
        });
      }
    },
    [setCachedReview, success, error],
  );

  const reviewBatchFlows = useCallback(
    async (flows: AuditFlowRecord[], force = false) => {
      const seen = new Set<string>();
      const unique: AuditFlowRecord[] = [];
      for (const f of flows) {
        const tk = getFlowTargetKey(f);
        if (seen.has(tk)) continue;
        seen.add(tk);
        unique.push(f);
        if (unique.length >= 25) break;
      }
      if (!unique.length) return;
      const tks = unique.map(getFlowTargetKey);
      setPendingTargets((prev) => {
        const next = new Set(prev);
        tks.forEach((tk) => next.add(tk));
        return next;
      });
      try {
        const res = await clientApi.reviewAuditBatch(unique, force);
        let updated = 0;
        unique.forEach((f) => {
          const fk = getFlowCacheKey(f);
          const tk = getFlowTargetKey(f);
          const rev = res.results?.[fk] || res.results?.[f.target] || res.results?.[tk];
          if (rev) {
            setCachedReview(f, f.target, rev, true);
            updated++;
          }
        });
        if (updated > 0) {
          flushCachedReviews();
          success(
            res.usedRemote
              ? `已完成 ${updated} 个目标的 AI 深度研判`
              : `已使用内置知识库研判 ${updated} 个目标`,
          );
        }
      } catch (e) {
        error((e as Error).message || '批量 AI 研判失败');
      } finally {
        setPendingTargets((prev) => {
          const next = new Set(prev);
          tks.forEach((tk) => next.delete(tk));
          return next;
        });
      }
    },
    [setCachedReview, flushCachedReviews, success, error],
  );

  return {
    aiEnabled,
    handleToggleAI,
    setCachedReview,
    getCachedReview,
    flushCachedReviews,
    pendingTargets,
    aiStatusText,
    reviewSingleFlow,
    reviewBatchFlows,
  };
}

export function useAuditViewportPrefetch(opts: {
  active: boolean;
  aiEnabled: boolean;
  processedFlows: AuditFlowRecord[];
  visibleFlowsCount: number;
  lastUpdated: string;
  flowScrollRef: React.RefObject<HTMLDivElement>;
  tableContainerRef: React.RefObject<HTMLDivElement>;
  getCachedReview: (f: AuditFlowRecord) => AuditAIReview | null;
  setCachedReview: (
    flowOrKey: AuditFlowRecord | string,
    target: string,
    rev: AuditAIReview,
    skipStorage?: boolean,
  ) => void;
  flushCachedReviews: () => void;
}): { pendingPrefetchTargets: Set<string>; prefetchStatusText: string } {
  const {
    active,
    aiEnabled,
    processedFlows,
    visibleFlowsCount,
    lastUpdated,
    flowScrollRef,
    tableContainerRef,
    getCachedReview,
    setCachedReview,
    flushCachedReviews,
  } = opts;

  const [pendingPrefetchTargets, setPendingPrefetchTargets] = useState<Set<string>>(() => new Set());
  const [prefetchStatusText, setPrefetchStatusText] = useState('');
  const aiInFlightRef = useRef(false);
  const aiRescheduleRef = useRef(false);

  const scheduleAIPrefetch = useCallback(async () => {
    if (!aiEnabled || !processedFlows.length) {
      setPrefetchStatusText('');
      return;
    }
    if (aiInFlightRef.current) {
      aiRescheduleRef.current = true;
      return;
    }

    const vh = window.innerHeight || document.documentElement.clientHeight || 800;
    const containerEl = flowScrollRef.current;
    const bounds = containerEl ? containerEl.getBoundingClientRect() : null;
    const viewTop = bounds ? Math.max(0, bounds.top) : 0;
    const viewBottom = bounds ? Math.min(vh, bounds.bottom) : vh;
    const rows = (containerEl || tableContainerRef.current)?.querySelectorAll('tbody tr') || [];
    let firstVis = -1;
    let lastVis = -1;
    rows.forEach((tr, idx) => {
      const rect = tr.getBoundingClientRect();
      if (rect.height === 0) return;
      if (rect.bottom >= viewTop - 40 && rect.top <= viewBottom + 40) {
        if (firstVis === -1) firstVis = idx;
        lastVis = idx;
      }
    });
    if (firstVis === -1) {
      firstVis = 0;
      lastVis = Math.min(processedFlows.length - 1, 14);
    }
    const visCount = Math.max(12, lastVis - firstVis + 1);
    const prefetchEnd = Math.min(processedFlows.length - 1, lastVis + visCount * 2);

    const pickBatch = (start: number, end: number, max: number) => {
      const seen = new Set<string>();
      const out: AuditFlowRecord[] = [];
      for (let i = start; i <= end; i++) {
        const f = processedFlows[i];
        if (!f) continue;
        const tk = getFlowTargetKey(f);
        if (seen.has(tk) || getCachedReview(f)) continue;
        seen.add(tk);
        out.push(f);
        if (out.length >= max) break;
      }
      return out;
    };

    let batch = pickBatch(firstVis, lastVis, 8);
    let label = '可视区';
    if (!batch.length) {
      batch = pickBatch(lastVis + 1, prefetchEnd, 10);
      label = '预取区';
    }
    if (!batch.length) {
      setPrefetchStatusText('');
      return;
    }

    aiInFlightRef.current = true;
    aiRescheduleRef.current = false;
    const targets = batch.map(getFlowTargetKey);
    if (label === '可视区') {
      setPendingPrefetchTargets((prev) => {
        const next = new Set(prev);
        targets.forEach((t) => next.add(t));
        return next;
      });
    }
    setPrefetchStatusText(`${label} ${batch.length} 条…`);

    try {
      const res = await clientApi.reviewAuditBatch(batch, false);
      if (res && res.results) {
        let updated = false;
        batch.forEach((f) => {
          const fk = getFlowCacheKey(f);
          const tk = getFlowTargetKey(f);
          const rev = res.results[fk] || res.results[f.target] || res.results[tk];
          if (rev) {
            setCachedReview(f, f.target, rev, true);
            updated = true;
          }
        });
        if (updated) {
          flushCachedReviews();
        }
      }
    } catch {
      // silent prefetch fallback
    } finally {
      aiInFlightRef.current = false;
      setPendingPrefetchTargets((prev) => {
        const next = new Set(prev);
        targets.forEach((t) => next.delete(t));
        return next;
      });
      setPrefetchStatusText('');
      if (aiRescheduleRef.current) {
        window.setTimeout(() => void scheduleAIPrefetch(), 80);
      }
    }
  }, [
    aiEnabled,
    processedFlows,
    flowScrollRef,
    tableContainerRef,
    getCachedReview,
    setCachedReview,
    flushCachedReviews,
  ]);

  useEffect(() => {
    if (!active || !aiEnabled) {
      if (!aiEnabled) setPrefetchStatusText('');
      return;
    }
    const timer = window.setTimeout(() => {
      void scheduleAIPrefetch();
    }, 180);
    return () => window.clearTimeout(timer);
  }, [active, aiEnabled, processedFlows.length, lastUpdated, scheduleAIPrefetch]);

  useEffect(() => {
    if (!active || !aiEnabled) return;
    let timer: number | null = null;
    const onScroll = () => {
      if (timer) window.clearTimeout(timer);
      timer = window.setTimeout(() => void scheduleAIPrefetch(), 180);
    };
    const scrollEl = flowScrollRef.current;
    window.addEventListener('scroll', onScroll, { passive: true });
    scrollEl?.addEventListener('scroll', onScroll, { passive: true });
    return () => {
      window.removeEventListener('scroll', onScroll);
      scrollEl?.removeEventListener('scroll', onScroll);
      if (timer) window.clearTimeout(timer);
    };
  }, [active, aiEnabled, visibleFlowsCount, flowScrollRef, scheduleAIPrefetch]);

  return { pendingPrefetchTargets, prefetchStatusText };
}

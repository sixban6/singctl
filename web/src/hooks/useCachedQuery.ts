import { useState, useEffect, useCallback, useRef } from 'react';

const queryCache = new Map<string, unknown>();

export function clearCachedQuery(keyPrefix?: string) {
  if (!keyPrefix) {
    queryCache.clear();
    return;
  }
  for (const key of queryCache.keys()) {
    if (key.startsWith(keyPrefix)) queryCache.delete(key);
  }
}

export interface UseCachedQueryOptions<T> {
  enabled?: boolean;
  pollMs?: number;
  initialData?: T;
}

export function useCachedQuery<T>(
  key: string,
  fetcher: () => Promise<T>,
  options: UseCachedQueryOptions<T> = {},
) {
  const { enabled = true, pollMs = 0, initialData } = options;
  const cached = queryCache.has(key) ? (queryCache.get(key) as T) : initialData;

  const [data, setDataState] = useState<T | undefined>(cached);
  const [loading, setLoading] = useState<boolean>(() => enabled && cached === undefined);
  const [refreshing, setRefreshing] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const fetcherRef = useRef(fetcher);
  fetcherRef.current = fetcher;

  const setData = useCallback(
    (updater: T | ((prev: T | undefined) => T)) => {
      setDataState((prev) => {
        const next = typeof updater === 'function' ? (updater as (p: T | undefined) => T)(prev) : updater;
        queryCache.set(key, next);
        return next;
      });
    },
    [key],
  );

  const refetch = useCallback(
    async (silent = false) => {
      if (!enabled) return undefined;
      if (!silent && !queryCache.has(key)) setLoading(true);
      if (silent || queryCache.has(key)) setRefreshing(true);
      try {
        const next = await fetcherRef.current();
        queryCache.set(key, next);
        setDataState(next);
        setError(null);
        return next;
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : '请求失败';
        setError(msg);
        return undefined;
      } finally {
        setLoading(false);
        setRefreshing(false);
      }
    },
    [enabled, key],
  );

  useEffect(() => {
    if (!enabled) return;
    if (queryCache.has(key)) {
      setDataState(queryCache.get(key) as T);
      setLoading(false);
      void refetch(true);
    } else {
      void refetch(false);
    }
  }, [enabled, key, refetch]);

  useEffect(() => {
    if (!enabled || !pollMs || pollMs <= 0) return;
    let timer: ReturnType<typeof setInterval> | null = null;

    const start = () => {
      if (timer) clearInterval(timer);
      timer = setInterval(() => {
        if (document.visibilityState === 'visible') {
          void refetch(true);
        }
      }, pollMs);
    };

    const onVisibility = () => {
      if (document.visibilityState === 'visible') {
        void refetch(true);
      }
    };

    start();
    document.addEventListener('visibilitychange', onVisibility);
    return () => {
      if (timer) clearInterval(timer);
      document.removeEventListener('visibilitychange', onVisibility);
    };
  }, [enabled, pollMs, refetch]);

  return { data, loading, refreshing, error, refetch, setData };
}

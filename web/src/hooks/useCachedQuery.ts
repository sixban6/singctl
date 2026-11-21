import { useState, useEffect, useCallback, useRef } from 'react';
import { useVisibilityInterval } from './useVisibilityInterval';

const queryCache = new Map<string, unknown>();
const inFlightMap = new Map<string, Promise<unknown>>();

export const CLIENT_INVALIDATE_EVENT = 'singctl:client-invalidate';
export type ClientInvalidateScope = 'all' | 'adguard' | 'audit';

export function emitClientInvalidate(scope: ClientInvalidateScope = 'all') {
  if (typeof window !== 'undefined') {
    window.dispatchEvent(new CustomEvent<ClientInvalidateScope>(CLIENT_INVALIDATE_EVENT, { detail: scope }));
  }
}

export function peekCachedQuery<T>(key: string): T | undefined {
  return queryCache.has(key) ? (queryCache.get(key) as T) : undefined;
}

export function writeCachedQuery<T>(key: string, value: T): void {
  queryCache.set(key, value);
}

export function prefetchCachedQuery<T>(key: string, fetcher: () => Promise<T>): Promise<T | undefined> {
  const existing = inFlightMap.get(key) as Promise<T | undefined> | undefined;
  if (existing) return existing;

  const p = fetcher()
    .then((res) => {
      queryCache.set(key, res);
      return res;
    })
    .catch(() => undefined)
    .finally(() => {
      inFlightMap.delete(key);
    });

  inFlightMap.set(key, p);
  return p;
}

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

  useVisibilityInterval(
    () => {
      void refetch(true);
    },
    enabled && pollMs && pollMs > 0 ? pollMs : null,
  );

  return { data, loading, refreshing, error, refetch, setData };
}

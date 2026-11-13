import { useState, useEffect, useCallback } from 'react';

export interface HashRouteState<T extends string> {
  tab: T;
  sub?: string;
}

function parseHash<T extends string>(raw: string, validTabs: readonly T[], fallback: T): HashRouteState<T> {
  const clean = (raw || '').replace(/^#\/?/, '').trim();
  if (!clean) return { tab: fallback };

  const [pathPart, queryPart] = clean.split('?');
  const [rawTab, rawSubPath] = pathPart.split('/');
  const params = new URLSearchParams(queryPart || '');
  const sub = params.get('sub') || rawSubPath || undefined;

  if (validTabs.includes(rawTab as T)) {
    return { tab: rawTab as T, sub };
  }
  return { tab: fallback };
}

function formatHash<T extends string>(tab: T, sub?: string): string {
  if (sub) return `#/${tab}?sub=${encodeURIComponent(sub)}`;
  return `#/${tab}`;
}

/**
 * 纯 Hash 路由 Hook：严禁改动 pathname（兼容服务端 Caddy 随机前缀与客户端 Clash 根路径反代）。
 */
export function useHashRoute<T extends string>(validTabs: readonly T[], defaultTab: T) {
  const [route, setRoute] = useState<HashRouteState<T>>(() =>
    parseHash(typeof window !== 'undefined' ? window.location.hash : '', validTabs, defaultTab),
  );

  useEffect(() => {
    const onHashChange = () => {
      setRoute(parseHash(window.location.hash, validTabs, defaultTab));
    };
    window.addEventListener('hashchange', onHashChange);
    return () => window.removeEventListener('hashchange', onHashChange);
  }, [validTabs, defaultTab]);

  const navigate = useCallback(
    (nextTab: T, sub?: string) => {
      const targetHash = formatHash(nextTab, sub);
      if (window.location.hash !== targetHash) {
        window.location.hash = targetHash;
      }
      setRoute({ tab: nextTab, sub });
    },
    [],
  );

  return {
    tab: route.tab,
    sub: route.sub,
    navigate,
  };
}

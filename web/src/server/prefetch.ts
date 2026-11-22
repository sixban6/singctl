import { api } from './api';
import { peekCachedQuery, prefetchCachedQuery } from '../hooks';

export const SUBS_CACHE_KEY = 'server:subs:main';
export const SUBS_AUDIT_CACHE_KEY = 'server:subs:audit';

export const HEAL_CACHE_KEY = 'server:sec:heal';
export const BANS_CACHE_KEY = 'server:sec:bans';
export const SNIFF_CACHE_KEY = 'server:sec:sniff:all';

export const WARP_ROUTING_CACHE_KEY = 'server:warp:routing:local';
export const WARP_CONNS_CACHE_KEY = 'server:warp:conns:local';

export const FLEET_CACHE_KEY = 'server:fleet:list';
export const FLEET_DEFAULTS_CACHE_KEY = 'server:fleet:defaults';

export function prefetchSubscriptionsTab(): void {
  void import('./pages/SubscriptionsTab');
  if (!peekCachedQuery(SUBS_CACHE_KEY)) {
    void prefetchCachedQuery(SUBS_CACHE_KEY, () => api.getSubscriptions());
  }
  if (!peekCachedQuery(SUBS_AUDIT_CACHE_KEY)) {
    void prefetchCachedQuery(SUBS_AUDIT_CACHE_KEY, () => api.getSubscriptionAuditLogs());
  }
}

export function prefetchSecurityTab(): void {
  void import('./pages/SecurityTab');
  if (!peekCachedQuery(HEAL_CACHE_KEY)) {
    void prefetchCachedQuery(HEAL_CACHE_KEY, () => api.getHealStatus(false));
  }
  if (!peekCachedQuery(BANS_CACHE_KEY)) {
    void prefetchCachedQuery(BANS_CACHE_KEY, () => api.getBans());
  }
  if (!peekCachedQuery(SNIFF_CACHE_KEY)) {
    void prefetchCachedQuery(SNIFF_CACHE_KEY, () => api.getSniffers('all', false));
  }
}

export function prefetchWarpTab(): void {
  void import('./pages/WarpTab');
  if (!peekCachedQuery(WARP_ROUTING_CACHE_KEY)) {
    void prefetchCachedQuery(WARP_ROUTING_CACHE_KEY, () => api.getWarpRouting(false, 'local'));
  }
  if (!peekCachedQuery(WARP_CONNS_CACHE_KEY)) {
    void prefetchCachedQuery(WARP_CONNS_CACHE_KEY, () => api.getWarpConnections('', 'all', 'local'));
  }
}

export function prefetchFleetTab(): void {
  void import('./pages/FleetTab');
  if (!peekCachedQuery(FLEET_CACHE_KEY)) {
    void prefetchCachedQuery(FLEET_CACHE_KEY, () => api.getFleet());
  }
  if (!peekCachedQuery(FLEET_DEFAULTS_CACHE_KEY)) {
    void prefetchCachedQuery(FLEET_DEFAULTS_CACHE_KEY, () => api.getFleetDefaults());
  }
}

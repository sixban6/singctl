import {
  ClientGatewayConfigResponse,
  FirewallApplyPayload,
  FirewallLogEvent,
  FirewallOverviewResponse,
  GatewayIPv6Mode,
  GatewayRoleMode,
  TailscaleConfigResponse,
  TailscaleP2PAssistConfig,
  TailscaleP2PPokeResult,
  TailscaleP2PReport,
  TailscaleUpgradePreflight,
  TailscaleUpgradeStatusResponse,
  WatchdogReport,
} from '../types';
import { request } from './session';

export const networkApi = {
  getGateway: () => request<ClientGatewayConfigResponse>('/api/gateway'),

  saveGateway: (payload: {
    mode: GatewayRoleMode;
    mainRouterIP?: string;
    lanIface?: string;
    ipv6Mode?: GatewayIPv6Mode;
  }) =>
    request<
      ClientGatewayConfigResponse & {
        ok: boolean;
        appliedLive: boolean;
        message: string;
      }
    >('/api/gateway', {
      method: 'PUT',
      body: JSON.stringify(payload),
    }),

  getTailscaleConfig: () => request<TailscaleConfigResponse>('/api/tailscale/config'),

  saveTailscaleConfig: (payload: {
    authKey?: string;
    clearAuthKey?: boolean;
    subnets?: string;
    useBuild?: boolean;
  }) =>
    request<{ ok: boolean } & TailscaleConfigResponse>('/api/tailscale/config', {
      method: 'PUT',
      body: JSON.stringify(payload),
    }),

  getTailscaleP2P: () => request<TailscaleP2PReport>('/api/tailscale/p2p'),

  saveTailscaleP2P: (payload: TailscaleP2PAssistConfig) =>
    request<TailscaleP2PReport>('/api/tailscale/p2p', {
      method: 'PUT',
      body: JSON.stringify(payload),
    }),

  pokeTailscaleP2P: (payload: { id?: string; name?: string }) =>
    request<TailscaleP2PPokeResult>('/api/tailscale/p2p/poke', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),

  getTailscaleUpgradePreflight: () =>
    request<TailscaleUpgradePreflight>('/api/tailscale/upgrade/preflight'),

  getTailscaleUpgradeStatus: (timeoutMs = 3000) =>
    request<TailscaleUpgradeStatusResponse>('/api/tailscale/upgrade/status', { timeoutMs }),

  getFirewallOverview: (params?: {
    scope?: string;
    search?: string;
    sort?: string;
    page?: number;
    pageSize?: number;
  }) => {
    const qs = new URLSearchParams();
    if (params?.scope && params.scope !== 'all') qs.set('scope', params.scope);
    if (params?.search) qs.set('search', params.search);
    if (params?.sort) qs.set('sort', params.sort);
    if (params?.page) qs.set('page', String(params.page));
    if (params?.pageSize) qs.set('pageSize', String(params.pageSize));
    const q = qs.toString();
    return request<FirewallOverviewResponse>(`/api/firewall/overview${q ? `?${q}` : ''}`);
  },

  getFirewallLogs: (limit = 50) =>
    request<{ ok: boolean; events: FirewallLogEvent[] }>(`/api/firewall/logs?limit=${limit}`),

  applyFirewall: (payload: FirewallApplyPayload) =>
    request<{ ok: boolean; message: string; overview: FirewallOverviewResponse }>('/api/firewall/apply', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),

  disableFirewall: () =>
    request<{ ok: boolean; message: string; overview: FirewallOverviewResponse }>('/api/firewall/disable', {
      method: 'POST',
      body: '{}',
    }),

  banFirewallTarget: (payload: { target: string; scope: 'dynamic' | 'forever'; timeoutDays?: number }) =>
    request<{ ok: boolean; target: string; scope: string; message: string; overview: FirewallOverviewResponse }>(
      '/api/firewall/ban',
      {
        method: 'POST',
        body: JSON.stringify(payload),
      },
    ),

  unbanFirewallTarget: (payload: { target: string; scope?: string }) =>
    request<{ ok: boolean; message: string; overview: FirewallOverviewResponse }>('/api/firewall/unban', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),

  clearDynamicFirewallBans: (family: 'all' | 'ipv4' | 'ipv6' = 'all') =>
    request<{ ok: boolean; message: string; overview: FirewallOverviewResponse }>('/api/firewall/clear-dynamic', {
      method: 'POST',
      body: JSON.stringify({ family }),
    }),

  manageFirewallWhitelist: (action: 'add' | 'remove', target: string) =>
    request<{
      ok: boolean;
      target: string;
      whitelist: string[];
      message: string;
      overview: FirewallOverviewResponse;
    }>('/api/firewall/whitelist', {
      method: 'POST',
      body: JSON.stringify({ action, target }),
    }),

  getWatchdog: () => request<WatchdogReport>('/api/watchdog'),

  updateWatchdogConfig: (payload: Record<string, unknown>) =>
    request<WatchdogReport & { ok?: boolean; message?: string; report?: WatchdogReport }>(
      '/api/watchdog/config',
      { method: 'PUT', body: JSON.stringify(payload) },
    ),

  runWatchdogPatrol: () =>
    request<{ message?: string; events?: { summary: string }[]; report?: WatchdogReport }>(
      '/api/watchdog/patrol',
      { method: 'POST', body: '{}' },
    ),
};

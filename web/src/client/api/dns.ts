import {
  AdGuardCredentialsResponse,
  AdGuardOverviewSnapshot,
  AdGuardProbeResult,
  AdGuardUpstreamMode,
  AdGuardUpstreamServerInfo,
  BrowserDoHCheckRequest,
  BrowserDoHCheckResponse,
  DNSLeakReport,
} from '../types';
import { request } from './session';

export const dnsApi = {
  runDNSLeakTest: (mode: 'standard' | 'deep' = 'standard') =>
    request<DNSLeakReport>('/api/dns/leak-test', {
      method: 'POST',
      body: JSON.stringify({ mode }),
    }),

  checkBrowserDoH: (payload: BrowserDoHCheckRequest = {}) =>
    request<BrowserDoHCheckResponse>('/api/dns/browser-doh', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),

  getAdGuardOverview: () => request<AdGuardOverviewSnapshot>('/api/adguard'),

  getAdGuardCredentials: () => request<AdGuardCredentialsResponse>('/api/adguard/credentials'),

  resetAdGuardCredentials: (username = '') =>
    request<AdGuardCredentialsResponse>('/api/adguard/credentials/reset', {
      method: 'POST',
      body: JSON.stringify({ username }),
    }),

  setAdGuardProtection: (enabled: boolean, durationMinutes = 0) =>
    request<{ ok: boolean }>('/api/adguard/protection', {
      method: 'POST',
      body: JSON.stringify({ enabled, durationMinutes }),
    }),

  clearAdGuardCache: () =>
    request<{ ok: boolean }>('/api/adguard/cache/clear', { method: 'POST', body: '{}' }),

  probeAdGuardUpstream: () =>
    request<AdGuardProbeResult>('/api/adguard/probe', { method: 'POST', body: '{}' }),

  saveAdGuardUpstreams: (payload: {
    upstreams?: string[];
    upstreamMode?: AdGuardUpstreamMode;
    resetDefault?: boolean;
  }) =>
    request<{
      ok: boolean;
      upstreams: AdGuardUpstreamServerInfo[];
      upstreamMode: AdGuardUpstreamMode;
      upstreamModeLabel: string;
      notes?: string[];
    }>('/api/adguard/upstreams', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),

  setAdGuardWhitelist: (action: 'add' | 'remove', domain: string) =>
    request<{ ok: boolean }>('/api/adguard/whitelist', {
      method: 'POST',
      body: JSON.stringify({ action, domain }),
    }),

  manageAdGuardRewrite: (action: 'add' | 'delete', domain: string, answer: string) =>
    request<{ ok: boolean }>('/api/adguard/rewrites', {
      method: 'POST',
      body: JSON.stringify({ action, domain, answer }),
    }),

  manageAdGuardFilter: (payload: {
    action: 'toggle' | 'add' | 'remove' | 'refresh';
    url?: string;
    name?: string;
    enabled?: boolean;
  }) =>
    request<{ ok: boolean }>('/api/adguard/filters', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),
};

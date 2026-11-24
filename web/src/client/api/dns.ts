import {
  AdGuardCredentialsResponse,
  AdGuardUpstreamServerInfo,
  BrowserDoHCheckRequest,
  BrowserDoHCheckResponse,
  DNSBypassGuardSnapshot,
  DNSBypassGuardUpdateRequest,
  DNSConfigPreviewResponse,
  DNSLeakReport,
  DNSOverviewSnapshot,
  DNSSwitchEngineRequest,
  DNSSwitchEngineResponse,
  DNSUpstreamMode,
  UpstreamProbeReport,
} from '../types';
import { request } from './session';

const getDNSOverview = () => request<DNSOverviewSnapshot>('/api/dns/overview');

const getDNSCredentials = () => request<AdGuardCredentialsResponse>('/api/dns/credentials');

const resetDNSCredentials = (username = '') =>
  request<AdGuardCredentialsResponse>('/api/dns/credentials/reset', {
    method: 'POST',
    body: JSON.stringify({ username }),
  });

const fetchDNSConfigPreview = () => request<DNSConfigPreviewResponse>('/api/dns/config-preview');

const switchDNSEngine = (payload: DNSSwitchEngineRequest) =>
  request<DNSSwitchEngineResponse>('/api/dns/engine', {
    method: 'POST',
    body: JSON.stringify(payload),
  });

const setDNSProtection = (enabled: boolean, durationMinutes = 0) =>
  request<{ ok: boolean }>('/api/dns/protection', {
    method: 'POST',
    body: JSON.stringify({ enabled, durationMinutes }),
  });

const clearDNSCache = () =>
  request<{ ok: boolean }>('/api/dns/cache/clear', { method: 'POST', body: '{}' });

const probeDNSUpstream = () =>
  request<UpstreamProbeReport>('/api/dns/probe', { method: 'POST', body: '{}' });

const saveDNSUpstreams = (payload: {
  upstreams?: string[];
  upstreamMode?: DNSUpstreamMode;
  resetDefault?: boolean;
}) =>
  request<{
    ok: boolean;
    upstreams: AdGuardUpstreamServerInfo[];
    upstreamMode: DNSUpstreamMode;
    upstreamModeLabel: string;
    notes?: string[];
  }>('/api/dns/upstreams', {
    method: 'POST',
    body: JSON.stringify(payload),
  });

const setDNSWhitelist = (action: 'add' | 'remove', domain: string) =>
  request<{ ok: boolean }>('/api/dns/whitelist', {
    method: 'POST',
    body: JSON.stringify({ action, domain }),
  });

const manageDNSRewrite = (action: 'add' | 'delete', domain: string, answer: string) =>
  request<{ ok: boolean }>('/api/dns/rewrites', {
    method: 'POST',
    body: JSON.stringify({ action, domain, answer }),
  });

const manageDNSFilter = (payload: {
  action: 'toggle' | 'add' | 'remove' | 'refresh';
  url?: string;
  name?: string;
  enabled?: boolean;
}) =>
  request<{ ok: boolean }>('/api/dns/filters', {
    method: 'POST',
    body: JSON.stringify(payload),
  });

const getDNSBypassGuard = () => request<DNSBypassGuardSnapshot>('/api/dns/bypass-guard');

const saveDNSBypassGuard = (payload: DNSBypassGuardUpdateRequest) =>
  request<{ ok: boolean; bypassGuard: DNSBypassGuardSnapshot }>('/api/dns/bypass-guard', {
    method: 'POST',
    body: JSON.stringify(payload),
  });

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

  // 统一双引擎 /api/dns/* 契约方法（SmartDNS / AdGuard Home）
  getDNSOverview,
  getDNSCredentials,
  resetDNSCredentials,
  fetchDNSConfigPreview,
  switchDNSEngine,
  setDNSProtection,
  clearDNSCache,
  probeDNSUpstream,
  saveDNSUpstreams,
  setDNSWhitelist,
  manageDNSRewrite,
  manageDNSFilter,
  getDNSBypassGuard,
  saveDNSBypassGuard,

  // 向后兼容既有调用方的方法别名（全部指向 /api/dns/*）
  getAdGuardOverview: getDNSOverview,
  getAdGuardCredentials: getDNSCredentials,
  resetAdGuardCredentials: resetDNSCredentials,
  setAdGuardProtection: setDNSProtection,
  clearAdGuardCache: clearDNSCache,
  probeAdGuardUpstream: probeDNSUpstream,
  saveAdGuardUpstreams: saveDNSUpstreams,
  setAdGuardWhitelist: setDNSWhitelist,
  manageAdGuardRewrite: manageDNSRewrite,
  manageAdGuardFilter: manageDNSFilter,
};

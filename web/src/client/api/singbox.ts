import {
  ClientConfigSubDTO,
  ClientGroupsGetResponse,
  ClientGroupsPreviewResponse,
  ClientGroupsPutResponse,
  ClientRoutingReport,
  SbConfigResponse,
  SbProxiesSnapshot,
  SbProxyMode,
  SbTrafficSnapshot,
} from '../types';
import { request } from './session';

export const singboxApi = {
  saveSbSubs: (payload: { subs: ClientConfigSubDTO[]; hy2: { up: number; down: number } }) =>
    request<{ ok: boolean }>('/api/sb/subs', { method: 'PUT', body: JSON.stringify(payload) }),

  getIOSUrl: () => request<{ url: string; importUrl?: string }>('/api/gen/ios/url'),

  getSbConfig: () => request<SbConfigResponse>('/api/sbconfig'),

  saveSbConfig: (content: string) =>
    request<{ ok: boolean; checked: boolean }>('/api/sbconfig', {
      method: 'PUT',
      body: JSON.stringify({ content }),
    }),

  setSbConfigPreserve: (preserve: boolean) =>
    request<{ ok: boolean; preserveManualConfig: boolean }>('/api/sbconfig/preserve', {
      method: 'PUT',
      body: JSON.stringify({ preserve }),
    }),

  restoreSbConfig: (name: string) =>
    request<{ ok: boolean }>('/api/sbconfig/restore', {
      method: 'POST',
      body: JSON.stringify({ name }),
    }),

  getSbProxies: () => request<SbProxiesSnapshot>('/api/sb/proxies'),

  switchSbProxy: (group: string, target: string) =>
    request<{ ok: boolean; group: string; target: string; message: string; snapshot?: SbProxiesSnapshot }>(
      '/api/sb/proxies/switch',
      { method: 'PUT', body: JSON.stringify({ group, target }) },
    ),

  testSbProxyDelay: (payload: { group?: string; node?: string; url?: string; timeoutMs?: number }) =>
    request<{
      ok: boolean;
      url: string;
      delays: Record<string, number>;
      testedCount: number;
      okCount: number;
      snapshot?: SbProxiesSnapshot;
    }>('/api/sb/proxies/delay', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),

  setSbMode: (mode: SbProxyMode) =>
    request<{ ok: boolean; mode: string; message: string; snapshot?: SbProxiesSnapshot }>('/api/sb/mode', {
      method: 'PUT',
      body: JSON.stringify({ mode }),
    }),

  getSbTraffic: () => request<SbTrafficSnapshot>('/api/sb/traffic'),

  getTrafficRouting: () => request<ClientRoutingReport>('/api/traffic-routing'),

  updateTrafficRouting: (payload: {
    reset?: boolean;
    replace?: boolean;
    presets?: Record<string, { enabled?: boolean; outbound?: string }>;
  }) =>
    request<{ ok: boolean; applied: boolean; message: string; report: ClientRoutingReport }>(
      '/api/traffic-routing',
      { method: 'PUT', body: JSON.stringify(payload) },
    ),

  getGroups: () => request<ClientGroupsGetResponse>('/api/groups'),

  previewGroups: (content: string) =>
    request<ClientGroupsPreviewResponse>('/api/groups/preview', {
      method: 'POST',
      body: JSON.stringify({ content }),
    }),

  saveGroups: (payload: { content?: string; reset?: boolean }) =>
    request<ClientGroupsPutResponse>('/api/groups', {
      method: 'PUT',
      body: JSON.stringify(payload),
    }),
};

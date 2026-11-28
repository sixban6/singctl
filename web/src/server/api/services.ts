import {
  CamouflageDefaultsResponse,
  CamouflageReport,
  CheckUpdateResponse,
  ServerSocketTuneApplyResponse,
  ServerSocketTuneStatus,
} from '../types';
import { LONG_OP_TIMEOUT_MS, MEDIUM_OP_TIMEOUT_MS, request } from './http';

export const servicesApi = {
  serviceAction: (service: string, action: 'start' | 'stop' | 'restart' | 'reload') =>
    request<{ message: string }>('/api/server/service/action', {
      method: 'POST',
      body: JSON.stringify({ service, action }),
      timeoutMs: MEDIUM_OP_TIMEOUT_MS,
    }),

  checkServiceUpdate: (service: string) =>
    request<CheckUpdateResponse>(`/api/server/service/check-update?service=${encodeURIComponent(service)}`, {
      timeoutMs: 25000,
    }),

  upgradeService: (service: string) =>
    request<{ message: string; willRestartUI?: boolean; results?: any[] }>('/api/server/service/upgrade', {
      method: 'POST',
      body: JSON.stringify({ service }),
      timeoutMs: LONG_OP_TIMEOUT_MS,
    }),

  getServiceConfig: (service: string) =>
    request<{ service: string; path: string; content: string }>(
      `/api/server/service/config?service=${encodeURIComponent(service)}`,
    ),

  updateServiceConfig: (service: string, content: string) =>
    request<{ message: string }>('/api/server/service/config', {
      method: 'PUT',
      body: JSON.stringify({ service, content }),
    }),

  enableBBR: () =>
    request<{ message: string; bbr: boolean }>('/api/server/bbr', {
      method: 'POST',
    }),

  getSocketTune: () =>
    request<ServerSocketTuneStatus>('/api/server/socket-tune'),

  applySocketTune: (payload: { defaultPreset?: 'auto' | '4m' | '8m'; restartCaddy?: boolean }) =>
    request<ServerSocketTuneApplyResponse>('/api/server/socket-tune', {
      method: 'POST',
      body: JSON.stringify(payload),
      timeoutMs: MEDIUM_OP_TIMEOUT_MS,
    }),

  updateSNI: (sni: string) =>
    request<{ message: string; sni: string }>('/api/server/sni', {
      method: 'PUT',
      body: JSON.stringify({ sni }),
      timeoutMs: MEDIUM_OP_TIMEOUT_MS,
    }),

  regeneratePath: () =>
    request<{ message: string; path: string; httpsUrl: string }>('/api/server/path/regenerate', {
      method: 'POST',
      timeoutMs: MEDIUM_OP_TIMEOUT_MS,
    }),

  regenerateMaskSite: () =>
    request<{ message: string; meta: any }>('/api/server/mask-site/regenerate', {
      method: 'POST',
      timeoutMs: MEDIUM_OP_TIMEOUT_MS,
    }),

  getCamouflageDefaults: () =>
    request<CamouflageDefaultsResponse>('/api/server/camouflage/defaults'),

  runCamouflageProbe: (input: { ip?: string; domain?: string; sni?: string; ports?: string; timeoutSec?: number }) =>
    request<CamouflageReport>('/api/server/camouflage/probe', {
      method: 'POST',
      body: JSON.stringify(input),
      timeoutMs: MEDIUM_OP_TIMEOUT_MS,
    }),
};

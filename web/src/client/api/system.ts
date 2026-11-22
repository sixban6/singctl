import {
  CacheResponse,
  ClientBackupExportResponse,
  ClientBackupRestoreResponse,
  ClientConfigDTO,
  ClientHealthResponse,
  ClientLogsResponse,
  ClientStatusResponse,
} from '../types';
import { clearSavedClientToken, request, saveClientToken } from './session';

export const systemApi = {
  checkAuth: (timeoutMs = 2500) =>
    request<{
      ok: boolean;
      authRequired: boolean;
      authenticated: boolean;
      version?: string;
    }>('/api/auth/check', {
      timeoutMs,
      skipUnauthorizedHook: true,
      formatHttpError: (status) => `HTTP ${status}`,
    }),

  login: async (password: string) => {
    const data = await request<{ ok: boolean; token: string }>('/api/auth/login', {
      method: 'POST',
      body: JSON.stringify({ password }),
      timeoutMs: 10000,
      skipUnauthorizedHook: true,
      timeoutMessage: '登录请求超时，请检查网关连接后重试',
      formatHttpError: (status, jsonError) => jsonError || `验证失败 (HTTP ${status})`,
    });
    if (data?.token) {
      saveClientToken(data.token);
    }
    return data;
  },

  getStatus: async (timeoutMs?: number) => {
    const res = await request<ClientStatusResponse>('/api/status', { timeoutMs });
    if (res?.sessionToken) {
      saveClientToken(res.sessionToken);
    }
    return res;
  },

  getHealth: () => request<ClientHealthResponse>('/api/health'),

  getConfig: () => request<{ path: string; config: ClientConfigDTO }>('/api/config'),

  saveConfig: (config: ClientConfigDTO) =>
    request<{ ok: boolean }>('/api/config', { method: 'PUT', body: JSON.stringify(config) }),

  getConfigRaw: () => request<{ path: string; content: string }>('/api/config/raw'),

  saveConfigRaw: (content: string) =>
    request<{ ok: boolean }>('/api/config/raw', { method: 'PUT', body: JSON.stringify({ content }) }),

  saveSystemMirror: (mirrorUrl: string) =>
    request<{ ok: boolean; mirrorUrl: string }>('/api/system/mirror', {
      method: 'PUT',
      body: JSON.stringify({ mirrorUrl }),
    }),

  getCache: () => request<CacheResponse>('/api/cache'),

  getLogs: (name: string, tail: number) =>
    request<ClientLogsResponse>(`/api/logs?name=${encodeURIComponent(name)}&tail=${tail}`),

  clearLogs: (name: string) =>
    request<{ ok: boolean; name: string; path: string; message: string }>('/api/logs/clear', {
      method: 'POST',
      body: JSON.stringify({ name }),
    }),

  getSessionUrl: () => request<{ url: string; token: string }>('/api/session/url'),

  logout: async () => {
    const res = await request<{ message: string }>('/api/logout', { method: 'POST', body: '{}' });
    clearSavedClientToken();
    return res;
  },

  exportBackup: (passphrase: string) =>
    request<ClientBackupExportResponse>('/api/backup/export', {
      method: 'POST',
      body: JSON.stringify({ passphrase }),
    }),

  restoreBackup: (passphrase: string, data: string) =>
    request<ClientBackupRestoreResponse>('/api/backup/restore', {
      method: 'POST',
      body: JSON.stringify({ passphrase, data }),
    }),
};

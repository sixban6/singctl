import { composeAbortSignals } from '../../lib/http';
import {
  AuditLogItem,
  BackupExportResponse,
  BannedIP,
  CertHealthItem,
  HealRunResponse,
  HealStatusReport,
  SniffSummary,
} from '../types';
import { ApiError, getBasePath, LONG_OP_TIMEOUT_MS, MEDIUM_OP_TIMEOUT_MS, request } from './http';

export const securityApi = {
  login: async (username: string, password: string, signal?: AbortSignal) => {
    const payload = JSON.stringify({ username, password });
    try {
      return await request<{ message: string; username: string }>('/api/server/login', {
        method: 'POST',
        body: payload,
        timeoutMs: 6000,
        signal,
      });
    } catch (err) {
      // 当浏览器复用了服务端重启/切网后僵尸化的 HTTP/2 或 QUIC 流导致无响应超时时，
      // 先强制 reload 探测驱逐死连接，再自动建立全新连接重试一次（未收到 401 不会消耗防爆破计数）
      if (!signal?.aborted && err instanceof ApiError && (err.status === 408 || err.status === 0)) {
        const warm = composeAbortSignals(signal, 1500);
        await fetch(`${getBasePath()}/?_ping=${Date.now()}`, {
          method: 'HEAD',
          cache: 'reload',
          credentials: 'same-origin',
          signal: warm.signal,
        })
          .catch(() => {})
          .finally(() => warm.cleanup());

        return request<{ message: string; username: string }>(`/api/server/login?_retry=${Date.now()}`, {
          method: 'POST',
          body: payload,
          timeoutMs: 8000,
          signal,
        });
      }
      throw err;
    }
  },

  logout: () =>
    request<{ message: string }>('/api/server/logout', {
      method: 'POST',
    }),

  updateCredentials: (body: { currentPassword: string; newUsername: string; newPassword: string }) =>
    request<{ message: string; username: string }>('/api/server/credentials', {
      method: 'PUT',
      body: JSON.stringify(body),
    }),

  ackInitialPassword: () =>
    request<{ message: string }>('/api/server/credentials/ack', {
      method: 'POST',
    }),

  getBans: () =>
    request<{ bans: BannedIP[]; loginFailCount?: number; manualSniffCount?: number }>('/api/server/bans'),

  getSniffers: (node = 'all', refresh = false) =>
    request<SniffSummary>(
      `/api/server/security/sniffers?node=${encodeURIComponent(node)}${refresh ? '&refresh=1' : ''}`,
    ),

  blockSniffer: (target: string, node = 'all', viewNode = 'all') =>
    request<{ message: string; target: string; appliedNodes?: number; summary: SniffSummary }>(
      '/api/server/security/block',
      {
        method: 'POST',
        body: JSON.stringify({ target, node, viewNode }),
        timeoutMs: MEDIUM_OP_TIMEOUT_MS,
      },
    ),

  getAuditLogs: () => request<{ logs: AuditLogItem[] }>('/api/server/audit-logs'),

  unban: (ip: string, node = 'all', viewNode = 'all') =>
    request<{ message: string; unbanned: string; appliedNodes?: number; summary?: SniffSummary }>(
      '/api/server/unban',
      {
        method: 'POST',
        body: JSON.stringify({ ip, node, viewNode }),
        timeoutMs: MEDIUM_OP_TIMEOUT_MS,
      },
    ),

  getCerts: (refresh = false) =>
    request<{ certs: CertHealthItem[] }>(`/api/server/certs${refresh ? '?refresh=1' : ''}`),

  exportBackup: (passphrase: string) =>
    request<BackupExportResponse>('/api/server/backup/export', {
      method: 'POST',
      body: JSON.stringify({ passphrase }),
      timeoutMs: MEDIUM_OP_TIMEOUT_MS,
    }),

  restoreBackup: (passphrase: string, data: string) =>
    request<{ message: string; restoredItems: string[] }>('/api/server/backup/restore', {
      method: 'POST',
      body: JSON.stringify({ passphrase, data }),
      timeoutMs: LONG_OP_TIMEOUT_MS,
    }),

  getHealStatus: (refresh = false) =>
    request<HealStatusReport>(`/api/server/heal/status${refresh ? '?refresh=1' : ''}`, {
      timeoutMs: MEDIUM_OP_TIMEOUT_MS,
    }),

  runHeal: (opts: {
    scope?: 'local' | 'fleet';
    checkOnly?: boolean;
    allowReboot?: boolean;
    enableTimers?: boolean;
    targetIds?: string[];
  }) =>
    request<HealRunResponse>('/api/server/heal/run', {
      method: 'POST',
      body: JSON.stringify(opts),
      timeoutMs: LONG_OP_TIMEOUT_MS,
    }),

  updateHealPolicy: (opts: {
    autoHealEnabled: boolean;
    schedule?: string;
    autoReboot?: boolean;
    applyToFleet?: boolean;
  }) =>
    request<{ message: string; status: HealStatusReport }>('/api/server/heal/policy', {
      method: 'PUT',
      body: JSON.stringify(opts),
      timeoutMs: MEDIUM_OP_TIMEOUT_MS,
    }),
};

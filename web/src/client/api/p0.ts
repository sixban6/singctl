import {
  DoctorReport,
  NotifyConfigDTO,
  NotifyConfigResponse,
  NotifyDeliveryResult,
  NotifyHistoryRecord,
  NotifySecretStatus,
  OOMShieldStatus,
  SafeCommitConfig,
  SafeCommitRollbackRecord,
  SafeCommitStatusResponse,
} from '../types';
import { request } from './session';

export const p0Api = {
  getSafeCommitStatus: () => request<SafeCommitStatusResponse>('/api/safe-commit/status'),

  armSafeCommit: (body: { ttlSec?: number; reason?: string } = {}) =>
    request<{ ok: boolean; status: SafeCommitStatusResponse }>('/api/safe-commit/arm', {
      method: 'POST',
      body: JSON.stringify(body),
    }),

  confirmSafeCommit: (token?: string) =>
    request<{ ok: boolean; confirmed: boolean; status: SafeCommitStatusResponse }>(
      '/api/safe-commit/confirm',
      {
        method: 'POST',
        body: JSON.stringify(token ? { token } : {}),
      },
    ),

  rollbackSafeCommit: (trigger?: string) =>
    request<{ ok: boolean; record: SafeCommitRollbackRecord; status: SafeCommitStatusResponse }>(
      '/api/safe-commit/rollback',
      {
        method: 'POST',
        body: JSON.stringify(trigger ? { trigger } : {}),
        timeoutMs: 30000,
      },
    ),

  protectTailscaleOOM: () =>
    request<{ ok: boolean; tailscaleOom: OOMShieldStatus; error?: string }>(
      '/api/safe-commit/oom-protect',
      {
        method: 'POST',
        body: '{}',
      },
    ),

  saveSafeCommitConfig: (cfg: SafeCommitConfig) =>
    request<{ ok: boolean; config: SafeCommitConfig; tailscaleOom: OOMShieldStatus }>(
      '/api/safe-commit/config',
      {
        method: 'PUT',
        body: JSON.stringify(cfg),
      },
    ),

  getNotifyConfig: () => request<NotifyConfigResponse>('/api/notify/config'),

  saveNotifyConfig: (config: NotifyConfigDTO) =>
    request<{ ok: boolean; config: NotifyConfigDTO; secretStatus: NotifySecretStatus }>(
      '/api/notify/config',
      {
        method: 'PUT',
        body: JSON.stringify({ config }),
      },
    ),

  testNotify: (body: { channel?: string; config?: NotifyConfigDTO } = {}) =>
    request<{
      ok: boolean;
      results: NotifyDeliveryResult[];
      recentHistory: NotifyHistoryRecord[];
    }>('/api/notify/test', {
      method: 'POST',
      body: JSON.stringify(body),
      timeoutMs: 25000,
    }),

  runDoctor: () => request<DoctorReport>('/api/doctor/run', { timeoutMs: 30000 }),

  runDoctorFix: (action: string) =>
    request<{ ok: boolean; action: string; message: string }>('/api/doctor/fix', {
      method: 'POST',
      body: JSON.stringify({ action }),
      timeoutMs: 30000,
    }),
};

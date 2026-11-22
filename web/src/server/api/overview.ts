import {
  DoctorReport,
  MediaUnlockReport,
  ReturnSummary,
  ServerStatusResponse,
  TelemetrySnapshot,
} from '../types';
import { MEDIUM_OP_TIMEOUT_MS, request } from './http';

export const overviewApi = {
  getStatus: () => request<ServerStatusResponse>('/api/server/status', { timeoutMs: 8000 }),

  getTelemetrySnapshot: () => request<TelemetrySnapshot>('/api/server/telemetry/snapshot'),

  enableTelemetry: () =>
    request<{ message: string; changed: boolean; snapshot: TelemetrySnapshot }>('/api/server/telemetry/enable', {
      method: 'POST',
      body: JSON.stringify({}),
    }),

  getDoctorReport: () => request<DoctorReport>('/api/server/doctor', { timeoutMs: MEDIUM_OP_TIMEOUT_MS }),

  getNetReturn: () => request<ReturnSummary>('/api/server/net/return', { timeoutMs: 70000 }),

  getMediaUnlock: () => request<MediaUnlockReport>('/api/server/diagnose/unlock', { timeoutMs: MEDIUM_OP_TIMEOUT_MS }),

  getServiceLogs: (service: string, lines = 100) =>
    request<{ service: string; logs: string }>(
      `/api/server/service/logs?service=${encodeURIComponent(service)}&lines=${lines}`,
    ),
};

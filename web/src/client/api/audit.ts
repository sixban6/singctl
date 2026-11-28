import {
  AuditAIConfig,
  AuditAIModelsResponse,
  AuditAIReview,
  AuditBlockBatchItem,
  AuditBlockBatchResult,
  AuditDeviceAccessResult,
  AuditFlowRecord,
  AuditReport,
  AuditRouteRuleDeleteRequest,
  AuditRouteRuleResponse,
  AuditRouteRuleUpsertRequest,
} from '../types';
import { clientHttp, request } from './session';

export const auditApi = {
  getAudit: (qs: URLSearchParams, signal?: AbortSignal) =>
    request<AuditReport>(`/api/audit?${qs.toString()}`, { timeoutMs: 12000, ...(signal ? { signal } : {}) }),

  downloadAuditCSV: (qs: URLSearchParams, signal?: AbortSignal): Promise<string> =>
    clientHttp.requestText(`/api/audit?${qs.toString()}`, signal ? { signal } : {}),

  getAuditAIConfig: () => request<AuditAIConfig>('/api/audit/ai-config'),

  saveAuditAIConfig: (payload: { baseUrl: string; apiKey: string; model: string }) =>
    request<{ ok: boolean; message: string; model: string }>('/api/audit/ai-config', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),

  fetchAuditAIModels: (payload: { baseUrl: string; apiKey: string }) =>
    request<AuditAIModelsResponse>('/api/audit/ai-models', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),

  reviewAuditBatch: (flows: AuditFlowRecord[], force = false) =>
    request<{ ok: boolean; usedRemote: boolean; results: Record<string, AuditAIReview> }>('/api/audit/ai-review', {
      method: 'POST',
      body: JSON.stringify({ flows, force }),
    }),

  blockAuditTarget: (target: string, sourceIp: string, reason: string) =>
    request<{ message?: string }>('/api/audit/block', {
      method: 'POST',
      body: JSON.stringify({ target, sourceIp, reason }),
    }),

  blockAuditBatch: (items: AuditBlockBatchItem[]) =>
    request<AuditBlockBatchResult>('/api/audit/block-batch', {
      method: 'POST',
      body: JSON.stringify({ items }),
    }),

  unblockAuditTarget: (target: string, sourceIp: string) =>
    request<{ message?: string }>('/api/audit/unblock', {
      method: 'POST',
      body: JSON.stringify({ target, sourceIp }),
    }),

  togglePCDNBlock: (enabled: boolean) =>
    request<{
      ok?: boolean;
      pcdnBlockEnabled?: boolean;
      target?: string;
      configSaved?: boolean;
      singboxSynced?: boolean;
      killedConnections?: number;
      message?: string;
    }>('/api/audit/pcdn-block', {
      method: 'POST',
      body: JSON.stringify({ enabled }),
    }),

  setAuditThrottle: (payload: { target: string; port?: number; rateKbps: number; comment?: string }) =>
    request<{
      ok: boolean;
      action: 'throttled' | 'removed' | string;
      target: string;
      port?: number;
      rateKbps: number;
      message?: string;
    }>('/api/audit/throttle', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),

  whitelistAuditTarget: (action: 'add' | 'remove', target: string) =>
    request<{ ok: boolean; target: string; whitelist: string[]; message: string }>('/api/audit/whitelist', {
      method: 'POST',
      body: JSON.stringify({ action, target }),
    }),

  closeAuditConnections: (payload: {
    all?: boolean;
    connIds?: string[];
    deviceIp?: string;
    target?: string;
    matchSuffix?: boolean;
    network?: string;
  }) =>
    request<{ ok: boolean; closed: number; all: boolean; message: string }>('/api/audit/close-connections', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),

  setAuditDeviceAccess: (deviceIp: string, allowOverseas: boolean) =>
    request<AuditDeviceAccessResult>('/api/audit/device-access', {
      method: 'POST',
      body: JSON.stringify({ deviceIp, allowOverseas }),
    }),

  upsertAuditRouteRule: (payload: AuditRouteRuleUpsertRequest) =>
    request<AuditRouteRuleResponse>('/api/audit/route-rule', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),

  deleteAuditRouteRule: (payload: AuditRouteRuleDeleteRequest) =>
    request<AuditRouteRuleResponse>('/api/audit/route-rule', {
      method: 'DELETE',
      body: JSON.stringify(payload),
    }),
};

import {
  SourceUpsertInput,
  SubscriptionAccessLogItem,
  SubscriptionPreviewResponse,
  SubscriptionRiskSummary,
  SubscriptionSourceItem,
  SubscriptionsResponse,
} from '../types';
import { MEDIUM_OP_TIMEOUT_MS, request } from './http';

export const subscriptionsApi = {
  getSubscriptions: () => request<SubscriptionsResponse>('/api/server/subscriptions'),

  upsertSubSource: (input: SourceUpsertInput) =>
    request<{ message: string; source: SubscriptionSourceItem }>('/api/server/subscriptions/sources', {
      method: 'POST',
      body: JSON.stringify(input),
      timeoutMs: MEDIUM_OP_TIMEOUT_MS,
    }),

  refreshSubSources: (name?: string) =>
    request<{ message: string; warning?: string; sources: SubscriptionSourceItem[] }>(
      '/api/server/subscriptions/sources/refresh',
      {
        method: 'POST',
        body: JSON.stringify(name ? { name } : {}),
        timeoutMs: MEDIUM_OP_TIMEOUT_MS,
      },
    ),

  deleteSubSource: (name: string) =>
    request<{ message: string }>(`/api/server/subscriptions/sources?name=${encodeURIComponent(name)}`, {
      method: 'DELETE',
      body: JSON.stringify({ name }),
    }),

  rotateSubKey: () =>
    request<{ message: string; substoreKey: string; subscriptionUrl: string }>(
      '/api/server/subscriptions/rotate-key',
      {
        method: 'POST',
        body: JSON.stringify({}),
      },
    ),

  previewSubscription: (target: string) =>
    request<SubscriptionPreviewResponse>(`/api/server/subscriptions/preview?target=${encodeURIComponent(target)}`),

  getSubscriptionAuditLogs: () =>
    request<{ logs: SubscriptionAccessLogItem[]; riskSummary?: SubscriptionRiskSummary; bannedIps?: string[] }>(
      '/api/server/subscriptions/audit',
    ),

  clearSubscriptionAuditLogs: () =>
    request<{ message: string }>('/api/server/subscriptions/audit', {
      method: 'DELETE',
      body: JSON.stringify({}),
    }),
};

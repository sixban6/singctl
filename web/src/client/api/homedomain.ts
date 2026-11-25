import {
  HomeDomainDeviceUpsertPayload,
  HomeDomainOverviewResponse,
  HomeDomainSettingsPayload,
  HomeDomainVerifyReport,
} from '../types';
import { request } from './session';

export const homeDomainApi = {
  getHomeDomain: () =>
    request<HomeDomainOverviewResponse>('/api/home-domain', { timeoutMs: 12000 }),

  saveHomeDomainSettings: (payload: HomeDomainSettingsPayload) =>
    request<HomeDomainOverviewResponse>('/api/home-domain/settings', {
      method: 'PUT',
      body: JSON.stringify(payload),
      timeoutMs: 20000,
    }),

  upsertHomeDomainDevice: (payload: HomeDomainDeviceUpsertPayload) =>
    request<HomeDomainOverviewResponse>('/api/home-domain/devices', {
      method: 'POST',
      body: JSON.stringify(payload),
      timeoutMs: 20000,
    }),

  deleteHomeDomainDevice: (alias: string) =>
    request<HomeDomainOverviewResponse>(
      `/api/home-domain/devices/${encodeURIComponent(alias)}`,
      {
        method: 'DELETE',
        timeoutMs: 20000,
      },
    ),

  verifyHomeDomain: () =>
    request<HomeDomainVerifyReport>('/api/home-domain/verify', {
      method: 'POST',
      body: JSON.stringify({}),
      timeoutMs: 15000,
    }),
};

import {
  VlanApplyResponse,
  VlanOverview,
  VlanPreviewResult,
  VlanSaveSegmentRequest,
  VlanWirelessSecretResponse,
} from '../types';
import { request } from './session';

export const vlanApi = {
  getVlanOverview: () => request<VlanOverview>('/api/vlan/overview', { timeoutMs: 12000 }),

  getVlanWifiSecret: (id: string) =>
    request<VlanWirelessSecretResponse>(`/api/vlan/segment/${encodeURIComponent(id)}/wifi-secret`, {
      timeoutMs: 8000,
    }),

  previewVlanSave: (payload: VlanSaveSegmentRequest) =>
    request<VlanPreviewResult>('/api/vlan/preview', {
      method: 'POST',
      body: JSON.stringify(payload),
      timeoutMs: 12000,
    }),

  applyVlanSave: (payload: VlanSaveSegmentRequest) =>
    request<VlanApplyResponse>('/api/vlan/apply', {
      method: 'POST',
      body: JSON.stringify(payload),
      timeoutMs: 30000,
    }),

  previewVlanDelete: (id: string) =>
    request<VlanPreviewResult>('/api/vlan/delete/preview', {
      method: 'POST',
      body: JSON.stringify({ id }),
      timeoutMs: 12000,
    }),

  deleteVlanSegment: (id: string) =>
    request<VlanApplyResponse>(`/api/vlan/segment/${encodeURIComponent(id)}`, {
      method: 'DELETE',
      timeoutMs: 30000,
    }),
};

import {
  WifiApplyRequest,
  WifiApplyResponse,
  WifiChassisApplyRequest,
  WifiChassisApplyResponse,
  WifiChassisStatus,
  WifiOverview,
  WifiScanResult,
} from '../types';
import { request } from './session';

export const wifiApi = {
  getWifiOverview: (fresh = false) =>
    request<WifiOverview>(fresh ? '/api/wifi/overview?fresh=1' : '/api/wifi/overview', {
      timeoutMs: 12000,
    }),

  scanWifiChannels: () =>
    request<WifiScanResult>('/api/wifi/scan', {
      method: 'POST',
      body: JSON.stringify({}),
      timeoutMs: 20000,
    }),

  retestWifiStats: () =>
    request<WifiOverview>('/api/wifi/retest', {
      method: 'POST',
      body: JSON.stringify({}),
      timeoutMs: 15000,
    }),

  applyWifiOptimize: (payload: WifiApplyRequest) =>
    request<WifiApplyResponse>('/api/wifi/apply', {
      method: 'POST',
      body: JSON.stringify(payload),
      timeoutMs: 45000,
    }),

  getChassis: () =>
    request<WifiChassisStatus>('/api/chassis', {
      timeoutMs: 8000,
    }),

  applyWifiChassis: (payload: WifiChassisApplyRequest) =>
    request<WifiChassisApplyResponse>('/api/chassis', {
      method: 'POST',
      body: JSON.stringify(payload),
      timeoutMs: 15000,
    }),
};

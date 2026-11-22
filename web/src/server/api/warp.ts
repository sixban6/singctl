import {
  WarpConnectionsResponse,
  WarpDaemonStatus,
  WarpDiagnoseResponse,
  WarpQuickSwitchResponse,
  WarpRoutingConfig,
  WarpRoutingStatusResponse,
  WarpRoutingUpdateResponse,
} from '../types';
import { LONG_OP_TIMEOUT_MS, MEDIUM_OP_TIMEOUT_MS, request } from './http';

export const warpApi = {
  getWarpDiagnose: () => request<WarpDiagnoseResponse>('/api/server/warp/diagnose', { timeoutMs: 12000 }),

  getWarpRouting: (refresh = false, node = 'local') =>
    request<WarpRoutingStatusResponse>(
      `/api/server/warp/routing?node=${encodeURIComponent(node)}${refresh ? '&refresh=1' : ''}`,
      { timeoutMs: node === 'local' && !refresh ? undefined : MEDIUM_OP_TIMEOUT_MS },
    ),

  updateWarpRouting: (
    routing: WarpRoutingConfig,
    opts?: { node?: string; viewNode?: string; syncCluster?: boolean },
  ) =>
    request<WarpRoutingUpdateResponse>('/api/server/warp/routing', {
      method: 'PUT',
      body: JSON.stringify({
        ...routing,
        node: opts?.node || 'local',
        viewNode: opts?.viewNode || opts?.node || 'local',
        syncCluster: Boolean(opts?.syncCluster),
      }),
      timeoutMs: MEDIUM_OP_TIMEOUT_MS,
    }),

  quickSwitchWarpTarget: (
    target: string,
    outbound: 'WARP' | 'DC',
    opts?: { node?: string; viewNode?: string; syncCluster?: boolean },
  ) =>
    request<WarpQuickSwitchResponse>('/api/server/warp/quick-switch', {
      method: 'POST',
      body: JSON.stringify({
        target,
        outbound,
        node: opts?.node || 'local',
        viewNode: opts?.viewNode || opts?.node || 'local',
        syncCluster: Boolean(opts?.syncCluster),
      }),
      timeoutMs: MEDIUM_OP_TIMEOUT_MS,
    }),

  getWarpConnections: (query = '', outbound: 'all' | 'DC' | 'WARP' = 'all', node = 'local') =>
    request<WarpConnectionsResponse>(
      `/api/server/warp/connections?node=${encodeURIComponent(node)}&q=${encodeURIComponent(query)}&outbound=${encodeURIComponent(outbound)}`,
    ),

  runWarpAction: (action: 'rekey' | 'ensure' | 'enable_telemetry', node = 'local') =>
    request<{
      message: string;
      warpIp?: string;
      warpLoc?: string;
      daemon: WarpDaemonStatus;
      nodes?: any[];
      results?: any[];
    }>('/api/server/warp/action', {
      method: 'POST',
      body: JSON.stringify({ action, node }),
      timeoutMs: action === 'ensure' || node === 'all' ? LONG_OP_TIMEOUT_MS : MEDIUM_OP_TIMEOUT_MS,
    }),
};

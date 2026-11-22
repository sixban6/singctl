import {
  FleetActionResult,
  FleetBootstrapDefaults,
  FleetBootstrapInput,
  FleetBootstrapPlan,
  FleetListResponse,
  FleetNode,
  FleetUpsertInput,
} from '../types';
import { LONG_OP_TIMEOUT_MS, MEDIUM_OP_TIMEOUT_MS, request } from './http';

export const fleetApi = {
  getFleet: () => request<FleetListResponse>('/api/server/fleet'),

  probeFleet: (ids?: string[]) =>
    request<FleetListResponse & { results: any[] }>('/api/server/fleet/probe', {
      method: 'POST',
      body: JSON.stringify({ ids: ids || [] }),
      timeoutMs: MEDIUM_OP_TIMEOUT_MS,
    }),

  getFleetDefaults: () => request<FleetBootstrapDefaults>('/api/server/fleet/defaults'),

  previewFleetBootstrap: (input: FleetBootstrapInput) =>
    request<FleetBootstrapPlan>('/api/server/fleet/preview-bootstrap', {
      method: 'POST',
      body: JSON.stringify(input),
      timeoutMs: MEDIUM_OP_TIMEOUT_MS,
    }),

  upsertFleetNode: (input: FleetUpsertInput) =>
    request<{ message: string; node: FleetNode; syncResult?: FleetActionResult }>('/api/server/fleet/nodes', {
      method: 'POST',
      body: JSON.stringify(input),
      timeoutMs: LONG_OP_TIMEOUT_MS,
    }),

  deleteFleetNode: (id: string, keepDns = false) =>
    request<{ message: string; dnsDeleted?: boolean }>(
      `/api/server/fleet/nodes?id=${encodeURIComponent(id)}&keepDns=${keepDns ? 'true' : 'false'}`,
      {
        method: 'DELETE',
        body: JSON.stringify({ id, keepDns }),
        timeoutMs: MEDIUM_OP_TIMEOUT_MS,
      },
    ),

  runFleetAction: (action: 'sync' | 'probe' | 'doctor' | 'reset' | 'update', ids?: string[]) =>
    request<{ message: string; results: FleetActionResult[] }>('/api/server/fleet/action', {
      method: 'POST',
      body: JSON.stringify({ action, ids: ids || [] }),
      timeoutMs: LONG_OP_TIMEOUT_MS,
    }),

  bootstrapFleetNode: (input: FleetBootstrapInput) =>
    request<{ message: string; result: FleetActionResult }>('/api/server/fleet/bootstrap', {
      method: 'POST',
      body: JSON.stringify(input),
      timeoutMs: LONG_OP_TIMEOUT_MS,
    }),
};

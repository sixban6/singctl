import {
  ServerStatusResponse,
  SubscriptionsResponse,
  SubscriptionSourceItem,
  SourceUpsertInput,
  SubscriptionPreviewResponse,
  SubscriptionAccessLogItem,
  SubscriptionRiskSummary,
  CertHealthItem,
  BackupExportResponse,
  WarpDiagnoseResponse,
  ReturnSummary,
  BannedIP,
  AuditLogItem,
  DoctorReport,
  MediaUnlockReport,
  CheckUpdateResponse,
  TelemetrySnapshot,
  FleetListResponse,
  FleetUpsertInput,
  FleetBootstrapInput,
  FleetBootstrapDefaults,
  FleetBootstrapPlan,
  FleetNode,
  FleetActionResult,
  HealStatusReport,
  HealRunResponse,
  CamouflageDefaultsResponse,
  CamouflageReport,
  SniffSummary,
  WarpRoutingConfig,
  WarpRoutingStatusResponse,
  WarpRoutingUpdateResponse,
  WarpQuickSwitchResponse,
  WarpConnectionsResponse,
  WarpDaemonStatus,
} from './types';

export const getBasePath = (): string => {
  const p = window.location.pathname.replace(/\/+$/, '');
  return p;
};

let onUnauthorizedCallback: (() => void) | null = null;

export const setOnUnauthorized = (cb: () => void) => {
  onUnauthorizedCallback = cb;
};

export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
  }
}

interface RequestOptions extends RequestInit {
  timeoutMs?: number;
}

const DEFAULT_TIMEOUT_MS = 15000;
const MEDIUM_OP_TIMEOUT_MS = 45000;
const LONG_OP_TIMEOUT_MS = 180000;

async function request<T>(endpoint: string, options: RequestOptions = {}): Promise<T> {
  const { timeoutMs = DEFAULT_TIMEOUT_MS, signal: externalSignal, headers, ...rest } = options;
  const base = getBasePath();
  const url = `${base}${endpoint}`;

  const controller = new AbortController();
  let timedOut = false;
  const timer = setTimeout(() => {
    timedOut = true;
    controller.abort();
  }, timeoutMs);

  const onExternalAbort = () => controller.abort();
  if (externalSignal) {
    if (externalSignal.aborted) {
      clearTimeout(timer);
      throw new ApiError(0, '已取消请求');
    }
    externalSignal.addEventListener('abort', onExternalAbort, { once: true });
  }

  let res: Response;
  try {
    res = await fetch(url, {
      cache: 'no-store',
      credentials: 'same-origin',
      ...rest,
      signal: controller.signal,
      headers: {
        'Content-Type': 'application/json',
        ...(headers || {}),
      },
    });
  } catch {
    if (externalSignal?.aborted) {
      throw new ApiError(0, '已取消请求');
    }
    if (timedOut) {
      throw new ApiError(408, '连接响应超时，请重试');
    }
    throw new ApiError(0, '网络不可达或连接已断开，请重试');
  } finally {
    clearTimeout(timer);
    if (externalSignal) {
      externalSignal.removeEventListener('abort', onExternalAbort);
    }
  }

  if (res.status === 401) {
    if (onUnauthorizedCallback) {
      onUnauthorizedCallback();
    }
    const err = await res.json().catch(() => ({ error: '未授权访问，请先登录' }));
    throw new ApiError(401, err.error || '未授权访问，请先登录');
  }

  const data = await res.json().catch(() => ({}));

  if (!res.ok) {
    throw new ApiError(res.status, data.error || `请求失败 (${res.status})`);
  }

  return data as T;
}

export const api = {
  getStatus: () => request<ServerStatusResponse>('/api/server/status', { timeoutMs: 8000 }),
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
      }
    ),

  deleteSubSource: (name: string) =>
    request<{ message: string }>(`/api/server/subscriptions/sources?name=${encodeURIComponent(name)}`, {
      method: 'DELETE',
      body: JSON.stringify({ name }),
    }),

  rotateSubKey: () =>
    request<{ message: string; substoreKey: string; subscriptionUrl: string }>('/api/server/subscriptions/rotate-key', {
      method: 'POST',
      body: JSON.stringify({}),
    }),

  previewSubscription: (target: string) =>
    request<SubscriptionPreviewResponse>(`/api/server/subscriptions/preview?target=${encodeURIComponent(target)}`),
  getWarpDiagnose: () => request<WarpDiagnoseResponse>('/api/server/warp/diagnose', { timeoutMs: 12000 }),
  getNetReturn: () => request<ReturnSummary>('/api/server/net/return', { timeoutMs: 70000 }),

  serviceAction: (service: string, action: 'start' | 'stop' | 'restart' | 'reload') =>
    request<{ message: string }>('/api/server/service/action', {
      method: 'POST',
      body: JSON.stringify({ service, action }),
      timeoutMs: MEDIUM_OP_TIMEOUT_MS,
    }),

  checkServiceUpdate: (service: string) =>
    request<CheckUpdateResponse>(`/api/server/service/check-update?service=${encodeURIComponent(service)}`, {
      timeoutMs: 25000,
    }),

  upgradeService: (service: string) =>
    request<{ message: string; willRestartUI?: boolean; results?: any[] }>('/api/server/service/upgrade', {
      method: 'POST',
      body: JSON.stringify({ service }),
      timeoutMs: LONG_OP_TIMEOUT_MS,
    }),

  getServiceLogs: (service: string, lines = 100) =>
    request<{ service: string; logs: string }>(`/api/server/service/logs?service=${encodeURIComponent(service)}&lines=${lines}`),

  getServiceConfig: (service: string) =>
    request<{ service: string; path: string; content: string }>(`/api/server/service/config?service=${encodeURIComponent(service)}`),

  updateServiceConfig: (service: string, content: string) =>
    request<{ message: string }>('/api/server/service/config', {
      method: 'PUT',
      body: JSON.stringify({ service, content }),
    }),

  enableBBR: () =>
    request<{ message: string; bbr: boolean }>('/api/server/bbr', {
      method: 'POST',
    }),

  updateSNI: (sni: string) =>
    request<{ message: string; sni: string }>('/api/server/sni', {
      method: 'PUT',
      body: JSON.stringify({ sni }),
      timeoutMs: MEDIUM_OP_TIMEOUT_MS,
    }),

  regeneratePath: () =>
    request<{ message: string; path: string; httpsUrl: string }>('/api/server/path/regenerate', {
      method: 'POST',
      timeoutMs: MEDIUM_OP_TIMEOUT_MS,
    }),

  regenerateMaskSite: () =>
    request<{ message: string; meta: any }>('/api/server/mask-site/regenerate', {
      method: 'POST',
      timeoutMs: MEDIUM_OP_TIMEOUT_MS,
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
        const warmCtrl = new AbortController();
        const warmTimer = setTimeout(() => warmCtrl.abort(), 1500);
        await fetch(`${getBasePath()}/?_ping=${Date.now()}`, {
          method: 'HEAD',
          cache: 'reload',
          credentials: 'same-origin',
          signal: warmCtrl.signal,
        }).catch(() => {});
        clearTimeout(warmTimer);

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

  getBans: () =>
    request<{ bans: BannedIP[]; loginFailCount?: number; manualSniffCount?: number }>('/api/server/bans'),

  getSniffers: (node = 'all', refresh = false) =>
    request<SniffSummary>(
      `/api/server/security/sniffers?node=${encodeURIComponent(node)}${refresh ? '&refresh=1' : ''}`
    ),

  blockSniffer: (target: string, node = 'all', viewNode = 'all') =>
    request<{ message: string; target: string; appliedNodes?: number; summary: SniffSummary }>(
      '/api/server/security/block',
      {
        method: 'POST',
        body: JSON.stringify({ target, node, viewNode }),
        timeoutMs: MEDIUM_OP_TIMEOUT_MS,
      }
    ),

  getAuditLogs: () => request<{ logs: AuditLogItem[] }>('/api/server/audit-logs'),

  unban: (ip: string, node = 'all', viewNode = 'all') =>
    request<{ message: string; unbanned: string; appliedNodes?: number; summary?: SniffSummary }>('/api/server/unban', {
      method: 'POST',
      body: JSON.stringify({ ip, node, viewNode }),
      timeoutMs: MEDIUM_OP_TIMEOUT_MS,
    }),

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

  getDoctorReport: () => request<DoctorReport>('/api/server/doctor', { timeoutMs: MEDIUM_OP_TIMEOUT_MS }),

  getMediaUnlock: () => request<MediaUnlockReport>('/api/server/diagnose/unlock', { timeoutMs: MEDIUM_OP_TIMEOUT_MS }),

  getTelemetrySnapshot: () => request<TelemetrySnapshot>('/api/server/telemetry/snapshot'),

  enableTelemetry: () =>
    request<{ message: string; changed: boolean; snapshot: TelemetrySnapshot }>('/api/server/telemetry/enable', {
      method: 'POST',
      body: JSON.stringify({}),
    }),

  getSubscriptionAuditLogs: () =>
    request<{ logs: SubscriptionAccessLogItem[]; riskSummary?: SubscriptionRiskSummary; bannedIps?: string[] }>(
      '/api/server/subscriptions/audit'
    ),

  clearSubscriptionAuditLogs: () =>
    request<{ message: string }>('/api/server/subscriptions/audit', {
      method: 'DELETE',
      body: JSON.stringify({}),
    }),

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
      }
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

  getHealStatus: (refresh = false) =>
    request<HealStatusReport>(`/api/server/heal/status${refresh ? '?refresh=1' : ''}`, {
      timeoutMs: MEDIUM_OP_TIMEOUT_MS,
    }),

  runHeal: (opts: { scope?: 'local' | 'fleet'; checkOnly?: boolean; allowReboot?: boolean; enableTimers?: boolean; targetIds?: string[] }) =>
    request<HealRunResponse>('/api/server/heal/run', {
      method: 'POST',
      body: JSON.stringify(opts),
      timeoutMs: LONG_OP_TIMEOUT_MS,
    }),

  updateHealPolicy: (opts: { autoHealEnabled: boolean; schedule?: string; autoReboot?: boolean; applyToFleet?: boolean }) =>
    request<{ message: string; status: HealStatusReport }>('/api/server/heal/policy', {
      method: 'PUT',
      body: JSON.stringify(opts),
      timeoutMs: MEDIUM_OP_TIMEOUT_MS,
    }),

  getCamouflageDefaults: () =>
    request<CamouflageDefaultsResponse>('/api/server/camouflage/defaults'),

  runCamouflageProbe: (input: { ip?: string; domain?: string; sni?: string; ports?: string; timeoutSec?: number }) =>
    request<CamouflageReport>('/api/server/camouflage/probe', {
      method: 'POST',
      body: JSON.stringify(input),
      timeoutMs: MEDIUM_OP_TIMEOUT_MS,
    }),

  getWarpRouting: (refresh = false) =>
    request<WarpRoutingStatusResponse>(`/api/server/warp/routing${refresh ? '?refresh=1' : ''}`),

  updateWarpRouting: (routing: WarpRoutingConfig) =>
    request<WarpRoutingUpdateResponse>('/api/server/warp/routing', {
      method: 'PUT',
      body: JSON.stringify(routing),
    }),

  quickSwitchWarpTarget: (target: string, outbound: 'WARP' | 'DC') =>
    request<WarpQuickSwitchResponse>('/api/server/warp/quick-switch', {
      method: 'POST',
      body: JSON.stringify({ target, outbound }),
    }),

  getWarpConnections: (query = '', outbound: 'all' | 'DC' | 'WARP' = 'all') =>
    request<WarpConnectionsResponse>(
      `/api/server/warp/connections?q=${encodeURIComponent(query)}&outbound=${encodeURIComponent(outbound)}`
    ),

  runWarpAction: (action: 'rekey' | 'ensure') =>
    request<{ message: string; warpIp?: string; warpLoc?: string; daemon: WarpDaemonStatus }>('/api/server/warp/action', {
      method: 'POST',
      body: JSON.stringify({ action }),
      timeoutMs: MEDIUM_OP_TIMEOUT_MS,
    }),

  logout: () =>
    request<{ message: string }>('/api/server/logout', {
      method: 'POST',
    }),
};

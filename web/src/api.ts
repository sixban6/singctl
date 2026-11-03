import {
  ServerStatusResponse,
  SubscriptionsResponse,
  WarpDiagnoseResponse,
  ReturnSummary,
  BannedIP,
  AuditLogItem,
  DoctorReport,
  MediaUnlockReport,
  CheckUpdateResponse,
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

async function request<T>(endpoint: string, options: RequestInit = {}): Promise<T> {
  const base = getBasePath();
  const url = `${base}${endpoint}`;

  let res: Response;
  try {
    res = await fetch(url, {
      ...options,
      headers: {
        'Content-Type': 'application/json',
        ...(options.headers || {}),
      },
    });
  } catch {
    throw new ApiError(0, '网络不可达');
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
  getStatus: () => request<ServerStatusResponse>('/api/server/status'),
  getSubscriptions: () => request<SubscriptionsResponse>('/api/server/subscriptions'),
  getWarpDiagnose: () => request<WarpDiagnoseResponse>('/api/server/warp/diagnose'),
  getNetReturn: () => request<ReturnSummary>('/api/server/net/return'),

  serviceAction: (service: string, action: 'start' | 'stop' | 'restart' | 'reload') =>
    request<{ message: string }>('/api/server/service/action', {
      method: 'POST',
      body: JSON.stringify({ service, action }),
    }),

  checkServiceUpdate: (service: string) =>
    request<CheckUpdateResponse>(`/api/server/service/check-update?service=${encodeURIComponent(service)}`),

  upgradeService: (service: string) =>
    request<{ message: string; results?: any[] }>('/api/server/service/upgrade', {
      method: 'POST',
      body: JSON.stringify({ service }),
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
    }),

  regeneratePath: () =>
    request<{ message: string; path: string; httpsUrl: string }>('/api/server/path/regenerate', {
      method: 'POST',
    }),

  regenerateMaskSite: () =>
    request<{ message: string; meta: any }>('/api/server/mask-site/regenerate', {
      method: 'POST',
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

  login: (username: string, password: string) =>
    request<{ message: string; username: string }>('/api/server/login', {
      method: 'POST',
      body: JSON.stringify({ username, password }),
    }),

  getBans: () => request<{ bans: BannedIP[] }>('/api/server/bans'),

  getAuditLogs: () => request<{ logs: AuditLogItem[] }>('/api/server/audit-logs'),

  unban: (ip: string) =>
    request<{ message: string; unbanned: string }>('/api/server/unban', {
      method: 'POST',
      body: JSON.stringify({ ip }),
    }),

  getDoctorReport: () => request<DoctorReport>('/api/server/doctor'),

  getMediaUnlock: () => request<MediaUnlockReport>('/api/server/diagnose/unlock'),

  logout: () =>
    request<{ message: string }>('/api/server/logout', {
      method: 'POST',
    }),
};

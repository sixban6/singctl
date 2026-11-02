import { ServerStatusResponse, SubscriptionsResponse, WarpDiagnoseResponse, ReturnSummary } from './types';

export const getBasePath = (): string => {
  const p = window.location.pathname.replace(/\/+$/, '');
  return p;
};

let onUnauthorizedCallback: (() => void) | null = null;

export const setOnUnauthorized = (cb: () => void) => {
  onUnauthorizedCallback = cb;
};

async function request<T>(endpoint: string, options: RequestInit = {}): Promise<T> {
  const base = getBasePath();
  const url = `${base}${endpoint}`;

  const res = await fetch(url, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...(options.headers || {}),
    },
  });

  if (res.status === 401) {
    if (onUnauthorizedCallback) {
      onUnauthorizedCallback();
    }
    const err = await res.json().catch(() => ({ error: '未授权访问，请先登录' }));
    throw new Error(err.error || '未授权访问，请先登录');
  }

  const data = await res.json().catch(() => ({}));

  if (!res.ok) {
    throw new Error(data.error || `请求失败 (${res.status})`);
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

  getServiceLogs: (service: string, lines = 100) =>
    request<{ service: string; logs: string }>(`/api/server/service/logs?service=${encodeURIComponent(service)}&lines=${lines}`),

  getServiceConfig: (service: string) =>
    request<{ service: string; path: string; content: string }>(`/api/server/service/config?service=${encodeURIComponent(service)}`),

  updateServiceConfig: (service: string, content: string) =>
    request<{ message: string }>('/api/server/service/config', {
      method: 'PUT',
      body: JSON.stringify({ service, content }),
    }),

  regeneratePath: () =>
    request<{ message: string; path: string; httpsUrl: string }>('/api/server/path/regenerate', {
      method: 'POST',
    }),

  updateCredentials: (body: { currentPassword: string; newUsername: string; newPassword: string }) =>
    request<{ message: string; username: string; token: string }>('/api/server/credentials', {
      method: 'PUT',
      body: JSON.stringify(body),
    }),

  login: (username: string, password: string) =>
    request<{ message: string; token: string; username: string }>('/api/server/login', {
      method: 'POST',
      body: JSON.stringify({ username, password }),
    }),

  logout: () =>
    request<{ message: string }>('/api/server/logout', {
      method: 'POST',
    }),
};

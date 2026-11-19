import {
  ActionStreamEvent,
  AdGuardCredentialsResponse,
  AdGuardOverviewSnapshot,
  AdGuardProbeResult,
  AdGuardUpstreamMode,
  AdGuardUpstreamServerInfo,
  AuditAIConfig,
  AuditAIModelsResponse,
  AuditAIReview,
  AuditFlowRecord,
  AuditReport,
  CacheResponse,
  ClientConfigDTO,
  ClientGatewayConfigResponse,
  ClientGroupsGetResponse,
  ClientGroupsPreviewResponse,
  ClientGroupsPutResponse,
  ClientHealthResponse,
  ClientLogsResponse,
  ClientRoutingReport,
  ClientStatusResponse,
  GatewayRoleMode,
  SbConfigResponse,
  SbProxiesSnapshot,
  SbProxyMode,
  SbTrafficSnapshot,
  WatchdogReport,
} from './types';

const CLIENT_TOKEN_KEY = 'sc_token';
export const CLIENT_AUTH_EVENT = 'singctl:unauthorized';

(function initClientSessionAuth() {
  if (typeof window === 'undefined') return;
  try {
    const params = new URLSearchParams(window.location.search);
    const token = params.get('token');
    const pwd = params.get('password');
    const bust = params.get('_t');
    if (token) {
      localStorage.setItem(CLIENT_TOKEN_KEY, token);
      document.cookie = `singctl_session=${token}; path=/; max-age=2592000; SameSite=Lax`;
    }
    // 静默清除地址栏敏感参数与刷新时间戳，防止复制或截图泄漏凭据
    if (token || pwd || bust) {
      params.delete('token');
      params.delete('password');
      params.delete('_t');
      const cleanSearch = params.toString() ? `?${params.toString()}` : '';
      window.history.replaceState(
        {},
        document.title,
        window.location.pathname + cleanSearch + window.location.hash,
      );
    }
  } catch {
    // ignore storage / history errors in restricted contexts
  }
})();

function getSavedClientToken(): string {
  try {
    return localStorage.getItem(CLIENT_TOKEN_KEY) || '';
  } catch {
    return '';
  }
}

export function saveClientToken(token: string) {
  if (!token) return;
  try {
    localStorage.setItem(CLIENT_TOKEN_KEY, token);
  } catch {
    // ignore
  }
}

export function clearSavedClientToken() {
  try {
    localStorage.removeItem(CLIENT_TOKEN_KEY);
  } catch {
    // ignore
  }
}

function notifyUnauthorized() {
  clearSavedClientToken();
  if (typeof window !== 'undefined') {
    window.dispatchEvent(new CustomEvent(CLIENT_AUTH_EVENT));
  }
}

interface ClientRequestInit extends RequestInit {
  timeoutMs?: number;
}

function defaultTimeoutForPath(path: string): number {
  if (
    path.startsWith('/api/health') ||
    path.startsWith('/api/sb/proxies/delay') ||
    path.startsWith('/api/adguard/probe') ||
    path.startsWith('/api/adguard/filters') ||
    path.startsWith('/api/audit/ai-') ||
    path.startsWith('/api/watchdog/patrol')
  ) {
    return 35000;
  }
  return 15000;
}

async function request<T>(path: string, init: ClientRequestInit = {}): Promise<T> {
  const { timeoutMs = defaultTimeoutForPath(path), ...fetchInit } = init;
  const headers = new Headers(fetchInit.headers);
  headers.set('X-Requested-With', 'SingCtlWebUI');
  const savedToken = getSavedClientToken();
  if (savedToken && !headers.has('Authorization')) {
    headers.set('Authorization', `Bearer ${savedToken}`);
  }
  const method = (fetchInit.method || 'GET').toUpperCase();
  if (method !== 'GET' && method !== 'HEAD') {
    // internal/webui guard 强制校验写请求必须为 application/json
    if (!headers.has('Content-Type')) {
      headers.set('Content-Type', 'application/json');
    }
  }
  if (typeof fetchInit.body === 'undefined' && method !== 'GET' && method !== 'HEAD') {
    fetchInit.body = '{}';
  }

  const ctrl = new AbortController();
  const timer = window.setTimeout(() => ctrl.abort(), timeoutMs);
  let resp: Response;
  try {
    resp = await fetch(path, {
      credentials: 'same-origin',
      cache: 'no-store',
      ...fetchInit,
      method,
      headers,
      signal: fetchInit.signal ?? ctrl.signal,
    });
  } catch (err) {
    if ((err as Error)?.name === 'AbortError') {
      throw new Error('请求网关超时，请稍后重试');
    }
    throw err;
  } finally {
    window.clearTimeout(timer);
  }

  if (resp.status === 401) {
    notifyUnauthorized();
    throw new Error('会话已过期或需要输入访问口令');
  }

  const text = await resp.text();
  let json: any = {};
  if (text) {
    try {
      json = JSON.parse(text);
    } catch {
      if (!resp.ok) throw new Error(text || `HTTP ${resp.status}`);
    }
  }
  if (!resp.ok) {
    throw new Error(json?.error || `HTTP ${resp.status}`);
  }
  return json as T;
}

export const clientApi = {
  checkAuth: async (timeoutMs = 2500) => {
    const ctrl = new AbortController();
    const timer = window.setTimeout(() => ctrl.abort(), timeoutMs);
    const headers: Record<string, string> = { 'X-Requested-With': 'SingCtlWebUI' };
    const savedToken = getSavedClientToken();
    if (savedToken) {
      headers['Authorization'] = `Bearer ${savedToken}`;
    }
    try {
      const resp = await fetch('/api/auth/check', {
        method: 'GET',
        credentials: 'same-origin',
        cache: 'no-store',
        headers,
        signal: ctrl.signal,
      });
      if (!resp.ok) {
        throw new Error(`HTTP ${resp.status}`);
      }
      return (await resp.json()) as {
        ok: boolean;
        authRequired: boolean;
        authenticated: boolean;
        version?: string;
      };
    } finally {
      window.clearTimeout(timer);
    }
  },
  login: async (password: string) => {
    const ctrl = new AbortController();
    const timer = window.setTimeout(() => ctrl.abort(), 10000);
    try {
      const resp = await fetch('/api/auth/login', {
        method: 'POST',
        credentials: 'same-origin',
        cache: 'no-store',
        headers: {
          'Content-Type': 'application/json',
          'X-Requested-With': 'SingCtlWebUI',
        },
        body: JSON.stringify({ password }),
        signal: ctrl.signal,
      });
      const data = await resp.json().catch(() => ({}));
      if (!resp.ok) {
        throw new Error(data?.error || `验证失败 (HTTP ${resp.status})`);
      }
      if (data?.token) {
        saveClientToken(data.token);
      }
      return data as { ok: boolean; token: string };
    } catch (err) {
      if ((err as Error)?.name === 'AbortError') {
        throw new Error('登录请求超时，请检查网关连接后重试');
      }
      throw err;
    } finally {
      window.clearTimeout(timer);
    }
  },
  getStatus: async (timeoutMs?: number) => {
    const res = await request<ClientStatusResponse>('/api/status', { timeoutMs });
    if (res?.sessionToken) {
      saveClientToken(res.sessionToken);
    }
    return res;
  },
  getHealth: () => request<ClientHealthResponse>('/api/health'),
  getConfig: () => request<{ path: string; config: ClientConfigDTO }>('/api/config'),
  saveConfig: (config: ClientConfigDTO) =>
    request<{ ok: boolean }>('/api/config', { method: 'PUT', body: JSON.stringify(config) }),
  getConfigRaw: () => request<{ path: string; content: string }>('/api/config/raw'),
  saveConfigRaw: (content: string) =>
    request<{ ok: boolean }>('/api/config/raw', { method: 'PUT', body: JSON.stringify({ content }) }),
  getCache: () => request<CacheResponse>('/api/cache'),
  getLogs: (name: string, tail: number) =>
    request<ClientLogsResponse>(`/api/logs?name=${encodeURIComponent(name)}&tail=${tail}`),
  getIOSUrl: () => request<{ url: string; importUrl?: string }>('/api/gen/ios/url'),
  getSessionUrl: () => request<{ url: string; token: string }>('/api/session/url'),
  logout: async () => {
    const res = await request<{ message: string }>('/api/logout', { method: 'POST', body: '{}' });
    clearSavedClientToken();
    return res;
  },

  getSbConfig: () => request<SbConfigResponse>('/api/sbconfig'),
  saveSbConfig: (content: string) =>
    request<{ ok: boolean; checked: boolean }>('/api/sbconfig', {
      method: 'PUT',
      body: JSON.stringify({ content }),
    }),
  setSbConfigPreserve: (preserve: boolean) =>
    request<{ ok: boolean; preserveManualConfig: boolean }>('/api/sbconfig/preserve', {
      method: 'PUT',
      body: JSON.stringify({ preserve }),
    }),
  restoreSbConfig: (name: string) =>
    request<{ ok: boolean }>('/api/sbconfig/restore', {
      method: 'POST',
      body: JSON.stringify({ name }),
    }),

  getSbProxies: () => request<SbProxiesSnapshot>('/api/sb/proxies'),
  switchSbProxy: (group: string, target: string) =>
    request<{ ok: boolean; group: string; target: string; message: string; snapshot?: SbProxiesSnapshot }>(
      '/api/sb/proxies/switch',
      { method: 'PUT', body: JSON.stringify({ group, target }) },
    ),
  testSbProxyDelay: (payload: { group?: string; node?: string; url?: string; timeoutMs?: number }) =>
    request<{
      ok: boolean;
      url: string;
      delays: Record<string, number>;
      testedCount: number;
      okCount: number;
      snapshot?: SbProxiesSnapshot;
    }>('/api/sb/proxies/delay', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),
  setSbMode: (mode: SbProxyMode) =>
    request<{ ok: boolean; mode: string; message: string; snapshot?: SbProxiesSnapshot }>('/api/sb/mode', {
      method: 'PUT',
      body: JSON.stringify({ mode }),
    }),
  getSbTraffic: () => request<SbTrafficSnapshot>('/api/sb/traffic'),

  getTrafficRouting: () => request<ClientRoutingReport>('/api/traffic-routing'),
  updateTrafficRouting: (payload: {
    reset?: boolean;
    replace?: boolean;
    presets?: Record<string, { enabled?: boolean; outbound?: string }>;
  }) =>
    request<{ ok: boolean; applied: boolean; message: string; report: ClientRoutingReport }>(
      '/api/traffic-routing',
      { method: 'PUT', body: JSON.stringify(payload) },
    ),

  getGroups: () => request<ClientGroupsGetResponse>('/api/groups'),
  previewGroups: (content: string) =>
    request<ClientGroupsPreviewResponse>('/api/groups/preview', {
      method: 'POST',
      body: JSON.stringify({ content }),
    }),
  saveGroups: (payload: { content?: string; reset?: boolean }) =>
    request<ClientGroupsPutResponse>('/api/groups', {
      method: 'PUT',
      body: JSON.stringify(payload),
    }),

  getGateway: () => request<ClientGatewayConfigResponse>('/api/gateway'),
  saveGateway: (payload: { mode: GatewayRoleMode; mainRouterIP?: string; lanIface?: string }) =>
    request<
      ClientGatewayConfigResponse & {
        ok: boolean;
        appliedLive: boolean;
        message: string;
      }
    >('/api/gateway', {
      method: 'PUT',
      body: JSON.stringify(payload),
    }),

  getWatchdog: () => request<WatchdogReport>('/api/watchdog'),
  updateWatchdogConfig: (payload: Record<string, unknown>) =>
    request<WatchdogReport & { ok?: boolean; message?: string; report?: WatchdogReport }>(
      '/api/watchdog/config',
      { method: 'PUT', body: JSON.stringify(payload) },
    ),
  runWatchdogPatrol: () =>
    request<{ message?: string; events?: { summary: string }[]; report?: WatchdogReport }>(
      '/api/watchdog/patrol',
      { method: 'POST', body: '{}' },
    ),

  getAdGuardOverview: () => request<AdGuardOverviewSnapshot>('/api/adguard'),
  getAdGuardCredentials: () => request<AdGuardCredentialsResponse>('/api/adguard/credentials'),
  resetAdGuardCredentials: (username = '') =>
    request<AdGuardCredentialsResponse>('/api/adguard/credentials/reset', {
      method: 'POST',
      body: JSON.stringify({ username }),
    }),
  setAdGuardProtection: (enabled: boolean, durationMinutes = 0) =>
    request<{ ok: boolean }>('/api/adguard/protection', {
      method: 'POST',
      body: JSON.stringify({ enabled, durationMinutes }),
    }),
  clearAdGuardCache: () =>
    request<{ ok: boolean }>('/api/adguard/cache/clear', { method: 'POST', body: '{}' }),
  probeAdGuardUpstream: () =>
    request<AdGuardProbeResult>('/api/adguard/probe', { method: 'POST', body: '{}' }),
  saveAdGuardUpstreams: (payload: {
    upstreams?: string[];
    upstreamMode?: AdGuardUpstreamMode;
    resetDefault?: boolean;
  }) =>
    request<{
      ok: boolean;
      upstreams: AdGuardUpstreamServerInfo[];
      upstreamMode: AdGuardUpstreamMode;
      upstreamModeLabel: string;
      notes?: string[];
    }>('/api/adguard/upstreams', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),
  setAdGuardWhitelist: (action: 'add' | 'remove', domain: string) =>
    request<{ ok: boolean }>('/api/adguard/whitelist', {
      method: 'POST',
      body: JSON.stringify({ action, domain }),
    }),
  manageAdGuardRewrite: (action: 'add' | 'delete', domain: string, answer: string) =>
    request<{ ok: boolean }>('/api/adguard/rewrites', {
      method: 'POST',
      body: JSON.stringify({ action, domain, answer }),
    }),
  manageAdGuardFilter: (payload: {
    action: 'toggle' | 'add' | 'remove' | 'refresh';
    url?: string;
    name?: string;
    enabled?: boolean;
  }) =>
    request<{ ok: boolean }>('/api/adguard/filters', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),

  getAudit: (qs: URLSearchParams, signal?: AbortSignal) =>
    request<AuditReport>(`/api/audit?${qs.toString()}`, signal ? { signal } : {}),
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
  unblockAuditTarget: (target: string, sourceIp: string) =>
    request<{ message?: string }>('/api/audit/unblock', {
      method: 'POST',
      body: JSON.stringify({ target, sourceIp }),
    }),
  whitelistAuditTarget: (action: 'add' | 'remove', target: string) =>
    request<{ ok: boolean; target: string; whitelist: string[]; message: string }>('/api/audit/whitelist', {
      method: 'POST',
      body: JSON.stringify({ action, target }),
    }),

  async downloadAuditCSV(qs: URLSearchParams): Promise<string> {
    const headers: Record<string, string> = { 'X-Requested-With': 'SingCtlWebUI' };
    try {
      const savedToken = localStorage.getItem('sc_token');
      if (savedToken) headers['Authorization'] = 'Bearer ' + savedToken;
    } catch {
      // ignore
    }
    const resp = await fetch(`/api/audit?${qs.toString()}`, {
      credentials: 'same-origin',
      cache: 'no-store',
      headers,
    });
    if (resp.status === 401) {
      notifyUnauthorized();
      throw new Error('会话已过期或需要输入访问口令');
    }
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    return resp.text();
  },

  async runActionStream(
    name: string,
    params: Record<string, unknown>,
    onEvent: (ev: ActionStreamEvent) => void,
  ): Promise<{ code: number; restarting: boolean }> {
    const streamHeaders: Record<string, string> = {
      'Content-Type': 'application/json',
      'X-Requested-With': 'SingCtlWebUI',
    };
    const savedToken = getSavedClientToken();
    if (savedToken) {
      streamHeaders['Authorization'] = `Bearer ${savedToken}`;
    }
    const resp = await fetch('/api/action', {
      method: 'POST',
      credentials: 'same-origin',
      cache: 'no-store',
      headers: streamHeaders,
      body: JSON.stringify({ name, params }),
    });
    if (resp.status === 401) {
      notifyUnauthorized();
      throw new Error('会话已过期或需要输入访问口令');
    }
    if (resp.status === 409) {
      throw new Error('已有任务在执行中，请稍候');
    }
    if (!resp.ok) {
      let msg = `HTTP ${resp.status}`;
      try {
        const j = await resp.json();
        if (j?.error) msg = j.error;
      } catch {
        // ignore
      }
      throw new Error(msg);
    }

    const reader = resp.body?.getReader();
    if (!reader) {
      throw new Error('流式读取不可用');
    }
    const dec = new TextDecoder();
    let buf = '';
    let exitCode = 0;
    let restarting = false;

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      buf += dec.decode(value, { stream: true });
      let idx: number;
      while ((idx = buf.indexOf('\n')) >= 0) {
        const raw = buf.slice(0, idx).trim();
        buf = buf.slice(idx + 1);
        if (!raw) continue;
        try {
          const ev = JSON.parse(raw) as ActionStreamEvent;
          onEvent(ev);
          if (ev.t === 'exit') {
            exitCode = ev.code ?? 0;
            restarting = Boolean(ev.restarting);
          }
        } catch {
          // ignore malformed chunk
        }
      }
    }
    return { code: exitCode, restarting };
  },
};

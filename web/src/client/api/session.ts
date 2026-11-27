import { createHttpClient, HttpRequestOptions } from '../../lib/http';

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

export function getSavedClientToken(): string {
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
    sessionStorage.removeItem('sc_client_status_snap_v1');
  } catch {
    // ignore
  }
}

export function notifyUnauthorized() {
  clearSavedClientToken();
  if (typeof window !== 'undefined') {
    window.dispatchEvent(new CustomEvent(CLIENT_AUTH_EVENT));
  }
}

function defaultTimeoutForPath(path: string): number {
  if (path.startsWith('/api/dns/engine')) {
    return 45000;
  }
  if (
    path.startsWith('/api/health') ||
    path.startsWith('/api/sb/proxies/delay') ||
    path.startsWith('/api/dns/probe') ||
    path.startsWith('/api/dns/filters') ||
    path.startsWith('/api/dns/upstreams') ||
    path.startsWith('/api/adguard/probe') ||
    path.startsWith('/api/adguard/filters') ||
    path.startsWith('/api/audit/ai-') ||
    path.startsWith('/api/watchdog/patrol') ||
    path.startsWith('/api/dns/leak-test') ||
    path.startsWith('/api/tailscale/p2p/poke') ||
    path.startsWith('/api/tailscale/upgrade/preflight')
  ) {
    return 25000;
  }
  return 15000;
}

export const clientHttp = createHttpClient({
  getDefaultTimeoutMs: (path) => defaultTimeoutForPath(path),
  prepareHeaders: (headers, method) => {
    headers.set('X-Requested-With', 'SingCtlWebUI');
    const savedToken = getSavedClientToken();
    if (savedToken && !headers.has('Authorization')) {
      headers.set('Authorization', `Bearer ${savedToken}`);
    }
    if (method !== 'GET' && method !== 'HEAD' && !headers.has('Content-Type')) {
      // internal/webui guard 强制校验写请求必须为 application/json
      headers.set('Content-Type', 'application/json');
    }
  },
  ensureDefaultWriteBody: true,
  onUnauthorized: notifyUnauthorized,
  unauthorizedMessage: '会话已过期或需要输入访问口令',
  timeoutMessage: '请求网关超时，请稍后重试',
  abortedMessage: '已取消请求',
  formatHttpError: (status, jsonError, rawText) => jsonError || rawText || `HTTP ${status}`,
});

export function request<T>(path: string, init: HttpRequestOptions = {}): Promise<T> {
  return clientHttp.requestJSON<T>(path, init);
}

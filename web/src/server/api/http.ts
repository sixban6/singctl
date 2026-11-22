import { ApiError, createHttpClient, HttpRequestOptions } from '../../lib/http';

export { ApiError };

export const DEFAULT_TIMEOUT_MS = 15000;
export const MEDIUM_OP_TIMEOUT_MS = 45000;
export const LONG_OP_TIMEOUT_MS = 180000;

export const getBasePath = (): string => {
  return window.location.pathname.replace(/\/+$/, '');
};

let onUnauthorizedCallback: (() => void) | null = null;

export const setOnUnauthorized = (cb: () => void) => {
  onUnauthorizedCallback = cb;
};

export const serverHttp = createHttpClient({
  resolveUrl: (endpoint) => `${getBasePath()}${endpoint}`,
  defaultTimeoutMs: DEFAULT_TIMEOUT_MS,
  prepareHeaders: (headers) => {
    if (!headers.has('Content-Type')) {
      headers.set('Content-Type', 'application/json');
    }
  },
  onUnauthorized: () => {
    onUnauthorizedCallback?.();
  },
  unauthorizedMessage: '未授权访问，请先登录',
  readUnauthorizedBodyMessage: true,
  timeoutMessage: '连接响应超时，请重试',
  abortedMessage: '已取消请求',
  networkErrorMessage: '网络不可达或连接已断开，请重试',
  formatHttpError: (status, jsonError) => jsonError || `请求失败 (${status})`,
});

export function request<T>(endpoint: string, options: HttpRequestOptions = {}): Promise<T> {
  return serverHttp.requestJSON<T>(endpoint, options);
}

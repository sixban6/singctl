export type ApiErrorKind = 'http' | 'timeout' | 'aborted' | 'network' | 'unauthorized';

export class ApiError extends Error {
  status: number;
  kind: ApiErrorKind;

  constructor(
    status: number,
    message: string,
    kind: ApiErrorKind = status === 401 ? 'unauthorized' : 'http',
  ) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.kind = kind;
  }
}

export interface ComposedAbortSignal {
  signal: AbortSignal;
  isTimedOut: () => boolean;
  isExternallyAborted: () => boolean;
  cleanup: () => void;
}

/**
 * 组合外部 AbortSignal 与内部超时定时器：
 * 修复传入外部 signal 时覆盖内部超时控制器的缺陷，并在请求结束时无泄漏清理监听器与定时器。
 */
export function composeAbortSignals(
  externalSignal?: AbortSignal | null,
  timeoutMs?: number,
): ComposedAbortSignal {
  const controller = new AbortController();
  let timedOut = false;
  let timer: ReturnType<typeof setTimeout> | undefined;

  const onExternalAbort = () => {
    controller.abort(externalSignal?.reason);
  };

  if (externalSignal?.aborted) {
    controller.abort(externalSignal.reason);
  } else {
    if (typeof timeoutMs === 'number' && timeoutMs > 0) {
      timer = setTimeout(() => {
        timedOut = true;
        controller.abort();
      }, timeoutMs);
    }
    if (externalSignal) {
      externalSignal.addEventListener('abort', onExternalAbort, { once: true });
    }
  }

  return {
    signal: controller.signal,
    isTimedOut: () => timedOut,
    isExternallyAborted: () => Boolean(externalSignal?.aborted),
    cleanup: () => {
      if (timer !== undefined) {
        clearTimeout(timer);
        timer = undefined;
      }
      if (externalSignal) {
        externalSignal.removeEventListener('abort', onExternalAbort);
      }
    },
  };
}

export interface HttpRequestOptions extends RequestInit {
  timeoutMs?: number;
  skipUnauthorizedHook?: boolean;
  timeoutMessage?: string;
  statusErrorMessages?: Record<number, string>;
  formatHttpError?: (status: number, jsonError?: string, rawText?: string) => string;
}

export interface HttpClientConfig {
  resolveUrl?: (path: string) => string;
  defaultTimeoutMs?: number;
  getDefaultTimeoutMs?: (path: string, method: string) => number;
  prepareHeaders?: (headers: Headers, method: string, path: string) => void;
  ensureDefaultWriteBody?: boolean;
  onUnauthorized?: () => void;
  unauthorizedMessage?: string;
  readUnauthorizedBodyMessage?: boolean;
  timeoutMessage?: string;
  abortedMessage?: string;
  networkErrorMessage?: string;
  statusErrorMessages?: Record<number, string>;
  formatHttpError?: (status: number, jsonError?: string, rawText?: string) => string;
}

export interface HttpClient {
  requestJSON: <T>(path: string, options?: HttpRequestOptions) => Promise<T>;
  requestText: (path: string, options?: HttpRequestOptions) => Promise<string>;
  requestNDJSON: <TEvent>(
    path: string,
    options: HttpRequestOptions,
    onEvent: (event: TEvent) => void,
  ) => Promise<void>;
}

function extractErrorFromText(
  status: number,
  text: string,
  options: HttpRequestOptions,
  config: HttpClientConfig,
): string {
  const mapped = options.statusErrorMessages?.[status] ?? config.statusErrorMessages?.[status];
  if (mapped) return mapped;

  let jsonError: string | undefined;
  if (text) {
    try {
      const parsed = JSON.parse(text);
      if (typeof parsed?.error === 'string' && parsed.error) {
        jsonError = parsed.error;
      }
    } catch {
      // non-JSON response body
    }
  }

  const formatter = options.formatHttpError ?? config.formatHttpError;
  if (formatter) {
    return formatter(status, jsonError, text);
  }
  return jsonError || text || `HTTP ${status}`;
}

export function createHttpClient(config: HttpClientConfig = {}): HttpClient {
  const executeFetch = async (
    path: string,
    options: HttpRequestOptions,
    composed: ComposedAbortSignal,
  ): Promise<Response> => {
    const {
      timeoutMs: _timeoutMs,
      skipUnauthorizedHook,
      timeoutMessage,
      statusErrorMessages: _statusErrorMessages,
      formatHttpError: _formatHttpError,
      signal: _externalSignal,
      headers: rawHeaders,
      ...fetchInit
    } = options;

    if (composed.isExternallyAborted()) {
      throw new ApiError(0, config.abortedMessage || '已取消请求', 'aborted');
    }

    const method = (fetchInit.method || 'GET').toUpperCase();
    const headers = new Headers(rawHeaders);
    config.prepareHeaders?.(headers, method, path);

    if (
      config.ensureDefaultWriteBody &&
      typeof fetchInit.body === 'undefined' &&
      method !== 'GET' &&
      method !== 'HEAD'
    ) {
      fetchInit.body = '{}';
    }

    const url = config.resolveUrl ? config.resolveUrl(path) : path;
    let resp: Response;
    try {
      resp = await fetch(url, {
        credentials: 'same-origin',
        cache: 'no-store',
        ...fetchInit,
        method,
        headers,
        signal: composed.signal,
      });
    } catch (err) {
      if (composed.isExternallyAborted()) {
        throw new ApiError(0, config.abortedMessage || '已取消请求', 'aborted');
      }
      if (composed.isTimedOut() || (err as Error)?.name === 'AbortError') {
        throw new ApiError(
          408,
          timeoutMessage || config.timeoutMessage || '请求超时，请稍后重试',
          'timeout',
        );
      }
      if (config.networkErrorMessage) {
        throw new ApiError(0, config.networkErrorMessage, 'network');
      }
      throw err;
    }

    if (resp.status === 401 && !skipUnauthorizedHook) {
      config.onUnauthorized?.();
      let msg = config.unauthorizedMessage || '未授权访问';
      if (config.readUnauthorizedBodyMessage) {
        const errText = await resp.text().catch(() => '');
        if (errText) {
          try {
            const parsed = JSON.parse(errText);
            if (typeof parsed?.error === 'string' && parsed.error) {
              msg = parsed.error;
            }
          } catch {
            // ignore non-JSON 401 body
          }
        }
      }
      throw new ApiError(401, msg, 'unauthorized');
    }

    return resp;
  };

  const resolveTimeout = (path: string, options: HttpRequestOptions): number => {
    if (typeof options.timeoutMs === 'number') {
      return options.timeoutMs;
    }
    const method = (options.method || 'GET').toUpperCase();
    if (config.getDefaultTimeoutMs) {
      return config.getDefaultTimeoutMs(path, method);
    }
    return config.defaultTimeoutMs ?? 15000;
  };

  return {
    async requestJSON<T>(path: string, options: HttpRequestOptions = {}): Promise<T> {
      const composed = composeAbortSignals(options.signal, resolveTimeout(path, options));
      try {
        const resp = await executeFetch(path, options, composed);
        const text = await resp.text();
        if (!resp.ok) {
          throw new ApiError(resp.status, extractErrorFromText(resp.status, text, options, config));
        }
        if (!text) {
          return {} as T;
        }
        try {
          return JSON.parse(text) as T;
        } catch {
          return {} as T;
        }
      } finally {
        composed.cleanup();
      }
    },

    async requestText(path: string, options: HttpRequestOptions = {}): Promise<string> {
      const composed = composeAbortSignals(options.signal, resolveTimeout(path, options));
      try {
        const resp = await executeFetch(path, options, composed);
        const text = await resp.text();
        if (!resp.ok) {
          throw new ApiError(resp.status, extractErrorFromText(resp.status, text, options, config));
        }
        return text;
      } finally {
        composed.cleanup();
      }
    },

    async requestNDJSON<TEvent>(
      path: string,
      options: HttpRequestOptions,
      onEvent: (event: TEvent) => void,
    ): Promise<void> {
      const composed = composeAbortSignals(options.signal, options.timeoutMs);
      try {
        const resp = await executeFetch(path, options, composed);
        if (!resp.ok) {
          const text = await resp.text().catch(() => '');
          throw new ApiError(resp.status, extractErrorFromText(resp.status, text, options, config));
        }

        const reader = resp.body?.getReader();
        if (!reader) {
          throw new ApiError(500, '流式读取不可用');
        }

        const decoder = new TextDecoder();
        let buf = '';
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          buf += decoder.decode(value, { stream: true });
          let idx: number;
          while ((idx = buf.indexOf('\n')) >= 0) {
            const raw = buf.slice(0, idx).trim();
            buf = buf.slice(idx + 1);
            if (!raw) continue;
            try {
              onEvent(JSON.parse(raw) as TEvent);
            } catch {
              // ignore malformed NDJSON chunk
            }
          }
        }
        buf += decoder.decode();
        const trailing = buf.trim();
        if (trailing) {
          try {
            onEvent(JSON.parse(trailing) as TEvent);
          } catch {
            // ignore malformed trailing chunk
          }
        }
      } finally {
        composed.cleanup();
      }
    },
  };
}

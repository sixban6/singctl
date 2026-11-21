import { useEffect, useRef } from 'react';

export interface UseVisibilityIntervalOptions {
  /** 浏览器标签页从隐藏切回前台时是否立即触发一次刷新（默认 true） */
  refreshOnVisible?: boolean;
}

/**
 * 仅在浏览器标签页处于前台可见状态时运行周期轮询：
 * 标签页切入后台后彻底销毁定时器，实现零后台唤醒功耗；切回前台时按需立刻无感补刷并恢复周期调度。
 */
export function useVisibilityInterval(
  callback: () => void,
  delayMs: number | null,
  options?: UseVisibilityIntervalOptions,
): void {
  const callbackRef = useRef(callback);
  callbackRef.current = callback;
  const refreshOnVisible = options?.refreshOnVisible ?? true;

  useEffect(() => {
    if (delayMs === null || delayMs <= 0) {
      return;
    }

    let timer: ReturnType<typeof setInterval> | null = null;

    const stop = () => {
      if (timer !== null) {
        clearInterval(timer);
        timer = null;
      }
    };

    const start = () => {
      stop();
      if (typeof document !== 'undefined' && document.visibilityState !== 'visible') {
        return;
      }
      timer = setInterval(() => {
        if (typeof document === 'undefined' || document.visibilityState === 'visible') {
          callbackRef.current();
        }
      }, delayMs);
    };

    const onVisibilityChange = () => {
      if (document.visibilityState === 'visible') {
        if (refreshOnVisible) {
          callbackRef.current();
        }
        start();
      } else {
        stop();
      }
    };

    start();
    document.addEventListener('visibilitychange', onVisibilityChange);
    return () => {
      stop();
      document.removeEventListener('visibilitychange', onVisibilityChange);
    };
  }, [delayMs, refreshOnVisible]);
}

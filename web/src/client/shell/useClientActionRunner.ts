import { useCallback, useRef, useState } from 'react';
import { emitClientInvalidate } from '../../hooks';
import { useToast } from '../../ui';
import { clientApi } from '../api';
import { ClientStatusResponse } from '../types';
import { TsSwapBannerState } from './clientNavConfig';

export interface ConfirmState {
  name: string;
  params: Record<string, unknown>;
  message: string;
}

export function useClientActionRunner(refreshStatus: (silent?: boolean) => Promise<ClientStatusResponse | null>) {
  const { success, error, warn, toast } = useToast();

  const [busy, setBusy] = useState(false);
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [consoleTitle, setConsoleTitle] = useState('');
  const [consoleCmd, setConsoleCmd] = useState('');
  const [consoleLines, setConsoleLines] = useState<string[]>([]);
  const [confirmState, setConfirmState] = useState<ConfirmState | null>(null);
  const [restartingBanner, setRestartingBanner] = useState(false);
  const [restartTimedOut, setRestartTimedOut] = useState(false);
  const [tsSwapBanner, setTsSwapBanner] = useState<TsSwapBannerState | null>(null);
  const tsSwapPollSeqRef = useRef(0);

  const reloadWithCacheBust = useCallback(() => {
    const sep = window.location.pathname.includes('?') ? '&' : '?';
    window.location.replace(
      `${window.location.pathname}${sep}_t=${Date.now()}${window.location.hash || ''}`,
    );
  }, []);

  const pollTailscaleUpgrade = useCallback(
    async (withInitialWait: boolean) => {
      const seq = ++tsSwapPollSeqRef.current;
      setTsSwapBanner({
        active: true,
        phase: 'swapping',
        message: '正在后台原子切换 Tailscale（健康门禁与自动回滚保护中，如通过 Tailscale 访问将短暂重连）…',
        timedOut: false,
      });

      if (withInitialWait) {
        await new Promise((r) => window.setTimeout(r, 2000));
      }

      const deadline = Date.now() + 50000;
      while (Date.now() < deadline) {
        if (tsSwapPollSeqRef.current !== seq) return;
        try {
          const resp = await clientApi.getTailscaleUpgradeStatus(3000);
          if (tsSwapPollSeqRef.current !== seq) return;
          const st = resp?.state;
          if (st?.phase === 'swapping' || st?.phase === 'verifying') {
            setTsSwapBanner({
              active: true,
              phase: st.phase,
              message:
                st.message ||
                (st.phase === 'verifying'
                  ? '新版已启动，正在等待健康门禁与隧道恢复…'
                  : '正在停止旧版并原子替换二进制文件…'),
              timedOut: false,
            });
          } else if (st?.phase === 'succeeded') {
            setTsSwapBanner(null);
            const summary = st.message || `Tailscale 已零失联升级至 ${st.toVersion || '最新版本'}`;
            const logLines = st.logTail
              ? st.logTail.split('\n').filter((l) => l.trim().length > 0)
              : [];
            setConsoleLines((prev) => [...prev, `[SUCCESS] ${summary}`, ...logLines].slice(-800));
            success(summary);
            await refreshStatus(true);
            emitClientInvalidate('all');
            window.dispatchEvent(new CustomEvent('singctl:ts-upgrade-done', { detail: st }));
            return;
          } else if (st?.phase === 'rolled_back' || st?.phase === 'failed') {
            setTsSwapBanner(null);
            const summary =
              st.message || st.error || 'Tailscale 新版验证失败并已执行自动回滚';
            const logLines = st.logTail
              ? st.logTail.split('\n').filter((l) => l.trim().length > 0)
              : [];
            const levelTag = st.phase === 'rolled_back' ? '[WARN]' : '[ERROR]';
            setConsoleLines((prev) =>
              [
                ...prev,
                `${levelTag} ${summary}${st.error ? ` (${st.error})` : ''}`,
                ...logLines,
              ].slice(-800),
            );
            if (st.phase === 'rolled_back') {
              warn(summary, 7000);
            } else {
              error(summary, 7000);
            }
            await refreshStatus(true);
            emitClientInvalidate('all');
            window.dispatchEvent(new CustomEvent('singctl:ts-upgrade-done', { detail: st }));
            return;
          }
        } catch {
          // 隧道重连期间短暂网络错误属于预期，继续静默重试
        }
        await new Promise((r) => window.setTimeout(r, 1500));
      }

      if (tsSwapPollSeqRef.current !== seq) return;
      setTsSwapBanner({
        active: true,
        phase: 'timeout',
        message: '后台切换轮询等待超时，若网络已恢复可点击右侧重新检测升级结果。',
        timedOut: true,
      });
    },
    [refreshStatus, success, warn, error],
  );

  const executeAction = useCallback(
    async (name: string, params: Record<string, unknown> = {}) => {
      if (busy || tsSwapBanner?.active) {
        toast('已有任务在执行中，请稍候', 'info');
        return;
      }
      setBusy(true);
      setDrawerOpen(true);
      setConsoleTitle(`执行 ${name}`);
      setConsoleCmd('');
      setConsoleLines([]);

      try {
        const res = await clientApi.runActionStream(name, params, (ev) => {
          if (ev.t === 'start') {
            if (ev.title) setConsoleTitle(ev.title);
            if (ev.cmd) setConsoleCmd(ev.cmd);
          } else if (ev.t === 'out' && typeof ev.line === 'string') {
            setConsoleLines((prev) => {
              const next = [...prev, ev.line as string];
              return next.length > 800 ? next.slice(next.length - 800) : next;
            });
          } else if (ev.t === 'exit') {
            setConsoleLines((prev) => [
              ...prev,
              ev.code === 0 ? '[SUCCESS] 执行完成 (exit 0)' : `[ERROR] 执行失败 (exit ${ev.code})`,
            ]);
          }
        });

        if (res.tailscaleSwapping) {
          void pollTailscaleUpgrade(true);
          return;
        }

        if (res.restarting) {
          setRestartingBanner(true);
          setRestartTimedOut(false);
          toast('程序已自更新，正在重启 Web 控制台并等待恢复…', 'info');
          void (async () => {
            // 等待 1.8s 让旧进程完成延时关闭与端口释放
            await new Promise((r) => window.setTimeout(r, 1800));
            const deadline = Date.now() + 25000;
            while (Date.now() < deadline) {
              try {
                const probe = await clientApi.checkAuth(2500);
                if (probe?.ok) {
                  reloadWithCacheBust();
                  return;
                }
              } catch {
                // 新版进程仍在启动中
              }
              await new Promise((r) => window.setTimeout(r, 1000));
            }
            setRestartTimedOut(true);
          })();
          return;
        }

        if (res.code === 0) {
          success('操作执行成功');
        } else {
          error(`操作退出异常 (code ${res.code})`);
        }
        await refreshStatus(true);
        emitClientInvalidate('all');
      } catch (e) {
        const msg = (e as Error).message || '执行失败';
        setConsoleLines((prev) => [...prev, `[ERROR] ${msg}`]);
        error(msg);
      } finally {
        setBusy(false);
      }
    },
    [busy, tsSwapBanner?.active, pollTailscaleUpgrade, refreshStatus, reloadWithCacheBust, success, error, toast],
  );

  const requestAction = useCallback(
    (name: string, params: Record<string, unknown> = {}, confirmMsg?: string) => {
      if (confirmMsg) {
        setConfirmState({ name, params, message: confirmMsg });
        return;
      }
      void executeAction(name, params);
    },
    [executeAction],
  );

  const handleCopyConsole = useCallback(async () => {
    try {
      await navigator.clipboard.writeText(consoleLines.join('\n'));
      success('终端日志已复制到剪贴板');
    } catch {
      error('复制失败');
    }
  }, [consoleLines, success, error]);

  return {
    busy,
    drawerOpen,
    setDrawerOpen,
    consoleTitle,
    consoleCmd,
    consoleLines,
    setConsoleLines,
    confirmState,
    setConfirmState,
    restartingBanner,
    restartTimedOut,
    tsSwapBanner,
    setTsSwapBanner,
    pollTailscaleUpgrade,
    executeAction,
    requestAction,
    handleCopyConsole,
    reloadWithCacheBust,
  };
}

import React, { useEffect, useState, useCallback, useRef } from 'react';
import { ServerStatusResponse } from './types';
import { ApiError, api, setOnUnauthorized } from './api';
import { clearCachedQuery, useHashRoute } from '../hooks';
import { ToastProvider, CardSkeleton, lazyWithReload, useToast } from '../ui';
import { Header } from './components/Header';
import { Navigation, SERVER_TAB_KEYS, TabKey } from './components/Navigation';
import { OverviewTab } from './components/OverviewTab';
import { LoginModal } from './components/LoginModal';
import {
  prefetchFleetTab,
  prefetchSecurityTab,
  prefetchSubscriptionsTab,
  prefetchWarpTab,
} from './prefetch';
import { Activity, RefreshCw, WifiOff } from 'lucide-react';

const ServicesTab = lazyWithReload(
  () => import('./components/ServicesTab').then((m) => ({ default: m.ServicesTab })),
  'server-services',
);
const SubscriptionsTab = lazyWithReload(
  () => import('./components/SubscriptionsTab').then((m) => ({ default: m.SubscriptionsTab })),
  'server-subscriptions',
);
const FleetTab = lazyWithReload(
  () => import('./components/FleetTab').then((m) => ({ default: m.FleetTab })),
  'server-fleet',
);
const LogsTab = lazyWithReload(
  () => import('./components/LogsTab').then((m) => ({ default: m.LogsTab })),
  'server-logs',
);
const DiagnosticsTab = lazyWithReload(
  () => import('./components/DiagnosticsTab').then((m) => ({ default: m.DiagnosticsTab })),
  'server-diagnostics',
);
const SecurityTab = lazyWithReload(
  () => import('./components/SecurityTab').then((m) => ({ default: m.SecurityTab })),
  'server-security',
);
const CamouflageTab = lazyWithReload(
  () => import('./components/CamouflageTab').then((m) => ({ default: m.CamouflageTab })),
  'server-camouflage',
);
const WarpTab = lazyWithReload(
  () => import('./components/WarpTab').then((m) => ({ default: m.WarpTab })),
  'server-warp',
);

// OCP 声明式保活与预热注册表：扩展新 Tab 时仅需在此注册 prefetch，无需修改外层调度逻辑
const KEEP_ALIVE_PREFETCHERS: Partial<Record<TabKey, () => void>> = {
  warp: prefetchWarpTab,
  subscriptions: prefetchSubscriptionsTab,
  fleet: prefetchFleetTab,
  security: prefetchSecurityTab,
};

const HOVER_CHUNK_WARMERS: Partial<Record<TabKey, () => void>> = {
  services: () => { void import('./components/ServicesTab'); },
  logs: () => { void import('./components/LogsTab'); },
  diagnostics: () => { void import('./components/DiagnosticsTab'); },
  camouflage: () => { void import('./components/CamouflageTab'); },
};

const DashboardContent: React.FC = () => {
  const { error, success } = useToast();
  const { tab: currentTab, navigate } = useHashRoute<TabKey>(SERVER_TAB_KEYS, 'overview');
  const setCurrentTab = useCallback((next: TabKey) => navigate(next), [navigate]);
  const [visitedTabs, setVisitedTabs] = useState<Set<TabKey>>(() => new Set([currentTab]));
  const [status, setStatus] = useState<ServerStatusResponse | null>(null);
  const [isCheckingAuth, setIsCheckingAuth] = useState(true);
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const isAuthenticatedRef = useRef(false);
  const [initNetError, setInitNetError] = useState<string | null>(null);
  const [logService, setLogService] = useState('singbox');
  const [linkDown, setLinkDown] = useState(false);
  const [lastOk, setLastOk] = useState<Date | null>(null);
  const [ackingPassword, setAckingPassword] = useState(false);

  const fetchStatus = useCallback(async (silent = false) => {
    if (!silent && !isAuthenticatedRef.current) setIsCheckingAuth(true);
    try {
      const data = await api.getStatus();
      setStatus(data);
      isAuthenticatedRef.current = true;
      setIsAuthenticated(true);
      setInitNetError(null);
      setLinkDown(false);
      setLastOk(new Date());
    } catch (err: unknown) {
      const unauthorized = err instanceof ApiError && err.status === 401;
      if (unauthorized) {
        isAuthenticatedRef.current = false;
        setIsAuthenticated(false);
        setInitNetError(null);
        setLinkDown(false);
      } else if (!isAuthenticatedRef.current) {
        // 仅 401 才弹出登录框；网络超时 / 502 / 504 等错误进入自动重连等待页，防止误踢回登录态
        const msg = err instanceof Error && err.message ? err.message : '管理通道连接超时';
        setInitNetError(msg);
      } else {
        setLinkDown(true);
      }
    } finally {
      setIsCheckingAuth(false);
    }
  }, []);

  useEffect(() => {
    setVisitedTabs((prev) => {
      if (prev.has(currentTab)) return prev;
      const next = new Set(prev);
      next.add(currentTab);
      return next;
    });
  }, [currentTab]);

  const handleHoverTab = useCallback((tab: TabKey) => {
    KEEP_ALIVE_PREFETCHERS[tab]?.();
    HOVER_CHUNK_WARMERS[tab]?.();
  }, []);

  useEffect(() => {
    setOnUnauthorized(() => {
      clearCachedQuery('server:');
      isAuthenticatedRef.current = false;
      setIsAuthenticated(false);
      setInitNetError(null);
      setIsCheckingAuth(false);
    });
    void fetchStatus();
  }, [fetchStatus]);

  // 首屏认证与总览就绪 600ms 后，按注册表静默预热重度 Tab 缓存，实现首次点击 0ms 瞬开
  useEffect(() => {
    if (!isAuthenticated || !status) return;
    const timer = window.setTimeout(() => {
      (Object.entries(KEEP_ALIVE_PREFETCHERS) as [TabKey, () => void][]).forEach(([key, prefetch]) => {
        if (key !== currentTab) prefetch();
      });
    }, 600);
    return () => window.clearTimeout(timer);
  }, [isAuthenticated, status, currentTab]);

  // Initial network timeout auto-retry every 4 seconds
  useEffect(() => {
    if (isAuthenticated || initNetError === null || isCheckingAuth) return;
    const timer = setTimeout(() => {
      void fetchStatus(true);
    }, 4000);
    return () => clearTimeout(timer);
  }, [isAuthenticated, initNetError, isCheckingAuth, fetchStatus]);

  // Periodic polling every 12 seconds only when authenticated
  useEffect(() => {
    if (!isAuthenticated) return;
    const timer = setInterval(() => {
      void fetchStatus(true);
    }, 12000);
    return () => clearInterval(timer);
  }, [isAuthenticated, fetchStatus]);

  const handleLogout = async () => {
    try {
      await api.logout();
      clearCachedQuery('server:');
      setVisitedTabs(new Set([currentTab]));
      success('已安全退出');
      setStatus(null);
      isAuthenticatedRef.current = false;
      setIsAuthenticated(false);
      setInitNetError(null);
      setLinkDown(false);
    } catch (err: any) {
      error(err.message || '登出失败');
    }
  };

  const handleAckPassword = async () => {
    setAckingPassword(true);
    try {
      await api.ackInitialPassword();
      success('已确认保存，面板不再显示密码');
      await fetchStatus(true);
    } catch (err: unknown) {
      error(err instanceof Error ? err.message : '确认失败');
    } finally {
      setAckingPassword(false);
    }
  };

  const copyPassword = async (password: string) => {
    try {
      await navigator.clipboard.writeText(password);
      success('密码已复制');
    } catch {
      error('复制失败，请手动选择密码');
    }
  };

  const handleOpenLogsForService = (service: string) => {
    setLogService(service);
    setCurrentTab('logs');
  };

  // 1. Initial Auth Checking Screen (Sleek dark minimal loading)
  if (isCheckingAuth) {
    return (
      <div className="min-h-dvh flex flex-col items-center justify-center px-page-safe bg-[#080d1a] text-slate-400 select-none">
        <div className="w-12 h-12 rounded-2xl bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center text-emerald-400 mb-4 animate-pulse glow-green">
          <Activity className="w-6 h-6" />
        </div>
        <div className="flex items-center gap-2 text-xs font-mono">
          <span className="w-2 h-2 rounded-full bg-emerald-400 animate-ping"></span>
          <span>正在安全验证管理会话...</span>
        </div>
      </div>
    );
  }

  // 2. Network / Gateway Timeout on initial load (avoid false login prompt)
  if (!isAuthenticated && initNetError !== null) {
    return (
      <div className="min-h-dvh flex items-center justify-center px-page-safe bg-[#080d1a] text-slate-200">
        <div className="w-full max-w-md p-6 rounded-2xl border border-amber-500/30 bg-slate-900/90 space-y-4 text-center shadow-2xl">
          <div className="w-12 h-12 mx-auto rounded-2xl bg-amber-500/10 border border-amber-500/25 flex items-center justify-center text-amber-400">
            <WifiOff className="w-6 h-6" />
          </div>
          <div className="space-y-1.5">
            <h2 className="text-base font-semibold text-white">管理通道连接超时，正在自动重试...</h2>
            <p className="text-xs font-mono text-slate-400 break-words">{initNetError}</p>
          </div>
          <button
            type="button"
            onClick={() => void fetchStatus(false)}
            className="inline-flex items-center justify-center gap-2 px-4 py-2 rounded-xl bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-semibold text-xs transition-colors"
          >
            <RefreshCw className="w-3.5 h-3.5" />
            <span>立即重连</span>
          </button>
        </div>
      </div>
    );
  }

  // 3. Unauthenticated Screen (Show ONLY Login Modal, zero dashboard leakage)
  if (!isAuthenticated) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-[#080d1a]">
        <LoginModal
          isOpen={true}
          onSuccess={() => {
            isAuthenticatedRef.current = true;
            setIsAuthenticated(true);
            setInitNetError(null);
            void fetchStatus(true);
          }}
        />
      </div>
    );
  }

  // 3. Authenticated Full Dashboard
  return (
    <div className="min-h-dvh flex flex-col bg-[#080d1a] text-slate-100 animate-fade-in">
      <Header status={status} onLogout={handleLogout} lastOk={lastOk} linkDown={linkDown} />

      {linkDown && (
        <div className="bg-amber-500/10 border-b border-amber-500/30 text-amber-200 text-xs font-mono px-4 py-2 text-center">
          连接中断，正在重试
          {lastOk ? `。上次成功刷新 ${lastOk.toLocaleTimeString()}` : ''}
        </div>
      )}

      <main className="flex-1 max-w-[1440px] w-full mx-auto px-page-safe py-4 sm:py-6 pb-mobile-nav md:pb-8 space-y-5 sm:space-y-6">
        {status?.initialCredentials?.pending && (
          <div className="p-5 rounded-2xl border border-amber-500/30 bg-amber-500/10 space-y-3">
            <div>
              <h2 className="text-sm font-semibold text-amber-100">请先保存安装时生成的管理密码</h2>
              <p className="text-xs text-amber-200/80 mt-1">确认之后，面板不再显示这组明文。</p>
            </div>
            <div className="font-mono text-xs text-slate-100 space-y-1">
              <div>账号 {status.initialCredentials.username}</div>
              <div>密码 {status.initialCredentials.password}</div>
            </div>
            <div className="flex flex-wrap gap-2">
              <button
                type="button"
                onClick={() => copyPassword(status.initialCredentials?.password || '')}
                className="px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-700 text-xs text-slate-100"
              >
                复制密码
              </button>
              <button
                type="button"
                onClick={handleAckPassword}
                disabled={ackingPassword}
                className="px-3 py-1.5 rounded-lg bg-emerald-500/20 border border-emerald-500/30 text-xs text-emerald-200 disabled:opacity-50"
              >
                {ackingPassword ? '正在确认...' : '我已保存'}
              </button>
            </div>
          </div>
        )}

        <Navigation
          currentTab={currentTab}
          onChangeTab={setCurrentTab}
          onHoverTab={handleHoverTab}
        />

        <div className="pt-2">
          {currentTab === 'overview' && (
            <OverviewTab
              status={status}
              onRefresh={() => fetchStatus(false)}
              onNavigate={setCurrentTab}
            />
          )}

          {currentTab === 'services' && (
            <React.Suspense fallback={<CardSkeleton rows={4} />}>
              <ServicesTab
                status={status}
                onRefresh={() => fetchStatus(false)}
                onOpenLogs={handleOpenLogsForService}
                onNavigate={setCurrentTab}
              />
            </React.Suspense>
          )}

          {visitedTabs.has('warp') && (
            <div className={currentTab === 'warp' ? undefined : 'hidden'}>
              <React.Suspense fallback={<CardSkeleton rows={4} />}>
                <WarpTab active={currentTab === 'warp'} onRefreshParent={() => fetchStatus(false)} />
              </React.Suspense>
            </div>
          )}

          {visitedTabs.has('subscriptions') && (
            <div className={currentTab === 'subscriptions' ? undefined : 'hidden'}>
              <React.Suspense fallback={<CardSkeleton rows={4} />}>
                <SubscriptionsTab active={currentTab === 'subscriptions'} />
              </React.Suspense>
            </div>
          )}

          {visitedTabs.has('fleet') && (
            <div className={currentTab === 'fleet' ? undefined : 'hidden'}>
              <React.Suspense fallback={<CardSkeleton rows={4} />}>
                <FleetTab active={currentTab === 'fleet'} />
              </React.Suspense>
            </div>
          )}

          {currentTab === 'logs' && (
            <React.Suspense fallback={<CardSkeleton rows={4} />}>
              <LogsTab initialService={logService} />
            </React.Suspense>
          )}

          {currentTab === 'diagnostics' && (
            <React.Suspense fallback={<CardSkeleton rows={4} />}>
              <DiagnosticsTab status={status} onNavigate={setCurrentTab} />
            </React.Suspense>
          )}

          {currentTab === 'camouflage' && (
            <React.Suspense fallback={<CardSkeleton rows={4} />}>
              <CamouflageTab status={status} />
            </React.Suspense>
          )}

          {visitedTabs.has('security') && (
            <div className={currentTab === 'security' ? undefined : 'hidden'}>
              <React.Suspense fallback={<CardSkeleton rows={4} />}>
                <SecurityTab
                  active={currentTab === 'security'}
                  status={status}
                  onRefresh={() => fetchStatus(false)}
                />
              </React.Suspense>
            </div>
          )}
        </div>
      </main>

      <footer className="hidden md:block border-t border-slate-900 py-5 text-center text-xs text-slate-600 font-mono">
        SingCtl Fleet &amp; Security Self-Healing · 极简零外部依赖 · 单二进制内嵌静态控制台
      </footer>
    </div>
  );
};

export const ServerApp: React.FC = () => {
  return (
    <ToastProvider>
      <DashboardContent />
    </ToastProvider>
  );
};

export default ServerApp;

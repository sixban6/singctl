import React, { useEffect, useState, useCallback } from 'react';
import { ServerStatusResponse } from './types';
import { ApiError, api, setOnUnauthorized } from './api';
import { ToastProvider, useToast } from './components/Toast';
import { Header } from './components/Header';
import { Navigation, TabKey } from './components/Navigation';
import { OverviewTab } from './components/OverviewTab';
import { ServicesTab } from './components/ServicesTab';
import { SubscriptionsTab } from './components/SubscriptionsTab';
import { FleetTab } from './components/FleetTab';
import { LogsTab } from './components/LogsTab';
import { DiagnosticsTab } from './components/DiagnosticsTab';
import { SecurityTab } from './components/SecurityTab';
import { CamouflageTab } from './components/CamouflageTab';
import { LoginModal } from './components/LoginModal';
import { Activity } from 'lucide-react';

const DashboardContent: React.FC = () => {
  const { error, success } = useToast();
  const [currentTab, setCurrentTab] = useState<TabKey>('overview');
  const [status, setStatus] = useState<ServerStatusResponse | null>(null);
  const [isCheckingAuth, setIsCheckingAuth] = useState(true);
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [logService, setLogService] = useState('singbox');
  const [linkDown, setLinkDown] = useState(false);
  const [lastOk, setLastOk] = useState<Date | null>(null);
  const [ackingPassword, setAckingPassword] = useState(false);

  const fetchStatus = useCallback(async (silent = false) => {
    if (!silent && !isAuthenticated) setIsCheckingAuth(true);
    try {
      const data = await api.getStatus();
      setStatus(data);
      setIsAuthenticated(true);
      setLinkDown(false);
      setLastOk(new Date());
    } catch (err: unknown) {
      const unauthorized = err instanceof ApiError && err.status === 401;
      if (unauthorized || !isAuthenticated) {
        setIsAuthenticated(false);
        setLinkDown(false);
      } else {
        setLinkDown(true);
      }
    } finally {
      setIsCheckingAuth(false);
    }
  }, [isAuthenticated]);

  useEffect(() => {
    setOnUnauthorized(() => {
      setIsAuthenticated(false);
      setIsCheckingAuth(false);
    });
    fetchStatus();
  }, [fetchStatus]);

  // Periodic polling every 12 seconds only when authenticated
  useEffect(() => {
    if (!isAuthenticated) return;
    const timer = setInterval(() => {
      fetchStatus(true);
    }, 12000);
    return () => clearInterval(timer);
  }, [isAuthenticated, fetchStatus]);

  const handleLogout = async () => {
    try {
      await api.logout();
      success('已安全退出');
      setStatus(null);
      setIsAuthenticated(false);
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
      <div className="min-h-screen flex flex-col items-center justify-center bg-[#080d1a] text-slate-400 select-none">
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

  // 2. Unauthenticated Screen (Show ONLY Login Modal, zero dashboard leakage)
  if (!isAuthenticated) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-[#080d1a]">
        <LoginModal
          isOpen={true}
          onSuccess={() => {
            fetchStatus();
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

      <main className="flex-1 max-w-[1440px] w-full mx-auto px-3.5 sm:px-6 lg:px-8 py-4 sm:py-6 pb-mobile-nav md:pb-8 space-y-5 sm:space-y-6">
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

        <Navigation currentTab={currentTab} onChangeTab={setCurrentTab} />

        <div className="pt-2">
          {currentTab === 'overview' && (
            <OverviewTab
              status={status}
              onRefresh={() => fetchStatus(false)}
              onNavigate={setCurrentTab}
            />
          )}

          {currentTab === 'services' && (
            <ServicesTab
              status={status}
              onRefresh={() => fetchStatus(false)}
              onOpenLogs={handleOpenLogsForService}
            />
          )}

          {currentTab === 'subscriptions' && <SubscriptionsTab />}

          {currentTab === 'fleet' && <FleetTab />}

          {currentTab === 'logs' && <LogsTab initialService={logService} />}

          {currentTab === 'diagnostics' && <DiagnosticsTab status={status} />}

          {currentTab === 'camouflage' && <CamouflageTab status={status} />}

          {currentTab === 'security' && (
            <SecurityTab status={status} onRefresh={() => fetchStatus(false)} />
          )}
        </div>
      </main>

      <footer className="hidden md:block border-t border-slate-900 py-5 text-center text-xs text-slate-600 font-mono">
        SingCtl Fleet &amp; Security Self-Healing · 极简零外部依赖 · 单二进制内嵌静态控制台
      </footer>
    </div>
  );
};

export const App: React.FC = () => {
  return (
    <ToastProvider>
      <DashboardContent />
    </ToastProvider>
  );
};

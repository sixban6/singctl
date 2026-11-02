import React, { useEffect, useState, useCallback } from 'react';
import { ServerStatusResponse } from './types';
import { api, setOnUnauthorized } from './api';
import { ToastProvider, useToast } from './components/Toast';
import { Header } from './components/Header';
import { Navigation, TabKey } from './components/Navigation';
import { OverviewTab } from './components/OverviewTab';
import { ServicesTab } from './components/ServicesTab';
import { SubscriptionsTab } from './components/SubscriptionsTab';
import { LogsTab } from './components/LogsTab';
import { DiagnosticsTab } from './components/DiagnosticsTab';
import { SecurityTab } from './components/SecurityTab';
import { LoginModal } from './components/LoginModal';
import { Activity } from 'lucide-react';

const DashboardContent: React.FC = () => {
  const { error, success } = useToast();
  const [currentTab, setCurrentTab] = useState<TabKey>('overview');
  const [status, setStatus] = useState<ServerStatusResponse | null>(null);
  const [isCheckingAuth, setIsCheckingAuth] = useState(true);
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [logService, setLogService] = useState('singbox');

  const fetchStatus = useCallback(async (silent = false) => {
    if (!silent && !isAuthenticated) setIsCheckingAuth(true);
    try {
      const data = await api.getStatus();
      setStatus(data);
      setIsAuthenticated(true);
    } catch (err: any) {
      setIsAuthenticated(false);
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
    } catch (err: any) {
      error(err.message || '登出失败');
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
    <div className="min-h-screen flex flex-col bg-[#080d1a] text-slate-100 animate-fade-in">
      <Header status={status} onLogout={handleLogout} />

      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-6 space-y-6">
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

          {currentTab === 'logs' && <LogsTab initialService={logService} />}

          {currentTab === 'diagnostics' && <DiagnosticsTab status={status} />}

          {currentTab === 'security' && (
            <SecurityTab status={status} onRefresh={() => fetchStatus(false)} />
          )}
        </div>
      </main>

      <footer className="border-t border-slate-900 py-6 text-center text-xs text-slate-600 font-mono">
        singctl fleet manager · zero external npm runtime · memory &lt; 25MB
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

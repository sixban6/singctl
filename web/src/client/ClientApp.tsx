import React, { useState, useCallback, useMemo, useEffect } from 'react';
import { Router, Terminal, RefreshCw, LogOut } from 'lucide-react';
import {
  AppShell,
  Button,
  CardSkeleton,
  ConfirmDialog,
  ToastProvider,
  lazyWithReload,
  useToast,
} from '../ui';
import {
  clearCachedQuery,
  emitClientInvalidate,
  peekCachedQuery,
  prefetchCachedQuery,
  useCachedQuery,
  useHashRoute,
} from '../hooks';
import { clientApi } from './api';
import { ADGUARD_OVERVIEW_CACHE_KEY, AUDIT_DEFAULT_CACHE_KEY, GATEWAY_CACHE_KEY } from './cacheKeys';
import { ClientStatusResponse } from './types';
import { TaskConsoleDrawer } from './TaskConsoleDrawer';
import { DashPage } from './pages/DashPage';
import {
  CLIENT_TABS,
  ClientTab,
  MOBILE_PRIMARY_TABS,
  ClientStatusPill,
  ClientTopbarBanners,
  buildClientExtraCommands,
  buildClientNavGroups,
} from './shell/clientNavConfig';
import { ClientInlineAuthModal } from './shell/ClientInlineAuthModal';
import { useClientActionRunner } from './shell/useClientActionRunner';

const SingBoxPage = lazyWithReload(
  () => import('./pages/SingBoxPage').then((m) => ({ default: m.SingBoxPage })),
  'client-singbox',
);
const AdGuardPage = lazyWithReload(
  () => import('./pages/AdGuardPage').then((m) => ({ default: m.AdGuardPage })),
  'client-adguard',
);
const AuditPage = lazyWithReload(
  () => import('./pages/AuditPage').then((m) => ({ default: m.AuditPage })),
  'client-audit',
);
const WatchdogPage = lazyWithReload(
  () => import('./pages/WatchdogPage').then((m) => ({ default: m.WatchdogPage })),
  'client-watchdog',
);
const NetworkHubPage = lazyWithReload(
  () => import('./pages/NetworkPage').then((m) => ({ default: m.NetworkHubPage })),
  'client-network',
);
const LogsPage = lazyWithReload(
  () => import('./pages/LogsPage').then((m) => ({ default: m.LogsPage })),
  'client-logs',
);
const SystemPage = lazyWithReload(
  () => import('./pages/SystemPage').then((m) => ({ default: m.SystemPage })),
  'client-system',
);

const ClientShell: React.FC = () => {
  const { error } = useToast();
  const { tab, sub, navigate } = useHashRoute<ClientTab>(CLIENT_TABS, 'dash');

  // 兼容旧版 #/fw 与 #/ts 书签跳转至「网络与组网」对应子页
  useEffect(() => {
    const normalizeLegacyHash = () => {
      const h = (window.location.hash || '').replace(/^#\/?/, '').split('?')[0];
      if (h === 'fw') navigate('net', 'fw');
      else if (h === 'ts') navigate('net', 'ts');
      else if (h === 'agh') navigate('dns');
      else if (h === 'panel') navigate('sb', 'nodes');
      else if (h === 'config') navigate('sb', 'subs');
    };
    normalizeLegacyHash();
    window.addEventListener('hashchange', normalizeLegacyHash);
    return () => window.removeEventListener('hashchange', normalizeLegacyHash);
  }, [navigate]);

  const {
    data: status,
    refreshing,
    refetch: refreshStatus,
  } = useCachedQuery<ClientStatusResponse>('client:status', () => clientApi.getStatus(), {
    pollMs: 12000,
  });

  // 已访问的高频重页面保活记录（仅对已点开过的 dns/audit 保持 DOM 挂载，切页 0ms 瞬开）
  const [visitedTabs, setVisitedTabs] = useState<Set<ClientTab>>(() => new Set([tab]));
  useEffect(() => {
    setVisitedTabs((prev) => {
      if (prev.has(tab)) return prev;
      const next = new Set(prev);
      next.add(tab);
      return next;
    });
  }, [tab]);

  // 悬停 / 触控预热：鼠标滑过或手指触碰导航栏时提前在内存预热数据与懒加载分包
  const handleHoverTab = useCallback((target: ClientTab) => {
    switch (target) {
      case 'sb':
        void import('./pages/SingBoxPage');
        break;
      case 'dns':
        void import('./pages/AdGuardPage');
        if (!peekCachedQuery(ADGUARD_OVERVIEW_CACHE_KEY)) {
          void prefetchCachedQuery(ADGUARD_OVERVIEW_CACHE_KEY, () => clientApi.getAdGuardOverview());
        }
        break;
      case 'audit':
        void import('./pages/AuditPage');
        if (!peekCachedQuery(AUDIT_DEFAULT_CACHE_KEY)) {
          const qs = new URLSearchParams({ sort: 'active', dir: 'desc' });
          void prefetchCachedQuery(AUDIT_DEFAULT_CACHE_KEY, () => clientApi.getAudit(qs));
        }
        break;
      case 'dm':
        void import('./pages/WatchdogPage');
        break;
      case 'net':
        void import('./pages/NetworkPage');
        if (!peekCachedQuery(GATEWAY_CACHE_KEY)) {
          void prefetchCachedQuery(GATEWAY_CACHE_KEY, () => clientApi.getGateway());
        }
        break;
      case 'logs':
        void import('./pages/LogsPage');
        break;
      case 'sys':
        void import('./pages/SystemPage');
        break;
    }
  }, []);

  // 首屏空闲静默预热：首屏核心 status 就绪后 500ms 自动预热防劫持 DNS、行为审计与网关拓扑快照
  useEffect(() => {
    if (!status) return;
    const timer = window.setTimeout(() => {
      if (tab !== 'dns' && !peekCachedQuery(ADGUARD_OVERVIEW_CACHE_KEY)) {
        void prefetchCachedQuery(ADGUARD_OVERVIEW_CACHE_KEY, () => clientApi.getAdGuardOverview());
      }
      if (tab !== 'audit' && status.singbox?.running && !peekCachedQuery(AUDIT_DEFAULT_CACHE_KEY)) {
        const qs = new URLSearchParams({ sort: 'active', dir: 'desc' });
        void prefetchCachedQuery(AUDIT_DEFAULT_CACHE_KEY, () => clientApi.getAudit(qs));
      }
      if (tab !== 'net' && !peekCachedQuery(GATEWAY_CACHE_KEY)) {
        void prefetchCachedQuery(GATEWAY_CACHE_KEY, () => clientApi.getGateway());
      }
    }, 500);
    return () => window.clearTimeout(timer);
  }, [status, tab]);

  const {
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
  } = useClientActionRunner(refreshStatus);

  const handleLogout = useCallback(async () => {
    try {
      await clientApi.logout();
      clearCachedQuery();
      reloadWithCacheBust();
    } catch (e) {
      error((e as Error).message || '退出登录失败');
    }
  }, [error, reloadWithCacheBust]);

  const navGroups = useMemo(() => buildClientNavGroups(status), [status]);

  const extraCommands = useMemo(
    () => buildClientExtraCommands(requestAction, () => setDrawerOpen(true)),
    [requestAction, setDrawerOpen],
  );

  const navigateSafe = useCallback(
    (next: string, nextSub?: string) => {
      if (next === 'fw') {
        navigate('net', 'fw');
        return;
      }
      if (next === 'ts') {
        navigate('net', 'ts');
        return;
      }
      if (next === 'panel') {
        navigate('sb', 'nodes');
        return;
      }
      if (next === 'agh') {
        navigate('dns');
        return;
      }
      if (next === 'config') {
        navigate('sb', 'subs');
        return;
      }
      if (CLIENT_TABS.includes(next as ClientTab)) {
        navigate(next as ClientTab, nextSub);
      }
    },
    [navigate],
  );

  const topbarActions = (
    <div className="flex items-center gap-1.5">
      {(consoleLines.length > 0 || busy) && (
        <Button
          size="sm"
          variant={drawerOpen ? 'primary' : 'secondary'}
          icon={<Terminal className={`w-3.5 h-3.5 ${busy ? 'animate-pulse text-emerald-400' : ''}`} />}
          onClick={() => setDrawerOpen((v) => !v)}
        >
          <span className="hidden sm:inline">{busy ? '任务执行中' : '任务控制台'}</span>
        </Button>
      )}

      <Button
        size="sm"
        variant="ghost"
        title="刷新系统状态"
        onClick={() => void refreshStatus(false)}
        icon={<RefreshCw className={`w-3.5 h-3.5 ${refreshing ? 'animate-spin text-emerald-400' : ''}`} />}
      />

      {status?.authEnabled && (
        <button
          type="button"
          onClick={() => void handleLogout()}
          title="退出登录"
          className="flex items-center gap-1.5 px-2.5 sm:px-3 py-1.5 rounded-lg bg-rose-500/10 hover:bg-rose-500/20 border border-rose-500/20 text-rose-300 text-xs font-medium transition-all cursor-pointer"
        >
          <LogOut className="w-3.5 h-3.5" />
          <span className="hidden sm:inline">退出</span>
        </button>
      )}
    </div>
  );

  const banner = (
    <ClientTopbarBanners
      status={status}
      busy={busy}
      tsSwapBanner={tsSwapBanner}
      restartingBanner={restartingBanner}
      restartTimedOut={restartTimedOut}
      onRepollTailscale={() => void pollTailscaleUpgrade(false)}
      onDismissTsBanner={() => setTsSwapBanner(null)}
      onReloadPage={reloadWithCacheBust}
      onRestartDaemon={() => requestAction('dm-restart')}
    />
  );

  return (
    <>
      <AppShell
        brandTitle="网关控制台"
        brandSubtitle={
          status?.host?.lanIP
            ? `${status.host.hostname || 'Router'} · ${status.host.lanIP}`
            : status?.host?.hostname || 'SingCtl Client Gateway'
        }
        brandIcon={<Router className="w-4 h-4 sm:w-5 sm:h-5 text-cyan-400" />}
        brandIconClassName="bg-gradient-to-br from-emerald-500/15 to-cyan-500/15 border border-cyan-400/25 shadow-[0_0_16px_-2px_rgba(34,211,238,0.35)]"
        version={status?.singctlVersion}
        groups={navGroups}
        activeTab={tab}
        onSelectTab={(next) => navigate(next)}
        onHoverTab={handleHoverTab}
        mobilePrimaryKeys={MOBILE_PRIMARY_TABS}
        statusPill={status ? <ClientStatusPill status={status} /> : null}
        topbarActions={topbarActions}
        banner={banner}
        extraCommandItems={extraCommands}
      >
        {tab === 'dash' && (
          <DashPage
            status={status ?? null}
            busy={busy}
            onAction={requestAction}
            onNavigate={navigateSafe}
          />
        )}
        {tab === 'sb' && (
          <React.Suspense fallback={<CardSkeleton rows={4} />}>
            <SingBoxPage
              status={status ?? null}
              busy={busy}
              initialSub={sub}
              onSubChange={(nextSub) => navigate('sb', nextSub === 'routing' ? undefined : nextSub)}
              onAction={requestAction}
              onNavigate={navigateSafe}
              onRefreshStatus={() => void refreshStatus(true)}
            />
          </React.Suspense>
        )}
        {(tab === 'dns' || visitedTabs.has('dns')) && (
          <div className={tab === 'dns' ? 'block' : 'hidden'} aria-hidden={tab !== 'dns'}>
            <React.Suspense fallback={<CardSkeleton rows={4} />}>
              <AdGuardPage
                active={tab === 'dns'}
                status={status ?? null}
                busy={busy}
                onAction={requestAction}
                onRefreshStatus={() => void refreshStatus(true)}
              />
            </React.Suspense>
          </div>
        )}
        {(tab === 'audit' || visitedTabs.has('audit')) && (
          <div className={tab === 'audit' ? 'block' : 'hidden'} aria-hidden={tab !== 'audit'}>
            <React.Suspense fallback={<CardSkeleton rows={4} />}>
              <AuditPage active={tab === 'audit'} />
            </React.Suspense>
          </div>
        )}
        {tab === 'dm' && (
          <React.Suspense fallback={<CardSkeleton rows={4} />}>
            <WatchdogPage
              busy={busy}
              onAction={requestAction}
              onRefreshStatus={() => void refreshStatus(true)}
              onOpenEventsLog={() => navigate('logs', 'events')}
            />
          </React.Suspense>
        )}
        {tab === 'net' && (
          <React.Suspense fallback={<CardSkeleton rows={4} />}>
            <NetworkHubPage
              status={status ?? null}
              busy={busy || Boolean(tsSwapBanner?.active)}
              initialSub={sub}
              onSubChange={(nextSub) => navigate('net', nextSub === 'gw' ? undefined : nextSub)}
              onAction={requestAction}
              onNavigate={navigateSafe}
              onRefreshStatus={() => void refreshStatus(true)}
            />
          </React.Suspense>
        )}
        {tab === 'logs' && (
          <React.Suspense fallback={<CardSkeleton rows={4} />}>
            <LogsPage initialLogName={sub} />
          </React.Suspense>
        )}
        {tab === 'sys' && (
          <React.Suspense fallback={<CardSkeleton rows={4} />}>
            <SystemPage
              status={status ?? null}
              busy={busy}
              onAction={requestAction}
              onRestored={() => {
                void refreshStatus(true);
                emitClientInvalidate('all');
              }}
            />
          </React.Suspense>
        )}
      </AppShell>

      <TaskConsoleDrawer
        open={drawerOpen}
        running={busy}
        title={consoleTitle}
        cmd={consoleCmd}
        lines={consoleLines}
        onClose={() => setDrawerOpen(false)}
        onClear={() => setConsoleLines([])}
        onCopy={handleCopyConsole}
      />

      <ConfirmDialog
        open={Boolean(confirmState)}
        title="确认执行高风险操作"
        description={confirmState?.message || ''}
        confirmText="确认执行"
        danger
        loading={busy}
        onCancel={() => setConfirmState(null)}
        onConfirm={() => {
          if (!confirmState) return;
          const next = confirmState;
          setConfirmState(null);
          void executeAction(next.name, next.params);
        }}
      />

      <ClientInlineAuthModal
        suppressPopup={restartingBanner || Boolean(tsSwapBanner?.active)}
        onVerified={async () => {
          await refreshStatus(true);
        }}
      />
    </>
  );
};

export const ClientApp: React.FC = () => (
  <ToastProvider>
    <ClientShell />
  </ToastProvider>
);

export default ClientApp;

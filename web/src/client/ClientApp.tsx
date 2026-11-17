import React, { useState, useCallback, useMemo, useEffect } from 'react';
import {
  Activity,
  Router,
  FileText,
  Zap,
  ShieldCheck,
  ShieldAlert,
  HeartPulse,
  Network,
  FileCode2,
  Wrench,
  Terminal,
  RefreshCw,
  LogOut,
  RotateCw,
  Download,
  Lock,
} from 'lucide-react';
import {
  AppShell,
  Button,
  CommandItem,
  ConfirmDialog,
  NavGroupConfig,
  StatusDot,
  ToastProvider,
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
import { clientApi, CLIENT_AUTH_EVENT } from './api';
import { ClientStatusResponse } from './types';
import { TaskConsoleDrawer } from './TaskConsoleDrawer';
import { DashPage } from './pages/DashPage';
import { SingBoxPage } from './pages/SingBoxPage';
import { AdGuardPage, ADGUARD_OVERVIEW_CACHE_KEY } from './pages/AdGuardPage';
import { AuditPage, AUDIT_DEFAULT_CACHE_KEY } from './pages/AuditPage';
import { WatchdogPage } from './pages/WatchdogPage';
import { NetworkHubPage } from './pages/NetworkPage';
import { ConfigPage } from './pages/ConfigPage';
import { LogsPage } from './pages/LogsPage';
import { SystemPage } from './pages/SystemPage';

const CLIENT_TABS = ['dash', 'sb', 'dns', 'audit', 'dm', 'net', 'config', 'logs', 'sys'] as const;
type ClientTab = (typeof CLIENT_TABS)[number];

const MOBILE_PRIMARY_TABS: readonly ClientTab[] = ['dash', 'sb', 'dns', 'audit'];

interface ConfirmState {
  name: string;
  params: Record<string, unknown>;
  message: string;
}

const ClientShell: React.FC = () => {
  const { success, error, toast } = useToast();
  const { tab, sub, navigate } = useHashRoute<ClientTab>(CLIENT_TABS, 'dash');

  // 兼容旧版 #/fw 与 #/ts 书签跳转至「网络与组网」对应子页
  useEffect(() => {
    const normalizeLegacyHash = () => {
      const h = (window.location.hash || '').replace(/^#\/?/, '').split('?')[0];
      if (h === 'fw') navigate('net', 'fw');
      else if (h === 'ts') navigate('net', 'ts');
      else if (h === 'agh') navigate('dns');
      else if (h === 'panel') navigate('sb', 'nodes');
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

  // 悬停 / 触控预热：鼠标滑过或手指触碰导航栏时提前在内存预热数据
  const handleHoverTab = useCallback((target: ClientTab) => {
    if (target === 'dns' && !peekCachedQuery(ADGUARD_OVERVIEW_CACHE_KEY)) {
      void prefetchCachedQuery(ADGUARD_OVERVIEW_CACHE_KEY, () => clientApi.getAdGuardOverview());
    } else if (target === 'audit' && !peekCachedQuery(AUDIT_DEFAULT_CACHE_KEY)) {
      const qs = new URLSearchParams({ sort: 'active', dir: 'desc' });
      void prefetchCachedQuery(AUDIT_DEFAULT_CACHE_KEY, () => clientApi.getAudit(qs));
    }
  }, []);

  // 首屏空闲静默预热：首屏核心 status 就绪后 500ms 自动预热防劫持 DNS 与行为审计默认快照，消除首次点击白屏
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
    }, 500);
    return () => window.clearTimeout(timer);
  }, [status, tab]);

  // Action Runner & Console Drawer state
  const [busy, setBusy] = useState(false);
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [consoleTitle, setConsoleTitle] = useState('');
  const [consoleCmd, setConsoleCmd] = useState('');
  const [consoleLines, setConsoleLines] = useState<string[]>([]);
  const [confirmState, setConfirmState] = useState<ConfirmState | null>(null);
  const [restartingBanner, setRestartingBanner] = useState(false);
  const [restartTimedOut, setRestartTimedOut] = useState(false);

  // 内嵌口令登录弹窗状态（会话过期或口令变更时免弹窗直登，彻底告别 401 无限刷新循环）
  const [authModalOpen, setAuthModalOpen] = useState(false);
  const [authPassword, setAuthPassword] = useState('');
  const [authSubmitting, setAuthSubmitting] = useState(false);
  const [authError, setAuthError] = useState('');

  const reloadWithCacheBust = useCallback(() => {
    const sep = window.location.pathname.includes('?') ? '&' : '?';
    window.location.replace(
      `${window.location.pathname}${sep}_t=${Date.now()}${window.location.hash || ''}`,
    );
  }, []);

  useEffect(() => {
    const onUnauthorized = () => {
      if (restartingBanner) return;
      setAuthModalOpen(true);
    };
    window.addEventListener(CLIENT_AUTH_EVENT, onUnauthorized);
    return () => window.removeEventListener(CLIENT_AUTH_EVENT, onUnauthorized);
  }, [restartingBanner]);

  const handleInlineLogin = useCallback(
    async (e: React.FormEvent) => {
      e.preventDefault();
      if (!authPassword || authSubmitting) return;
      setAuthSubmitting(true);
      setAuthError('');
      try {
        await clientApi.login(authPassword);
        setAuthModalOpen(false);
        setAuthPassword('');
        success('验证成功，已恢复会话');
        await refreshStatus(true);
      } catch (err) {
        setAuthError((err as Error).message || '访问口令验证失败');
      } finally {
        setAuthSubmitting(false);
      }
    },
    [authPassword, authSubmitting, refreshStatus, success],
  );

  const executeAction = useCallback(
    async (name: string, params: Record<string, unknown> = {}) => {
      if (busy) {
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
    [busy, refreshStatus, reloadWithCacheBust, success, error, toast],
  );

  const requestAction = useCallback(
    (name: string, params: Record<string, unknown> = {}, confirmMsg?: string) => {
      if (confirmMsg) {
        setConfirmState({ name, params, message: confirmMsg });
        return;
      }
      executeAction(name, params);
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

  const handleLogout = useCallback(async () => {
    try {
      await clientApi.logout();
      clearCachedQuery();
      reloadWithCacheBust();
    } catch (e) {
      error((e as Error).message || '退出登录失败');
    }
  }, [error, reloadWithCacheBust]);

  const navGroups: NavGroupConfig<ClientTab>[] = useMemo(() => {
    // 遵循「常态零绿点、仅异常微标提醒」规范：健康运行时 9 个选项卡视觉完全统一对称
    const sbBadge =
      status && status.singbox.installed && !status.singbox.running ? (
        <StatusDot tone="danger" />
      ) : undefined;
    const dmBadge = status?.daemon?.staleBinary ? <StatusDot tone="warn" /> : undefined;
    const dnsBadge =
      status?.adguard?.installed && status.adguard.enabled && !status.adguard.dnsHealthy ? (
        <StatusDot tone="danger" />
      ) : undefined;

    return [
      {
        title: '运行与核心',
        items: [
          {
            key: 'dash',
            label: '总览与监控',
            shortLabel: '总览',
            desc: '核心服务运行状态与一键运维操作',
            icon: Activity,
          },
          {
            key: 'sb',
            label: 'sing-box',
            shortLabel: '核心',
            desc: '智能分流开关、策略组节点选择测速、模式切换与内核控制',
            icon: Zap,
            badge: sbBadge,
          },
          {
            key: 'dns',
            label: '防劫持 DNS',
            shortLabel: 'DNS',
            desc: '本地 AdGuard Home 加密 DoH 防抢答、防误伤暂停与内网域名重写',
            icon: ShieldCheck,
            badge: dnsBadge,
          },
          {
            key: 'audit',
            label: '行为与审计',
            shortLabel: '审计',
            desc: '局域网异常流量识别、AI 研判与一键封禁',
            icon: ShieldAlert,
          },
          {
            key: 'dm',
            label: '看门狗自愈',
            shortLabel: '看门狗',
            desc: '自动巡检保活、订阅同步与故障切换配置',
            icon: HeartPulse,
            badge: dmBadge,
          },
        ],
      },
      {
        title: '代理与网络',
        items: [
          {
            key: 'net',
            label: '网络与组网',
            shortLabel: '组网',
            desc: 'Tailscale 异地子网组网与 nftables 防火墙加固',
            icon: Network,
          },
        ],
      },
      {
        title: '配置与维护',
        items: [
          {
            key: 'config',
            label: '配置与订阅',
            shortLabel: '配置',
            desc: '订阅源、GitHub 加速镜像与 singctl.yaml 编辑',
            icon: FileCode2,
          },
          {
            key: 'logs',
            label: '系统日志',
            shortLabel: '日志',
            desc: '查看守护进程、事件与 Web 审计日志',
            icon: FileText,
          },
          {
            key: 'sys',
            label: '系统维护',
            shortLabel: '运维',
            desc: '版本信息、一键更新与移动设备授权连接',
            icon: Wrench,
          },
        ],
      },
    ];
  }, [status]);

  const extraCommands: CommandItem[] = useMemo(
    () => [
      {
        id: 'act-sb-restart',
        label: '重启 sing-box 代理核心',
        hint: 'singctl',
        group: '快捷操作',
        icon: <RotateCw className="w-3.5 h-3.5" />,
        keywords: 'restart singbox proxy core',
        onSelect: () => requestAction('sb-restart'),
      },
      {
        id: 'act-sb-gen',
        label: '更新订阅并生成最新 sing-box 配置',
        hint: 'sync',
        group: '快捷操作',
        icon: <Download className="w-3.5 h-3.5" />,
        keywords: 'gen subscribe update config',
        onSelect: () => requestAction('sb-gen'),
      },
      {
        id: 'act-dm-restart',
        label: '重启看门狗守护进程',
        hint: 'daemon',
        group: '快捷操作',
        icon: <HeartPulse className="w-3.5 h-3.5" />,
        keywords: 'watchdog daemon restart',
        onSelect: () => requestAction('dm-restart'),
      },
      {
        id: 'act-dns-restart',
        label: '重启本地 AdGuard Home 防劫持 DNS',
        hint: 'dns',
        group: '快捷操作',
        icon: <ShieldCheck className="w-3.5 h-3.5" />,
        keywords: 'adguard dns doh restart',
        onSelect: () => requestAction('dns-restart'),
      },
      {
        id: 'act-open-console',
        label: '打开任务执行终端控制台',
        hint: 'console',
        group: '快捷操作',
        icon: <Terminal className="w-3.5 h-3.5" />,
        keywords: 'terminal console log task',
        onSelect: () => setDrawerOpen(true),
      },
    ],
    [requestAction],
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
      if (CLIENT_TABS.includes(next as ClientTab)) {
        navigate(next as ClientTab, nextSub);
      }
    },
    [navigate],
  );

  const statusPill = status ? (
    <div className="hidden md:flex items-center gap-2 text-xs font-mono text-slate-400">
      <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-slate-900 border border-slate-800">
        <StatusDot tone={status.singbox.running ? 'ok' : 'danger'} pulse={status.singbox.running} />
        <span className="text-slate-400">核心</span>
        <span className={status.singbox.running ? 'text-emerald-400 font-semibold' : 'text-rose-400 font-semibold'}>
          {status.singbox.running ? '运行中' : '已停止'}
        </span>
      </div>
      <div className="hidden lg:flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-slate-900 border border-slate-800">
        <span className="text-slate-400">看门狗</span>
        <span className={status.daemon.running ? 'text-emerald-400 font-semibold' : 'text-slate-300 font-semibold'}>
          {status.daemon.running ? '守护中' : '未运行'}
        </span>
      </div>
      {status.host.lanIP && (
        <div className="hidden xl:flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-slate-900 border border-slate-800">
          <span className="text-slate-400">网关</span>
          <span className="text-slate-200 font-semibold">{status.host.lanIP}</span>
        </div>
      )}
    </div>
  ) : null;

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
        onClick={() => refreshStatus(false)}
        icon={<RefreshCw className={`w-3.5 h-3.5 ${refreshing ? 'animate-spin text-emerald-400' : ''}`} />}
      />

      {status?.authEnabled && (
        <button
          type="button"
          onClick={handleLogout}
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
    <>
      {restartingBanner && (
        <div
          className={`rounded-xl border px-4 py-2.5 text-xs flex flex-wrap items-center justify-between gap-2 ${
            restartTimedOut
              ? 'border-amber-500/35 bg-amber-500/10 text-amber-200'
              : 'border-emerald-500/30 bg-emerald-500/10 text-emerald-300'
          }`}
        >
          <div className="flex items-center gap-2">
            <RefreshCw className={`w-4 h-4 shrink-0 ${restartTimedOut ? '' : 'animate-spin'}`} />
            <span>
              {restartTimedOut
                ? '服务重启等待超时，若新版进程已完成启动，可点击右侧按钮手动重连刷新。'
                : '程序已完成自我更新并正在平滑重启 Web 服务，恢复后将自动刷新加载最新版本…'}
            </span>
          </div>
          <Button size="xs" variant="secondary" onClick={reloadWithCacheBust}>
            立即重连 / 刷新页面
          </Button>
        </div>
      )}
      {status?.daemon?.staleBinary && (
        <div className="rounded-xl border border-amber-500/30 bg-amber-500/10 px-4 py-2.5 flex flex-wrap items-center justify-between gap-2 text-xs">
          <span className="text-amber-200">
            检测到看门狗守护进程仍在运行旧版本二进制 ({status.daemon.daemonVersion || '未知'} →{' '}
            {status.singctlVersion})，建议重启看门狗使其加载新特性。
          </span>
          <Button
            size="xs"
            variant="secondary"
            loading={busy}
            onClick={() => requestAction('dm-restart')}
          >
            立即重启看门狗
          </Button>
        </div>
      )}
    </>
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
        statusPill={statusPill}
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
          <SingBoxPage
            status={status ?? null}
            busy={busy}
            initialSub={sub}
            onSubChange={(nextSub) => navigate('sb', nextSub === 'routing' ? undefined : nextSub)}
            onAction={requestAction}
            onNavigate={navigateSafe}
          />
        )}
        {(tab === 'dns' || visitedTabs.has('dns')) && (
          <div className={tab === 'dns' ? 'block' : 'hidden'} aria-hidden={tab !== 'dns'}>
            <AdGuardPage
              active={tab === 'dns'}
              status={status ?? null}
              busy={busy}
              onAction={requestAction}
              onRefreshStatus={() => refreshStatus(true)}
            />
          </div>
        )}
        {(tab === 'audit' || visitedTabs.has('audit')) && (
          <div className={tab === 'audit' ? 'block' : 'hidden'} aria-hidden={tab !== 'audit'}>
            <AuditPage active={tab === 'audit'} />
          </div>
        )}
        {tab === 'dm' && (
          <WatchdogPage
            busy={busy}
            onAction={requestAction}
            onRefreshStatus={() => refreshStatus(true)}
            onOpenEventsLog={() => navigate('logs', 'events')}
          />
        )}
        {tab === 'net' && (
          <NetworkHubPage
            status={status ?? null}
            busy={busy}
            initialSub={sub}
            onSubChange={(nextSub) => navigate('net', nextSub === 'gw' ? undefined : nextSub)}
            onAction={requestAction}
            onNavigate={navigateSafe}
            onRefreshStatus={() => refreshStatus(true)}
          />
        )}
        {tab === 'config' && (
          <ConfigPage
            onSaved={() => {
              void refreshStatus(true);
              emitClientInvalidate('all');
            }}
          />
        )}
        {tab === 'logs' && <LogsPage initialLogName={sub} />}
        {tab === 'sys' && (
          <SystemPage status={status ?? null} busy={busy} onAction={requestAction} />
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
          executeAction(next.name, next.params);
        }}
      />

      {authModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/75 backdrop-blur-sm p-4">
          <form
            onSubmit={handleInlineLogin}
            className="w-full max-w-sm rounded-2xl border border-slate-800 bg-slate-900 p-6 shadow-2xl space-y-4"
          >
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-xl bg-cyan-500/15 border border-cyan-400/25 flex items-center justify-center text-cyan-400 shrink-0">
                <Lock className="w-5 h-5" />
              </div>
              <div>
                <h3 className="text-base font-semibold text-slate-100">需要验证访问口令</h3>
                <p className="text-xs text-slate-400">会话已过期或服务已启用口令保护</p>
              </div>
            </div>

            {authError && (
              <div className="rounded-xl border border-rose-500/30 bg-rose-500/10 px-3 py-2 text-xs text-rose-300">
                {authError}
              </div>
            )}

            <div className="space-y-1.5">
              <label className="block text-xs font-medium text-slate-300">WebUI 访问口令</label>
              <input
                type="password"
                value={authPassword}
                onChange={(e) => setAuthPassword(e.target.value)}
                placeholder="请输入访问口令"
                autoFocus
                required
                className="w-full h-10 rounded-xl border border-slate-700 bg-slate-950 px-3 text-sm text-slate-100 placeholder:text-slate-500 focus:border-cyan-500 focus:outline-none"
              />
            </div>

            <div className="flex items-center justify-end gap-2 pt-1">
              <Button
                type="submit"
                variant="primary"
                loading={authSubmitting}
                disabled={!authPassword || authSubmitting}
                className="w-full justify-center"
              >
                {authSubmitting ? '正在验证...' : '验证并恢复控制台'}
              </Button>
            </div>
          </form>
        </div>
      )}
    </>
  );
};

export const ClientApp: React.FC = () => (
  <ToastProvider>
    <ClientShell />
  </ToastProvider>
);

export default ClientApp;

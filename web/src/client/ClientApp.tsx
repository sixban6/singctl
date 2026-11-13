import React, { useState, useCallback, useMemo } from 'react';
import {
  Activity,
  FileText,
  Zap,
  Sliders,
  ShieldAlert,
  HeartPulse,
  Shield,
  Network,
  FileCode2,
  Wrench,
  Terminal,
  RefreshCw,
  LogOut,
  RotateCw,
  Download,
} from 'lucide-react';
import {
  AppShell,
  Badge,
  Button,
  CommandItem,
  ConfirmDialog,
  NavGroupConfig,
  StatusDot,
  ToastProvider,
  useToast,
} from '../ui';
import { useCachedQuery, useHashRoute, useTheme } from '../hooks';
import { clientApi } from './api';
import { ClientStatusResponse } from './types';
import { TaskConsoleDrawer } from './TaskConsoleDrawer';
import { DashPage } from './pages/DashPage';
import { SingBoxPage } from './pages/SingBoxPage';
import { PanelPage } from './pages/PanelPage';
import { AuditPage } from './pages/AuditPage';
import { WatchdogPage } from './pages/WatchdogPage';
import { FirewallPage, TailscalePage } from './pages/NetworkPage';
import { ConfigPage } from './pages/ConfigPage';
import { LogsPage } from './pages/LogsPage';
import { SystemPage } from './pages/SystemPage';

const CLIENT_TABS = ['dash', 'logs', 'sb', 'panel', 'audit', 'dm', 'fw', 'ts', 'config', 'sys'] as const;
type ClientTab = (typeof CLIENT_TABS)[number];

const MOBILE_PRIMARY_TABS: readonly ClientTab[] = ['dash', 'sb', 'audit', 'dm'];

interface ConfirmState {
  name: string;
  params: Record<string, unknown>;
  message: string;
}

const ClientShell: React.FC = () => {
  const { success, error, toast } = useToast();
  const { theme, toggleTheme } = useTheme();
  const { tab, sub, navigate } = useHashRoute<ClientTab>(CLIENT_TABS, 'dash');

  const {
    data: status,
    refreshing,
    refetch: refreshStatus,
  } = useCachedQuery<ClientStatusResponse>('client:status', () => clientApi.getStatus(), {
    pollMs: 12000,
  });

  // Action Runner & Console Drawer state
  const [busy, setBusy] = useState(false);
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [consoleTitle, setConsoleTitle] = useState('');
  const [consoleCmd, setConsoleCmd] = useState('');
  const [consoleLines, setConsoleLines] = useState<string[]>([]);
  const [confirmState, setConfirmState] = useState<ConfirmState | null>(null);
  const [restartingBanner, setRestartingBanner] = useState(false);

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
          toast('程序已自更新，正在重启 Web 控制台并等待恢复…', 'info');
          window.setTimeout(() => {
            const poll = window.setInterval(async () => {
              try {
                await clientApi.getStatus();
                window.clearInterval(poll);
                window.location.reload();
              } catch {
                // still restarting
              }
            }, 1200);
          }, 3000);
          return;
        }

        if (res.code === 0) {
          success('操作执行成功');
        } else {
          error(`操作退出异常 (code ${res.code})`);
        }
        await refreshStatus(true);
      } catch (e) {
        const msg = (e as Error).message || '执行失败';
        setConsoleLines((prev) => [...prev, `[ERROR] ${msg}`]);
        error(msg);
      } finally {
        setBusy(false);
      }
    },
    [busy, refreshStatus, success, error, toast],
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
      window.location.reload();
    } catch (e) {
      error((e as Error).message || '退出登录失败');
    }
  }, [error]);

  const navGroups: NavGroupConfig<ClientTab>[] = useMemo(() => {
    const sbBadge = status ? (
      <StatusDot tone={status.singbox.running ? 'ok' : 'danger'} pulse={status.singbox.running} />
    ) : undefined;
    const dmBadge = status?.daemon?.staleBinary ? (
      <Badge tone="warn">旧版</Badge>
    ) : status ? (
      <StatusDot tone={status.daemon.running ? 'ok' : 'neutral'} pulse={status.daemon.running} />
    ) : undefined;

    return [
      {
        title: '运行监控',
        items: [
          {
            key: 'dash',
            label: '系统总览',
            shortLabel: '总览',
            desc: '核心服务运行状态与快速操作',
            icon: Activity,
          },
          {
            key: 'logs',
            label: '运行日志',
            shortLabel: '日志',
            desc: '查看守护进程、事件与 Web 审计日志',
            icon: FileText,
          },
        ],
      },
      {
        title: '代理核心',
        items: [
          {
            key: 'sb',
            label: 'sing-box',
            shortLabel: '核心',
            desc: '内核生命周期、规则集缓存与配置文件编辑器',
            icon: Zap,
            badge: sbBadge,
          },
          {
            key: 'panel',
            label: '控制面板',
            shortLabel: '面板',
            desc: '内置 Zashboard 实时节点测速与连接监控',
            icon: Sliders,
          },
        ],
      },
      {
        title: '安全守护',
        items: [
          {
            key: 'audit',
            label: '设备审计',
            shortLabel: '审计',
            desc: '局域网异常流量识别、AI 研判与一键封禁',
            icon: ShieldAlert,
          },
          {
            key: 'dm',
            label: '看门狗',
            shortLabel: '看门狗',
            desc: '自动巡检保活、订阅同步与故障切换配置',
            icon: HeartPulse,
            badge: dmBadge,
          },
          {
            key: 'fw',
            label: '防火墙',
            shortLabel: '防火墙',
            desc: 'macOS / Linux 透明代理网关转发策略',
            icon: Shield,
          },
          {
            key: 'ts',
            label: '组网',
            shortLabel: '组网',
            desc: 'Tailscale 异地子网与出口节点状态',
            icon: Network,
          },
        ],
      },
      {
        title: '配置系统',
        items: [
          {
            key: 'config',
            label: '配置管理',
            shortLabel: '配置',
            desc: '订阅源、GitHub 加速镜像与 singctl.yaml 编辑',
            icon: FileCode2,
          },
          {
            key: 'sys',
            label: '系统维护',
            shortLabel: '系统',
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
    (next: string) => {
      if (CLIENT_TABS.includes(next as ClientTab)) {
        navigate(next as ClientTab);
      }
    },
    [navigate],
  );

  const statusPill = status ? (
    <div className="inline-flex items-center gap-2 px-2.5 py-1 rounded-full bg-surface2 border border-subtle text-xs">
      <StatusDot tone={status.singbox.running ? 'ok' : 'danger'} pulse={status.singbox.running} />
      <span className="font-medium text-primary hidden sm:inline">
        {status.singbox.running ? '代理运行中' : '代理已停止'}
      </span>
      <span className="font-mono text-[11px] text-muted hidden md:inline">
        {status.host.hostname}
        {status.host.lanIP ? ` · ${status.host.lanIP}` : ''}
      </span>
    </div>
  ) : null;

  const topbarActions = (
    <div className="flex items-center gap-1.5">
      {(consoleLines.length > 0 || busy) && (
        <Button
          size="sm"
          variant={drawerOpen ? 'primary' : 'secondary'}
          icon={<Terminal className={`w-3.5 h-3.5 ${busy ? 'animate-pulse text-sky-400' : ''}`} />}
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
        icon={<RefreshCw className={`w-3.5 h-3.5 ${refreshing ? 'animate-spin' : ''}`} />}
      />

      {status?.authEnabled && (
        <Button
          size="sm"
          variant="ghost"
          title="退出登录"
          onClick={handleLogout}
          icon={<LogOut className="w-3.5 h-3.5" />}
        />
      )}
    </div>
  );

  const banner = (
    <>
      {restartingBanner && (
        <div className="rounded-xl border border-sky-500/30 bg-sky-500/10 px-4 py-2.5 text-xs text-sky-300 flex items-center gap-2">
          <RefreshCw className="w-4 h-4 animate-spin shrink-0" />
          <span>程序已完成自我更新并正在重启服务，控制台将在恢复后自动刷新…</span>
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
        brandTitle="SingCtl"
        brandSubtitle="客户端控制台"
        version={status?.singctlVersion}
        groups={navGroups}
        activeTab={tab}
        onSelectTab={(next) => navigate(next)}
        mobilePrimaryKeys={MOBILE_PRIMARY_TABS}
        statusPill={statusPill}
        topbarActions={topbarActions}
        banner={banner}
        theme={theme}
        onToggleTheme={toggleTheme}
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
            onAction={requestAction}
            onNavigate={navigateSafe}
          />
        )}
        {tab === 'panel' && <PanelPage status={status ?? null} />}
        {tab === 'audit' && <AuditPage />}
        {tab === 'dm' && (
          <WatchdogPage
            busy={busy}
            onAction={requestAction}
            onRefreshStatus={() => refreshStatus(true)}
            onOpenEventsLog={() => navigate('logs', 'events')}
          />
        )}
        {tab === 'ts' && (
          <TailscalePage
            status={status ?? null}
            busy={busy}
            onAction={requestAction}
            onNavigate={navigateSafe}
          />
        )}
        {tab === 'fw' && (
          <FirewallPage status={status ?? null} busy={busy} onAction={requestAction} />
        )}
        {tab === 'config' && <ConfigPage onSaved={() => refreshStatus(true)} />}
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
    </>
  );
};

export const ClientApp: React.FC = () => (
  <ToastProvider>
    <ClientShell />
  </ToastProvider>
);

export default ClientApp;

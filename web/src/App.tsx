import React, { useState, useEffect, useCallback, useMemo } from 'react';
import {
  Activity,
  Server,
  Globe2,
  Rss,
  Network,
  FileText,
  Stethoscope,
  EyeOff,
  ShieldCheck,
  RefreshCw,
  LogOut,
  AlertTriangle,
  Copy,
  Check,
} from 'lucide-react';
import { api, ApiError, setOnUnauthorized } from './api';
import { ServerStatusResponse } from './types';
import {
  AppShell,
  Button,
  CommandItem,
  NavGroupConfig,
  StatusDot,
  ToastProvider,
  useToast,
} from './ui';
import { useHashRoute, useTheme } from './hooks';
import { LoginModal } from './components/LoginModal';
import { OverviewTab } from './components/OverviewTab';
import { ServicesTab } from './components/ServicesTab';
import { WarpTab } from './components/WarpTab';
import { SubscriptionsTab } from './components/SubscriptionsTab';
import { FleetTab } from './components/FleetTab';
import { LogsTab } from './components/LogsTab';
import { DiagnosticsTab } from './components/DiagnosticsTab';
import { CamouflageTab } from './components/CamouflageTab';
import { SecurityTab } from './components/SecurityTab';

export const SERVER_TABS = [
  'overview',
  'diagnostics',
  'logs',
  'services',
  'warp',
  'subscriptions',
  'fleet',
  'security',
  'camouflage',
] as const;

export type TabKey = (typeof SERVER_TABS)[number];

const MOBILE_PRIMARY_TABS: readonly TabKey[] = ['overview', 'services', 'warp', 'security'];

const DashboardContent: React.FC = () => {
  const { success, error } = useToast();
  const { theme, toggleTheme } = useTheme();
  const { tab: currentTab, sub, navigate } = useHashRoute<TabKey>(SERVER_TABS, 'overview');

  const [status, setStatus] = useState<ServerStatusResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [needsAuth, setNeedsAuth] = useState(false);
  const [ackingPassword, setAckingPassword] = useState(false);
  const [logService, setLogService] = useState<string>(sub || 'singbox');

  const fetchStatus = useCallback(
    async (silent = false) => {
      if (!silent) {
        setRefreshing(true);
      }
      try {
        const res = await api.getStatus();
        setStatus(res);
        setNeedsAuth(false);
      } catch (err: unknown) {
        if (err instanceof ApiError && err.status === 401) {
          setNeedsAuth(true);
        } else if (!silent) {
          error(err instanceof Error ? err.message : '读取服务端状态失败');
        }
      } finally {
        setLoading(false);
        setRefreshing(false);
      }
    },
    [error],
  );

  useEffect(() => {
    setOnUnauthorized(() => {
      setNeedsAuth(true);
    });
    fetchStatus(false);
    const timer = window.setInterval(() => {
      fetchStatus(true);
    }, 15000);
    return () => window.clearInterval(timer);
  }, [fetchStatus]);

  const handleOpenLogsForService = useCallback(
    (service: string) => {
      setLogService(service);
      navigate('logs', service);
    },
    [navigate],
  );

  const handleChangeTab = useCallback(
    (tab: TabKey) => {
      navigate(tab);
    },
    [navigate],
  );

  const handleChangeSecuritySub = useCallback(
    (nextSub: string) => {
      navigate('security', nextSub);
    },
    [navigate],
  );

  const copyPassword = useCallback(
    async (pwd: string) => {
      if (!pwd) return;
      try {
        await navigator.clipboard.writeText(pwd);
        success('初始密码已复制到剪贴板');
      } catch {
        error('复制失败，请手动选中复制');
      }
    },
    [success, error],
  );

  const handleAckPassword = useCallback(async () => {
    setAckingPassword(true);
    try {
      await api.ackInitialPassword();
      success('已确认保存初始管理密码');
      await fetchStatus(false);
    } catch (err: unknown) {
      error(err instanceof Error ? err.message : '确认失败');
    } finally {
      setAckingPassword(false);
    }
  }, [fetchStatus, success, error]);

  const handleLogout = useCallback(async () => {
    try {
      await api.logout();
      setNeedsAuth(true);
      success('已安全退出登录');
    } catch (err: unknown) {
      error(err instanceof Error ? err.message : '退出失败');
    }
  }, [success, error]);

  const navGroups: NavGroupConfig<TabKey>[] = useMemo(() => {
    const coreHealthy = Boolean(status?.services?.singbox?.running && status?.services?.caddy?.running);
    return [
      {
        title: '监控诊断',
        items: [
          {
            key: 'overview',
            label: '节点概览',
            shortLabel: '概览',
            desc: '系统资源、核心服务、TLS 证书与最近审计动态',
            icon: Activity,
          },
          {
            key: 'diagnostics',
            label: '诊断解锁',
            shortLabel: '诊断',
            desc: '流媒体解锁测试、系统自检与回程质量检测',
            icon: Stethoscope,
          },
          {
            key: 'logs',
            label: '服务日志',
            shortLabel: '日志',
            desc: '实时检索 sing-box、Caddy 与 SubHub systemd 日志',
            icon: FileText,
          },
        ],
      },
      {
        title: '代理与订阅',
        items: [
          {
            key: 'services',
            label: '核心服务',
            shortLabel: '服务',
            desc: '服务启停、在线升级、配置文件编辑与实时遥测',
            icon: Server,
            badge: status ? <StatusDot tone={coreHealthy ? 'ok' : 'warn'} pulse={coreHealthy} /> : undefined,
          },
          {
            key: 'warp',
            label: 'WARP 分流',
            shortLabel: 'WARP',
            desc: 'OpenAI / 流媒体 / 自定义域名一键切换 DC 与 WARP 出口',
            icon: Globe2,
            badge: status ? (
              <StatusDot tone={status.services.warp.running ? 'ok' : 'neutral'} pulse={status.services.warp.running} />
            ) : undefined,
          },
          {
            key: 'subscriptions',
            label: '订阅工厂',
            shortLabel: '订阅',
            desc: '多订阅源融合、节点实时预览、UA 审计与秘钥轮换',
            icon: Rss,
          },
        ],
      },
      {
        title: '集群管理',
        items: [
          {
            key: 'fleet',
            label: '节点集群',
            shortLabel: '集群',
            desc: '主控/节点多机统一巡检、安装同步与证书管理',
            icon: Network,
          },
        ],
      },
      {
        title: '安全与伪装',
        items: [
          {
            key: 'security',
            label: '安全中心',
            shortLabel: '安全',
            desc: '扫描嗅探拦截、隐身入口、无人值守自愈与加密备份',
            icon: ShieldCheck,
          },
          {
            key: 'camouflage',
            label: '伪装隐身',
            shortLabel: '伪装',
            desc: 'REALITY 握手回落与伪装站防探测渗透体检',
            icon: EyeOff,
          },
        ],
      },
    ];
  }, [status]);

  const extraCommands: CommandItem[] = useMemo(
    () => [
      {
        id: 'srv-refresh',
        label: '刷新服务端全景状态',
        hint: 'status',
        group: '快捷操作',
        icon: <RefreshCw className="w-3.5 h-3.5" />,
        keywords: 'refresh reload status',
        onSelect: () => fetchStatus(false),
      },
      {
        id: 'srv-log-sb',
        label: '查看 sing-box 服务端日志',
        hint: 'logs',
        group: '快捷操作',
        icon: <FileText className="w-3.5 h-3.5" />,
        keywords: 'singbox logs journalctl',
        onSelect: () => handleOpenLogsForService('singbox'),
      },
      {
        id: 'srv-log-caddy',
        label: '查看 Caddy 服务端日志',
        hint: 'logs',
        group: '快捷操作',
        icon: <FileText className="w-3.5 h-3.5" />,
        keywords: 'caddy tls logs',
        onSelect: () => handleOpenLogsForService('caddy'),
      },
    ],
    [fetchStatus, handleOpenLogsForService],
  );

  const statusPill = status ? (
    <div className="inline-flex items-center gap-2 px-2.5 py-1 rounded-full bg-surface2 border border-subtle text-xs">
      <StatusDot
        tone={status.services.singbox.running && status.services.caddy.running ? 'ok' : 'warn'}
        pulse={status.services.singbox.running && status.services.caddy.running}
      />
      <span className="font-medium text-primary hidden sm:inline">
        {status.services.singbox.running ? '节点在线' : '核心离线'}
      </span>
      {status.config.nodeDomain && (
        <span className="font-mono text-[11px] text-muted hidden md:inline">{status.config.nodeDomain}</span>
      )}
    </div>
  ) : null;

  const topbarActions = (
    <div className="flex items-center gap-1.5">
      <Button
        size="sm"
        variant="ghost"
        title="刷新节点状态"
        onClick={() => fetchStatus(false)}
        icon={<RefreshCw className={`w-3.5 h-3.5 ${refreshing ? 'animate-spin' : ''}`} />}
      />
      {status?.authEnabled && !needsAuth && (
        <Button
          size="sm"
          variant="ghost"
          title={`退出登录 (${status.admin.username})`}
          onClick={handleLogout}
          icon={<LogOut className="w-3.5 h-3.5" />}
        />
      )}
    </div>
  );

  const banner = status?.initialCredentials?.pending ? (
    <div className="rounded-2xl border border-amber-500/35 bg-amber-500/10 p-4 flex flex-col lg:flex-row lg:items-center lg:justify-between gap-3">
      <div className="flex items-start gap-2.5">
        <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
        <div>
          <h2 className="text-xs sm:text-sm font-semibold text-primary">请先保存安装时生成的管理密码</h2>
          <p className="text-xs text-secondary mt-0.5">
            确认之后，面板不再显示这组明文。账号：
            <span className="font-mono font-semibold text-primary ml-1">
              {status.initialCredentials.username}
            </span>{' '}
            · 密码：
            <span className="font-mono font-semibold text-primary ml-1">
              {status.initialCredentials.password}
            </span>
          </p>
        </div>
      </div>
      <div className="flex flex-wrap gap-2 shrink-0">
        <Button
          size="sm"
          variant="secondary"
          icon={<Copy className="w-3.5 h-3.5" />}
          onClick={() => copyPassword(status.initialCredentials?.password || '')}
        >
          复制密码
        </Button>
        <Button
          size="sm"
          variant="primary"
          loading={ackingPassword}
          icon={<Check className="w-3.5 h-3.5" />}
          onClick={handleAckPassword}
        >
          我已保存
        </Button>
      </div>
    </div>
  ) : null;

  return (
    <>
      <LoginModal
        isOpen={needsAuth}
        onSuccess={() => {
          setNeedsAuth(false);
          fetchStatus(false);
        }}
      />

      <AppShell
        brandTitle="SingCtl"
        brandSubtitle="服务端控制台"
        version={status?.version}
        groups={navGroups}
        activeTab={currentTab}
        onSelectTab={handleChangeTab}
        mobilePrimaryKeys={MOBILE_PRIMARY_TABS}
        statusPill={statusPill}
        topbarActions={topbarActions}
        banner={banner}
        theme={theme}
        onToggleTheme={toggleTheme}
        extraCommandItems={extraCommands}
      >
        {loading && !status ? (
          <div className="py-16 text-center text-xs text-muted">正在加载节点状态…</div>
        ) : (
          <>
            {currentTab === 'overview' && (
              <OverviewTab
                status={status}
                onRefresh={() => fetchStatus(false)}
                onNavigate={handleChangeTab}
              />
            )}
            {currentTab === 'services' && (
              <ServicesTab
                status={status}
                onRefresh={() => fetchStatus(false)}
                onOpenLogs={handleOpenLogsForService}
                onNavigate={handleChangeTab}
              />
            )}
            {currentTab === 'warp' && <WarpTab onRefreshParent={() => fetchStatus(false)} />}
            {currentTab === 'subscriptions' && <SubscriptionsTab />}
            {currentTab === 'fleet' && <FleetTab />}
            {currentTab === 'logs' && <LogsTab initialService={logService} />}
            {currentTab === 'diagnostics' && (
              <DiagnosticsTab status={status} onNavigate={handleChangeTab} />
            )}
            {currentTab === 'camouflage' && <CamouflageTab status={status} />}
            {currentTab === 'security' && (
              <SecurityTab
                status={status}
                onRefresh={() => fetchStatus(false)}
                sub={currentTab === 'security' ? sub : undefined}
                onChangeSub={handleChangeSecuritySub}
              />
            )}
          </>
        )}
      </AppShell>
    </>
  );
};

export const App: React.FC = () => (
  <ToastProvider>
    <DashboardContent />
  </ToastProvider>
);

export default App;

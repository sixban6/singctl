import React, { useState, useEffect, useCallback, useMemo } from 'react';
import {
  Flame,
  ShieldCheck,
  ShieldAlert,
  RefreshCw,
  CheckCircle2,
  AlertTriangle,
  Lock,
  Unlock,
  Plus,
  Trash2,
  Search,
  Copy,
  Check,
  Terminal,
  FileCode2,
  RotateCcw,
  Ban,
} from 'lucide-react';
import {
  Badge,
  Button,
  ConfirmDialog,
  DataColumn,
  DataTable,
  PageHeader,
  SectionCard,
  SegmentedTabs,
  SlideDrawer,
  formatBytes,
  useToast,
} from '../../ui';
import { clientApi } from '../api';
import { copyPlainText } from '../lib/leakProbes';
import { maskFullIP } from '../lib/privacyMask';
import {
  ClientStatusResponse,
  FirewallBanItem,
  FirewallLogEvent,
  FirewallOverviewResponse,
} from '../types';

export interface FirewallPanelProps {
  status: ClientStatusResponse | null;
  busy: boolean;
  privacyMask?: boolean;
  onRefreshStatus?: () => void;
}

type BanScopeFilter = 'all' | 'dynamic_v4' | 'dynamic_v6' | 'forever';
type RuleTabKey = 'bans' | 'whitelist' | 'ports';

function fmtNum(n?: number): string {
  return Number(n || 0).toLocaleString('en-US');
}

function formatRemainingTTL(sec?: number): string {
  const s = Number(sec || 0);
  if (s <= 0) return '永久';
  const days = Math.floor(s / 86400);
  const hours = Math.floor((s % 86400) / 3600);
  const mins = Math.floor((s % 3600) / 60);
  if (days > 0) return `${days}天${hours}小时`;
  if (hours > 0) return `${hours}小时${mins}分`;
  return `${Math.max(1, mins)}分钟`;
}

function maskDisplayIP(raw: string, privacyMask: boolean): string {
  if (!privacyMask || !raw) return raw;
  return maskFullIP(raw);
}

const DEFAULT_FALLBACK_PORTS = [20, 21, 22, 23, 25, 110, 465, 587, 993, 995, 1433, 1434, 1521, 3306, 3389, 6379];

export const FirewallPanel: React.FC<FirewallPanelProps> = ({
  status,
  busy,
  privacyMask = false,
  onRefreshStatus,
}) => {
  const { toast, success, error } = useToast();

  // Overview state + server pagination query
  const [overview, setOverview] = useState<FirewallOverviewResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [acting, setActing] = useState(false);

  const [scopeFilter, setScopeFilter] = useState<BanScopeFilter>('all');
  const [searchInput, setSearchInput] = useState('');
  const [searchApplied, setSearchApplied] = useState('');
  const [sortBy, setSortBy] = useState<'expires' | 'target' | 'scope'>('expires');
  const [page, setPage] = useState(1);

  const [activeTab, setActiveTab] = useState<RuleTabKey>('bans');

  // Layer 2 editable config controls
  const [modeInput, setModeInput] = useState<'standard' | 'minimal'>('standard');
  const [timeoutDaysInput, setTimeoutDaysInput] = useState<number>(7);
  const [pingLimitInput, setPingLimitInput] = useState<number>(10);
  const [selectedPorts, setSelectedPorts] = useState<number[]>(DEFAULT_FALLBACK_PORTS);
  const [customPortInput, setCustomPortInput] = useState('');
  const [configDirty, setConfigDirty] = useState(false);

  // Layer 3 inline forms & confirm modals
  const [addBanOpen, setAddBanOpen] = useState(false);
  const [banTargetInput, setBanTargetInput] = useState('');
  const [banScopeInput, setBanScopeInput] = useState<'dynamic' | 'forever'>('dynamic');
  const [clearDynConfirmOpen, setClearDynConfirmOpen] = useState(false);
  const [disableConfirmOpen, setDisableConfirmOpen] = useState(false);
  const [whitelistInput, setWhitelistInput] = useState('');

  // Layer 4 drawers
  const [logsDrawerOpen, setLogsDrawerOpen] = useState(false);
  const [logs, setLogs] = useState<FirewallLogEvent[]>([]);
  const [logsLoading, setLogsLoading] = useState(false);

  const [rulesDrawerOpen, setRulesDrawerOpen] = useState(false);
  const [copiedRules, setCopiedRules] = useState(false);

  const syncConfigInputs = useCallback((ov: FirewallOverviewResponse) => {
    if (!ov?.config) return;
    setModeInput(ov.config.mode === 'minimal' ? 'minimal' : 'standard');
    setTimeoutDaysInput(ov.config.banTimeoutDays || 7);
    setPingLimitInput(ov.config.pingLimitPerSec || 10);
    setSelectedPorts(
      ov.config.protectedPorts && ov.config.protectedPorts.length > 0
        ? [...ov.config.protectedPorts]
        : [...DEFAULT_FALLBACK_PORTS],
    );
    setConfigDirty(false);
  }, []);

  const loadOverview = useCallback(
    async (opts?: { forceSyncConfig?: boolean; targetPage?: number }) => {
      setLoading((prev) => prev || overview === null);
      try {
        const res = await clientApi.getFirewallOverview({
          scope: scopeFilter,
          search: searchApplied,
          sort: sortBy,
          page: opts?.targetPage ?? page,
          pageSize: 25,
        });
        setOverview(res);
        if (opts?.forceSyncConfig || !configDirty) {
          syncConfigInputs(res);
        }
      } catch (e) {
        error((e as Error).message || '读取防火墙状态失败');
      } finally {
        setLoading(false);
      }
    },
    [scopeFilter, searchApplied, sortBy, page, configDirty, syncConfigInputs, error, overview],
  );

  useEffect(() => {
    void loadOverview();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [scopeFilter, searchApplied, sortBy, page]);

  // Debounce search input -> server query
  useEffect(() => {
    const timer = window.setTimeout(() => {
      const next = searchInput.trim();
      if (next !== searchApplied) {
        setPage(1);
        setSearchApplied(next);
      }
    }, 280);
    return () => window.clearTimeout(timer);
  }, [searchInput, searchApplied]);

  const loadLogs = useCallback(async () => {
    setLogsLoading(true);
    try {
      const res = await clientApi.getFirewallLogs(50);
      setLogs(res.events || []);
    } catch (e) {
      error((e as Error).message || '读取防火墙日志失败');
    } finally {
      setLogsLoading(false);
    }
  }, [error]);

  const openLogsDrawer = () => {
    setLogsDrawerOpen(true);
    void loadLogs();
  };

  const st = overview?.status ?? status?.firewall;
  const stats = overview?.stats;
  const preflight = overview?.preflight;
  const supported = Boolean(st?.supported);
  const kernelActive = Boolean(st?.kernelActive);
  const autostartEnabled = Boolean(st?.autostartEnabled);
  const drifted = Boolean(st?.drifted);

  const trapPackets =
    (stats?.honeypotTcpV4?.packets || 0) +
    (stats?.honeypotUdpV4?.packets || 0) +
    (stats?.honeypotTcpV6?.packets || 0) +
    (stats?.honeypotUdpV6?.packets || 0);
  const dynamicPackets = (stats?.dynamicV4Blocked?.packets || 0) + (stats?.dynamicV6Blocked?.packets || 0);
  const totalDynamicCount = (stats?.dynamicV4Count || 0) + (stats?.dynamicV6Count || 0);

  const applyConfigAndReload = async (overrideMode?: 'standard' | 'minimal') => {
    setActing(true);
    try {
      const res = await clientApi.applyFirewall({
        mode: overrideMode ?? modeInput,
        banTimeoutDays: timeoutDaysInput,
        pingLimitPerSec: pingLimitInput,
        protectedPorts: selectedPorts,
      });
      success(res.message || '防火墙规则已生效');
      if (res.overview) {
        setOverview(res.overview);
        syncConfigInputs(res.overview);
      } else {
        await loadOverview({ forceSyncConfig: true });
      }
      onRefreshStatus?.();
    } catch (e) {
      error((e as Error).message || '应用防火墙规则失败');
    } finally {
      setActing(false);
    }
  };

  const handleDisable = async () => {
    setActing(true);
    try {
      const res = await clientApi.disableFirewall();
      setDisableConfirmOpen(false);
      success(res.message || '已禁用防火墙加固');
      if (res.overview) {
        setOverview(res.overview);
        syncConfigInputs(res.overview);
      } else {
        await loadOverview({ forceSyncConfig: true });
      }
      onRefreshStatus?.();
    } catch (e) {
      error((e as Error).message || '停用防火墙失败');
    } finally {
      setActing(false);
    }
  };

  const handleManualBan = async () => {
    const t = banTargetInput.trim();
    if (!t) {
      toast('请输入要封禁的公网 IP 或 CIDR 网段', 'info');
      return;
    }
    setActing(true);
    try {
      const res = await clientApi.banFirewallTarget({
        target: t,
        scope: banScopeInput,
        timeoutDays: timeoutDaysInput,
      });
      success(res.message || `已封禁 ${res.target}`);
      setBanTargetInput('');
      setAddBanOpen(false);
      setPage(1);
      await loadOverview({ targetPage: 1 });
    } catch (e) {
      error((e as Error).message || '封禁失败');
    } finally {
      setActing(false);
    }
  };

  const handleUnban = async (item: FirewallBanItem) => {
    setActing(true);
    try {
      const res = await clientApi.unbanFirewallTarget({
        target: item.target,
        scope: item.scope,
      });
      success(res.message || `已解封 ${item.target}`);
      await loadOverview();
    } catch (e) {
      error((e as Error).message || '解封失败');
    } finally {
      setActing(false);
    }
  };

  const handleClearDynamic = async () => {
    setActing(true);
    try {
      const res = await clientApi.clearDynamicFirewallBans('all');
      setClearDynConfirmOpen(false);
      success(res.message || '已清空动态黑名单');
      setPage(1);
      await loadOverview({ targetPage: 1 });
    } catch (e) {
      error((e as Error).message || '清空失败');
    } finally {
      setActing(false);
    }
  };

  const handleWhitelistAction = async (action: 'add' | 'remove', targetRaw?: string) => {
    const t = (targetRaw ?? whitelistInput).trim();
    if (!t) {
      toast('请输入白名单 IP 或 CIDR 网段', 'info');
      return;
    }
    setActing(true);
    try {
      const res = await clientApi.manageFirewallWhitelist(action, t);
      success(res.message || '白名单已更新');
      if (action === 'add' && !targetRaw) setWhitelistInput('');
      if (res.overview) {
        setOverview(res.overview);
      } else {
        await loadOverview();
      }
    } catch (e) {
      error((e as Error).message || '白名单更新失败');
    } finally {
      setActing(false);
    }
  };

  const togglePort = (port: number) => {
    if (preflight?.detectedSSHPorts?.includes(port) || preflight?.exemptServicePorts?.includes(port)) {
      return;
    }
    setConfigDirty(true);
    setSelectedPorts((prev) =>
      prev.includes(port) ? prev.filter((p) => p !== port) : [...prev, port].sort((a, b) => a - b),
    );
  };

  const handleAddCustomPort = () => {
    const p = Number(customPortInput.trim());
    if (!Number.isInteger(p) || p < 1 || p > 65535) {
      toast('请输入合法端口号 (1~65535)', 'info');
      return;
    }
    if (preflight?.detectedSSHPorts?.includes(p)) {
      error(`安全拦截: 端口 ${p} 是当前 SSH 管理端口，禁止加入诱捕`);
      return;
    }
    if (preflight?.exemptServicePorts?.includes(p)) {
      error(`安全拦截: 端口 ${p} 属于核心服务豁免端口，禁止加入诱捕`);
      return;
    }
    setConfigDirty(true);
    setSelectedPorts((prev) => (prev.includes(p) ? prev : [...prev, p].sort((a, b) => a - b)));
    setCustomPortInput('');
  };

  const portLabelsMap = useMemo(() => {
    const m = new Map<number, string>();
    for (const entry of overview?.portCatalog || []) {
      m.set(entry.port, entry.label);
    }
    return m;
  }, [overview?.portCatalog]);

  const allCatalogPorts = useMemo(() => {
    const s = new Set<number>();
    for (const entry of overview?.portCatalog || []) s.add(entry.port);
    for (const p of selectedPorts) s.add(p);
    for (const p of preflight?.detectedSSHPorts || []) s.add(p);
    return Array.from(s).sort((a, b) => a - b);
  }, [overview?.portCatalog, selectedPorts, preflight?.detectedSSHPorts]);

  const totalPages = useMemo(() => {
    const total = overview?.bans?.total || 0;
    const size = overview?.bans?.pageSize || 25;
    return Math.max(1, Math.ceil(total / size));
  }, [overview?.bans]);

  const banColumns: DataColumn<FirewallBanItem>[] = [
    {
      key: 'target',
      header: '封禁 IP / 网段',
      render: (item) => (
        <div className="flex items-center gap-2">
          <span className="font-mono text-xs font-semibold text-primary">
            {maskDisplayIP(item.target, privacyMask)}
          </span>
          {item.builtin && <Badge tone="neutral">内置威胁库</Badge>}
        </div>
      ),
    },
    {
      key: 'scope',
      header: '拦截集合',
      render: (item) =>
        item.scope === 'forever' ? (
          <Badge tone="danger">永久威胁段</Badge>
        ) : item.scope === 'dynamic_v6' ? (
          <Badge tone="warn">动态 IPv6</Badge>
        ) : (
          <Badge tone="accent">动态 IPv4</Badge>
        ),
    },
    {
      key: 'expires',
      header: '剩余解封时间',
      align: 'right',
      render: (item) => (
        <span className="font-mono tnum text-xs text-secondary whitespace-nowrap">
          {item.scope === 'forever' ? '永久有效' : formatRemainingTTL(item.expiresSec)}
        </span>
      ),
    },
    {
      key: 'actions',
      header: '操作',
      align: 'right',
      render: (item) =>
        item.builtin ? (
          <span className="text-[11px] text-muted">系统威胁库</span>
        ) : (
          <Button
            size="xs"
            variant="ghost"
            disabled={acting || busy}
            icon={<Unlock className="w-3 h-3" />}
            onClick={() => void handleUnban(item)}
          >
            解封
          </Button>
        ),
    },
  ];

  const isDisabledAll = acting || busy || !supported;

  const statusBadge = !supported ? (
    <Badge tone="warn">当前系统不支持</Badge>
  ) : drifted ? (
    <Badge tone="warn" dot>
      规则异常 ({kernelActive ? '未设自启' : '内核未加载'})
    </Badge>
  ) : kernelActive ? (
    <Badge tone="ok" dot>
      运行中 · {overview?.status?.mode === 'minimal' ? '极简黑名单' : '标准护盾'}
    </Badge>
  ) : (
    <Badge tone="neutral">未启用</Badge>
  );

  const callerAlreadyWhitelisted = useMemo(() => {
    const cip = preflight?.callerIp;
    if (!cip) return true;
    const allCustom = overview?.whitelist?.custom || [];
    const liveExtra = overview?.whitelist?.liveExtra || [];
    // If local RFC1918 or Tailscale CGNAT, already covered by builtin rules
    if (/^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|100\.(6[4-9]|[7-9]\d|1\d\d)|127\.|::1$|fc|fd|fe80:)/i.test(cip)) {
      return true;
    }
    return allCustom.includes(cip) || liveExtra.includes(cip);
  }, [preflight?.callerIp, overview?.whitelist]);

  return (
    <div className="space-y-5">
      <PageHeader
        title="防火墙加固"
        description="基于内核 nftables inet security 表的公网入口防扫描、高危端口诱捕与防自锁管理"
        badge={statusBadge}
        actions={
          <div className="flex flex-wrap items-center gap-2">
            <Button
              size="sm"
              variant="secondary"
              disabled={loading}
              icon={<RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />}
              onClick={() => void loadOverview()}
            >
              刷新
            </Button>
            {supported && (
              <>
                <Button
                  size="sm"
                  variant="secondary"
                  icon={<Terminal className="w-3.5 h-3.5" />}
                  onClick={openLogsDrawer}
                >
                  拦截日志
                </Button>
                {kernelActive && (
                  <Button
                    size="sm"
                    variant="secondary"
                    icon={<FileCode2 className="w-3.5 h-3.5" />}
                    onClick={() => setRulesDrawerOpen(true)}
                  >
                    规则透视
                  </Button>
                )}
              </>
            )}
          </div>
        }
      />

      {/* Drift warning banner */}
      {drifted && (
        <div className="rounded-2xl border border-amber-500/35 bg-amber-500/10 p-4 flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-start gap-3 text-xs leading-relaxed text-secondary">
            <AlertTriangle className="w-5 h-5 text-amber-400 shrink-0 mt-0.5" />
            <div>
              <strong className="text-primary">
                {kernelActive ? '检测到内核规则存活但缺少开机自启：' : '检测到自启脚本存在但内核安全表未加载：'}
              </strong>
              {kernelActive
                ? '路由器重启后防火墙加固可能不会自动恢复，建议点击右侧重新下发以注册自启。'
                : '当前网关处于无公网防火墙保护状态，可能因开机早期内核模块未就绪或规则被冲刷导致。'}
            </div>
          </div>
          <Button
            size="sm"
            variant="primary"
            disabled={isDisabledAll}
            onClick={() => void applyConfigAndReload()}
          >
            {kernelActive ? '补齐自启保护' : '一键恢复内核表'}
          </Button>
        </div>
      )}

      {/* Layer 1: 4-Card Live Stats Strip */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
        <div className="rounded-2xl border border-subtle bg-surface1 p-4 space-y-1">
          <div className="text-[11px] text-muted flex items-center justify-between">
            <span>累计拦截攻击包</span>
            <ShieldAlert className="w-3.5 h-3.5 text-rose-400" />
          </div>
          <div className="text-xl font-bold font-mono tnum text-primary">
            {kernelActive ? `${fmtNum(stats?.totalBlockedPackets)} 次` : '未加载'}
          </div>
          <div className="text-[11px] text-muted truncate">
            {kernelActive
              ? `${formatBytes(stats?.totalBlockedBytes || 0)} · 永久 ${fmtNum(stats?.foreverBlocked?.packets)} / 动态 ${fmtNum(dynamicPackets)} / 诱捕 ${fmtNum(trapPackets)}`
              : '启用后将实时统计全网公网扫描拦截战果'}
          </div>
        </div>

        <button
          type="button"
          onClick={() => {
            setActiveTab('bans');
            setScopeFilter('dynamic_v4');
            setPage(1);
          }}
          className="text-left rounded-2xl border border-subtle bg-surface1 hover:border-accent/40 transition-colors p-4 space-y-1 cursor-pointer"
        >
          <div className="text-[11px] text-muted flex items-center justify-between">
            <span>动态关押扫描器</span>
            <Flame className="w-3.5 h-3.5 text-amber-400" />
          </div>
          <div className="text-xl font-bold font-mono tnum text-primary">
            {kernelActive ? `${stats?.dynamicV4Count || 0} / ${stats?.dynamicV6Count || 0}` : '0 / 0'}
          </div>
          <div className="text-[11px] text-muted truncate">
            IPv4 / IPv6 活跃封禁 · 命中诱捕自动关 {overview?.config?.banTimeoutDays || 7} 天
          </div>
        </button>

        <button
          type="button"
          onClick={() => {
            setActiveTab('bans');
            setScopeFilter('forever');
            setPage(1);
          }}
          className="text-left rounded-2xl border border-subtle bg-surface1 hover:border-accent/40 transition-colors p-4 space-y-1 cursor-pointer"
        >
          <div className="text-[11px] text-muted flex items-center justify-between">
            <span>永久威胁黑段</span>
            <Ban className="w-3.5 h-3.5 text-rose-400" />
          </div>
          <div className="text-xl font-bold font-mono tnum text-primary">
            {kernelActive ? `${stats?.foreverCount || 0} 条` : '19 条预设'}
          </div>
          <div className="text-[11px] text-muted truncate">
            内置恶意扫描段 + 自定义永久封禁网段
          </div>
        </button>

        <button
          type="button"
          onClick={() => setActiveTab('whitelist')}
          className="text-left rounded-2xl border border-subtle bg-surface1 hover:border-accent/40 transition-colors p-4 space-y-1 cursor-pointer"
        >
          <div className="text-[11px] text-muted flex items-center justify-between">
            <span>防自锁免检护栏</span>
            <Lock className="w-3.5 h-3.5 text-emerald-400" />
          </div>
          <div className="text-xl font-bold font-mono tnum text-primary truncate">
            SSH {preflight?.detectedSSHPorts?.length ? `:${preflight.detectedSSHPorts.join(',')}` : '已保护'}
          </div>
          <div className="text-[11px] text-muted truncate">
            自动放行私网 · Tailscale · 白名单 {kernelActive ? stats?.whitelistCount || 4 : 4} 项
          </div>
        </button>
      </div>

      {/* Layer 2: Preflight Safety Checklist & Dual-Mode Control */}
      <SectionCard
        title="安全策略与防自锁预检"
        subtitle="每次启用或热重载均自动迁移保留现有 7 天动态黑名单与自定义白名单"
        icon={<ShieldCheck className="w-4 h-4 text-emerald-400" />}
        collapsible={kernelActive}
        defaultOpen={!kernelActive || drifted}
      >
        <div className="space-y-4">
          {/* Anti-lockout preflight checks */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-2.5 text-xs">
            <div className="flex items-start gap-2 rounded-xl border border-emerald-500/20 bg-emerald-500/5 px-3 py-2.5">
              <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
              <div className="text-secondary leading-relaxed">
                <span className="font-semibold text-primary">SSH 端口自动豁免：</span>
                已探测活跃 SSH 端口{' '}
                <code className="font-mono text-emerald-300">
                  {preflight?.detectedSSHPorts?.join(', ') || '22'}
                </code>
                ，不会纳入高危诱捕池。
              </div>
            </div>
            <div className="flex items-start gap-2 rounded-xl border border-emerald-500/20 bg-emerald-500/5 px-3 py-2.5">
              <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
              <div className="text-secondary leading-relaxed">
                <span className="font-semibold text-primary">内网与隧道全放行：</span>
                自动放行 <code className="font-mono">lo</code> / <code className="font-mono">tailscale0</code> /{' '}
                <code className="font-mono">100.64.0.0/10</code> 及 RFC1918 私网
                {preflight?.callerIp ? `（当前来源 ${maskDisplayIP(preflight.callerIp, privacyMask)}）` : ''}。
              </div>
            </div>
          </div>

          {/* Dual mode selector */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {[
              {
                key: 'standard' as const,
                title: '🛡️ 标准公网护盾（推荐）',
                desc: '永久威胁段拦截 + 高危管理端口诱捕（命中自动关 7 天）+ Ping 限频 + 白名单放行。',
              },
              {
                key: 'minimal' as const,
                title: '🧱 极简黑名单模式',
                desc: '零端口诱捕，仅保留恶意网段 / 手动黑名单拦截与白名单放行，适合公网暴露非常规多端口场景。',
              },
            ].map((item) => {
              const selected = modeInput === item.key;
              return (
                <button
                  key={item.key}
                  type="button"
                  onClick={() => {
                    setModeInput(item.key);
                    setConfigDirty(true);
                  }}
                  className={`text-left rounded-xl border p-3.5 transition-all cursor-pointer ${
                    selected
                      ? 'border-accent bg-accent/10 shadow-sm'
                      : 'border-subtle bg-surface2/50 hover:border-strong'
                  }`}
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-xs font-semibold text-primary">{item.title}</span>
                    {selected && <Badge tone="accent">已选模式</Badge>}
                  </div>
                  <p className="mt-1.5 text-[11px] text-secondary leading-relaxed">{item.desc}</p>
                </button>
              );
            })}
          </div>

          {/* Primary actions */}
          <div className="flex flex-wrap items-center justify-between gap-3 pt-1">
            <div className="flex flex-wrap items-center gap-2.5">
              <Button
                variant="primary"
                disabled={isDisabledAll}
                loading={acting}
                onClick={() => void applyConfigAndReload()}
              >
                {kernelActive ? '热重载并保留现有黑名单' : '启用防火墙加固'}
              </Button>
              {(kernelActive || autostartEnabled) && (
                <Button
                  variant="danger"
                  disabled={isDisabledAll}
                  onClick={() => setDisableConfirmOpen(true)}
                >
                  禁用并移除规则
                </Button>
              )}
            </div>
            {!supported && (
              <span className="text-xs text-muted">提示：nftables 护盾仅适用于 Linux / OpenWrt 网关。</span>
            )}
          </div>
        </div>
      </SectionCard>

      {/* Layer 3: 3-Tab Rule Governance */}
      <SectionCard
        title="规则与名单治理"
        subtitle="支持动态黑名单检索解封、自定义信任白名单与高危诱捕端口精细配置"
        icon={<Flame className="w-4 h-4" />}
        actions={
          <SegmentedTabs
            value={activeTab}
            onChange={(k) => setActiveTab(k as RuleTabKey)}
            items={[
              {
                key: 'bans',
                label: '封禁名单',
                badge: <Badge tone="neutral">{totalDynamicCount + (stats?.foreverCount || 0)}</Badge>,
              },
              {
                key: 'whitelist',
                label: '信任白名单',
                badge: <Badge tone="neutral">{overview?.whitelist?.custom?.length || 0}</Badge>,
              },
              {
                key: 'ports',
                label: '诱捕端口与参数',
                badge: (
                  <Badge tone={modeInput === 'minimal' ? 'warn' : 'neutral'}>
                    {modeInput === 'minimal' ? '极简' : selectedPorts.length}
                  </Badge>
                ),
              },
            ]}
          />
        }
      >
        {activeTab === 'bans' && (
          <div className="space-y-4">
            {/* Filter bar */}
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div className="flex flex-wrap items-center gap-1.5">
                {[
                  { key: 'all' as BanScopeFilter, label: '全部' },
                  { key: 'dynamic_v4' as BanScopeFilter, label: `7天动态 IPv4 (${stats?.dynamicV4Count || 0})` },
                  { key: 'dynamic_v6' as BanScopeFilter, label: `7天动态 IPv6 (${stats?.dynamicV6Count || 0})` },
                  { key: 'forever' as BanScopeFilter, label: `永久威胁段 (${stats?.foreverCount || 0})` },
                ].map((pill) => {
                  const active = scopeFilter === pill.key;
                  return (
                    <button
                      key={pill.key}
                      type="button"
                      onClick={() => {
                        setScopeFilter(pill.key);
                        setPage(1);
                      }}
                      className={`px-2.5 py-1 rounded-lg text-xs border transition-colors cursor-pointer ${
                        active
                          ? 'bg-accent/15 border-accent/40 text-accent font-semibold'
                          : 'bg-surface2/60 border-subtle text-secondary hover:text-primary'
                      }`}
                    >
                      {pill.label}
                    </button>
                  );
                })}
              </div>

              <div className="flex flex-wrap items-center gap-2">
                <Button
                  size="xs"
                  variant="secondary"
                  disabled={!supported}
                  icon={<Plus className="w-3.5 h-3.5" />}
                  onClick={() => setAddBanOpen((v) => !v)}
                >
                  手动封禁 IP/CIDR
                </Button>
                {totalDynamicCount > 0 && (
                  <Button
                    size="xs"
                    variant="secondary"
                    className="border-rose-500/35 text-rose-300 hover:bg-rose-500/15"
                    disabled={isDisabledAll}
                    icon={<Trash2 className="w-3.5 h-3.5" />}
                    onClick={() => setClearDynConfirmOpen(true)}
                  >
                    清空动态黑名单
                  </Button>
                )}
              </div>
            </div>

            {/* Search & Sort row */}
            <div className="flex flex-wrap items-center gap-2.5">
              <div className="relative flex-1 min-w-[200px]">
                <Search className="w-3.5 h-3.5 text-muted absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none" />
                <input
                  type="text"
                  value={searchInput}
                  onChange={(e) => setSearchInput(e.target.value)}
                  placeholder="搜索 IP 或网段前缀（如 167.94 或 2604:）…"
                  className="w-full rounded-xl border border-subtle bg-surface2 pl-8 pr-3 py-1.5 text-xs text-primary placeholder:text-muted focus:border-accent focus:outline-none font-mono"
                />
              </div>
              <select
                value={sortBy}
                onChange={(e) => {
                  setSortBy(e.target.value as 'expires' | 'target' | 'scope');
                  setPage(1);
                }}
                className="rounded-xl border border-subtle bg-surface2 px-3 py-1.5 text-xs text-secondary focus:border-accent focus:outline-none"
              >
                <option value="expires">最近触发优先 (TTL 最长)</option>
                <option value="target">按 IP / 网段排序</option>
                <option value="scope">按拦截集合分组</option>
              </select>
            </div>

            {/* Inline manual ban form */}
            {addBanOpen && (
              <div className="rounded-xl border border-accent/35 bg-surface2/80 p-3.5 flex flex-wrap items-end gap-2.5">
                <div className="flex-1 min-w-[200px]">
                  <label className="block text-[11px] text-muted mb-1">待封禁公网 IP 或 CIDR 网段（严禁私网/当前访问 IP）</label>
                  <input
                    type="text"
                    value={banTargetInput}
                    onChange={(e) => setBanTargetInput(e.target.value)}
                    placeholder="如 198.51.100.42 或 203.0.113.0/24"
                    className="w-full rounded-lg border border-subtle bg-surface1 px-3 py-1.5 text-xs font-mono text-primary focus:border-accent focus:outline-none"
                  />
                </div>
                <div>
                  <label className="block text-[11px] text-muted mb-1">封禁周期</label>
                  <select
                    value={banScopeInput}
                    onChange={(e) => setBanScopeInput(e.target.value as 'dynamic' | 'forever')}
                    className="rounded-lg border border-subtle bg-surface1 px-3 py-1.5 text-xs text-primary focus:border-accent focus:outline-none"
                  >
                    <option value="dynamic">{timeoutDaysInput} 天动态黑名单（单 IP）</option>
                    <option value="forever">永久威胁段（IPv4/CIDR 落盘）</option>
                  </select>
                </div>
                <Button size="sm" variant="danger" disabled={acting} onClick={() => void handleManualBan()}>
                  立即封禁
                </Button>
              </div>
            )}

            <DataTable
              columns={banColumns}
              rows={overview?.bans?.items || []}
              rowKey={(item) => `${item.scope}|${item.target}`}
              loading={loading}
              compact
              emptyText={
                kernelActive
                  ? searchApplied
                    ? '没有匹配的封禁 IP 或网段'
                    : '当前该分类暂无封禁记录'
                  : '防火墙尚未在内核启用（点击上方「启用防火墙加固」即可开启）'
              }
              footerSlot={
                (overview?.bans?.total || 0) > 0 ? (
                  <div className="border-t border-subtle bg-surface2/40 px-4 py-2.5 flex flex-wrap items-center justify-between gap-2 text-xs text-muted">
                    <span>
                      共 {fmtNum(overview?.bans?.total)} 条记录 · 第 {overview?.bans?.page || 1} / {totalPages} 页
                    </span>
                    <div className="flex items-center gap-1.5">
                      <Button
                        size="xs"
                        variant="secondary"
                        disabled={loading || (overview?.bans?.page || 1) <= 1}
                        onClick={() => setPage((p) => Math.max(1, p - 1))}
                      >
                        上一页
                      </Button>
                      <Button
                        size="xs"
                        variant="secondary"
                        disabled={loading || (overview?.bans?.page || 1) >= totalPages}
                        onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
                      >
                        下一页
                      </Button>
                    </div>
                  </div>
                ) : undefined
              }
            />
          </div>
        )}

        {activeTab === 'whitelist' && (
          <div className="space-y-4">
            {/* Builtin anti-lockout ranges */}
            <div className="space-y-2">
              <div className="text-xs font-semibold text-primary flex items-center gap-1.5">
                <Lock className="w-3.5 h-3.5 text-emerald-400" />
                <span>系统内置防锁死网段（只读豁免，任何操作均不会误封）</span>
              </div>
              <div className="flex flex-wrap gap-2">
                {(overview?.whitelist?.builtin || []).map((cidr) => (
                  <span
                    key={cidr}
                    className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg border border-emerald-500/25 bg-emerald-500/10 font-mono text-xs text-emerald-300"
                  >
                    <Lock className="w-3 h-3" />
                    {cidr}
                  </span>
                ))}
              </div>
            </div>

            {/* Custom persisted whitelist */}
            <div className="space-y-2.5 pt-2 border-t border-subtle">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <span className="text-xs font-semibold text-primary">用户自定义信任白名单（持久化至 singctl.yaml）</span>
                {preflight?.callerIp && !callerAlreadyWhitelisted && (
                  <Button
                    size="xs"
                    variant="secondary"
                    disabled={acting}
                    icon={<Plus className="w-3 h-3" />}
                    onClick={() => void handleWhitelistAction('add', preflight.callerIp)}
                  >
                    一键加入当前来源 {maskDisplayIP(preflight.callerIp, privacyMask)}
                  </Button>
                )}
              </div>

              <div className="flex flex-wrap gap-2">
                {(overview?.whitelist?.custom || []).length === 0 ? (
                  <span className="text-xs text-muted">暂无自定义白名单条目。</span>
                ) : (
                  (overview?.whitelist?.custom || []).map((entry) => (
                    <span
                      key={entry}
                      className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg border border-subtle bg-surface2 font-mono text-xs text-primary"
                    >
                      {maskDisplayIP(entry, privacyMask)}
                      <button
                        type="button"
                        disabled={acting}
                        onClick={() => void handleWhitelistAction('remove', entry)}
                        title="移出白名单"
                        className="text-muted hover:text-rose-400 cursor-pointer"
                      >
                        ×
                      </button>
                    </span>
                  ))
                )}
              </div>

              {/* Add form */}
              <div className="flex flex-wrap items-center gap-2 pt-1">
                <input
                  type="text"
                  value={whitelistInput}
                  onChange={(e) => setWhitelistInput(e.target.value)}
                  placeholder="输入信任 IP 或 CIDR 网段（如 198.51.100.10 或 2001:db8::/48）"
                  className="flex-1 min-w-[220px] rounded-xl border border-subtle bg-surface2 px-3 py-1.5 text-xs font-mono text-primary placeholder:text-muted focus:border-accent focus:outline-none"
                />
                <Button
                  size="sm"
                  variant="primary"
                  disabled={acting}
                  icon={<Plus className="w-3.5 h-3.5" />}
                  onClick={() => void handleWhitelistAction('add')}
                >
                  加入白名单
                </Button>
              </div>
            </div>

            {/* Live extra notice if kernel has legacy non-config entries */}
            {(overview?.whitelist?.liveExtra || []).length > 0 && (
              <div className="rounded-xl border border-subtle bg-surface2/50 p-3 space-y-2">
                <div className="text-[11px] text-muted">
                  以下条目当前存在于内核运行态 <code className="font-mono">whitelist_ip</code> 中（非本面板配置写入，可点击「固化」存入配置或移出）：
                </div>
                <div className="flex flex-wrap gap-2">
                  {(overview?.whitelist?.liveExtra || []).map((entry) => (
                    <span
                      key={entry}
                      className="inline-flex items-center gap-2 px-2.5 py-1 rounded-lg border border-amber-500/25 bg-amber-500/10 font-mono text-xs text-amber-200"
                    >
                      <span>{maskDisplayIP(entry, privacyMask)}</span>
                      <button
                        type="button"
                        disabled={acting}
                        onClick={() => void handleWhitelistAction('add', entry)}
                        className="text-[11px] text-emerald-300 hover:underline cursor-pointer"
                      >
                        固化
                      </button>
                      <button
                        type="button"
                        disabled={acting}
                        onClick={() => void handleWhitelistAction('remove', entry)}
                        className="text-[11px] text-rose-300 hover:underline cursor-pointer"
                      >
                        移出
                      </button>
                    </span>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}

        {activeTab === 'ports' && (
          <div className="space-y-4">
            {modeInput === 'minimal' && (
              <div className="rounded-xl border border-amber-500/30 bg-amber-500/10 px-3 py-2 text-xs text-amber-200">
                当前选择了「极简黑名单模式」：下方高危端口诱捕仅暂存配置，需切换回「标准公网护盾」后才会写入内核诱捕。
              </div>
            )}

            {/* Semantic port wall */}
            <div className="space-y-2">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <span className="text-xs font-semibold text-primary">
                  高危管理端口诱捕池（公网主动探测这些端口将被自动关入动态黑名单）
                </span>
                <button
                  type="button"
                  onClick={() => {
                    setSelectedPorts([...DEFAULT_FALLBACK_PORTS]);
                    setConfigDirty(true);
                  }}
                  className="inline-flex items-center gap-1 text-[11px] text-accent hover:underline cursor-pointer"
                >
                  <RotateCcw className="w-3 h-3" />
                  恢复默认端口集
                </button>
              </div>
              <div className="flex flex-wrap gap-2">
                {allCatalogPorts.map((port) => {
                  const isSSH = preflight?.detectedSSHPorts?.includes(port);
                  const isExempt = preflight?.exemptServicePorts?.includes(port);
                  const active = selectedPorts.includes(port) && !isSSH && !isExempt;
                  const label = portLabelsMap.get(port);

                  return (
                    <button
                      key={port}
                      type="button"
                      disabled={Boolean(isSSH || isExempt)}
                      onClick={() => togglePort(port)}
                      title={
                        isSSH
                          ? '本机活跃 SSH 端口，已强制锁定豁免防止锁死'
                          : isExempt
                          ? '核心网关服务端口，禁止诱捕'
                          : '点击切换是否纳入公网诱捕'
                      }
                      className={`inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg border text-xs transition-all ${
                        isSSH
                          ? 'border-emerald-500/40 bg-emerald-500/10 text-emerald-300 cursor-not-allowed'
                          : active
                          ? 'border-accent/50 bg-accent/15 text-primary font-semibold cursor-pointer'
                          : 'border-subtle bg-surface2/50 text-muted hover:text-secondary cursor-pointer'
                      }`}
                    >
                      {isSSH && <Lock className="w-3 h-3 text-emerald-400" />}
                      <span className="font-mono">{port}</span>
                      {label && <span className="text-[10.5px] opacity-80">{label}</span>}
                      {isSSH && <span className="text-[10px] text-emerald-300">(SSH豁免)</span>}
                    </button>
                  );
                })}
              </div>

              {/* Add custom port */}
              <div className="flex flex-wrap items-center gap-2 pt-1">
                <input
                  type="number"
                  min={1}
                  max={65535}
                  value={customPortInput}
                  onChange={(e) => setCustomPortInput(e.target.value)}
                  placeholder="自定义端口 (如 5900 VNC)"
                  className="w-48 rounded-xl border border-subtle bg-surface2 px-3 py-1.5 text-xs font-mono text-primary placeholder:text-muted focus:border-accent focus:outline-none"
                />
                <Button size="xs" variant="secondary" icon={<Plus className="w-3 h-3" />} onClick={handleAddCustomPort}>
                  添加诱捕端口
                </Button>
              </div>
            </div>

            {/* Timing & ICMP params */}
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 pt-2 border-t border-subtle">
              <div>
                <label className="block text-xs font-medium text-secondary mb-1.5">动态黑名单封禁周期</label>
                <select
                  value={timeoutDaysInput}
                  onChange={(e) => {
                    setTimeoutDaysInput(Number(e.target.value));
                    setConfigDirty(true);
                  }}
                  className="w-full rounded-xl border border-subtle bg-surface2 px-3 py-2 text-xs text-primary focus:border-accent focus:outline-none"
                >
                  {[1, 3, 7, 14, 30].map((d) => (
                    <option key={d} value={d}>
                      {d} 天 {d === 7 ? '(默认推荐)' : ''}
                    </option>
                  ))}
                </select>
              </div>
              <div>
                <label className="block text-xs font-medium text-secondary mb-1.5">ICMP Ping 每秒允许上限</label>
                <select
                  value={pingLimitInput}
                  onChange={(e) => {
                    setPingLimitInput(Number(e.target.value));
                    setConfigDirty(true);
                  }}
                  className="w-full rounded-xl border border-subtle bg-surface2 px-3 py-2 text-xs text-primary focus:border-accent focus:outline-none"
                >
                  {[5, 10, 20, 50].map((r) => (
                    <option key={r} value={r}>
                      {r} 次/秒 {r === 10 ? '(默认推荐)' : ''}
                    </option>
                  ))}
                </select>
              </div>
            </div>

            <div className="flex flex-wrap items-center justify-between gap-2 pt-2">
              <span className="text-[11px] text-muted">
                保存并热重载时会自动迁移当前动态黑名单与计数器结构，不影响正常隧道连接。
              </span>
              <Button
                size="sm"
                variant="primary"
                disabled={isDisabledAll}
                loading={acting}
                onClick={() => void applyConfigAndReload()}
              >
                保存并热重载规则
              </Button>
            </div>
          </div>
        )}
      </SectionCard>

      {/* Layer 4 Drawer 1: Real-time [NFT] Block Logs */}
      <SlideDrawer
        open={logsDrawerOpen}
        onClose={() => setLogsDrawerOpen(false)}
        size="md"
        title="实时防火墙拦截日志 ([NFT])"
        subtitle="已自动剥离本机公网入口 IP（DST），仅展示攻击来源、入站接口与目标端口"
        footer={
          <div className="flex items-center justify-between gap-2">
            <span className="text-[11px] text-muted">最近最多展示 50 条内核拦截记录</span>
            <Button
              size="sm"
              variant="secondary"
              loading={logsLoading}
              icon={<RefreshCw className="w-3.5 h-3.5" />}
              onClick={() => void loadLogs()}
            >
              刷新日志
            </Button>
          </div>
        }
      >
        {logsLoading ? (
          <div className="py-12 text-center text-xs text-muted">正在读取内核日志…</div>
        ) : logs.length === 0 ? (
          <div className="py-12 text-center text-xs text-muted">
            近期系统日志缓冲区暂无 <code className="font-mono">[NFT]</code> 拦截事件。
          </div>
        ) : (
          <div className="space-y-2">
            {logs.map((ev, idx) => (
              <div
                key={`${ev.time}-${ev.srcIp}-${idx}`}
                className="rounded-xl border border-subtle bg-surface2/60 p-3 text-xs space-y-1.5"
              >
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="flex items-center gap-2">
                    <Badge tone={ev.category.includes('永久') ? 'danger' : ev.category.includes('诱捕') ? 'warn' : 'accent'}>
                      {ev.category}
                    </Badge>
                    <span className="font-mono font-semibold text-primary">
                      {maskDisplayIP(ev.srcIp, privacyMask)}
                    </span>
                  </div>
                  <span className="font-mono text-[10.5px] text-muted">{ev.time || '—'}</span>
                </div>
                <div className="flex flex-wrap items-center gap-3 text-[11px] font-mono text-secondary">
                  {ev.iface && <span>接口: {ev.iface}</span>}
                  {ev.proto && <span>协议: {ev.proto}</span>}
                  {ev.dstPort ? <span>探测端口: :{ev.dstPort}</span> : null}
                </div>
              </div>
            ))}
          </div>
        )}
      </SlideDrawer>

      {/* Layer 4 Drawer 2: Compact Rule Skeleton & Multi-Table Cooperation */}
      <SlideDrawer
        open={rulesDrawerOpen}
        onClose={() => setRulesDrawerOpen(false)}
        size="lg"
        title="内核 nftables 规则透视 (table inet security)"
        subtitle="长动态集合已自动折叠摘要，避免浏览器渲染卡顿"
        footer={
          <div className="flex items-center justify-between gap-2">
            <span className="text-[11px] text-muted">
              共存内核表：{preflight?.coexistingTables?.join(' · ') || 'inet security'}
            </span>
            <Button
              size="sm"
              variant="secondary"
              icon={copiedRules ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
              onClick={async () => {
                if (!overview?.compactRuleText) return;
                try {
                  await copyPlainText(overview.compactRuleText);
                  setCopiedRules(true);
                  toast('已复制规则骨架文本', 'success');
                  window.setTimeout(() => setCopiedRules(false), 1800);
                } catch {
                  error('当前浏览器不支持自动复制');
                }
              }}
            >
              {copiedRules ? '已复制' : '复制规则骨架'}
            </Button>
          </div>
        }
      >
        <div className="space-y-4">
          <div className="rounded-xl border border-subtle bg-surface2/60 p-3.5 text-xs text-secondary leading-relaxed space-y-1.5">
            <div className="font-semibold text-primary">多表隔离协作架构（零冲突、卸载零残留）</div>
            <p>
              • <code className="font-mono text-primary">inet fw4</code>：OpenWrt 基础区域转发与 LAN/WAN 路由控制；
            </p>
            <p>
              • <code className="font-mono text-primary">inet sing-box</code>：透明代理分流（TProxy 劫持）；
            </p>
            <p>
              • <code className="font-mono text-primary">inet singctl_audit_throttle</code>：特定 IoT/流目标的不断网速率封顶；
            </p>
            <p>
              • <code className="font-mono text-emerald-300">inet security</code>：本页面托管的公网入口防扫描护盾，停用时整表销毁，不影响上述任何业务表。
            </p>
          </div>

          <pre className="p-3.5 rounded-xl bg-[#070a10] border border-subtle text-[11px] font-mono text-slate-300 overflow-x-auto max-h-[55vh] whitespace-pre-wrap break-all leading-relaxed">
            {overview?.compactRuleText || '当前内核未加载 table inet security'}
          </pre>
        </div>
      </SlideDrawer>

      {/* Confirm dialogs */}
      <ConfirmDialog
        open={disableConfirmOpen}
        danger
        title="禁用并移除防火墙加固规则？"
        description="将彻底删除内核 inet security 表及开机自启脚本，当前动态黑名单中的扫描器也将一并清空（您写入 singctl.yaml 的自定义白名单配置会安全保留）。"
        confirmText="确认禁用移除"
        loading={acting}
        onCancel={() => setDisableConfirmOpen(false)}
        onConfirm={() => void handleDisable()}
      />

      <ConfirmDialog
        open={clearDynConfirmOpen}
        danger
        title="清空 7 天动态黑名单？"
        description={`将立即释放动态黑名单中的 ${totalDynamicCount} 个临时封禁 IP（永久威胁段与累计拦截计数器仍会保留）。`}
        confirmText="确认清空"
        loading={acting}
        onCancel={() => setClearDynConfirmOpen(false)}
        onConfirm={() => void handleClearDynamic()}
      />
    </div>
  );
};

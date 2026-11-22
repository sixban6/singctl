import React, { useState, useEffect, useCallback } from 'react';
import { FileCode2, RefreshCw, Terminal } from 'lucide-react';
import { Badge, Button, ConfirmDialog, PageHeader, useToast } from '../../../ui';
import { clientApi } from '../../api';
import {
  ClientStatusResponse,
  FirewallBanItem,
  FirewallLogEvent,
  FirewallOverviewResponse,
} from '../../types';
import { FirewallLogsDrawer, FirewallRulesDrawer } from './FirewallDrawers';
import { FirewallGovernanceTabs } from './FirewallGovernanceTabs';
import {
  BanScopeFilter,
  DEFAULT_FALLBACK_PORTS,
  RuleTabKey,
} from './firewallHelpers';
import { FirewallOverviewSection } from './FirewallOverviewSection';

export interface FirewallPanelProps {
  status: ClientStatusResponse | null;
  busy: boolean;
  privacyMask?: boolean;
  onRefreshStatus?: () => void;
}

export const FirewallPanel: React.FC<FirewallPanelProps> = ({
  status,
  busy,
  privacyMask = false,
  onRefreshStatus,
}) => {
  const { toast, success, error } = useToast();

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
  const [configDirty, setConfigDirty] = useState(false);

  const [clearDynConfirmOpen, setClearDynConfirmOpen] = useState(false);
  const [disableConfirmOpen, setDisableConfirmOpen] = useState(false);

  const [logsDrawerOpen, setLogsDrawerOpen] = useState(false);
  const [logs, setLogs] = useState<FirewallLogEvent[]>([]);
  const [logsLoading, setLogsLoading] = useState(false);
  const [rulesDrawerOpen, setRulesDrawerOpen] = useState(false);

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
  const totalDynamicCount = (stats?.dynamicV4Count || 0) + (stats?.dynamicV6Count || 0);
  const isDisabledAll = acting || busy || !supported;

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

  const handleManualBan = async (rawTarget: string, scope: 'dynamic' | 'forever'): Promise<boolean> => {
    const t = rawTarget.trim();
    if (!t) {
      toast('请输入要封禁的公网 IP 或 CIDR 网段', 'info');
      return false;
    }
    setActing(true);
    try {
      const res = await clientApi.banFirewallTarget({
        target: t,
        scope,
        timeoutDays: timeoutDaysInput,
      });
      success(res.message || `已封禁 ${res.target}`);
      setPage(1);
      await loadOverview({ targetPage: 1 });
      return true;
    } catch (e) {
      error((e as Error).message || '封禁失败');
      return false;
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

  const handleWhitelistAction = async (action: 'add' | 'remove', targetRaw: string): Promise<boolean> => {
    const t = targetRaw.trim();
    if (!t) {
      toast('请输入白名单 IP 或 CIDR 网段', 'info');
      return false;
    }
    setActing(true);
    try {
      const res = await clientApi.manageFirewallWhitelist(action, t);
      success(res.message || '白名单已更新');
      if (res.overview) {
        setOverview(res.overview);
      } else {
        await loadOverview();
      }
      return true;
    } catch (e) {
      error((e as Error).message || '白名单更新失败');
      return false;
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

  const handleAddCustomPort = (rawPort: string): boolean => {
    const p = Number(rawPort.trim());
    if (!Number.isInteger(p) || p < 1 || p > 65535) {
      toast('请输入合法端口号 (1~65535)', 'info');
      return false;
    }
    if (preflight?.detectedSSHPorts?.includes(p)) {
      error(`安全拦截: 端口 ${p} 是当前 SSH 管理端口，禁止加入诱捕`);
      return false;
    }
    if (preflight?.exemptServicePorts?.includes(p)) {
      error(`安全拦截: 端口 ${p} 属于核心服务豁免端口，禁止加入诱捕`);
      return false;
    }
    setConfigDirty(true);
    setSelectedPorts((prev) => (prev.includes(p) ? prev : [...prev, p].sort((a, b) => a - b)));
    return true;
  };

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

      <FirewallOverviewSection
        overview={overview}
        supported={supported}
        kernelActive={kernelActive}
        autostartEnabled={autostartEnabled}
        drifted={drifted}
        acting={acting}
        isDisabledAll={isDisabledAll}
        privacyMask={privacyMask}
        modeInput={modeInput}
        onSelectMode={(mode) => {
          setModeInput(mode);
          setConfigDirty(true);
        }}
        onApplyAndReload={() => void applyConfigAndReload()}
        onOpenDisableConfirm={() => setDisableConfirmOpen(true)}
        onJumpToTab={(tab, scope) => {
          setActiveTab(tab);
          if (scope) {
            setScopeFilter(scope);
            setPage(1);
          }
        }}
      />

      <FirewallGovernanceTabs
        overview={overview}
        loading={loading}
        acting={acting}
        busy={busy}
        supported={supported}
        kernelActive={kernelActive}
        isDisabledAll={isDisabledAll}
        privacyMask={privacyMask}
        activeTab={activeTab}
        onActiveTabChange={setActiveTab}
        scopeFilter={scopeFilter}
        onScopeFilterChange={(scope) => {
          setScopeFilter(scope);
          setPage(1);
        }}
        searchInput={searchInput}
        onSearchInputChange={setSearchInput}
        searchApplied={searchApplied}
        sortBy={sortBy}
        onSortByChange={(sort) => {
          setSortBy(sort);
          setPage(1);
        }}
        onPageChange={setPage}
        modeInput={modeInput}
        timeoutDaysInput={timeoutDaysInput}
        onTimeoutDaysChange={(days) => {
          setTimeoutDaysInput(days);
          setConfigDirty(true);
        }}
        pingLimitInput={pingLimitInput}
        onPingLimitChange={(rate) => {
          setPingLimitInput(rate);
          setConfigDirty(true);
        }}
        selectedPorts={selectedPorts}
        onResetDefaultPorts={() => {
          setSelectedPorts([...DEFAULT_FALLBACK_PORTS]);
          setConfigDirty(true);
        }}
        onTogglePort={togglePort}
        onAddCustomPort={handleAddCustomPort}
        onManualBan={handleManualBan}
        onUnban={(item) => void handleUnban(item)}
        onOpenClearDynamicConfirm={() => setClearDynConfirmOpen(true)}
        onWhitelistAction={handleWhitelistAction}
        onSaveAndReload={() => void applyConfigAndReload()}
      />

      <FirewallLogsDrawer
        open={logsDrawerOpen}
        logs={logs}
        logsLoading={logsLoading}
        privacyMask={privacyMask}
        onClose={() => setLogsDrawerOpen(false)}
        onReload={() => void loadLogs()}
      />

      <FirewallRulesDrawer
        open={rulesDrawerOpen}
        overview={overview}
        onClose={() => setRulesDrawerOpen(false)}
      />

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

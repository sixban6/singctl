import React, { useMemo, useState } from 'react';
import { Flame, Lock, Plus, RotateCcw, Search, Trash2, Unlock } from 'lucide-react';
import {
  Badge,
  Button,
  DataColumn,
  DataTable,
  SectionCard,
  SegmentedTabs,
} from '../../../ui';
import { FirewallBanItem, FirewallOverviewResponse } from '../../types';
import {
  BanScopeFilter,
  DEFAULT_FALLBACK_PORTS,
  fmtNum,
  formatRemainingTTL,
  maskDisplayIP,
  RuleTabKey,
} from './firewallHelpers';

export interface FirewallGovernanceTabsProps {
  overview: FirewallOverviewResponse | null;
  loading: boolean;
  acting: boolean;
  busy: boolean;
  supported: boolean;
  kernelActive: boolean;
  isDisabledAll: boolean;
  privacyMask: boolean;
  activeTab: RuleTabKey;
  onActiveTabChange: (tab: RuleTabKey) => void;
  scopeFilter: BanScopeFilter;
  onScopeFilterChange: (scope: BanScopeFilter) => void;
  searchInput: string;
  onSearchInputChange: (v: string) => void;
  searchApplied: string;
  sortBy: 'expires' | 'target' | 'scope';
  onSortByChange: (sort: 'expires' | 'target' | 'scope') => void;
  onPageChange: (nextPage: number) => void;
  modeInput: 'standard' | 'minimal';
  timeoutDaysInput: number;
  onTimeoutDaysChange: (days: number) => void;
  pingLimitInput: number;
  onPingLimitChange: (rate: number) => void;
  selectedPorts: number[];
  onResetDefaultPorts: () => void;
  onTogglePort: (port: number) => void;
  onAddCustomPort: (rawPort: string) => boolean;
  onManualBan: (target: string, scope: 'dynamic' | 'forever') => Promise<boolean>;
  onUnban: (item: FirewallBanItem) => void;
  onOpenClearDynamicConfirm: () => void;
  onWhitelistAction: (action: 'add' | 'remove', targetRaw: string) => Promise<boolean>;
  onSaveAndReload: () => void;
}

export const FirewallGovernanceTabs: React.FC<FirewallGovernanceTabsProps> = ({
  overview,
  loading,
  acting,
  busy,
  supported,
  kernelActive,
  isDisabledAll,
  privacyMask,
  activeTab,
  onActiveTabChange,
  scopeFilter,
  onScopeFilterChange,
  searchInput,
  onSearchInputChange,
  searchApplied,
  sortBy,
  onSortByChange,
  onPageChange,
  modeInput,
  timeoutDaysInput,
  onTimeoutDaysChange,
  pingLimitInput,
  onPingLimitChange,
  selectedPorts,
  onResetDefaultPorts,
  onTogglePort,
  onAddCustomPort,
  onManualBan,
  onUnban,
  onOpenClearDynamicConfirm,
  onWhitelistAction,
  onSaveAndReload,
}) => {
  const [addBanOpen, setAddBanOpen] = useState(false);
  const [banTargetInput, setBanTargetInput] = useState('');
  const [banScopeInput, setBanScopeInput] = useState<'dynamic' | 'forever'>('dynamic');
  const [whitelistInput, setWhitelistInput] = useState('');
  const [customPortInput, setCustomPortInput] = useState('');

  const stats = overview?.stats;
  const preflight = overview?.preflight;
  const totalDynamicCount = (stats?.dynamicV4Count || 0) + (stats?.dynamicV6Count || 0);

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
    if (s.size === 0) {
      for (const p of DEFAULT_FALLBACK_PORTS) s.add(p);
    }
    return Array.from(s).sort((a, b) => a - b);
  }, [overview?.portCatalog, selectedPorts, preflight?.detectedSSHPorts]);

  const totalPages = useMemo(() => {
    const total = overview?.bans?.total || 0;
    const size = overview?.bans?.pageSize || 25;
    return Math.max(1, Math.ceil(total / size));
  }, [overview?.bans]);

  const callerAlreadyWhitelisted = useMemo(() => {
    const cip = preflight?.callerIp;
    if (!cip) return true;
    const allCustom = overview?.whitelist?.custom || [];
    const liveExtra = overview?.whitelist?.liveExtra || [];
    if (/^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|100\.(6[4-9]|[7-9]\d|1\d\d)|127\.|::1$|fc|fd|fe80:)/i.test(cip)) {
      return true;
    }
    return allCustom.includes(cip) || liveExtra.includes(cip);
  }, [preflight?.callerIp, overview?.whitelist]);

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
            onClick={() => onUnban(item)}
          >
            解封
          </Button>
        ),
    },
  ];

  const submitManualBan = async () => {
    const ok = await onManualBan(banTargetInput, banScopeInput);
    if (ok) {
      setBanTargetInput('');
      setAddBanOpen(false);
    }
  };

  const submitWhitelistAdd = async () => {
    const ok = await onWhitelistAction('add', whitelistInput);
    if (ok) {
      setWhitelistInput('');
    }
  };

  const submitCustomPort = () => {
    if (onAddCustomPort(customPortInput)) {
      setCustomPortInput('');
    }
  };

  return (
    <SectionCard
      title="规则与名单治理"
      subtitle="支持动态黑名单检索解封、自定义信任白名单与高危诱捕端口精细配置"
      icon={<Flame className="w-4 h-4" />}
      actions={
        <SegmentedTabs
          value={activeTab}
          onChange={(k) => onActiveTabChange(k as RuleTabKey)}
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
                    onClick={() => onScopeFilterChange(pill.key)}
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
                  onClick={onOpenClearDynamicConfirm}
                >
                  清空动态黑名单
                </Button>
              )}
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-2.5">
            <div className="relative flex-1 min-w-[200px]">
              <Search className="w-3.5 h-3.5 text-muted absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none" />
              <input
                type="text"
                value={searchInput}
                onChange={(e) => onSearchInputChange(e.target.value)}
                placeholder="搜索 IP 或网段前缀（如 198.51.100 或 2001:db8:）…"
                className="w-full rounded-xl border border-subtle bg-surface2 pl-8 pr-3 py-1.5 text-xs text-primary placeholder:text-muted focus:border-accent focus:outline-none font-mono"
              />
            </div>
            <select
              value={sortBy}
              onChange={(e) => onSortByChange(e.target.value as 'expires' | 'target' | 'scope')}
              className="rounded-xl border border-subtle bg-surface2 px-3 py-1.5 text-xs text-secondary focus:border-accent focus:outline-none"
            >
              <option value="expires">最近触发优先 (TTL 最长)</option>
              <option value="target">按 IP / 网段排序</option>
              <option value="scope">按拦截集合分组</option>
            </select>
          </div>

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
              <Button size="sm" variant="danger" disabled={acting} onClick={() => void submitManualBan()}>
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
                      onClick={() => onPageChange(Math.max(1, (overview?.bans?.page || 1) - 1))}
                    >
                      上一页
                    </Button>
                    <Button
                      size="xs"
                      variant="secondary"
                      disabled={loading || (overview?.bans?.page || 1) >= totalPages}
                      onClick={() => onPageChange(Math.min(totalPages, (overview?.bans?.page || 1) + 1))}
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

          <div className="space-y-2.5 pt-2 border-t border-subtle">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <span className="text-xs font-semibold text-primary">用户自定义信任白名单（持久化至 singctl.yaml）</span>
              {preflight?.callerIp && !callerAlreadyWhitelisted && (
                <Button
                  size="xs"
                  variant="secondary"
                  disabled={acting}
                  icon={<Plus className="w-3 h-3" />}
                  onClick={() => void onWhitelistAction('add', preflight.callerIp!)}
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
                      onClick={() => void onWhitelistAction('remove', entry)}
                      title="移出白名单"
                      className="text-muted hover:text-rose-400 cursor-pointer"
                    >
                      ×
                    </button>
                  </span>
                ))
              )}
            </div>

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
                onClick={() => void submitWhitelistAdd()}
              >
                加入白名单
              </Button>
            </div>
          </div>

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
                      onClick={() => void onWhitelistAction('add', entry)}
                      className="text-[11px] text-emerald-300 hover:underline cursor-pointer"
                    >
                      固化
                    </button>
                    <button
                      type="button"
                      disabled={acting}
                      onClick={() => void onWhitelistAction('remove', entry)}
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

          <div className="space-y-2">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <span className="text-xs font-semibold text-primary">
                高危管理端口诱捕池（公网主动探测这些端口将被自动关入动态黑名单）
              </span>
              <button
                type="button"
                onClick={onResetDefaultPorts}
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
                    onClick={() => onTogglePort(port)}
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
              <Button size="xs" variant="secondary" icon={<Plus className="w-3 h-3" />} onClick={submitCustomPort}>
                添加诱捕端口
              </Button>
            </div>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 pt-2 border-t border-subtle">
            <div>
              <label className="block text-xs font-medium text-secondary mb-1.5">动态黑名单封禁周期</label>
              <select
                value={timeoutDaysInput}
                onChange={(e) => onTimeoutDaysChange(Number(e.target.value))}
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
                onChange={(e) => onPingLimitChange(Number(e.target.value))}
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
              onClick={onSaveAndReload}
            >
              保存并热重载规则
            </Button>
          </div>
        </div>
      )}
    </SectionCard>
  );
};

import React, { useCallback, useEffect, useMemo, useState } from 'react';
import {
  ShieldCheck,
  PauseCircle,
  PlayCircle,
  RefreshCw,
  Trash2,
  Plus,
  ExternalLink,
  KeyRound,
  Copy,
  Eye,
  EyeOff,
  CheckCircle2,
  AlertTriangle,
  Globe,
  Zap,
  Layers,
  Download,
  RotateCw,
  Power,
} from 'lucide-react';
import {
  Badge,
  Button,
  PageHeader,
  SectionCard,
  SlideDrawer,
  useToast,
} from '../../ui';
import { clientApi } from '../api';
import {
  AdGuardCredentialsResponse,
  AdGuardOverviewSnapshot,
  AdGuardProbeResult,
  ClientStatusResponse,
} from '../types';

export interface AdGuardPageProps {
  status: ClientStatusResponse | null;
  busy: boolean;
  onAction: (name: string, params?: Record<string, unknown>, confirmMsg?: string) => void;
  onRefreshStatus: () => void;
}

function formatNumber(n: number): string {
  if (!Number.isFinite(n)) return '0';
  return n.toLocaleString('zh-CN');
}

function formatDurationSec(totalSec: number): string {
  const s = Math.max(0, Math.floor(totalSec));
  const m = Math.floor(s / 60);
  const rem = s % 60;
  if (m >= 60) {
    const h = Math.floor(m / 60);
    const rm = m % 60;
    return `${h} 小时 ${rm} 分 ${rem} 秒`;
  }
  if (m > 0) return `${m} 分 ${rem.toString().padStart(2, '0')} 秒`;
  return `${rem} 秒`;
}

export const AdGuardPage: React.FC<AdGuardPageProps> = ({
  status,
  busy,
  onAction,
  onRefreshStatus,
}) => {
  const { success, error } = useToast();
  const [snap, setSnap] = useState<AdGuardOverviewSnapshot | null>(null);
  const [loading, setLoading] = useState(true);
  const [mutating, setMutating] = useState(false);

  // Upstream live latency probe
  const [probe, setProbe] = useState<AdGuardProbeResult | null>(null);
  const [probing, setProbing] = useState(false);

  // Pause protection live countdown (seconds)
  const [pauseRemainSec, setPauseRemainSec] = useState<number>(0);

  // Whitelist quick input
  const [wlInput, setWlInput] = useState('');

  // DNS Rewrite quick form
  const [rwDomain, setRwDomain] = useState('');
  const [rwAnswer, setRwAnswer] = useState('');

  // Custom Filter URL collapsible form
  const [showCustomFilter, setShowCustomFilter] = useState(false);
  const [customFilterName, setCustomFilterName] = useState('');
  const [customFilterUrl, setCustomFilterUrl] = useState('');

  // Native Panel & Credentials Drawer
  const [credOpen, setCredOpen] = useState(false);
  const [credData, setCredData] = useState<AdGuardCredentialsResponse | null>(null);
  const [credLoading, setCredLoading] = useState(false);
  const [showPwd, setShowPwd] = useState(false);
  const [resettingPwd, setResettingPwd] = useState(false);

  const loadOverview = useCallback(
    async (silent = false) => {
      if (!silent) setLoading(true);
      try {
        const res = await clientApi.getAdGuardOverview();
        setSnap(res);
        if (!res.protectionEnabled && res.protectionDisabledDurationMs && res.protectionDisabledDurationMs > 0) {
          setPauseRemainSec(Math.ceil(res.protectionDisabledDurationMs / 1000));
        } else {
          setPauseRemainSec(0);
        }
      } catch (e) {
        if (!silent) error((e as Error).message || '加载防劫持 DNS 状态失败');
      } finally {
        if (!silent) setLoading(false);
      }
    },
    [error],
  );

  // Initial & status-change reload
  useEffect(() => {
    loadOverview(Boolean(snap));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [status?.adguard?.installed, status?.adguard?.running, status?.adguard?.singboxLinked]);

  // Periodic background refresh (15s) when installed
  useEffect(() => {
    if (!snap?.installed) return;
    const t = window.setInterval(() => {
      loadOverview(true);
    }, 15000);
    return () => window.clearInterval(t);
  }, [snap?.installed, loadOverview]);

  // Countdown tick when protection is temporarily paused
  useEffect(() => {
    if (pauseRemainSec <= 0) return;
    const t = window.setInterval(() => {
      setPauseRemainSec((prev) => {
        if (prev <= 1) {
          window.setTimeout(() => loadOverview(true), 600);
          return 0;
        }
        return prev - 1;
      });
    }, 1000);
    return () => window.clearInterval(t);
  }, [pauseRemainSec, loadOverview]);

  const runProbe = useCallback(
    async (silent = false) => {
      setProbing(true);
      try {
        const res = await clientApi.probeAdGuardUpstream();
        setProbe(res);
        if (!silent) {
          if (res.healthy) {
            success(`加密 DoH 上游正常：${res.domain} → ${res.resolved} (${res.latencyMs}ms)`);
          } else {
            error(res.error || '上游解析探测异常');
          }
        }
      } catch (e) {
        if (!silent) error((e as Error).message || '探测失败');
      } finally {
        setProbing(false);
      }
    },
    [success, error],
  );

  // Auto-probe once when DNS becomes healthy
  useEffect(() => {
    if (snap?.installed && snap.dnsHealthy && !probe && !probing) {
      runProbe(true);
    }
  }, [snap?.installed, snap?.dnsHealthy, probe, probing, runProbe]);

  const handleProtection = async (enabled: boolean, durationMinutes = 0) => {
    setMutating(true);
    try {
      await clientApi.setAdGuardProtection(enabled, durationMinutes);
      if (enabled) {
        success('已恢复去广告与隐私追踪过滤保护');
      } else if (durationMinutes > 0) {
        success(`已临时暂停广告过滤 ${durationMinutes} 分钟（防劫持 DoH 解析保持运行，不断网）`);
      } else {
        success('已暂停广告过滤规则');
      }
      await loadOverview(true);
    } catch (e) {
      error((e as Error).message || '切换过滤状态失败');
    } finally {
      setMutating(false);
    }
  };

  const handleClearCache = async () => {
    setMutating(true);
    try {
      await clientApi.clearAdGuardCache();
      success('已清空本地 DNS 缓存');
      runProbe(true);
    } catch (e) {
      error((e as Error).message || '清空缓存失败');
    } finally {
      setMutating(false);
    }
  };

  const handleWhitelist = async (action: 'add' | 'remove', rawDomain: string) => {
    const d = rawDomain.trim();
    if (!d) return;
    setMutating(true);
    try {
      await clientApi.setAdGuardWhitelist(action, d);
      success(action === 'add' ? `已放行域名 ${d}` : `已移出白名单 ${d}`);
      if (action === 'add') setWlInput('');
      await loadOverview(true);
    } catch (e) {
      error((e as Error).message || '更新白名单失败');
    } finally {
      setMutating(false);
    }
  };

  const handleAddRewrite = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!rwDomain.trim() || !rwAnswer.trim()) {
      error('请填写内网域名与目标 IP / 域名');
      return;
    }
    setMutating(true);
    try {
      await clientApi.manageAdGuardRewrite('add', rwDomain.trim(), rwAnswer.trim());
      success(`已添加域名映射：${rwDomain.trim()} → ${rwAnswer.trim()}`);
      setRwDomain('');
      setRwAnswer('');
      await loadOverview(true);
    } catch (err) {
      error((err as Error).message || '添加重写失败');
    } finally {
      setMutating(false);
    }
  };

  const handleDeleteRewrite = async (domain: string, answer: string) => {
    setMutating(true);
    try {
      await clientApi.manageAdGuardRewrite('delete', domain, answer);
      success(`已移除映射 ${domain}`);
      await loadOverview(true);
    } catch (err) {
      error((err as Error).message || '删除映射失败');
    } finally {
      setMutating(false);
    }
  };

  const handleFilterToggle = async (url: string, name: string, enabled: boolean) => {
    setMutating(true);
    try {
      await clientApi.manageAdGuardFilter({ action: 'toggle', url, name, enabled });
      success(enabled ? `已启用规则库：${name}` : `已停用规则库：${name}`);
      await loadOverview(true);
    } catch (err) {
      error((err as Error).message || '切换规则库失败');
    } finally {
      setMutating(false);
    }
  };

  const handleAddCustomFilter = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!customFilterUrl.trim()) {
      error('请输入有效的 http:// 或 https:// 规则订阅链接');
      return;
    }
    setMutating(true);
    try {
      await clientApi.manageAdGuardFilter({
        action: 'add',
        url: customFilterUrl.trim(),
        name: customFilterName.trim(),
        enabled: true,
      });
      success('已添加并启用自定义过滤规则库');
      setCustomFilterName('');
      setCustomFilterUrl('');
      setShowCustomFilter(false);
      await loadOverview(true);
    } catch (err) {
      error((err as Error).message || '添加自定义规则库失败');
    } finally {
      setMutating(false);
    }
  };

  const handleRemoveCustomFilter = async (url: string, name: string) => {
    setMutating(true);
    try {
      await clientApi.manageAdGuardFilter({ action: 'remove', url });
      success(`已移除规则库：${name}`);
      await loadOverview(true);
    } catch (err) {
      error((err as Error).message || '移除规则库失败');
    } finally {
      setMutating(false);
    }
  };

  const handleRefreshFilters = async () => {
    setMutating(true);
    try {
      await clientApi.manageAdGuardFilter({ action: 'refresh' });
      success('已在线同步更新全部规则库');
      await loadOverview(true);
    } catch (err) {
      error((err as Error).message || '更新规则库失败');
    } finally {
      setMutating(false);
    }
  };

  const openCredentialsDrawer = async () => {
    setCredOpen(true);
    setShowPwd(false);
    setCredLoading(true);
    try {
      const res = await clientApi.getAdGuardCredentials();
      setCredData(res);
    } catch (err) {
      error((err as Error).message || '读取凭据失败');
    } finally {
      setCredLoading(false);
    }
  };

  const handleResetPassword = async () => {
    setResettingPwd(true);
    try {
      const res = await clientApi.resetAdGuardCredentials();
      setCredData(res);
      setShowPwd(true);
      success('已生成新的 16 位随机管理密码并热同步生效');
      onRefreshStatus();
    } catch (err) {
      error((err as Error).message || '重置密码失败');
    } finally {
      setResettingPwd(false);
    }
  };

  const copyText = async (text: string, msg: string) => {
    try {
      await navigator.clipboard.writeText(text);
      success(msg);
    } catch {
      error('复制失败，请手动复制');
    }
  };

  const whitelistSet = useMemo(() => {
    return new Set((snap?.whitelistedDomains || []).map((d) => d.toLowerCase()));
  }, [snap?.whitelistedDomains]);

  const presetUrlSet = useMemo(() => {
    return new Set((snap?.presets || []).map((p) => p.url));
  }, [snap?.presets]);

  const extraCustomFilters = useMemo(() => {
    return (snap?.filters || []).filter((f) => !presetUrlSet.has(f.url));
  }, [snap?.filters, presetUrlSet]);

  const headerBadge = useMemo(() => {
    if (!snap) return <Badge tone="neutral">加载中</Badge>;
    if (!snap.supported) return <Badge tone="warn">当前平台不支持</Badge>;
    if (!snap.installed) return <Badge tone="neutral">未安装</Badge>;
    if (!snap.dnsHealthy) return <Badge tone="danger">未运行</Badge>;
    if (!snap.singboxLinked) {
      return (
        <Badge tone="warn" dot>
          运行中 · 待接管 sing-box
        </Badge>
      );
    }
    if (!snap.protectionEnabled) {
      return (
        <Badge tone="warn" dot>
          防劫持在线 · 暂停去广告中
        </Badge>
      );
    }
    return (
      <Badge tone="ok" dot pulse>
        防劫持接管中 · {snap.dnsAddr}
      </Badge>
    );
  }, [snap]);

  if (loading && !snap) {
    return (
      <div className="space-y-5">
        <PageHeader title="防劫持 DNS (AdGuard Home)" description="正在读取本地防劫持引擎与解析遥测…" />
      </div>
    );
  }

  // ── 未安装：极简一键接管引导页 ──
  if (snap && !snap.installed) {
    return (
      <div className="space-y-5">
        <PageHeader
          title="防劫持 DNS (AdGuard Home)"
          description="本地 127.0.0.1:5353 回环托管 + 纯 IP 加密 DoH 上游，彻底根除宽带运营商明文 DNS 抢答劫持"
          badge={headerBadge}
        />

        <SectionCard
          title="为什么建议在网关客户端启用本地 AdGuard Home？"
          icon={<ShieldCheck className="w-4 h-4" />}
          subtitle="安装过程全自动免向导，先验证解析就绪再热切换 sing-box，全程零断网"
        >
          <div className="space-y-5">
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              {[
                {
                  title: '纯 IP 加密 DoH 防运营商抢答',
                  desc: '接管 sing-box 国内分流与代理节点引导解析，并发查询阿里/腾讯纯 IP DoH/DoT，杜绝 UDP 53 污染。',
                },
                {
                  title: '回环隔离不抢 53 端口',
                  desc: '仅绑定 127.0.0.1:5353 供本机内核调用，不与 OpenWrt dnsmasq 或系统 DHCP 主机名解析冲突。',
                },
                {
                  title: '控制台一体化免记密码',
                  desc: '直接在当前页面一键临时暂停去广告、放行误拦域名、配置内网 NAS 域名映射，免登第二套后台。',
                },
                {
                  title: '软路由闪存保护 + 永不断网联动',
                  desc: 'OpenWrt 自动关闭查询日志落盘保护闪存；启停、卸载或异常时自动原子回退内置加密 DNS，全屋不断网。',
                },
              ].map((item) => (
                <div
                  key={item.title}
                  className="p-3.5 rounded-xl bg-surface2 border border-subtle space-y-1"
                >
                  <div className="text-xs sm:text-sm font-semibold text-primary">{item.title}</div>
                  <div className="text-[11px] sm:text-xs text-secondary leading-relaxed">
                    {item.desc}
                  </div>
                </div>
              ))}
            </div>

            <div className="flex flex-wrap items-center gap-3 pt-2 border-t border-subtle">
              <Button
                variant="primary"
                disabled={busy || !snap.supported}
                icon={<Download className="w-4 h-4" />}
                onClick={() => onAction('dns-install')}
              >
                一键安装并无感接管 DNS
              </Button>
              {!snap.supported && (
                <span className="text-xs text-muted">
                  当前操作系统暂不支持托管，请在 Linux / OpenWrt 客户端网关上使用。
                </span>
              )}
            </div>
          </div>
        </SectionCard>
      </div>
    );
  }

  // ── 已安装：完整一体化管控工作台 ──
  return (
    <div className="space-y-5">
      <PageHeader
        title="防劫持 DNS (AdGuard Home)"
        description={`${snap?.version ? `${snap.version} · ` : ''}引擎监听 ${snap?.dnsAddr || '127.0.0.1:5353'}${snap?.isOpenWrt ? ' · OpenWrt 闪存保护已开启' : ''}`}
        badge={headerBadge}
        actions={
          <>
            <Button
              size="sm"
              variant="secondary"
              loading={probing}
              disabled={!snap?.dnsHealthy}
              onClick={() => runProbe(false)}
              icon={<Zap className="w-3.5 h-3.5" />}
            >
              实测上游
            </Button>
            <Button
              size="sm"
              variant="secondary"
              disabled={mutating || !snap?.webHealthy}
              onClick={handleClearCache}
              icon={<RefreshCw className="w-3.5 h-3.5" />}
            >
              清 DNS 缓存
            </Button>
            <Button
              size="sm"
              variant="primary"
              onClick={openCredentialsDrawer}
              icon={<KeyRound className="w-3.5 h-3.5" />}
            >
              原生面板与凭据
            </Button>
          </>
        }
      />

      {/* 临时暂停去广告倒计时提示条 */}
      {snap && snap.dnsHealthy && !snap.protectionEnabled && (
        <div
          className="console-card rounded-2xl p-4 flex flex-wrap items-center justify-between gap-3 border animate-sc-in"
          style={{
            borderColor: 'var(--status-warn)',
            backgroundColor: 'var(--status-warn-soft)',
          }}
        >
          <div className="flex items-start gap-2.5 min-w-0">
            <PauseCircle
              className="w-5 h-5 shrink-0 mt-0.5"
              style={{ color: 'var(--status-warn)' }}
            />
            <div className="text-xs sm:text-sm">
              <div className="font-semibold text-primary">
                去广告规则过滤已临时暂停
                {pauseRemainSec > 0 ? `（剩余 ${formatDurationSec(pauseRemainSec)} 自动恢复）` : ''}
              </div>
              <div className="text-secondary mt-0.5">
                本地 {snap.dnsAddr} 加密防劫持 DoH 解析仍在正常运行中，全屋网络不受任何影响。
              </div>
            </div>
          </div>
          <Button
            size="sm"
            variant="primary"
            disabled={mutating}
            icon={<PlayCircle className="w-3.5 h-3.5" />}
            onClick={() => handleProtection(true, 0)}
          >
            立即恢复拦截
          </Button>
        </div>
      )}

      {/* 未联动或未运行提示条 */}
      {snap && (!snap.dnsHealthy || !snap.singboxLinked) && (
        <div
          className="console-card rounded-2xl p-4 flex flex-wrap items-center justify-between gap-3 border"
          style={{
            borderColor: 'var(--status-warn)',
            backgroundColor: 'var(--status-warn-soft)',
          }}
        >
          <div className="flex items-start gap-2.5 min-w-0">
            <AlertTriangle
              className="w-5 h-5 shrink-0 mt-0.5"
              style={{ color: 'var(--status-warn)' }}
            />
            <div className="text-xs sm:text-sm">
              <div className="font-semibold text-primary">
                {!snap.dnsHealthy
                  ? 'AdGuard Home 当前处于停止状态（网关正在使用内置纯 IP 加密 DoH 兜底）'
                  : 'AdGuard Home 已运行，但当前 sing-box 尚未将 dns_local 切换至本地接管'}
              </div>
              <div className="text-secondary mt-0.5">
                点击右侧按钮即可在确认本地加密解析就绪后，平滑热重载 sing-box 完成零断网接管。
              </div>
            </div>
          </div>
          <Button
            size="sm"
            variant="primary"
            disabled={busy}
            icon={<Power className="w-3.5 h-3.5" />}
            onClick={() => onAction('dns-start')}
          >
            启动并接管 DNS
          </Button>
        </div>
      )}

      {/* 家人防误伤快捷栏 */}
      {snap?.dnsHealthy && (
        <SectionCard
          title="防误伤快捷控制"
          icon={<ShieldCheck className="w-4 h-4" />}
          subtitle="遇到小程序、电商活动或视频激励加载异常时，一键临时放行广告拦截（不断网），到点自动恢复"
        >
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div className="flex flex-wrap items-center gap-2">
              {snap.protectionEnabled ? (
                <>
                  <Button
                    size="sm"
                    variant="secondary"
                    disabled={mutating || !snap.webHealthy}
                    icon={<PauseCircle className="w-3.5 h-3.5" />}
                    onClick={() => handleProtection(false, 5)}
                  >
                    暂停过滤 5 分钟
                  </Button>
                  <Button
                    size="sm"
                    variant="secondary"
                    disabled={mutating || !snap.webHealthy}
                    onClick={() => handleProtection(false, 30)}
                  >
                    暂停 30 分钟
                  </Button>
                  <Button
                    size="sm"
                    variant="secondary"
                    disabled={mutating || !snap.webHealthy}
                    onClick={() => handleProtection(false, 60)}
                  >
                    暂停 1 小时
                  </Button>
                </>
              ) : (
                <Button
                  size="sm"
                  variant="primary"
                  disabled={mutating || !snap.webHealthy}
                  icon={<PlayCircle className="w-3.5 h-3.5" />}
                  onClick={() => handleProtection(true, 0)}
                >
                  立即恢复去广告保护
                </Button>
              )}
            </div>

            <div className="flex flex-wrap items-center gap-2 text-xs text-secondary">
              {snap.autoWhitelistedSubs.length > 0 && (
                <Badge tone="ok">已自动保护 {snap.autoWhitelistedSubs.length} 个订阅域名</Badge>
              )}
              {snap.auditManagedCount > 0 && (
                <Badge tone="accent">行为审计联动阻断 {snap.auditManagedCount} 条</Badge>
              )}
            </div>
          </div>
        </SectionCard>
      )}

      {/* 4 核心遥测指标 */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3.5">
        <div className="console-card rounded-2xl p-4 space-y-1">
          <div className="text-xs text-secondary">24h DNS 查询总量</div>
          <div className="text-xl sm:text-2xl font-bold text-primary font-mono tnum">
            {formatNumber(snap?.stats.numDnsQueries || 0)}
          </div>
          <div className="text-[11px] text-muted">
            {snap?.singboxLinked ? 'sing-box dns_local 实时接管中' : '等待接管'}
          </div>
        </div>

        <div className="console-card rounded-2xl p-4 space-y-1">
          <div className="text-xs text-secondary">已拦截广告与追踪</div>
          <div
            className="text-xl sm:text-2xl font-bold font-mono tnum"
            style={{ color: 'var(--status-ok)' }}
          >
            {formatNumber(snap?.stats.numBlockedFiltering || 0)}
          </div>
          <div className="text-[11px] text-muted tnum">
            拦截占比 {snap?.stats.blockedPercent ?? 0}% · 生效规则 {formatNumber(snap?.totalRulesCount || 0)} 条
          </div>
        </div>

        <div className="console-card rounded-2xl p-4 space-y-1">
          <div className="text-xs text-secondary">平均解析耗时</div>
          <div className="text-xl sm:text-2xl font-bold text-primary font-mono tnum">
            {snap?.stats.avgProcessingMs ?? 0} <span className="text-xs font-normal">ms</span>
          </div>
          <div className="text-[11px] text-muted">含乐观缓存加速响应</div>
        </div>

        <div className="console-card rounded-2xl p-4 space-y-1">
          <div className="text-xs text-secondary">加密 DoH 上游实测</div>
          <div className="text-xl sm:text-2xl font-bold text-primary font-mono tnum">
            {probing ? (
              <span className="text-sm text-secondary">探测中…</span>
            ) : probe?.healthy ? (
              <>
                {probe.latencyMs} <span className="text-xs font-normal">ms</span>
              </>
            ) : (
              <span className="text-sm text-secondary">--</span>
            )}
          </div>
          <div className="text-[11px] text-muted truncate">
            {probe?.healthy
              ? `${probe.domain} → ${probe.resolved}`
              : probe?.error || '阿里 / 腾讯纯 IP DoH 并发'}
          </div>
        </div>
      </div>

      {/* 双栏工作区：误拦一键放行 + 局域网 DNS 重写 */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* 左：高频拦截排行 & 白名单放行 */}
        <SectionCard
          title="高频拦截排行与一键白名单"
          icon={<CheckCircle2 className="w-4 h-4" />}
          subtitle="发现正常服务被误拦时，点击「放行」立即写入高优白名单"
        >
          <div className="space-y-4">
            <form
              onSubmit={(e) => {
                e.preventDefault();
                handleWhitelist('add', wlInput);
              }}
              className="flex items-center gap-2"
            >
              <input
                type="text"
                value={wlInput}
                onChange={(e) => setWlInput(e.target.value)}
                placeholder="手动输入需放行的域名（如 api.example.com）"
                className="flex-1 min-w-0 h-9 px-3 rounded-xl bg-surface2 border border-subtle text-xs sm:text-sm text-primary font-mono focus:outline-none focus:border-strong"
              />
              <Button
                type="submit"
                size="sm"
                variant="secondary"
                disabled={mutating || !wlInput.trim()}
                icon={<Plus className="w-3.5 h-3.5" />}
              >
                放行
              </Button>
            </form>

            {snap && snap.whitelistedDomains.length > 0 && (
              <div className="space-y-1.5">
                <div className="text-[11px] text-muted">当前手动放行白名单（点击 × 恢复拦截）：</div>
                <div className="flex flex-wrap gap-1.5">
                  {snap.whitelistedDomains.map((d) => (
                    <button
                      key={d}
                      type="button"
                      disabled={mutating}
                      onClick={() => handleWhitelist('remove', d)}
                      className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-xs font-mono bg-emerald-500/10 hover:bg-emerald-500/20 border border-emerald-500/25 text-emerald-400 transition-colors cursor-pointer"
                    >
                      <span>{d}</span>
                      <span className="opacity-75">×</span>
                    </button>
                  ))}
                </div>
              </div>
            )}

            {!snap?.stats.topBlockedDomains?.length ? (
              <div className="py-6 text-center text-xs text-muted">
                暂无近期被拦截域名记录
              </div>
            ) : (
              <div className="divide-y divide-[var(--border-subtle)] text-xs sm:text-sm max-h-72 overflow-y-auto pr-1">
                {snap.stats.topBlockedDomains.map((item) => {
                  const allowed = whitelistSet.has(item.domain.toLowerCase());
                  return (
                    <div
                      key={item.domain}
                      className="flex items-center justify-between gap-3 py-2"
                    >
                      <div className="min-w-0 flex-1">
                        <div className="font-mono text-primary truncate">{item.domain}</div>
                        <div className="text-[11px] text-muted tnum">拦截 {item.count} 次</div>
                      </div>
                      {allowed ? (
                        <Badge tone="ok">已放行</Badge>
                      ) : (
                        <Button
                          size="xs"
                          variant="ghost"
                          disabled={mutating}
                          onClick={() => handleWhitelist('add', item.domain)}
                        >
                          放行
                        </Button>
                      )}
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        </SectionCard>

        {/* 右：局域网自定义域名重写 */}
        <SectionCard
          title="局域网自定义域名映射 (DNS Rewrites)"
          icon={<Globe className="w-4 h-4" />}
          subtitle="为家庭 NAS、路由器或自建服务绑定好记的内网域名（支持 *.lan 通配符）"
        >
          <div className="space-y-4">
            <form onSubmit={handleAddRewrite} className="grid grid-cols-1 sm:grid-cols-12 gap-2">
              <input
                type="text"
                value={rwDomain}
                onChange={(e) => setRwDomain(e.target.value)}
                placeholder="域名 (如 nas.lan)"
                className="sm:col-span-5 h-9 px-3 rounded-xl bg-surface2 border border-subtle text-xs sm:text-sm text-primary font-mono focus:outline-none focus:border-strong"
              />
              <input
                type="text"
                value={rwAnswer}
                onChange={(e) => setRwAnswer(e.target.value)}
                placeholder="目标 IP (如 192.168.1.10)"
                className="sm:col-span-5 h-9 px-3 rounded-xl bg-surface2 border border-subtle text-xs sm:text-sm text-primary font-mono focus:outline-none focus:border-strong"
              />
              <div className="sm:col-span-2">
                <Button
                  type="submit"
                  size="sm"
                  variant="primary"
                  className="w-full h-9"
                  disabled={mutating || !snap?.webHealthy}
                >
                  添加
                </Button>
              </div>
            </form>

            {!snap?.rewrites?.length ? (
              <div className="py-6 text-center text-xs text-muted">
                暂未配置自定义域名映射（例如可将 router.lan 指向本机网关 IP）
              </div>
            ) : (
              <div className="divide-y divide-[var(--border-subtle)] text-xs sm:text-sm max-h-72 overflow-y-auto pr-1">
                {snap.rewrites.map((rw, idx) => (
                  <div
                    key={`${rw.domain}-${rw.answer}-${idx}`}
                    className="flex items-center justify-between gap-3 py-2"
                  >
                    <div className="min-w-0 flex-1 flex items-center gap-2 font-mono">
                      <span className="text-primary font-medium truncate">{rw.domain}</span>
                      <span className="text-muted">→</span>
                      <span className="text-secondary truncate">{rw.answer}</span>
                    </div>
                    <Button
                      size="xs"
                      variant="ghost"
                      disabled={mutating || !snap.webHealthy}
                      onClick={() => handleDeleteRewrite(rw.domain, rw.answer)}
                      icon={<Trash2 className="w-3.5 h-3.5" />}
                    />
                  </div>
                ))}
              </div>
            )}
          </div>
        </SectionCard>
      </div>

      {/* 精选去广告规则库管理 */}
      <SectionCard
        title="去广告与隐私过滤规则库"
        icon={<Layers className="w-4 h-4" />}
        subtitle="默认仅开启官方低误杀基础规则；可按需一键叠加中文增强与轻量规则"
        actions={
          <div className="flex items-center gap-2">
            <Button
              size="xs"
              variant="ghost"
              onClick={() => setShowCustomFilter((v) => !v)}
              icon={<Plus className="w-3.5 h-3.5" />}
            >
              自定义订阅
            </Button>
            <Button
              size="xs"
              variant="secondary"
              disabled={mutating || !snap?.webHealthy}
              onClick={handleRefreshFilters}
              icon={<RefreshCw className="w-3.5 h-3.5" />}
            >
              更新规则库
            </Button>
          </div>
        }
      >
        <div className="space-y-4">
          {snap?.isOpenWrt && (snap.totalRulesCount || 0) > 150000 && (
            <div className="p-3 rounded-xl bg-amber-500/10 border border-amber-500/25 text-xs text-amber-300">
              软路由内存提示：当前启用规则总数已超过 {formatNumber(snap.totalRulesCount)} 条，小内存 OpenWrt 设备建议保持在 15 万条以内以兼顾流畅度。
            </div>
          )}

          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {(snap?.presets || []).map((preset) => (
              <div
                key={preset.id}
                className="p-3.5 rounded-xl border bg-surface2 border-subtle flex items-start justify-between gap-3"
              >
                <div className="min-w-0 flex-1 space-y-1">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="text-xs sm:text-sm font-semibold text-primary">
                      {preset.name}
                    </span>
                    {preset.recommended && <Badge tone="accent">推荐</Badge>}
                    {preset.enabled && preset.rulesCount > 0 && (
                      <span className="text-[11px] font-mono text-muted tnum">
                        {formatNumber(preset.rulesCount)} 条
                      </span>
                    )}
                  </div>
                  <p className="text-[11px] sm:text-xs text-secondary leading-relaxed">
                    {preset.desc}
                  </p>
                </div>
                <Button
                  size="xs"
                  variant={preset.enabled ? 'primary' : 'secondary'}
                  disabled={mutating || !snap?.webHealthy}
                  onClick={() => handleFilterToggle(preset.url, preset.name, !preset.enabled)}
                >
                  {preset.enabled ? '已启用' : '启用'}
                </Button>
              </div>
            ))}
          </div>

          {showCustomFilter && (
            <form
              onSubmit={handleAddCustomFilter}
              className="p-3.5 rounded-xl bg-surface2 border border-subtle grid grid-cols-1 sm:grid-cols-12 gap-2"
            >
              <input
                type="text"
                value={customFilterName}
                onChange={(e) => setCustomFilterName(e.target.value)}
                placeholder="规则名称（选填）"
                className="sm:col-span-4 h-9 px-3 rounded-xl bg-surface border border-subtle text-xs text-primary focus:outline-none focus:border-strong"
              />
              <input
                type="url"
                value={customFilterUrl}
                onChange={(e) => setCustomFilterUrl(e.target.value)}
                placeholder="https://example.com/filter.txt"
                className="sm:col-span-6 h-9 px-3 rounded-xl bg-surface border border-subtle text-xs font-mono text-primary focus:outline-none focus:border-strong"
              />
              <div className="sm:col-span-2">
                <Button
                  type="submit"
                  size="sm"
                  variant="primary"
                  className="w-full h-9"
                  disabled={mutating || !snap?.webHealthy}
                >
                  添加订阅
                </Button>
              </div>
            </form>
          )}

          {extraCustomFilters.length > 0 && (
            <div className="divide-y divide-[var(--border-subtle)] text-xs sm:text-sm pt-1">
              {extraCustomFilters.map((f) => (
                <div key={f.url} className="flex items-center justify-between gap-3 py-2">
                  <div className="min-w-0 flex-1">
                    <div className="font-medium text-primary truncate">{f.name}</div>
                    <div className="text-[11px] font-mono text-muted truncate">
                      {f.url} · {formatNumber(f.rulesCount)} 条
                    </div>
                  </div>
                  <div className="flex items-center gap-1.5 shrink-0">
                    <Button
                      size="xs"
                      variant={f.enabled ? 'primary' : 'secondary'}
                      disabled={mutating || !snap?.webHealthy}
                      onClick={() => handleFilterToggle(f.url, f.name, !f.enabled)}
                    >
                      {f.enabled ? '已启用' : '已停用'}
                    </Button>
                    <Button
                      size="xs"
                      variant="ghost"
                      disabled={mutating || !snap?.webHealthy}
                      onClick={() => handleRemoveCustomFilter(f.url, f.name)}
                      icon={<Trash2 className="w-3.5 h-3.5" />}
                    />
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </SectionCard>

      {/* 服务生命周期管理（零断网闭环） */}
      <SectionCard
        title="服务生命周期与安全切换"
        subtitle="停用或卸载时会自动先将 sing-box dns_local 平滑切回内置纯 IP 加密 DoH，确保全屋网关零断网"
      >
        <div className="flex flex-wrap items-center gap-2.5">
          {snap?.dnsHealthy ? (
            <>
              <Button
                size="sm"
                variant="secondary"
                disabled={busy}
                icon={<RotateCw className="w-3.5 h-3.5" />}
                onClick={() => onAction('dns-restart')}
              >
                重启服务
              </Button>
              <Button
                size="sm"
                variant="secondary"
                disabled={busy}
                onClick={() =>
                  onAction(
                    'dns-stop',
                    {},
                    '确认停用本地 AdGuard Home 接管？系统将自动先把 sing-box 切回内置纯 IP 加密 DoH，不会中断当前网络。',
                  )
                }
              >
                安全停用接管
              </Button>
            </>
          ) : (
            <Button
              size="sm"
              variant="primary"
              disabled={busy}
              icon={<Power className="w-3.5 h-3.5" />}
              onClick={() => onAction('dns-start')}
            >
              启动并接管 DNS
            </Button>
          )}

          <Button
            size="sm"
            variant="secondary"
            disabled={busy}
            icon={<Download className="w-3.5 h-3.5" />}
            onClick={() => onAction('dns-update')}
          >
            更新核心版本
          </Button>

          <Button
            size="sm"
            variant="danger"
            disabled={busy}
            onClick={() =>
              onAction(
                'dns-uninstall',
                { purge: false },
                '确认卸载 AdGuard Home？（将自动先切回 sing-box 内置加密 DNS 保证不断网，并保留 /etc/AdGuardHome 自定义规则目录以备重装恢复）',
              )
            }
          >
            安全卸载
          </Button>
        </div>
      </SectionCard>

      {/* 原生面板与登录凭据抽屉 */}
      <SlideDrawer
        open={credOpen}
        onClose={() => setCredOpen(false)}
        title="原生 AdGuard Home 面板与凭据"
        subtitle="仅供需要查看完整查询明细或高阶调优时使用（仅绑定局域网私网 IP，绝不暴露公网）"
      >
        <div className="space-y-4 py-1 text-xs sm:text-sm">
          {credLoading ? (
            <div className="py-8 text-center text-muted">正在读取凭据…</div>
          ) : (
            <>
              <div className="p-3.5 rounded-xl bg-surface2 border border-subtle space-y-2.5">
                <div className="flex items-center justify-between gap-2">
                  <span className="text-secondary">局域网访问地址</span>
                  <div className="flex items-center gap-1.5">
                    <Button
                      size="xs"
                      variant="ghost"
                      onClick={() =>
                        copyText(credData?.webUrl || snap?.webUrl || '', '已复制面板地址')
                      }
                      icon={<Copy className="w-3 h-3" />}
                    >
                      复制
                    </Button>
                    {(credData?.webUrl || snap?.webUrl) && (
                      <a
                        href={credData?.webUrl || snap?.webUrl}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="inline-flex items-center gap-1 px-2.5 py-1 rounded-lg text-xs font-semibold bg-[var(--accent)] text-white"
                      >
                        <span>打开面板</span>
                        <ExternalLink className="w-3 h-3" />
                      </a>
                    )}
                  </div>
                </div>
                <div className="font-mono text-primary break-all">
                  {credData?.webUrl || snap?.webUrl || '-'}
                </div>
              </div>

              <div className="p-3.5 rounded-xl bg-surface2 border border-subtle space-y-3">
                <div className="flex items-center justify-between gap-2">
                  <span className="text-secondary">管理员账号</span>
                  <div className="flex items-center gap-2">
                    <span className="font-mono font-semibold text-primary">
                      {credData?.username || snap?.username || 'root'}
                    </span>
                    <Button
                      size="xs"
                      variant="ghost"
                      onClick={() =>
                        copyText(credData?.username || snap?.username || 'root', '已复制管理员账号')
                      }
                      icon={<Copy className="w-3 h-3" />}
                    />
                  </div>
                </div>

                <div className="flex items-center justify-between gap-2 pt-2 border-t border-subtle">
                  <span className="text-secondary">管理员密码</span>
                  {credData?.password ? (
                    <div className="flex items-center gap-1.5">
                      <span className="font-mono text-primary">
                        {showPwd ? credData.password : '••••••••••••••••'}
                      </span>
                      <Button
                        size="xs"
                        variant="ghost"
                        onClick={() => setShowPwd((v) => !v)}
                        icon={
                          showPwd ? (
                            <EyeOff className="w-3.5 h-3.5" />
                          ) : (
                            <Eye className="w-3.5 h-3.5" />
                          )
                        }
                      />
                      <Button
                        size="xs"
                        variant="secondary"
                        onClick={() => copyText(credData.password, '已复制管理员密码')}
                        icon={<Copy className="w-3 h-3" />}
                      >
                        复制密码
                      </Button>
                    </div>
                  ) : (
                    <span className="text-muted text-xs">密码已哈希落盘，点击下方可一键重置</span>
                  )}
                </div>
              </div>

              <div className="pt-2 flex items-center justify-between gap-2">
                <span className="text-[11px] text-muted">
                  重置不会影响已添加的去广告规则库与内网重写映射
                </span>
                <Button
                  size="sm"
                  variant="secondary"
                  loading={resettingPwd}
                  onClick={handleResetPassword}
                >
                  生成新随机密码
                </Button>
              </div>
            </>
          )}
        </div>
      </SlideDrawer>
    </div>
  );
};

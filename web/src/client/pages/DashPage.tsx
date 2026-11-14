import React, { useEffect, useState } from 'react';
import {
  Activity,
  Box,
  Dog,
  ShieldCheck,
  Share2,
  Flame,
  QrCode,
  SlidersHorizontal,
  Copy,
  CheckCircle2,
  XCircle,
  Zap,
  Globe,
  ExternalLink,
} from 'lucide-react';
import {
  Badge,
  Button,
  PageHeader,
  QRCodeBox,
  SectionCard,
  SlideDrawer,
  useToast,
} from '../../ui';
import { clientApi } from '../api';
import { ClientHealthResponse, ClientStatusResponse, SbProxiesSnapshot } from '../types';

export interface DashPageProps {
  status: ClientStatusResponse | null;
  busy: boolean;
  onAction: (name: string, params?: Record<string, unknown>, confirmMsg?: string) => void;
  onNavigate: (tab: string, sub?: string) => void;
}

function getTailscaleBadge(ts: ClientStatusResponse['tailscale']): {
  text: string;
  tone: 'ok' | 'warn' | 'neutral';
  pulse?: boolean;
} {
  if (!ts.installed) return { text: '未安装', tone: 'warn' };
  if (!ts.running) return { text: '未运行', tone: 'neutral' };
  if (ts.state === 'Running') return { text: '已连接', tone: 'ok', pulse: true };
  if (ts.state === 'NeedsLogin' || ts.state === 'NeedsMachineAuth' || ts.state === 'Starting') {
    return { text: '待认证', tone: 'warn' };
  }
  return { text: ts.state || '运行中', tone: 'ok', pulse: true };
}

export const DashPage: React.FC<DashPageProps> = ({ status, busy, onAction, onNavigate }) => {
  const { success, error } = useToast();
  const [health, setHealth] = useState<ClientHealthResponse | null>(null);
  const [checkingHealth, setCheckingHealth] = useState(false);
  const [iosOpen, setIosOpen] = useState(false);
  const [iosUrl, setIosUrl] = useState('');
  const [iosImportUrl, setIosImportUrl] = useState('');
  const [iosQrMode, setIosQrMode] = useState<'import' | 'raw'>('import');
  const [iosLoading, setIosLoading] = useState(false);
  const [proxySnap, setProxySnap] = useState<SbProxiesSnapshot | null>(null);

  const sbRunning = !!status?.singbox?.running;
  useEffect(() => {
    if (!sbRunning) {
      setProxySnap(null);
      return;
    }
    let cancelled = false;
    clientApi
      .getSbProxies()
      .then((res) => {
        if (!cancelled) setProxySnap(res);
      })
      .catch(() => {
        if (!cancelled) setProxySnap(null);
      });
    return () => {
      cancelled = true;
    };
  }, [sbRunning]);

  const runHealthCheck = async () => {
    setCheckingHealth(true);
    try {
      const res = await clientApi.getHealth();
      setHealth(res);
    } catch (err: unknown) {
      setHealth({
        healthy: false,
        dnsOK: false,
        details: err instanceof Error ? err.message : '检测失败',
        checkTime: new Date().toLocaleTimeString(),
      });
    } finally {
      setCheckingHealth(false);
    }
  };

  const openIOSDrawer = async () => {
    setIosOpen(true);
    setIosLoading(true);
    try {
      const res = await clientApi.getIOSUrl();
      setIosUrl(res.url);
      setIosImportUrl(
        res.importUrl || `sing-box://import-remote-profile?url=${encodeURIComponent(res.url)}`,
      );
    } catch (err: unknown) {
      error(err instanceof Error ? err.message : '获取 iOS 配置地址失败');
    } finally {
      setIosLoading(false);
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

  if (!status) {
    return (
      <div className="space-y-5">
        <PageHeader title="系统总览" description="正在连接网关状态接口…" />
      </div>
    );
  }

  const { singbox: sb, daemon: dm, adguard: agh, tailscale: ts, firewall: fw, host, config } = status;
  const tsBadgeInfo = getTailscaleBadge(ts);
  const subs = config?.subs || [];
  const primaryExitText = !sb.running
    ? 'sing-box 启动后可用'
    : proxySnap?.primaryNode
      ? `${proxySnap.primaryGroup || 'Proxy'} → ${proxySnap.primaryNode}${proxySnap.primaryDelay && proxySnap.primaryDelay > 0 ? ` (${proxySnap.primaryDelay}ms)` : ''}`
      : proxySnap?.error
        ? '节点状态暂不可用'
        : '读取中…';

  return (
    <div className="space-y-5">
      <PageHeader
        title="系统总览"
        description={`${host.hostname || 'singctl'} · ${host.os}/${host.arch}${host.openwrt ? ' (OpenWrt)' : ''} · ${host.lanIP || '127.0.0.1'}`}
        badge={
          <Badge tone={sb.running ? 'ok' : 'danger'} dot pulse={sb.running}>
            {sb.running ? '代理运行中' : '代理已停止'}
          </Badge>
        }
        actions={
          <>
            <Button
              variant="secondary"
              size="sm"
              loading={checkingHealth}
              onClick={runHealthCheck}
              icon={<Activity className="w-3.5 h-3.5" />}
            >
              健康检测
            </Button>
            <Button
              variant="primary"
              size="sm"
              onClick={openIOSDrawer}
              icon={<QrCode className="w-3.5 h-3.5" />}
            >
              iOS 扫码导入
            </Button>
          </>
        }
      />

      {/* Health Check Result Banner */}
      {health && (
        <div
          className="console-card rounded-2xl p-4 flex items-start gap-3 border animate-sc-in"
          style={{
            borderColor: health.healthy ? 'var(--status-ok)' : 'var(--status-danger)',
            backgroundColor: health.healthy ? 'var(--status-ok-soft)' : 'var(--status-danger-soft)',
          }}
        >
          {health.healthy ? (
            <CheckCircle2 className="w-5 h-5 shrink-0 mt-0.5" style={{ color: 'var(--status-ok)' }} />
          ) : (
            <XCircle className="w-5 h-5 shrink-0 mt-0.5" style={{ color: 'var(--status-danger)' }} />
          )}
          <div className="min-w-0 flex-1 text-xs sm:text-sm">
            <div className="font-semibold text-primary">
              {health.healthy ? '网关连通性与内部 DNS 解析健康' : '检测到网络或 DNS 异常'}
            </div>
            <div className="text-secondary mt-0.5 break-words">{health.details || health.failedReason}</div>
            <div className="text-[11px] font-mono text-muted mt-1 tnum">检测时间：{health.checkTime}</div>
          </div>
        </div>
      )}

      {/* Core KPI Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-5 gap-4">
        {/* sing-box */}
        <div className="console-card rounded-2xl p-4 flex flex-col justify-between gap-4">
          <div className="flex items-start justify-between gap-2">
            <div
              className="w-9 h-9 rounded-xl flex items-center justify-center shrink-0"
              style={{
                backgroundColor: sb.running ? 'var(--status-ok-soft)' : 'var(--bg-surface-2)',
                color: sb.running ? 'var(--status-ok)' : 'var(--text-secondary)',
              }}
            >
              <Box className="w-4.5 h-4.5" />
            </div>
            <Badge tone={sb.running ? 'ok' : sb.installed ? 'neutral' : 'warn'} dot pulse={sb.running}>
              {sb.running ? '运行中' : sb.installed ? '已停止' : '未安装'}
            </Badge>
          </div>
          <div>
            <div className="text-sm font-semibold text-primary">sing-box 内核</div>
            <div className="text-xs text-secondary mt-1 tnum">
              {sb.version ? `v${sb.version}` : '版本未知'} · {sb.configExists ? '配置就绪' : '未生成配置'}
            </div>
          </div>
          <div className="flex items-center gap-2 flex-wrap pt-1 border-t border-subtle">
            {sb.running ? (
              <>
                <Button size="xs" disabled={busy} onClick={() => onAction('sb-restart')}>
                  重启
                </Button>
                <Button
                  size="xs"
                  variant="danger"
                  disabled={busy}
                  onClick={() => onAction('sb-stop', {}, '确认停止 sing-box？这会中断当前代理连接。')}
                >
                  停止
                </Button>
              </>
            ) : (
              <Button size="xs" variant="primary" disabled={busy} onClick={() => onAction('sb-start')}>
                启动
              </Button>
            )}
            <Button size="xs" variant="ghost" onClick={() => onNavigate('sb')}>
              管理
            </Button>
          </div>
        </div>

        {/* AdGuard Home Anti-Hijack DNS */}
        <div className="console-card rounded-2xl p-4 flex flex-col justify-between gap-4">
          <div className="flex items-start justify-between gap-2">
            <div
              className="w-9 h-9 rounded-xl flex items-center justify-center shrink-0"
              style={{
                backgroundColor: agh?.dnsHealthy ? 'var(--status-ok-soft)' : 'var(--bg-surface-2)',
                color: agh?.dnsHealthy ? 'var(--status-ok)' : 'var(--text-secondary)',
              }}
            >
              <ShieldCheck className="w-4.5 h-4.5" />
            </div>
            <Badge
              tone={
                !agh?.installed
                  ? 'neutral'
                  : !agh.dnsHealthy
                    ? 'danger'
                    : agh.singboxLinked
                      ? 'ok'
                      : 'warn'
              }
              dot={Boolean(agh?.dnsHealthy)}
              pulse={Boolean(agh?.dnsHealthy && agh?.singboxLinked)}
            >
              {!agh?.installed
                ? '未安装'
                : !agh.dnsHealthy
                  ? '已停止'
                  : agh.singboxLinked
                    ? '防劫持接管'
                    : '待接管'}
            </Badge>
          </div>
          <div>
            <div className="text-sm font-semibold text-primary">防劫持 DNS</div>
            <div className="text-xs text-secondary mt-1 tnum truncate">
              {agh?.installed
                ? `${agh.dnsAddr || '127.0.0.1:5353'} · ${agh.singboxLinked ? '已联动内核' : '内置 DoH 兜底'}`
                : '本地 AdGuard Home 加密 DoH'}
            </div>
          </div>
          <div className="flex items-center gap-2 flex-wrap pt-1 border-t border-subtle">
            {!agh?.installed ? (
              <Button
                size="xs"
                variant="primary"
                disabled={busy || agh?.supported === false}
                onClick={() => onAction('dns-install')}
              >
                安装
              </Button>
            ) : agh.dnsHealthy && agh.singboxLinked ? (
              <Button size="xs" disabled={busy} onClick={() => onAction('dns-restart')}>
                重启
              </Button>
            ) : (
              <Button size="xs" variant="primary" disabled={busy} onClick={() => onAction('dns-start')}>
                接管
              </Button>
            )}
            <Button size="xs" variant="ghost" onClick={() => onNavigate('dns')}>
              管理
            </Button>
          </div>
        </div>

        {/* Watchdog */}
        <div className="console-card rounded-2xl p-4 flex flex-col justify-between gap-4">
          <div className="flex items-start justify-between gap-2">
            <div
              className="w-9 h-9 rounded-xl flex items-center justify-center shrink-0"
              style={{
                backgroundColor: dm.running ? 'var(--accent-soft)' : 'var(--bg-surface-2)',
                color: dm.running ? 'var(--accent)' : 'var(--text-secondary)',
              }}
            >
              <Dog className="w-4.5 h-4.5" />
            </div>
            <Badge
              tone={
                !dm.running
                  ? 'neutral'
                  : (dm.activeFailoverCount || 0) > 0 || dm.versionMismatch
                  ? 'warn'
                  : 'ok'
              }
              dot={dm.running}
            >
              {!dm.running
                ? '未运行'
                : (dm.activeFailoverCount || 0) > 0
                ? `${dm.activeFailoverCount} 组容灾中`
                : dm.versionMismatch
                ? '待重启升级'
                : '守护中'}
            </Badge>
          </div>
          <div>
            <div className="text-sm font-semibold text-primary">看门狗守护</div>
            <div className="text-xs text-secondary mt-1 tnum">
              {dm.running
                ? `${dm.failoverEnabled !== false ? '容灾已开启' : '容灾已关闭'} · 1h 重启 ${dm.restarts}/${dm.maxRestarts}`
                : '异常或断流时不会自动自愈切换'}
            </div>
          </div>
          <div className="flex items-center gap-2 flex-wrap pt-1 border-t border-subtle">
            {dm.running ? (
              <>
                <Button size="xs" disabled={busy} onClick={() => onAction('dm-restart')}>
                  平滑重启
                </Button>
                <Button
                  size="xs"
                  variant="danger"
                  disabled={busy}
                  onClick={() => onAction('dm-stop', {}, '确认停止看门狗守护进程？')}
                >
                  停止
                </Button>
              </>
            ) : (
              <Button size="xs" variant="primary" disabled={busy} onClick={() => onAction('dm-start')}>
                启动
              </Button>
            )}
            <Button size="xs" variant="ghost" onClick={() => onNavigate('dm')}>
              策略
            </Button>
          </div>
        </div>

        {/* Tailscale */}
        <div className="console-card rounded-2xl p-4 flex flex-col justify-between gap-4">
          <div className="flex items-start justify-between gap-2">
            <div
              className="w-9 h-9 rounded-xl flex items-center justify-center shrink-0"
              style={{
                backgroundColor: ts.running ? 'var(--accent-soft)' : 'var(--bg-surface-2)',
                color: ts.running ? 'var(--accent)' : 'var(--text-secondary)',
              }}
            >
              <Share2 className="w-4.5 h-4.5" />
            </div>
            <Badge tone={tsBadgeInfo.tone} dot pulse={tsBadgeInfo.pulse}>
              {tsBadgeInfo.text}
            </Badge>
          </div>
          <div>
            <div className="text-sm font-semibold text-primary">Tailscale 组网</div>
            <div className="text-xs text-secondary mt-1 tnum truncate">
              {ts.version ? `v${ts.version}` : ts.installed ? '已安装' : '未安装'}
              {ts.mode ? ` · ${ts.mode}` : ''}
              {ts.authKeySet ? ' · auth_key 就绪' : ''}
            </div>
          </div>
          <div className="flex items-center gap-2 flex-wrap pt-1 border-t border-subtle">
            {ts.installed ? (
              <>
                <Button size="xs" disabled={busy} onClick={() => onAction('ts-start')}>
                  启动
                </Button>
                <Button size="xs" variant="danger" disabled={busy} onClick={() => onAction('ts-stop')}>
                  停止
                </Button>
              </>
            ) : (
              <Button size="xs" variant="primary" disabled={busy} onClick={() => onAction('ts-install')}>
                安装
              </Button>
            )}
            <Button size="xs" variant="ghost" onClick={() => onNavigate('ts')}>
              配置
            </Button>
          </div>
        </div>

        {/* Firewall */}
        <div className="console-card rounded-2xl p-4 flex flex-col justify-between gap-4">
          <div className="flex items-start justify-between gap-2">
            <div
              className="w-9 h-9 rounded-xl flex items-center justify-center shrink-0"
              style={{
                backgroundColor: fw.enabled ? 'var(--status-ok-soft)' : 'var(--bg-surface-2)',
                color: fw.enabled ? 'var(--status-ok)' : 'var(--text-secondary)',
              }}
            >
              <Flame className="w-4.5 h-4.5" />
            </div>
            <Badge tone={!fw.supported ? 'warn' : fw.enabled ? 'ok' : 'neutral'} dot={fw.enabled}>
              {!fw.supported ? '不支持' : fw.enabled ? '已加固' : '未启用'}
            </Badge>
          </div>
          <div>
            <div className="text-sm font-semibold text-primary">防火墙安全加固</div>
            <div className="text-xs text-secondary mt-1">
              {fw.supported ? 'nftables inet security 表保护' : '仅 Linux / OpenWrt 网关支持'}
            </div>
          </div>
          <div className="flex items-center gap-2 flex-wrap pt-1 border-t border-subtle">
            {fw.supported ? (
              fw.enabled ? (
                <Button
                  size="xs"
                  variant="danger"
                  disabled={busy}
                  onClick={() => onAction('fw-disable', {}, '确认禁用并移除防火墙加固规则？')}
                >
                  禁用规则
                </Button>
              ) : (
                <Button size="xs" variant="primary" disabled={busy} onClick={() => onAction('fw-enable')}>
                  启用加固
                </Button>
              )
            ) : (
              <Button size="xs" variant="ghost" onClick={() => onNavigate('fw')}>
                详情
              </Button>
            )}
          </div>
        </div>
      </div>

      {/* Host & Subscriptions Two-Column Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <SectionCard
          title="主机与网关环境"
          icon={<Globe className="w-4 h-4" />}
          actions={
            sb.running ? (
              <Button
                size="xs"
                onClick={() => onNavigate('sb', 'nodes')}
                icon={<SlidersHorizontal className="w-3 h-3" />}
              >
                选择节点
              </Button>
            ) : undefined
          }
        >
          <div className="divide-y divide-[var(--border-subtle)] text-xs sm:text-sm">
            {[
              ['主机名称', host.hostname || '-'],
              ['运行架构', `${host.os} / ${host.arch}${host.openwrt ? ' · OpenWrt' : ''}`],
              ['局域网 IP', host.lanIP || '-'],
              ['SingCtl 版本', `v${String(status.singctlVersion || 'dev').replace(/^v/, '')}`],
              ['当前主出口', primaryExitText],
            ].map(([k, v]) => (
              <div key={k} className="flex items-center justify-between gap-4 py-2.5">
                <span className="text-secondary shrink-0">{k}</span>
                <span className="font-mono text-primary truncate tnum">{v}</span>
              </div>
            ))}
          </div>
        </SectionCard>

        <SectionCard
          title="订阅配置摘要"
          icon={<Zap className="w-4 h-4" />}
          subtitle={config?.path || ''}
          actions={
            <Button size="xs" onClick={() => onNavigate('config')}>
              编辑订阅
            </Button>
          }
        >
          {config?.error ? (
            <div className="text-xs text-red-400 py-4">{config.error}</div>
          ) : subs.length === 0 ? (
            <div className="py-6 text-center space-y-2">
              <p className="text-xs text-muted">尚未配置任何机场订阅</p>
              <Button size="xs" variant="primary" onClick={() => onNavigate('config')}>
                去添加订阅
              </Button>
            </div>
          ) : (
            <div className="divide-y divide-[var(--border-subtle)] text-xs sm:text-sm">
              {subs.map((sub, i) => (
                <div key={i} className="flex items-center justify-between gap-4 py-2.5">
                  <span className="font-medium text-primary truncate">{sub.name || `订阅 ${i + 1}`}</span>
                  <span className="font-mono text-secondary truncate">{sub.urlHint || '-'}</span>
                </div>
              ))}
            </div>
          )}
          <div className="mt-3 pt-3 border-t border-subtle flex items-center justify-between gap-2 flex-wrap">
            <span className="text-xs text-muted">快速重建分流配置并热加载</span>
            <Button size="xs" variant="secondary" disabled={busy} onClick={() => onAction('sb-gen')}>
              从订阅重新生成配置
            </Button>
          </div>
        </SectionCard>
      </div>

      {/* iOS SFI Import Drawer */}
      <SlideDrawer
        open={iosOpen}
        onClose={() => setIosOpen(false)}
        title="iOS · Sing-Box (SFI) 扫码导入"
        subtitle="同一局域网手机相机或 SFI App 扫描即可同步完整远程分流配置"
      >
        <div className="flex flex-col items-center text-center space-y-4 py-2">
          {iosLoading ? (
            <div className="w-44 h-44 rounded-2xl bg-surface2 animate-pulse" />
          ) : iosUrl ? (
            <>
              <div className="inline-flex items-center p-1 rounded-xl bg-surface2 border border-subtle text-xs">
                <button
                  type="button"
                  onClick={() => setIosQrMode('import')}
                  className={`px-3 py-1 rounded-lg font-medium transition-colors cursor-pointer ${
                    iosQrMode === 'import'
                      ? 'bg-[var(--accent)] text-white shadow-sm'
                      : 'text-secondary hover:text-primary'
                  }`}
                >
                  SFI 一键扫码导入
                </button>
                <button
                  type="button"
                  onClick={() => setIosQrMode('raw')}
                  className={`px-3 py-1 rounded-lg font-medium transition-colors cursor-pointer ${
                    iosQrMode === 'raw'
                      ? 'bg-[var(--accent)] text-white shadow-sm'
                      : 'text-secondary hover:text-primary'
                  }`}
                >
                  纯配置链接
                </button>
              </div>
              <QRCodeBox value={iosQrMode === 'import' ? iosImportUrl : iosUrl} size={184} />
              <div className="w-full p-3 rounded-xl bg-surface2 border border-subtle font-mono text-xs text-primary break-all select-all">
                {iosUrl}
              </div>
              <div className="flex flex-wrap items-center justify-center gap-2">
                <a
                  href={iosImportUrl}
                  className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-xl text-xs font-semibold bg-emerald-500 hover:bg-emerald-400 text-slate-950 shadow-sm transition-colors"
                >
                  <ExternalLink className="w-3.5 h-3.5" />
                  一键打开 Sing-Box 导入
                </a>
                <Button
                  variant="primary"
                  onClick={() => copyText(iosUrl, '已复制 iOS 配置同步地址')}
                  icon={<Copy className="w-3.5 h-3.5" />}
                >
                  复制配置链接
                </Button>
                <Button
                  variant="secondary"
                  onClick={() => {
                    window.open(iosUrl, '_blank', 'noopener');
                  }}
                >
                  直接下载 JSON
                </Button>
              </div>
            </>
          ) : (
            <p className="text-xs text-muted">未能生成链接，请确认已配置订阅且处于局域网中。</p>
          )}
        </div>
      </SlideDrawer>
    </div>
  );
};

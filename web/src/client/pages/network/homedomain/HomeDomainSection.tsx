import React, { useCallback, useEffect, useMemo, useState } from 'react';
import {
  AlertTriangle,
  BookOpen,
  CheckCircle2,
  Copy,
  ExternalLink,
  Globe,
  Laptop,
  Pencil,
  Plus,
  Radio,
  RefreshCw,
  Router,
  Share2,
  Sparkles,
  Terminal,
  Trash2,
  Zap,
} from 'lucide-react';
import { Badge, Button, ConfirmDialog, SectionCard, useToast } from '../../../../ui';
import { maskFullIP, maskSensitiveText } from '../../../../lib/privacyMask';
import { clientApi } from '../../../api';
import { copyPlainText } from '../../../lib/leakProbes';
import {
  HomeDomainDeviceUpsertPayload,
  HomeDomainDeviceView,
  HomeDomainOverviewResponse,
  HomeDomainService,
  HomeDomainVerifyReport,
} from '../../../types';
import { DeviceEditDrawer, DeviceEditInitial } from './DeviceEditDrawer';
import { SplitDNSGuideDrawer } from './SplitDNSGuideDrawer';

export interface HomeDomainSectionProps {
  busy?: boolean;
  privacyMask?: boolean;
  onRefreshStatus?: () => void;
}

const SUFFIX_OPTIONS = [
  { value: 'home', label: '.home（默认推荐 · 最短顺手）' },
  { value: 'home.arpa', label: '.home.arpa（RFC 8375 标准）' },
  { value: 'lan', label: '.lan（传统局域网）' },
];

export const HomeDomainSection: React.FC<HomeDomainSectionProps> = ({
  busy = false,
  privacyMask = false,
  onRefreshStatus,
}) => {
  const { success, error, toast } = useToast();
  const [data, setData] = useState<HomeDomainOverviewResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [discoverTab, setDiscoverTab] = useState<'lan' | 'ts'>('lan');

  const [drawerOpen, setDrawerOpen] = useState(false);
  const [drawerInit, setDrawerInit] = useState<DeviceEditInitial | null>(null);
  const [guideOpen, setGuideOpen] = useState(false);
  const [verifying, setVerifying] = useState(false);
  const [verifyReport, setVerifyReport] = useState<HomeDomainVerifyReport | null>(null);
  const [deleteTarget, setDeleteTarget] = useState<HomeDomainDeviceView | null>(null);

  const loadOverview = useCallback(async () => {
    setLoading(true);
    try {
      const res = await clientApi.getHomeDomain();
      setData(res);
    } catch (err) {
      error((err as Error)?.message || '读取本地域名配置失败');
    } finally {
      setLoading(false);
    }
  }, [error]);

  useEffect(() => {
    void loadOverview();
  }, [loadOverview]);

  const suffix = data?.suffix || 'home';
  const selfAlreadyNamed = useMemo(() => {
    if (!data?.self) return true;
    const selfIPs = new Set([data.self.lanIp, data.self.tailscaleIp].filter(Boolean));
    return data.devices.some((d) => selfIPs.has(d.ip) || d.source === 'self');
  }, [data]);

  const handleSaveSettings = async (patch: {
    enabled?: boolean;
    suffix?: string;
    tailscaleDns?: boolean;
    followDhcp?: boolean;
  }) => {
    if (!data) return;
    setSaving(true);
    try {
      const next = await clientApi.saveHomeDomainSettings({
        enabled: patch.enabled ?? data.enabled,
        suffix: patch.suffix ?? data.suffix,
        tailscaleDns: patch.tailscaleDns ?? data.tailscaleDns,
        followDhcp: patch.followDhcp ?? data.followDhcp,
      });
      setData(next);
      success('本地域名设置已保存并同步生效');
      onRefreshStatus?.();
    } catch (err) {
      error((err as Error)?.message || '保存设置失败');
    } finally {
      setSaving(false);
    }
  };

  const handleUpsertDevice = async (payload: HomeDomainDeviceUpsertPayload): Promise<boolean> => {
    setSaving(true);
    try {
      const next = await clientApi.upsertHomeDomainDevice(payload);
      setData(next);
      success(`已同步 ${payload.alias}.${next.suffix} → ${privacyMask ? '•••' : payload.ip}`);
      onRefreshStatus?.();
      return true;
    } catch (err) {
      error((err as Error)?.message || '保存设备失败');
      return false;
    } finally {
      setSaving(false);
    }
  };

  const handleDeleteDevice = async () => {
    if (!deleteTarget) return;
    setSaving(true);
    try {
      const next = await clientApi.deleteHomeDomainDevice(deleteTarget.alias);
      setData(next);
      success(`已移除 ${deleteTarget.fqdn}`);
      setDeleteTarget(null);
      onRefreshStatus?.();
    } catch (err) {
      error((err as Error)?.message || '删除设备失败');
    } finally {
      setSaving(false);
    }
  };

  const handleRunVerify = async () => {
    setVerifying(true);
    setGuideOpen(true);
    try {
      const rep = await clientApi.verifyHomeDomain();
      setVerifyReport(rep);
      if (rep.overallOk) {
        success('四项端到端本地域名自检全部通过');
      } else {
        toast('端到端自检发现待处理项，请查看抽屉详情', 'warn');
      }
    } catch (err) {
      error((err as Error)?.message || '端到端自检失败');
    } finally {
      setVerifying(false);
    }
  };

  const handleCopyText = async (label: string, text: string) => {
    try {
      await copyPlainText(text);
      success(`已复制 ${label}`);
    } catch {
      toast('复制失败，请手动选中复制', 'warn');
    }
  };

  const openQuickAddSelf = () => {
    if (!data?.self) return;
    const ip = data.self.lanIp || data.self.tailscaleIp || '';
    setDrawerInit({
      alias: data.self.suggestedAlias || 'router',
      displayName: `主路由 (${data.self.hostname || '本机'})`,
      ip,
      source: 'self',
      services: [
        { label: 'SingCtl WebUI', scheme: 'http', port: 8090 },
        { label: 'SSH', scheme: 'ssh', port: 22 },
      ],
    });
    setDrawerOpen(true);
  };

  const renderServiceButton = (fqdn: string, svc: HomeDomainService, idx: number) => {
    const scheme = (svc.scheme || 'http').toLowerCase();
    if (scheme === 'ssh') {
      const portArg = svc.port && svc.port !== 22 ? ` -p ${svc.port}` : '';
      const sshCmd = `ssh root@${fqdn}${portArg}`;
      return (
        <button
          key={idx}
          type="button"
          onClick={() => void handleCopyText('SSH 命令', sshCmd)}
          title={`复制命令：${sshCmd}`}
          className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md text-[11px] font-mono bg-surface2 hover:bg-surface3 border border-subtle text-secondary hover:text-primary transition-colors cursor-pointer"
        >
          <Terminal className="w-3 h-3 text-emerald-400" />
          <span>{svc.label || 'SSH'}</span>
        </button>
      );
    }
    const defaultPort = scheme === 'https' ? 443 : 80;
    const portSuffix = svc.port && svc.port !== defaultPort ? `:${svc.port}` : '';
    const href = `${scheme}://${fqdn}${portSuffix}`;
    return (
      <a
        key={idx}
        href={href}
        target="_blank"
        rel="noreferrer"
        title={`打开 ${href}`}
        className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md text-[11px] font-mono bg-sky-500/10 hover:bg-sky-500/20 border border-sky-500/25 text-sky-300 transition-colors"
      >
        <span>{svc.label || `${scheme.toUpperCase()}${portSuffix}`}</span>
        <ExternalLink className="w-2.5 h-2.5" />
      </a>
    );
  };

  const responderBadge = useMemo(() => {
    if (!data) return <Badge tone="neutral">加载中</Badge>;
    if (!data.enabled) return <Badge tone="neutral">已暂停</Badge>;
    if (!data.tailscaleDns) return <Badge tone="neutral">仅局域网模式</Badge>;
    if (data.responder?.running) {
      return (
        <Badge tone="ok" dot pulse>
          Split-DNS 运行中 ({maskFullIP(data.responder.listenAddr || '', privacyMask)})
        </Badge>
      );
    }
    if (data.devices.length === 0) {
      return <Badge tone="accent">添加首台设备后自动拉起</Badge>;
    }
    return <Badge tone="warn">等待 Tailscale 虚拟网口就绪</Badge>;
  }, [data, privacyMask]);

  return (
    <div className="space-y-5">
      <SectionCard
        title="本地域名与跨 Tailscale 命名中心"
        icon={<Globe className="w-4 h-4" />}
        subtitle="给家里路由器、NAS 与电脑起个好记的短名字（如 ax3000t.home / nas.home），在家与咖啡馆直连告别背 IP"
        actions={
          <div className="flex flex-wrap items-center gap-2">
            <Button
              size="xs"
              variant="secondary"
              loading={verifying}
              icon={<Zap className="w-3.5 h-3.5" />}
              onClick={() => void handleRunVerify()}
            >
              一键自检
            </Button>
            <Button
              size="xs"
              variant="secondary"
              icon={<BookOpen className="w-3.5 h-3.5" />}
              onClick={() => setGuideOpen(true)}
            >
              Tailscale 15秒向导
            </Button>
            <Button
              size="xs"
              variant="ghost"
              loading={loading}
              icon={<RefreshCw className="w-3.5 h-3.5" />}
              onClick={() => void loadOverview()}
            >
              刷新
            </Button>
          </div>
        }
      >
        <div className="space-y-4">
          <div className="flex flex-wrap items-center gap-2 text-xs">
            <Badge tone={data?.dnsHealthy ? 'ok' : 'warn'} dot>
              本地引擎：{data?.dnsEngineLabel || '加载中'}
            </Badge>
            {responderBadge}
            {data?.self?.tailscaleIp && (
              <Badge tone="neutral" className="font-mono">
                Split-DNS NS: {maskFullIP(data.self.tailscaleIp, privacyMask)}
              </Badge>
            )}
            {(data?.responder?.queryCount || 0) > 0 && (
              <Badge tone="neutral" className="font-mono">
                外网已应答 {data?.responder.queryCount} 次
              </Badge>
            )}
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs pt-1">
            <label className="block space-y-1">
              <span className="text-secondary">统一本地域名后缀</span>
              <select
                value={suffix}
                disabled={saving || busy || !data}
                onChange={(e) => void handleSaveSettings({ suffix: e.target.value })}
                className="w-full h-9 px-3 rounded-xl bg-surface1 border border-subtle text-primary font-mono focus:outline-none focus:border-strong"
              >
                {SUFFIX_OPTIONS.map((opt) => (
                  <option key={opt.value} value={opt.value}>
                    {opt.label}
                  </option>
                ))}
              </select>
            </label>

            <label className="flex items-center justify-between gap-3 px-3.5 py-2 rounded-xl bg-surface2/50 border border-subtle cursor-pointer select-none">
              <div className="space-y-0.5">
                <div className="text-primary font-medium">Tailscale Split-DNS 应答器</div>
                <div className="text-[11px] text-muted">仅监听 Tailscale IP:53，零开放递归</div>
              </div>
              <input
                type="checkbox"
                checked={Boolean(data?.tailscaleDns ?? true)}
                disabled={saving || busy || !data}
                onChange={(e) => void handleSaveSettings({ tailscaleDns: e.target.checked })}
                className="accent-sky-500 w-4 h-4 shrink-0"
              />
            </label>

            <label className="flex items-center justify-between gap-3 px-3.5 py-2 rounded-xl bg-surface2/50 border border-subtle cursor-pointer select-none">
              <div className="space-y-0.5">
                <div className="text-primary font-medium">MAC 自动跟随 DHCP 换 IP</div>
                <div className="text-[11px] text-muted">设备续租换 IP 后自动更新域名解析</div>
              </div>
              <input
                type="checkbox"
                checked={Boolean(data?.followDhcp ?? true)}
                disabled={saving || busy || !data}
                onChange={(e) => void handleSaveSettings({ followDhcp: e.target.checked })}
                className="accent-sky-500 w-4 h-4 shrink-0"
              />
            </label>
          </div>

          {!selfAlreadyNamed && data?.self && (data.self.lanIp || data.self.tailscaleIp) && (
            <div className="rounded-xl border border-sky-500/30 bg-sky-500/10 px-3.5 py-2.5 flex flex-wrap items-center justify-between gap-2 text-xs">
              <div className="flex items-center gap-2 text-sky-100">
                <Router className="w-4 h-4 text-sky-400 shrink-0" />
                <span>
                  建议先把本机路由器命名为{' '}
                  <code className="font-mono text-sky-300 font-semibold">
                    {data.self.suggestedAlias}.{suffix}
                  </code>{' '}
                  （{maskFullIP(data.self.lanIp || data.self.tailscaleIp || '', privacyMask)}），以后直接浏览器输入它打开 SingCtl 面板！
                </span>
              </div>
              <Button size="xs" variant="primary" icon={<Plus className="w-3 h-3" />} onClick={openQuickAddSelf}>
                一键为本机命名
              </Button>
            </div>
          )}
        </div>
      </SectionCard>

      <SectionCard
        title={`已命名设备名册 (${data?.devices.length || 0})`}
        icon={<Radio className="w-4 h-4" />}
        subtitle="所有设备均自动同步至 AdGuard / SmartDNS 重写、sing-box 本地直连与流量审计友好昵称"
        actions={
          <Button
            size="xs"
            variant="primary"
            icon={<Plus className="w-3.5 h-3.5" />}
            disabled={saving || busy}
            onClick={() => {
              setDrawerInit({ alias: '', ip: '', source: 'manual' });
              setDrawerOpen(true);
            }}
          >
            手动添加设备
          </Button>
        }
      >
        {!data?.devices.length ? (
          <div className="py-8 text-center text-xs text-muted space-y-2">
            <div>暂未添加任何命名设备</div>
            <div>点击上方「一键为本机命名」或直接在下方「发现的设备」中点一下「+ 命名」即可 3 秒生效</div>
          </div>
        ) : (
          <div className="divide-y divide-[var(--border-subtle)]">
            {data.devices.map((dev) => {
              const reachTone =
                dev.reachability.status === 'tailscale' || dev.reachability.status === 'subnet'
                  ? 'ok'
                  : 'warn';
              return (
                <div
                  key={dev.alias}
                  className="py-3.5 flex flex-col lg:flex-row lg:items-center justify-between gap-3"
                >
                  <div className="min-w-0 flex-1 space-y-1.5">
                    <div className="flex flex-wrap items-center gap-2">
                      <span
                        className={`w-2 h-2 rounded-full shrink-0 ${
                          dev.online ? 'bg-emerald-400' : 'bg-slate-500'
                        }`}
                        title={dev.online ? '在线' : '离线或休眠'}
                      />
                      <span className="font-semibold text-sm text-primary">
                        {dev.displayName || dev.alias}
                      </span>
                      <button
                        type="button"
                        onClick={() => void handleCopyText('本地域名', dev.fqdn)}
                        className="inline-flex items-center gap-1 px-2 py-0.5 rounded-lg bg-sky-500/12 hover:bg-sky-500/20 border border-sky-500/25 font-mono text-xs text-sky-300 cursor-pointer transition-colors"
                        title="点击复制完整域名"
                      >
                        <span>{dev.fqdn}</span>
                        <Copy className="w-3 h-3 opacity-80" />
                      </button>
                      {dev.wildcard && (
                        <Badge tone="accent" className="font-mono">
                          <Sparkles className="w-2.5 h-2.5 inline mr-0.5" />
                          *.{dev.fqdn}
                        </Badge>
                      )}
                      <Badge tone={reachTone}>
                        {dev.reachability.status === 'lan_only' ? (
                          <AlertTriangle className="w-2.5 h-2.5 inline mr-1" />
                        ) : (
                          <CheckCircle2 className="w-2.5 h-2.5 inline mr-1" />
                        )}
                        {dev.reachability.label}
                      </Badge>
                    </div>

                    <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-[11px] font-mono text-muted">
                      <span>IP: {maskFullIP(dev.ip, privacyMask)}</span>
                      {dev.mac && <span>MAC: {maskSensitiveText(dev.mac, privacyMask, '••:••:••:••:••:••')}</span>}
                      {dev.services && dev.services.length > 0 && (
                        <span className="inline-flex flex-wrap items-center gap-1.5">
                          {dev.services.map((svc, i) => renderServiceButton(dev.fqdn, svc, i))}
                        </span>
                      )}
                    </div>

                    {dev.reachability.status === 'lan_only' && dev.reachability.suggestedTailscaleIp && (
                      <div className="flex flex-wrap items-center gap-2 text-[11px] text-amber-300/95 pt-0.5">
                        <span>{dev.reachability.hint}</span>
                        <Button
                          size="xs"
                          variant="secondary"
                          disabled={saving || busy}
                          onClick={() =>
                            void handleUpsertDevice({
                              originalAlias: dev.alias,
                              alias: dev.alias,
                              displayName: dev.displayName,
                              ip: dev.reachability.suggestedTailscaleIp || dev.ip,
                              mac: dev.mac,
                              source: 'tailscale',
                              wildcard: dev.wildcard,
                              services: dev.services,
                              note: dev.note,
                            })
                          }
                        >
                          一键改用 Tailscale IP ({maskFullIP(dev.reachability.suggestedTailscaleIp, privacyMask)})
                        </Button>
                      </div>
                    )}
                  </div>

                  <div className="flex items-center gap-1.5 shrink-0">
                    <Button
                      size="xs"
                      variant="ghost"
                      disabled={saving || busy}
                      icon={<Pencil className="w-3.5 h-3.5" />}
                      onClick={() => {
                        setDrawerInit({
                          originalAlias: dev.alias,
                          alias: dev.alias,
                          displayName: dev.displayName,
                          ip: dev.ip,
                          mac: dev.mac,
                          source: dev.source,
                          wildcard: dev.wildcard,
                          services: dev.services,
                          note: dev.note,
                        });
                        setDrawerOpen(true);
                      }}
                    >
                      编辑
                    </Button>
                    <Button
                      size="xs"
                      variant="ghost"
                      disabled={saving || busy}
                      icon={<Trash2 className="w-3.5 h-3.5 text-rose-400" />}
                      onClick={() => setDeleteTarget(dev)}
                    />
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </SectionCard>

      <SectionCard
        title="发现的未命名设备（点一下直接命名）"
        icon={<Laptop className="w-4 h-4" />}
        subtitle="自动聚合本机局域网 DHCP/ARP 终端与同组网 Tailscale 节点，免去手动查 IP 与 MAC"
        actions={
          <div className="inline-flex rounded-xl bg-surface2 p-0.5 border border-subtle text-xs">
            <button
              type="button"
              onClick={() => setDiscoverTab('lan')}
              className={`px-3 py-1 rounded-lg transition-colors cursor-pointer ${
                discoverTab === 'lan'
                  ? 'bg-surface1 text-primary font-semibold shadow-sm'
                  : 'text-muted hover:text-primary'
              }`}
            >
              局域网终端 ({data?.discoveredLan.length || 0})
            </button>
            <button
              type="button"
              onClick={() => setDiscoverTab('ts')}
              className={`px-3 py-1 rounded-lg transition-colors cursor-pointer flex items-center gap-1 ${
                discoverTab === 'ts'
                  ? 'bg-surface1 text-primary font-semibold shadow-sm'
                  : 'text-muted hover:text-primary'
              }`}
            >
              <Share2 className="w-3 h-3" />
              <span>Tailscale 节点 ({data?.discoveredTailscale.length || 0})</span>
            </button>
          </div>
        }
      >
        {discoverTab === 'lan' ? (
          !data?.discoveredLan.length ? (
            <div className="py-6 text-center text-xs text-muted">
              当前没有待命名的局域网在线设备
            </div>
          ) : (
            <div className="divide-y divide-[var(--border-subtle)] text-xs max-h-80 overflow-y-auto pr-1">
              {data.discoveredLan.map((d) => (
                <div key={`${d.ip}-${d.mac}`} className="py-2.5 flex items-center justify-between gap-3">
                  <div className="min-w-0 flex-1 space-y-0.5">
                    <div className="flex items-center gap-2">
                      <span
                        className={`w-2 h-2 rounded-full shrink-0 ${
                          d.online ? 'bg-emerald-400' : 'bg-slate-500'
                        }`}
                      />
                      <span className="font-medium text-primary truncate">
                        {d.hostname || maskFullIP(d.ip, privacyMask)}
                      </span>
                      {d.suggestedAlias && (
                        <Badge tone="neutral" className="font-mono">
                          建议: {d.suggestedAlias}.{suffix}
                        </Badge>
                      )}
                    </div>
                    <div className="font-mono text-[11px] text-muted">
                      {maskFullIP(d.ip, privacyMask)}
                      {d.mac ? ` · ${maskSensitiveText(d.mac, privacyMask, '••:••:••:••:••:••')}` : ''}
                      {d.interface ? ` · ${d.interface}` : ''}
                    </div>
                  </div>
                  <Button
                    size="xs"
                    variant="secondary"
                    icon={<Plus className="w-3 h-3" />}
                    onClick={() => {
                      setDrawerInit({
                        alias: d.suggestedAlias || '',
                        displayName: d.hostname || '',
                        ip: d.ip,
                        mac: d.mac || '',
                        source: 'lan',
                      });
                      setDrawerOpen(true);
                    }}
                  >
                    设昵称
                  </Button>
                </div>
              ))}
            </div>
          )
        ) : !data?.discoveredTailscale.length ? (
          <div className="py-6 text-center text-xs text-muted">
            未发现其他待命名的 Tailscale 节点（如已全部命名或 Tailscale 未登录）
          </div>
        ) : (
          <div className="divide-y divide-[var(--border-subtle)] text-xs max-h-80 overflow-y-auto pr-1">
            {data.discoveredTailscale.map((p) => (
              <div key={p.tailscaleIp} className="py-2.5 flex items-center justify-between gap-3">
                <div className="min-w-0 flex-1 space-y-0.5">
                  <div className="flex flex-wrap items-center gap-2">
                    <span
                      className={`w-2 h-2 rounded-full shrink-0 ${
                        p.online ? 'bg-emerald-400' : 'bg-slate-500'
                      }`}
                    />
                    <span className="font-medium text-primary">{p.hostname}</span>
                    {p.os && <Badge tone="neutral">{p.os}</Badge>}
                    {p.suggestedAlias && (
                      <Badge tone="accent" className="font-mono">
                        建议: {p.suggestedAlias}.{suffix}
                      </Badge>
                    )}
                  </div>
                  <div className="font-mono text-[11px] text-muted">
                    Tailscale IP: {maskFullIP(p.tailscaleIp, privacyMask)}
                    {p.subnets && p.subnets.length > 0 ? ` · 广播: ${privacyMask ? '•••' : p.subnets.join(', ')}` : ''}
                  </div>
                </div>
                <Button
                  size="xs"
                  variant="secondary"
                  icon={<Plus className="w-3 h-3" />}
                  onClick={() => {
                    setDrawerInit({
                      alias: p.suggestedAlias || '',
                      displayName: p.hostname,
                      ip: p.tailscaleIp,
                      source: 'tailscale',
                      services:
                        p.os?.toLowerCase() === 'linux'
                          ? [
                              { label: 'SingCtl WebUI', scheme: 'http', port: 8090 },
                              { label: 'SSH', scheme: 'ssh', port: 22 },
                            ]
                          : [],
                    });
                    setDrawerOpen(true);
                  }}
                >
                  一键导入
                </Button>
              </div>
            ))}
          </div>
        )}
      </SectionCard>

      <DeviceEditDrawer
        open={drawerOpen}
        suffix={suffix}
        saving={saving}
        initial={drawerInit}
        onClose={() => setDrawerOpen(false)}
        onSubmit={handleUpsertDevice}
      />

      <SplitDNSGuideDrawer
        open={guideOpen}
        data={data}
        privacyMask={privacyMask}
        verifying={verifying}
        verifyReport={verifyReport}
        onClose={() => setGuideOpen(false)}
        onRunVerify={() => void handleRunVerify()}
      />

      <ConfirmDialog
        open={Boolean(deleteTarget)}
        title={`移除本地域名 ${deleteTarget?.fqdn || ''}？`}
        description="移除后将自动清理本地防劫持 DNS 重写与 Tailscale Split-DNS 应答记录，不影响该设备的正常上网。"
        confirmText="确认移除"
        danger
        loading={saving}
        onCancel={() => setDeleteTarget(null)}
        onConfirm={() => void handleDeleteDevice()}
      />
    </div>
  );
};

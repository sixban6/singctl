import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  Cable,
  Check,
  Copy,
  Cpu,
  Globe,
  Home,
  Info,
  Lock,
  Network,
  Plus,
  RefreshCw,
  Settings2,
  Shield,
  Sliders,
  Trash2,
  Users,
  Wifi,
  Zap,
} from 'lucide-react';
import { Badge, Button, CardSkeleton, ConfirmDialog, SectionCard, useToast } from '../../../../ui';
import { useCachedQuery } from '../../../../hooks';
import { clientApi } from '../../../api';
import { VLAN_OVERVIEW_CACHE_KEY } from '../../../cacheKeys';
import { copyPlainText } from '../../../lib/leakProbes';
import {
  SafeCommitStatusReport,
  VlanApplyResponse,
  VlanOverview,
  VlanPresetTemplate,
  VlanPreviewResult,
  VlanSaveSegmentRequest,
  VlanSegment,
} from '../../../types';
import { PortSwitchBar } from './PortSwitchBar';
import { VlanSegmentDrawer } from './VlanSegmentDrawer';
import { AppliedWifiCredential, VlanWifiCredentialBanner } from './VlanWirelessCard';
import {
  buildDraftFromPreset,
  buildDraftFromSegment,
  getSegmentTheme,
  isPrivateIPv4,
  maskVlanText,
} from './vlanHelpers';

const PRO_MODE_STORAGE_KEY = 'singctl:vlan:proMode';

function readProModePref(): boolean {
  try {
    return window.localStorage.getItem(PRO_MODE_STORAGE_KEY) === '1';
  } catch {
    return false;
  }
}

function presetIcon(id: string) {
  switch (id) {
    case 'iot':
      return <Home className="w-4 h-4 text-amber-400" />;
    case 'guest':
      return <Users className="w-4 h-4 text-violet-400" />;
    case 'wifi':
      return <Wifi className="w-4 h-4 text-sky-400" />;
    default:
      return <Cable className="w-4 h-4 text-cyan-400" />;
  }
}

export interface VlanManagerSectionProps {
  busy?: boolean;
  privacyMask?: boolean;
  safeCommit?: SafeCommitStatusReport | null;
  onRefreshStatus?: () => void;
  onSafeCommitUpdated?: (sc: SafeCommitStatusReport) => void;
}

export const VlanManagerSection: React.FC<VlanManagerSectionProps> = ({
  busy = false,
  privacyMask = false,
  safeCommit,
  onRefreshStatus,
  onSafeCommitUpdated,
}) => {
  const { success, error, toast } = useToast();
  const {
    data: overview,
    loading,
    refreshing,
    setData: setOverview,
    refetch,
  } = useCachedQuery<VlanOverview>(VLAN_OVERVIEW_CACHE_KEY, () => clientApi.getVlanOverview());

  const [proMode, setProMode] = useState<boolean>(() => readProModePref());
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [drawerIsEdit, setDrawerIsEdit] = useState(false);
  const [drawerIsCallerMgmt, setDrawerIsCallerMgmt] = useState(false);
  const [drawerDraft, setDrawerDraft] = useState<VlanSaveSegmentRequest | null>(null);
  const [appliedWifiCred, setAppliedWifiCred] = useState<AppliedWifiCredential | null>(null);
  const lastRollbackAtRef = useRef<number | undefined>(safeCommit?.lastRollback?.rolledBackAt);

  // 防回滚误导：一旦监听到 Safe Commit 发生手动或超时回滚，立即销毁新 Wi-Fi 凭据速记卡
  useEffect(() => {
    const nextRolledBackAt = safeCommit?.lastRollback?.rolledBackAt;
    if (nextRolledBackAt && nextRolledBackAt !== lastRollbackAtRef.current) {
      setAppliedWifiCred(null);
    }
    lastRollbackAtRef.current = nextRolledBackAt;
  }, [safeCommit?.lastRollback?.rolledBackAt]);

  // 临时内存态速记卡 10 分钟后自动销毁
  useEffect(() => {
    if (!appliedWifiCred) return;
    const timer = window.setTimeout(() => {
      setAppliedWifiCred(null);
    }, 10 * 60 * 1000);
    return () => window.clearTimeout(timer);
  }, [appliedWifiCred]);

  const [deleteTarget, setDeleteTarget] = useState<VlanSegment | null>(null);
  const [deletePreview, setDeletePreview] = useState<VlanPreviewResult | null>(null);
  const [deleting, setDeleting] = useState(false);
  const [copiedRoutes, setCopiedRoutes] = useState(false);

  const toggleProMode = () => {
    const next = !proMode;
    setProMode(next);
    try {
      window.localStorage.setItem(PRO_MODE_STORAGE_KEY, next ? '1' : '0');
    } catch {
      // ignore storage errors
    }
    toast(next ? '已切换至专家模式（展示 VLAN ID / Trunk / UCI 预览）' : '已切换至小白简明模式', 'info');
  };

  const handleRefresh = useCallback(async () => {
    try {
      await refetch(false);
    } catch (e: unknown) {
      error(e instanceof Error ? e.message : '读取路由器 VLAN 拓扑失败');
    }
  }, [refetch, error]);

  const openFromPreset = (preset: VlanPresetTemplate) => {
    setDrawerDraft(buildDraftFromPreset(preset));
    setDrawerIsEdit(false);
    setDrawerIsCallerMgmt(false);
    setDrawerOpen(true);
  };

  const openEditSegment = (seg: VlanSegment) => {
    if (!overview) return;
    if (seg.isPrimaryLan) {
      toast('默认主管理网 (lan) 作为全局兜底入口已受保护，无需修改', 'info');
      return;
    }
    setDrawerDraft(buildDraftFromSegment(seg, overview));
    setDrawerIsEdit(true);
    setDrawerIsCallerMgmt(seg.isCallerMgmt);
    setDrawerOpen(true);
  };

  const handleOpenDelete = async (seg: VlanSegment) => {
    setDeleteTarget(seg);
    setDeletePreview(null);
    try {
      const prev = await clientApi.previewVlanDelete(seg.id);
      setDeletePreview(prev);
    } catch (e: unknown) {
      setDeletePreview({
        valid: false,
        errors: [e instanceof Error ? e.message : '生成删除预览失败'],
      });
    }
  };

  const handleConfirmDelete = async () => {
    if (!deleteTarget) return;
    setDeleting(true);
    try {
      const res = await clientApi.deleteVlanSegment(deleteTarget.id);
      setDeleteTarget(null);
      if (res.safeCommit) {
        onSafeCommitUpdated?.(res.safeCommit);
      }
      if (res.overview) {
        setOverview(res.overview);
      } else {
        await refetch(false);
      }
      onRefreshStatus?.();
      success(`已移除子网「${deleteTarget.displayName}」，防失联保险丝已启动 (${res.safeCommitTtlSec || 180}s)`, 6000);
    } catch (e: unknown) {
      error(e instanceof Error ? e.message : '删除子网失败');
    } finally {
      setDeleting(false);
    }
  };

  const handleApplied = (res: VlanApplyResponse, newCredential?: AppliedWifiCredential | null) => {
    setDrawerOpen(false);
    if (res.safeCommit) {
      onSafeCommitUpdated?.(res.safeCommit);
    }
    if (newCredential) {
      setAppliedWifiCred(newCredential);
    }
    if (res.overview) {
      setOverview(res.overview);
    } else {
      void refetch(false);
    }
    onRefreshStatus?.();
  };

  const totalOnline = useMemo(
    () => (overview?.segments ?? []).reduce((acc, s) => acc + (s.onlineClients || 0), 0),
    [overview],
  );

  const upstreamRouteBatch = useMemo(() => {
    if (!overview?.wanIp || !isPrivateIPv4(overview.wanIp)) return '';
    const customSegs = overview.segments.filter((s) => s.cidr && s.cidr !== overview.wanSubnet);
    if (customSegs.length === 0) return '';
    return customSegs.map((s) => `ip route replace ${s.cidr} via ${overview.wanIp}`).join('\n');
  }, [overview]);

  const handleCopyBatchRoutes = async () => {
    if (!upstreamRouteBatch) return;
    try {
      await copyPlainText(upstreamRouteBatch);
      setCopiedRoutes(true);
      success('已复制全部子网的上级回程静态路由命令');
      window.setTimeout(() => setCopiedRoutes(false), 2000);
    } catch {
      error('复制失败，请手动复制');
    }
  };

  if (loading && !overview) {
    return (
      <div className="space-y-4">
        <CardSkeleton rows={3} />
        <CardSkeleton rows={4} />
      </div>
    );
  }

  if (!overview) {
    return (
      <SectionCard
        title="子网隔离与无线分段"
        icon={<Network className="w-4 h-4" />}
        actions={
          <Button size="sm" variant="secondary" icon={<RefreshCw className="w-3.5 h-3.5" />} onClick={() => void handleRefresh()}>
            重试加载
          </Button>
        }
      >
        <p className="text-xs text-slate-400">暂未获取到当前设备网络拓扑，请点击重试。</p>
      </SectionCard>
    );
  }

  if (!overview.supported) {
    return (
      <SectionCard
        title="子网隔离与无线分段 (VLAN)"
        subtitle="OpenWrt 本机原生网络分段自动化"
        icon={<Network className="w-4 h-4" />}
        badge={<Badge tone="neutral">当前设备未启用</Badge>}
      >
        <div className="rounded-xl border border-slate-800 bg-slate-950/60 p-4 flex items-start gap-3">
          <Info className="w-5 h-5 text-sky-400 shrink-0 mt-0.5" />
          <div className="space-y-1 text-xs text-slate-300">
            <div className="font-semibold text-white">该功能仅在 OpenWrt / ImmortalWrt 路由器上自动激活</div>
            <p className="text-slate-400 leading-relaxed">
              {overview.unsupportedReason || '未检测到 OpenWrt UCI 环境，因此已自动隐藏物理交换机分段配置。'}
            </p>
          </div>
        </div>
      </SectionCard>
    );
  }

  return (
    <div className="space-y-5">
      <VlanWifiCredentialBanner
        credential={appliedWifiCred}
        privacyMask={privacyMask}
        onDismiss={() => setAppliedWifiCred(null)}
      />

      {/* Header summary & mode toggle */}
      <SectionCard
        title="家庭网络分区与隔离"
        subtitle={
          proMode
            ? `${overview.boardModel || 'OpenWrt 路由器'} · ${overview.driverLabel} · 在线终端 ${totalOnline} 台`
            : `${overview.boardModel || 'OpenWrt 路由器'} · 当前共有 ${overview.segments.length} 个网络分段，${totalOnline} 台在线设备`
        }
        icon={<Network className="w-4 h-4" />}
        badge={
          <Badge tone="ok" dot>
            {proMode ? overview.driver.toUpperCase() : '已开启防断联保护'}
          </Badge>
        }
        actions={
          <>
            <Button
              size="sm"
              variant={proMode ? 'primary' : 'secondary'}
              icon={<Sliders className="w-3.5 h-3.5" />}
              onClick={toggleProMode}
              title="切换小白简明模式与网络工程师专家模式"
            >
              {proMode ? '专家模式' : '简明模式'}
            </Button>
            <Button
              size="sm"
              variant="secondary"
              loading={refreshing}
              disabled={busy}
              icon={<RefreshCw className="w-3.5 h-3.5" />}
              onClick={() => void handleRefresh()}
            >
              刷新
            </Button>
            {overview.presets.length > 0 && (
              <Button
                size="sm"
                variant="primary"
                disabled={busy}
                icon={<Plus className="w-3.5 h-3.5" />}
                onClick={() => openFromPreset(overview.presets[0])}
              >
                新建隔离网
              </Button>
            )}
          </>
        }
      >
        <div className="space-y-4">
          {proMode && (
            <div className="flex flex-wrap items-center gap-2 text-[11px] text-slate-300">
              <span className="inline-flex items-center gap-1.5 rounded-lg border border-slate-800 bg-slate-950/70 px-2.5 py-1">
                <Cpu className="w-3.5 h-3.5 text-emerald-400" />
                驱动：{overview.driverLabel}
              </span>
              {overview.wanIp && (
                <span className="inline-flex items-center gap-1.5 rounded-lg border border-slate-800 bg-slate-950/70 px-2.5 py-1 font-mono">
                  WAN: {overview.wanDevice} ({maskVlanText(overview.wanIp, privacyMask)})
                </span>
              )}
              {overview.callerIp && (
                <span className="inline-flex items-center gap-1.5 rounded-lg border border-amber-500/30 bg-amber-500/10 px-2.5 py-1 text-amber-200 font-mono">
                  <Lock className="w-3 h-3" />
                  管理会话: {maskVlanText(overview.callerIp, privacyMask)} ({overview.callerSegmentId || 'lan'})
                </span>
              )}
            </div>
          )}

          <PortSwitchBar
            ports={overview.ports}
            segments={overview.segments}
            mode="overview"
            proMode={proMode}
            onSelectOverviewSegment={(segId) => {
              const target = overview.segments.find((s) => s.id === segId);
              if (target) openEditSegment(target);
            }}
          />
        </div>
      </SectionCard>

      {/* Scenario preset quick-add cards */}
      {overview.presets.length > 0 && (
        <SectionCard
          title="一键添加隔离网络"
          subtitle="不懂 VLAN 也没关系——直接按用途选择，系统自动分配不冲突的网段与隔离防火墙"
          icon={<Shield className="w-4 h-4" />}
        >
          <div className="grid sm:grid-cols-2 xl:grid-cols-4 gap-3">
            {overview.presets.map((preset) => {
              const theme = getSegmentTheme(preset.suggestedId, preset.id);
              return (
                <button
                  key={preset.id}
                  type="button"
                  disabled={busy}
                  onClick={() => openFromPreset(preset)}
                  className={`group rounded-2xl border border-slate-800/90 bg-slate-900/55 ${theme.hoverBorder} hover:bg-slate-900/90 p-3.5 text-left transition-all flex flex-col justify-between gap-3 cursor-pointer`}
                >
                  <div className="space-y-2">
                    <div className="flex items-center justify-between gap-2">
                      <div className="w-8 h-8 rounded-xl bg-slate-950/90 border border-slate-800 flex items-center justify-center">
                        {presetIcon(preset.id)}
                      </div>
                      <Badge tone={preset.defaultProxyMode === 'direct' ? 'warn' : 'accent'}>
                        {preset.defaultProxyMode === 'direct' ? '纯直连绕过代理' : '跟随透明代理'}
                      </Badge>
                    </div>
                    <div>
                      <div className="text-sm font-semibold text-white group-hover:text-emerald-300 transition-colors">
                        {preset.title}
                      </div>
                      <p className="text-[11px] text-slate-400 mt-1 leading-relaxed">{preset.tagline}</p>
                    </div>
                  </div>
                  <div className="flex items-center justify-between pt-2 border-t border-slate-800/70 text-[11px]">
                    <span className="font-mono text-slate-400">
                      {proMode
                        ? `VLAN ${preset.suggestedVlanId} · ${maskVlanText(preset.suggestedIpAddr, privacyMask)}`
                        : `推荐网段 ${maskVlanText(preset.suggestedIpAddr.replace(/\.1$/, '.x'), privacyMask)}`}
                    </span>
                    <span className="text-emerald-400 font-medium inline-flex items-center gap-0.5">
                      <Plus className="w-3 h-3" />
                      配置
                    </span>
                  </div>
                </button>
              );
            })}
          </div>
        </SectionCard>
      )}

      {/* Existing segments grid */}
      <SectionCard
        title="当前网络分段总览"
        subtitle="每个分段拥有独立网段、DHCP 与安全隔离策略，支持单独决定是否经过透明代理"
        icon={<Globe className="w-4 h-4" />}
        badge={<Badge tone="neutral">{overview.segments.length} 个分段</Badge>}
      >
        <div className="grid md:grid-cols-2 gap-3.5">
          {overview.segments.map((seg) => {
            const theme = getSegmentTheme(seg.id, seg.preset);
            const assignedPorts = Object.entries(seg.ports ?? {});
            return (
              <div
                key={seg.id}
                className={`relative rounded-2xl border ${theme.border} bg-slate-900/60 overflow-hidden flex flex-col justify-between`}
              >
                <div className={`h-1 w-full ${theme.bar} opacity-80`} />
                <div className="p-4 space-y-3">
                  {/* Top row */}
                  <div className="flex items-start justify-between gap-2">
                    <div className="min-w-0">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className={`w-2 h-2 rounded-full ${theme.dot} shrink-0`} />
                        <h3 className="text-sm font-bold text-white truncate">{seg.displayName}</h3>
                        {seg.isCallerMgmt && (
                          <Badge tone="warn">
                            <Lock className="w-2.5 h-2.5" />
                            当前管理会话
                          </Badge>
                        )}
                      </div>
                      <div className="flex items-center gap-2 mt-1 text-[11px] font-mono text-slate-400 flex-wrap">
                        <span>{maskVlanText(seg.cidr || seg.ipAddr, privacyMask)}</span>
                        {proMode && seg.vlanId > 0 && <span>· VLAN {seg.vlanId}</span>}
                        {proMode && seg.device && <span>· {seg.device}</span>}
                      </div>
                    </div>

                    <div className="flex items-center gap-1.5 shrink-0">
                      <Badge tone={seg.onlineClients > 0 ? 'ok' : 'neutral'}>
                        {seg.onlineClients} 台在线
                      </Badge>
                    </div>
                  </div>

                  {/* Proxy + Wireless + Ports summary */}
                  <div className="flex flex-wrap items-center gap-1.5">
                    <Badge tone={seg.proxyMode === 'direct' ? 'warn' : 'accent'}>
                      {seg.proxyMode === 'direct' ? (
                        <>
                          <Zap className="w-3 h-3" />
                          纯直连 · 绕过代理
                        </>
                      ) : (
                        <>
                          <Globe className="w-3 h-3" />
                          跟随透明代理
                        </>
                      )}
                    </Badge>

                    {seg.wireless?.enabled && seg.wireless.ssid && (
                      <Badge tone="neutral">
                        <Wifi className="w-3 h-3 text-sky-400" />
                        {maskVlanText(seg.wireless.ssid, privacyMask)}
                        {seg.wireless.band === '5g' ? ' (5G)' : seg.wireless.band === '2g' ? ' (2.4G)' : ''}
                        {seg.wireless.isolate ? ' · 隔离' : ''}
                      </Badge>
                    )}

                    {assignedPorts.map(([pName, pMode]) => (
                      <span
                        key={pName}
                        className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[11px] font-mono border border-slate-700/80 bg-slate-950/70 text-slate-300"
                      >
                        <Cable className="w-2.5 h-2.5 text-slate-400" />
                        {pName.toUpperCase()}
                        {proMode && pMode === 'trunk' ? ' (Trunk)' : ''}
                      </span>
                    ))}
                  </div>

                  {/* Plain-Chinese isolation relation chips */}
                  {seg.relations && seg.relations.length > 0 && (
                    <div className="flex flex-wrap items-center gap-1.5 pt-1">
                      {seg.relations.map((rel, idx) => (
                        <Badge key={idx} tone={rel.tone}>
                          {rel.text}
                        </Badge>
                      ))}
                    </div>
                  )}

                  {proMode && (
                    <div className="pt-2 border-t border-slate-800/70 text-[11px] font-mono text-slate-400 flex flex-wrap gap-x-3 gap-y-1">
                      <span>DHCP: .{seg.dhcpStart}~.{seg.dhcpStart + seg.dhcpLimit} ({seg.leaseTime})</span>
                      <span>IPv6: {seg.ipv6Mode || 'off'}</span>
                      {seg.policy.trustedSourceIps && seg.policy.trustedSourceIps.length > 0 && (
                        <span>
                          放行主控: {maskVlanText(seg.policy.trustedSourceIps.join(', '), privacyMask)}
                        </span>
                      )}
                    </div>
                  )}
                </div>

                {/* Footer actions */}
                <div className="px-4 py-2.5 border-t border-slate-800/70 bg-slate-950/40 flex items-center justify-between gap-2">
                  <span className="text-[11px] text-slate-400">
                    {seg.isPrimaryLan
                      ? '默认兜底主网（不可删除）'
                      : seg.managedBySingCtl
                        ? '由 SingCtl 托管'
                        : '现网识别（支持接管编辑）'}
                  </span>
                  <div className="flex items-center gap-1.5">
                    {!seg.isPrimaryLan && (
                      <Button
                        size="xs"
                        variant="secondary"
                        disabled={busy}
                        icon={<Settings2 className="w-3 h-3" />}
                        onClick={() => openEditSegment(seg)}
                      >
                        配置
                      </Button>
                    )}
                    {!seg.isPrimaryLan && !seg.isCallerMgmt && (
                      <Button
                        size="xs"
                        variant="danger"
                        disabled={busy}
                        icon={<Trash2 className="w-3 h-3" />}
                        onClick={() => void handleOpenDelete(seg)}
                      >
                        删除
                      </Button>
                    )}
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      </SectionCard>

      {/* Upstream static route helper (only shown when router sits behind an upstream private LAN) */}
      {upstreamRouteBatch && (
        <SectionCard
          title="上级主软路由互访提示（二级路由场景）"
          subtitle={`检测到本机 WAN 位于上级私网 (${maskVlanText(overview.wanSubnet || '', privacyMask)})，若需主路由主动访问下方隔离网（如 Home Assistant 控设备），请在主路由添加静态路由`}
          icon={<Info className="w-4 h-4" />}
          collapsible
          defaultOpen={proMode}
          actions={
            <Button
              size="xs"
              variant="secondary"
              icon={copiedRoutes ? <Check className="w-3 h-3" /> : <Copy className="w-3 h-3" />}
              onClick={() => void handleCopyBatchRoutes()}
            >
              {copiedRoutes ? '已复制全部命令' : '一键复制路由命令'}
            </Button>
          }
        >
          <pre className="rounded-xl border border-slate-800 bg-slate-950/80 p-3 text-xs font-mono text-sky-300 overflow-x-auto leading-relaxed">
            {maskVlanText(upstreamRouteBatch, privacyMask)}
          </pre>
        </SectionCard>
      )}

      {/* Config slide drawer */}
      <VlanSegmentDrawer
        open={drawerOpen}
        isEdit={drawerIsEdit}
        isCallerMgmt={drawerIsCallerMgmt}
        proMode={proMode}
        privacyMask={privacyMask}
        overview={overview}
        initialDraft={drawerDraft}
        onClose={() => setDrawerOpen(false)}
        onApplied={handleApplied}
        onSafeCommitUpdated={onSafeCommitUpdated}
      />

      {/* Delete confirmation dialog */}
      <ConfirmDialog
        open={Boolean(deleteTarget)}
        title={`确认移除隔离网「${deleteTarget?.displayName || deleteTarget?.id || ''}」？`}
        description={
          deletePreview?.errors?.length
            ? deletePreview.errors.join('；')
            : deletePreview?.plainSummary?.length
              ? `${deletePreview.plainSummary.join('；')}。系统将自动激活 180 秒安全回滚保险丝以防意外断联。`
              : '将清理该子网的接口、DHCP、防火墙隔离规则并安全解绑无线网络，同时启动 180 秒自动回滚保护。'
        }
        confirmText="安全删除（带回滚保护）"
        danger
        loading={deleting}
        onConfirm={() => void handleConfirmDelete()}
        onCancel={() => setDeleteTarget(null)}
      />
    </div>
  );
};

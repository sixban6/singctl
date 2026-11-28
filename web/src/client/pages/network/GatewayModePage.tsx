import React, { useCallback, useEffect, useState } from 'react';
import {
  AlertTriangle,
  CheckCircle2,
  GitFork,
  RefreshCw,
  RotateCcw,
  Save,
} from 'lucide-react';
import { Badge, Button, PageHeader, SectionCard, useToast } from '../../../ui';
import { useCachedQuery } from '../../../hooks';
import { clientApi } from '../../api';
import { GATEWAY_CACHE_KEY } from '../../cacheKeys';
import { DNSLeakTestCard } from '../../components/DNSLeakTestCard';
import { maskFullIP } from '../../../lib/privacyMask';
import {
  ClientGatewayConfigResponse,
  ClientStatusResponse,
  GatewayIPv6Mode,
  GatewayRoleMode,
} from '../../types';
import { ChassisAccelCard } from './ChassisAccelCard';
import { GatewayIPv6Section } from './GatewayIPv6Section';
import { GatewayFlowOffloadSection } from './GatewayFlowOffloadSection';
import { SideRouterDelegationCard } from './SideRouterDelegationCard';

export interface GatewayModePageProps {
  status?: ClientStatusResponse | null;
  busy: boolean;
  privacyMask?: boolean;
  onAction?: (name: string, params?: Record<string, unknown>, confirmMsg?: string) => void;
  onNavigate?: (tab: string, sub?: string) => void;
  onSaved?: () => void;
}

type GatewayUIRole = 'standalone' | 'side' | 'delegated';

const ROLE_OPTIONS: Array<{
  key: GatewayUIRole;
  title: string;
  tag: string;
  flow: string;
  desc: string;
}> = [
  {
    key: 'standalone',
    title: '独立路由',
    tag: '默认推荐',
    flow: '终端 → 本机分流 → 外网',
    desc: '本机直接拨号或接光猫，独立完成上网与透明分流（无订阅时自动免订阅审计守护）。',
  },
  {
    key: 'side',
    title: '旁挂路由',
    tag: '专职分流',
    flow: '终端 → 本机分流 → 上级路由 → 外网',
    desc: '单网口接入主路由 LAN 口，自动启用转发、MSS 钳制与单臂防丢包，专职透明分流与审计。',
  },
  {
    key: 'delegated',
    title: '托管路由',
    tag: '主旁协同',
    flow: '终端 → 本机转发 → 旁挂节点 → 外网',
    desc: '本机负责拨号、Wi-Fi 与 VLAN，自动停用本机 sing-box 释放内存，把需分流流量转交旁挂节点。',
  },
];

function roleLabel(role: GatewayUIRole | null): string {
  switch (role) {
    case 'side':
      return '旁挂路由';
    case 'delegated':
      return '托管路由';
    case 'standalone':
      return '独立路由';
    default:
      return '读取中…';
  }
}

export const GatewayModePage: React.FC<GatewayModePageProps> = ({
  status,
  busy,
  privacyMask = false,
  onAction,
  onNavigate,
  onSaved,
}) => {
  const { toast, success, error } = useToast();
  const {
    data,
    loading,
    refreshing,
    setData: setGatewayData,
    refetch: refetchGateway,
  } = useCachedQuery<ClientGatewayConfigResponse>(GATEWAY_CACHE_KEY, () => clientApi.getGateway());

  const [saving, setSaving] = useState(false);
  const [ipv6Saving, setIpv6Saving] = useState(false);
  const [offloadSaving, setOffloadSaving] = useState(false);
  const [offloadRebootNotice, setOffloadRebootNotice] = useState<string | null>(null);

  const gwSummary = status?.gateway;

  const savedMode: GatewayRoleMode | null = data?.mode
    ? data.mode === 'side'
      ? 'side'
      : 'main'
    : gwSummary?.mode
      ? gwSummary.mode === 'side'
        ? 'side'
        : 'main'
      : null;
  const savedMainRouterIP = (data?.mainRouterIP ?? gwSummary?.mainRouterIP ?? '').trim();
  const savedSideRouterIP = (data?.sideRouterIP ?? gwSummary?.sideRouterIP ?? '').trim();
  const savedSideFailover = data?.sideRouterFailover ?? gwSummary?.sideRouterFailover ?? true;
  const savedIPv6Mode: GatewayIPv6Mode | null =
    (data?.ipv6Mode as GatewayIPv6Mode | undefined) ??
    (gwSummary?.ipv6Mode as GatewayIPv6Mode | undefined) ??
    null;

  const savedRole: GatewayUIRole | null = !savedMode
    ? null
    : savedMode === 'side'
      ? 'side'
      : savedSideRouterIP
        ? 'delegated'
        : 'standalone';

  const [role, setRole] = useState<GatewayUIRole | null>(() => savedRole);
  const [mainRouterIP, setMainRouterIP] = useState<string>(
    () => savedMainRouterIP || data?.topology?.suggestedMainRouterIP || '',
  );
  const [sideRouterIP, setSideRouterIP] = useState<string>(() => savedSideRouterIP);
  const [sideFailover, setSideFailover] = useState<boolean>(() => savedSideFailover);
  const [ipv6Mode, setIpv6Mode] = useState<GatewayIPv6Mode | null>(() => savedIPv6Mode);

  const [roleDirty, setRoleDirty] = useState(false);
  const [mainRouterDirty, setMainRouterDirty] = useState(false);
  const [sideRouterDirty, setSideRouterDirty] = useState(false);
  const [ipv6Dirty, setIpv6Dirty] = useState(false);

  useEffect(() => {
    if (data) {
      const nextSavedRole: GatewayUIRole =
        data.mode === 'side' ? 'side' : (data.sideRouterIP || '').trim() ? 'delegated' : 'standalone';
      if (!roleDirty) {
        setRole(nextSavedRole);
      }
      if (!mainRouterDirty) {
        setMainRouterIP(data.mainRouterIP || data.topology?.suggestedMainRouterIP || '');
      }
      if (!sideRouterDirty) {
        setSideRouterIP((data.sideRouterIP || '').trim());
        setSideFailover(data.sideRouterFailover ?? true);
      }
      if (!ipv6Dirty) {
        setIpv6Mode((data.ipv6Mode as GatewayIPv6Mode) || 'off');
      }
      return;
    }
    if (gwSummary) {
      if (!roleDirty && role === null && savedRole) {
        setRole(savedRole);
      }
      if (!mainRouterDirty && !mainRouterIP && gwSummary.mainRouterIP) {
        setMainRouterIP(gwSummary.mainRouterIP);
      }
      if (!sideRouterDirty && !sideRouterIP && gwSummary.sideRouterIP) {
        setSideRouterIP(gwSummary.sideRouterIP);
        setSideFailover(gwSummary.sideRouterFailover ?? true);
      }
      if (!ipv6Dirty && ipv6Mode === null && gwSummary.ipv6Mode) {
        setIpv6Mode(gwSummary.ipv6Mode);
      }
    }
  }, [
    data,
    gwSummary,
    savedRole,
    roleDirty,
    mainRouterDirty,
    sideRouterDirty,
    ipv6Dirty,
    role,
    mainRouterIP,
    sideRouterIP,
    ipv6Mode,
  ]);

  const loadGateway = useCallback(async () => {
    try {
      await refetchGateway(false);
    } catch (e: unknown) {
      error(e instanceof Error ? e.message : '读取网关模式配置失败');
    }
  }, [error, refetchGateway]);

  const topo = data?.topology;
  const v6Status = data?.ipv6Status;
  const trimmedMainIP = mainRouterIP.trim();
  const trimmedSideIP = sideRouterIP.trim();

  const isSideSelfLoop = Boolean(role === 'side' && topo?.lanIP && trimmedMainIP === topo.lanIP);
  const isDelegatedSelfLoop = Boolean(role === 'delegated' && topo?.lanIP && trimmedSideIP === topo.lanIP);
  const isSelfLoop = isSideSelfLoop || isDelegatedSelfLoop;

  const backendModeForUI: GatewayRoleMode | null = role === null ? null : role === 'side' ? 'side' : 'main';
  const effectiveDisplayIPv6Mode: GatewayIPv6Mode | null =
    role === 'side' ? 'off' : ipv6Mode ?? savedIPv6Mode ?? null;

  const roleChanged = Boolean(role && savedRole && role !== savedRole);
  const mainGwChanged = Boolean(role === 'side' && savedRole === 'side' && trimmedMainIP !== savedMainRouterIP);
  const sideIPChanged = Boolean(role === 'delegated' && savedRole === 'delegated' && trimmedSideIP !== savedSideRouterIP);
  const failoverChanged = Boolean(role === 'delegated' && savedRole === 'delegated' && sideFailover !== savedSideFailover);
  const hasRoleChanges = roleChanged || mainGwChanged || sideIPChanged || failoverChanged || Boolean(topo?.selfLooped);

  const missingRequiredIP =
    (role === 'side' && !trimmedMainIP) || (role === 'delegated' && !trimmedSideIP);

  const handleSelectRole = (nextRole: GatewayUIRole) => {
    setRole(nextRole);
    setRoleDirty(savedRole ? nextRole !== savedRole : true);
    if (nextRole === 'side') {
      setIpv6Mode('off');
      setIpv6Dirty(savedIPv6Mode !== null && savedIPv6Mode !== 'off');
      if (!trimmedMainIP && topo?.suggestedMainRouterIP) {
        setMainRouterIP(topo.suggestedMainRouterIP);
      }
    } else if (!ipv6Dirty) {
      setIpv6Mode(savedIPv6Mode || 'off');
    }
  };

  const handleResetRole = () => {
    if (!savedRole) return;
    setRole(savedRole);
    setMainRouterIP(savedMainRouterIP || topo?.suggestedMainRouterIP || '');
    setSideRouterIP(savedSideRouterIP);
    setSideFailover(savedSideFailover);
    setIpv6Mode(savedIPv6Mode || 'off');
    setRoleDirty(false);
    setMainRouterDirty(false);
    setSideRouterDirty(false);
    setIpv6Dirty(false);
  };

  const handleResetIPv6 = () => {
    setIpv6Mode(savedIPv6Mode || 'off');
    setIpv6Dirty(false);
  };

  const handleSave = async (forIPv6 = false) => {
    if (!role || privacyMask) return;
    if (!forIPv6 && !hasRoleChanges) return;
    if (role === 'side' && !trimmedMainIP) {
      error('旁挂路由请填写上级主路由(网关) IP');
      return;
    }
    if (role === 'delegated' && !trimmedSideIP) {
      error('托管路由请填写旁挂分流节点的局域网 IP');
      return;
    }
    if (isSideSelfLoop) {
      error(`上级主路由 IP 不能等于本机 IP (${topo?.lanIP})`);
      return;
    }
    if (isDelegatedSelfLoop) {
      error(`旁挂节点 IP 不能等于本机 IP (${topo?.lanIP})`);
      return;
    }

    const effectiveV6: GatewayIPv6Mode = role === 'side' ? 'off' : ipv6Mode || 'off';
    const nextBackendMode: GatewayRoleMode = role === 'side' ? 'side' : 'main';

    if (forIPv6) {
      setIpv6Saving(true);
    } else {
      setSaving(true);
    }
    try {
      const payload = forIPv6
        ? {
            mode: savedMode || nextBackendMode,
            mainRouterIP: (savedMode || nextBackendMode) === 'side' ? savedMainRouterIP : '',
            ipv6Mode: effectiveV6,
          }
        : {
            mode: nextBackendMode,
            mainRouterIP: role === 'side' ? trimmedMainIP : '',
            sideRouterIP: role === 'delegated' ? trimmedSideIP : '',
            sideRouterFailover: role === 'delegated' ? sideFailover : savedSideFailover,
            ipv6Mode: effectiveV6,
          };

      const res = await clientApi.saveGateway(payload);
      setGatewayData(res);
      const syncedRole: GatewayUIRole =
        res.mode === 'side' ? 'side' : (res.sideRouterIP || '').trim() ? 'delegated' : 'standalone';
      setRole(syncedRole);
      setMainRouterIP(res.mainRouterIP || res.topology?.suggestedMainRouterIP || '');
      setSideRouterIP((res.sideRouterIP || '').trim());
      setSideFailover(res.sideRouterFailover ?? true);
      setIpv6Mode((res.ipv6Mode as GatewayIPv6Mode) || effectiveV6);
      setRoleDirty(false);
      setMainRouterDirty(false);
      setSideRouterDirty(false);
      setIpv6Dirty(false);
      success(res.message || `已切换并生效：${roleLabel(syncedRole)}`);
      onSaved?.();
    } catch (e: unknown) {
      error(e instanceof Error ? e.message : '保存网关模式失败');
    } finally {
      setSaving(false);
      setIpv6Saving(false);
    }
  };

  const handleApplyFlowOffload = async (enable: boolean): Promise<boolean> => {
    if (privacyMask) return false;
    setOffloadSaving(true);
    try {
      const res = await clientApi.saveGatewayFlowOffload({ enabled: enable });
      setGatewayData((prev) =>
        prev
          ? {
              ...prev,
              flowOffloadStatus: res.flowOffloadStatus,
            }
          : prev,
      );
      if (res.rebootRequired) {
        setOffloadRebootNotice(res.message);
        toast(res.message, 'warn');
      } else {
        setOffloadRebootNotice(null);
        success(res.message);
      }
      onSaved?.();
      return true;
    } catch (e: unknown) {
      error(e instanceof Error ? e.message : '切换流量卸载状态失败');
      return false;
    } finally {
      setOffloadSaving(false);
    }
  };

  const hasOffloadConflictRisk = Boolean(
    status?.singbox?.running ||
      savedRole === 'side' ||
      savedRole === 'delegated' ||
      data?.effectiveWorkMode === 'proxy' ||
      data?.effectiveWorkMode === 'audit' ||
      data?.effectiveWorkMode === 'delegated',
  );

  const sideLanDisplay = privacyMask ? '••••••••' : topo?.lanIP || '<旁挂路由IP>';
  const mainGwDisplay = privacyMask ? '••••••••' : trimmedMainIP || topo?.suggestedMainRouterIP || '<主路由IP>';

  const headerBadgeText = !savedRole ? '读取中…' : `${roleLabel(savedRole)} · 已生效`;

  const roleCardBadgeText = !savedRole
    ? '读取中…'
    : savedRole === 'side'
      ? `当前生效：旁挂路由${savedMainRouterIP ? `（上级 ${maskFullIP(savedMainRouterIP, privacyMask)}）` : ''}`
      : savedRole === 'delegated'
        ? `当前生效：托管路由（转交 ${maskFullIP(savedSideRouterIP, privacyMask)}）`
        : '当前生效：独立路由';

  const roleSaveLabel = (() => {
    if (saving) return '正在应用网关角色…';
    if (topo?.selfLooped && !roleChanged && !mainGwChanged) return '一键修复默认网关路由';
    if (role === 'delegated' && !trimmedSideIP) return '请先填写旁挂节点 IP';
    if (role === 'side' && !trimmedMainIP) return '请先填写上级主路由 IP';
    if (roleChanged) return `切换并生效为「${roleLabel(role)}」`;
    if (mainGwChanged) return '保存并更新上级网关';
    if (sideIPChanged) return '保存并更新旁挂节点';
    if (failoverChanged) return '保存容灾回退设置';
    if (!savedRole) return '读取中…';
    return `当前已生效：${roleLabel(savedRole)}`;
  })();

  return (
    <div className="space-y-5">
      <PageHeader
        title="网关模式"
        description="按实际流量流向选择本机路由器角色，以及 IPv6 双栈与硬件加速策略"
        badge={
          <Badge
            tone={!savedRole ? 'neutral' : savedRole === 'side' ? 'accent' : 'ok'}
            dot={Boolean(savedRole)}
          >
            {headerBadgeText}
          </Badge>
        }
        actions={
          <Button
            size="xs"
            loading={loading || refreshing}
            onClick={() => void loadGateway()}
            icon={<RefreshCw className="w-3 h-3" />}
          >
            重新探测拓扑
          </Button>
        }
      />

      <SectionCard
        title="选择路由器角色"
        icon={<GitFork className="w-4 h-4" />}
        subtitle="按流量去向三选一：独立路由由本机直跑分流，旁挂路由专职承接分流，托管路由把分流转交给局域网旁挂节点"
        actions={
          <Badge
            tone={!savedRole ? 'neutral' : savedRole === 'side' ? 'accent' : 'ok'}
            dot={Boolean(savedRole)}
          >
            {roleCardBadgeText}
          </Badge>
        }
      >
        <div className="space-y-4">
          {topo?.selfLooped && (
            <div className="rounded-xl border border-amber-500/35 bg-amber-500/10 px-3.5 py-2.5 text-xs text-amber-200 flex items-start gap-2">
              <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
              <span>
                检测到当前系统默认网关已误指回本机 ({maskFullIP(topo.lanIP, privacyMask)})！请确认下方上级主路由 IP 并点击修复，系统将自动修复默认路由避免死循环。
              </span>
            </div>
          )}

          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
            {ROLE_OPTIONS.map((opt) => {
              const isSelected = role !== null && role === opt.key;
              const isSaved = savedRole !== null && savedRole === opt.key;
              return (
                <button
                  key={opt.key}
                  type="button"
                  disabled={role === null}
                  onClick={() => handleSelectRole(opt.key)}
                  style={
                    isSelected
                      ? {
                          backgroundColor: 'var(--accent-soft)',
                          borderColor: 'var(--accent)',
                        }
                      : undefined
                  }
                  className={`p-3.5 sm:p-4 rounded-xl border text-left transition-all cursor-pointer flex flex-col justify-between gap-2 ${
                    isSelected ? '' : 'bg-surface2 border-subtle hover:border-strong'
                  }`}
                >
                  <div>
                    <div className="flex items-center justify-between gap-2">
                      <div className="flex items-center gap-1.5 min-w-0 flex-wrap">
                        <span className="text-sm font-semibold text-primary">{opt.title}</span>
                        {isSaved && isSelected && (
                          <span className="text-[10px] px-1.5 py-0.5 rounded bg-emerald-500/15 text-emerald-300 border border-emerald-500/35">
                            ✓ 当前生效
                          </span>
                        )}
                        {isSelected && !isSaved && savedRole !== null && (
                          <span className="text-[10px] px-1.5 py-0.5 rounded bg-amber-500/15 text-amber-300 border border-amber-500/35">
                            待保存
                          </span>
                        )}
                        {!isSelected && isSaved && (
                          <span className="text-[10px] px-1.5 py-0.5 rounded bg-emerald-500/10 text-emerald-400/80 border border-emerald-500/25">
                            当前生效
                          </span>
                        )}
                      </div>
                      <span className="text-[10px] px-1.5 py-0.5 rounded bg-surface1 text-secondary border border-subtle shrink-0">
                        {opt.tag}
                      </span>
                    </div>
                    <p className="text-xs text-secondary mt-1.5 leading-relaxed">{opt.desc}</p>
                  </div>
                  <div className="text-[11px] font-mono text-secondary/90 px-2 py-1 rounded-lg bg-surface1/70 border border-subtle/60 truncate">
                    {opt.flow}
                  </div>
                </button>
              );
            })}
          </div>

          {role === 'delegated' && (
            <SideRouterDelegationCard
              ipInput={sideRouterIP}
              savedSideRouterIP={savedSideRouterIP}
              failover={sideFailover}
              hasChanges={sideIPChanged || failoverChanged || (roleChanged && role === 'delegated')}
              isSelfLoop={isDelegatedSelfLoop}
              lanIP={topo?.lanIP}
              sideRouterStatus={data?.sideRouterStatus}
              privacyMask={privacyMask}
              onChangeIP={(val) => {
                setSideRouterIP(val);
                setSideRouterDirty(true);
              }}
              onChangeFailover={(checked) => {
                setSideFailover(checked);
                setSideRouterDirty(true);
              }}
              onGoVlan={
                onNavigate && status?.host?.capabilities?.vlan !== false
                  ? () => onNavigate('net', 'vlan')
                  : undefined
              }
            />
          )}

          {role === 'side' && (
            <div className="rounded-xl bg-surface2 border border-subtle p-4 space-y-3">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                <div>
                  <label htmlFor="main-router-ip-input" className="text-xs sm:text-sm font-semibold text-primary">
                    上级主路由（网关）IPv4 地址
                  </label>
                  <p className="text-[11px] text-secondary mt-0.5">
                    已自动探测候选网关，确认无误可直接保存；若与实际主路由不符请手动修改。
                  </p>
                </div>
                {topo?.suggestedMainRouterIP && trimmedMainIP !== topo.suggestedMainRouterIP && !privacyMask && (
                  <Button
                    size="xs"
                    variant="ghost"
                    onClick={() => {
                      setMainRouterIP(topo.suggestedMainRouterIP);
                      setMainRouterDirty(true);
                    }}
                  >
                    填入探测值 ({topo.suggestedMainRouterIP})
                  </Button>
                )}
              </div>

              <input
                id="main-router-ip-input"
                type={privacyMask ? 'password' : 'text'}
                readOnly={privacyMask}
                value={mainRouterIP}
                onChange={(e) => {
                  setMainRouterIP(e.target.value);
                  setMainRouterDirty(true);
                }}
                placeholder={privacyMask ? '••••••••' : topo?.suggestedMainRouterIP || '例如 192.168.1.1'}
                className="sc-input w-full sm:max-w-xs h-10 sm:h-9 px-3 text-base sm:text-xs font-mono"
              />

              {isSideSelfLoop && (
                <p className="text-xs text-rose-400">
                  上级主路由 IP 不能等于旁挂路由本机地址 ({maskFullIP(topo?.lanIP, privacyMask)})，否则会引发路由死循环！
                </p>
              )}
            </div>
          )}

          <div className="flex flex-wrap items-center justify-between gap-3 pt-2 border-t border-subtle">
            <div className="space-y-1">
              <div className="text-xs text-secondary font-mono">
                本机地址: <span className="text-primary">{maskFullIP(topo?.lanIP, privacyMask)}</span> · 网卡:{' '}
                <span className="text-primary">{topo?.lanIface || '-'}</span> · 系统当前网关:{' '}
                <span className="text-primary">{maskFullIP(topo?.currentGatewayIP, privacyMask)}</span>
              </div>
              {hasRoleChanges && (
                <div className="text-[11px] text-amber-300">
                  {roleChanged
                    ? `即将切换为「${roleLabel(role)}」，点击右侧按钮保存生效`
                    : '角色参数已修改，点击右侧按钮保存生效'}
                </div>
              )}
            </div>

            <div className="flex items-center gap-2 flex-wrap">
              {hasRoleChanges && !saving && (
                <Button
                  variant="ghost"
                  size="sm"
                  disabled={busy || privacyMask}
                  icon={<RotateCcw className="w-3.5 h-3.5" />}
                  onClick={handleResetRole}
                >
                  撤销更改
                </Button>
              )}
              <Button
                variant={hasRoleChanges && !missingRequiredIP ? 'primary' : 'secondary'}
                loading={saving}
                disabled={busy || !role || isSelfLoop || missingRequiredIP || privacyMask || !hasRoleChanges}
                title={privacyMask ? '隐私完全遮挡开启期间已锁定修改，避免误改网络配置' : undefined}
                icon={
                  hasRoleChanges ? (
                    <Save className="w-3.5 h-3.5" />
                  ) : (
                    <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                  )
                }
                onClick={() => void handleSave()}
              >
                {roleSaveLabel}
              </Button>
            </div>
          </div>
        </div>
      </SectionCard>

      {role === 'side' && (
        <SectionCard
          title="旁挂路由终端与主路由 DHCP 接入指引"
          icon={<CheckCircle2 className="w-4 h-4" />}
        >
          <div className="space-y-2.5 text-xs sm:text-sm text-secondary leading-relaxed">
            <p>
              1. <strong className="text-primary">单设备测试接入</strong>：将手机或电脑 Wi-Fi / 有线网络的{' '}
              <code className="font-mono text-emerald-300">默认网关</code> 与{' '}
              <code className="font-mono text-emerald-300">DNS 服务器</code> 同时设为旁挂路由地址{' '}
              <code className="font-mono text-cyan-300">{sideLanDisplay}</code>。
            </p>
            <p>
              2. <strong className="text-primary">全屋自动透明生效</strong>：登录上级主路由（
              <code className="font-mono text-primary">{mainGwDisplay}</code>）后台，在 LAN 口 DHCP 设置中将下发的「默认网关」与「DNS 服务器」填写为{' '}
              <code className="font-mono text-cyan-300">{sideLanDisplay}</code>（切勿修改主路由 WAN 口上游 DNS）。
            </p>
            <p>
              3. <strong className="text-primary">防绕过与防自环提醒</strong>：请为旁挂路由本机固定静态 IP（或在主路由绑定静态租约），并在主路由关闭 LAN 侧{' '}
              <code className="font-mono text-amber-300">IPv6 RA / DHCPv6</code> 通告，防止手机经主路由 IPv6 直出绕过旁挂路由。
            </p>
          </div>
        </SectionCard>
      )}

      <GatewayIPv6Section
        mode={backendModeForUI}
        v6Status={v6Status}
        effectiveDisplayIPv6Mode={effectiveDisplayIPv6Mode}
        savedIPv6Mode={savedIPv6Mode}
        ipv6Saving={ipv6Saving}
        busy={busy}
        isSelfLoop={isSideSelfLoop}
        privacyMask={privacyMask}
        onSelectIPv6Mode={(next) => {
          setIpv6Mode(next);
          setIpv6Dirty(savedIPv6Mode !== null ? next !== savedIPv6Mode : true);
        }}
        onResetIPv6={handleResetIPv6}
        onSaveIPv6={() => void handleSave(true)}
      />

      <GatewayFlowOffloadSection
        flowStatus={data?.flowOffloadStatus}
        hasConflictRisk={hasOffloadConflictRisk}
        saving={offloadSaving}
        busy={busy}
        privacyMask={privacyMask}
        rebootNotice={offloadRebootNotice}
        onApply={handleApplyFlowOffload}
      />

      <ChassisAccelCard
        busy={busy}
        supportedHint={status?.host?.capabilities?.chassis}
        onAction={onAction}
      />

      <DNSLeakTestCard privacyMask={privacyMask} />
    </div>
  );
};

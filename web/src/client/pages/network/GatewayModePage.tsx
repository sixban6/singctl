import React, { useCallback, useEffect, useState } from 'react';
import { AlertTriangle, CheckCircle2, GitFork, RefreshCw, Save } from 'lucide-react';
import { Badge, Button, PageHeader, SectionCard, useToast } from '../../../ui';
import { useCachedQuery } from '../../../hooks';
import { clientApi } from '../../api';
import { GATEWAY_CACHE_KEY } from '../../cacheKeys';
import { DNSLeakTestCard } from '../../components/DNSLeakTestCard';
import { maskFullIP } from '../../../lib/privacyMask';
import {
  ClientGatewayConfigResponse,
  ClientStatusResponse,
  EffectiveGatewayWorkMode,
  GatewayIPv6Mode,
  GatewayRoleMode,
} from '../../types';
import { GatewayIPv6Section } from './GatewayIPv6Section';
import { getWorkModeLabel, WorkModeCard } from './WorkModeCard';

export interface GatewayModePageProps {
  status?: ClientStatusResponse | null;
  busy: boolean;
  privacyMask?: boolean;
  onNavigate?: (tab: string, sub?: string) => void;
  onSaved?: () => void;
}

export const GatewayModePage: React.FC<GatewayModePageProps> = ({
  status,
  busy,
  privacyMask = false,
  onNavigate,
  onSaved,
}) => {
  const { success, error } = useToast();
  const {
    data,
    loading,
    refreshing,
    setData: setGatewayData,
    refetch: refetchGateway,
  } = useCachedQuery<ClientGatewayConfigResponse>(GATEWAY_CACHE_KEY, () => clientApi.getGateway());

  const [saving, setSaving] = useState(false);
  const [workModeSaving, setWorkModeSaving] = useState(false);
  const [ipv6Saving, setIpv6Saving] = useState(false);

  const gwSummary = status?.gateway;

  const [mode, setMode] = useState<GatewayRoleMode | null>(() => {
    if (data?.mode) return data.mode === 'side' ? 'side' : 'main';
    if (gwSummary?.mode) return gwSummary.mode === 'side' ? 'side' : 'main';
    return null;
  });
  const [mainRouterIP, setMainRouterIP] = useState<string>(
    () => data?.mainRouterIP || data?.topology?.suggestedMainRouterIP || gwSummary?.mainRouterIP || '',
  );
  const [ipv6Mode, setIpv6Mode] = useState<GatewayIPv6Mode | null>(
    () => (data?.ipv6Mode as GatewayIPv6Mode | undefined) || (gwSummary?.ipv6Mode as GatewayIPv6Mode | undefined) || null,
  );
  const [modeDirty, setModeDirty] = useState(false);
  const [mainRouterDirty, setMainRouterDirty] = useState(false);
  const [ipv6Dirty, setIpv6Dirty] = useState(false);

  useEffect(() => {
    if (data) {
      if (!modeDirty) {
        setMode(data.mode === 'side' ? 'side' : 'main');
      }
      if (!mainRouterDirty) {
        setMainRouterIP(data.mainRouterIP || data.topology?.suggestedMainRouterIP || '');
      }
      if (!ipv6Dirty) {
        setIpv6Mode((data.ipv6Mode as GatewayIPv6Mode) || 'off');
      }
      return;
    }
    if (gwSummary) {
      if (!modeDirty && mode === null && gwSummary.mode) {
        setMode(gwSummary.mode === 'side' ? 'side' : 'main');
      }
      if (!mainRouterDirty && !mainRouterIP && gwSummary.mainRouterIP) {
        setMainRouterIP(gwSummary.mainRouterIP);
      }
      if (!ipv6Dirty && ipv6Mode === null && gwSummary.ipv6Mode) {
        setIpv6Mode(gwSummary.ipv6Mode);
      }
    }
  }, [data, gwSummary, modeDirty, mainRouterDirty, ipv6Dirty, mode, mainRouterIP, ipv6Mode]);

  const loadGateway = useCallback(async () => {
    try {
      await refetchGateway(false);
    } catch (e: unknown) {
      error(e instanceof Error ? e.message : '读取网关模式配置失败');
    }
  }, [error, refetchGateway]);

  const topo = data?.topology;
  const v6Status = data?.ipv6Status;
  const trimmedIP = mainRouterIP.trim();
  const isSelfLoop = Boolean(mode === 'side' && topo?.lanIP && trimmedIP === topo.lanIP);
  const activeGatewayMode = data?.mode ?? gwSummary?.mode ?? mode;
  const configuredWorkMode = data?.workMode ?? gwSummary?.workMode;
  const hasSubs = data?.hasSubs ?? gwSummary?.hasSubs ?? Boolean((status?.config?.subs?.length || 0) > 0);
  const effectiveWorkMode: EffectiveGatewayWorkMode =
    data?.effectiveWorkMode ?? gwSummary?.effectiveWorkMode ?? (hasSubs ? 'proxy' : 'basic');
  const effectiveDisplayIPv6Mode: GatewayIPv6Mode | null =
    mode === 'side' ? 'off' : ipv6Mode ?? (data?.ipv6Mode as GatewayIPv6Mode | undefined) ?? gwSummary?.ipv6Mode ?? null;

  const handleSelectMode = (nextMode: GatewayRoleMode) => {
    setMode(nextMode);
    setModeDirty(true);
    if (nextMode === 'side') {
      setIpv6Mode('off');
      setIpv6Dirty(true);
      if (!trimmedIP && topo?.suggestedMainRouterIP) {
        setMainRouterIP(topo.suggestedMainRouterIP);
      }
    }
  };

  const handleSave = async (forIPv6 = false) => {
    if (!mode || privacyMask) return;
    if (mode === 'side' && !trimmedIP) {
      error('旁路由模式请填写上级主路由(网关) IP');
      return;
    }
    if (isSelfLoop) {
      error(`上级主路由 IP 不能等于旁路由本机 IP (${topo?.lanIP})`);
      return;
    }
    const effectiveV6: GatewayIPv6Mode = mode === 'side' ? 'off' : ipv6Mode || 'off';
    if (forIPv6) {
      setIpv6Saving(true);
    } else {
      setSaving(true);
    }
    try {
      const res = await clientApi.saveGateway({
        mode,
        mainRouterIP: mode === 'side' ? trimmedIP : '',
        ipv6Mode: effectiveV6,
      });
      setGatewayData(res);
      setMode(res.mode);
      setMainRouterIP(res.mainRouterIP || res.topology?.suggestedMainRouterIP || '');
      setIpv6Mode((res.ipv6Mode as GatewayIPv6Mode) || effectiveV6);
      setModeDirty(false);
      setMainRouterDirty(false);
      setIpv6Dirty(false);
      success(res.message || '网关模式已保存');
      onSaved?.();
    } catch (e: unknown) {
      error(e instanceof Error ? e.message : '保存网关模式失败');
    } finally {
      setSaving(false);
      setIpv6Saving(false);
    }
  };

  const handleSaveWorkMode = async (nextWorkMode: EffectiveGatewayWorkMode) => {
    if (privacyMask) return;
    const roleMode: GatewayRoleMode = mode || (activeGatewayMode === 'side' ? 'side' : 'main');
    const effectiveV6: GatewayIPv6Mode = roleMode === 'side' ? 'off' : ipv6Mode || 'off';
    setWorkModeSaving(true);
    try {
      const res = await clientApi.saveGateway({
        mode: roleMode,
        workMode: nextWorkMode,
        mainRouterIP: roleMode === 'side' ? trimmedIP : '',
        ipv6Mode: effectiveV6,
      });
      setGatewayData(res);
      success(res.message || `已切换为${getWorkModeLabel(nextWorkMode)}`);
      onSaved?.();
    } catch (e: unknown) {
      error(e instanceof Error ? e.message : '切换运行模式失败');
    } finally {
      setWorkModeSaving(false);
    }
  };

  const sideLanDisplay = privacyMask ? '••••••••' : topo?.lanIP || '<旁路由IP>';
  const mainGwDisplay = privacyMask ? '••••••••' : trimmedIP || topo?.suggestedMainRouterIP || '<主路由IP>';

  return (
    <div className="space-y-5">
      <PageHeader
        title="网关模式"
        description="按需选择基础模式、审计模式或代理模式，同时支持主/旁路由与 IPv6 双栈配置"
        badge={
          <Badge
            tone={!activeGatewayMode ? 'neutral' : activeGatewayMode === 'side' ? 'accent' : 'ok'}
            dot={Boolean(activeGatewayMode)}
          >
            {!activeGatewayMode
              ? '读取中…'
              : `${activeGatewayMode === 'side' ? '旁路由' : '主路由'} · ${getWorkModeLabel(effectiveWorkMode)}`}
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

      <WorkModeCard
        configuredWorkMode={configuredWorkMode}
        effectiveWorkMode={effectiveWorkMode}
        hasSubs={hasSubs}
        saving={workModeSaving}
        busy={busy}
        privacyMask={privacyMask}
        onSaveWorkMode={(next) => void handleSaveWorkMode(next)}
        onGoSubs={onNavigate ? () => onNavigate('sb', 'subs') : undefined}
      />

      <SectionCard
        title="选择客户端网关角色"
        icon={<GitFork className="w-4 h-4" />}
        subtitle="主路由模式不加载任何旁路由附加规则；旁路由模式自动挂载独立可逆的内核转发与单臂防丢包规则"
      >
        <div className="space-y-4">
          {topo?.selfLooped && (
            <div className="rounded-xl border border-amber-500/35 bg-amber-500/10 px-3.5 py-2.5 text-xs text-amber-200 flex items-start gap-2">
              <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
              <span>
                检测到当前系统默认网关已误指回本机 ({maskFullIP(topo.lanIP, privacyMask)})！请确认下方上级主路由 IP 并保存，系统将自动修复默认路由避免死循环。
              </span>
            </div>
          )}

          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {[
              {
                key: 'main' as GatewayRoleMode,
                title: '主路由模式 (Main Router)',
                tag: '默认推荐',
                desc: '设备本身直接拨号或连接光猫，作为全屋主网关运行（保持原生 TProxy 规则零变动）。',
              },
              {
                key: 'side' as GatewayRoleMode,
                title: '旁路由模式 (Side Router)',
                tag: '单臂网关',
                desc: '单网口接入主路由 LAN 口，自动开启转发、MSS 钳制与单臂防非对称丢包，同时保留终端真实 IP 审计。',
              },
            ].map((opt) => {
              const active = mode !== null && mode === opt.key;
              return (
                <button
                  key={opt.key}
                  type="button"
                  disabled={mode === null}
                  onClick={() => handleSelectMode(opt.key)}
                  style={
                    active
                      ? {
                          backgroundColor: 'var(--accent-soft)',
                          borderColor: 'var(--accent)',
                        }
                      : undefined
                  }
                  className={`p-4 rounded-xl border text-left transition-all cursor-pointer ${
                    active ? '' : 'bg-surface2 border-subtle hover:border-strong'
                  }`}
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-xs sm:text-sm font-semibold text-primary">{opt.title}</span>
                    <span className="text-[10px] px-1.5 py-0.5 rounded bg-surface1 text-secondary border border-subtle">
                      {opt.tag}
                    </span>
                  </div>
                  <p className="text-xs text-secondary mt-1.5 leading-relaxed">{opt.desc}</p>
                </button>
              );
            })}
          </div>

          {mode === 'side' && (
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
                {topo?.suggestedMainRouterIP && trimmedIP !== topo.suggestedMainRouterIP && !privacyMask && (
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
                className="sc-input w-full sm:max-w-xs h-9 px-3 text-xs sm:text-sm font-mono"
              />

              {isSelfLoop && (
                <p className="text-xs text-rose-400">
                  上级主路由 IP 不能等于旁路由本机地址 ({maskFullIP(topo?.lanIP, privacyMask)})，否则会引发路由死循环！
                </p>
              )}
            </div>
          )}

          <div className="flex flex-wrap items-center justify-between gap-3 pt-2 border-t border-subtle">
            <div className="text-xs text-secondary font-mono">
              本机地址: <span className="text-primary">{maskFullIP(topo?.lanIP, privacyMask)}</span> · 网卡:{' '}
              <span className="text-primary">{topo?.lanIface || '-'}</span> · 系统当前网关:{' '}
              <span className="text-primary">{maskFullIP(topo?.currentGatewayIP, privacyMask)}</span>
            </div>

            <Button
              variant="primary"
              loading={saving}
              disabled={busy || !mode || isSelfLoop || privacyMask}
              title={privacyMask ? '隐私完全遮挡开启期间已锁定修改，避免误改网络配置' : undefined}
              icon={<Save className="w-3.5 h-3.5" />}
              onClick={() => void handleSave()}
            >
              保存并应用模式
            </Button>
          </div>
        </div>
      </SectionCard>

      {mode === 'side' && (
        <SectionCard
          title="旁路由终端与主路由 DHCP 接入指引"
          icon={<CheckCircle2 className="w-4 h-4" />}
        >
          <div className="space-y-2.5 text-xs sm:text-sm text-secondary leading-relaxed">
            <p>
              1. <strong className="text-primary">单设备测试接入</strong>：将手机或电脑 Wi-Fi / 有线网络的{' '}
              <code className="font-mono text-emerald-300">默认网关</code> 与{' '}
              <code className="font-mono text-emerald-300">DNS 服务器</code> 同时设为旁路由地址{' '}
              <code className="font-mono text-cyan-300">{sideLanDisplay}</code>。
            </p>
            <p>
              2. <strong className="text-primary">全屋自动透明生效</strong>：登录上级主路由（
              <code className="font-mono text-primary">{mainGwDisplay}</code>）后台，在 LAN 口 DHCP 设置中将下发的「默认网关」与「DNS 服务器」填写为{' '}
              <code className="font-mono text-cyan-300">{sideLanDisplay}</code>（切勿修改主路由 WAN 口上游 DNS）。
            </p>
            <p>
              3. <strong className="text-primary">防绕过与防自环提醒</strong>：请为旁路由本机固定静态 IP（或在主路由绑定静态租约），并在主路由关闭 LAN 侧{' '}
              <code className="font-mono text-amber-300">IPv6 RA / DHCPv6</code> 通告，防止手机经主路由 IPv6 直出绕过旁路由。
            </p>
          </div>
        </SectionCard>
      )}

      <GatewayIPv6Section
        mode={mode}
        v6Status={v6Status}
        effectiveDisplayIPv6Mode={effectiveDisplayIPv6Mode}
        ipv6Saving={ipv6Saving}
        busy={busy}
        isSelfLoop={isSelfLoop}
        privacyMask={privacyMask}
        onSelectIPv6Mode={(next) => {
          setIpv6Mode(next);
          setIpv6Dirty(true);
        }}
        onSaveIPv6={() => void handleSave(true)}
      />

      <DNSLeakTestCard privacyMask={privacyMask} />
    </div>
  );
};

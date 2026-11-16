import React, { useState, useEffect, useCallback } from 'react';
import { Share2, Flame, GitFork, RefreshCw, Save, AlertTriangle, CheckCircle2 } from 'lucide-react';
import { Badge, Button, PageHeader, SectionCard, SegmentedTabs, useToast } from '../../ui';
import { clientApi } from '../api';
import {
  ClientGatewayConfigResponse,
  ClientStatusResponse,
  GatewayRoleMode,
} from '../types';

export interface TailscalePageProps {
  status: ClientStatusResponse | null;
  busy: boolean;
  onAction: (name: string, params?: Record<string, unknown>, confirmMsg?: string) => void;
  onNavigate: (tab: string) => void;
}

const TS_MODES = [
  { value: '', title: '默认客户端', desc: '仅作为普通节点加入 Tailscale，不广播路由' },
  { value: 'router', title: '子网路由器', desc: '广播本机局域网网段，软路由设备推荐此项' },
  { value: 'exit', title: '出口节点', desc: '将本机设为全网流量出口，供其他设备选为 Exit Node' },
  { value: 'gateway', title: '全能网关', desc: '同时充当子网路由器 + 出口节点' },
];

export const TailscalePage: React.FC<TailscalePageProps> = ({ status, busy, onAction, onNavigate }) => {
  const ts = status?.tailscale;
  const [mode, setMode] = useState<string>('router');
  const [acceptRoutes, setAcceptRoutes] = useState(false);

  useEffect(() => {
    if (ts?.installed && typeof ts.mode === 'string') {
      setMode(ts.mode);
    }
  }, [ts?.installed, ts?.mode]);

  return (
    <div className="space-y-5">
      <PageHeader
        title="Tailscale 组网"
        description={ts?.version ? `v${ts.version}` : ts?.installed ? '已安装' : '尚未安装 Tailscale'}
        badge={
          <Badge
            tone={!ts?.installed ? 'warn' : ts.state === 'Running' ? 'ok' : ts.running ? 'warn' : 'neutral'}
            dot={Boolean(ts?.running)}
            pulse={ts?.state === 'Running'}
          >
            {!ts?.installed ? '未安装' : ts.state === 'Running' ? '已连接' : ts.running ? ts.state : '未运行'}
          </Badge>
        }
      />

      <SectionCard
        title="启动模式选择"
        icon={<Share2 className="w-4 h-4" />}
        subtitle="首次启用请先在配置管理填写授权密钥 auth_key"
      >
        <div className="space-y-4">
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
            {TS_MODES.map((m) => {
              const selected = mode === m.value;
              return (
                <button
                  key={m.value || 'default'}
                  type="button"
                  onClick={() => setMode(m.value)}
                  style={
                    selected
                      ? {
                          backgroundColor: 'var(--accent-soft)',
                          borderColor: 'var(--accent)',
                        }
                      : undefined
                  }
                  className={`p-3.5 rounded-xl border text-left transition-all cursor-pointer ${
                    selected ? '' : 'bg-surface2 border-subtle hover:border-strong'
                  }`}
                >
                  <div className="text-xs sm:text-sm font-semibold text-primary">{m.title}</div>
                  <div className="text-[11px] text-secondary mt-1 leading-relaxed">{m.desc}</div>
                </button>
              );
            })}
          </div>

          <label className="inline-flex items-center gap-2 text-xs sm:text-sm text-primary cursor-pointer select-none">
            <input
              type="checkbox"
              checked={acceptRoutes}
              onChange={(e) => setAcceptRoutes(e.target.checked)}
              className="accent-[var(--accent)] w-4 h-4"
            />
            <span>接收其他节点广播的路由（`--accept-routes`）</span>
          </label>

          <div className="flex flex-wrap items-center gap-2.5 pt-2 border-t border-subtle">
            <Button
              variant="primary"
              disabled={busy}
              onClick={() => onAction('ts-start', { mode, acceptRoutes })}
            >
              启动 Tailscale
            </Button>
            <Button variant="danger" disabled={busy} onClick={() => onAction('ts-stop')}>
              停止
            </Button>
            <Button disabled={busy} onClick={() => onAction('ts-install')}>
              安装
            </Button>
            <Button disabled={busy} onClick={() => onAction('ts-update')}>
              更新
            </Button>
            {!ts?.authKeySet && (
              <Button size="sm" variant="ghost" onClick={() => onNavigate('config')}>
                去配置 auth_key →
              </Button>
            )}
          </div>
        </div>
      </SectionCard>

      <SectionCard title="当前运行状态">
        <div className="divide-y divide-[var(--border-subtle)] text-xs sm:text-sm">
          {[
            ['Daemon 状态', ts?.running ? '运行中' : '未运行'],
            ['后端连接态', ts?.state || '-'],
            ['当前工作模式', ts?.running ? TS_MODES.find((m) => m.value === (ts.mode || ''))?.title || ts.mode || '默认' : '-'],
            ['是否已安装', ts?.installed ? '是' : '否'],
            ['auth_key 凭据', ts?.authKeySet ? '已配置' : '未配置'],
          ].map(([k, v]) => (
            <div key={k} className="flex items-center justify-between py-2.5 gap-3">
              <span className="text-secondary">{k}</span>
              <span className="font-mono text-primary">{v}</span>
            </div>
          ))}
        </div>
      </SectionCard>
    </div>
  );
};

export interface FirewallPageProps {
  status: ClientStatusResponse | null;
  busy: boolean;
  onAction: (name: string, params?: Record<string, unknown>, confirmMsg?: string) => void;
}

export const FirewallPage: React.FC<FirewallPageProps> = ({ status, busy, onAction }) => {
  const fw = status?.firewall;

  return (
    <div className="space-y-5">
      <PageHeader
        title="防火墙加固"
        description="基于 nftables inet security 表的公网入口防护与开机自启"
        badge={
          <Badge tone={!fw?.supported ? 'warn' : fw.enabled ? 'ok' : 'neutral'} dot={Boolean(fw?.enabled)}>
            {!fw?.supported ? '当前系统不支持' : fw.enabled ? '已启用加固' : '未启用'}
          </Badge>
        }
      />

      <SectionCard title="nftables 安全封锁规则" icon={<Flame className="w-4 h-4" />}>
        <div className="space-y-4">
          <p className="text-xs sm:text-sm text-secondary leading-relaxed">
            加载安全封锁规则（`nftables inet security` 表）：自动拦截路由器高危管理端口的外部公网探测与访问、阻止伪造源地址报文进入、丢弃畸形包并注册系统自启服务。仅面向 WAN 公网侧防护，不影响内网与隧道正常流量。
          </p>
          <div className="flex flex-wrap items-center gap-2.5">
            <Button
              variant="primary"
              disabled={busy || !fw?.supported}
              onClick={() => onAction('fw-enable')}
            >
              启用防火墙加固
            </Button>
            <Button
              variant="danger"
              disabled={busy || !fw?.supported}
              onClick={() => onAction('fw-disable', {}, '确认禁用并移除防火墙加固规则？')}
            >
              禁用并移除规则
            </Button>
          </div>
          {!fw?.supported && (
            <p className="text-xs text-muted">提示：该功能仅适用于 Linux / OpenWrt 网关系统。</p>
          )}
        </div>
      </SectionCard>
    </div>
  );
};

export interface GatewayModePageProps {
  busy: boolean;
  onSaved?: () => void;
}

export const GatewayModePage: React.FC<GatewayModePageProps> = ({ busy, onSaved }) => {
  const { success, error } = useToast();
  const [data, setData] = useState<ClientGatewayConfigResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);

  const [mode, setMode] = useState<GatewayRoleMode>('main');
  const [mainRouterIP, setMainRouterIP] = useState('');

  const loadGateway = useCallback(async () => {
    setLoading(true);
    try {
      const res = await clientApi.getGateway();
      setData(res);
      setMode(res.mode === 'side' ? 'side' : 'main');
      setMainRouterIP(res.mainRouterIP || res.topology?.suggestedMainRouterIP || '');
    } catch (e: unknown) {
      error(e instanceof Error ? e.message : '读取网关模式配置失败');
    } finally {
      setLoading(false);
    }
  }, [error]);

  useEffect(() => {
    void loadGateway();
  }, [loadGateway]);

  const topo = data?.topology;
  const trimmedIP = mainRouterIP.trim();
  const isSelfLoop = Boolean(mode === 'side' && topo?.lanIP && trimmedIP === topo.lanIP);

  const handleSelectMode = (nextMode: GatewayRoleMode) => {
    setMode(nextMode);
    if (nextMode === 'side' && !trimmedIP && topo?.suggestedMainRouterIP) {
      setMainRouterIP(topo.suggestedMainRouterIP);
    }
  };

  const handleSave = async () => {
    if (mode === 'side' && !trimmedIP) {
      error('旁路由模式请填写上级主路由(网关) IP');
      return;
    }
    if (isSelfLoop) {
      error(`上级主路由 IP 不能等于旁路由本机 IP (${topo?.lanIP})`);
      return;
    }
    setSaving(true);
    try {
      const res = await clientApi.saveGateway({
        mode,
        mainRouterIP: mode === 'side' ? trimmedIP : '',
      });
      setData(res);
      setMode(res.mode);
      setMainRouterIP(res.mainRouterIP || res.topology?.suggestedMainRouterIP || '');
      success(res.message || '网关模式已保存');
      onSaved?.();
    } catch (e: unknown) {
      error(e instanceof Error ? e.message : '保存网关模式失败');
    } finally {
      setSaving(false);
    }
  };

  const sideLanDisplay = topo?.lanIP || '<旁路由IP>';
  const mainGwDisplay = trimmedIP || topo?.suggestedMainRouterIP || '<主路由IP>';

  return (
    <div className="space-y-5">
      <PageHeader
        title="网关部署模式"
        description="默认主路由模式；单网口挂在主路由下做旁路由时可在此一键切换"
        badge={
          <Badge tone={data?.mode === 'side' ? 'accent' : 'ok'} dot>
            {data?.mode === 'side' ? '当前：旁路由模式 (Side)' : '当前：主路由模式 (Main)'}
          </Badge>
        }
        actions={
          <Button
            size="xs"
            loading={loading}
            onClick={() => void loadGateway()}
            icon={<RefreshCw className="w-3 h-3" />}
          >
            重新探测拓扑
          </Button>
        }
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
                检测到当前系统默认网关已误指回本机 ({topo.lanIP})！请确认下方上级主路由 IP 并保存，系统将自动修复默认路由避免死循环。
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
              const active = mode === opt.key;
              return (
                <button
                  key={opt.key}
                  type="button"
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
                {topo?.suggestedMainRouterIP && trimmedIP !== topo.suggestedMainRouterIP && (
                  <Button
                    size="xs"
                    variant="ghost"
                    onClick={() => setMainRouterIP(topo.suggestedMainRouterIP)}
                  >
                    填入探测值 ({topo.suggestedMainRouterIP})
                  </Button>
                )}
              </div>

              <input
                id="main-router-ip-input"
                type="text"
                value={mainRouterIP}
                onChange={(e) => setMainRouterIP(e.target.value)}
                placeholder={topo?.suggestedMainRouterIP || '例如 192.168.1.1'}
                className="sc-input w-full sm:max-w-xs h-9 px-3 text-xs sm:text-sm font-mono"
              />

              {isSelfLoop && (
                <p className="text-xs text-rose-400">
                  上级主路由 IP 不能等于旁路由本机地址 ({topo?.lanIP})，否则会引发路由死循环！
                </p>
              )}
            </div>
          )}

          <div className="flex flex-wrap items-center justify-between gap-3 pt-2 border-t border-subtle">
            <div className="text-xs text-secondary font-mono">
              本机地址: <span className="text-primary">{topo?.lanIP || '-'}</span> · 网卡:{' '}
              <span className="text-primary">{topo?.lanIface || '-'}</span> · 系统当前网关:{' '}
              <span className="text-primary">{topo?.currentGatewayIP || '-'}</span>
            </div>

            <Button
              variant="primary"
              loading={saving}
              disabled={busy || loading || isSelfLoop}
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
              <code className="font-mono text-cyan-300">{sideLanDisplay}</code>。
            </p>
            <p>
              3. <strong className="text-primary">防绕过与防自环提醒</strong>：请为旁路由本机固定静态 IP（或在主路由绑定静态租约），并在主路由关闭 LAN 侧{' '}
              <code className="font-mono text-amber-300">IPv6 RA / DHCPv6</code> 通告，防止手机经主路由 IPv6 直出绕过旁路由。
            </p>
          </div>
        </SectionCard>
      )}
    </div>
  );
};

export type NetSubTab = 'gw' | 'ts' | 'fw';

function normalizeNetSubTab(raw?: string): NetSubTab {
  if (raw === 'fw') return 'fw';
  if (raw === 'ts') return 'ts';
  if (raw === 'gw') return 'gw';
  return 'gw';
}

export interface NetworkHubPageProps {
  status: ClientStatusResponse | null;
  busy: boolean;
  initialSub?: string;
  onSubChange?: (sub: NetSubTab) => void;
  onAction: (name: string, params?: Record<string, unknown>, confirmMsg?: string) => void;
  onNavigate: (tab: string) => void;
  onRefreshStatus?: () => void;
}

export const NetworkHubPage: React.FC<NetworkHubPageProps> = ({
  status,
  busy,
  initialSub,
  onSubChange,
  onAction,
  onNavigate,
  onRefreshStatus,
}) => {
  const [sub, setSub] = useState<NetSubTab>(() => normalizeNetSubTab(initialSub));

  useEffect(() => {
    if (initialSub !== undefined) {
      setSub(normalizeNetSubTab(initialSub));
    }
  }, [initialSub]);

  const handleSelect = (next: NetSubTab) => {
    setSub(next);
    onSubChange?.(next);
  };

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <SegmentedTabs
          value={sub}
          onChange={(k) => handleSelect(k as NetSubTab)}
          items={[
            {
              key: 'gw',
              label: '网关模式 (主/旁路由)',
              icon: <GitFork className="w-3.5 h-3.5" />,
            },
            {
              key: 'ts',
              label: 'Tailscale 异地组网',
              icon: <Share2 className="w-3.5 h-3.5" />,
            },
            {
              key: 'fw',
              label: 'nftables 防火墙加固',
              icon: <Flame className="w-3.5 h-3.5" />,
            },
          ]}
        />
      </div>

      {sub === 'gw' && <GatewayModePage busy={busy} onSaved={onRefreshStatus} />}
      {sub === 'ts' && (
        <TailscalePage status={status} busy={busy} onAction={onAction} onNavigate={onNavigate} />
      )}
      {sub === 'fw' && <FirewallPage status={status} busy={busy} onAction={onAction} />}
    </div>
  );
};

import React, { useState, useEffect } from 'react';
import { Share2, Flame } from 'lucide-react';
import { Badge, Button, PageHeader, SectionCard, SegmentedTabs } from '../../ui';
import { ClientStatusResponse } from '../types';

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

export interface NetworkHubPageProps {
  status: ClientStatusResponse | null;
  busy: boolean;
  initialSub?: string;
  onSubChange?: (sub: 'ts' | 'fw') => void;
  onAction: (name: string, params?: Record<string, unknown>, confirmMsg?: string) => void;
  onNavigate: (tab: string) => void;
}

export const NetworkHubPage: React.FC<NetworkHubPageProps> = ({
  status,
  busy,
  initialSub,
  onSubChange,
  onAction,
  onNavigate,
}) => {
  const [sub, setSub] = useState<'ts' | 'fw'>(initialSub === 'fw' ? 'fw' : 'ts');

  useEffect(() => {
    if (initialSub === 'fw' || initialSub === 'ts') {
      setSub(initialSub);
    }
  }, [initialSub]);

  const handleSelect = (next: 'ts' | 'fw') => {
    setSub(next);
    onSubChange?.(next);
  };

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <SegmentedTabs
          value={sub}
          onChange={handleSelect}
          items={[
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

      {sub === 'ts' ? (
        <TailscalePage status={status} busy={busy} onAction={onAction} onNavigate={onNavigate} />
      ) : (
        <FirewallPage status={status} busy={busy} onAction={onAction} />
      )}
    </div>
  );
};

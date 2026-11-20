import React, { useState, useEffect, useCallback } from 'react';
import { Share2, Flame, GitFork, RefreshCw, Save, AlertTriangle, CheckCircle2, Network, Smartphone, Copy, Check, ShieldCheck, Zap } from 'lucide-react';
import { Badge, Button, PageHeader, SectionCard, SegmentedTabs, useToast } from '../../ui';
import { clientApi } from '../api';
import { DNSLeakTestCard } from '../components/DNSLeakTestCard';
import {
  ClientGatewayConfigResponse,
  ClientStatusResponse,
  GatewayIPv6Mode,
  GatewayRoleMode,
  TailscaleAccessMode,
  TailscaleP2PPeerConfig,
  TailscaleP2PPeerView,
  TailscaleP2PReport,
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

const P2P_ACCESS_MODES: { key: TailscaleAccessMode; label: string }[] = [
  { key: 'outbound_only', label: '单向锁死' },
  { key: 'bidirectional_timed', label: '探亲限时双向' },
  { key: 'bidirectional', label: '长期双向' },
];

interface EditableP2PPeer {
  key: string;
  id: string;
  name: string;
  tailscaleIP: string;
  configured: boolean;
  jitEnabled: boolean;
  accessMode: TailscaleAccessMode;
  bidirectionalUntil: string;
  allowedLanTargetsText: string;
}

function peerEditKey(p: TailscaleP2PPeerView): string {
  return p.id || p.tailscaleIPs?.[0] || p.name || p.shortName;
}

function formatRemainingCountdown(sec: number): string {
  if (sec <= 0) return '已过期（自动锁死）';
  const days = Math.floor(sec / 86400);
  const hours = Math.floor((sec % 86400) / 3600);
  const mins = Math.floor((sec % 3600) / 60);
  if (days > 0) return `剩余 ${days}天${hours}小时`;
  if (hours > 0) return `剩余 ${hours}小时${mins}分`;
  return `剩余 ${Math.max(1, mins)} 分钟`;
}

export const TailscalePage: React.FC<TailscalePageProps> = ({ status, busy, onAction, onNavigate }) => {
  const { toast } = useToast();
  const ts = status?.tailscale;
  const [mode, setMode] = useState<string>('router');
  const [acceptRoutes, setAcceptRoutes] = useState(false);

  const [p2pReport, setP2pReport] = useState<TailscaleP2PReport | null>(null);
  const [p2pLoading, setP2pLoading] = useState(false);
  const [p2pSaving, setP2pSaving] = useState(false);
  const [pokingKey, setPokingKey] = useState('');

  const [p2pEnabled, setP2pEnabled] = useState(false);
  const [jitWindowSec, setJitWindowSec] = useState(5);
  const [cooldownSec, setCooldownSec] = useState(300);
  const [payloadFilter, setPayloadFilter] = useState(true);
  const [sandboxUjail, setSandboxUjail] = useState(false);
  const [peerEdits, setPeerEdits] = useState<Record<string, EditableP2PPeer>>({});

  useEffect(() => {
    if (ts?.installed && typeof ts.mode === 'string') {
      setMode(ts.mode);
    }
  }, [ts?.installed, ts?.mode]);

  const hydrateP2PReport = useCallback((rep: TailscaleP2PReport) => {
    setP2pReport(rep);
    setP2pEnabled(Boolean(rep.config?.enabled));
    setJitWindowSec(rep.config?.jit_window_sec && rep.config.jit_window_sec > 0 ? rep.config.jit_window_sec : 5);
    setCooldownSec(rep.config?.cooldown_sec && rep.config.cooldown_sec > 0 ? rep.config.cooldown_sec : 300);
    setPayloadFilter(rep.config?.payload_filter !== false);
    setSandboxUjail(Boolean(rep.config?.sandbox_ujail));

    const nextEdits: Record<string, EditableP2PPeer> = {};
    for (const p of rep.peers || []) {
      const k = peerEditKey(p);
      const rawMode = (p.accessMode || 'outbound_only') as TailscaleAccessMode;
      const modeVal: TailscaleAccessMode =
        rawMode === 'bidirectional' || rawMode === 'bidirectional_timed' ? rawMode : 'outbound_only';
      nextEdits[k] = {
        key: k,
        id: p.id || '',
        name: p.shortName || p.name || p.hostName || k,
        tailscaleIP: p.tailscaleIPs?.[0] || '',
        configured: Boolean(p.configured),
        jitEnabled: Boolean(p.jitEnabled),
        accessMode: modeVal,
        bidirectionalUntil: p.bidirectionalUntil || '',
        allowedLanTargetsText: (p.allowedLanTargets || []).join(', '),
      };
    }
    setPeerEdits(nextEdits);
  }, []);

  const loadP2P = useCallback(async () => {
    setP2pLoading(true);
    try {
      const rep = await clientApi.getTailscaleP2P();
      hydrateP2PReport(rep);
    } catch (err) {
      toast((err as Error)?.message || '读取 P2P 防线状态失败', 'error');
    } finally {
      setP2pLoading(false);
    }
  }, [hydrateP2PReport, toast]);

  useEffect(() => {
    void loadP2P();
  }, [loadP2P]);

  const updatePeerEdit = (k: string, patch: Partial<EditableP2PPeer>) => {
    setPeerEdits((prev) => {
      const cur = prev[k];
      if (!cur) return prev;
      return { ...prev, [k]: { ...cur, ...patch } };
    });
  };

  const applyQuickDays = (k: string, days: number) => {
    const until = new Date(Date.now() + days * 86400 * 1000).toISOString().replace(/\.\d{3}Z$/, 'Z');
    updatePeerEdit(k, {
      configured: true,
      accessMode: 'bidirectional_timed',
      bidirectionalUntil: until,
    });
  };

  const handleSaveP2P = async () => {
    setP2pSaving(true);
    try {
      const peersPayload: TailscaleP2PPeerConfig[] = Object.values(peerEdits)
        .filter((e) => e.configured)
        .map((e) => {
          const targets = e.allowedLanTargetsText
            .split(/[,，\n]+/)
            .map((s) => s.trim())
            .filter(Boolean);
          let until = e.bidirectionalUntil.trim();
          if (e.accessMode === 'bidirectional_timed' && !until) {
            until = new Date(Date.now() + 7 * 86400 * 1000).toISOString().replace(/\.\d{3}Z$/, 'Z');
          }
          return {
            id: e.id || undefined,
            name: e.name,
            tailscale_ip: e.tailscaleIP || undefined,
            jit_enabled: e.jitEnabled,
            access_mode: e.accessMode,
            bidirectional_until: e.accessMode === 'bidirectional_timed' ? until : undefined,
            allowed_lan_targets: targets,
          };
        });

      const rep = await clientApi.saveTailscaleP2P({
        enabled: p2pEnabled,
        jit_window_sec: Math.min(10, Math.max(3, Number(jitWindowSec) || 5)),
        cooldown_sec: Math.min(3600, Math.max(30, Number(cooldownSec) || 300)),
        payload_filter: payloadFilter,
        sandbox_ujail: sandboxUjail,
        peers: peersPayload,
      });
      hydrateP2PReport(rep);
      toast(rep.message || 'P2P 防线配置已生效', 'success');
    } catch (err) {
      toast((err as Error)?.message || '保存 P2P 防线配置失败', 'error');
    } finally {
      setP2pSaving(false);
    }
  };

  const handlePokePeer = async (p: TailscaleP2PPeerView) => {
    const k = peerEditKey(p);
    setPokingKey(k);
    try {
      const res = await clientApi.pokeTailscaleP2P({ id: p.id, name: p.name });
      toast(res.message || '测试完成', res.direct ? 'success' : 'warn');
      if (res.report) {
        hydrateP2PReport(res.report);
      } else {
        await loadP2P();
      }
    } catch (err) {
      toast((err as Error)?.message || '瞬时打洞测试失败', 'error');
    } finally {
      setPokingKey('');
    }
  };

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

      <SectionCard
        title="P2P 直连防线 · 零常驻暴露 (JIT)"
        icon={<ShieldCheck className="w-4 h-4" />}
        subtitle="闲置与直连期间 WAN 侧 UDP :41641 零暴露；仅在授权节点按需直连时瞬时放行 3~10s 并在连上后毫秒级自动关门"
        actions={
          <div className="flex items-center gap-2">
            {p2pReport && (
              <Badge tone={p2pReport.openPinholes > 0 ? 'warn' : p2pEnabled ? 'ok' : 'neutral'} dot>
                {p2pReport.openPinholes > 0
                  ? `瞬时放行 ${p2pReport.openPinholes} 个 IP`
                  : p2pEnabled
                  ? '0 开放 · 零暴露'
                  : '未开启'}
              </Badge>
            )}
            <Button size="sm" variant="ghost" onClick={loadP2P} disabled={p2pLoading}>
              <RefreshCw className={`w-3.5 h-3.5 ${p2pLoading ? 'animate-spin' : ''}`} />
              刷新
            </Button>
          </div>
        }
      >
        <div className="space-y-4">
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 text-xs">
            <label className="flex items-center justify-between gap-3 p-3 rounded-xl border border-subtle bg-surface2 cursor-pointer">
              <div>
                <div className="font-semibold text-primary">启用防线守护</div>
                <div className="text-[11px] text-secondary mt-0.5">
                  {p2pReport?.fw4Available
                    ? p2pReport.runtime?.applyMode === 'nft_direct'
                      ? 'OpenWrt nftables 原子注入就绪'
                      : 'OpenWrt fw4 原生热重载就绪'
                    : '未检测到 inet fw4 表'}
                </div>
              </div>
              <input
                type="checkbox"
                checked={p2pEnabled}
                onChange={(e) => setP2pEnabled(e.target.checked)}
                className="accent-[var(--accent)] w-4 h-4 shrink-0"
              />
            </label>

            <div className="p-3 rounded-xl border border-subtle bg-surface2">
              <label className="block font-semibold text-primary mb-1">JIT 瞬时窗口（秒）</label>
              <input
                type="number"
                min={3}
                max={10}
                value={jitWindowSec}
                onChange={(e) => setJitWindowSec(Number(e.target.value))}
                className="w-full px-2.5 py-1.5 rounded-lg border border-subtle bg-surface1 font-mono text-xs text-primary focus:outline-none focus:border-[var(--accent)]"
              />
            </div>

            <div className="p-3 rounded-xl border border-subtle bg-surface2">
              <label className="block font-semibold text-primary mb-1">失败冷却退避（秒）</label>
              <input
                type="number"
                min={30}
                max={3600}
                value={cooldownSec}
                onChange={(e) => setCooldownSec(Number(e.target.value))}
                className="w-full px-2.5 py-1.5 rounded-lg border border-subtle bg-surface1 font-mono text-xs text-primary focus:outline-none focus:border-[var(--accent)]"
              />
            </div>

            <div className="p-3 rounded-xl border border-subtle bg-surface2 space-y-2">
              <label className="flex items-center justify-between gap-2 cursor-pointer">
                <span className="font-semibold text-primary">Layer 2 载荷魔法头过滤</span>
                <input
                  type="checkbox"
                  checked={payloadFilter}
                  onChange={(e) => setPayloadFilter(e.target.checked)}
                  className="accent-[var(--accent)] w-4 h-4"
                />
              </label>
              <label
                className={`flex items-center justify-between gap-2 ${
                  p2pReport?.ujailAvailable ? 'cursor-pointer' : 'opacity-50 cursor-not-allowed'
                }`}
                title={p2pReport?.ujailAvailable ? '重启 tailscaled 进入 OpenWrt ujail 沙盒' : '当前环境无 /sbin/ujail'}
              >
                <span className="text-[11px] text-secondary">Layer 3 ujail 沙盒隔离（可选）</span>
                <input
                  type="checkbox"
                  disabled={!p2pReport?.ujailAvailable}
                  checked={sandboxUjail}
                  onChange={(e) => setSandboxUjail(e.target.checked)}
                  className="accent-[var(--accent)] w-3.5 h-3.5"
                />
              </label>
            </div>
          </div>

          <div className="p-3 rounded-xl border border-subtle bg-surface2/60 text-xs text-secondary leading-relaxed">
            未勾选「纳入防线管控」的个人管理员终端（如您的 MacBook、iPhone）保持 24/7 全量放行不受入向子网锁死限制；仅勾选需要隔离或 P2P 协助的异地路由器/节点。
          </div>

          <div className="space-y-3">
            {(p2pReport?.peers || []).length === 0 ? (
              <div className="p-4 rounded-xl border border-subtle bg-surface2 text-xs text-secondary text-center">
                {p2pLoading ? '正在读取 Tailscale 节点拓扑…' : '暂无已发现的 Tailscale 对端节点'}
              </div>
            ) : (
              (p2pReport?.peers || []).map((p) => {
                const k = peerEditKey(p);
                const ed = peerEdits[k];
                if (!ed) return null;
                const isDirect = Boolean(p.curAddr);
                const showLANTargets =
                  ed.configured && (ed.accessMode === 'bidirectional' || ed.accessMode === 'bidirectional_timed');

                return (
                  <div key={k} className="p-3.5 rounded-xl border border-subtle bg-surface2 space-y-3">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <div className="min-w-0">
                        <div className="flex flex-wrap items-center gap-2">
                          <span className="text-xs sm:text-sm font-semibold text-primary">
                            {p.shortName || p.name || p.hostName}
                          </span>
                          <Badge tone={p.online ? 'ok' : 'neutral'} dot>
                            {p.online ? '在线' : '离线'}
                          </Badge>
                          {p.online && (
                            <Badge tone={isDirect ? 'ok' : 'warn'}>
                              {isDirect ? 'P2P 直连' : `DERP 中继${p.relay ? ` (${p.relay})` : ''}`}
                            </Badge>
                          )}
                          {p.pinholeActive && <Badge tone="warn">JIT 窗口放行中</Badge>}
                          {p.cooldownRemainingSec > 0 && (
                            <Badge tone="neutral">退避冷却 {p.cooldownRemainingSec}s</Badge>
                          )}
                        </div>
                        <div className="text-[11px] font-mono text-secondary mt-1 flex flex-wrap gap-x-3 gap-y-0.5">
                          <span>IP: {p.tailscaleIPs?.join(', ') || '-'}</span>
                          {p.primaryRoutes && p.primaryRoutes.length > 0 && (
                            <span>广播子网: {p.primaryRoutes.join(', ')}</span>
                          )}
                          <span>候选公网端点: {p.candidatePublicCount}</span>
                          {p.lastUpgradeAt && <span>最近直连: {p.lastUpgradeAt}</span>}
                        </div>
                      </div>

                      <div className="flex items-center gap-2">
                        <Button
                          size="sm"
                          disabled={!p2pEnabled || !ed.configured || !ed.jitEnabled || !p.online || pokingKey === k}
                          onClick={() => handlePokePeer(p)}
                        >
                          <Zap className="w-3.5 h-3.5" />
                          {pokingKey === k ? '打洞中…' : '测试瞬时打洞'}
                        </Button>
                      </div>
                    </div>

                    <div className="flex flex-wrap items-center gap-4 pt-2 border-t border-subtle text-xs">
                      <label className="inline-flex items-center gap-2 cursor-pointer text-primary">
                        <input
                          type="checkbox"
                          checked={ed.configured}
                          onChange={(e) => updatePeerEdit(k, { configured: e.target.checked })}
                          className="accent-[var(--accent)] w-4 h-4"
                        />
                        <span>纳入防线管控</span>
                      </label>

                      {ed.configured && (
                        <>
                          <label className="inline-flex items-center gap-2 cursor-pointer text-primary">
                            <input
                              type="checkbox"
                              checked={ed.jitEnabled}
                              onChange={(e) => updatePeerEdit(k, { jitEnabled: e.target.checked })}
                              className="accent-[var(--accent)] w-4 h-4"
                            />
                            <span>允许 JIT 自动瞬时打洞</span>
                          </label>

                          <SegmentedTabs
                            items={P2P_ACCESS_MODES}
                            value={ed.accessMode}
                            onChange={(val) => {
                              const nextMode = val as TailscaleAccessMode;
                              const patch: Partial<EditableP2PPeer> = { accessMode: nextMode };
                              if (nextMode === 'bidirectional_timed' && !ed.bidirectionalUntil) {
                                patch.bidirectionalUntil = new Date(Date.now() + 7 * 86400 * 1000)
                                  .toISOString()
                                  .replace(/\.\d{3}Z$/, 'Z');
                              }
                              updatePeerEdit(k, patch);
                            }}
                          />
                        </>
                      )}
                    </div>

                    {showLANTargets && (
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-3 pt-2 border-t border-subtle text-xs">
                        {ed.accessMode === 'bidirectional_timed' && (
                          <div className="space-y-1.5">
                            <div className="flex items-center justify-between gap-2">
                              <span className="font-medium text-primary">限时双向到期时间 (UTC RFC3339)</span>
                              <span className="text-[11px] font-mono text-secondary">
                                {p.bidirectionalRemainingSec > 0
                                  ? formatRemainingCountdown(p.bidirectionalRemainingSec)
                                  : '保存后按设定倒计时生效'}
                              </span>
                            </div>
                            <input
                              type="text"
                              value={ed.bidirectionalUntil}
                              onChange={(e) => updatePeerEdit(k, { bidirectionalUntil: e.target.value })}
                              placeholder="2026-12-01T00:00:00Z"
                              className="w-full px-2.5 py-1.5 rounded-lg border border-subtle bg-surface1 font-mono text-xs text-primary"
                            />
                            <div className="flex flex-wrap gap-1.5">
                              {[7, 15, 30].map((d) => (
                                <Button key={d} size="sm" onClick={() => applyQuickDays(k, d)}>
                                  +{d}天
                                </Button>
                              ))}
                            </div>
                          </div>
                        )}

                        <div className="space-y-1.5">
                          <span className="block font-medium text-primary">
                            允许对方主动访问的本机 LAN 目标（留空默认 {p2pReport?.defaultLanCidr || '本地 LAN 网段'}）
                          </span>
                          <input
                            type="text"
                            value={ed.allowedLanTargetsText}
                            onChange={(e) => updatePeerEdit(k, { allowedLanTargetsText: e.target.value })}
                            placeholder={p2pReport?.defaultLanCidr ? `${p2pReport.defaultLanCidr}, 192.168.1.10:445` : '192.168.1.0/24, 192.168.1.10:445'}
                            className="w-full px-2.5 py-1.5 rounded-lg border border-subtle bg-surface1 font-mono text-xs text-primary"
                          />
                        </div>
                      </div>
                    )}
                  </div>
                );
              })
            )}
          </div>

          <div className="flex flex-wrap items-center justify-between gap-3 pt-2 border-t border-subtle">
            <div className="text-[11px] text-secondary font-mono">
              {p2pReport?.runtime?.lastError
                ? `最近状态异常: ${p2pReport.runtime.lastError}`
                : p2pReport?.runtime?.updatedAt
                ? `最近守护收敛: ${p2pReport.runtime.updatedAt}`
                : '修改配置并保存后立即下发防火墙与看门狗'}
            </div>
            <Button variant="primary" disabled={p2pSaving} onClick={handleSaveP2P}>
              <Save className="w-3.5 h-3.5" />
              {p2pSaving ? '正在下发规则…' : '保存并应用防线策略'}
            </Button>
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

const SECONDARY_ROUTER_IPV6_CMD = `cp -a /etc/config/dhcp /etc/config/dhcp.bak && chmod 600 /etc/config/dhcp.bak && \\
uci set dhcp.@dnsmasq[0].dnsforwardmax=1024 && \\
for s in $(uci show dhcp | sed -n 's/^dhcp\\.\\([^.=]*\\)=dhcp$/\\1/p'); do
  [ "$s" = "wan" ] || [ "$s" = "wan6" ] && continue
  uci set "dhcp.$s.ra_dns=0"
  uci set "dhcp.$s.dns_service=0"
done && \\
uci commit dhcp && /etc/init.d/odhcpd reload && /etc/init.d/dnsmasq reload`;

export const GatewayModePage: React.FC<GatewayModePageProps> = ({ busy, onSaved }) => {
  const { success, error } = useToast();
  const [data, setData] = useState<ClientGatewayConfigResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);

  const [mode, setMode] = useState<GatewayRoleMode>('main');
  const [mainRouterIP, setMainRouterIP] = useState('');
  const [ipv6Mode, setIpv6Mode] = useState<GatewayIPv6Mode>('off');
  const [ipv6Saving, setIpv6Saving] = useState(false);
  const [copiedSubCmd, setCopiedSubCmd] = useState(false);

  const handleCopySubRouterCmd = async () => {
    try {
      if (navigator.clipboard?.writeText) {
        await navigator.clipboard.writeText(SECONDARY_ROUTER_IPV6_CMD);
      } else {
        const ta = document.createElement('textarea');
        ta.value = SECONDARY_ROUTER_IPV6_CMD;
        ta.setAttribute('readonly', '');
        ta.style.position = 'fixed';
        ta.style.opacity = '0';
        document.body.appendChild(ta);
        ta.select();
        document.execCommand('copy');
        document.body.removeChild(ta);
      }
      setCopiedSubCmd(true);
      success('已复制二级路由一键加固命令');
      window.setTimeout(() => setCopiedSubCmd(false), 2000);
    } catch {
      error('复制失败，请手动选中下方命令复制');
    }
  };

  const loadGateway = useCallback(async () => {
    setLoading(true);
    try {
      const res = await clientApi.getGateway();
      setData(res);
      setMode(res.mode === 'side' ? 'side' : 'main');
      setMainRouterIP(res.mainRouterIP || res.topology?.suggestedMainRouterIP || '');
      setIpv6Mode((res.ipv6Mode as GatewayIPv6Mode) || 'off');
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
  const v6Status = data?.ipv6Status;
  const trimmedIP = mainRouterIP.trim();
  const isSelfLoop = Boolean(mode === 'side' && topo?.lanIP && trimmedIP === topo.lanIP);

  const handleSelectMode = (nextMode: GatewayRoleMode) => {
    setMode(nextMode);
    if (nextMode === 'side') {
      setIpv6Mode('off');
      if (!trimmedIP && topo?.suggestedMainRouterIP) {
        setMainRouterIP(topo.suggestedMainRouterIP);
      }
    }
  };

  const handleSave = async (forIPv6 = false) => {
    if (mode === 'side' && !trimmedIP) {
      error('旁路由模式请填写上级主路由(网关) IP');
      return;
    }
    if (isSelfLoop) {
      error(`上级主路由 IP 不能等于旁路由本机 IP (${topo?.lanIP})`);
      return;
    }
    const effectiveV6: GatewayIPv6Mode = mode === 'side' ? 'off' : ipv6Mode;
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
      setData(res);
      setMode(res.mode);
      setMainRouterIP(res.mainRouterIP || res.topology?.suggestedMainRouterIP || '');
      setIpv6Mode((res.ipv6Mode as GatewayIPv6Mode) || effectiveV6);
      success(res.message || '网关模式已保存');
      onSaved?.();
    } catch (e: unknown) {
      error(e instanceof Error ? e.message : '保存网关模式失败');
    } finally {
      setSaving(false);
      setIpv6Saving(false);
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
              <code className="font-mono text-cyan-300">{sideLanDisplay}</code>（切勿修改主路由 WAN 口上游 DNS）。
            </p>
            <p>
              3. <strong className="text-primary">防绕过与防自环提醒</strong>：请为旁路由本机固定静态 IP（或在主路由绑定静态租约），并在主路由关闭 LAN 侧{' '}
              <code className="font-mono text-amber-300">IPv6 RA / DHCPv6</code> 通告，防止手机经主路由 IPv6 直出绕过旁路由。
            </p>
          </div>
        </SectionCard>
      )}

      <SectionCard
        title="IPv6 智能双栈分流 (自动探测与配置)"
        icon={<Network className="w-4 h-4" />}
        subtitle="主路由开启时自动探测 WAN 前缀，一键托管 OpenWrt RA/DHCPv6、dnsmasq 放行与本地防 DNS 泄漏策略"
        actions={
          <Badge
            tone={
              ipv6Mode === 'off'
                ? 'neutral'
                : ipv6Mode === 'cn_only'
                  ? 'ok'
                  : 'accent'
            }
          >
            {ipv6Mode === 'cn_only'
              ? '当前：智能双栈 (推荐)'
              : ipv6Mode === 'full'
                ? '当前：全量双栈'
                : '当前：纯 IPv4'}
          </Badge>
        }
      >
        <div className="space-y-4">
          {v6Status && (
            <div className="rounded-xl border border-subtle bg-surface2/60 px-3.5 py-2.5 flex flex-wrap items-center gap-x-4 gap-y-1.5 text-xs">
              <div className="flex items-center gap-1.5">
                <span className="text-muted">WAN IPv6:</span>
                <Badge tone={v6Status.wanHasGua ? 'ok' : 'warn'}>
                  {v6Status.wanHasGua
                    ? v6Status.pdPrefix
                      ? `已获公网 + PD ${v6Status.pdPrefix}`
                      : '已获公网地址'
                    : '未检测到公网 IPv6'}
                </Badge>
              </div>
              <div className="flex items-center gap-1.5">
                <span className="text-muted">LAN 前缀与 RA:</span>
                <span className="font-mono text-primary">
                  {v6Status.lanPrefixes && v6Status.lanPrefixes.length > 0
                    ? v6Status.lanPrefixes.join(', ')
                    : '未分配'}
                </span>
                {v6Status.isOpenWrt && (
                  <span className="text-[11px] text-secondary">
                    (RA={v6Status.lanRaMode || 'off'}, DHCPv6={v6Status.lanDhcpv6Mode || 'off'})
                  </span>
                )}
              </div>
              {v6Status.isOpenWrt && (
                <>
                  <div className="flex items-center gap-1.5">
                    <span className="text-muted">dnsmasq AAAA:</span>
                    <span className="font-mono text-primary">
                      {v6Status.dnsmasqFilterAaaa === '1' ? '过滤关闭' : '正常解析'}
                    </span>
                  </div>
                  <div className="flex items-center gap-1.5">
                    <span className="text-muted">IPv6 DNS 通告:</span>
                    <Badge tone={v6Status.raDnsAnnounce ? 'warn' : 'ok'}>
                      {v6Status.raDnsAnnounce ? '仍在通告' : '已关闭(仅 IPv4 DNS)'}
                    </Badge>
                  </div>
                  <div className="flex items-center gap-1.5">
                    <span className="text-muted">并发上限:</span>
                    <span className="font-mono text-primary">
                      {v6Status.dnsmasqForwardMax || '默认(150)'}
                    </span>
                  </div>
                </>
              )}
            </div>
          )}

          {v6Status?.warnings && v6Status.warnings.length > 0 && (
            <div className="rounded-xl border border-amber-500/35 bg-amber-500/10 px-3.5 py-2.5 text-xs text-amber-200 space-y-1">
              {v6Status.warnings.map((w, idx) => (
                <div key={idx} className="flex items-start gap-2">
                  <AlertTriangle className="w-3.5 h-3.5 text-amber-400 shrink-0 mt-0.5" />
                  <span>{w}</span>
                </div>
              ))}
            </div>
          )}

          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
            {[
              {
                key: 'off' as GatewayIPv6Mode,
                title: '关闭 (仅 IPv4)',
                tag: '默认兼容',
                desc: '屏蔽并还原 AAAA 解析（ipv4_only），最稳妥但局域网设备不使用宽带 IPv6。',
                disabled: false,
              },
              {
                key: 'cn_only' as GatewayIPv6Mode,
                title: '智能双栈 (国内 IPv6 + 海外 IPv4)',
                tag: '黄金推荐',
                desc: '国内直连与 PT 原生 IPv6+IPv4；海外域名 0ms 静音海外 AAAA/HTTPS、拦截 DoT/国内 DoH 与代理侧 ::/0，彻底免去节点无 IPv6 导致的卡顿/弹盾与泄漏。',
                disabled: mode === 'side',
              },
              {
                key: 'full' as GatewayIPv6Mode,
                title: '全量双栈 (国内外全部 IPv6)',
                tag: '节点需双栈',
                desc: '国内外域名均保留 A+AAAA 双栈解析。仅建议在自建/机场主力节点全部具备优质 IPv6 出站时启用。',
                disabled: mode === 'side',
              },
            ].map((opt) => {
              const selected = (mode === 'side' ? 'off' : ipv6Mode) === opt.key;
              return (
                <button
                  key={opt.key}
                  type="button"
                  disabled={opt.disabled}
                  onClick={() => setIpv6Mode(opt.key)}
                  style={
                    selected
                      ? {
                          backgroundColor: 'var(--accent-soft)',
                          borderColor: 'var(--accent)',
                        }
                      : undefined
                  }
                  className={`p-3.5 rounded-xl border text-left transition-all ${
                    opt.disabled
                      ? 'opacity-45 cursor-not-allowed bg-surface2 border-subtle'
                      : selected
                        ? 'cursor-pointer'
                        : 'bg-surface2 border-subtle hover:border-strong cursor-pointer'
                  }`}
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-xs sm:text-sm font-semibold text-primary">{opt.title}</span>
                    <span className="text-[10px] px-1.5 py-0.5 rounded bg-surface1 text-secondary border border-subtle shrink-0">
                      {opt.tag}
                    </span>
                  </div>
                  <p className="text-[11px] text-secondary mt-1.5 leading-relaxed">{opt.desc}</p>
                </button>
              );
            })}
          </div>

          {mode !== 'side' && ipv6Mode !== 'off' && (
            <div className="rounded-xl border border-sky-500/35 bg-sky-500/10 px-3.5 py-3 space-y-2 text-xs text-sky-100">
              <div className="flex items-center gap-2 font-semibold text-sky-200">
                <Smartphone className="w-4 h-4 text-sky-400 shrink-0" />
                <span>开启 IPv6 必看：如何彻底关闭手机端 5G 蜂窝兜底泄漏</span>
              </div>
              <p className="text-[11px] text-sky-100/90 leading-relaxed">
                当路由器对海外 AAAA/HTTPS 做静音（或遭遇高并发 DNS 探测）时，手机若开启 Wi-Fi/蜂窝智能切网且同时开着 5G 数据，系统会误判 Wi-Fi 无 IPv6 而直接经 5G 基站发出运营商 IPv6 DNS 查询，绕过家用路由器：
              </p>
              <ul className="space-y-1 text-[11px] text-sky-100/90 list-disc pl-4 leading-relaxed">
                <li>
                  <span className="font-semibold text-white">iPhone (iOS)</span>：打开{' '}
                  <code className="px-1 py-0.5 rounded bg-sky-950/60 border border-sky-400/20">设置 → 无线局域网 (WLAN)</code>{' '}
                  关闭 <span className="font-semibold text-white">「连接助理」</span>（部分系统版本位于{' '}
                  <code className="px-1 py-0.5 rounded bg-sky-950/60 border border-sky-400/20">设置 → 蜂窝网络 → 展开全部应用 → 拉至最底端</code>{' '}
                  关闭 <span className="font-semibold text-white">「无线局域网助理」</span>）。
                </li>
                <li>
                  <span className="font-semibold text-white">华为 / 鸿蒙</span>：打开{' '}
                  <code className="px-1 py-0.5 rounded bg-sky-950/60 border border-sky-400/20">设置 → WLAN → 更多 WLAN 设置</code>{' '}
                  关闭 <span className="font-semibold text-white">「WLAN+」</span> 与{' '}
                  <span className="font-semibold text-white">「网络加速 / 双通道加速」</span>。
                </li>
                <li>
                  <span className="font-semibold text-white">小米 / OPPO / vivo / 三星等安卓</span>：打开{' '}
                  <code className="px-1 py-0.5 rounded bg-sky-950/60 border border-sky-400/20">设置 → WLAN → WLAN 助理 / 智能选网</code>{' '}
                  关闭 <span className="font-semibold text-white">「自动切换移动数据」</span> 与{' '}
                  <span className="font-semibold text-white">「双通道加速」</span>。
                </li>
                <li>
                  <span className="font-semibold text-white">多级路由 &amp; 生效步骤</span>：若前端还接有二级无线路由器，请同步将其{' '}
                  <code className="px-1 py-0.5 rounded bg-sky-950/60 border border-sky-400/20">dnsforwardmax</code> 调至{' '}
                  <code className="px-1 py-0.5 rounded bg-sky-950/60 border border-sky-400/20">1024</code> 并关闭 IPv6 RDNSS（
                  <code className="px-1 py-0.5 rounded bg-sky-950/60 border border-sky-400/20">ra_dns=0</code> /{' '}
                  <code className="px-1 py-0.5 rounded bg-sky-950/60 border border-sky-400/20">dns_service=0</code>）；保存后请
                  <span className="font-semibold text-white">断开并重连一次 Wi-Fi</span> 刷新租约后再复测。
                </li>
              </ul>
              <div className="rounded-lg border border-sky-400/20 bg-slate-950/75 p-2.5 space-y-1.5">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <span className="text-[11px] font-medium text-sky-200/95">
                    二级 OpenWrt / ImmortalWrt 无线路由一键加固命令（SSH 登录二级路由后直接粘贴执行）
                  </span>
                  <button
                    type="button"
                    onClick={() => void handleCopySubRouterCmd()}
                    className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md border border-sky-400/30 bg-sky-500/15 hover:bg-sky-500/25 text-[11px] text-sky-100 transition-colors cursor-pointer"
                  >
                    {copiedSubCmd ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                    <span>{copiedSubCmd ? '已复制' : '复制命令'}</span>
                  </button>
                </div>
                <pre className="overflow-x-auto text-[11px] font-mono text-sky-100/95 leading-relaxed select-all whitespace-pre">
                  {SECONDARY_ROUTER_IPV6_CMD}
                </pre>
              </div>
            </div>
          )}

          <div className="flex flex-wrap items-center justify-between gap-3 pt-2 border-t border-subtle">
            <span className="text-[11px] text-muted">
              {mode === 'side'
                ? '当前选择旁路由模式：为避免主路由 RA 绕过旁路由造成泄漏，IPv6 自动保持关闭。'
                : '保存后自动同步 OpenWrt RA/DHCPv6、dnsmasq 与 sing-box 规则并零断网热重载（切回关闭会自动按备份还原）。'}
            </span>
            <Button
              variant="primary"
              loading={ipv6Saving}
              disabled={busy || loading || isSelfLoop}
              icon={<Save className="w-3.5 h-3.5" />}
              onClick={() => void handleSave(true)}
            >
              保存并自动配置 IPv6
            </Button>
          </div>
        </div>
      </SectionCard>

      <DNSLeakTestCard />
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

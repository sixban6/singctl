import React, { useCallback, useEffect, useRef, useState } from 'react';
import { RefreshCw, Save, ShieldCheck, Zap } from 'lucide-react';
import { Badge, Button, SectionCard, SegmentedTabs, useToast } from '../../../ui';
import { useCachedQuery } from '../../../hooks';
import { clientApi } from '../../api';
import { TAILSCALE_P2P_CACHE_KEY } from '../../cacheKeys';
import { redactInlineSensitive } from '../../../lib/privacyMask';
import {
  TailscaleAccessMode,
  TailscaleP2PPeerConfig,
  TailscaleP2PPeerView,
  TailscaleP2PReport,
} from '../../types';

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

export const TailscaleP2PSection: React.FC<{ privacyMask: boolean }> = ({ privacyMask }) => {
  const { toast } = useToast();
  const {
    data: p2pReport,
    loading: p2pLoading,
    setData: setP2pReportData,
    refetch: refetchP2P,
  } = useCachedQuery<TailscaleP2PReport>(TAILSCALE_P2P_CACHE_KEY, () => clientApi.getTailscaleP2P());

  const p2pDirtyRef = useRef(false);
  const [p2pSaving, setP2pSaving] = useState(false);
  const [pokingKey, setPokingKey] = useState('');

  const p2pLiveEnabled = Boolean(p2pReport?.config?.enabled);
  const [jitWindowSec, setJitWindowSec] = useState(() =>
    p2pReport?.config?.jit_window_sec && p2pReport.config.jit_window_sec > 0
      ? p2pReport.config.jit_window_sec
      : 5,
  );
  const [cooldownSec, setCooldownSec] = useState(() =>
    p2pReport?.config?.cooldown_sec && p2pReport.config.cooldown_sec > 0 ? p2pReport.config.cooldown_sec : 300,
  );
  const [sandboxUjail, setSandboxUjail] = useState(() =>
    p2pReport?.ujailAvailable
      ? !p2pReport.config?.enabled
        ? true
        : Boolean(p2pReport.config?.sandbox_ujail)
      : false,
  );
  const [peerEdits, setPeerEdits] = useState<Record<string, EditableP2PPeer>>({});

  const hydrateP2PReport = useCallback(
    (rep: TailscaleP2PReport, updateCache = true) => {
      if (updateCache) {
        setP2pReportData(rep);
      }
      setJitWindowSec(rep.config?.jit_window_sec && rep.config.jit_window_sec > 0 ? rep.config.jit_window_sec : 5);
      setCooldownSec(rep.config?.cooldown_sec && rep.config.cooldown_sec > 0 ? rep.config.cooldown_sec : 300);
      setSandboxUjail(
        rep.ujailAvailable ? (!rep.config?.enabled ? true : Boolean(rep.config?.sandbox_ujail)) : false,
      );

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
    },
    [setP2pReportData],
  );

  useEffect(() => {
    if (!p2pReport) return;
    if (!p2pDirtyRef.current) {
      hydrateP2PReport(p2pReport, false);
    }
  }, [p2pReport, hydrateP2PReport]);

  const loadP2P = useCallback(async () => {
    p2pDirtyRef.current = false;
    try {
      const rep = await refetchP2P(false);
      if (rep) hydrateP2PReport(rep, false);
    } catch (err) {
      toast((err as Error)?.message || '读取 P2P 防线状态失败', 'error');
    }
  }, [hydrateP2PReport, refetchP2P, toast]);

  const updatePeerEdit = (k: string, patch: Partial<EditableP2PPeer>) => {
    p2pDirtyRef.current = true;
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
        enabled: true,
        jit_window_sec: Math.min(10, Math.max(3, Number(jitWindowSec) || 5)),
        cooldown_sec: Math.min(3600, Math.max(30, Number(cooldownSec) || 300)),
        payload_filter: true,
        sandbox_ujail: Boolean(p2pReport?.ujailAvailable && sandboxUjail),
        peers: peersPayload,
      });
      p2pDirtyRef.current = false;
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
    <SectionCard
      title="P2P 直连防线 · 零常驻暴露 (JIT)"
      icon={<ShieldCheck className="w-4 h-4" />}
      subtitle="闲置与直连期间 WAN 侧 UDP :41641 零暴露；仅在授权节点按需直连时瞬时放行 3~10s 并在连上后毫秒级自动关门"
      actions={
        <div className="flex items-center gap-2">
          {p2pReport && (
            <Badge tone={p2pReport.openPinholes > 0 ? 'warn' : p2pLiveEnabled ? 'ok' : 'neutral'} dot>
              {p2pReport.openPinholes > 0
                ? `瞬时放行 ${p2pReport.openPinholes} 个 IP`
                : p2pLiveEnabled
                  ? '0 开放 · 零暴露'
                  : '未开启'}
            </Badge>
          )}
          <Button size="sm" variant="ghost" onClick={() => void loadP2P()} disabled={p2pLoading}>
            <RefreshCw className={`w-3.5 h-3.5 ${p2pLoading ? 'animate-spin' : ''}`} />
            刷新
          </Button>
        </div>
      }
    >
      <div className="space-y-4">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs">
          <div
            className="flex items-center justify-between gap-3 p-3.5 rounded-xl border border-subtle bg-surface2 cursor-default"
            title="核心防线默认强制开启，确保 UDP :41641 不长期裸露公网"
          >
            <div className="min-w-0">
              <div className="font-semibold text-primary flex items-center gap-1.5 flex-wrap">
                <span>启用防线守护</span>
                <span className="text-[10px] px-1.5 py-0.5 rounded bg-[var(--accent)]/15 text-[var(--accent)] font-medium">
                  必选
                </span>
              </div>
              <div className="text-[11px] text-secondary mt-1 truncate">
                {p2pReport?.fw4Available
                  ? p2pReport.runtime?.applyMode === 'nft_direct'
                    ? 'OpenWrt nftables 原子注入就绪'
                    : 'OpenWrt fw4 原生热重载就绪'
                  : '未检测到 inet fw4 表'}
              </div>
            </div>
            <input
              type="checkbox"
              checked
              readOnly
              tabIndex={-1}
              aria-label="启用防线守护（必选）"
              className="accent-[var(--accent)] w-4 h-4 shrink-0 pointer-events-none"
            />
          </div>

          <div
            className="flex items-center justify-between gap-3 p-3.5 rounded-xl border border-subtle bg-surface2 cursor-default"
            title="核心安全拦截默认强制开启，仅放行 STUN / DISCO / WireGuard 合法载荷"
          >
            <div className="min-w-0">
              <div className="font-semibold text-primary flex items-center gap-1.5 flex-wrap">
                <span>Layer 2 载荷魔法头过滤</span>
                <span className="text-[10px] px-1.5 py-0.5 rounded bg-[var(--accent)]/15 text-[var(--accent)] font-medium">
                  必选
                </span>
              </div>
              <div className="text-[11px] text-secondary mt-1 truncate">
                UDP :41641 仅放行 STUN / DISCO / WireGuard
              </div>
            </div>
            <input
              type="checkbox"
              checked
              readOnly
              tabIndex={-1}
              aria-label="Layer 2 载荷魔法头过滤（必选）"
              className="accent-[var(--accent)] w-4 h-4 shrink-0 pointer-events-none"
            />
          </div>

          <label
            className={`flex items-center justify-between gap-3 p-3.5 rounded-xl border border-subtle bg-surface2 ${
              p2pReport?.ujailAvailable ? 'cursor-pointer' : 'opacity-60 cursor-not-allowed'
            }`}
            title={p2pReport?.ujailAvailable ? '重启 tailscaled 进入 OpenWrt ujail 沙盒' : '当前环境无 /sbin/ujail'}
          >
            <div className="min-w-0">
              <div className="font-semibold text-primary flex items-center gap-1.5 flex-wrap">
                <span>Layer 3 ujail 沙盒隔离</span>
                <span className="text-[10px] px-1.5 py-0.5 rounded bg-surface1 text-secondary border border-subtle font-medium">
                  {p2pReport?.ujailAvailable ? '默认开启 · 可取消' : '不可用'}
                </span>
              </div>
              <div className="text-[11px] text-secondary mt-1 truncate">
                {p2pReport?.ujailAvailable ? '裁剪 Capabilities 并隔离敏感配置目录' : '当前环境无 /sbin/ujail'}
              </div>
            </div>
            <input
              type="checkbox"
              disabled={!p2pReport?.ujailAvailable}
              checked={sandboxUjail}
              onChange={(e) => {
                p2pDirtyRef.current = true;
                setSandboxUjail(e.target.checked);
              }}
              aria-label="Layer 3 ujail 沙盒隔离"
              className="accent-[var(--accent)] w-4 h-4 shrink-0"
            />
          </label>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
          <div className="p-3 rounded-xl border border-subtle bg-surface2">
            <label className="block font-semibold text-primary mb-1">JIT 瞬时窗口（秒）</label>
            <input
              type="number"
              min={3}
              max={10}
              value={jitWindowSec}
              onChange={(e) => {
                p2pDirtyRef.current = true;
                setJitWindowSec(Number(e.target.value));
              }}
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
              onChange={(e) => {
                p2pDirtyRef.current = true;
                setCooldownSec(Number(e.target.value));
              }}
              className="w-full px-2.5 py-1.5 rounded-lg border border-subtle bg-surface1 font-mono text-xs text-primary focus:outline-none focus:border-[var(--accent)]"
            />
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
            (p2pReport?.peers || []).map((p, peerIdx) => {
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
                          {privacyMask ? `对端节点 #${peerIdx + 1}` : p.shortName || p.name || p.hostName}
                        </span>
                        <Badge tone={p.online ? 'ok' : 'neutral'} dot>
                          {p.online ? '在线' : '离线'}
                        </Badge>
                        {p.online && (
                          <Badge tone={isDirect ? 'ok' : 'warn'}>
                            {isDirect ? 'P2P 直连' : `DERP 中继${!privacyMask && p.relay ? ` (${p.relay})` : ''}`}
                          </Badge>
                        )}
                        {p.pinholeActive && <Badge tone="warn">JIT 窗口放行中</Badge>}
                        {p.cooldownRemainingSec > 0 && (
                          <Badge tone="neutral">退避冷却 {p.cooldownRemainingSec}s</Badge>
                        )}
                      </div>
                      <div className="text-[11px] font-mono text-secondary mt-1 flex flex-wrap gap-x-3 gap-y-0.5">
                        <span>IP: {privacyMask ? '••••••••' : p.tailscaleIPs?.join(', ') || '-'}</span>
                        {p.primaryRoutes && p.primaryRoutes.length > 0 && (
                          <span>广播子网: {privacyMask ? '••••••••' : p.primaryRoutes.join(', ')}</span>
                        )}
                        <span>候选公网端点: {p.candidatePublicCount}</span>
                        {p.lastUpgradeAt && <span>最近直连: {p.lastUpgradeAt}</span>}
                      </div>
                    </div>

                    <div className="flex items-center gap-2">
                      <Button
                        size="sm"
                        disabled={!p2pLiveEnabled || !ed.configured || !ed.jitEnabled || !p.online || pokingKey === k}
                        onClick={() => void handlePokePeer(p)}
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
                          允许对方主动访问的本机 LAN 目标（留空默认{' '}
                          {privacyMask ? '本地 LAN 网段 (已遮挡)' : p2pReport?.defaultLanCidr || '本地 LAN 网段'}）
                        </span>
                        <input
                          type={privacyMask ? 'password' : 'text'}
                          readOnly={privacyMask}
                          value={ed.allowedLanTargetsText}
                          onChange={(e) => updatePeerEdit(k, { allowedLanTargetsText: e.target.value })}
                          placeholder={
                            privacyMask
                              ? '••••••••'
                              : p2pReport?.defaultLanCidr
                                ? `${p2pReport.defaultLanCidr}, 192.168.1.10:445`
                                : '192.168.1.0/24, 192.168.1.10:445'
                          }
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
              ? `最近状态异常: ${redactInlineSensitive(p2pReport.runtime.lastError, privacyMask)}`
              : p2pReport?.runtime?.updatedAt
                ? `最近守护收敛: ${p2pReport.runtime.updatedAt}`
                : '修改配置并保存后立即下发防火墙与看门狗'}
          </div>
          <Button variant="primary" disabled={p2pSaving || privacyMask} onClick={() => void handleSaveP2P()}>
            <Save className="w-3.5 h-3.5" />
            {p2pSaving ? '正在下发规则…' : '保存并应用防线策略'}
          </Button>
        </div>
      </div>
    </SectionCard>
  );
};

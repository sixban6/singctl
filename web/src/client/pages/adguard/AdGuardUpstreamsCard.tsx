import React, { useMemo, useState } from 'react';
import { Check, Plus, RotateCcw, Server, Trash2, Trophy, Zap } from 'lucide-react';
import { Badge, Button, SectionCard } from '../../../ui';
import {
  DNSOverviewSnapshot,
  DNSUpstreamMode,
  DNSUpstreamProbeItem,
  UpstreamProbeReport,
} from '../../types';
import {
  getUpstreamModeBadgeText,
  getUpstreamModeOptions,
  isPureIPUpstreamAddress,
  normalizeUpstreamMode,
  resolveActiveEngine,
} from './adguardHelpers';

export interface AdGuardUpstreamsCardProps {
  snap: DNSOverviewSnapshot | null;
  probe: UpstreamProbeReport | null;
  probing: boolean;
  savingUpstreams: boolean;
  mutating: boolean;
  canMutate: boolean;
  onRunProbe: () => void;
  onUpdateUpstreams: (
    nextList: string[],
    nextMode?: DNSUpstreamMode,
    resetDefault?: boolean,
  ) => Promise<boolean>;
  onTogglePreset: (presetAddr: string) => void;
  onRemoveUpstream: (addr: string) => void;
}

export const AdGuardUpstreamsCard: React.FC<AdGuardUpstreamsCardProps> = ({
  snap,
  probe,
  probing,
  savingUpstreams,
  mutating,
  canMutate,
  onRunProbe,
  onUpdateUpstreams,
  onTogglePreset,
  onRemoveUpstream,
}) => {
  const [upstreamInput, setUpstreamInput] = useState('');
  const activeEngine = resolveActiveEngine(snap);
  const modeOptions = useMemo(() => getUpstreamModeOptions(activeEngine), [activeEngine]);
  const currentMode = normalizeUpstreamMode(activeEngine, snap?.upstreamMode);

  const probeItemMap = useMemo(() => {
    const map = new Map<string, DNSUpstreamProbeItem>();
    for (const item of probe?.upstreams || []) {
      map.set(item.address.toLowerCase(), item);
    }
    return map;
  }, [probe?.upstreams]);

  const activeUpstreamSet = useMemo(() => {
    return new Set((snap?.upstreams || []).map((u) => u.address.toLowerCase()));
  }, [snap?.upstreams]);

  const { pureIPCount, hasDomainUpstream } = useMemo(() => {
    let pureCount = 0;
    let hasDomain = false;
    for (const u of snap?.upstreams || []) {
      if (isPureIPUpstreamAddress(u.address)) {
        pureCount += 1;
      } else {
        hasDomain = true;
      }
    }
    return { pureIPCount: pureCount, hasDomainUpstream: hasDomain };
  }, [snap?.upstreams]);

  const handleAddCustomUpstream = async (e: React.FormEvent) => {
    e.preventDefault();
    const raw = upstreamInput.trim();
    if (!raw || !snap) return;
    const current = (snap.upstreams || []).map((u) => u.address);
    const ok = await onUpdateUpstreams([...current, raw]);
    if (ok) {
      setUpstreamInput('');
    }
  };

  return (
    <SectionCard
      title="加密上游 DNS 服务器与竞速策略"
      icon={<Server className="w-4 h-4" />}
      subtitle="支持纯 IP 与域名型加密 DoH / DoT / DoQ 上游（至少保留 1 条纯 IP 兜底），规避 53 端口劫持与透明代理冷启动回环"
      actions={
        <div className="flex flex-wrap items-center gap-2">
          <Button
            size="xs"
            variant="secondary"
            loading={probing}
            disabled={!snap || !snap.dnsHealthy}
            onClick={onRunProbe}
            icon={<Zap className="w-3 h-3" />}
          >
            实测上游速度
          </Button>
          <Button
            size="xs"
            variant="ghost"
            disabled={savingUpstreams || mutating || !canMutate}
            onClick={() => void onUpdateUpstreams([], undefined, true)}
            icon={<RotateCcw className="w-3 h-3" />}
          >
            恢复默认上游
          </Button>
        </div>
      }
    >
      <div className="space-y-4">
        <div className="rounded-xl border border-subtle bg-surface2/70 px-3.5 py-3 flex flex-col lg:flex-row lg:items-center justify-between gap-3">
          <div className="space-y-1 min-w-0">
            <div className="flex flex-wrap items-center gap-2 text-xs">
              <Badge tone="ok">{getUpstreamModeBadgeText(activeEngine, snap?.upstreamMode)}</Badge>
              {probe?.fastestUpstream && (
                <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md bg-emerald-500/15 border border-emerald-500/30 text-emerald-300 font-medium">
                  <Trophy className="w-3 h-3 text-emerald-400" />
                  <span>
                    最快响应：{probe.fastestName} ({probe.fastestLatencyMs}ms)
                  </span>
                </span>
              )}
              {probe?.healthy && (
                <span className="text-[11px] font-mono text-muted">
                  本地引擎端到端：{probe.domain} → {probe.resolved} ({probe.latencyMs}ms)
                </span>
              )}
            </div>
            <p className="text-[11px] text-secondary">
              {snap?.upstreamModeLabel ||
                modeOptions.find((m) => m.key === currentMode)?.shortDesc ||
                '并行竞速（同时请求全部加密上游，每次自动采用最快返回的结果）'}
            </p>
          </div>

          <div
            role="group"
            aria-label="上游查询调度策略"
            className="inline-flex items-center p-0.5 rounded-xl bg-surface1 border border-subtle shrink-0 self-start lg:self-center"
          >
            {modeOptions.map((m) => {
              const active = currentMode === m.key;
              return (
                <button
                  key={m.key}
                  type="button"
                  disabled={savingUpstreams || mutating || !canMutate}
                  title={m.shortDesc}
                  onClick={() => {
                    if (active || !snap) return;
                    void onUpdateUpstreams(
                      (snap.upstreams || []).map((u) => u.address),
                      m.key,
                    );
                  }}
                  className={`px-2.5 py-1 rounded-lg text-xs font-medium transition-colors cursor-pointer disabled:opacity-50 ${
                    active
                      ? 'bg-[var(--accent)] text-white shadow-sm'
                      : 'text-secondary hover:text-primary'
                  }`}
                >
                  {m.label}
                </button>
              );
            })}
          </div>
        </div>

        <div className="divide-y divide-[var(--border-subtle)] rounded-xl border border-subtle bg-surface1 overflow-hidden">
          {(snap?.upstreams || []).map((up) => {
            const pItem = probeItemMap.get(up.address.toLowerCase());
            const isPureIP = isPureIPUpstreamAddress(up.address);
            const isLastPureIPFallback = hasDomainUpstream && pureIPCount <= 1 && isPureIP;
            const canRemove = (snap?.upstreams?.length || 0) > 1 && !isLastPureIPFallback;
            const isManagedUnprobed =
              Boolean(pItem && !pItem.healthy) &&
              (up.protocol === 'DoQ' ||
                up.protocol === 'DoH3' ||
                Boolean(pItem?.error?.includes('暂不支持直接探测')));
            return (
              <div
                key={up.address}
                className="flex flex-col sm:flex-row sm:items-center justify-between gap-2.5 px-3.5 py-2.5 hover:bg-surface2/40 transition-colors"
              >
                <div className="min-w-0 flex flex-wrap items-center gap-2">
                  <Badge tone={up.protocol === 'DoH' || up.protocol === 'DoH3' ? 'accent' : 'neutral'}>
                    {up.protocol}
                  </Badge>
                  <span className="font-mono text-xs sm:text-sm font-semibold text-primary break-all">
                    {up.address}
                  </span>
                  <span className="text-xs text-secondary">{up.name}</span>
                  {isLastPureIPFallback && <Badge tone="ok">兜底纯 IP</Badge>}
                </div>

                <div className="flex items-center justify-between sm:justify-end gap-2 shrink-0">
                  {probing ? (
                    <span className="text-[11px] font-mono text-muted">测速中…</span>
                  ) : pItem ? (
                    pItem.healthy ? (
                      <div className="flex items-center gap-1.5">
                        {pItem.resolved && (
                          <span className="hidden md:inline text-[11px] font-mono text-muted">
                            → {pItem.resolved}
                          </span>
                        )}
                        <span
                          className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-md text-xs font-mono tnum border ${
                            pItem.fastest
                              ? 'bg-emerald-500/15 text-emerald-300 border-emerald-500/35 font-semibold'
                              : pItem.latencyMs <= 60
                                ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20'
                                : pItem.latencyMs <= 150
                                  ? 'bg-sky-500/10 text-sky-300 border-sky-500/20'
                                  : 'bg-amber-500/10 text-amber-300 border-amber-500/20'
                          }`}
                        >
                          {pItem.fastest && <Trophy className="w-3 h-3 text-emerald-400" />}
                          <span>{pItem.latencyMs} ms</span>
                          {pItem.fastest && <span className="font-sans text-[11px]">最快</span>}
                        </span>
                      </div>
                    ) : isManagedUnprobed ? (
                      <Badge tone="neutral">SmartDNS 托管</Badge>
                    ) : (
                      <Badge tone="danger">{pItem.error || '不可达'}</Badge>
                    )
                  ) : (
                    <span className="text-[11px] text-muted">待测速</span>
                  )}

                  <Button
                    size="xs"
                    variant="ghost"
                    disabled={savingUpstreams || !canMutate || !canRemove}
                    title={
                      isLastPureIPFallback
                        ? '存在域名上游时需保留至少 1 条纯 IP 兜底防冷启动死锁'
                        : canRemove
                          ? '移除该上游'
                          : '至少需保留 1 条加密上游'
                    }
                    onClick={() => onRemoveUpstream(up.address)}
                    icon={<Trash2 className="w-3.5 h-3.5" />}
                  />
                </div>
              </div>
            );
          })}
        </div>

        <div className="space-y-2.5 pt-1">
          <div className="text-[11px] text-muted">
            精选国内纯 IP 加密上游预设（已验证 IP 证书并豁免防火墙，点击即可启用或移除）：
          </div>
          <div className="flex flex-wrap gap-1.5">
            {(snap?.upstreamPresets || []).map((preset) => {
              const active = activeUpstreamSet.has(preset.address.toLowerCase());
              return (
                <button
                  key={preset.address}
                  type="button"
                  disabled={savingUpstreams || !canMutate}
                  onClick={() => onTogglePreset(preset.address)}
                  title={preset.address}
                  className={`inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-xl text-xs transition-colors border cursor-pointer disabled:opacity-50 ${
                    active
                      ? 'bg-emerald-500/15 text-emerald-300 border-emerald-500/35 font-medium'
                      : 'bg-surface2 text-secondary hover:text-primary border-subtle'
                  }`}
                >
                  {active ? (
                    <Check className="w-3.5 h-3.5 text-emerald-400" />
                  ) : (
                    <Plus className="w-3.5 h-3.5 opacity-70" />
                  )}
                  <span>{preset.name}</span>
                </button>
              );
            })}
          </div>

          <form
            onSubmit={(e) => void handleAddCustomUpstream(e)}
            className="flex flex-col sm:flex-row gap-2 pt-1"
          >
            <input
              type="text"
              value={upstreamInput}
              onChange={(e) => setUpstreamInput(e.target.value)}
              placeholder="手动添加加密上游，如 https://223.5.5.5/dns-query 或 tls://dot.onedns.net"
              className="flex-1 min-w-0 h-9 px-3 rounded-xl bg-surface2 border border-subtle text-xs sm:text-sm text-primary font-mono focus:outline-none focus:border-strong"
            />
            <Button
              type="submit"
              size="sm"
              variant="secondary"
              loading={savingUpstreams}
              disabled={!upstreamInput.trim() || !canMutate}
              icon={<Plus className="w-3.5 h-3.5" />}
            >
              验证并添加上游
            </Button>
          </form>
        </div>
      </div>
    </SectionCard>
  );
};

import React, { useState } from 'react';
import {
  ChevronDown,
  ChevronUp,
  Layers,
  Radio,
  Shield,
  Sliders,
  Sparkles,
  Wifi,
  WifiOff,
} from 'lucide-react';
import { Badge, Button, SectionCard } from '../../../../ui';
import { WifiRadioInfo, WifiRadioPatch, WifiSSIDInfo } from '../../../types';

interface WifiRadioCardsProps {
  radios: WifiRadioInfo[];
  ssids: WifiSSIDInfo[];
  busy: boolean;
  recommended2gCh?: number;
  recommended5gCh?: number;
  onDualBandMerge: (sourceSection: string, ssid: string) => void;
  onTuneRadio: (patch: WifiRadioPatch) => void;
}

const CHANNELS_2G = ['auto', '1', '6', '11', '2', '3', '4', '5', '7', '8', '9', '10', '12', '13'];
const CHANNELS_5G = ['auto', '36', '40', '44', '48', '149', '153', '157', '161', '165', '52', '56', '60', '64'];

export const WifiRadioCards: React.FC<WifiRadioCardsProps> = ({
  radios,
  ssids,
  busy,
  recommended2gCh,
  recommended5gCh,
  onDualBandMerge,
  onTuneRadio,
}) => {
  const [expandedDev, setExpandedDev] = useState<string | null>(null);
  const [drafts, setDrafts] = useState<Record<string, WifiRadioPatch>>({});

  const openEditor = (r: WifiRadioInfo) => {
    if (expandedDev === r.device) {
      setExpandedDev(null);
      return;
    }
    const devSSIDs = ssids.filter((s) => s.device === r.device && !s.isolate);
    setDrafts((prev) => ({
      ...prev,
      [r.device]: {
        device: r.device,
        disabled: r.disabled,
        channel: r.channel || 'auto',
        htmode: r.htmode || (r.band === '5g' ? 'HE80' : 'HE20'),
        txPowerPct: r.txPowerPct || 100,
        ieee80211k: devSSIDs.some((s) => s.ieee80211k),
      },
    }));
    setExpandedDev(r.device);
  };

  const updateDraft = (dev: string, patch: Partial<WifiRadioPatch>) => {
    setDrafts((prev) => ({
      ...prev,
      [dev]: { ...(prev[dev] || { device: dev }), ...patch },
    }));
  };

  return (
    <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
      {radios.map((r) => {
        const is5G = r.band === '5g';
        const bandLabel = is5G ? '5 GHz 高速频段' : '2.4 GHz 覆盖频段';
        const devSSIDs = ssids.filter((s) => s.device === r.device);
        const recCh = is5G ? recommended5gCh : recommended2gCh;
        const isEditing = expandedDev === r.device;
        const draft = drafts[r.device];
        const chOptions = is5G ? CHANNELS_5G : CHANNELS_2G;
        const modeOptions = r.supportedModes?.length ? r.supportedModes : is5G ? ['HE20', 'HE40', 'HE80', 'HE160'] : ['HE20', 'HE40'];

        return (
          <SectionCard
            key={r.device}
            title={
              <span className="flex items-center gap-2">
                {r.disabled ? (
                  <WifiOff className="w-4 h-4 text-rose-400" />
                ) : (
                  <Wifi className={`w-4 h-4 ${is5G ? 'text-sky-400' : 'text-emerald-400'}`} />
                )}
                <span>{bandLabel}</span>
                <Badge tone={r.disabled ? 'danger' : is5G ? 'accent' : 'ok'}>
                  {r.disabled ? '已关闭' : r.htmode}
                </Badge>
              </span>
            }
            subtitle={`${r.device}${r.hardware ? ` · ${r.hardware}` : ''} · 驱动 ${r.driver}`}
            actions={
              <Button
                size="xs"
                variant="secondary"
                disabled={busy}
                icon={isEditing ? <ChevronUp className="w-3.5 h-3.5" /> : <Sliders className="w-3.5 h-3.5" />}
                onClick={() => openEditor(r)}
              >
                {isEditing ? '收起微调' : '高级微调'}
              </Button>
            }
          >
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-2.5 text-xs mb-4">
              <div className="rounded-xl bg-white/[0.03] border border-white/10 p-2.5">
                <div className="text-secondary text-[11px]">当前信道</div>
                <div className="mt-1 font-mono font-semibold text-primary flex items-center gap-1.5 flex-wrap">
                  <span>{r.disabled ? '-' : r.currentChannel || r.channel}</span>
                  {r.overlappingChannel && <Badge tone="danger">重叠</Badge>}
                  {r.dfsChannel && <Badge tone="warn">DFS</Badge>}
                  {!r.disabled && !r.overlappingChannel && !r.dfsChannel && (
                    <Badge tone="ok">正交</Badge>
                  )}
                </div>
              </div>
              <div className="rounded-xl bg-white/[0.03] border border-white/10 p-2.5">
                <div className="text-secondary text-[11px]">理论速率</div>
                <div className="mt-1 font-mono font-semibold text-primary">
                  {r.disabled || !r.bitRateMbps ? '-' : `${Math.round(r.bitRateMbps)} Mbps`}
                </div>
              </div>
              <div className="rounded-xl bg-white/[0.03] border border-white/10 p-2.5">
                <div className="text-secondary text-[11px]">发射功率</div>
                <div className="mt-1 font-mono font-semibold text-primary">
                  {r.disabled ? '-' : r.txPowerDbm ? `${r.txPowerDbm} dBm` : `${r.txPowerPct}%`}
                </div>
              </div>
              <div className="rounded-xl bg-white/[0.03] border border-white/10 p-2.5">
                <div className="text-secondary text-[11px]">在线 / 错包率</div>
                <div className="mt-1 font-mono font-semibold flex items-center gap-1.5">
                  <span className="text-primary">{r.clientCount} 台</span>
                  <span className={r.rxErrorRatePct >= 5 ? 'text-amber-300' : 'text-emerald-300'}>
                    ({r.rxErrorRatePct.toFixed(1)}%)
                  </span>
                </div>
              </div>
            </div>

            <div className="space-y-2">
              <div className="text-[11px] uppercase tracking-wider text-secondary flex items-center gap-1.5">
                <Radio className="w-3 h-3" />
                <span>挂载热点 ({devSSIDs.length})</span>
              </div>
              {devSSIDs.length === 0 ? (
                <div className="text-xs text-secondary py-2">该射频下暂无 AP 热点。</div>
              ) : (
                devSSIDs.map((s) => (
                  <div
                    key={s.section}
                    className="rounded-xl border border-white/10 bg-white/[0.02] px-3 py-2.5 flex flex-wrap items-center justify-between gap-2"
                  >
                    <div className="min-w-0 space-y-0.5">
                      <div className="flex flex-wrap items-center gap-1.5 text-xs font-medium text-primary">
                        <span>{s.ssid || s.section}</span>
                        {s.disabled ? (
                          <Badge tone="neutral">已禁用</Badge>
                        ) : s.dualBandPaired ? (
                          <Badge tone="ok">双频合一</Badge>
                        ) : null}
                        {s.isolate && <Badge tone="neutral">隔离</Badge>}
                        {s.ieee80211k && <Badge tone="accent">802.11k</Badge>}
                      </div>
                      <div className="text-[11px] text-secondary font-mono flex flex-wrap items-center gap-2">
                        <span>接口: {s.ifname || '-'}</span>
                        <span>网桥: {s.bridge || s.network}</span>
                        <span className="inline-flex items-center gap-1">
                          <Shield className="w-3 h-3" />
                          {s.encryption || 'none'}
                        </span>
                        <span>在线: {s.clientCount}</span>
                      </div>
                    </div>

                    {s.canUpgradeDualBand && (
                      <Button
                        size="xs"
                        variant="primary"
                        disabled={busy}
                        icon={<Layers className="w-3 h-3" />}
                        onClick={() => onDualBandMerge(s.section, s.ssid)}
                      >
                        一键升级双频合一
                      </Button>
                    )}
                  </div>
                ))
              )}
            </div>

            {isEditing && draft && (
              <div className="mt-4 pt-4 border-t border-white/10 space-y-3">
                <div className="flex items-center justify-between text-xs">
                  <span className="font-medium text-primary flex items-center gap-1.5">
                    <Sparkles className="w-3.5 h-3.5 text-sky-400" />
                    射频参数微调（修改将触发防失联自动回滚保护）
                  </span>
                  {recCh ? (
                    <button
                      type="button"
                      onClick={() => updateDraft(r.device, { channel: String(recCh), htmode: is5G ? 'HE80' : 'HE20', disabled: false })}
                      className="text-[11px] text-sky-300 hover:text-sky-200 underline cursor-pointer"
                    >
                      填入推荐信道 {recCh}
                    </button>
                  ) : null}
                </div>

                <div className="grid grid-cols-2 sm:grid-cols-4 gap-2.5 text-xs">
                  <label className="space-y-1">
                    <span className="text-secondary text-[11px]">射频状态</span>
                    <select
                      value={draft.disabled ? '1' : '0'}
                      onChange={(e) => updateDraft(r.device, { disabled: e.target.value === '1' })}
                      className="w-full rounded-lg bg-slate-900/90 border border-white/15 px-2.5 py-1.5 text-xs text-primary"
                    >
                      <option value="0">开启</option>
                      <option value="1">关闭</option>
                    </select>
                  </label>

                  <label className="space-y-1">
                    <span className="text-secondary text-[11px]">无线信道</span>
                    <select
                      value={draft.channel || 'auto'}
                      onChange={(e) => updateDraft(r.device, { channel: e.target.value })}
                      className="w-full rounded-lg bg-slate-900/90 border border-white/15 px-2.5 py-1.5 text-xs text-primary font-mono"
                    >
                      {chOptions.map((c) => {
                        const n = Number(c);
                        const suffix =
                          c === 'auto'
                            ? ' (自动)'
                            : recCh && n === recCh
                              ? ' ★推荐'
                              : is5G && n >= 52 && n <= 144
                                ? ' (DFS)'
                                : !is5G && (n === 1 || n === 6 || n === 11)
                                  ? ' (正交)'
                                  : '';
                        return (
                          <option key={c} value={c}>
                            {c}
                            {suffix}
                          </option>
                        );
                      })}
                    </select>
                  </label>

                  <label className="space-y-1">
                    <span className="text-secondary text-[11px]">频道频宽</span>
                    <select
                      value={draft.htmode || 'HE20'}
                      onChange={(e) => updateDraft(r.device, { htmode: e.target.value })}
                      className="w-full rounded-lg bg-slate-900/90 border border-white/15 px-2.5 py-1.5 text-xs text-primary font-mono"
                    >
                      {modeOptions.map((m) => (
                        <option key={m} value={m}>
                          {m}
                        </option>
                      ))}
                    </select>
                  </label>

                  <label className="space-y-1">
                    <span className="text-secondary text-[11px]">发射功率</span>
                    <select
                      value={String(draft.txPowerPct || 100)}
                      onChange={(e) => updateDraft(r.device, { txPowerPct: Number(e.target.value) })}
                      className="w-full rounded-lg bg-slate-900/90 border border-white/15 px-2.5 py-1.5 text-xs text-primary font-mono"
                    >
                      {[100, 80, 60, 40, 25].map((p) => (
                        <option key={p} value={p}>
                          {p}%
                        </option>
                      ))}
                    </select>
                  </label>
                </div>

                <div className="flex flex-wrap items-center justify-between gap-2 pt-1">
                  <label className="inline-flex items-center gap-2 text-xs text-secondary cursor-pointer">
                    <input
                      type="checkbox"
                      checked={Boolean(draft.ieee80211k)}
                      onChange={(e) => updateDraft(r.device, { ieee80211k: e.target.checked })}
                      className="rounded border-white/20 bg-slate-900 text-sky-500"
                    />
                    <span>启用 802.11k 邻居报告（加速手机切 5G）</span>
                  </label>
                  <div className="flex items-center gap-2">
                    <Button size="xs" variant="secondary" onClick={() => setExpandedDev(null)}>
                      取消
                    </Button>
                    <Button
                      size="xs"
                      variant="primary"
                      disabled={busy}
                      icon={<ChevronDown className="w-3 h-3 -rotate-90" />}
                      onClick={() => onTuneRadio(draft)}
                    >
                      预览并安全应用
                    </Button>
                  </div>
                </div>
              </div>
            )}
          </SectionCard>
        );
      })}
    </div>
  );
};

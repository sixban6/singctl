import React from 'react';
import { Cable, Lock, ShieldCheck } from 'lucide-react';
import { VlanPortInfo, VlanPortMode, VlanSegment } from '../../../types';
import { formatSpeedMbps, getSegmentTheme } from './vlanHelpers';

export interface PortSwitchBarProps {
  ports: VlanPortInfo[];
  segments: VlanSegment[];
  mode: 'overview' | 'select';
  proMode?: boolean;
  selectedPorts?: Record<string, VlanPortMode | string>;
  editingSegmentId?: string;
  onSelectOverviewSegment?: (segmentId: string) => void;
  onChangePortMode?: (portName: string, nextMode: VlanPortMode) => void;
}

export const PortSwitchBar: React.FC<PortSwitchBarProps> = ({
  ports,
  segments,
  mode,
  proMode = false,
  selectedPorts = {},
  editingSegmentId,
  onSelectOverviewSegment,
  onChangePortMode,
}) => {
  const segById = React.useMemo(() => {
    const map = new Map<string, VlanSegment>();
    for (const seg of segments) {
      map.set(seg.id, seg);
    }
    return map;
  }, [segments]);

  if (ports.length === 0) {
    return (
      <div className="rounded-xl border border-slate-800 bg-slate-950/50 px-4 py-3 text-xs text-slate-400">
        当前设备未探测到独立物理交换机网口。
      </div>
    );
  }

  const handlePortClick = (p: VlanPortInfo) => {
    if (p.isWan) return;
    if (mode === 'overview') {
      if (p.untaggedSegmentId && onSelectOverviewSegment) {
        onSelectOverviewSegment(p.untaggedSegmentId);
      }
      return;
    }

    if (!onChangePortMode) return;
    const cur = (selectedPorts[p.name] as VlanPortMode | undefined) || 'off';
    if (p.isMgmt && !proMode) {
      return;
    }
    if (!proMode) {
      onChangePortMode(p.name, cur === 'access' ? 'off' : 'access');
      return;
    }
    // Pro mode cycles off -> access -> trunk -> off (mgmt port skips access unless unlocked in validator)
    if (p.isMgmt) {
      onChangePortMode(p.name, cur === 'trunk' ? 'off' : 'trunk');
      return;
    }
    const next: VlanPortMode = cur === 'off' ? 'access' : cur === 'access' ? 'trunk' : 'off';
    onChangePortMode(p.name, next);
  };

  return (
    <div className="space-y-2.5">
      <div className="rounded-2xl border border-slate-800/90 bg-slate-950/75 p-3 sm:p-4">
        <div className="flex flex-wrap items-center justify-between gap-2 mb-3">
          <div className="flex items-center gap-2 text-xs font-medium text-slate-300">
            <Cable className="w-3.5 h-3.5 text-emerald-400" />
            <span>{mode === 'overview' ? '路由器背面物理网口状态' : '点击下方物理网口分配归属'}</span>
          </div>
          <span className="text-[11px] text-slate-400">
            {mode === 'overview'
              ? '点选任意 LAN 口可直达对应网段设置'
              : proMode
                ? '专家模式：点击循环切换 未分配 / 接入口 (Access) / 透传口 (Trunk)'
                : '点选网口后，插上网线即自动进入当前隔离网'}
          </span>
        </div>

        <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-5 gap-2.5">
          {ports.map((p) => {
            const ownerSeg = p.untaggedSegmentId ? segById.get(p.untaggedSegmentId) : undefined;
            const ownerTheme = getSegmentTheme(ownerSeg?.id, ownerSeg?.preset);
            const curSel = (selectedPorts[p.name] as VlanPortMode | undefined) || 'off';
            const speedText = formatSpeedMbps(p.speedMbps);

            const isLockedInSelect = mode === 'select' && (p.isWan || (p.isMgmt && !proMode));
            const isAssignedHere = mode === 'select' && (curSel === 'access' || curSel === 'trunk');
            const ownedByOtherCustom =
              mode === 'select' &&
              Boolean(p.untaggedSegmentId) &&
              p.untaggedSegmentId !== 'lan' &&
              p.untaggedSegmentId !== editingSegmentId;

            let cardStyle = 'border-slate-800 bg-slate-900/70 hover:border-slate-700';
            if (p.isWan) {
              cardStyle = 'border-slate-700/80 bg-slate-900/40 opacity-85 cursor-not-allowed';
            } else if (mode === 'select') {
              if (curSel === 'access') {
                cardStyle = 'border-emerald-400/70 bg-emerald-500/15 shadow-sm shadow-emerald-500/15';
              } else if (curSel === 'trunk') {
                cardStyle = 'border-sky-400/70 bg-sky-500/15 shadow-sm shadow-sky-500/15';
              } else if (isLockedInSelect) {
                cardStyle = 'border-amber-500/35 bg-amber-500/8 opacity-85 cursor-not-allowed';
              } else {
                cardStyle = 'border-slate-800 bg-slate-900/70 hover:border-emerald-500/45 cursor-pointer';
              }
            } else if (ownerSeg) {
              cardStyle = `${ownerTheme.border} ${ownerTheme.bg} hover:brightness-110 cursor-pointer`;
            }

            return (
              <button
                key={p.name}
                type="button"
                disabled={p.isWan || isLockedInSelect}
                onClick={() => handlePortClick(p)}
                className={`group relative flex flex-col items-start justify-between rounded-xl border p-2.5 text-left transition-all ${cardStyle}`}
              >
                <div className="w-full flex items-center justify-between gap-1.5">
                  <div className="flex items-center gap-1.5 min-w-0">
                    <span
                      className={`inline-block w-2 h-2 rounded-full shrink-0 ${
                        p.linkUp ? 'bg-emerald-400 shadow-[0_0_6px_rgba(52,211,153,0.8)]' : 'bg-slate-600'
                      }`}
                      title={p.linkUp ? '网线已连接' : '未插网线'}
                    />
                    <span className="text-xs font-bold text-white tracking-wide truncate">
                      {p.label}
                    </span>
                  </div>
                  {p.isWan || p.isMgmt ? (
                    <Lock className="w-3 h-3 text-amber-300 shrink-0" />
                  ) : null}
                </div>

                {/* RJ45 visual slot */}
                <div className="w-full my-2 h-6 rounded-md border border-slate-700/80 bg-slate-950/90 flex items-center justify-between px-2">
                  <div className="flex items-center gap-0.5">
                    {[0, 1, 2, 3].map((pin) => (
                      <span
                        key={pin}
                        className={`w-0.5 h-2.5 rounded-full ${
                          p.linkUp ? 'bg-amber-400/80' : 'bg-slate-700'
                        }`}
                      />
                    ))}
                  </div>
                  <span className="text-[10px] font-mono text-slate-400">
                    {p.linkUp ? speedText || 'UP' : '未插线'}
                  </span>
                </div>

                {/* Bottom assignment status */}
                <div className="w-full space-y-1">
                  {p.isWan ? (
                    <span className="inline-flex items-center gap-1 text-[10px] font-medium text-slate-300">
                      <ShieldCheck className="w-3 h-3 text-sky-400" />
                      上级宽带口 · 锁定
                    </span>
                  ) : mode === 'select' ? (
                    <div className="flex flex-wrap items-center gap-1">
                      {isAssignedHere ? (
                        <span
                          className={`text-[10px] font-semibold px-1.5 py-0.5 rounded border ${
                            curSel === 'trunk'
                              ? 'bg-sky-500/20 border-sky-400/50 text-sky-200'
                              : 'bg-emerald-500/20 border-emerald-400/50 text-emerald-200'
                          }`}
                        >
                          {curSel === 'trunk'
                            ? '透传口 (Trunk)'
                            : proMode
                              ? '接入口 (Access)'
                              : '已划入此网'}
                        </span>
                      ) : p.isMgmt ? (
                        <span className="text-[10px] font-medium text-amber-300">
                          当前管理口 · 防断联
                        </span>
                      ) : (
                        <span className="text-[10px] text-slate-400 truncate">
                          {ownedByOtherCustom
                            ? `当前属: ${ownerSeg?.displayName || p.untaggedSegmentId}`
                            : '点击划入此网'}
                        </span>
                      )}
                    </div>
                  ) : (
                    <div className="flex flex-col gap-0.5">
                      <span
                        className={`text-[11px] font-medium truncate ${
                          ownerSeg ? ownerTheme.text : 'text-slate-400'
                        }`}
                      >
                        {ownerSeg ? ownerSeg.displayName : '未分配'}
                      </span>
                      <div className="flex items-center gap-1 flex-wrap">
                        {p.isMgmt && (
                          <span className="text-[10px] text-amber-300 font-medium">管理口🔒</span>
                        )}
                        {proMode && p.taggedSegmentIds && p.taggedSegmentIds.length > 0 && (
                          <span className="text-[10px] font-mono text-sky-300">
                            +Trunk({p.taggedSegmentIds.join(',')})
                          </span>
                        )}
                      </div>
                    </div>
                  )}
                </div>
              </button>
            );
          })}
        </div>
      </div>
    </div>
  );
};

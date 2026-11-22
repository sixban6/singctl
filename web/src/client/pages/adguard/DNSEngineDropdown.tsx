import React, { useEffect, useRef, useState } from 'react';
import {
  AlertTriangle,
  Check,
  ChevronDown,
  Download,
  Gauge,
  Loader2,
  ShieldCheck,
  Sparkles,
} from 'lucide-react';
import { Badge, BadgeTone, StatusDot } from '../../../ui';
import {
  DNSEngineID,
  DNSEngineOption,
  DNSEnginePreference,
  DNSOverviewSnapshot,
} from '../../types';
import {
  getEngineDisplayName,
  isMemoryOnlyBlocked,
  resolveActiveEngine,
  resolveEngineOptions,
  resolveRecommendedEngine,
} from './adguardHelpers';

export interface DNSEngineDropdownProps {
  snap: DNSOverviewSnapshot | null;
  busy: boolean;
  mutating: boolean;
  switchingEngine: DNSEnginePreference | null;
  onSwitchEngine: (engine: DNSEnginePreference, forceLowMemory?: boolean) => Promise<boolean>;
  onAction: (name: string, params?: Record<string, unknown>, confirmMsg?: string) => void;
}

function getEngineIcon(id: DNSEngineID, className = 'w-3.5 h-3.5'): React.ReactNode {
  return id === 'smartdns' ? <Gauge className={className} /> : <ShieldCheck className={className} />;
}

function getEngineSummaryLine(opt: DNSEngineOption): string {
  if (opt.id === 'smartdns') {
    return `轻量极速并发测速 · ${opt.diskHint || '~3 MB'} 闪存 / ${opt.ramHint || '~10 MB'} 内存`;
  }
  return `全功能可视化与海量规则 · ${opt.diskHint || '~80 MB'} 闪存${opt.ramHint ? ` / ${opt.ramHint} 内存` : ''}`;
}

export const DNSEngineDropdown: React.FC<DNSEngineDropdownProps> = ({
  snap,
  busy,
  mutating,
  switchingEngine,
  onSwitchEngine,
  onAction,
}) => {
  const [open, setOpen] = useState(false);
  const containerRef = useRef<HTMLDivElement>(null);
  const triggerRef = useRef<HTMLButtonElement>(null);

  const activeEngine = resolveActiveEngine(snap);
  const recommendedEngine = resolveRecommendedEngine(snap);
  const configuredEngine: DNSEnginePreference =
    snap?.configuredEngine === 'smartdns' || snap?.configuredEngine === 'adguard'
      ? snap.configuredEngine
      : 'auto';
  const engines = resolveEngineOptions(snap);
  const activeLabel = getEngineDisplayName(activeEngine, snap?.activeEngineLabel);
  const recommendedLabel = getEngineDisplayName(recommendedEngine);
  const isSwitching = switchingEngine !== null;
  const anyDisabled = busy || mutating || isSwitching;

  useEffect(() => {
    if (!open) return;

    const handlePointerDown = (e: MouseEvent) => {
      if (containerRef.current && !containerRef.current.contains(e.target as Node)) {
        setOpen(false);
      }
    };
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        setOpen(false);
        triggerRef.current?.focus();
      }
    };

    document.addEventListener('mousedown', handlePointerDown);
    document.addEventListener('keydown', handleKeyDown);
    return () => {
      document.removeEventListener('mousedown', handlePointerDown);
      document.removeEventListener('keydown', handleKeyDown);
    };
  }, [open]);

  const statusTone: BadgeTone = !snap
    ? 'neutral'
    : !snap.installed
      ? 'accent'
      : snap.dnsHealthy && snap.singboxLinked
        ? 'ok'
        : snap.dnsHealthy
          ? 'warn'
          : 'danger';

  const statusPulse = Boolean(snap?.installed && snap?.dnsHealthy && snap?.singboxLinked);

  const handleSelectAuto = () => {
    setOpen(false);
    if (anyDisabled) return;

    const recOpt = engines.find((e) => e.id === recommendedEngine);
    if (configuredEngine === 'auto' && recOpt?.installed) {
      return;
    }

    if (recOpt && !recOpt.eligible) {
      if (isMemoryOnlyBlocked(recOpt)) {
        onAction(
          'dns-switch',
          { engine: 'auto', forceLowMemory: true },
          `当前设备可用内存偏低（${recOpt.blockedReason || '触发低内存保护'}），强行运行 ${recOpt.name} 可能导致路由器 OOM 死机断网。确定要忽略低内存保护并强制切换吗？`,
        );
      }
      return;
    }

    if (recOpt?.installed) {
      void onSwitchEngine('auto', false);
      return;
    }

    onAction('dns-switch', { engine: 'auto' });
  };

  const handleSelectEngine = (opt: DNSEngineOption) => {
    if (anyDisabled) return;

    if (!opt.eligible) {
      if (!isMemoryOnlyBlocked(opt)) return;
      setOpen(false);
      onAction(
        'dns-switch',
        { engine: opt.id, forceLowMemory: true },
        `当前设备可用内存偏低（${opt.blockedReason || '触发低内存保护'}），强行运行 ${opt.name} 可能导致路由器 OOM 死机断网。确定要忽略低内存保护并强制安装切换吗？`,
      );
      return;
    }

    setOpen(false);
    if (opt.installed) {
      if (configuredEngine === opt.id && (opt.active || opt.id === activeEngine)) {
        return;
      }
      void onSwitchEngine(opt.id, false);
      return;
    }

    onAction('dns-switch', { engine: opt.id });
  };

  const recOpt = engines.find((e) => e.id === recommendedEngine);
  const autoHardBlocked = Boolean(recOpt && !recOpt.eligible && !isMemoryOnlyBlocked(recOpt));

  return (
    <div ref={containerRef} className="relative inline-block text-left">
      <button
        ref={triggerRef}
        type="button"
        disabled={!snap || anyDisabled}
        aria-haspopup="menu"
        aria-expanded={open}
        onClick={() => setOpen((v) => !v)}
        style={{
          backgroundColor: 'var(--bg-surface-1)',
          borderColor: open ? 'var(--border-strong)' : 'var(--border-subtle)',
        }}
        className="h-8 px-3 rounded-xl border text-xs font-medium text-primary inline-flex items-center gap-2 transition-all duration-150 hover:bg-surfaceHover disabled:opacity-50 disabled:pointer-events-none select-none cursor-pointer shadow-sm"
      >
        <StatusDot tone={statusTone} pulse={statusPulse} />
        <span className="text-secondary flex items-center shrink-0">
          {isSwitching ? (
            <Loader2 className="w-3.5 h-3.5 animate-spin text-emerald-400" />
          ) : (
            getEngineIcon(activeEngine, 'w-3.5 h-3.5')
          )}
        </span>
        <span className="font-semibold tracking-tight whitespace-nowrap">
          {isSwitching ? '切换中…' : activeLabel}
        </span>
        {configuredEngine === 'auto' && !isSwitching && (
          <span
            className="px-1.5 py-0.5 rounded-md text-[10px] font-medium leading-none whitespace-nowrap"
            style={{
              backgroundColor: 'var(--accent-soft)',
              color: 'var(--accent)',
            }}
          >
            自动
          </span>
        )}
        <ChevronDown
          className={`w-3.5 h-3.5 text-muted transition-transform duration-150 shrink-0 ${
            open ? 'rotate-180 text-primary' : ''
          }`}
        />
      </button>

      {open && (
        <div
          role="menu"
          aria-label="切换防劫持 DNS 引擎"
          style={{
            backgroundColor: 'var(--bg-surface-1)',
            borderColor: 'var(--border-subtle)',
          }}
          className="absolute left-0 sm:left-auto sm:right-0 mt-2 w-[min(calc(100vw-2rem),23rem)] rounded-2xl border shadow-2xl shadow-black/50 p-1.5 z-50 animate-sc-in"
        >
          <div className="flex items-center justify-between px-2.5 py-1.5 text-[11px] text-muted border-b border-subtle mb-1">
            <span>防劫持 DNS 引擎</span>
            <span className="font-mono">零断网原子切换</span>
          </div>

          <div className="space-y-1">
            {/* Option 1: Auto Recommended */}
            <button
              type="button"
              role="menuitem"
              disabled={anyDisabled || autoHardBlocked}
              onClick={handleSelectAuto}
              className={`w-full text-left px-2.5 py-2 rounded-xl border transition-colors flex items-start gap-2.5 ${
                configuredEngine === 'auto'
                  ? 'bg-surface2 border-strong'
                  : autoHardBlocked
                    ? 'opacity-50 cursor-not-allowed border-transparent'
                    : 'border-transparent hover:bg-surfaceHover cursor-pointer'
              }`}
            >
              <div
                className="w-7 h-7 rounded-lg flex items-center justify-center shrink-0 mt-0.5"
                style={{
                  backgroundColor: 'var(--accent-soft)',
                  color: 'var(--accent)',
                }}
              >
                <Sparkles className="w-3.5 h-3.5" />
              </div>
              <div className="min-w-0 flex-1 space-y-0.5">
                <div className="flex items-center justify-between gap-2">
                  <span className="text-xs font-semibold text-primary truncate">
                    自动选择 (推荐: {recommendedLabel})
                  </span>
                  {configuredEngine === 'auto' && (
                    <Check
                      className="w-3.5 h-3.5 shrink-0"
                      style={{ color: 'var(--status-ok)' }}
                    />
                  )}
                </div>
                <p className="text-[11px] text-secondary leading-snug break-words">
                  {snap?.recommendedReason ||
                    `根据本机闪存与可用内存自动评估，当前优先推荐 ${recommendedLabel}`}
                </p>
              </div>
            </button>

            <div className="border-t border-subtle my-1" />

            {/* Option 2 & 3: SmartDNS / AdGuard Home */}
            {engines.map((opt) => {
              const isActive = opt.active || opt.id === activeEngine;
              const isPinned = configuredEngine === opt.id;
              const memOnlyBlocked = !opt.eligible && isMemoryOnlyBlocked(opt);
              const hardBlocked = !opt.eligible && !memOnlyBlocked;
              const needsInstall = !opt.installed;

              return (
                <button
                  key={opt.id}
                  type="button"
                  role="menuitem"
                  disabled={anyDisabled || hardBlocked}
                  onClick={() => handleSelectEngine(opt)}
                  className={`w-full text-left px-2.5 py-2 rounded-xl border transition-colors flex items-start gap-2.5 ${
                    isPinned
                      ? 'bg-surface2 border-strong'
                      : hardBlocked
                        ? 'opacity-55 cursor-not-allowed border-transparent bg-surface1'
                        : 'border-transparent hover:bg-surfaceHover cursor-pointer'
                  }`}
                >
                  <div
                    className="w-7 h-7 rounded-lg flex items-center justify-center shrink-0 mt-0.5"
                    style={{
                      backgroundColor:
                        isActive && opt.installed
                          ? 'var(--status-ok-soft)'
                          : opt.recommended
                            ? 'var(--accent-soft)'
                            : 'var(--bg-surface-2)',
                      color:
                        isActive && opt.installed
                          ? 'var(--status-ok)'
                          : opt.recommended
                            ? 'var(--accent)'
                            : 'var(--text-secondary)',
                    }}
                  >
                    {getEngineIcon(opt.id, 'w-3.5 h-3.5')}
                  </div>

                  <div className="min-w-0 flex-1 space-y-1">
                    <div className="flex items-center justify-between gap-2">
                      <div className="flex items-center gap-1.5 min-w-0 flex-wrap">
                        <span className="text-xs font-semibold text-primary">{opt.name}</span>
                        {isActive && opt.installed && <Badge tone="ok">当前</Badge>}
                        {opt.recommended && <Badge tone="accent">推荐</Badge>}
                        {opt.installed && !isActive && <Badge tone="neutral">已安装</Badge>}
                        {!opt.installed && opt.eligible && <Badge tone="neutral">未安装</Badge>}
                      </div>

                      <div className="shrink-0 flex items-center">
                        {isPinned && opt.installed ? (
                          <Check className="w-3.5 h-3.5" style={{ color: 'var(--status-ok)' }} />
                        ) : hardBlocked ? (
                          <span className="text-[10px] text-muted">硬件受限</span>
                        ) : memOnlyBlocked ? (
                          <span
                            className="text-[10px] font-medium"
                            style={{ color: 'var(--status-warn)' }}
                          >
                            强制安装
                          </span>
                        ) : needsInstall ? (
                          <span className="inline-flex items-center gap-1 text-[10px] font-medium text-secondary">
                            <Download className="w-3 h-3" />
                            安装
                          </span>
                        ) : null}
                      </div>
                    </div>

                    <p className="text-[11px] text-secondary leading-snug">
                      {getEngineSummaryLine(opt)}
                    </p>

                    {!opt.eligible && opt.blockedReason && (
                      <div
                        className="rounded-lg px-2 py-1 border text-[10.5px] leading-snug flex items-start gap-1.5"
                        style={{
                          borderColor: hardBlocked ? 'var(--status-danger)' : 'var(--status-warn)',
                          backgroundColor: hardBlocked
                            ? 'var(--status-danger-soft)'
                            : 'var(--status-warn-soft)',
                        }}
                      >
                        <AlertTriangle
                          className="w-3 h-3 shrink-0 mt-0.5"
                          style={{
                            color: hardBlocked ? 'var(--status-danger)' : 'var(--status-warn)',
                          }}
                        />
                        <span className="text-primary break-words">{opt.blockedReason}</span>
                      </div>
                    )}
                  </div>
                </button>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
};

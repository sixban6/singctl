import React, { useCallback, useEffect, useLayoutEffect, useRef, useState } from 'react';
import { createPortal } from 'react-dom';
import {
  ArrowDown,
  ArrowUp,
  ArrowUpCircle,
  Box,
  Check,
  ChevronDown,
  Play,
  Power,
  RotateCw,
  SlidersHorizontal,
  Sparkles,
  Zap,
} from 'lucide-react';
import { Button } from '../../../ui';
import { ClientSingBoxStatus, SbProxyMode, SbTrafficSnapshot } from '../../types';

const MODE_OPTIONS: {
  key: SbProxyMode;
  label: string;
  activePillLabel: string;
  tag: string;
  hint: string;
  recommended?: boolean;
}[] = [
  {
    key: 'rule',
    label: '智能分流',
    activePillLabel: '智能分流',
    tag: '默认',
    hint: '按分流规则智能决定直连与代理（日常默认推荐）',
    recommended: true,
  },
  {
    key: 'global',
    label: '全局代理',
    activePillLabel: '全局代理中',
    tag: '排障',
    hint: '临时排障：除基础放行外全部流量经 GLOBAL 策略组代理',
  },
  {
    key: 'direct',
    label: '全局直连',
    activePillLabel: '全局直连中',
    tag: '直连',
    hint: '临时对比：所有流量暂走宽带直连，排查代理链路问题',
  },
];

function formatByteRate(bytesPerSec: number): string {
  const v = Math.max(0, Number(bytesPerSec) || 0);
  if (v < 1024) return `${v.toFixed(0)} B/s`;
  if (v < 1024 * 1024) return `${(v / 1024).toFixed(1)} KB/s`;
  return `${(v / (1024 * 1024)).toFixed(2)} MB/s`;
}

function formatMemMB(bytes: number): string {
  const mb = (Number(bytes) || 0) / (1024 * 1024);
  if (mb <= 0) return '';
  return `${mb.toFixed(0)} MB`;
}

export interface SingBoxControlBarProps {
  sb?: ClientSingBoxStatus;
  sbRunning: boolean;
  busy: boolean;
  traffic: SbTrafficSnapshot | null;
  currentMode: SbProxyMode;
  switchingMode: boolean;
  onAction: (name: string, params?: Record<string, unknown>, confirmMsg?: string) => void;
  onNavigate: (tab: string, sub?: string) => void;
  onModeSwitch: (nextMode: SbProxyMode) => void;
}

export const SingBoxControlBar: React.FC<SingBoxControlBarProps> = ({
  sb,
  sbRunning,
  busy,
  traffic,
  currentMode,
  switchingMode,
  onAction,
  onNavigate,
  onModeSwitch,
}) => {
  const [modeMenuOpen, setModeMenuOpen] = useState(false);
  const [modeMenuPos, setModeMenuPos] = useState<{ top: number; left: number; width: number } | null>(null);
  const modeTriggerRef = useRef<HTMLButtonElement>(null);
  const modeDropdownRef = useRef<HTMLDivElement>(null);

  const updateModeMenuPosition = useCallback(() => {
    const trigger = modeTriggerRef.current;
    if (!trigger || typeof window === 'undefined') return;
    const rect = trigger.getBoundingClientRect();
    const vw = window.innerWidth;
    const vh = window.innerHeight;
    const menuWidth = vw < 640 ? 156 : 176;
    const margin = 12;
    const isLeftSide = rect.left + rect.width / 2 < vw / 2;
    const preferredLeft = isLeftSide ? rect.left : rect.right - menuWidth;
    const left = Math.min(
      Math.max(margin, preferredLeft),
      Math.max(margin, vw - menuWidth - margin),
    );
    const estHeight = modeDropdownRef.current?.offsetHeight || 116;
    const bottomSafe = vw < 768 ? 76 : 16;
    let top = rect.bottom + 6;
    if (top + estHeight > vh - bottomSafe && rect.top - estHeight - 6 > margin) {
      top = rect.top - estHeight - 6;
    }
    setModeMenuPos({ top, left, width: menuWidth });
  }, []);

  const toggleModeMenu = useCallback(() => {
    setModeMenuOpen((prev) => {
      const next = !prev;
      if (next) {
        updateModeMenuPosition();
      }
      return next;
    });
  }, [updateModeMenuPosition]);

  useLayoutEffect(() => {
    if (!modeMenuOpen) return;
    updateModeMenuPosition();
    const onViewportChange = () => updateModeMenuPosition();
    window.addEventListener('resize', onViewportChange);
    window.addEventListener('scroll', onViewportChange, true);
    return () => {
      window.removeEventListener('resize', onViewportChange);
      window.removeEventListener('scroll', onViewportChange, true);
    };
  }, [modeMenuOpen, updateModeMenuPosition]);

  useEffect(() => {
    if (!modeMenuOpen) return;
    const onPointerDown = (e: PointerEvent) => {
      const target = e.target as Node;
      if (modeTriggerRef.current?.contains(target) || modeDropdownRef.current?.contains(target)) {
        return;
      }
      setModeMenuOpen(false);
    };
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') setModeMenuOpen(false);
    };
    document.addEventListener('pointerdown', onPointerDown);
    document.addEventListener('keydown', onKeyDown);
    return () => {
      document.removeEventListener('pointerdown', onPointerDown);
      document.removeEventListener('keydown', onKeyDown);
    };
  }, [modeMenuOpen]);

  const currentModeMeta = MODE_OPTIONS.find((m) => m.key === currentMode) || MODE_OPTIONS[0];
  const isNonDefaultMode = currentMode !== 'rule';
  const memLabel = traffic?.memory ? formatMemMB(traffic.memory) : '';

  return (
    <div className="console-card rounded-2xl px-4 py-3 flex flex-col xl:flex-row xl:items-center justify-between gap-3">
      <div className="flex flex-wrap items-center gap-2">
        {sbRunning ? (
          <>
            <Button
              size="sm"
              variant="secondary"
              disabled={busy}
              icon={<RotateCw className="w-3.5 h-3.5" />}
              onClick={() => onAction('sb-restart')}
            >
              重启内核
            </Button>
            <Button
              size="sm"
              variant="secondary"
              disabled={busy}
              icon={<ArrowUpCircle className="w-3.5 h-3.5" />}
              onClick={() => onAction(sb?.installed ? 'sb-update' : 'sb-install')}
            >
              {sb?.installed ? '更新内核' : '安装内核'}
            </Button>
            <Button
              size="sm"
              variant="danger"
              disabled={busy}
              icon={<Power className="w-3.5 h-3.5" />}
              onClick={() => onAction('sb-stop', {}, '确认停止 sing-box？这会中断当前代理连接。')}
            >
              停止内核
            </Button>
          </>
        ) : (
          <>
            <Button
              size="sm"
              variant="primary"
              disabled={busy}
              icon={<Play className="w-3.5 h-3.5" />}
              onClick={() => onAction('sb-start')}
            >
              启动内核
            </Button>
            <Button
              size="sm"
              variant="secondary"
              disabled={busy}
              icon={<ArrowUpCircle className="w-3.5 h-3.5" />}
              onClick={() => onAction(sb?.installed ? 'sb-update' : 'sb-install')}
            >
              {sb?.installed ? '更新内核' : '安装内核'}
            </Button>
          </>
        )}

        <span className="hidden sm:inline-block h-4 w-px bg-slate-800 mx-0.5" aria-hidden="true" />

        <Button
          size="sm"
          variant="secondary"
          disabled={busy}
          onClick={() => onAction('sb-gen')}
          icon={<Sparkles className="w-3.5 h-3.5" />}
        >
          从订阅生成配置
        </Button>
      </div>

      {sbRunning && (
        <div className="flex flex-wrap items-center justify-between sm:justify-end gap-2">
          <div className="flex flex-wrap items-center gap-1.5 sm:gap-2 text-[11px] sm:text-xs font-mono tnum">
            <div className="inline-flex items-center gap-1.5 sm:gap-2 px-2 sm:px-2.5 py-1 rounded-lg bg-surface2 border border-subtle text-secondary">
              <span className="inline-flex items-center gap-0.5 text-cyan-300">
                <ArrowUp className="w-3 h-3" />
                {formatByteRate(traffic?.up ?? 0)}
              </span>
              <span className="opacity-30">|</span>
              <span className="inline-flex items-center gap-0.5 text-emerald-300">
                <ArrowDown className="w-3 h-3" />
                {formatByteRate(traffic?.down ?? 0)}
              </span>
            </div>

            <button
              type="button"
              onClick={() => onNavigate('audit')}
              title="点击前往「行为与审计」查看设备与活跃连接"
              className="inline-flex items-center gap-1 sm:gap-1.5 px-2 sm:px-2.5 py-1 rounded-lg bg-surface2 border border-subtle text-secondary hover:text-primary hover:border-strong transition-colors cursor-pointer"
            >
              <Box className="w-3 h-3 text-muted shrink-0" />
              <span>
                <span className="hidden sm:inline">连接 </span>
                {traffic?.connections ?? 0}
              </span>
            </button>

            {memLabel && (
              <span className="hidden sm:inline-flex items-center px-2 py-1 rounded-lg bg-surface2 border border-subtle text-muted">
                内存 {memLabel}
              </span>
            )}
          </div>

          <div className="shrink-0">
            <button
              ref={modeTriggerRef}
              type="button"
              disabled={switchingMode}
              aria-haspopup="listbox"
              aria-expanded={modeMenuOpen}
              title={currentModeMeta.hint}
              onClick={toggleModeMenu}
              className={`inline-flex items-center gap-1.5 h-8 px-2.5 sm:px-3 rounded-xl text-xs font-medium border transition-all cursor-pointer disabled:opacity-60 ${
                isNonDefaultMode
                  ? 'bg-amber-500/15 text-amber-300 border-amber-500/35 hover:bg-amber-500/25'
                  : 'bg-surface2 text-primary border-subtle hover:border-strong'
              }`}
            >
              {isNonDefaultMode ? (
                <Zap className="w-3.5 h-3.5 text-amber-400 shrink-0" />
              ) : (
                <SlidersHorizontal className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
              )}
              <span>{currentModeMeta.activePillLabel}</span>
              <ChevronDown
                className={`w-3.5 h-3.5 opacity-75 transition-transform ${modeMenuOpen ? 'rotate-180' : ''}`}
              />
            </button>

            {modeMenuOpen &&
              modeMenuPos &&
              typeof document !== 'undefined' &&
              createPortal(
                <div
                  ref={modeDropdownRef}
                  role="listbox"
                  aria-label="切换代理运行模式"
                  style={{
                    top: `${modeMenuPos.top}px`,
                    left: `${modeMenuPos.left}px`,
                    width: `${modeMenuPos.width}px`,
                  }}
                  className="fixed z-[100] rounded-xl bg-slate-900/95 backdrop-blur-xl border border-slate-700/90 shadow-2xl shadow-black/60 p-1 space-y-0.5"
                >
                  {MODE_OPTIONS.map((opt) => {
                    const active = currentMode === opt.key;
                    return (
                      <button
                        key={opt.key}
                        type="button"
                        role="option"
                        aria-selected={active}
                        disabled={switchingMode}
                        title={opt.hint}
                        onClick={() => {
                          setModeMenuOpen(false);
                          onModeSwitch(opt.key);
                        }}
                        className={`w-full text-left px-2.5 py-2 sm:py-1.5 rounded-lg transition-colors cursor-pointer flex items-center justify-between gap-1.5 ${
                          active
                            ? 'bg-emerald-500/15 text-emerald-300 border border-emerald-500/25'
                            : 'text-slate-200 hover:bg-slate-800/85 border border-transparent'
                        }`}
                      >
                        <div className="flex items-center gap-1.5 min-w-0">
                          <span className="text-xs font-medium truncate">{opt.label}</span>
                          <span
                            className={`text-[10px] leading-none px-1 py-0.5 rounded shrink-0 ${
                              opt.recommended
                                ? 'bg-emerald-500/15 text-emerald-400'
                                : 'bg-slate-800 text-slate-400'
                            }`}
                          >
                            {opt.tag}
                          </span>
                        </div>
                        {active && <Check className="w-3.5 h-3.5 text-emerald-400 shrink-0" />}
                      </button>
                    );
                  })}
                </div>,
                document.body,
              )}
          </div>
        </div>
      )}
    </div>
  );
};

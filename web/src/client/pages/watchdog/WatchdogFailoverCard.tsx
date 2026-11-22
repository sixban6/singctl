import React, { useState } from 'react';
import { GitBranch, RotateCcw, Settings2, Zap } from 'lucide-react';
import { Badge, Button, SectionCard } from '../../../ui';
import { WatchdogActiveFailover, WatchdogSelectorGroup } from '../../types';
import { DEFAULT_FO_URLS, parseClampedInt, sanitizeDigits } from './watchdogHelpers';

export interface WatchdogFailoverCardProps {
  foEnabled: boolean;
  activeFO: WatchdogActiveFailover[];
  patrolling: boolean;
  savingFO: boolean;
  dirty: boolean;
  selectedGroups: string[];
  defaultGroupList: string[];
  liveSelectors: WatchdogSelectorGroup[];
  patrolInterval: string;
  setPatrolInterval: (v: string) => void;
  probeTimeoutMs: string;
  setProbeTimeoutMs: (v: string) => void;
  confirmRetries: number;
  setConfirmRetries: (v: number) => void;
  autoFailback: boolean;
  setAutoFailback: (v: boolean) => void;
  cooldownSec: string;
  setCooldownSec: (v: string) => void;
  maxFailbackDelayMs: string;
  setMaxFailbackDelayMs: (v: string) => void;
  probeUrlsText: string;
  setProbeUrlsText: (v: string) => void;
  onMarkDirty: () => void;
  onToggleFailover: (next: boolean) => void;
  onImmediatePatrol: () => void;
  onToggleGroupChip: (name: string) => void;
  onAddCustomGroup: (name: string) => void;
  onClearStaleGroups: () => void;
  onRestoreDefaultGroups: () => void;
  onSaveFailover: () => void;
  onResetAllFailover: () => void;
}

export const WatchdogFailoverCard: React.FC<WatchdogFailoverCardProps> = ({
  foEnabled,
  activeFO,
  patrolling,
  savingFO,
  dirty,
  selectedGroups,
  defaultGroupList,
  liveSelectors,
  patrolInterval,
  setPatrolInterval,
  probeTimeoutMs,
  setProbeTimeoutMs,
  confirmRetries,
  setConfirmRetries,
  autoFailback,
  setAutoFailback,
  cooldownSec,
  setCooldownSec,
  maxFailbackDelayMs,
  setMaxFailbackDelayMs,
  probeUrlsText,
  setProbeUrlsText,
  onMarkDirty,
  onToggleFailover,
  onImmediatePatrol,
  onToggleGroupChip,
  onAddCustomGroup,
  onClearStaleGroups,
  onRestoreDefaultGroups,
  onSaveFailover,
  onResetAllFailover,
}) => {
  const [customGroupInput, setCustomGroupInput] = useState('');
  const [showAdvURLs, setShowAdvURLs] = useState(false);

  const hasLiveSelectors = liveSelectors.length > 0;
  const liveGroupMap = new Map(liveSelectors.map((g) => [g.name, g]));
  const orderedGroupNames = hasLiveSelectors
    ? Array.from(new Set(liveSelectors.map((g) => g.name).filter(Boolean)))
    : Array.from(
        new Set([
          ...selectedGroups,
          ...(selectedGroups.length === 0 ? defaultGroupList : []),
        ]),
      );
  const staleSelectedGroups = hasLiveSelectors
    ? selectedGroups.filter((name) => !liveGroupMap.has(name))
    : [];
  const activeSelectedCount = hasLiveSelectors
    ? selectedGroups.filter((name) => liveGroupMap.has(name)).length
    : selectedGroups.length;

  const submitCustomGroup = () => {
    const val = customGroupInput.trim();
    if (!val) return;
    onAddCustomGroup(val);
    setCustomGroupInput('');
  };

  return (
    <SectionCard
      title="策略组自动故障切换（容灾自愈）"
      icon={<GitBranch className="w-4 h-4" />}
      badge={
        <Badge tone={!foEnabled ? 'neutral' : activeFO.length > 0 ? 'warn' : 'ok'}>
          {!foEnabled ? '已关闭' : activeFO.length > 0 ? `${activeFO.length} 组接管中` : '默认开启'}
        </Badge>
      }
      actions={
        <div className="flex items-center gap-3 flex-wrap">
          <label className="inline-flex items-center gap-2 cursor-pointer text-xs font-medium text-primary select-none">
            <input
              type="checkbox"
              checked={foEnabled}
              onChange={(e) => onToggleFailover(e.target.checked)}
              className="w-4 h-4 accent-[var(--accent)]"
            />
            <span>{foEnabled ? '已开启故障切换' : '已关闭故障切换'}</span>
          </label>
          <Button size="xs" loading={patrolling} onClick={onImmediatePatrol} icon={<Zap className="w-3 h-3" />}>
            立即巡检线路
          </Button>
        </div>
      }
    >
      <div className="space-y-4">
        {activeFO.length > 0 && (
          <div
            className="p-3.5 rounded-xl border text-xs space-y-1"
            style={{
              borderColor: 'var(--status-warn)',
              backgroundColor: 'var(--status-warn-soft)',
            }}
          >
            <div className="font-semibold text-primary">
              当前有 {activeFO.length} 个策略组正由备用健康节点容灾接管：
            </div>
            {activeFO.map((item) => (
              <div key={item.group} className="text-secondary font-mono tnum">
                • <strong>{item.group}</strong>：{item.origin} → {item.current}
                {item.lastDelayMs ? ` (${item.lastDelayMs}ms)` : ''}
                {item.since ? ` · ${item.since}` : ''}
              </div>
            ))}
          </div>
        )}

        <div className={foEnabled ? 'space-y-4' : 'space-y-4 opacity-50 pointer-events-none'}>
          <div className="space-y-2.5">
            <div className="flex items-center justify-between gap-2 flex-wrap">
              <span className="text-xs font-semibold text-primary">
                受保护策略组（已启用 {activeSelectedCount} 个
                {staleSelectedGroups.length > 0
                  ? ` · ${staleSelectedGroups.length} 个未在 sing-box 中`
                  : ''}
                ）
              </span>
              <div className="flex items-center gap-1.5">
                {staleSelectedGroups.length > 0 && (
                  <Button size="xs" variant="ghost" onClick={onClearStaleGroups}>
                    清理无效分组
                  </Button>
                )}
                <Button size="xs" variant="ghost" onClick={onRestoreDefaultGroups}>
                  恢复默认分组
                </Button>
              </div>
            </div>
            <div className="flex flex-wrap gap-2">
              {orderedGroupNames.map((name) => {
                const sel = selectedGroups.includes(name);
                const live = liveGroupMap.get(name);
                return (
                  <button
                    key={name}
                    type="button"
                    onClick={() => onToggleGroupChip(name)}
                    style={
                      sel
                        ? {
                            backgroundColor: 'var(--accent-soft)',
                            borderColor: 'var(--accent)',
                            color: 'var(--accent)',
                          }
                        : undefined
                    }
                    className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-xs font-medium border transition-colors cursor-pointer ${
                      sel ? '' : 'bg-surface2 border-subtle text-secondary hover:text-primary'
                    }`}
                  >
                    <span>{sel ? '✓' : '+'}</span>
                    <span>{name}</span>
                    {live?.now && <span className="text-[11px] opacity-75 font-mono">→ {live.now}</span>}
                    {live?.failedOver && <Badge tone="warn">容灾中</Badge>}
                  </button>
                );
              })}
            </div>
            {staleSelectedGroups.length > 0 && (
              <div className="flex flex-wrap items-center gap-2 text-xs text-amber-300/90 bg-amber-500/10 border border-amber-500/25 rounded-xl px-3 py-2">
                <span>未在当前 sing-box 中找到的自定义/旧分组（点击移除）：</span>
                {staleSelectedGroups.map((name) => (
                  <button
                    key={name}
                    type="button"
                    onClick={() => onToggleGroupChip(name)}
                    className="inline-flex items-center gap-1 px-2 py-0.5 rounded-lg bg-amber-500/15 border border-amber-500/30 font-mono hover:bg-amber-500/25 cursor-pointer"
                  >
                    <span>{name}</span>
                    <span>×</span>
                  </button>
                ))}
              </div>
            )}
            <div className="flex gap-2 max-w-md">
              <input
                type="text"
                value={customGroupInput}
                onChange={(e) => setCustomGroupInput(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter') {
                    e.preventDefault();
                    submitCustomGroup();
                  }
                }}
                placeholder="自定义 Selector 组名（如 Streaming / Telegram）"
                className="flex-1 h-8 px-3 rounded-lg bg-surface2 border border-subtle text-xs text-primary focus:outline-none focus:border-strong"
              />
              <Button size="xs" onClick={submitCustomGroup}>
                添加分组
              </Button>
            </div>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3.5">
            <label className="block space-y-1 text-xs">
              <span className="text-secondary">巡检间隔（秒，默认 300 / 5 分钟 · 范围 10~3600）</span>
              <input
                type="text"
                inputMode="numeric"
                value={patrolInterval}
                onChange={(e) => {
                  setPatrolInterval(sanitizeDigits(e.target.value));
                  onMarkDirty();
                }}
                onBlur={() => setPatrolInterval(String(parseClampedInt(patrolInterval, 300, 10, 3600)))}
                placeholder="300"
                className="w-full h-9 px-3 rounded-xl bg-surface2 border border-subtle text-primary font-mono tnum focus:outline-none focus:border-strong"
              />
            </label>

            <label className="block space-y-1 text-xs">
              <span className="text-secondary">单次探测超时（毫秒，默认 5000）</span>
              <input
                type="text"
                inputMode="numeric"
                value={probeTimeoutMs}
                onChange={(e) => {
                  setProbeTimeoutMs(sanitizeDigits(e.target.value));
                  onMarkDirty();
                }}
                onBlur={() => setProbeTimeoutMs(String(parseClampedInt(probeTimeoutMs, 5000, 500, 15000)))}
                placeholder="5000"
                className="w-full h-9 px-3 rounded-xl bg-surface2 border border-subtle text-primary font-mono tnum focus:outline-none focus:border-strong"
              />
            </label>

            <label className="block space-y-1 text-xs">
              <span className="text-secondary">切备前复测次数</span>
              <select
                value={confirmRetries}
                onChange={(e) => {
                  setConfirmRetries(Number(e.target.value));
                  onMarkDirty();
                }}
                className="w-full h-9 px-3 rounded-xl bg-surface2 border border-subtle text-primary focus:outline-none focus:border-strong"
              >
                <option value={0}>0 次（首次超时立即切换）</option>
                <option value={1}>1 次（间隔 5s 复测确认）</option>
                <option value={2}>2 次（5s → 8s 阶梯复测防抖动，推荐）</option>
                <option value={3}>3 次（高容忍度）</option>
              </select>
            </label>

            <label className="block space-y-1 text-xs">
              <span className="text-secondary">原节点恢复自动回切</span>
              <div className="h-9 px-3 rounded-xl bg-surface2 border border-subtle flex items-center gap-2 cursor-pointer">
                <input
                  type="checkbox"
                  checked={autoFailback}
                  onChange={(e) => {
                    setAutoFailback(e.target.checked);
                    onMarkDirty();
                  }}
                  className="accent-[var(--accent)]"
                />
                <span className="text-primary">{autoFailback ? '自动切回稳定主节点' : '保持备用节点'}</span>
              </div>
            </label>

            <label className="block space-y-1 text-xs">
              <span className="text-secondary">回切冷却期（秒，默认 180）</span>
              <input
                type="text"
                inputMode="numeric"
                disabled={!autoFailback}
                value={cooldownSec}
                onChange={(e) => {
                  setCooldownSec(sanitizeDigits(e.target.value));
                  onMarkDirty();
                }}
                onBlur={() => setCooldownSec(String(parseClampedInt(cooldownSec, 180, 10, 86400)))}
                placeholder="180"
                className="w-full h-9 px-3 rounded-xl bg-surface2 border border-subtle text-primary font-mono tnum disabled:opacity-50 focus:outline-none focus:border-strong"
              />
            </label>

            <label className="block space-y-1 text-xs">
              <span className="text-secondary">允许回切最高延迟（ms，默认 600）</span>
              <input
                type="text"
                inputMode="numeric"
                disabled={!autoFailback}
                value={maxFailbackDelayMs}
                onChange={(e) => {
                  setMaxFailbackDelayMs(sanitizeDigits(e.target.value));
                  onMarkDirty();
                }}
                onBlur={() => setMaxFailbackDelayMs(String(parseClampedInt(maxFailbackDelayMs, 600, 100, 5000)))}
                placeholder="600"
                className="w-full h-9 px-3 rounded-xl bg-surface2 border border-subtle text-primary font-mono tnum disabled:opacity-50 focus:outline-none focus:border-strong"
              />
            </label>
          </div>

          <div>
            <Button size="xs" variant="ghost" onClick={() => setShowAdvURLs((v) => !v)}>
              {showAdvURLs ? '收起探测目标 URL ▲' : '自定义探测目标 URL ▼'}
            </Button>
            {showAdvURLs && (
              <div className="mt-2 space-y-2">
                <textarea
                  rows={3}
                  value={probeUrlsText}
                  onChange={(e) => {
                    setProbeUrlsText(e.target.value);
                    onMarkDirty();
                  }}
                  className="w-full p-3 rounded-xl bg-surface2 border border-subtle font-mono text-xs text-primary focus:outline-none focus:border-strong"
                />
                <Button
                  size="xs"
                  onClick={() => {
                    setProbeUrlsText(DEFAULT_FO_URLS.join('\n'));
                    onMarkDirty();
                  }}
                >
                  恢复默认探测 URL
                </Button>
              </div>
            )}
          </div>

          <div className="flex flex-wrap items-center gap-2.5 pt-2 border-t border-subtle">
            <Button variant="primary" loading={savingFO} onClick={onSaveFailover}>
              保存故障切换配置
            </Button>
            <Button disabled={savingFO} onClick={onResetAllFailover} icon={<RotateCcw className="w-3.5 h-3.5" />}>
              恢复全部默认值
            </Button>
            {dirty && <Badge tone="warn">有未保存修改</Badge>}
          </div>
        </div>
      </div>
    </SectionCard>
  );
};

export interface WatchdogBasicConfigCardProps {
  wdInterval: string;
  setWdInterval: (v: string) => void;
  wdConfirmWait: string;
  setWdConfirmWait: (v: string) => void;
  wdMaxRestarts: string;
  setWdMaxRestarts: (v: string) => void;
  wdSubSyncEnabled: boolean;
  setWdSubSyncEnabled: (v: boolean) => void;
  wdSubSyncInterval: string;
  setWdSubSyncInterval: (v: string) => void;
  savingBasic: boolean;
  onMarkDirty: () => void;
  onSaveBasic: () => void;
}

export const WatchdogBasicConfigCard: React.FC<WatchdogBasicConfigCardProps> = ({
  wdInterval,
  setWdInterval,
  wdConfirmWait,
  setWdConfirmWait,
  wdMaxRestarts,
  setWdMaxRestarts,
  wdSubSyncEnabled,
  setWdSubSyncEnabled,
  wdSubSyncInterval,
  setWdSubSyncInterval,
  savingBasic,
  onMarkDirty,
  onSaveBasic,
}) => (
  <SectionCard title="基础守护与订阅热同步参数" icon={<Settings2 className="w-4 h-4" />} collapsible defaultOpen={false}>
    <div className="space-y-4">
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3.5 text-xs">
        <label className="block space-y-1">
          <span className="text-secondary">健康检查间隔（秒，默认 180）</span>
          <input
            type="text"
            inputMode="numeric"
            value={wdInterval}
            onChange={(e) => {
              setWdInterval(sanitizeDigits(e.target.value));
              onMarkDirty();
            }}
            onBlur={() => setWdInterval(String(parseClampedInt(wdInterval, 180, 15, 86400)))}
            placeholder="180"
            className="w-full h-9 px-3 rounded-xl bg-surface2 border border-subtle text-primary font-mono tnum"
          />
        </label>
        <label className="block space-y-1">
          <span className="text-secondary">异常二次确认等待（秒，默认 30）</span>
          <input
            type="text"
            inputMode="numeric"
            value={wdConfirmWait}
            onChange={(e) => {
              setWdConfirmWait(sanitizeDigits(e.target.value));
              onMarkDirty();
            }}
            onBlur={() => setWdConfirmWait(String(parseClampedInt(wdConfirmWait, 30, 5, 600)))}
            placeholder="30"
            className="w-full h-9 px-3 rounded-xl bg-surface2 border border-subtle text-primary font-mono tnum"
          />
        </label>
        <label className="block space-y-1">
          <span className="text-secondary">每小时最大自愈重启次数（默认 3）</span>
          <input
            type="text"
            inputMode="numeric"
            value={wdMaxRestarts}
            onChange={(e) => {
              setWdMaxRestarts(sanitizeDigits(e.target.value));
              onMarkDirty();
            }}
            onBlur={() => setWdMaxRestarts(String(parseClampedInt(wdMaxRestarts, 3, 1, 50)))}
            placeholder="3"
            className="w-full h-9 px-3 rounded-xl bg-surface2 border border-subtle text-primary font-mono tnum"
          />
        </label>
        <label className="block space-y-1">
          <span className="text-secondary">订阅无感热同步</span>
          <div className="h-9 px-3 rounded-xl bg-surface2 border border-subtle flex items-center gap-2 cursor-pointer">
            <input
              type="checkbox"
              checked={wdSubSyncEnabled}
              onChange={(e) => {
                setWdSubSyncEnabled(e.target.checked);
                onMarkDirty();
              }}
              className="accent-[var(--accent)]"
            />
            <span className="text-primary">后台比对并热重载节点</span>
          </div>
        </label>
        <label className="block space-y-1">
          <span className="text-secondary">订阅同步间隔（秒，默认 600）</span>
          <input
            type="text"
            inputMode="numeric"
            disabled={!wdSubSyncEnabled}
            value={wdSubSyncInterval}
            onChange={(e) => {
              setWdSubSyncInterval(sanitizeDigits(e.target.value));
              onMarkDirty();
            }}
            onBlur={() => setWdSubSyncInterval(String(parseClampedInt(wdSubSyncInterval, 600, 60, 86400)))}
            placeholder="600"
            className="w-full h-9 px-3 rounded-xl bg-surface2 border border-subtle text-primary font-mono tnum disabled:opacity-50"
          />
        </label>
      </div>
      <Button size="sm" variant="primary" loading={savingBasic} onClick={onSaveBasic}>
        保存基础守护参数
      </Button>
    </div>
  </SectionCard>
);

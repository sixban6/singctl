import React from 'react';
import {
  ArrowDownWideNarrow,
  ArrowUpNarrowWide,
  Bot,
  EyeOff,
  Layers,
  List,
  Pause,
  RotateCcw,
  Search,
  Sparkles,
  X,
} from 'lucide-react';
import { formatBytes as fmtBytes } from '../../../ui';
import {
  AUDIT_SORT_OPTIONS,
  AuditFlowTelemetry,
  AuditPresetCounts,
  AuditPresetFilter,
  AuditRefreshCadence,
  AuditSelectedDevice,
  AuditSortKey,
  AuditViewMode,
} from './auditFlowModel';
import { fmtBps } from './auditHelpers';

export interface AuditToolbarAndPresetsProps {
  onlyActive: boolean;
  onOnlyActiveChange: (v: boolean) => void;
  totalActiveFlows: number;
  totalAllFlows: number;
  viewMode: AuditViewMode;
  onViewModeChange: (v: AuditViewMode) => void;
  preset: AuditPresetFilter;
  onPresetChange: (v: AuditPresetFilter) => void;
  presetCounts: AuditPresetCounts;
  searchQuery: string;
  onSearchQueryChange: (v: string) => void;
  selectedDevice: AuditSelectedDevice | null;
  onClearSelectedDevice: () => void;
  selectedChain: string;
  onClearSelectedChain: () => void;
  networkFilter: '' | 'tcp' | 'udp';
  onNetworkFilterChange: (v: '' | 'tcp' | 'udp') => void;
  axisFilter: '' | 'security' | 'privacy';
  onAxisFilterChange: (v: '' | 'security' | 'privacy') => void;
  hideWhitelisted: boolean;
  onHideWhitelistedChange: (v: boolean) => void;
  sortBy: AuditSortKey;
  onSortByChange: (v: AuditSortKey) => void;
  sortDir: 'asc' | 'desc';
  onToggleSortDir: () => void;
  refreshMs: AuditRefreshCadence;
  onRefreshMsChange: (v: AuditRefreshCadence) => void;
  refreshAutoPausedReason: string;
  aiEnabled: boolean;
  onToggleAI: (v: boolean) => void;
  telemetry: AuditFlowTelemetry;
  hasAnyFilter: boolean;
  onResetAllFilters: () => void;
}

const PRESET_ITEMS: {
  key: AuditPresetFilter;
  label: string;
  activeClass: string;
  badgeClass: string;
}[] = [
  {
    key: 'all',
    label: '全部',
    activeClass: 'bg-accent/15 border-accent/45 text-accent',
    badgeClass: 'bg-accent/20 text-accent',
  },
  {
    key: 'actionable',
    label: '待处置',
    activeClass: 'bg-rose-500/15 border-rose-500/45 text-rose-300',
    badgeClass: 'bg-rose-500/20 text-rose-300',
  },
  {
    key: 'uploading',
    label: '正在上传',
    activeClass: 'bg-emerald-500/15 border-emerald-500/45 text-emerald-300',
    badgeClass: 'bg-emerald-500/20 text-emerald-300',
  },
  {
    key: 'direct_ip',
    label: '裸 IP 直连',
    activeClass: 'bg-amber-500/15 border-amber-500/45 text-amber-300',
    badgeClass: 'bg-amber-500/20 text-amber-300',
  },
  {
    key: 'pcdn',
    label: 'PCDN / 聚集',
    activeClass: 'bg-purple-500/15 border-purple-500/45 text-purple-300',
    badgeClass: 'bg-purple-500/20 text-purple-300',
  },
];

export const AuditToolbarAndPresets: React.FC<AuditToolbarAndPresetsProps> = ({
  onlyActive,
  onOnlyActiveChange,
  totalActiveFlows,
  totalAllFlows,
  viewMode,
  onViewModeChange,
  preset,
  onPresetChange,
  presetCounts,
  searchQuery,
  onSearchQueryChange,
  selectedDevice,
  onClearSelectedDevice,
  selectedChain,
  onClearSelectedChain,
  networkFilter,
  onNetworkFilterChange,
  axisFilter,
  onAxisFilterChange,
  hideWhitelisted,
  onHideWhitelistedChange,
  sortBy,
  onSortByChange,
  sortDir,
  onToggleSortDir,
  refreshMs,
  onRefreshMsChange,
  refreshAutoPausedReason,
  aiEnabled,
  onToggleAI,
  telemetry,
  hasAnyFilter,
  onResetAllFilters,
}) => {
  return (
    <div className="border-b border-subtle bg-surface2/35 px-3.5 sm:px-5 py-3 space-y-2.5">
      {/* Row 1: Active/History dual tabs + View mode + Refresh cadence + AI toggle */}
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex flex-wrap items-center gap-2">
          <div className="inline-flex rounded-xl border border-subtle bg-surface1/80 p-0.5">
            <button
              type="button"
              onClick={() => onOnlyActiveChange(true)}
              className={`inline-flex items-center gap-1.5 px-3 py-1 rounded-lg text-xs font-medium transition-colors cursor-pointer ${
                onlyActive
                  ? 'bg-emerald-500/18 text-emerald-300 shadow-xs'
                  : 'text-secondary hover:text-primary'
              }`}
            >
              <span
                className={`w-1.5 h-1.5 rounded-full ${
                  onlyActive && totalActiveFlows > 0 ? 'bg-emerald-400 animate-pulse' : 'bg-slate-500'
                }`}
              />
              <span>活跃连接</span>
              <span className="font-mono tnum text-[11px] opacity-85">({totalActiveFlows})</span>
            </button>
            <button
              type="button"
              onClick={() => onOnlyActiveChange(false)}
              className={`inline-flex items-center gap-1.5 px-3 py-1 rounded-lg text-xs font-medium transition-colors cursor-pointer ${
                !onlyActive
                  ? 'bg-accent/18 text-accent shadow-xs'
                  : 'text-secondary hover:text-primary'
              }`}
            >
              <span>全部历史</span>
              <span className="font-mono tnum text-[11px] opacity-85">({totalAllFlows})</span>
            </button>
          </div>

          <div className="inline-flex rounded-xl border border-subtle bg-surface1/80 p-0.5">
            <button
              type="button"
              onClick={() => onViewModeChange('list')}
              className={`inline-flex items-center gap-1 px-2.5 py-1 rounded-lg text-xs font-medium transition-colors cursor-pointer ${
                viewMode === 'list' ? 'bg-surfaceHover text-primary' : 'text-muted hover:text-primary'
              }`}
              title="按每条设备×目标连接明细查看"
            >
              <List className="w-3.5 h-3.5" />
              <span>明细</span>
            </button>
            <button
              type="button"
              onClick={() => onViewModeChange('grouped')}
              className={`inline-flex items-center gap-1 px-2.5 py-1 rounded-lg text-xs font-medium transition-colors cursor-pointer ${
                viewMode === 'grouped' ? 'bg-surfaceHover text-primary' : 'text-muted hover:text-primary'
              }`}
              title="按相同域名/IP 跨设备聚合统计"
            >
              <Layers className="w-3.5 h-3.5" />
              <span>按目标聚合</span>
            </button>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          {refreshAutoPausedReason && refreshMs > 0 && (
            <span
              className="inline-flex items-center gap-1 px-2 py-1 rounded-lg bg-amber-500/12 border border-amber-500/30 text-[11px] text-amber-300"
              title="阅读、悬停或勾选批量处置时自动暂缓重排，避免点偏"
            >
              <Pause className="w-3 h-3" />
              {refreshAutoPausedReason}
            </span>
          )}

          <div
            className="inline-flex items-center rounded-xl border border-subtle bg-surface1/80 p-0.5 text-[11px]"
            title="实时自动刷新频率（类似 Clash 连接监控）"
          >
            {([2000, 5000, 0] as AuditRefreshCadence[]).map((ms) => {
              const active = refreshMs === ms;
              return (
                <button
                  key={ms}
                  type="button"
                  onClick={() => onRefreshMsChange(ms)}
                  className={`px-2 py-1 rounded-lg font-mono font-medium transition-colors cursor-pointer ${
                    active
                      ? ms === 0
                        ? 'bg-amber-500/20 text-amber-300'
                        : 'bg-emerald-500/18 text-emerald-300'
                      : 'text-muted hover:text-primary'
                  }`}
                >
                  {ms === 0 ? '暂停' : `${ms / 1000}s`}
                </button>
              );
            })}
          </div>

          <button
            type="button"
            onClick={() => onToggleAI(!aiEnabled)}
            className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-xl border text-xs font-medium transition-colors cursor-pointer ${
              aiEnabled
                ? 'border-accent/40 bg-accent/12 text-accent'
                : 'border-subtle bg-surface1/70 text-muted hover:text-primary'
            }`}
            title="自动对可视区域连接进行 AI 深度研判与误杀防护"
          >
            <Bot className="w-3.5 h-3.5" />
            <span>AI 研判</span>
          </button>
        </div>
      </div>

      {/* Row 2: Quick Scenario Presets */}
      <div className="flex flex-wrap items-center gap-1.5">
        {PRESET_ITEMS.map((item) => {
          const count = presetCounts[item.key];
          const active = preset === item.key;
          return (
            <button
              key={item.key}
              type="button"
              onClick={() => onPresetChange(item.key)}
              className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full border text-xs font-medium transition-all cursor-pointer ${
                active
                  ? item.activeClass
                  : 'border-subtle bg-surface1/70 text-secondary hover:text-primary hover:border-strong'
              }`}
            >
              {item.key === 'actionable' && count > 0 && (
                <Sparkles className="w-3 h-3 text-rose-400" />
              )}
              <span>{item.label}</span>
              <span
                className={`px-1.5 py-0.2 rounded-full font-mono tnum text-[10.5px] ${
                  active
                    ? item.badgeClass
                    : count > 0 && item.key === 'actionable'
                      ? 'bg-rose-500/20 text-rose-300'
                      : 'bg-surface2 text-muted'
                }`}
              >
                {count}
              </span>
            </button>
          );
        })}
      </div>

      {/* Row 3: Search + Sort + Compact filters */}
      <div className="flex flex-wrap items-center gap-2">
        <div className="relative flex-1 min-w-[200px] max-w-sm">
          <Search className="w-3.5 h-3.5 text-muted absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => onSearchQueryChange(e.target.value)}
            placeholder="搜索域名、IP、端口、规则、应用或设备…"
            className="sc-input w-full pl-8 pr-7 py-1.5 text-xs"
          />
          {searchQuery && (
            <button
              type="button"
              onClick={() => onSearchQueryChange('')}
              className="absolute right-2 top-1/2 -translate-y-1/2 text-muted hover:text-primary cursor-pointer"
              aria-label="清空搜索"
            >
              <X className="w-3.5 h-3.5" />
            </button>
          )}
        </div>

        <div className="inline-flex items-center rounded-xl border border-subtle bg-surface1/80 overflow-hidden">
          <select
            aria-label="排序方式"
            value={sortBy}
            onChange={(e) => onSortByChange(e.target.value as AuditSortKey)}
            className="bg-transparent px-2.5 py-1.5 text-xs text-primary outline-none cursor-pointer"
          >
            {AUDIT_SORT_OPTIONS.map((opt) => (
              <option key={opt.value} value={opt.value} className="bg-slate-900 text-slate-100">
                排序: {opt.label}
              </option>
            ))}
          </select>
          <button
            type="button"
            onClick={onToggleSortDir}
            title={sortDir === 'desc' ? '当前降序，点击切换升序' : '当前升序，点击切换降序'}
            className="px-2 py-1.5 border-l border-subtle text-secondary hover:text-primary hover:bg-surfaceHover transition-colors cursor-pointer"
          >
            {sortDir === 'desc' ? (
              <ArrowDownWideNarrow className="w-3.5 h-3.5" />
            ) : (
              <ArrowUpNarrowWide className="w-3.5 h-3.5" />
            )}
          </button>
        </div>

        <select
          aria-label="按传输协议筛选"
          value={networkFilter}
          onChange={(e) => onNetworkFilterChange(e.target.value as '' | 'tcp' | 'udp')}
          className="sc-input px-2.5 py-1.5 text-xs"
        >
          <option value="">协议: 全部</option>
          <option value="tcp">仅 TCP</option>
          <option value="udp">仅 UDP / QUIC</option>
        </select>

        <select
          aria-label="按风险轴筛选"
          value={axisFilter}
          onChange={(e) => onAxisFilterChange(e.target.value as '' | 'security' | 'privacy')}
          className="sc-input px-2.5 py-1.5 text-xs"
        >
          <option value="">风险轴: 全部</option>
          <option value="security">仅安全异常</option>
          <option value="privacy">仅隐私追踪</option>
        </select>

        <button
          type="button"
          onClick={() => onHideWhitelistedChange(!hideWhitelisted)}
          className={`inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-xl border text-xs transition-colors cursor-pointer ${
            hideWhitelisted
              ? 'border-emerald-500/40 bg-emerald-500/12 text-emerald-300'
              : 'border-subtle bg-surface1/70 text-secondary hover:text-primary'
          }`}
          title="隐藏已加入白名单的记录，聚焦未知和待审连接"
        >
          <EyeOff className="w-3.5 h-3.5" />
          <span>隐藏已放行</span>
        </button>
      </div>

      {/* Row 4: Active Filter Chips + Live Telemetry Summary Bar */}
      <div className="flex flex-wrap items-center justify-between gap-2 pt-0.5 text-[11px]">
        <div className="flex flex-wrap items-center gap-1.5">
          {selectedDevice && (
            <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-lg bg-accent/15 border border-accent/35 text-accent font-medium">
              <span>
                设备: {selectedDevice.label} ({selectedDevice.ip})
              </span>
              <button
                type="button"
                onClick={onClearSelectedDevice}
                className="hover:text-white cursor-pointer"
                aria-label="取消设备筛选"
              >
                <X className="w-3 h-3" />
              </button>
            </span>
          )}
          {selectedChain && (
            <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-lg bg-emerald-500/15 border border-emerald-500/35 text-emerald-300 font-medium">
              <span>链路: {selectedChain}</span>
              <button
                type="button"
                onClick={onClearSelectedChain}
                className="hover:text-white cursor-pointer"
                aria-label="取消链路筛选"
              >
                <X className="w-3 h-3" />
              </button>
            </span>
          )}
          {hasAnyFilter && (
            <button
              type="button"
              onClick={onResetAllFilters}
              className="inline-flex items-center gap-1 px-2 py-0.5 rounded-lg text-muted hover:text-primary hover:bg-surfaceHover transition-colors cursor-pointer"
            >
              <RotateCcw className="w-3 h-3" />
              <span>重置筛选</span>
            </button>
          )}
        </div>

        <div className="flex flex-wrap items-center gap-x-3 gap-y-1 font-mono tnum text-muted">
          <span>
            命中 <strong className="text-primary">{telemetry.count}</strong> 条
            {telemetry.activeConnCount > 0 ? ` (${telemetry.activeConnCount} 活跃句柄)` : ''}
          </span>
          {(telemetry.liveUploadBps > 0 || telemetry.liveDownloadBps > 0) && (
            <span>
              实时{' '}
              <span className="text-emerald-400 font-semibold">↑{fmtBps(telemetry.liveUploadBps)}</span>{' '}
              <span className="text-sky-400 font-semibold">↓{fmtBps(telemetry.liveDownloadBps)}</span>
            </span>
          )}
          <span>
            累计 <span className="text-primary">↑{fmtBytes(telemetry.uploadBytes)}</span> /{' '}
            <span className="text-secondary">↓{fmtBytes(telemetry.downloadBytes)}</span>
          </span>
          {telemetry.directIpCount > 0 && (
            <span className="text-amber-300/90">裸 IP {telemetry.directIpCount} 条</span>
          )}
        </div>
      </div>
    </div>
  );
};

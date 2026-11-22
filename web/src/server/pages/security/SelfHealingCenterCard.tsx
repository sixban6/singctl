import React from 'react';
import { FleetHealReport, HealStatusReport } from '../../types';
import {
  AlertTriangle,
  CheckCircle2,
  Clock,
  Cpu,
  HardDrive,
  Layers,
  Network,
  RefreshCw,
  ShieldCheck,
  X,
  Zap,
} from 'lucide-react';
import { computePostureBadge } from './helpers';

export const SelfHealingCenterCard: React.FC<{
  healStatus: HealStatusReport | null;
  loadingHeal: boolean;
  runningHealScope: 'local' | 'fleet' | null;
  savingPolicy: boolean;
  syncPolicyToFleet: boolean;
  setSyncPolicyToFleet: (v: boolean) => void;
  lastFleetHeal: FleetHealReport | null;
  onClearFleetHeal: () => void;
  onRunHeal: (scope: 'local' | 'fleet') => void;
  onRescan: () => void;
  onTogglePolicy: (nextEnabled: boolean, nextAutoReboot: boolean) => void;
}> = ({
  healStatus,
  loadingHeal,
  runningHealScope,
  savingPolicy,
  syncPolicyToFleet,
  setSyncPolicyToFleet,
  lastFleetHeal,
  onClearFleetHeal,
  onRunHeal,
  onRescan,
  onTogglePolicy,
}) => {
  const postureBadge = computePostureBadge(healStatus);

  return (
    <div className="p-4 sm:p-6 rounded-2xl glass-card border border-emerald-500/20 space-y-5">
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 text-emerald-400 text-xs font-semibold uppercase tracking-wider mb-1">
            <ShieldCheck className="w-4 h-4" />
            <span>AI 时代主动漏洞防御 · 零常驻内存开销</span>
          </div>
          <div className="flex flex-wrap items-center gap-2.5">
            <h2 className="text-lg sm:text-xl font-bold text-white tracking-tight">三层自动化安全漏洞自愈中心</h2>
            <span className={`px-2.5 py-0.5 rounded-full text-xs font-semibold border ${postureBadge.cls}`}>
              {postureBadge.text}
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-1 max-w-3xl leading-relaxed">
            兼顾安全修复速度与业务高可用：核心二进制采用「SHA-256 校验 + 沙盒配置预检 + 异常秒级回滚」，系统补丁严格保留自定义 SSH 2222 配置并热重载残留动态库，多节点内核采用单台串行滚动重启与故障熔断。
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2 shrink-0">
          <button
            type="button"
            onClick={() => onRunHeal('local')}
            disabled={!!runningHealScope}
            className="flex items-center gap-1.5 px-3.5 py-2 rounded-xl bg-emerald-500 hover:bg-emerald-600 text-slate-950 font-semibold text-xs transition-all shadow-lg shadow-emerald-500/15 disabled:opacity-50"
          >
            <Zap className={`w-3.5 h-3.5 ${runningHealScope === 'local' ? 'animate-bounce' : ''}`} />
            <span>{runningHealScope === 'local' ? '正在本机自愈...' : '立即自愈本机'}</span>
          </button>
          <button
            type="button"
            onClick={() => onRunHeal('fleet')}
            disabled={!!runningHealScope}
            className="flex items-center gap-1.5 px-3.5 py-2 rounded-xl bg-sky-500/15 hover:bg-sky-500/25 border border-sky-500/30 text-sky-200 font-semibold text-xs transition-all disabled:opacity-50"
          >
            <Network className={`w-3.5 h-3.5 text-sky-400 ${runningHealScope === 'fleet' ? 'animate-spin' : ''}`} />
            <span>{runningHealScope === 'fleet' ? '正在全网协同自愈...' : '全舰队协同自愈'}</span>
          </button>
          <button
            type="button"
            onClick={onRescan}
            disabled={loadingHeal || !!runningHealScope}
            className="flex items-center gap-1.5 px-3 py-2 rounded-xl bg-slate-900 hover:bg-slate-800 border border-slate-800 text-xs text-slate-300 transition-all disabled:opacity-50"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loadingHeal ? 'animate-spin' : ''}`} />
            <span>重新扫描</span>
          </button>
        </div>
      </div>

      {/* 3 Defense Layer Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-3.5">
        {/* Layer 1: Core Stack */}
        <div className="p-4 rounded-2xl bg-slate-950/70 border border-slate-800/90 space-y-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2 text-xs font-semibold text-white">
              <Layers className="w-4 h-4 text-emerald-400" />
              <span>第一层 · 核心代理栈</span>
            </div>
            <span
              className={`text-[11px] font-mono px-2 py-0.5 rounded-md ${
                healStatus?.core?.healthy
                  ? 'bg-emerald-500/10 text-emerald-400'
                  : 'bg-amber-500/15 text-amber-300'
              }`}
            >
              {healStatus ? (healStatus.core.healthy ? '全部最新 ✓' : `${healStatus.core.pendingCount} 项待升`) : '--'}
            </span>
          </div>
          <div className="space-y-1.5 text-xs font-mono">
            {(healStatus?.core?.components || [])
              .filter((c) => c.installed)
              .map((c) => (
                <div key={c.name} className="flex items-center justify-between gap-2 text-[11px]">
                  <span className="text-slate-400 truncate">{c.displayName}</span>
                  {c.hasUpdate ? (
                    <span className="text-amber-300 shrink-0">
                      v{c.currentVersion} → v{c.latestVersion}
                    </span>
                  ) : (
                    <span className="text-emerald-400 shrink-0">v{c.currentVersion} ✓</span>
                  )}
                </div>
              ))}
          </div>
          <div className="text-[11px] text-slate-500 pt-1 border-t border-slate-800/70">
            金丝雀校验 + <code className="text-slate-400">.heal.bak</code> 15s 异常秒级回滚
          </div>
        </div>

        {/* Layer 2: OS Security & Shared Libraries */}
        <div className="p-4 rounded-2xl bg-slate-950/70 border border-slate-800/90 space-y-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2 text-xs font-semibold text-white">
              <HardDrive className="w-4 h-4 text-sky-400" />
              <span>第二层 · 系统与应用库</span>
            </div>
            <span
              className={`text-[11px] font-mono px-2 py-0.5 rounded-md ${
                healStatus?.os?.healthy ? 'bg-emerald-500/10 text-emerald-400' : 'bg-amber-500/15 text-amber-300'
              }`}
            >
              {healStatus ? (healStatus.os.healthy ? '零高危漏洞 ✓' : '待热修补') : '--'}
            </span>
          </div>
          <div className="space-y-1.5 text-[11px] font-mono">
            <div className="flex items-center justify-between gap-2">
              <span className="text-slate-400">发行版环境</span>
              <span className="text-slate-200 truncate max-w-[160px]">{healStatus?.os?.distro || '--'}</span>
            </div>
            <div className="flex items-center justify-between gap-2">
              <span className="text-slate-400">安全仓库补丁</span>
              <span className={healStatus?.os?.securityCount ? 'text-amber-300' : 'text-emerald-400'}>
                {healStatus ? `${healStatus.os.securityCount} 个待装` : '--'}
              </span>
            </div>
            <div className="flex items-center justify-between gap-2">
              <span className="text-slate-400">内存残留旧 .so</span>
              <span className={healStatus?.os?.staleServices?.length ? 'text-amber-300' : 'text-emerald-400'}>
                {healStatus
                  ? healStatus.os.staleServices?.length
                    ? healStatus.os.staleServices.join(', ')
                    : '干净无残留 ✓'
                  : '--'}
              </span>
            </div>
          </div>
          <div className="text-[11px] text-slate-500 pt-1 border-t border-slate-800/70">
            强制 <code className="text-slate-400">--force-confold</code> 保护 SSH 2222 配置
          </div>
        </div>

        {/* Layer 3: Kernel & Rolling Reboot */}
        <div className="p-4 rounded-2xl bg-slate-950/70 border border-slate-800/90 space-y-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2 text-xs font-semibold text-white">
              <Cpu className="w-4 h-4 text-purple-400" />
              <span>第三层 · 内核与滚动重启</span>
            </div>
            <span
              className={`text-[11px] font-mono px-2 py-0.5 rounded-md ${
                healStatus?.kernel?.healthy ? 'bg-emerald-500/10 text-emerald-400' : 'bg-sky-500/15 text-sky-300'
              }`}
            >
              {healStatus ? (healStatus.kernel.rebootRequired ? '待重启加载' : '无需重启 ✓') : '--'}
            </span>
          </div>
          <div className="space-y-1.5 text-[11px] font-mono">
            <div className="flex items-center justify-between gap-2">
              <span className="text-slate-400">当前运行内核</span>
              <span className="text-slate-200 truncate max-w-[165px]">{healStatus?.kernel?.runningKernel || '--'}</span>
            </div>
            <div className="flex items-center justify-between gap-2">
              <span className="text-slate-400">磁盘最新内核</span>
              <span className="text-slate-300 truncate max-w-[165px]">
                {healStatus?.kernel?.installedKernel || healStatus?.kernel?.runningKernel || '--'}
              </span>
            </div>
            {healStatus?.kernel?.rebootReason && (
              <div className="text-sky-300 text-[10px] leading-snug pt-0.5">{healStatus.kernel.rebootReason}</div>
            )}
          </div>
          <div className="text-[11px] text-slate-500 pt-1 border-t border-slate-800/70">
            舰队每次最多重启 1 台 · 超时自动熔断中止
          </div>
        </div>
      </div>

      {/* Automated Daily 04:00 Timer Policy Bar */}
      <div className="p-4 rounded-2xl bg-slate-950/60 border border-slate-800 flex flex-col lg:flex-row lg:items-center justify-between gap-3.5">
        <div className="space-y-1">
          <div className="flex items-center gap-2 text-xs font-semibold text-white">
            <Clock className="w-4 h-4 text-emerald-400" />
            <span>凌晨维护窗口自动巡检与自愈守护 (systemd timer)</span>
            {healStatus?.timer?.enabled && (
              <span className="px-2 py-0.5 rounded bg-emerald-500/15 text-emerald-300 text-[10px] font-mono">
                已启用 · {healStatus.timer.schedule}
              </span>
            )}
          </div>
          <p className="text-[11px] text-slate-400">
            默认每日凌晨 <code className="text-slate-300">04:00</code> 低峰期自动唤醒巡检修复，执行完毕即退出，平时常驻内存为 0MB
            {healStatus?.timer?.nextRun ? `（下次触发: ${healStatus.timer.nextRun}）` : ''}
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-3 text-xs">
          <label className="inline-flex items-center gap-1.5 text-slate-300 cursor-pointer select-none">
            <input
              type="checkbox"
              checked={syncPolicyToFleet}
              onChange={(e) => setSyncPolicyToFleet(e.target.checked)}
              className="rounded border-slate-700 bg-slate-900 text-emerald-500"
            />
            <span>同步下发至全部子节点</span>
          </label>

          <label className="inline-flex items-center gap-1.5 text-slate-300 cursor-pointer select-none">
            <input
              type="checkbox"
              disabled={savingPolicy}
              checked={!!healStatus?.policy?.autoReboot}
              onChange={(e) => onTogglePolicy(healStatus?.policy?.autoHealEnabled ?? true, e.target.checked)}
              className="rounded border-slate-700 bg-slate-900 text-sky-500"
            />
            <span>允许凌晨窗口自动重启新内核</span>
          </label>

          <button
            type="button"
            disabled={savingPolicy}
            onClick={() =>
              onTogglePolicy(!healStatus?.policy?.autoHealEnabled, !!healStatus?.policy?.autoReboot)
            }
            className={`px-3.5 py-1.5 rounded-xl font-semibold transition-all disabled:opacity-50 ${
              healStatus?.policy?.autoHealEnabled
                ? 'bg-rose-500/15 hover:bg-rose-500/25 border border-rose-500/30 text-rose-200'
                : 'bg-emerald-500/20 hover:bg-emerald-500/30 border border-emerald-500/35 text-emerald-200'
            }`}
          >
            {savingPolicy
              ? '正在应用...'
              : healStatus?.policy?.autoHealEnabled
              ? '关闭定时自愈'
              : '开启每日 04:00 自动自愈'}
          </button>
        </div>
      </div>

      {/* Fleet Heal Result Summary if Triggered */}
      {lastFleetHeal && lastFleetHeal.results.length > 0 && (
        <div className="p-3.5 rounded-2xl bg-slate-950/80 border border-sky-500/25 space-y-2 text-xs font-mono">
          <div className="flex items-center justify-between text-sky-300 font-semibold">
            <span>
              最近一次舰队协同自愈结果 ({lastFleetHeal.healthyNodes}/{lastFleetHeal.totalNodes} 健康)
            </span>
            <button type="button" onClick={onClearFleetHeal} className="text-slate-400 hover:text-white">
              <X className="w-3.5 h-3.5" />
            </button>
          </div>
          {lastFleetHeal.circuitBreakerHit && (
            <div className="p-2 rounded-lg bg-rose-500/15 border border-rose-500/30 text-rose-200 flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 shrink-0" />
              <span>{lastFleetHeal.circuitBreakerNote}</span>
            </div>
          )}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
            {lastFleetHeal.results.map((r) => (
              <div
                key={r.id}
                className="p-2.5 rounded-xl bg-slate-900/80 border border-slate-800 flex items-start gap-2"
              >
                {r.success ? (
                  <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0 mt-0.5" />
                ) : (
                  <AlertTriangle className="w-3.5 h-3.5 text-rose-400 shrink-0 mt-0.5" />
                )}
                <div className="min-w-0">
                  <div className="font-semibold text-white">
                    {r.name} (#{r.id})
                  </div>
                  <div className="text-[11px] text-slate-400 break-words">{r.summary}</div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Recent Self-Healing History */}
      {healStatus?.history && healStatus.history.length > 0 && (
        <div className="space-y-2">
          <div className="text-xs font-semibold text-slate-400">最近自愈记录</div>
          <div className="space-y-1.5 max-h-40 overflow-y-auto pr-1">
            {healStatus.history.slice(0, 5).map((h, i) => (
              <div
                key={`${h.timestamp}-${i}`}
                className="px-3 py-2 rounded-xl bg-slate-950/50 border border-slate-800/70 flex flex-col sm:flex-row sm:items-center justify-between gap-1 text-xs font-mono"
              >
                <div className="flex items-center gap-2 min-w-0">
                  <span className={h.success ? 'text-emerald-400' : 'text-amber-400'}>{h.success ? '✓' : '!'}</span>
                  <span className="text-slate-200 font-sans truncate">{h.summary}</span>
                </div>
                <div className="text-[11px] text-slate-500 shrink-0">
                  [{h.trigger}] {new Date(h.timestamp).toLocaleString()}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};

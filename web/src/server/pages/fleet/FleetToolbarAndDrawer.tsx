import React from 'react';
import { FleetActionResult, FleetSummary } from '../../types';
import {
  ArrowUpCircle,
  CheckCircle2,
  Network,
  Plus,
  RefreshCw,
  Rocket,
  RotateCcw,
  ShieldAlert,
  Stethoscope,
  Terminal,
  X,
  XCircle,
  Zap,
} from 'lucide-react';
import { ModalMode } from './helpers';

export const FleetToolbarAndDrawer: React.FC<{
  summary: FleetSummary;
  hasNodes: boolean;
  runningKey: string | null;
  actionResults: FleetActionResult[] | null;
  actionBannerTitle: string;
  onClearResults: () => void;
  onOpenAddModal: (mode: ModalMode) => void;
  onFleetHeal: () => void;
  onRunAction: (action: 'sync' | 'probe' | 'doctor' | 'reset' | 'update', ids?: string[], label?: string) => void;
}> = ({
  summary,
  hasNodes,
  runningKey,
  actionResults,
  actionBannerTitle,
  onClearResults,
  onOpenAddModal,
  onFleetHeal,
  onRunAction,
}) => {
  return (
    <>
      {/* Top KPI Strip */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3 sm:gap-4">
        <div className="p-3.5 sm:p-4 rounded-2xl glass-card">
          <div className="text-xs text-slate-400">纳管子节点总数</div>
          <div className="text-xl sm:text-2xl font-bold font-mono text-white mt-1">{summary.total}</div>
          <div className="text-[11px] text-slate-500 mt-1 font-mono truncate">无 Agent 原生 SSH 编排</div>
        </div>
        <div className="p-3.5 sm:p-4 rounded-2xl glass-card">
          <div className="text-xs text-slate-400">在线健康节点</div>
          <div className="text-xl sm:text-2xl font-bold font-mono text-emerald-400 mt-1">
            {summary.online} <span className="text-sm text-slate-500">/ {summary.total}</span>
          </div>
          <div className="text-[11px] text-slate-500 mt-1 font-mono truncate">HTTPS :443 零日志自动巡检</div>
        </div>
        <div className="p-3.5 sm:p-4 rounded-2xl glass-card">
          <div className="text-xs text-slate-400">全网平均健康分</div>
          <div className="text-xl sm:text-2xl font-bold font-mono text-purple-300 mt-1">
            {summary.avgDoctorScore > 0 ? `${summary.avgDoctorScore} / 100` : '--'}
          </div>
          <div className="text-[11px] text-slate-500 mt-1 font-mono truncate">并发全链路 Doctor 评分</div>
        </div>
        <div className="p-3.5 sm:p-4 rounded-2xl glass-card">
          <div className="text-xs text-slate-400">已自动汇入 SubHub</div>
          <div className="text-xl sm:text-2xl font-bold font-mono text-sky-300 mt-1">{summary.totalSyncedEndpoints}</div>
          <div className="text-[11px] text-slate-500 mt-1 font-mono truncate">一条订阅链接统管全球</div>
        </div>
      </div>

      {/* Fleet Command Toolbar */}
      <div className="p-4 sm:p-5 rounded-2xl glass-card flex flex-col xl:flex-row xl:items-center justify-between gap-4">
        <div>
          <h2 className="text-base sm:text-lg font-semibold text-white tracking-tight flex items-center gap-2">
            <Network className="w-5 h-5 text-emerald-400 shrink-0" />
            <span>全球多节点舰队中枢</span>
          </h2>
          <p className="text-xs text-slate-400 mt-0.5 leading-relaxed">
            新购裸机只需输入 IP 与初始密码，自动复用主控配置创建灰云 DNS、完成 22→2222 免密加固并汇入总订阅
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <button
            onClick={() => onOpenAddModal('bootstrap')}
            className="flex items-center gap-1.5 px-3.5 py-2 rounded-xl bg-sky-500 hover:bg-sky-600 text-slate-950 font-semibold text-xs transition-colors shadow-lg shadow-sky-500/15"
          >
            <Rocket className="w-3.5 h-3.5" />
            <span>新机零配置开荒</span>
          </button>
          <button
            onClick={() => onOpenAddModal('existing')}
            className="flex items-center gap-1.5 px-3 py-2 rounded-xl bg-emerald-500/15 hover:bg-emerald-500/25 border border-emerald-500/30 text-emerald-300 font-semibold text-xs transition-colors"
          >
            <Plus className="w-3.5 h-3.5" />
            <span>纳管已有节点</span>
          </button>

          {hasNodes && (
            <>
              <button
                onClick={onFleetHeal}
                disabled={!!runningKey}
                className="flex items-center gap-1.5 px-3 py-2 rounded-xl bg-emerald-500/15 hover:bg-emerald-500/25 border border-emerald-500/30 text-xs text-emerald-200 font-semibold transition-colors disabled:opacity-50"
              >
                <ShieldAlert className={`w-3.5 h-3.5 text-emerald-400 ${runningKey === 'heal:all' ? 'animate-pulse' : ''}`} />
                <span>{runningKey === 'heal:all' ? '正在全网自愈...' : '全网安全自愈'}</span>
              </button>
              <button
                onClick={() => onRunAction('probe', undefined, '全网 HTTPS :443 毫秒级探活报告')}
                disabled={!!runningKey}
                className="flex items-center gap-1.5 px-3 py-2 rounded-xl bg-sky-500/15 hover:bg-sky-500/25 border border-sky-500/30 text-xs text-sky-200 font-medium transition-colors disabled:opacity-50"
              >
                <Zap className={`w-3.5 h-3.5 text-sky-400 ${runningKey === 'probe:all' ? 'animate-pulse' : ''}`} />
                <span>秒级探活</span>
              </button>
              <button
                onClick={() => onRunAction('sync', undefined, '全网节点同步报告')}
                disabled={!!runningKey}
                className="flex items-center gap-1.5 px-3 py-2 rounded-xl bg-slate-900 hover:bg-slate-800 border border-slate-700/70 text-xs text-slate-200 transition-colors disabled:opacity-50"
              >
                <RefreshCw className={`w-3.5 h-3.5 ${runningKey === 'sync:all' ? 'animate-spin text-emerald-400' : ''}`} />
                <span>同步订阅</span>
              </button>
              <button
                onClick={() => onRunAction('doctor', undefined, '全网并发体检报告')}
                disabled={!!runningKey}
                className="flex items-center gap-1.5 px-3 py-2 rounded-xl bg-purple-500/15 hover:bg-purple-500/25 border border-purple-500/30 text-xs text-purple-200 font-medium transition-colors disabled:opacity-50"
              >
                <Stethoscope className={`w-3.5 h-3.5 ${runningKey === 'doctor:all' ? 'animate-spin' : ''}`} />
                <span>全网体检</span>
              </button>
              <button
                onClick={() => onRunAction('reset', undefined, '全网凭据换血与自动同步报告')}
                disabled={!!runningKey}
                className="flex items-center gap-1.5 px-3 py-2 rounded-xl bg-amber-500/10 hover:bg-amber-500/20 border border-amber-500/30 text-xs text-amber-200 font-medium transition-colors disabled:opacity-50"
              >
                <RotateCcw className={`w-3.5 h-3.5 ${runningKey === 'reset:all' ? 'animate-spin' : ''}`} />
                <span>全网换血</span>
              </button>
              <button
                onClick={() => onRunAction('update', undefined, '全网 SingCtl 升级报告')}
                disabled={!!runningKey}
                className="flex items-center gap-1.5 px-3 py-2 rounded-xl bg-slate-900 hover:bg-slate-800 border border-slate-700/70 text-xs text-slate-300 transition-colors disabled:opacity-50"
              >
                <ArrowUpCircle className={`w-3.5 h-3.5 ${runningKey === 'update:all' ? 'animate-spin text-sky-400' : ''}`} />
                <span>升级版本</span>
              </button>
            </>
          )}
        </div>
      </div>

      {/* Execution Output Drawer */}
      {actionResults && actionResults.length > 0 && (
        <div className="p-4 sm:p-5 rounded-2xl glass-card border border-emerald-500/25 space-y-3">
          <div className="flex items-center justify-between gap-2">
            <div className="flex items-center gap-2 text-xs font-semibold text-white min-w-0">
              <Terminal className="w-4 h-4 text-emerald-400 shrink-0" />
              <span className="truncate">{actionBannerTitle || '舰队指令执行结果'}</span>
            </div>
            <button
              onClick={onClearResults}
              className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 shrink-0"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
          <div className="space-y-2 max-h-72 overflow-y-auto pr-1">
            {actionResults.map((r) => (
              <div
                key={r.id}
                className={`p-3 rounded-xl border text-xs font-mono ${
                  r.success
                    ? 'bg-emerald-950/20 border-emerald-500/25 text-slate-200'
                    : 'bg-rose-950/20 border-rose-500/30 text-rose-200'
                }`}
              >
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="flex items-center gap-2 font-semibold">
                    {r.success ? (
                      <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                    ) : (
                      <XCircle className="w-3.5 h-3.5 text-rose-400 shrink-0" />
                    )}
                    <span>
                      {r.name} ({r.id})
                    </span>
                    {r.latencyMs > 0 && <span className="text-slate-400 font-normal">· SSH {r.latencyMs}ms</span>}
                  </div>
                  {typeof r.doctorScore === 'number' && r.doctorScore > 0 && (
                    <span className="px-2 py-0.5 rounded bg-purple-500/20 text-purple-200 text-[11px]">
                      健康分 {r.doctorScore}/100
                    </span>
                  )}
                </div>
                <p className="mt-1 text-[11px] text-slate-300 break-words">{r.message}</p>
                {r.output && (
                  <pre className="mt-2 p-2.5 rounded-lg bg-slate-950/80 border border-slate-800/80 text-[11px] text-slate-400 whitespace-pre-wrap break-all max-h-40 overflow-y-auto">
                    {r.output}
                  </pre>
                )}
              </div>
            ))}
          </div>
        </div>
      )}
    </>
  );
};

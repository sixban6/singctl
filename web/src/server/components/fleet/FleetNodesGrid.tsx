import React from 'react';
import { FleetNode } from '../../types';
import {
  ArrowUpCircle,
  CheckCircle2,
  Clock,
  Edit3,
  Globe,
  Plus,
  RefreshCw,
  Rocket,
  RotateCcw,
  Server,
  Stethoscope,
  Trash2,
} from 'lucide-react';
import { authTypeLabel, ModalMode } from './helpers';

export const FleetNodesGrid: React.FC<{
  nodes: FleetNode[];
  runningKey: string | null;
  onOpenAddModal: (mode: ModalMode) => void;
  onOpenEditModal: (n: FleetNode) => void;
  onDeleteNode: (n: FleetNode) => void;
  onRunAction: (action: 'sync' | 'probe' | 'doctor' | 'reset' | 'update', ids?: string[], label?: string) => void;
}> = ({ nodes, runningKey, onOpenAddModal, onOpenEditModal, onDeleteNode, onRunAction }) => {
  if (nodes.length === 0) {
    return (
      <div className="p-8 sm:p-10 rounded-2xl glass-card text-center space-y-4">
        <div className="w-12 h-12 rounded-2xl bg-sky-500/10 border border-sky-500/20 flex items-center justify-center text-sky-400 mx-auto">
          <Server className="w-6 h-6" />
        </div>
        <div className="max-w-lg mx-auto space-y-1.5">
          <h3 className="text-base font-semibold text-white">尚未纳管任何远程子节点</h3>
          <p className="text-xs text-slate-400 leading-relaxed">
            新买任何空白 Linux VPS，只需填入 <strong>IP 地址</strong> 和 <strong>初始 root 密码</strong>
            ，主控将自动按归属地命名、自动在 Cloudflare 创建灰云解析、切换 SSH 2222 免密并装好四核服务汇入总订阅。
          </p>
        </div>
        <div className="flex flex-wrap items-center justify-center gap-3 pt-1">
          <button
            onClick={() => onOpenAddModal('bootstrap')}
            className="flex items-center gap-1.5 px-4 py-2.5 rounded-xl bg-sky-500 hover:bg-sky-600 text-slate-950 font-semibold text-xs transition-colors"
          >
            <Rocket className="w-4 h-4" />
            <span>新机零配置 60s 开荒纳管</span>
          </button>
          <button
            onClick={() => onOpenAddModal('existing')}
            className="flex items-center gap-1.5 px-4 py-2.5 rounded-xl bg-emerald-500/15 hover:bg-emerald-500/25 border border-emerald-500/30 text-emerald-300 font-semibold text-xs transition-colors"
          >
            <Plus className="w-4 h-4" />
            <span>纳管已有 SingCtl 节点</span>
          </button>
        </div>
        <p className="text-[11px] text-slate-500 font-mono break-all">
          SSH 命令行同样支持零参数向导: <code className="text-emerald-300">singctl fl new</code>
        </p>
      </div>
    );
  }

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 2xl:grid-cols-3 gap-4">
      {nodes.map((n) => {
        const isSyncing = runningKey === `sync:${n.id}`;
        const isDoctoring = runningKey === `doctor:${n.id}`;
        const isResetting = runningKey === `reset:${n.id}`;
        const isUpdating = runningKey === `update:${n.id}`;
        return (
          <div key={n.id} className="p-4 sm:p-5 rounded-2xl glass-card flex flex-col justify-between gap-4">
            <div className="space-y-3">
              <div className="flex items-start justify-between gap-2">
                <div className="min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="text-base font-bold text-white">{n.name}</span>
                    <span className="px-2 py-0.5 rounded-md text-[10px] font-mono bg-slate-800 text-emerald-300">
                      #{n.id}
                    </span>
                    <span className="px-2 py-0.5 rounded-md text-[10px] font-mono bg-slate-900 border border-slate-700/80 text-slate-400">
                      {authTypeLabel(n.authType)}
                    </span>
                  </div>
                  <div className="text-xs font-mono text-slate-400 mt-1 break-all">
                    {n.authType === 'ssh_alias'
                      ? `SSH Alias: ${n.sshAlias || n.host}`
                      : `${n.user}@${n.host}:${n.port || 22}`}
                  </div>
                  {n.domain && (
                    <div className="inline-flex items-center gap-1.5 mt-1.5 px-2 py-0.5 rounded-md bg-sky-500/10 border border-sky-500/20 text-[11px] font-mono text-sky-300 break-all">
                      <Globe className="w-3 h-3 shrink-0" />
                      <span>{n.domain}</span>
                      {n.dnsAutoManaged && <span className="text-[10px] text-sky-400/80">· 自动灰云</span>}
                      {typeof n.certDaysLeft === 'number' && n.certDaysLeft > 0 && (
                        <span
                          className={`text-[10px] ${
                            n.certDaysLeft <= 7 ? 'text-amber-300 font-semibold' : 'text-emerald-300/80'
                          }`}
                        >
                          · 证书{n.certDaysLeft}天
                        </span>
                      )}
                    </div>
                  )}
                </div>

                <div className="flex flex-col sm:flex-row items-end sm:items-center gap-1.5 shrink-0">
                  {n.doctorScore > 0 && (
                    <span
                      className={`px-2 py-0.5 rounded-full text-[11px] font-mono border ${
                        n.doctorScore >= 90
                          ? 'bg-purple-500/15 text-purple-200 border-purple-500/30'
                          : 'bg-amber-500/15 text-amber-200 border-amber-500/30'
                      }`}
                    >
                      {n.doctorScore}分
                    </span>
                  )}
                  <span
                    className={`inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-[11px] font-medium border ${
                      n.online
                        ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/25'
                        : 'bg-slate-800/80 text-slate-400 border-slate-700'
                    }`}
                  >
                    {n.online ? (
                      <>
                        <CheckCircle2 className="w-3 h-3" />
                        <span>在线 {n.latencyMs > 0 ? `${n.latencyMs}ms` : ''}</span>
                      </>
                    ) : (
                      <>
                        <Clock className="w-3 h-3" />
                        <span>待同步</span>
                      </>
                    )}
                  </span>
                </div>
              </div>

              {/* Runtime Metrics Box */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 p-3 rounded-xl bg-slate-950/60 border border-slate-800/80 text-xs font-mono">
                <div>
                  <div className="text-[10px] text-slate-500">已同步节点</div>
                  <div className="text-emerald-300 font-semibold mt-0.5 truncate">{n.syncedNodes} 个</div>
                </div>
                <div>
                  <div className="text-[10px] text-slate-500">版本</div>
                  <div className="text-slate-200 mt-0.5 truncate">{n.singctlVersion || '--'}</div>
                </div>
                <div>
                  <div className="text-[10px] text-slate-500">CPU / 内存</div>
                  <div className="text-slate-200 mt-0.5 truncate">
                    {n.cpuLoad ? n.cpuLoad.split(' ')[0] : '--'} / {n.memPercent > 0 ? `${n.memPercent.toFixed(0)}%` : '--'}
                  </div>
                </div>
                <div>
                  <div className="text-[10px] text-slate-500">BBR 加速</div>
                  <div className={n.bbrEnabled ? 'text-emerald-400 mt-0.5' : 'text-slate-400 mt-0.5'}>
                    {n.bbrEnabled ? '已开启' : '--'}
                  </div>
                </div>
              </div>

              {n.lastError && (
                <div className="px-3 py-2 rounded-xl bg-rose-950/30 border border-rose-500/30 text-[11px] font-mono text-rose-300 break-words">
                  上次异常: {n.lastError}
                </div>
              )}
            </div>

            <div className="pt-3 border-t border-slate-800 flex flex-wrap items-center justify-between gap-2 text-xs">
              <div className="flex flex-wrap items-center gap-1.5">
                <button
                  onClick={() => onRunAction('sync', [n.id], `同步节点 · ${n.name}`)}
                  disabled={!!runningKey}
                  className="flex items-center gap-1 px-2.5 py-1.5 rounded-lg bg-emerald-500/10 hover:bg-emerald-500/20 border border-emerald-500/25 text-emerald-300 transition-colors disabled:opacity-50"
                >
                  <RefreshCw className={`w-3 h-3 ${isSyncing ? 'animate-spin' : ''}`} />
                  <span>同步</span>
                </button>
                <button
                  onClick={() => onRunAction('doctor', [n.id], `健康体检 · ${n.name}`)}
                  disabled={!!runningKey}
                  className="flex items-center gap-1 px-2.5 py-1.5 rounded-lg bg-purple-500/10 hover:bg-purple-500/20 border border-purple-500/25 text-purple-200 transition-colors disabled:opacity-50"
                >
                  <Stethoscope className={`w-3 h-3 ${isDoctoring ? 'animate-spin' : ''}`} />
                  <span>体检</span>
                </button>
                <button
                  onClick={() => onRunAction('reset', [n.id], `凭据换血 · ${n.name}`)}
                  disabled={!!runningKey}
                  className="flex items-center gap-1 px-2.5 py-1.5 rounded-lg bg-amber-500/10 hover:bg-amber-500/20 border border-amber-500/25 text-amber-200 transition-colors disabled:opacity-50"
                >
                  <RotateCcw className={`w-3 h-3 ${isResetting ? 'animate-spin' : ''}`} />
                  <span>换血</span>
                </button>
                <button
                  onClick={() => onRunAction('update', [n.id], `升级 SingCtl · ${n.name}`)}
                  disabled={!!runningKey}
                  className="flex items-center gap-1 px-2.5 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-800 text-slate-300 transition-colors disabled:opacity-50"
                >
                  <ArrowUpCircle className={`w-3 h-3 ${isUpdating ? 'animate-spin' : ''}`} />
                  <span>升级</span>
                </button>
              </div>

              <div className="flex items-center gap-1.5">
                <button
                  onClick={() => onOpenEditModal(n)}
                  className="p-2 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-800 text-slate-400 hover:text-white transition-colors"
                  title="编辑连接信息"
                >
                  <Edit3 className="w-3.5 h-3.5" />
                </button>
                <button
                  onClick={() => onDeleteNode(n)}
                  className="p-2 rounded-lg bg-rose-500/10 hover:bg-rose-500/20 border border-rose-500/20 text-rose-300 transition-colors"
                  title="从舰队及订阅池移除"
                >
                  <Trash2 className="w-3.5 h-3.5" />
                </button>
              </div>
            </div>
          </div>
        );
      })}
    </div>
  );
};

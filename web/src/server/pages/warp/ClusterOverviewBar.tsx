import React from 'react';
import { WarpNodeSummary } from '../../types';
import { Globe, RefreshCw, RotateCcw, Server, Wrench } from 'lucide-react';

export const ClusterOverviewBar: React.FC<{
  clusterNodes: WarpNodeSummary[];
  healthyNodeCount: number;
  selectedNode: string;
  syncCluster: boolean;
  setSyncCluster: React.Dispatch<React.SetStateAction<boolean>>;
  switchingNode: boolean;
  actingNodeKey: string | null;
  acting: 'rekey' | 'ensure' | 'enable_telemetry' | null;
  onSelectNode: (nodeId: string) => void;
  onWarpAction: (action: 'rekey' | 'ensure', nodeOverride?: string) => void;
}> = ({
  clusterNodes,
  healthyNodeCount,
  selectedNode,
  syncCluster,
  setSyncCluster,
  switchingNode,
  actingNodeKey,
  acting,
  onSelectNode,
  onWarpAction,
}) => {
  if (clusterNodes.length <= 1) return null;

  return (
    <div className="p-4 rounded-2xl glass-card space-y-3.5">
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-3">
        <div className="flex flex-wrap items-center gap-1.5">
          <button
            type="button"
            onClick={() => onSelectNode('all')}
            className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-xs font-semibold border transition-all ${
              selectedNode === 'all'
                ? 'bg-amber-500/20 text-amber-200 border-amber-500/40 shadow-sm'
                : 'bg-slate-950/70 text-slate-300 border-slate-800 hover:border-slate-700'
            }`}
          >
            <Globe className="w-3.5 h-3.5 text-amber-400" />
            <span>全集群总览</span>
            <span className="px-1.5 py-0.5 rounded bg-slate-900/90 text-[10px] font-mono text-amber-300">
              {healthyNodeCount}/{clusterNodes.length}
            </span>
          </button>

          {clusterNodes.map((n) => {
            const isSelected = selectedNode === n.id;
            const healthy = Boolean(n.daemon?.tunnelHealthy);
            const installed = Boolean(n.daemon?.installed);
            return (
              <button
                key={n.id}
                type="button"
                onClick={() => onSelectNode(n.id)}
                className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-xs font-medium border transition-all ${
                  isSelected
                    ? 'bg-emerald-500/15 text-emerald-200 border-emerald-500/40 shadow-sm'
                    : 'bg-slate-950/70 text-slate-300 border-slate-800 hover:border-slate-700'
                }`}
              >
                <span
                  className={`w-2 h-2 rounded-full shrink-0 ${
                    healthy ? 'bg-emerald-400' : installed ? 'bg-amber-400' : 'bg-slate-500'
                  }`}
                />
                <span>{n.isLocal ? '🏠 主控本机' : n.name}</span>
                {n.daemon?.warpLoc && (
                  <span className="px-1.5 py-0.5 rounded bg-slate-900/90 text-[10px] font-mono text-slate-300">
                    {n.daemon.warpLoc}
                  </span>
                )}
                {n.mode === 'global_warp' && (
                  <span className="px-1.5 py-0.5 rounded bg-amber-500/15 text-[10px] font-mono text-amber-300">
                    全局
                  </span>
                )}
                {n.mode === 'bypass' && (
                  <span className="px-1.5 py-0.5 rounded bg-rose-500/15 text-[10px] font-mono text-rose-300">
                    旁路
                  </span>
                )}
              </button>
            );
          })}
        </div>

        <div className="flex flex-wrap items-center gap-2 shrink-0">
          {selectedNode !== 'all' ? (
            <button
              type="button"
              role="switch"
              aria-checked={syncCluster}
              onClick={() => setSyncCluster((v) => !v)}
              className={`inline-flex items-center gap-2 px-3 py-1.5 rounded-xl text-xs font-medium border transition-all ${
                syncCluster
                  ? 'bg-amber-500/20 text-amber-200 border-amber-500/45'
                  : 'bg-slate-950/80 text-slate-400 border-slate-800 hover:text-slate-200'
              }`}
              title="开启后，在当前节点修改分流模式、预设或自定义规则将同步并发下发至全集群所有就绪节点"
            >
              <span className={`w-2 h-2 rounded-full ${syncCluster ? 'bg-amber-400 animate-pulse' : 'bg-slate-600'}`} />
              <span>同步规则至全集群</span>
            </button>
          ) : (
            <button
              type="button"
              onClick={() => onWarpAction('rekey', 'all')}
              disabled={actingNodeKey === 'all:rekey' || acting !== null}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-xl bg-amber-500/15 hover:bg-amber-500/25 border border-amber-500/35 text-amber-200 text-xs font-medium transition-colors disabled:opacity-45"
            >
              <RotateCcw className={`w-3.5 h-3.5 ${actingNodeKey === 'all:rekey' ? 'animate-spin' : ''}`} />
              <span>{actingNodeKey === 'all:rekey' ? '全集群换 IP 中...' : '全集群批量换 IP'}</span>
            </button>
          )}

          {switchingNode && (
            <span className="inline-flex items-center gap-1 text-[11px] font-mono text-sky-300">
              <RefreshCw className="w-3 h-3 animate-spin" />
              切换中...
            </span>
          )}
        </div>
      </div>

      {/* 全集群总览模式下的各节点健康矩阵 */}
      {selectedNode === 'all' && (
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-3 pt-2 border-t border-slate-800/80">
          {clusterNodes.map((n) => {
            const healthy = Boolean(n.daemon?.tunnelHealthy);
            const busyRekey = actingNodeKey === `${n.id}:rekey`;
            const busyEnsure = actingNodeKey === `${n.id}:ensure`;
            const modeText =
              n.mode === 'global_warp' ? '全局 WARP' : n.mode === 'bypass' ? '紧急旁路' : '按需分流';
            return (
              <div
                key={`card-${n.id}`}
                className="p-3.5 rounded-xl bg-slate-950/65 border border-slate-800/90 flex flex-col justify-between gap-2.5"
              >
                <div className="space-y-1.5">
                  <div className="flex items-center justify-between gap-2">
                    <div className="flex items-center gap-1.5 min-w-0">
                      <Server className="w-3.5 h-3.5 text-slate-400 shrink-0" />
                      <span className="text-xs font-semibold text-white truncate">
                        {n.isLocal ? '主控本机' : n.name}
                      </span>
                    </div>
                    <span
                      className={`px-1.5 py-0.5 rounded text-[10px] font-mono border shrink-0 ${
                        healthy
                          ? 'bg-emerald-500/10 text-emerald-300 border-emerald-500/25'
                          : 'bg-rose-500/10 text-rose-300 border-rose-500/25'
                      }`}
                    >
                      {healthy ? 'WARP 就绪' : '未就绪'}
                    </span>
                  </div>
                  <div className="text-[11px] font-mono text-slate-300 truncate">
                    出口:{' '}
                    {n.daemon?.warpIp
                      ? `${n.daemon.warpIp}${n.daemon.warpLoc ? ` (${n.daemon.warpLoc})` : ''}`
                      : n.daemon?.error || '未安装 / 待探测'}
                  </div>
                  <div className="flex items-center justify-between text-[10px] font-mono text-slate-400">
                    <span>策略: {modeText}</span>
                    <span>
                      DC {n.dcConnCount} / WARP {n.warpConnCount}
                    </span>
                  </div>
                </div>

                <div className="flex items-center justify-between gap-1.5 pt-2 border-t border-slate-800/70">
                  {healthy ? (
                    <button
                      type="button"
                      onClick={() => onWarpAction('rekey', n.id)}
                      disabled={busyRekey || actingNodeKey !== null}
                      className="inline-flex items-center gap-1 px-2 py-1 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-700/70 text-[11px] text-slate-200 disabled:opacity-45"
                    >
                      <RotateCcw className={`w-3 h-3 text-amber-400 ${busyRekey ? 'animate-spin' : ''}`} />
                      <span>{busyRekey ? '换 IP 中...' : '换 IP'}</span>
                    </button>
                  ) : (
                    <button
                      type="button"
                      onClick={() => onWarpAction('ensure', n.id)}
                      disabled={busyEnsure || actingNodeKey !== null}
                      className="inline-flex items-center gap-1 px-2 py-1 rounded-lg bg-amber-500/20 hover:bg-amber-500/30 border border-amber-500/35 text-[11px] text-amber-200 disabled:opacity-45"
                    >
                      <Wrench className={`w-3 h-3 ${busyEnsure ? 'animate-spin' : ''}`} />
                      <span>{busyEnsure ? '部署中...' : '一键部署 WARP'}</span>
                    </button>
                  )}

                  <button
                    type="button"
                    onClick={() => onSelectNode(n.id)}
                    className="px-2 py-1 rounded-lg bg-slate-900/80 hover:bg-slate-800 border border-slate-800 text-[11px] text-sky-300"
                  >
                    单独配置 →
                  </button>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
};

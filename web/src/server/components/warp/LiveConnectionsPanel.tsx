import React from 'react';
import { ActiveDestinationGroup, WarpNodeSummary, WarpRoutingMode } from '../../types';
import { formatBytes } from '../../../ui';
import { Globe, RefreshCw, Search, Zap } from 'lucide-react';

export const LiveConnectionsPanel: React.FC<{
  selectedNode: string;
  clusterNodes: WarpNodeSummary[];
  connEnabled: boolean;
  connMsg: string;
  connections: ActiveDestinationGroup[];
  connQuery: string;
  setConnQuery: (q: string) => void;
  connFilter: 'all' | 'DC' | 'WARP';
  setConnFilter: (f: 'all' | 'DC' | 'WARP') => void;
  autoRefreshConn: boolean;
  setAutoRefreshConn: React.Dispatch<React.SetStateAction<boolean>>;
  loadingConn: boolean;
  switchingTarget: string | null;
  routingMode: WarpRoutingMode;
  enablingTelemetry: boolean;
  onSelectNode: (nodeId: string) => void;
  onRefreshConnections: () => void;
  onEnableTelemetry: () => void;
  onQuickSwitch: (target: string, outbound: 'WARP' | 'DC') => void;
}> = ({
  selectedNode,
  clusterNodes,
  connEnabled,
  connMsg,
  connections,
  connQuery,
  setConnQuery,
  connFilter,
  setConnFilter,
  autoRefreshConn,
  setAutoRefreshConn,
  loadingConn,
  switchingTarget,
  routingMode,
  enablingTelemetry,
  onSelectNode,
  onRefreshConnections,
  onEnableTelemetry,
  onQuickSwitch,
}) => {
  return (
    <div className="p-5 rounded-2xl glass-card space-y-4">
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-3 pb-3 border-b border-slate-800/80">
        <div className="flex items-center gap-2.5">
          <div className="p-1.5 rounded-xl bg-purple-500/10 text-purple-400 border border-purple-500/20">
            <Globe className="w-4 h-4" />
          </div>
          <div>
            <h3 className="text-sm font-semibold text-white flex items-center gap-2">
              <span>实时活跃连接透视与行内秒切</span>
              <span className="px-2 py-0.5 rounded-full bg-slate-900 border border-slate-800 text-[10px] font-mono text-slate-400">
                {connections.length} 个活跃目标
              </span>
            </h3>
            <p className="text-[11px] text-slate-400">
              实时追踪当前节点访问的远端站点与出口（不展示客户端源 IP），发现卡顿/弹验证可直接点选切走 WARP
            </p>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <div className="relative">
            <Search className="w-3.5 h-3.5 text-slate-500 absolute left-2.5 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={connQuery}
              onChange={(e) => setConnQuery(e.target.value)}
              placeholder="筛选域名 / IP / 规则..."
              className="bg-slate-950 border border-slate-800 rounded-xl pl-8 pr-3 py-1.5 text-xs text-slate-200 placeholder:text-slate-500 focus:outline-none focus:border-amber-500/50 w-44 sm:w-56"
            />
          </div>

          <div className="inline-flex rounded-xl bg-slate-950 p-0.5 border border-slate-800 text-[11px]">
            {(['all', 'DC', 'WARP'] as const).map((f) => (
              <button
                key={f}
                type="button"
                onClick={() => setConnFilter(f)}
                className={`px-2.5 py-1 rounded-lg font-medium transition-colors ${
                  connFilter === f ? 'bg-slate-800 text-white' : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                {f === 'all' ? '全部' : f === 'DC' ? '直出 DC' : 'WARP'}
              </button>
            ))}
          </div>

          <button
            type="button"
            onClick={() => setAutoRefreshConn((v) => !v)}
            className={`px-2.5 py-1.5 rounded-xl border text-[11px] font-mono transition-colors ${
              autoRefreshConn
                ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-300'
                : 'bg-slate-900 border-slate-800 text-slate-400'
            }`}
          >
            {autoRefreshConn ? '5s 自动刷新' : '已暂停刷新'}
          </button>

          <button
            type="button"
            onClick={onRefreshConnections}
            className="p-1.5 rounded-xl bg-slate-900 hover:bg-slate-800 border border-slate-800 text-slate-300"
            title="立即刷新活跃连接"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loadingConn ? 'animate-spin' : ''}`} />
          </button>
        </div>
      </div>

      {selectedNode === 'all' ? (
        <div className="p-5 rounded-xl bg-slate-950/60 border border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div className="text-xs text-slate-300">
            当前处于「全集群总览」视角，活跃连接按单机实时采集。点击任意节点即可实时透视该主机的出站连接并一键秒切：
          </div>
          <div className="flex flex-wrap items-center gap-1.5 shrink-0">
            {clusterNodes.map((n) => (
              <button
                key={`jump-${n.id}`}
                type="button"
                onClick={() => onSelectNode(n.id)}
                className="px-2.5 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-700/80 text-xs text-sky-300 font-medium"
              >
                {n.isLocal ? '主控本机' : n.name} ({n.dcConnCount + n.warpConnCount})
              </button>
            ))}
          </div>
        </div>
      ) : !connEnabled ? (
        <div className="p-5 rounded-xl bg-slate-950/60 border border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div className="text-xs text-slate-300">
            {connMsg || '当前节点 sing-box 尚未开启本地回环遥测接口 (127.0.0.1:9099)，无法透视实时连接。'}
          </div>
          <button
            type="button"
            onClick={onEnableTelemetry}
            disabled={enablingTelemetry}
            className="px-3.5 py-2 rounded-xl bg-emerald-500 hover:bg-emerald-600 text-slate-950 font-semibold text-xs shrink-0 disabled:opacity-50"
          >
            {enablingTelemetry ? '正在开启...' : '一键开启该节点遥测'}
          </button>
        </div>
      ) : connections.length === 0 ? (
        <div className="py-8 text-center text-xs font-mono text-slate-500">
          当前无符合条件的活跃目标连接，客户端发起访问后将实时出现在此处
        </div>
      ) : (
        <div className="space-y-2 max-h-96 overflow-y-auto pr-1">
          {connections.map((item) => {
            const isWarp = item.outbound === 'WARP';
            const showRootBtn = !item.isIP && item.rootDomain && item.rootDomain !== item.target;
            const primaryTarget = showRootBtn ? item.rootDomain : item.target;
            const busyPrimary = switchingTarget === primaryTarget;
            const busyExact = switchingTarget === item.target;

            return (
              <div
                key={`${item.target}-${item.outbound}`}
                className="px-3.5 py-2.5 rounded-xl bg-slate-950/65 border border-slate-800/80 flex flex-col sm:flex-row sm:items-center justify-between gap-2.5 text-xs"
              >
                <div className="min-w-0 flex-1 space-y-1">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="font-mono font-semibold text-slate-100 truncate" title={item.target}>
                      {item.target}
                    </span>
                    {showRootBtn && (
                      <span className="px-1.5 py-0.5 rounded bg-slate-900 border border-slate-800 text-[10px] font-mono text-slate-400">
                        主域 {item.rootDomain}
                      </span>
                    )}
                    <span className="px-1.5 py-0.5 rounded bg-slate-900 border border-slate-800 text-[10px] font-mono text-purple-300">
                      {item.protocol}
                    </span>
                    <span
                      className={`px-1.5 py-0.5 rounded text-[10px] font-mono border ${
                        isWarp
                          ? 'bg-amber-500/15 text-amber-300 border-amber-500/30'
                          : 'bg-sky-500/15 text-sky-300 border-sky-500/30'
                      }`}
                    >
                      {isWarp ? 'WARP' : '直出 DC'}
                    </span>
                  </div>
                  <div className="flex items-center gap-3 text-[11px] font-mono text-slate-400 flex-wrap">
                    <span>{item.connections} 条连接</span>
                    <span>累计 {formatBytes(item.totalBytes)}</span>
                    {item.rule && <span className="text-slate-500 truncate">命中: {item.rule}</span>}
                  </div>
                </div>

                <div className="flex items-center gap-1.5 shrink-0">
                  <button
                    type="button"
                    disabled={busyPrimary || routingMode === 'bypass'}
                    onClick={() => onQuickSwitch(primaryTarget, isWarp ? 'DC' : 'WARP')}
                    className={`inline-flex items-center gap-1 px-2.5 py-1.5 rounded-lg text-[11px] font-semibold border transition-colors disabled:opacity-45 ${
                      isWarp
                        ? 'bg-sky-500/10 hover:bg-sky-500/20 text-sky-300 border-sky-500/30'
                        : 'bg-amber-500/15 hover:bg-amber-500/25 text-amber-300 border-amber-500/35'
                    }`}
                  >
                    <Zap className={`w-3 h-3 ${busyPrimary ? 'animate-spin' : ''}`} />
                    <span>
                      {showRootBtn
                        ? isWarp
                          ? `主域切回直出`
                          : `主域切 WARP`
                        : isWarp
                        ? '切回直出'
                        : '切走 WARP'}
                    </span>
                  </button>

                  {showRootBtn && (
                    <button
                      type="button"
                      disabled={busyExact || routingMode === 'bypass'}
                      onClick={() => onQuickSwitch(`full:${item.target}`, isWarp ? 'DC' : 'WARP')}
                      className="px-2 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-700/70 text-[10px] font-mono text-slate-300 disabled:opacity-45"
                      title={`仅对精确域名 ${item.target} 进行分流`}
                    >
                      仅此子域
                    </button>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
};

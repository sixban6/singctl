import React from 'react';
import { SubscriptionSourceItem } from '../../types';
import { Edit3, Globe, Layers, Plus, RefreshCw, Server, Trash2 } from 'lucide-react';
import { formatEffectiveUA } from './helpers';

export const SourcesPoolCard: React.FC<{
  sources: SubscriptionSourceItem[];
  refreshingSource: string | null;
  onRefreshSources: (targetName?: string) => void;
  onAddSource: () => void;
  onEditSource: (item: SubscriptionSourceItem) => void;
  onToggleSourceEnabled: (item: SubscriptionSourceItem) => void;
  onDeleteSource: (item: SubscriptionSourceItem) => void;
}> = ({
  sources,
  refreshingSource,
  onRefreshSources,
  onAddSource,
  onEditSource,
  onToggleSourceEnabled,
  onDeleteSource,
}) => {
  return (
    <div className="p-5 rounded-2xl glass-card space-y-4">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-slate-800">
        <div>
          <h3 className="text-sm font-semibold text-white flex items-center gap-2">
            <Layers className="w-4 h-4 text-emerald-400" />
            <span>多源聚合节点池 (Aggregated Sources)</span>
          </h3>
          <p className="text-xs text-slate-400 mt-0.5">
            除本机自动同步节点外，可添加其他自建 VPS 节点链接或第三方远程订阅链接统一合并下发
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2 shrink-0">
          {sources.some((s) => s.source === 'remote') && (
            <button
              type="button"
              onClick={() => onRefreshSources()}
              disabled={refreshingSource !== null}
              className="flex items-center justify-center gap-1.5 px-3 py-2 rounded-xl bg-blue-500/10 hover:bg-blue-500/20 border border-blue-500/30 text-blue-300 text-xs font-semibold transition-colors disabled:opacity-50"
              title="使用自适应客户端 UA 重新拉取并解析全部外部订阅"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${refreshingSource === '__all__' ? 'animate-spin' : ''}`} />
              <span>刷新远程源</span>
            </button>
          )}
          <button
            onClick={onAddSource}
            className="flex items-center justify-center gap-1.5 px-3.5 py-2 rounded-xl bg-emerald-500/15 hover:bg-emerald-500/25 border border-emerald-500/30 text-emerald-300 text-xs font-semibold transition-colors"
          >
            <Plus className="w-3.5 h-3.5" />
            <span>添加节点源 / 外部订阅</span>
          </button>
        </div>
      </div>

      {sources.length === 0 ? (
        <div className="p-6 text-center text-xs text-slate-500 bg-slate-950/40 rounded-xl border border-slate-800/70">
          当前暂无订阅源记录，点击右上角「添加节点源」或执行 <code className="text-slate-300">singctl sr sync</code> 同步本机节点
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          {sources.map((item) => (
            <div
              key={item.name}
              className={`p-4 rounded-xl border transition-all flex flex-col justify-between gap-3 ${
                item.enabled
                  ? 'bg-slate-950/60 border-slate-800'
                  : 'bg-slate-950/30 border-slate-800/50 opacity-65'
              }`}
            >
              <div className="flex items-start justify-between gap-2">
                <div className="min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="font-semibold text-sm text-white truncate">{item.displayName}</span>
                    {item.autoManaged ? (
                      <span className="px-2 py-0.5 rounded-md text-[10px] font-mono bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                        本机自动同步
                      </span>
                    ) : item.name.startsWith('fleet_') ? (
                      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md text-[10px] font-mono bg-cyan-500/10 text-cyan-300 border border-cyan-500/25">
                        <Server className="w-2.5 h-2.5" />
                        舰队自动同步
                      </span>
                    ) : item.source === 'remote' ? (
                      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md text-[10px] font-mono bg-blue-500/10 text-blue-400 border border-blue-500/20">
                        <Globe className="w-2.5 h-2.5" />
                        远程订阅
                      </span>
                    ) : (
                      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md text-[10px] font-mono bg-purple-500/10 text-purple-300 border border-purple-500/20">
                        <Server className="w-2.5 h-2.5" />
                        自定义节点
                      </span>
                    )}
                    <span
                      className={`px-2 py-0.5 rounded-md text-[10px] font-mono ${
                        item.nodeCount > 0
                          ? 'bg-slate-800 text-slate-200'
                          : 'bg-amber-500/15 text-amber-300 border border-amber-500/25'
                      }`}
                    >
                      {item.nodeCount} 节点
                    </span>
                    {item.source === 'remote' && item.effectiveUa && (
                      <span
                        className="px-2 py-0.5 rounded-md text-[10px] font-mono bg-slate-900 text-slate-400 border border-slate-800"
                        title={`协商客户端 UA: ${item.effectiveUa}${item.usedProxy ? ` (${item.usedProxy})` : ''}`}
                      >
                        {formatEffectiveUA(item.effectiveUa)}
                        {item.usedProxy === 'warp' ? ' · WARP' : ''}
                      </span>
                    )}
                  </div>
                  <p className="text-[11px] text-slate-500 font-mono mt-1 truncate">
                    {item.source === 'remote' ? item.url : item.remark || `标识: ${item.name}`}
                  </p>
                  {item.source === 'remote' && item.lastError && (
                    <p className="text-[11px] text-amber-300/90 font-mono mt-1.5 px-2 py-1 rounded-lg bg-amber-500/10 border border-amber-500/20 break-all">
                      拉取提示: {item.lastError}
                    </p>
                  )}
                </div>

                <button
                  type="button"
                  onClick={() => onToggleSourceEnabled(item)}
                  className={`px-2.5 py-1 rounded-lg text-[11px] font-mono border shrink-0 transition-colors ${
                    item.enabled
                      ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30 hover:bg-emerald-500/20'
                      : 'bg-slate-900 text-slate-400 border-slate-700 hover:text-white'
                  }`}
                >
                  {item.enabled ? '已启用' : '已停用'}
                </button>
              </div>

              <div className="pt-2.5 border-t border-slate-800/70 flex items-center justify-between gap-2 text-xs">
                <span className="text-[11px] text-slate-500 font-mono truncate">
                  {item.source === 'remote' && item.lastFetchedAt
                    ? `更新于 ${new Date(item.lastFetchedAt).toLocaleTimeString()}`
                    : item.name}
                </span>
                <div className="flex items-center gap-1.5 shrink-0">
                  {item.source === 'remote' && (
                    <button
                      type="button"
                      onClick={() => onRefreshSources(item.name)}
                      disabled={refreshingSource !== null}
                      className="flex items-center gap-1 px-2.5 py-1 rounded-lg bg-blue-500/10 hover:bg-blue-500/20 border border-blue-500/25 text-blue-300 transition-colors disabled:opacity-50"
                      title="立即重新拉取此远程订阅"
                    >
                      <RefreshCw className={`w-3 h-3 ${refreshingSource === item.name ? 'animate-spin' : ''}`} />
                      <span>刷新</span>
                    </button>
                  )}
                  <button
                    type="button"
                    onClick={() => onEditSource(item)}
                    className="flex items-center gap-1 px-2.5 py-1 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-800 text-slate-300 hover:text-white transition-colors"
                  >
                    <Edit3 className="w-3 h-3" />
                    <span>编辑</span>
                  </button>
                  {!item.autoManaged && (
                    <button
                      type="button"
                      onClick={() => onDeleteSource(item)}
                      className="flex items-center gap-1 px-2.5 py-1 rounded-lg bg-rose-500/10 hover:bg-rose-500/20 border border-rose-500/20 text-rose-300 transition-colors"
                    >
                      <Trash2 className="w-3 h-3" />
                      <span>移除</span>
                    </button>
                  )}
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

import React, { useMemo, useState } from 'react';
import { WarpRoutingConfig } from '../../types';
import { CheckCircle2, Plus, ShieldCheck, Sparkles, Trash2 } from 'lucide-react';
import { previewCleanRuleTarget } from './helpers';

export const CustomRulesBuckets: React.FC<{
  routing: WarpRoutingConfig;
  onAddRules: (bucket: 'warp' | 'direct', rawText: string) => void;
  onRemoveRule: (bucket: 'warp' | 'direct', kind: 'domain' | 'cidr', value: string) => void;
}> = ({ routing, onAddRules, onRemoveRule }) => {
  const [warpInput, setWarpInput] = useState('');
  const [directInput, setDirectInput] = useState('');

  const warpPreview = useMemo(() => previewCleanRuleTarget(warpInput), [warpInput]);
  const directPreview = useMemo(() => previewCleanRuleTarget(directInput), [directInput]);

  const submitWarp = () => {
    if (!warpInput.trim()) return;
    onAddRules('warp', warpInput);
    setWarpInput('');
  };

  const submitDirect = () => {
    if (!directInput.trim()) return;
    onAddRules('direct', directInput);
    setDirectInput('');
  };

  return (
    <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
      {/* 强制走 WARP 名单 */}
      <div className="p-5 rounded-2xl glass-card space-y-4">
        <div className="flex items-center justify-between pb-3 border-b border-slate-800/80">
          <div className="flex items-center gap-2">
            <Sparkles className="w-4 h-4 text-amber-400" />
            <div>
              <h3 className="text-sm font-semibold text-white">强制走 WARP 名单</h3>
              <p className="text-[11px] text-slate-400">
                支持直接粘贴完整网址（自动提取域名）、<code className="text-amber-300">full:</code>、
                <code className="text-amber-300">keyword:</code> 或 IP/CIDR
              </p>
            </div>
          </div>
          <span className="px-2 py-0.5 rounded-md bg-amber-500/10 border border-amber-500/25 text-[11px] font-mono text-amber-300">
            {(routing.warpDomains?.length || 0) + (routing.warpCidrs?.length || 0)} 项
          </span>
        </div>

        <div className="space-y-2">
          <div className="flex gap-2">
            <input
              type="text"
              value={warpInput}
              onChange={(e) => setWarpInput(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === 'Enter') {
                  e.preventDefault();
                  submitWarp();
                }
              }}
              placeholder="例如: missav.ws 或粘贴 https://missav.ws/dm13/... 或 198.51.100.0/24"
              className="flex-1 bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-xs font-mono text-slate-100 placeholder:text-slate-500 focus:outline-none focus:border-amber-500/60"
            />
            <button
              type="button"
              onClick={submitWarp}
              disabled={!warpInput.trim()}
              className="inline-flex items-center gap-1 px-3.5 py-2 rounded-xl bg-amber-500 hover:bg-amber-400 text-slate-950 font-semibold text-xs disabled:opacity-40 shrink-0"
            >
              <Plus className="w-3.5 h-3.5" />
              <span>添加</span>
            </button>
          </div>
          {warpPreview && (
            <div className="text-[11px] font-mono text-amber-300/90 flex items-center gap-1.5">
              <CheckCircle2 className="w-3 h-3" />
              <span>
                将添加{warpPreview.kind === 'cidr' ? ' IP/CIDR 规则' : '域名规则'}: <strong>{warpPreview.value}</strong>
              </span>
            </div>
          )}
        </div>

        <div className="flex flex-wrap gap-1.5 min-h-[44px] items-start">
          {(routing.warpDomains || []).map((d) => (
            <span
              key={`wd-${d}`}
              className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-amber-500/10 border border-amber-500/30 text-xs font-mono text-amber-200"
            >
              <span>{d}</span>
              <button
                type="button"
                onClick={() => onRemoveRule('warp', 'domain', d)}
                className="text-amber-300/70 hover:text-rose-300"
                title="移除规则"
              >
                <Trash2 className="w-3 h-3" />
              </button>
            </span>
          ))}
          {(routing.warpCidrs || []).map((c) => (
            <span
              key={`wc-${c}`}
              className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-orange-500/10 border border-orange-500/30 text-xs font-mono text-orange-200"
            >
              <span>CIDR {c}</span>
              <button
                type="button"
                onClick={() => onRemoveRule('warp', 'cidr', c)}
                className="text-orange-300/70 hover:text-rose-300"
                title="移除规则"
              >
                <Trash2 className="w-3 h-3" />
              </button>
            </span>
          ))}
          {(routing.warpDomains?.length || 0) + (routing.warpCidrs?.length || 0) === 0 && (
            <span className="text-xs font-mono text-slate-500">暂无自定义 WARP 规则</span>
          )}
        </div>
      </div>

      {/* 强制原生直出白名单 */}
      <div className="p-5 rounded-2xl glass-card space-y-4">
        <div className="flex items-center justify-between pb-3 border-b border-slate-800/80">
          <div className="flex items-center gap-2">
            <ShieldCheck className="w-4 h-4 text-sky-400" />
            <div>
              <h3 className="text-sm font-semibold text-white">强制原生直出白名单 (最高优先级)</h3>
              <p className="text-[11px] text-slate-400">
                优先于全局 WARP 与预设规则执行，适合国内直连服务、银行或内部接口放行原生出口
              </p>
            </div>
          </div>
          <span className="px-2 py-0.5 rounded-md bg-sky-500/10 border border-sky-500/25 text-[11px] font-mono text-sky-300">
            {(routing.directDomains?.length || 0) + (routing.directCidrs?.length || 0)} 项
          </span>
        </div>

        <div className="space-y-2">
          <div className="flex gap-2">
            <input
              type="text"
              value={directInput}
              onChange={(e) => setDirectInput(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === 'Enter') {
                  e.preventDefault();
                  submitDirect();
                }
              }}
              placeholder="例如: direct.example.com 或 203.0.113.0/24"
              className="flex-1 bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-xs font-mono text-slate-100 placeholder:text-slate-500 focus:outline-none focus:border-sky-500/60"
            />
            <button
              type="button"
              onClick={submitDirect}
              disabled={!directInput.trim()}
              className="inline-flex items-center gap-1 px-3.5 py-2 rounded-xl bg-sky-500 hover:bg-sky-400 text-slate-950 font-semibold text-xs disabled:opacity-40 shrink-0"
            >
              <Plus className="w-3.5 h-3.5" />
              <span>添加</span>
            </button>
          </div>
          {directPreview && (
            <div className="text-[11px] font-mono text-sky-300/90 flex items-center gap-1.5">
              <CheckCircle2 className="w-3 h-3" />
              <span>
                将添加{directPreview.kind === 'cidr' ? ' IP/CIDR 白名单' : '直出域名白名单'}:{' '}
                <strong>{directPreview.value}</strong>
              </span>
            </div>
          )}
        </div>

        <div className="flex flex-wrap gap-1.5 min-h-[44px] items-start">
          {(routing.directDomains || []).map((d) => (
            <span
              key={`dd-${d}`}
              className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-sky-500/10 border border-sky-500/30 text-xs font-mono text-sky-200"
            >
              <span>{d}</span>
              <button
                type="button"
                onClick={() => onRemoveRule('direct', 'domain', d)}
                className="text-sky-300/70 hover:text-rose-300"
                title="移除白名单"
              >
                <Trash2 className="w-3 h-3" />
              </button>
            </span>
          ))}
          {(routing.directCidrs || []).map((c) => (
            <span
              key={`dc-${c}`}
              className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-cyan-500/10 border border-cyan-500/30 text-xs font-mono text-cyan-200"
            >
              <span>CIDR {c}</span>
              <button
                type="button"
                onClick={() => onRemoveRule('direct', 'cidr', c)}
                className="text-cyan-300/70 hover:text-rose-300"
                title="移除白名单"
              >
                <Trash2 className="w-3 h-3" />
              </button>
            </span>
          ))}
          {(routing.directDomains?.length || 0) + (routing.directCidrs?.length || 0) === 0 && (
            <span className="text-xs font-mono text-slate-500">暂无强制直出白名单</span>
          )}
        </div>
      </div>
    </div>
  );
};

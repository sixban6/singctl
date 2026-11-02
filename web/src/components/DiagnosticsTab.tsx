import React, { useState } from 'react';
import { WarpDiagnoseResponse, ServerStatusResponse, ReturnSummary } from '../types';
import { api } from '../api';
import { useToast } from './Toast';
import { Globe, Activity, RefreshCw, CheckCircle2, AlertTriangle, ArrowUpDown, ChevronDown, ChevronUp } from 'lucide-react';

interface DiagnosticsTabProps {
  status: ServerStatusResponse | null;
}

export const DiagnosticsTab: React.FC<DiagnosticsTabProps> = ({ status }) => {
  const { success, error } = useToast();
  const [warpData, setWarpData] = useState<WarpDiagnoseResponse | null>(null);
  const [testingWarp, setTestingWarp] = useState(false);

  const [returnSummary, setReturnSummary] = useState<ReturnSummary | null>(null);
  const [testingReturn, setTestingReturn] = useState(false);
  const [showHops, setShowHops] = useState<{ [key: number]: boolean }>({});

  const runWarpDiagnose = async () => {
    setTestingWarp(true);
    try {
      const res = await api.getWarpDiagnose();
      setWarpData(res);
      if (res.connected) {
        success('WARP 出口探测成功');
      } else {
        error('WARP 出口未连接或未响应');
      }
    } catch (err: any) {
      error(err.message || '探测失败');
    } finally {
      setTestingWarp(false);
    }
  };

  const runReturnTest = async () => {
    setTestingReturn(true);
    try {
      const res = await api.getNetReturn();
      setReturnSummary(res);
      success('三网回程测试完成');
    } catch (err: any) {
      error(err.message || '回程测试失败');
    } finally {
      setTestingReturn(false);
    }
  };

  const toggleHop = (idx: number) => {
    setShowHops((prev) => ({ ...prev, [idx]: !prev[idx] }));
  };

  const formatRTT = (ns?: number) => {
    if (!ns || ns <= 0) return '-';
    const ms = ns / 1_000_000;
    return `${ms.toFixed(1)} ms`;
  };

  return (
    <div className="space-y-6">
      {/* Return Route Test Card */}
      <div className="p-6 rounded-2xl glass-card">
        <div className="flex items-center gap-2 text-emerald-400 text-xs font-semibold uppercase tracking-wider mb-2">
          <ArrowUpDown className="w-3.5 h-3.5" />
          <span>三网回程质量诊断</span>
        </div>
        <h2 className="text-xl font-bold text-white tracking-tight">三网回程线路探测</h2>
        <p className="text-xs text-slate-400 mt-1 max-w-2xl">
          并发向中国电信 (163/CN2)、中国联通 (4837/9929)、中国移动 (CMI/CMIN2) 国内核心节点发起轻量路由追踪与 Ping 丢包探测
        </p>

        <div className="mt-5">
          <button
            onClick={runReturnTest}
            disabled={testingReturn}
            className="flex items-center gap-2 px-5 py-2.5 rounded-xl bg-emerald-500 hover:bg-emerald-600 text-slate-950 font-semibold text-xs transition-all shadow-lg shadow-emerald-500/20 disabled:opacity-50"
          >
            <RefreshCw className={`w-4 h-4 ${testingReturn ? 'animate-spin' : ''}`} />
            <span>{testingReturn ? '正在探测三网骨干节点线路...' : '开始三网回程测试'}</span>
          </button>
        </div>

        {/* Return Test Results */}
        {returnSummary && (
          <div className="mt-6 space-y-4 animate-fade-in">
            {/* Overall Summary Banner */}
            <div className="p-4 rounded-xl bg-slate-950/80 border border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-2">
              <div className="flex items-center gap-2 text-xs font-mono">
                <span className="text-slate-400">探测源 IP:</span>
                <span className="text-slate-200 font-semibold">{returnSummary.server_ip || returnSummary.serverIp || '本机公网'}</span>
              </div>
              <div className="text-xs font-semibold text-emerald-400 font-mono bg-emerald-500/10 px-3 py-1 rounded-lg border border-emerald-500/20">
                {returnSummary.summary}
              </div>
            </div>

            {/* Target Results Grid */}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
              {returnSummary.results.map((r, i) => {
                const loss = r.loss_rate ?? r.lossRate ?? 0;
                const rtt = r.avg_rtt ?? r.avgRtt;
                const lineName = r.route_name || r.routeName || '普通回程';
                const hops = r.key_hops || r.keyHops;

                return (
                  <div key={i} className="p-4 rounded-xl bg-slate-950/60 border border-slate-800/80 flex flex-col justify-between">
                    <div>
                      <div className="flex items-center justify-between mb-2">
                        <span className="text-xs font-bold text-white">{r.name}</span>
                        <span className="text-[10px] px-2 py-0.5 rounded-md bg-slate-900 text-slate-300 font-mono border border-slate-800">
                          {r.city}
                        </span>
                      </div>

                      <div className="space-y-1.5 text-xs font-mono mt-3">
                        <div className="flex justify-between">
                          <span className="text-slate-500">骨干识别</span>
                          <span className="text-emerald-400 font-semibold">{lineName}</span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-slate-500">平均延迟</span>
                          <span className="text-slate-200">{formatRTT(rtt)}</span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-slate-500">丢包率</span>
                          <span className={loss > 5 ? 'text-rose-400 font-bold' : 'text-slate-300'}>
                            {loss.toFixed(1)}%
                          </span>
                        </div>
                      </div>
                    </div>

                    {hops && hops.length > 0 && (
                      <div className="mt-3 pt-2.5 border-t border-slate-800/60">
                        <button
                          onClick={() => toggleHop(i)}
                          className="text-[11px] text-slate-400 hover:text-white flex items-center gap-1 font-mono transition-colors"
                        >
                          <span>沿途跳点 ({hops.length})</span>
                          {showHops[i] ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
                        </button>
                        {showHops[i] && (
                          <div className="mt-2 text-[10px] font-mono text-slate-400 space-y-1 bg-slate-900/60 p-2 rounded-lg">
                            {hops.map((h, k) => (
                              <div key={k} className="truncate">• {h}</div>
                            ))}
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          </div>
        )}
      </div>

      {/* WARP Exit Test Banner */}
      <div className="p-6 rounded-2xl glass-card">
        <div className="flex items-center gap-2 text-blue-400 text-xs font-semibold uppercase tracking-wider mb-2">
          <Activity className="w-3.5 h-3.5" />
          <span>WARP 出口实测</span>
        </div>
        <h3 className="text-xl font-bold text-white tracking-tight">Cloudflare WARP 出口探测</h3>
        <p className="text-xs text-slate-400 mt-1 max-w-2xl">
          模拟流量经由本地 wireproxy SOCKS5 代理出海，检测落地的 Anycast IPv4/IPv6 与流媒体解锁定位
        </p>

        <div className="mt-5">
          <button
            onClick={runWarpDiagnose}
            disabled={testingWarp}
            className="flex items-center gap-2 px-4 py-2 rounded-xl bg-slate-900 hover:bg-slate-800 border border-slate-700/60 text-slate-200 text-xs font-semibold transition-all disabled:opacity-50"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${testingWarp ? 'animate-spin text-blue-400' : ''}`} />
            <span>{testingWarp ? '正在测试出口...' : '探测 WARP 落地 IP'}</span>
          </button>
        </div>

        {/* WARP Results Grid */}
        {warpData && (
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 mt-5 animate-fade-in">
            <div className="p-4 rounded-xl bg-slate-950/70 border border-slate-800">
              <span className="text-xs text-slate-400">WARP 状态</span>
              <div className="flex items-center gap-2 mt-2">
                {warpData.connected ? (
                  <>
                    <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                    <span className="text-sm font-bold text-emerald-400 font-mono">已连通 (ON)</span>
                  </>
                ) : (
                  <>
                    <AlertTriangle className="w-4 h-4 text-rose-400" />
                    <span className="text-sm font-bold text-rose-400 font-mono">未连通</span>
                  </>
                )}
              </div>
            </div>

            <div className="p-4 rounded-xl bg-slate-950/70 border border-slate-800">
              <span className="text-xs text-slate-400">出口公网 IP</span>
              <div className="text-sm font-bold text-white font-mono mt-2 truncate">
                {warpData.ip || '未知'}
              </div>
            </div>

            <div className="p-4 rounded-xl bg-slate-950/70 border border-slate-800">
              <span className="text-xs text-slate-400">出口地理位置</span>
              <div className="text-sm font-bold text-white font-mono mt-2">
                {warpData.loc ? `${warpData.loc} (区域代码)` : '未知'}
              </div>
            </div>

            <div className="p-4 rounded-xl bg-slate-950/70 border border-slate-800">
              <span className="text-xs text-slate-400">Trace 延时</span>
              <div className="text-sm font-bold text-emerald-400 font-mono mt-2">
                {warpData.latencyMs ? `${warpData.latencyMs} ms` : '-'}
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

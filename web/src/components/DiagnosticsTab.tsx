import React, { useState } from 'react';
import { WarpDiagnoseResponse, ServerStatusResponse, ReturnSummary, MediaUnlockReport } from '../types';
import { api } from '../api';
import { useToast } from './Toast';
import { Globe, Activity, RefreshCw, CheckCircle2, AlertTriangle, ArrowUpDown, ChevronDown, ChevronUp, Sparkles, Tv, Bot, Search, PlaySquare, ShieldCheck } from 'lucide-react';

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

  const [unlockData, setUnlockData] = useState<MediaUnlockReport | null>(null);
  const [testingUnlock, setTestingUnlock] = useState(false);

  const runUnlockDiagnose = async () => {
    setTestingUnlock(true);
    try {
      const res = await api.getMediaUnlock();
      setUnlockData(res);
      success('全球边缘多点出口画像与服务连通性探测完成');
    } catch (err: any) {
      error(err.message || '解锁探测失败');
    } finally {
      setTestingUnlock(false);
    }
  };

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

      {/* Streaming & AI Unlock Card */}
      <div className="p-6 rounded-2xl glass-card">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-4 border-b border-slate-800">
          <div>
            <div className="flex items-center gap-2 text-purple-400 text-xs font-semibold uppercase tracking-wider mb-1">
              <Sparkles className="w-3.5 h-3.5" />
              <span>原生流媒体与 AI 出口解锁能力</span>
            </div>
            <h3 className="text-xl font-bold text-white tracking-tight">海外流媒体与 AI 关键服务解锁画像</h3>
            <p className="text-xs text-slate-400 mt-0.5">
              实测当前落地出口对 ChatGPT / OpenAI、Netflix、YouTube Premium、Disney+ 以及 Google 搜索风控状态
            </p>
          </div>

          <button
            onClick={runUnlockDiagnose}
            disabled={testingUnlock}
            className="flex items-center gap-2 px-4 py-2 rounded-xl bg-purple-500/20 hover:bg-purple-500/30 border border-purple-500/30 text-purple-200 text-xs font-semibold self-start sm:self-auto transition-all disabled:opacity-50"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${testingUnlock ? 'animate-spin' : ''}`} />
            <span>{testingUnlock ? '正在深度探测海外服务...' : '开始解锁测试'}</span>
          </button>
        </div>

        {/* Unlock Results */}
        {unlockData ? (
          <div className="mt-5 space-y-4 animate-fade-in">
            <div className="text-[11px] font-mono text-slate-400 flex items-center justify-between">
              <span>探测时间: {unlockData.testedAt}</span>
              {unlockData.proxyUsed && (
                <span className="text-purple-300">出口链路: {unlockData.proxyUsed}</span>
              )}
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3.5">
              {/* OpenAI */}
              <div className="p-4 rounded-xl bg-slate-950/70 border border-slate-800 flex items-start gap-3">
                <div className="p-2 rounded-lg bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                  <Bot className="w-5 h-5" />
                </div>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center justify-between">
                    <span className="font-semibold text-sm text-white">ChatGPT / OpenAI</span>
                    {unlockData.openai.status === 'unlocked' ? (
                      <span className="px-2 py-0.5 rounded-full bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 text-[11px] font-semibold">
                        完整解锁 {unlockData.openai.region ? `(${unlockData.openai.region})` : ''}
                      </span>
                    ) : (
                      <span className="px-2 py-0.5 rounded-full bg-rose-500/20 text-rose-300 border border-rose-500/30 text-[11px] font-semibold">
                        受阻/风控
                      </span>
                    )}
                  </div>
                  <p className="text-xs text-slate-400 mt-1">{unlockData.openai.details || '测试完成'}</p>
                </div>
              </div>

              {/* Netflix */}
              <div className="p-4 rounded-xl bg-slate-950/70 border border-slate-800 flex items-start gap-3">
                <div className="p-2 rounded-lg bg-rose-500/10 text-rose-400 border border-rose-500/20">
                  <Tv className="w-5 h-5" />
                </div>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center justify-between">
                    <span className="font-semibold text-sm text-white">Netflix (奈飞)</span>
                    {unlockData.netflix.status === 'unlocked' ? (
                      <span className="px-2 py-0.5 rounded-full bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 text-[11px] font-semibold">
                        完整解锁 (含非自制)
                      </span>
                    ) : unlockData.netflix.status === 'partially_unlocked' ? (
                      <span className="px-2 py-0.5 rounded-full bg-amber-500/20 text-amber-300 border border-amber-500/30 text-[11px] font-semibold">
                        仅自制剧
                      </span>
                    ) : (
                      <span className="px-2 py-0.5 rounded-full bg-rose-500/20 text-rose-300 border border-rose-500/30 text-[11px] font-semibold">
                        未解锁
                      </span>
                    )}
                  </div>
                  <p className="text-xs text-slate-400 mt-1">{unlockData.netflix.details || '测试完成'}</p>
                </div>
              </div>

              {/* YouTube Premium */}
              <div className="p-4 rounded-xl bg-slate-950/70 border border-slate-800 flex items-start gap-3">
                <div className="p-2 rounded-lg bg-red-500/10 text-red-400 border border-red-500/20">
                  <PlaySquare className="w-5 h-5" />
                </div>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center justify-between">
                    <span className="font-semibold text-sm text-white">YouTube Premium</span>
                    {unlockData.youtube.status === 'unlocked' ? (
                      <span className="px-2 py-0.5 rounded-full bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 text-[11px] font-semibold">
                        原生支持
                      </span>
                    ) : (
                      <span className="px-2 py-0.5 rounded-full bg-rose-500/20 text-rose-300 border border-rose-500/30 text-[11px] font-semibold">
                        地区受限
                      </span>
                    )}
                  </div>
                  <p className="text-xs text-slate-400 mt-1">{unlockData.youtube.details || '测试完成'}</p>
                </div>
              </div>

              {/* Disney+ */}
              <div className="p-4 rounded-xl bg-slate-950/70 border border-slate-800 flex items-start gap-3">
                <div className="p-2 rounded-lg bg-blue-500/10 text-blue-400 border border-blue-500/20">
                  <Globe className="w-5 h-5" />
                </div>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center justify-between">
                    <span className="font-semibold text-sm text-white">Disney+</span>
                    {unlockData.disney.status === 'unlocked' ? (
                      <span className="px-2 py-0.5 rounded-full bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 text-[11px] font-semibold">
                        支持访问
                      </span>
                    ) : (
                      <span className="px-2 py-0.5 rounded-full bg-rose-500/20 text-rose-300 border border-rose-500/30 text-[11px] font-semibold">
                        拦截受阻
                      </span>
                    )}
                  </div>
                  <p className="text-xs text-slate-400 mt-1">{unlockData.disney.details || '测试完成'}</p>
                </div>
              </div>

              {/* Google Search */}
              <div className="p-4 rounded-xl bg-slate-950/70 border border-slate-800 flex items-start gap-3">
                <div className="p-2 rounded-lg bg-amber-500/10 text-amber-400 border border-amber-500/20">
                  <Search className="w-5 h-5" />
                </div>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center justify-between">
                    <span className="font-semibold text-sm text-white">Google 搜索人机风控</span>
                    {unlockData.google.status === 'unlocked' ? (
                      <span className="px-2 py-0.5 rounded-full bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 text-[11px] font-semibold">
                        绿灯 (无验证码)
                      </span>
                    ) : (
                      <span className="px-2 py-0.5 rounded-full bg-amber-500/20 text-amber-300 border border-amber-500/30 text-[11px] font-semibold">
                        需人机验证
                      </span>
                    )}
                  </div>
                  <p className="text-xs text-slate-400 mt-1">{unlockData.google.details || '测试完成'}</p>
                </div>
              </div>
            </div>
          </div>
        ) : (
          <div className="mt-5 p-6 rounded-xl bg-slate-950/40 border border-slate-800/80 text-center">
            <Sparkles className="w-8 h-8 text-purple-400 mx-auto mb-2 opacity-70" />
            <div className="text-sm font-semibold text-slate-300">尚未执行流媒体与 AI 出口解锁诊断</div>
            <p className="text-xs text-slate-500 mt-1 max-w-md mx-auto">
              点击上方【开始解锁测试】按钮，后台将并发检测节点或 WARP 落地出口对 ChatGPT、Netflix、Disney+ 等主流海外平台的访问能力。
            </p>
          </div>
        )}
      </div>
    </div>
  );
};

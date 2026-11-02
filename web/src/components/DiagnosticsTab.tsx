import React, { useState } from 'react';
import { WarpDiagnoseResponse, ServerStatusResponse, ReturnSummary, MediaUnlockReport, ExitProfile } from '../types';
import { api } from '../api';
import { useToast } from './Toast';
import { Globe, Activity, RefreshCw, CheckCircle2, AlertTriangle, ArrowUpDown, ChevronDown, ChevronUp, Sparkles, Tv, Bot, Search, PlaySquare, ShieldCheck, Shield } from 'lucide-react';

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

  const renderExitProfile = (profile: ExitProfile, isWarp: boolean) => {
    return (
      <div className="p-4 rounded-xl bg-slate-950/70 border border-slate-800 space-y-3">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-2.5 border-b border-slate-800/80">
          <div className="flex items-center gap-2">
            <div className={`p-1.5 rounded-lg ${isWarp ? 'bg-amber-500/10 text-amber-400 border border-amber-500/20' : 'bg-blue-500/10 text-blue-400 border border-blue-500/20'}`}>
              {isWarp ? <Shield className="w-4 h-4" /> : <Globe className="w-4 h-4" />}
            </div>
            <div>
              <span className="font-bold text-white text-xs sm:text-sm">{profile.name}</span>
              {profile.exitIP && (
                <span className="ml-2 font-mono text-[11px] text-slate-400">
                  IP: <span className="text-slate-200">{profile.exitIP}</span> {profile.exitLoc ? `(${profile.exitLoc})` : ''}
                </span>
              )}
            </div>
          </div>

          <div>
            {profile.available ? (
              <span className="px-2 py-0.5 rounded-full bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 text-[11px] font-semibold">
                在线就绪
              </span>
            ) : (
              <span className="px-2 py-0.5 rounded-full bg-slate-800 text-slate-400 border border-slate-700 text-[11px] font-semibold">
                未启用 / 未启动
              </span>
            )}
          </div>
        </div>

        {!profile.available ? (
          <div className="py-3 text-center text-xs text-slate-400 font-mono">
            {profile.errorReason || '该出口未启动或端口未监听'}
          </div>
        ) : (
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2.5">
            {/* OpenAI */}
            <div className="p-2.5 rounded-lg bg-slate-900/60 border border-slate-800/80 flex items-start gap-2">
              <Bot className="w-4 h-4 text-emerald-400 mt-0.5 shrink-0" />
              <div className="flex-1 min-w-0">
                <div className="flex items-center justify-between">
                  <span className="font-semibold text-xs text-white">ChatGPT / OpenAI</span>
                  {profile.openai.status === 'unlocked' ? (
                    <span className="text-[10px] font-semibold text-emerald-400 font-mono">
                      解锁 {profile.openai.region ? `[${profile.openai.region}]` : ''}
                    </span>
                  ) : (
                    <span className="text-[10px] font-semibold text-rose-400 font-mono">受限</span>
                  )}
                </div>
                <p className="text-[11px] text-slate-400 truncate mt-0.5">{profile.openai.details || '-'}</p>
              </div>
            </div>

            {/* Netflix */}
            <div className="p-2.5 rounded-lg bg-slate-900/60 border border-slate-800/80 flex items-start gap-2">
              <Tv className="w-4 h-4 text-rose-400 mt-0.5 shrink-0" />
              <div className="flex-1 min-w-0">
                <div className="flex items-center justify-between">
                  <span className="font-semibold text-xs text-white">Netflix (奈飞)</span>
                  {profile.netflix.status === 'unlocked' ? (
                    <span className="text-[10px] font-semibold text-emerald-400 font-mono">完整解锁</span>
                  ) : profile.netflix.status === 'partially_unlocked' ? (
                    <span className="text-[10px] font-semibold text-amber-400 font-mono">自制剧</span>
                  ) : (
                    <span className="text-[10px] font-semibold text-rose-400 font-mono">未解锁</span>
                  )}
                </div>
                <p className="text-[11px] text-slate-400 truncate mt-0.5">{profile.netflix.details || '-'}</p>
              </div>
            </div>

            {/* YouTube Premium */}
            <div className="p-2.5 rounded-lg bg-slate-900/60 border border-slate-800/80 flex items-start gap-2">
              <PlaySquare className="w-4 h-4 text-red-400 mt-0.5 shrink-0" />
              <div className="flex-1 min-w-0">
                <div className="flex items-center justify-between">
                  <span className="font-semibold text-xs text-white">YouTube Premium</span>
                  {profile.youtube.status === 'unlocked' ? (
                    <span className="text-[10px] font-semibold text-emerald-400 font-mono">原生支持</span>
                  ) : (
                    <span className="text-[10px] font-semibold text-rose-400 font-mono">受限</span>
                  )}
                </div>
                <p className="text-[11px] text-slate-400 truncate mt-0.5">{profile.youtube.details || '-'}</p>
              </div>
            </div>

            {/* Disney+ */}
            <div className="p-2.5 rounded-lg bg-slate-900/60 border border-slate-800/80 flex items-start gap-2">
              <Globe className="w-4 h-4 text-blue-400 mt-0.5 shrink-0" />
              <div className="flex-1 min-w-0">
                <div className="flex items-center justify-between">
                  <span className="font-semibold text-xs text-white">Disney+</span>
                  {profile.disney.status === 'unlocked' ? (
                    <span className="text-[10px] font-semibold text-emerald-400 font-mono">支持访问</span>
                  ) : (
                    <span className="text-[10px] font-semibold text-rose-400 font-mono">受阻</span>
                  )}
                </div>
                <p className="text-[11px] text-slate-400 truncate mt-0.5">{profile.disney.details || '-'}</p>
              </div>
            </div>

            {/* Google Search */}
            <div className="p-2.5 rounded-lg bg-slate-900/60 border border-slate-800/80 flex items-start gap-2">
              <Search className="w-4 h-4 text-amber-400 mt-0.5 shrink-0" />
              <div className="flex-1 min-w-0">
                <div className="flex items-center justify-between">
                  <span className="font-semibold text-xs text-white">Google 搜索</span>
                  {profile.google.status === 'unlocked' ? (
                    <span className="text-[10px] font-semibold text-emerald-400 font-mono">无验证码</span>
                  ) : (
                    <span className="text-[10px] font-semibold text-amber-400 font-mono">需验证码</span>
                  )}
                </div>
                <p className="text-[11px] text-slate-400 truncate mt-0.5">{profile.google.details || '-'}</p>
              </div>
            </div>
          </div>
        )}
      </div>
    );
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
              <span className="text-purple-300">双出口链路对比 (VPS 原生 vs WARP 分流)</span>
            </div>

            {/* 1. VPS 原生直连出口 */}
            {renderExitProfile(unlockData.direct, false)}

            {/* 2. WARP 分流出口 */}
            {renderExitProfile(unlockData.warp, true)}
          </div>
        ) : (
          <div className="mt-5 p-6 rounded-xl bg-slate-950/40 border border-slate-800/80 text-center">
            <Sparkles className="w-8 h-8 text-purple-400 mx-auto mb-2 opacity-70" />
            <div className="text-sm font-semibold text-slate-300">尚未执行流媒体与 AI 出口解锁诊断</div>
            <p className="text-xs text-slate-500 mt-1 max-w-md mx-auto">
              点击上方【开始解锁测试】按钮，后台将并发测试【VPS 原生出口】与【WARP 分流出口】对 ChatGPT、Netflix、Disney+ 等主流海外平台的访问与抗风控能力。
            </p>
          </div>
        )}
      </div>
    </div>
  );
};

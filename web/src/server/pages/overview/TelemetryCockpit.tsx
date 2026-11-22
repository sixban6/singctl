import React, { useState } from 'react';
import { TabKey, TelemetrySnapshot } from '../../types';
import { formatBytes } from '../../../ui';
import { Activity, ArrowDown, ArrowRight, ArrowUp, Globe, ShieldAlert, Split, Zap } from 'lucide-react';

function formatRate(bps: number): string {
  const bits = Math.max(0, bps) * 8;
  if (bits >= 1_000_000_000) return `${(bits / 1_000_000_000).toFixed(2)} Gbps`;
  if (bits >= 1_000_000) return `${(bits / 1_000_000).toFixed(2)} Mbps`;
  if (bits >= 1_000) return `${(bits / 1_000).toFixed(1)} Kbps`;
  return `${Math.round(bits)} bps`;
}

interface TelemetryCockpitProps {
  telemetry: TelemetrySnapshot | null;
  telemetryStreamLive: boolean;
  enablingTelemetry: boolean;
  switchingDomain: string | null;
  onEnableTelemetry: () => void;
  onQuickSwitchDomain: (domain: string, currentOutbound: string) => void;
  onNavigate: (tab: TabKey) => void;
}

export const TelemetryCockpit: React.FC<TelemetryCockpitProps> = ({
  telemetry,
  telemetryStreamLive,
  enablingTelemetry,
  switchingDomain,
  onEnableTelemetry,
  onQuickSwitchDomain,
  onNavigate,
}) => {
  const [sniffTab, setSniffTab] = useState<'ip' | 'subnet' | 'country'>('ip');

  if (!telemetry) return null;

  if (!telemetry.enabled) {
    return (
      <div className="p-5 rounded-2xl glass-card border border-emerald-500/25 bg-gradient-to-r from-emerald-950/20 via-slate-900/60 to-slate-900/60 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div className="space-y-1">
          <div className="flex items-center gap-2 text-emerald-400 text-xs font-semibold">
            <Activity className="w-4 h-4" />
            <span>实时流量与双出口分流驾驶舱</span>
          </div>
          <p className="text-xs text-slate-300">
            当前旧版配置尚未注入本地回环遥测接口（<code className="text-emerald-300 font-mono">127.0.0.1:9099</code>
            ，仅本机鉴权访问，零公网暴露）。开启过程<strong>不会更改任何现有节点 UUID、密码或订阅链接</strong>。
          </p>
        </div>
        <button
          onClick={onEnableTelemetry}
          disabled={enablingTelemetry}
          className="flex items-center gap-1.5 px-4 py-2.5 rounded-xl bg-emerald-500 hover:bg-emerald-600 text-slate-950 font-semibold text-xs transition-all shrink-0 disabled:opacity-50"
        >
          <Zap className={`w-3.5 h-3.5 ${enablingTelemetry ? 'animate-spin' : ''}`} />
          <span>{enablingTelemetry ? '正在无损注入配置...' : '一键无损开启实时遥测'}</span>
        </button>
      </div>
    );
  }

  // Sparkline geometry calculation
  const rawHistory = telemetry.history && telemetry.history.length > 0 ? telemetry.history : [];
  const chartPoints =
    rawHistory.length >= 2
      ? rawHistory
      : rawHistory.length === 1
      ? [rawHistory[0], rawHistory[0]]
      : [
          { time: '', upBps: 0, downBps: 0 },
          { time: '', upBps: 0, downBps: 0 },
        ];
  const peakBps = Math.max(
    12_500, // floor at 100 Kbps for calm baseline
    ...chartPoints.map((p) => Math.max(p.upBps, p.downBps)),
  );
  const svgW = 320;
  const svgH = 88;
  const toXY = (idx: number, bps: number) => {
    const x = (idx / (chartPoints.length - 1)) * svgW;
    const y = svgH - 6 - Math.min(1, Math.max(0, bps / peakBps)) * (svgH - 14);
    return { x: Number(x.toFixed(1)), y: Number(y.toFixed(1)) };
  };
  const downCoords = chartPoints.map((p, i) => toXY(i, p.downBps));
  const upCoords = chartPoints.map((p, i) => toXY(i, p.upBps));
  const downLine = downCoords.map((c) => `${c.x},${c.y}`).join(' ');
  const upLine = upCoords.map((c) => `${c.x},${c.y}`).join(' ');
  const downArea = `M 0,${svgH - 6} L ${downCoords.map((c) => `${c.x},${c.y}`).join(' L ')} L ${svgW},${svgH - 6} Z`;
  const upArea = `M 0,${svgH - 6} L ${upCoords.map((c) => `${c.x},${c.y}`).join(' L ')} L ${svgW},${svgH - 6} Z`;

  // Protocol & Outbound ratios
  const protoByteTotal = (telemetry.protocols?.hy2Bytes || 0) + (telemetry.protocols?.realityBytes || 0);
  const protoConnTotal = (telemetry.protocols?.hy2Connections || 0) + (telemetry.protocols?.realityConnections || 0);
  const hy2Ratio =
    protoByteTotal > 0
      ? Math.round(((telemetry.protocols?.hy2Bytes || 0) / protoByteTotal) * 100)
      : protoConnTotal > 0
      ? Math.round(((telemetry.protocols?.hy2Connections || 0) / protoConnTotal) * 100)
      : 0;
  const realityRatio = protoByteTotal > 0 || protoConnTotal > 0 ? 100 - hy2Ratio : 0;

  const outByteTotal = (telemetry.outbounds?.directBytes || 0) + (telemetry.outbounds?.warpBytes || 0);
  const outConnTotal = (telemetry.outbounds?.directConnections || 0) + (telemetry.outbounds?.warpConnections || 0);
  const directRatio =
    outByteTotal > 0
      ? Math.round(((telemetry.outbounds?.directBytes || 0) / outByteTotal) * 100)
      : outConnTotal > 0
      ? Math.round(((telemetry.outbounds?.directConnections || 0) / outConnTotal) * 100)
      : 0;
  const warpRatio = outByteTotal > 0 || outConnTotal > 0 ? 100 - directRatio : 0;

  return (
    <div className="p-5 rounded-2xl glass-card space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-2 pb-3 border-b border-slate-800/80">
        <div className="flex items-center gap-2.5">
          <div className="p-1.5 rounded-xl bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
            <Activity className="w-4 h-4" />
          </div>
          <div>
            <h3 className="text-sm font-semibold text-white flex items-center gap-2">
              <span>实时流量与双出口分流驾驶舱</span>
              <span
                className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-mono border ${
                  telemetry.reachable
                    ? 'bg-emerald-500/10 text-emerald-300 border-emerald-500/25'
                    : 'bg-amber-500/10 text-amber-300 border-amber-500/25'
                }`}
              >
                <span
                  className={`w-1.5 h-1.5 rounded-full ${
                    telemetry.reachable ? 'bg-emerald-400 animate-ping' : 'bg-amber-400'
                  }`}
                ></span>
                {telemetry.reachable ? (telemetryStreamLive ? 'LIVE SSE' : 'POLLING') : 'WAITING'}
              </span>
            </h3>
            <p className="text-[11px] text-slate-400">
              终端同等视图可运行 <code className="text-emerald-300 font-mono">singctl sr top</code>
            </p>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2 text-xs font-mono">
          <span className="px-2.5 py-1 rounded-lg bg-slate-950/70 border border-slate-800 text-slate-300">
            活跃连接: <strong className="text-white">{telemetry.activeConnections}</strong>
          </span>
          <span className="px-2.5 py-1 rounded-lg bg-slate-950/70 border border-slate-800 text-sky-300">
            ↑ 累计 {formatBytes(telemetry.uploadTotal)}
          </span>
          <span className="px-2.5 py-1 rounded-lg bg-slate-950/70 border border-slate-800 text-emerald-300">
            ↓ 累计 {formatBytes(telemetry.downloadTotal)}
          </span>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Column 1: Throughput & Waveform */}
        <div className="p-4 rounded-xl bg-slate-950/50 border border-slate-800/80 flex flex-col justify-between">
          <div className="grid grid-cols-2 gap-3 mb-3">
            <div>
              <div className="flex items-center gap-1 text-[11px] text-slate-400">
                <ArrowDown className="w-3 h-3 text-emerald-400" />
                <span>实时下行速率</span>
              </div>
              <div className="text-lg font-bold font-mono text-emerald-400 mt-0.5">
                {formatRate(telemetry.downBps)}
              </div>
            </div>
            <div>
              <div className="flex items-center gap-1 text-[11px] text-slate-400">
                <ArrowUp className="w-3 h-3 text-sky-400" />
                <span>实时上行速率</span>
              </div>
              <div className="text-lg font-bold font-mono text-sky-400 mt-0.5">
                {formatRate(telemetry.upBps)}
              </div>
            </div>
          </div>

          <div className="relative rounded-lg bg-slate-950/90 border border-slate-900 px-2 pt-2 pb-1 overflow-hidden">
            <svg viewBox={`0 0 ${svgW} ${svgH}`} className="w-full h-20 overflow-visible">
              <defs>
                <linearGradient id="downGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="#10b981" stopOpacity="0.36" />
                  <stop offset="100%" stopColor="#10b981" stopOpacity="0.0" />
                </linearGradient>
                <linearGradient id="upGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="#38bdf8" stopOpacity="0.28" />
                  <stop offset="100%" stopColor="#38bdf8" stopOpacity="0.0" />
                </linearGradient>
              </defs>
              <path d={downArea} fill="url(#downGrad)" />
              <path d={upArea} fill="url(#upGrad)" />
              <polyline
                fill="none"
                stroke="#10b981"
                strokeWidth="2"
                strokeLinecap="round"
                strokeLinejoin="round"
                points={downLine}
              />
              <polyline
                fill="none"
                stroke="#38bdf8"
                strokeWidth="1.5"
                strokeLinecap="round"
                strokeLinejoin="round"
                points={upLine}
              />
            </svg>
            <div className="flex items-center justify-between text-[10px] font-mono text-slate-500 mt-0.5">
              <span>近 {rawHistory.length || 1} 次采样波形</span>
              <span>峰值刻度 {formatRate(peakBps)}</span>
            </div>
          </div>
        </div>

        {/* Column 2: Protocol & Outbound Split Bars */}
        <div className="p-4 rounded-xl bg-slate-950/50 border border-slate-800/80 flex flex-col justify-between space-y-4">
          {/* Inbound Protocol Split */}
          <div>
            <div className="flex items-center justify-between text-xs mb-1.5">
              <span className="text-slate-300 font-medium flex items-center gap-1.5">
                <Zap className="w-3.5 h-3.5 text-emerald-400" />
                入站协议负载
              </span>
              <span className="text-[11px] font-mono text-slate-400">
                HY2 {hy2Ratio}% · Reality {realityRatio}%
              </span>
            </div>
            <div className="w-full h-2.5 bg-slate-900 rounded-full overflow-hidden flex border border-slate-800">
              <div
                className="bg-emerald-500 h-full transition-all duration-300"
                style={{ width: `${hy2Ratio}%` }}
              />
              <div
                className="bg-purple-500 h-full transition-all duration-300"
                style={{ width: `${realityRatio}%` }}
              />
            </div>
            <div className="flex items-center justify-between text-[11px] font-mono text-slate-400 mt-1.5">
              <span className="text-emerald-300">
                HY2: {telemetry.protocols.hy2Connections} 连 ({formatBytes(telemetry.protocols.hy2Bytes)})
              </span>
              <span className="text-purple-300">
                Reality: {telemetry.protocols.realityConnections} 连 ({formatBytes(telemetry.protocols.realityBytes)})
              </span>
            </div>
          </div>

          {/* Outbound Split Routing */}
          <div className="pt-3 border-t border-slate-800/70">
            <div className="flex items-center justify-between text-xs mb-1.5">
              <span className="text-slate-300 font-medium flex items-center gap-1.5">
                <Split className="w-3.5 h-3.5 text-sky-400" />
                双出口智能分流
              </span>
              <span className="text-[11px] font-mono text-slate-400">
                直出 {directRatio}% · WARP {warpRatio}%
              </span>
            </div>
            <div className="w-full h-2.5 bg-slate-900 rounded-full overflow-hidden flex border border-slate-800">
              <div
                className="bg-sky-500 h-full transition-all duration-300"
                style={{ width: `${directRatio}%` }}
              />
              <div
                className="bg-amber-500 h-full transition-all duration-300"
                style={{ width: `${warpRatio}%` }}
              />
            </div>
            <div className="flex items-center justify-between text-[11px] font-mono text-slate-400 mt-1.5">
              <span className="text-sky-300">
                原生直出: {telemetry.outbounds.directConnections} 连 ({formatBytes(telemetry.outbounds.directBytes)})
              </span>
              <span className="text-amber-300">
                WARP: {telemetry.outbounds.warpConnections} 连 ({formatBytes(telemetry.outbounds.warpBytes)})
              </span>
            </div>
          </div>
        </div>

        {/* Column 3: Active Target Domains */}
        <div className="p-4 rounded-xl bg-slate-950/50 border border-slate-800/80 flex flex-col">
          <div className="flex items-center justify-between text-xs mb-2">
            <span className="text-slate-300 font-medium flex items-center gap-1.5">
              <Globe className="w-3.5 h-3.5 text-purple-400" />
              活跃目标域名分流追踪 (Top {telemetry.topDomains?.length || 0})
            </span>
            <button
              type="button"
              onClick={() => onNavigate('warp')}
              className="text-[11px] font-medium text-amber-400 hover:text-amber-300 flex items-center gap-1 transition-colors"
            >
              <span>WARP 分流中心</span>
              <ArrowRight className="w-3 h-3" />
            </button>
          </div>
          {!telemetry.topDomains || telemetry.topDomains.length === 0 ? (
            <div className="flex-1 flex items-center justify-center text-center text-xs text-slate-500 py-6 font-mono">
              当前暂无活跃代理会话，客户端发起流量后将实时呈现分流去向
            </div>
          ) : (
            <div className="space-y-1.5 max-h-40 overflow-y-auto pr-1">
              {telemetry.topDomains.map((d) => {
                const isWarp = d.outbound === 'WARP';
                const isBusy = switchingDomain === d.domain;
                return (
                  <div
                    key={d.domain}
                    className="px-2.5 py-1.5 rounded-lg bg-slate-900/70 border border-slate-800/70 flex items-center justify-between gap-2 text-[11px] font-mono"
                  >
                    <span className="text-slate-200 truncate" title={d.domain}>
                      {d.domain}
                    </span>
                    <div className="flex items-center gap-1.5 shrink-0">
                      <span
                        className={`px-1.5 py-0.5 rounded text-[10px] ${
                          isWarp
                            ? 'bg-amber-500/15 text-amber-300 border border-amber-500/25'
                            : 'bg-sky-500/15 text-sky-300 border border-sky-500/25'
                        }`}
                      >
                        {isWarp ? 'WARP' : '直出'}
                      </span>
                      <span className="text-slate-400">{formatBytes(d.bytes)}</span>
                      {d.domain !== 'unknown' && (
                        <button
                          type="button"
                          disabled={isBusy}
                          onClick={() => onQuickSwitchDomain(d.domain, d.outbound)}
                          className={`px-1.5 py-0.5 rounded text-[10px] font-sans font-medium border transition-colors disabled:opacity-45 ${
                            isWarp
                              ? 'bg-sky-500/10 hover:bg-sky-500/20 text-sky-300 border-sky-500/30'
                              : 'bg-amber-500/10 hover:bg-amber-500/20 text-amber-300 border-amber-500/30'
                          }`}
                          title={isWarp ? `将 ${d.domain} 切回原生直出` : `将 ${d.domain} 一键切走 WARP`}
                        >
                          {isBusy ? '切换中' : isWarp ? '↩ 切直出' : '⚡ 切 WARP'}
                        </button>
                      )}
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      </div>

      {/* External Active Sniffing & Probing Tracker */}
      <div className="mt-4 p-4 rounded-xl bg-slate-950/50 border border-slate-800/80">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2.5 mb-3">
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-xs font-medium text-slate-200 flex items-center gap-1.5">
              <ShieldAlert className="w-3.5 h-3.5 text-rose-400" />
              集群活跃嗅探与探测追踪
            </span>
            <span className="px-2 py-0.5 rounded-md bg-slate-900 border border-slate-800 text-[10px] font-mono text-slate-400">
              已排除合法代理用户 · 嗅探源 {telemetry.sniffing?.totalSniffIPs || 0} IP /{' '}
              {telemetry.sniffing?.totalSubnets || 0} 网段 / {telemetry.sniffing?.totalCountries || 0} 国
            </span>
          </div>

          <div className="flex flex-wrap items-center gap-1.5">
            <div className="inline-flex rounded-lg bg-slate-900/90 p-0.5 border border-slate-800 text-[11px]">
              <button
                type="button"
                onClick={() => setSniffTab('ip')}
                className={`px-2.5 py-1 rounded-md font-medium transition-all ${
                  sniffTab === 'ip'
                    ? 'bg-rose-500/20 text-rose-300 border border-rose-500/30'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                活跃嗅探 IP ({telemetry.sniffing?.topIPs?.length || 0})
              </button>
              <button
                type="button"
                onClick={() => setSniffTab('subnet')}
                className={`px-2.5 py-1 rounded-md font-medium transition-all ${
                  sniffTab === 'subnet'
                    ? 'bg-amber-500/20 text-amber-300 border border-amber-500/30'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                活跃嗅探 IP段 ({telemetry.sniffing?.topSubnets?.length || 0})
              </button>
              <button
                type="button"
                onClick={() => setSniffTab('country')}
                className={`px-2.5 py-1 rounded-md font-medium transition-all ${
                  sniffTab === 'country'
                    ? 'bg-indigo-500/20 text-indigo-300 border border-indigo-500/30'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                活跃嗅探国 ({telemetry.sniffing?.topCountries?.length || 0})
              </button>
            </div>

            <button
              type="button"
              onClick={() => onNavigate('security')}
              className="px-2.5 py-1 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-800 text-[11px] text-emerald-400 flex items-center gap-1 transition-colors"
            >
              <span>分主机查看全部与拉黑</span>
              <ArrowRight className="w-3 h-3" />
            </button>
          </div>
        </div>

        {sniffTab === 'ip' && (
          <>
            {!telemetry.sniffing?.topIPs || telemetry.sniffing.topIPs.length === 0 ? (
              <div className="text-center text-xs text-slate-500 py-4 font-mono">
                当前暂无外部异常嗅探 IP，防火墙与伪装层静默守护中
              </div>
            ) : (
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-2">
                {telemetry.sniffing.topIPs.slice(0, 12).map((item) => (
                  <div
                    key={item.ip}
                    className="px-3 py-2 rounded-lg bg-slate-900/70 border border-slate-800/80 flex flex-col justify-between gap-1 text-[11px] font-mono"
                  >
                    <div className="flex items-center justify-between gap-1.5">
                      <span className="text-slate-100 font-semibold truncate" title={item.ip}>
                        {item.flag ? `${item.flag} ` : ''}
                        {item.ip}
                      </span>
                      <span
                        className={`px-1.5 py-0.5 rounded text-[10px] shrink-0 ${
                          item.status === 'banned'
                            ? 'bg-rose-500/20 text-rose-300 border border-rose-500/30'
                            : 'bg-amber-500/15 text-amber-300 border border-amber-500/25'
                        }`}
                      >
                        {item.status === 'banned' ? '已封禁' : '已伪装回落'}
                      </span>
                    </div>
                    <div className="flex items-center justify-between gap-1 text-[10px] text-slate-400 font-sans">
                      <span className="truncate" title={item.vector}>
                        {item.scannerTag ? `[${item.scannerTag}] ` : ''}
                        {item.vector}
                      </span>
                      <span className="font-mono text-slate-300 shrink-0">{item.hits} 次</span>
                    </div>
                    <div className="flex items-center justify-between gap-1 text-[10px] text-slate-500 pt-0.5 border-t border-slate-800/60">
                      <span className="truncate" title={`开始: ${item.firstSeen || item.lastSeen}`}>
                        始: {(item.firstSeen || item.lastSeen || '').slice(5)}
                      </span>
                      <span className="text-emerald-400/90 truncate" title={`最近: ${item.lastSeen}`}>
                        近: {(item.lastSeen || '').slice(5)}
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </>
        )}

        {sniffTab === 'subnet' && (
          <>
            {!telemetry.sniffing?.topSubnets || telemetry.sniffing.topSubnets.length === 0 ? (
              <div className="text-center text-xs text-slate-500 py-4 font-mono">
                当前暂无聚集性 /24 嗅探网段
              </div>
            ) : (
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-2">
                {telemetry.sniffing.topSubnets.slice(0, 12).map((sub) => (
                  <div
                    key={sub.cidr}
                    className="px-3 py-2 rounded-lg bg-slate-900/70 border border-slate-800/80 flex flex-col justify-between gap-1 text-[11px] font-mono"
                  >
                    <div className="flex items-center justify-between gap-1.5">
                      <span className="text-amber-300 font-semibold truncate" title={sub.cidr}>
                        {sub.flag ? `${sub.flag} ` : ''}
                        {sub.cidr}
                      </span>
                      <span className="px-1.5 py-0.5 rounded bg-slate-800 text-slate-200 text-[10px] shrink-0">
                        {sub.uniqueIPs} 个 IP
                      </span>
                    </div>
                    <div className="flex items-center justify-between gap-1 text-[10px] text-slate-400 font-sans">
                      <span className="truncate">
                        {sub.scannerTag || sub.country || sub.isp || '外部探测网段'}
                      </span>
                      <span className="font-mono text-slate-300 shrink-0">累计 {sub.totalHits} 次</span>
                    </div>
                    {(sub.firstSeen || sub.lastSeen) && (
                      <div className="flex items-center justify-between gap-1 text-[10px] text-slate-500 pt-0.5 border-t border-slate-800/60">
                        <span className="truncate">始: {(sub.firstSeen || sub.lastSeen || '').slice(5)}</span>
                        <span className="text-emerald-400/90 truncate">近: {(sub.lastSeen || '').slice(5)}</span>
                      </div>
                    )}
                  </div>
                ))}
              </div>
            )}
          </>
        )}

        {sniffTab === 'country' && (
          <>
            {!telemetry.sniffing?.topCountries || telemetry.sniffing.topCountries.length === 0 ? (
              <div className="text-center text-xs text-slate-500 py-4 font-mono">
                当前暂无外部嗅探国家分布数据
              </div>
            ) : (
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-2">
                {telemetry.sniffing.topCountries.map((c) => (
                  <div
                    key={c.countryCode}
                    className="px-3 py-2 rounded-lg bg-slate-900/70 border border-slate-800/80 flex flex-col justify-between gap-1.5 text-[11px]"
                  >
                    <div className="flex items-center justify-between gap-1.5">
                      <span className="text-slate-100 font-medium truncate">
                        {c.flag ? `${c.flag} ` : ''}
                        {c.country}
                      </span>
                      <span className="font-mono text-indigo-300 font-semibold shrink-0">
                        {c.ratioPercent}%
                      </span>
                    </div>
                    <div className="w-full h-1.5 bg-slate-950 rounded-full overflow-hidden">
                      <div
                        className="bg-indigo-500 h-full rounded-full"
                        style={{ width: `${Math.min(100, Math.max(4, c.ratioPercent))}%` }}
                      />
                    </div>
                    <div className="flex items-center justify-between text-[10px] font-mono text-slate-400">
                      <span>
                        {c.uniqueIPs} 独立 IP ({c.uniqueSubnets} 段)
                      </span>
                      <span>{c.totalHits} 次试探</span>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
};

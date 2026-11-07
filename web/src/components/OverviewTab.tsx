import React, { useEffect, useState } from 'react';
import { ServerStatusResponse, DoctorReport, TelemetrySnapshot } from '../types';
import { api, getBasePath } from '../api';
import { useToast } from './Toast';
import {
  Cpu,
  HardDrive,
  MemoryStick,
  Clock,
  RefreshCw,
  CheckCircle2,
  XCircle,
  ArrowRight,
  Stethoscope,
  AlertTriangle,
  X,
  Activity,
  ArrowDown,
  ArrowUp,
  Zap,
  Globe,
  Split,
  ShieldAlert,
} from 'lucide-react';
import { TabKey } from './Navigation';

interface OverviewTabProps {
  status: ServerStatusResponse | null;
  onRefresh: () => void;
  onNavigate: (tab: TabKey) => void;
}

function formatRate(bps: number): string {
  const bits = Math.max(0, bps) * 8;
  if (bits >= 1_000_000_000) return `${(bits / 1_000_000_000).toFixed(2)} Gbps`;
  if (bits >= 1_000_000) return `${(bits / 1_000_000).toFixed(2)} Mbps`;
  if (bits >= 1_000) return `${(bits / 1_000).toFixed(1)} Kbps`;
  return `${Math.round(bits)} bps`;
}

function formatBytes(bytes: number): string {
  const val = Math.max(0, bytes);
  const KB = 1024;
  const MB = 1024 * KB;
  const GB = 1024 * MB;
  const TB = 1024 * GB;
  if (val >= TB) return `${(val / TB).toFixed(2)} TB`;
  if (val >= GB) return `${(val / GB).toFixed(2)} GB`;
  if (val >= MB) return `${(val / MB).toFixed(1)} MB`;
  if (val >= KB) return `${(val / KB).toFixed(1)} KB`;
  return `${Math.round(val)} B`;
}

export const OverviewTab: React.FC<OverviewTabProps> = ({ status, onRefresh, onNavigate }) => {
  const { success, error } = useToast();
  const [loadingAction, setLoadingAction] = useState<string | null>(null);
  const [doctorReport, setDoctorReport] = useState<DoctorReport | null>(null);
  const [runningDoctor, setRunningDoctor] = useState(false);
  const [showDoctorModal, setShowDoctorModal] = useState(false);

  // Live Telemetry Cockpit state
  const [telemetry, setTelemetry] = useState<TelemetrySnapshot | null>(null);
  const [telemetryStreamLive, setTelemetryStreamLive] = useState(false);
  const [enablingTelemetry, setEnablingTelemetry] = useState(false);
  const [sniffTab, setSniffTab] = useState<'ip' | 'subnet' | 'country'>('ip');

  useEffect(() => {
    let cancelled = false;
    let es: EventSource | null = null;
    let fallbackTimer: ReturnType<typeof setInterval> | null = null;

    const fetchOnce = async () => {
      try {
        const snap = await api.getTelemetrySnapshot();
        if (!cancelled) {
          setTelemetry(snap);
        }
        return snap;
      } catch {
        return null;
      }
    };

    const startStream = () => {
      try {
        const streamUrl = `${getBasePath()}/api/server/telemetry/stream`;
        es = new EventSource(streamUrl, { withCredentials: true });
        es.onopen = () => {
          if (!cancelled) setTelemetryStreamLive(true);
        };
        es.onmessage = (ev) => {
          if (cancelled) return;
          try {
            const parsed: TelemetrySnapshot = JSON.parse(ev.data);
            setTelemetry(parsed);
            setTelemetryStreamLive(true);
          } catch {
            // ignore malformed frame
          }
        };
        es.onerror = () => {
          if (cancelled) return;
          setTelemetryStreamLive(false);
          if (es) {
            es.close();
            es = null;
          }
          if (!fallbackTimer) {
            fallbackTimer = setInterval(() => {
              fetchOnce();
            }, 2500);
          }
        };
      } catch {
        if (!fallbackTimer) {
          fallbackTimer = setInterval(() => {
            fetchOnce();
          }, 2500);
        }
      }
    };

    fetchOnce().then((snap) => {
      if (!cancelled && snap?.enabled) {
        startStream();
      }
    });

    return () => {
      cancelled = true;
      if (es) es.close();
      if (fallbackTimer) clearInterval(fallbackTimer);
    };
  }, [telemetry?.enabled]);

  const handleEnableTelemetry = async () => {
    setEnablingTelemetry(true);
    try {
      const res = await api.enableTelemetry();
      success(res.message || '实时遥测已开启');
      setTelemetry(res.snapshot);
    } catch (err: any) {
      error(err.message || '开启实时流量遥测失败');
    } finally {
      setEnablingTelemetry(false);
    }
  };

  const handleRunDoctor = async () => {
    setRunningDoctor(true);
    try {
      const res = await api.getDoctorReport();
      setDoctorReport(res);
      setShowDoctorModal(true);
      if (res.score >= 90) {
        success(`健康体检完成！健康评分: ${res.score}/100`);
      } else {
        error(`健康体检完成，评分 ${res.score}/100，存在需关注项`);
      }
    } catch (err: any) {
      error(err.message || '体检执行失败');
    } finally {
      setRunningDoctor(false);
    }
  };

  const handleQuickRestart = async (service: string) => {
    setLoadingAction(service);
    try {
      await api.serviceAction(service, 'restart');
      success(`服务 ${service} 重启成功`);
      setTimeout(onRefresh, 1000);
    } catch (err: any) {
      error(err.message || '重启失败');
    } finally {
      setLoadingAction(null);
    }
  };

  const handleRestartAll = async () => {
    if (!window.confirm('确定要一键重启所有核心服务吗 (Caddy, sing-box, SubHub, WARP)？')) return;
    setLoadingAction('all');
    try {
      await api.serviceAction('all', 'restart');
      success('全部核心服务已发送重启指令');
      setTimeout(onRefresh, 1500);
    } catch (err: any) {
      error(err.message || '操作失败');
    } finally {
      setLoadingAction(null);
    }
  };

  const services = [
    {
      key: 'singbox',
      name: 'sing-box 核心',
      desc: 'Reality & Hysteria2 代理中继',
      detail: status?.services?.singbox,
      ports: '52021, 8443',
    },
    {
      key: 'caddy',
      name: 'Caddy 网关',
      desc: '自动申请 TLS 证书与隐蔽路径反代',
      detail: status?.services?.caddy,
      ports: '80, 443',
    },
    {
      key: 'substore',
      name: 'SubHub 订阅中枢',
      desc: 'Go 原生多协议节点转换与聚合分发',
      detail: status?.services?.substore,
      ports: '3001',
    },
    {
      key: 'warp',
      name: 'Cloudflare WARP',
      desc: '解锁海外流媒体与落地原生分流',
      detail: status?.services?.warp,
      ports: 'SOCKS5: 40000',
    },
  ];

  const memPercentNum = parseFloat(status?.system?.memUsagePercent?.replace('%', '') || '0');
  const diskPercentNum = parseFloat(status?.system?.diskPercent?.replace('%', '') || '0');

  // Sparkline geometry calculation
  const rawHistory = telemetry?.history && telemetry.history.length > 0 ? telemetry.history : [];
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
    ...chartPoints.map((p) => Math.max(p.upBps, p.downBps))
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
  const protoByteTotal = (telemetry?.protocols?.hy2Bytes || 0) + (telemetry?.protocols?.realityBytes || 0);
  const protoConnTotal =
    (telemetry?.protocols?.hy2Connections || 0) + (telemetry?.protocols?.realityConnections || 0);
  const hy2Ratio =
    protoByteTotal > 0
      ? Math.round(((telemetry?.protocols?.hy2Bytes || 0) / protoByteTotal) * 100)
      : protoConnTotal > 0
      ? Math.round(((telemetry?.protocols?.hy2Connections || 0) / protoConnTotal) * 100)
      : 0;
  const realityRatio = protoByteTotal > 0 || protoConnTotal > 0 ? 100 - hy2Ratio : 0;

  const outByteTotal = (telemetry?.outbounds?.directBytes || 0) + (telemetry?.outbounds?.warpBytes || 0);
  const outConnTotal =
    (telemetry?.outbounds?.directConnections || 0) + (telemetry?.outbounds?.warpConnections || 0);
  const directRatio =
    outByteTotal > 0
      ? Math.round(((telemetry?.outbounds?.directBytes || 0) / outByteTotal) * 100)
      : outConnTotal > 0
      ? Math.round(((telemetry?.outbounds?.directConnections || 0) / outConnTotal) * 100)
      : 0;
  const warpRatio = outByteTotal > 0 || outConnTotal > 0 ? 100 - directRatio : 0;

  return (
    <div className="space-y-6">
      {/* Top Banner Actions */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 p-5 rounded-2xl glass-card">
        <div>
          <h2 className="text-lg font-semibold text-white tracking-tight flex items-center gap-2">
            <span>节点集群总览与健康状态</span>
            <span className="w-2.5 h-2.5 rounded-full bg-emerald-500 animate-pulse"></span>
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            监控守护四大核心组件，支持实时流量分流观测、独立运维控制与资源指标
          </p>
        </div>
        <div className="flex items-center gap-2.5 w-full sm:w-auto">
          <button
            onClick={handleRunDoctor}
            disabled={runningDoctor}
            className="flex-1 sm:flex-initial flex items-center justify-center gap-1.5 px-3.5 py-2 rounded-xl bg-purple-500/20 hover:bg-purple-500/30 border border-purple-500/30 text-xs font-semibold text-purple-200 transition-colors disabled:opacity-50 shadow-lg shadow-purple-500/10"
          >
            <Stethoscope className={`w-3.5 h-3.5 ${runningDoctor ? 'animate-spin' : ''}`} />
            <span>{runningDoctor ? '体检诊断中...' : '全链路体检'}</span>
          </button>
          <button
            onClick={onRefresh}
            className="flex-1 sm:flex-initial flex items-center justify-center gap-1.5 px-3.5 py-2 rounded-xl bg-slate-900 hover:bg-slate-800 border border-slate-700/60 text-xs font-medium text-slate-200 transition-colors"
          >
            <RefreshCw className="w-3.5 h-3.5" />
            <span>刷新</span>
          </button>
          <button
            onClick={handleRestartAll}
            disabled={loadingAction === 'all'}
            className="flex-1 sm:flex-initial flex items-center justify-center gap-1.5 px-4 py-2 rounded-xl bg-rose-500/10 hover:bg-rose-500/20 border border-rose-500/30 text-rose-300 text-xs font-semibold transition-all disabled:opacity-50"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loadingAction === 'all' ? 'animate-spin' : ''}`} />
            <span>一键重启全服务</span>
          </button>
        </div>
      </div>

      {/* Live Telemetry Cockpit */}
      {telemetry && !telemetry.enabled ? (
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
            onClick={handleEnableTelemetry}
            disabled={enablingTelemetry}
            className="flex items-center gap-1.5 px-4 py-2.5 rounded-xl bg-emerald-500 hover:bg-emerald-600 text-slate-950 font-semibold text-xs transition-all shrink-0 disabled:opacity-50"
          >
            <Zap className={`w-3.5 h-3.5 ${enablingTelemetry ? 'animate-spin' : ''}`} />
            <span>{enablingTelemetry ? '正在无损注入配置...' : '一键无损开启实时遥测'}</span>
          </button>
        </div>
      ) : telemetry?.enabled ? (
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
              </div>
              {!telemetry.topDomains || telemetry.topDomains.length === 0 ? (
                <div className="flex-1 flex items-center justify-center text-center text-xs text-slate-500 py-6 font-mono">
                  当前暂无活跃代理会话，客户端发起流量后将实时呈现分流去向
                </div>
              ) : (
                <div className="space-y-1.5 max-h-40 overflow-y-auto pr-1">
                  {telemetry.topDomains.map((d) => (
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
                            d.outbound === 'WARP'
                              ? 'bg-amber-500/15 text-amber-300 border border-amber-500/25'
                              : 'bg-sky-500/15 text-sky-300 border border-sky-500/25'
                          }`}
                        >
                          {d.outbound === 'WARP' ? 'WARP' : '直出'}
                        </span>
                        <span className="text-slate-400">{formatBytes(d.bytes)}</span>
                      </div>
                    </div>
                  ))}
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
                          <span>{c.uniqueIPs} 独立 IP ({c.uniqueSubnets} 段)</span>
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
      ) : null}

      {/* Services Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {services.map((s) => {
          const isRunning = !!s.detail?.running;
          const isLoading = loadingAction === s.key;
          return (
            <div key={s.key} className="p-4 rounded-2xl glass-card glass-card-hover flex flex-col justify-between">
              <div>
                <div className="flex items-center justify-between">
                  <span className="text-sm font-semibold text-white">{s.name}</span>
                  <div
                    className={`flex items-center gap-1 px-2 py-0.5 rounded-full text-[11px] font-medium border ${
                      isRunning
                        ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20'
                        : 'bg-rose-500/10 text-rose-400 border-rose-500/20'
                    }`}
                  >
                    {isRunning ? (
                      <>
                        <CheckCircle2 className="w-3 h-3" />
                        <span>运行中</span>
                      </>
                    ) : (
                      <>
                        <XCircle className="w-3 h-3" />
                        <span>已停止</span>
                      </>
                    )}
                  </div>
                </div>
                <p className="text-xs text-slate-400 mt-1">{s.desc}</p>
                <div className="mt-3 text-xs font-mono text-slate-300 space-y-1 bg-slate-950/40 p-2.5 rounded-xl border border-slate-800/60">
                  <div className="flex justify-between">
                    <span className="text-slate-500">端口</span>
                    <span>{s.ports}</span>
                  </div>
                  {s.detail?.pid && (
                    <div className="flex justify-between">
                      <span className="text-slate-500">PID</span>
                      <span>{s.detail.pid}</span>
                    </div>
                  )}
                  {s.detail?.uptime && (
                    <div className="flex justify-between">
                      <span className="text-slate-500">在线时长</span>
                      <span>{s.detail.uptime}</span>
                    </div>
                  )}
                </div>
              </div>

              <div className="mt-4 pt-3 border-t border-slate-800 flex items-center justify-between">
                <button
                  onClick={() => onNavigate('services')}
                  className="text-xs text-slate-400 hover:text-emerald-400 flex items-center gap-1 font-medium transition-colors"
                >
                  <span>详细管控</span>
                  <ArrowRight className="w-3 h-3" />
                </button>
                <button
                  onClick={() => handleQuickRestart(s.key)}
                  disabled={isLoading}
                  className="p-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-slate-300 hover:text-white border border-slate-700/60 transition-all disabled:opacity-50"
                  title="快速重启此服务"
                >
                  <RefreshCw className={`w-3.5 h-3.5 ${isLoading ? 'animate-spin text-emerald-400' : ''}`} />
                </button>
              </div>
            </div>
          );
        })}
      </div>

      {/* Hardware Metrics Dashboard */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {/* CPU Load */}
        <div className="p-5 rounded-2xl glass-card">
          <div className="flex items-center gap-2.5 text-slate-300 mb-3">
            <div className="p-2 rounded-xl bg-blue-500/10 text-blue-400 border border-blue-500/20">
              <Cpu className="w-4 h-4" />
            </div>
            <div>
              <h3 className="text-xs font-medium text-slate-400">系统 CPU 负载 (LoadAvg)</h3>
              <p className="text-base font-bold text-white font-mono mt-0.5">
                {status?.system?.loadAvg || '0.00, 0.00, 0.00'}
              </p>
            </div>
          </div>
          <div className="grid grid-cols-3 gap-2 mt-4 text-center">
            <div className="bg-slate-900/60 p-2 rounded-xl border border-slate-800">
              <div className="text-[10px] text-slate-400">1 分钟</div>
              <div className="text-xs font-mono font-semibold text-slate-200 mt-0.5">
                {status?.system?.load1 || '0.00'}
              </div>
            </div>
            <div className="bg-slate-900/60 p-2 rounded-xl border border-slate-800">
              <div className="text-[10px] text-slate-400">5 分钟</div>
              <div className="text-xs font-mono font-semibold text-slate-200 mt-0.5">
                {status?.system?.load5 || '0.00'}
              </div>
            </div>
            <div className="bg-slate-900/60 p-2 rounded-xl border border-slate-800">
              <div className="text-[10px] text-slate-400">15 分钟</div>
              <div className="text-xs font-mono font-semibold text-slate-200 mt-0.5">
                {status?.system?.load15 || '0.00'}
              </div>
            </div>
          </div>
        </div>

        {/* RAM Usage */}
        <div className="p-5 rounded-2xl glass-card">
          <div className="flex items-center gap-2.5 text-slate-300 mb-3">
            <div className="p-2 rounded-xl bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
              <MemoryStick className="w-4 h-4" />
            </div>
            <div className="flex-1">
              <div className="flex items-center justify-between">
                <h3 className="text-xs font-medium text-slate-400">物理内存占用</h3>
                <span className="text-xs font-bold text-emerald-400 font-mono">
                  {status?.system?.memUsagePercent || '0%'}
                </span>
              </div>
              <p className="text-base font-bold text-white font-mono mt-0.5">
                {status?.system?.memUsedMB || 0} MB / {status?.system?.memTotalMB || 0} MB
              </p>
            </div>
          </div>
          <div className="w-full bg-slate-900 h-2.5 rounded-full overflow-hidden mt-4 border border-slate-800">
            <div
              className="bg-emerald-500 h-full rounded-full transition-all duration-500"
              style={{ width: `${Math.min(memPercentNum, 100)}%` }}
            ></div>
          </div>
        </div>

        {/* Disk Space & Uptime */}
        <div className="p-5 rounded-2xl glass-card">
          <div className="flex items-center gap-2.5 text-slate-300 mb-3">
            <div className="p-2 rounded-xl bg-purple-500/10 text-purple-400 border border-purple-500/20">
              <HardDrive className="w-4 h-4" />
            </div>
            <div className="flex-1">
              <div className="flex items-center justify-between">
                <h3 className="text-xs font-medium text-slate-400">根系统盘容量</h3>
                <span className="text-xs font-bold text-purple-400 font-mono">
                  {status?.system?.diskPercent || '0%'}
                </span>
              </div>
              <p className="text-base font-bold text-white font-mono mt-0.5">
                {status?.system?.diskUsed || '0G'} / {status?.system?.diskTotal || '0G'}
              </p>
            </div>
          </div>
          <div className="w-full bg-slate-900 h-2.5 rounded-full overflow-hidden mt-4 border border-slate-800">
            <div
              className="bg-purple-500 h-full rounded-full transition-all duration-500"
              style={{ width: `${Math.min(diskPercentNum, 100)}%` }}
            ></div>
          </div>
          <div className="mt-4 pt-3 border-t border-slate-800/80 flex items-center justify-between text-xs font-mono text-slate-400">
            <div className="flex items-center gap-1.5">
              <Clock className="w-3.5 h-3.5 text-slate-500" />
              <span>系统运行</span>
            </div>
            <span className="text-slate-200">{status?.system?.uptime || '正常'}</span>
          </div>
        </div>
      </div>

      {/* Doctor Health Report Modal */}
      {showDoctorModal && doctorReport && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm animate-fade-in">
          <div className="w-full max-w-2xl bg-slate-900 border border-slate-800 rounded-2xl shadow-2xl overflow-hidden max-h-[90vh] flex flex-col">
            {/* Modal Header */}
            <div className="p-5 border-b border-slate-800 flex items-center justify-between bg-slate-950/60">
              <div className="flex items-center gap-2.5">
                <div className="p-2 rounded-xl bg-purple-500/10 text-purple-400 border border-purple-500/20">
                  <Stethoscope className="w-5 h-5" />
                </div>
                <div>
                  <h3 className="font-bold text-white text-base flex items-center gap-2">
                    <span>全链路健康体检报告</span>
                    <span
                      className={`text-xs px-2.5 py-0.5 rounded-full font-mono font-semibold border ${
                        doctorReport.score >= 90
                          ? 'bg-emerald-500/20 text-emerald-300 border-emerald-500/30'
                          : doctorReport.score >= 60
                          ? 'bg-amber-500/20 text-amber-300 border-amber-500/30'
                          : 'bg-rose-500/20 text-rose-300 border-rose-500/30'
                      }`}
                    >
                      综合评分: {doctorReport.score} / 100
                    </span>
                  </h3>
                  <p className="text-xs text-slate-400 mt-0.5">体检时间: {doctorReport.checkedAt}</p>
                </div>
              </div>
              <button
                onClick={() => setShowDoctorModal(false)}
                className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition-colors"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Modal Body */}
            <div className="p-5 overflow-y-auto space-y-4">
              <div
                className={`p-3.5 rounded-xl border text-xs leading-relaxed ${
                  doctorReport.score >= 90
                    ? 'bg-emerald-950/30 border-emerald-500/30 text-emerald-200'
                    : doctorReport.score >= 60
                    ? 'bg-amber-950/30 border-amber-500/30 text-amber-200'
                    : 'bg-rose-950/30 border-rose-500/30 text-rose-200'
                }`}
              >
                {doctorReport.summary}
              </div>

              <div className="space-y-2">
                {doctorReport.items.map((item, idx) => (
                  <div
                    key={idx}
                    className="p-3 rounded-xl bg-slate-950/60 border border-slate-800/80 flex items-start justify-between gap-3 text-xs"
                  >
                    <div className="flex-1">
                      <div className="flex items-center gap-2 font-medium text-slate-200">
                        {item.status === 'ok' ? (
                          <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                        ) : item.status === 'warn' ? (
                          <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0" />
                        ) : (
                          <XCircle className="w-4 h-4 text-rose-400 shrink-0" />
                        )}
                        <span className="font-semibold text-white">{item.name}</span>
                      </div>
                      <p className="text-slate-300 font-mono mt-1 text-[11px] pl-6">{item.summary}</p>
                      {item.detail && (
                        <p className="text-slate-500 text-[11px] mt-0.5 pl-6">{item.detail}</p>
                      )}
                    </div>

                    <span
                      className={`text-[10px] uppercase font-mono px-2 py-0.5 rounded-md border shrink-0 ${
                        item.status === 'ok'
                          ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20'
                          : item.status === 'warn'
                          ? 'bg-amber-500/10 text-amber-400 border-amber-500/20'
                          : 'bg-rose-500/10 text-rose-400 border-rose-500/20'
                      }`}
                    >
                      {item.status === 'ok' ? '正常' : item.status === 'warn' ? '建议优化' : '异常'}
                    </span>
                  </div>
                ))}
              </div>
            </div>

            {/* Modal Footer */}
            <div className="p-4 border-t border-slate-800 bg-slate-950/40 flex items-center justify-between">
              <span className="text-xs text-slate-500">
                支持在终端执行: <code className="text-purple-300 font-mono">singctl sr doctor</code>
              </span>
              <button
                onClick={() => setShowDoctorModal(false)}
                className="px-4 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-xs font-semibold text-white transition-colors"
              >
                关闭体检报告
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

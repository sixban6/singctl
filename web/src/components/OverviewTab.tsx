import React, { useEffect, useState } from 'react';
import { ServerStatusResponse, DoctorReport, TelemetrySnapshot } from '../types';
import { api, getBasePath } from '../api';
import {
  Badge,
  Button,
  ConfirmDialog,
  PageHeader,
  SectionCard,
  SegmentedTabs,
  SlideDrawer,
  StatusDot,
  useToast,
} from '../ui';
import { TabKey } from '../App';
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
  Activity,
  ArrowDown,
  ArrowUp,
  Zap,
  Globe,
  Split,
  ShieldAlert,
} from 'lucide-react';

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
  const [confirmRestartAll, setConfirmRestartAll] = useState(false);

  const [doctorReport, setDoctorReport] = useState<DoctorReport | null>(null);
  const [runningDoctor, setRunningDoctor] = useState(false);
  const [showDoctorDrawer, setShowDoctorDrawer] = useState(false);

  const [telemetry, setTelemetry] = useState<TelemetrySnapshot | null>(null);
  const [telemetryStreamLive, setTelemetryStreamLive] = useState(false);
  const [enablingTelemetry, setEnablingTelemetry] = useState(false);
  const [sniffTab, setSniffTab] = useState<'ip' | 'subnet' | 'country'>('ip');
  const [switchingDomain, setSwitchingDomain] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    let es: EventSource | null = null;
    let fallbackTimer: ReturnType<typeof setInterval> | null = null;

    const fetchOnce = async () => {
      try {
        const snap = await api.getTelemetrySnapshot();
        if (!cancelled) setTelemetry(snap);
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
            // ignore
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
            fallbackTimer = setInterval(fetchOnce, 2500);
          }
        };
      } catch {
        if (!fallbackTimer) {
          fallbackTimer = setInterval(fetchOnce, 2500);
        }
      }
    };

    fetchOnce().then((snap) => {
      if (!cancelled && snap?.enabled) startStream();
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
    } catch (err: unknown) {
      error(err instanceof Error ? err.message : '开启实时流量遥测失败');
    } finally {
      setEnablingTelemetry(false);
    }
  };

  const handleRunDoctor = async () => {
    setRunningDoctor(true);
    try {
      const res = await api.getDoctorReport();
      setDoctorReport(res);
      setShowDoctorDrawer(true);
      if (res.score >= 90) {
        success(`健康体检完成！健康评分: ${res.score}/100`);
      } else {
        error(`健康体检完成，评分 ${res.score}/100，存在需关注项`);
      }
    } catch (err: unknown) {
      error(err instanceof Error ? err.message : '体检执行失败');
    } finally {
      setRunningDoctor(false);
    }
  };

  const handleQuickRestart = async (service: string) => {
    setLoadingAction(service);
    try {
      await api.serviceAction(service, 'restart');
      success(`服务 ${service} 重启成功`);
      window.setTimeout(onRefresh, 1000);
    } catch (err: unknown) {
      error(err instanceof Error ? err.message : '重启失败');
    } finally {
      setLoadingAction(null);
    }
  };

  const handleQuickSwitchDomain = async (domain: string, currentOutbound: string) => {
    if (!domain || domain === 'unknown') return;
    const nextOutbound: 'WARP' | 'DC' = currentOutbound === 'WARP' ? 'DC' : 'WARP';
    setSwitchingDomain(domain);
    try {
      const res = await api.quickSwitchWarpTarget(domain, nextOutbound);
      success(res.message);
      const snap = await api.getTelemetrySnapshot().catch(() => null);
      if (snap) setTelemetry(snap);
    } catch (err: unknown) {
      error(err instanceof Error ? err.message : '切换目标出口失败');
    } finally {
      setSwitchingDomain(null);
    }
  };

  const handleRestartAll = async () => {
    setConfirmRestartAll(false);
    setLoadingAction('all');
    try {
      await api.serviceAction('all', 'restart');
      success('全部核心服务已发送重启指令');
      window.setTimeout(onRefresh, 1500);
    } catch (err: unknown) {
      error(err instanceof Error ? err.message : '操作失败');
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
      key: 'subhub',
      name: 'SubHub 订阅中枢',
      desc: 'Go 原生多协议节点转换与分发',
      detail: status?.services?.subhub,
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
  const peakBps = Math.max(12_500, ...chartPoints.map((p) => Math.max(p.upBps, p.downBps)));
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
    <div className="space-y-5">
      <PageHeader
        title="节点集群总览与健康状态"
        description="实时监控四大核心组件、ACME 证书健康度、双向流量遥测与主机资源指标"
        badge={
          <StatusDot
            tone={status?.services?.singbox?.running && status?.services?.caddy?.running ? 'ok' : 'warn'}
            pulse={Boolean(status?.services?.singbox?.running)}
          />
        }
        actions={
          <div className="flex flex-wrap items-center gap-2">
            <Button
              size="sm"
              variant="secondary"
              loading={runningDoctor}
              icon={<Stethoscope className="w-3.5 h-3.5" />}
              onClick={handleRunDoctor}
            >
              {runningDoctor ? '体检诊断中…' : '全链路体检'}
            </Button>
            <Button
              size="sm"
              variant="secondary"
              icon={<RefreshCw className="w-3.5 h-3.5" />}
              onClick={onRefresh}
            >
              刷新
            </Button>
            <Button
              size="sm"
              variant="danger"
              loading={loadingAction === 'all'}
              icon={<RefreshCw className="w-3.5 h-3.5" />}
              onClick={() => setConfirmRestartAll(true)}
            >
              重启全服务
            </Button>
          </div>
        }
      />

      {/* ACME TLS Certificate Strip */}
      {status?.certs && status.certs.length > 0 && (
        <SectionCard
          title="ACME TLS 证书健康度"
          subtitle="自动巡检节点与订阅域名到期状态"
          icon={<Globe className="w-4 h-4" />}
        >
          <div className="flex flex-wrap items-center gap-2">
            {status.certs.map((cert) => {
              const tone =
                cert.status === 'healthy'
                  ? 'ok'
                  : cert.status === 'expiring'
                  ? 'warn'
                  : cert.status === 'expired'
                  ? 'danger'
                  : 'neutral';
              const text =
                cert.status === 'healthy'
                  ? `剩余 ${cert.daysRemaining} 天`
                  : cert.status === 'expiring'
                  ? `即将到期 (${cert.daysRemaining} 天)`
                  : cert.status === 'expired'
                  ? '已过期'
                  : '待签发/外部反代';
              return (
                <button
                  key={cert.domain}
                  type="button"
                  onClick={() => onNavigate('security')}
                  title={cert.message || ''}
                  className="cursor-pointer"
                >
                  <Badge tone={tone} pulse={cert.status === 'expiring' || cert.status === 'expired'}>
                    <span className="font-mono">{cert.domain}</span>
                    <span className="opacity-80 ml-1">· {text}</span>
                  </Badge>
                </button>
              );
            })}
          </div>
        </SectionCard>
      )}

      {/* Live Telemetry Cockpit */}
      {telemetry && !telemetry.enabled ? (
        <SectionCard>
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
            <div className="space-y-1">
              <div className="flex items-center gap-2 text-accent text-xs font-semibold">
                <Activity className="w-4 h-4" />
                <span>实时流量与双出口分流驾驶舱</span>
              </div>
              <p className="text-xs text-secondary leading-relaxed">
                当前配置尚未启用本地回环遥测（<code className="font-mono text-primary">127.0.0.1:9099</code>
                ）。开启过程不会更改任何现有节点凭据或订阅链接。
              </p>
            </div>
            <Button
              variant="primary"
              loading={enablingTelemetry}
              icon={<Zap className="w-3.5 h-3.5" />}
              onClick={handleEnableTelemetry}
            >
              一键无损开启实时遥测
            </Button>
          </div>
        </SectionCard>
      ) : telemetry?.enabled ? (
        <SectionCard
          title="实时流量与双出口分流驾驶舱"
          subtitle={
            <span>
              终端视图可运行 <code className="font-mono text-primary">singctl sr top</code>
            </span>
          }
          icon={<Activity className="w-4 h-4" />}
          badge={
            <Badge tone={telemetry.reachable ? 'ok' : 'warn'} dot pulse={telemetry.reachable}>
              {telemetry.reachable ? (telemetryStreamLive ? 'LIVE SSE' : 'POLLING') : 'WAITING'}
            </Badge>
          }
          actions={
            <div className="flex flex-wrap items-center gap-2 text-xs font-mono tnum">
              <Badge tone="neutral">活跃 {telemetry.activeConnections}</Badge>
              <Badge tone="accent">↑ {formatBytes(telemetry.uploadTotal)}</Badge>
              <Badge tone="ok">↓ {formatBytes(telemetry.downloadTotal)}</Badge>
            </div>
          }
        >
          <div className="space-y-4">
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
              {/* Throughput Waveform */}
              <div className="p-4 rounded-xl bg-surface2/60 border border-subtle flex flex-col justify-between">
                <div className="grid grid-cols-2 gap-3 mb-3">
                  <div>
                    <div className="flex items-center gap-1 text-[11px] text-muted">
                      <ArrowDown className="w-3 h-3 text-emerald-400" />
                      <span>实时下行速率</span>
                    </div>
                    <div className="text-lg font-bold font-mono tnum text-emerald-400 mt-0.5">
                      {formatRate(telemetry.downBps)}
                    </div>
                  </div>
                  <div>
                    <div className="flex items-center gap-1 text-[11px] text-muted">
                      <ArrowUp className="w-3 h-3 text-sky-400" />
                      <span>实时上行速率</span>
                    </div>
                    <div className="text-lg font-bold font-mono tnum text-sky-400 mt-0.5">
                      {formatRate(telemetry.upBps)}
                    </div>
                  </div>
                </div>

                <div className="relative rounded-xl bg-[#070a10] border border-subtle px-2.5 pt-2 pb-1.5 overflow-hidden">
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
                  <div className="flex items-center justify-between text-[10px] font-mono tnum text-slate-400 mt-0.5">
                    <span>近 {rawHistory.length || 1} 次采样</span>
                    <span>峰值刻度 {formatRate(peakBps)}</span>
                  </div>
                </div>
              </div>

              {/* Protocol & Outbound Split Bars */}
              <div className="p-4 rounded-xl bg-surface2/60 border border-subtle flex flex-col justify-between space-y-4">
                <div>
                  <div className="flex items-center justify-between text-xs mb-1.5">
                    <span className="text-primary font-medium flex items-center gap-1.5">
                      <Zap className="w-3.5 h-3.5 text-emerald-400" />
                      入站协议负载
                    </span>
                    <span className="text-[11px] font-mono tnum text-muted">
                      HY2 {hy2Ratio}% · Reality {realityRatio}%
                    </span>
                  </div>
                  <div className="w-full h-2.5 bg-surface1 rounded-full overflow-hidden flex border border-subtle">
                    <div className="bg-emerald-500 h-full transition-all" style={{ width: `${hy2Ratio}%` }} />
                    <div className="bg-purple-500 h-full transition-all" style={{ width: `${realityRatio}%` }} />
                  </div>
                  <div className="flex items-center justify-between text-[11px] font-mono tnum text-muted mt-1.5">
                    <span className="text-emerald-400">
                      HY2: {telemetry.protocols.hy2Connections} 连 ({formatBytes(telemetry.protocols.hy2Bytes)})
                    </span>
                    <span className="text-purple-400">
                      Reality: {telemetry.protocols.realityConnections} 连 (
                      {formatBytes(telemetry.protocols.realityBytes)})
                    </span>
                  </div>
                </div>

                <div className="pt-3 border-t border-subtle">
                  <div className="flex items-center justify-between text-xs mb-1.5">
                    <span className="text-primary font-medium flex items-center gap-1.5">
                      <Split className="w-3.5 h-3.5 text-sky-400" />
                      双出口智能分流
                    </span>
                    <span className="text-[11px] font-mono tnum text-muted">
                      直出 {directRatio}% · WARP {warpRatio}%
                    </span>
                  </div>
                  <div className="w-full h-2.5 bg-surface1 rounded-full overflow-hidden flex border border-subtle">
                    <div className="bg-sky-500 h-full transition-all" style={{ width: `${directRatio}%` }} />
                    <div className="bg-amber-500 h-full transition-all" style={{ width: `${warpRatio}%` }} />
                  </div>
                  <div className="flex items-center justify-between text-[11px] font-mono tnum text-muted mt-1.5">
                    <span className="text-sky-400">
                      直出: {telemetry.outbounds.directConnections} 连 ({formatBytes(telemetry.outbounds.directBytes)})
                    </span>
                    <span className="text-amber-400">
                      WARP: {telemetry.outbounds.warpConnections} 连 ({formatBytes(telemetry.outbounds.warpBytes)})
                    </span>
                  </div>
                </div>
              </div>

              {/* Active Target Domains */}
              <div className="p-4 rounded-xl bg-surface2/60 border border-subtle flex flex-col">
                <div className="flex items-center justify-between text-xs mb-2">
                  <span className="text-primary font-medium flex items-center gap-1.5">
                    <Globe className="w-3.5 h-3.5 text-accent" />
                    活跃目标域名分流 (Top {telemetry.topDomains?.length || 0})
                  </span>
                  <button
                    type="button"
                    onClick={() => onNavigate('warp')}
                    className="text-[11px] font-medium text-accent hover:underline flex items-center gap-1 cursor-pointer"
                  >
                    <span>分流中心</span>
                    <ArrowRight className="w-3 h-3" />
                  </button>
                </div>
                {!telemetry.topDomains || telemetry.topDomains.length === 0 ? (
                  <div className="flex-1 flex items-center justify-center text-center text-xs text-muted py-6 font-mono">
                    暂无活跃代理会话
                  </div>
                ) : (
                  <div className="space-y-1.5 max-h-40 overflow-y-auto pr-1">
                    {telemetry.topDomains.map((d) => {
                      const isWarp = d.outbound === 'WARP';
                      const isBusy = switchingDomain === d.domain;
                      return (
                        <div
                          key={d.domain}
                          className="px-2.5 py-1.5 rounded-lg bg-surface1 border border-subtle flex items-center justify-between gap-2 text-[11px] font-mono"
                        >
                          <span className="text-primary truncate" title={d.domain}>
                            {d.domain}
                          </span>
                          <div className="flex items-center gap-1.5 shrink-0">
                            <Badge tone={isWarp ? 'warn' : 'accent'}>{isWarp ? 'WARP' : '直出'}</Badge>
                            <span className="text-muted tnum">{formatBytes(d.bytes)}</span>
                            {d.domain !== 'unknown' && (
                              <Button
                                size="xs"
                                variant="secondary"
                                loading={isBusy}
                                onClick={() => handleQuickSwitchDomain(d.domain, d.outbound)}
                              >
                                {isWarp ? '切直出' : '切WARP'}
                              </Button>
                            )}
                          </div>
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>
            </div>

            {/* Sniffing Activity Strip */}
            <div className="p-4 rounded-xl bg-surface2/60 border border-subtle space-y-3">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2.5">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="text-xs font-semibold text-primary flex items-center gap-1.5">
                    <ShieldAlert className="w-3.5 h-3.5 text-rose-400" />
                    集群活跃嗅探与探测追踪
                  </span>
                  <Badge tone="neutral">
                    {telemetry.sniffing?.totalSniffIPs || 0} IP / {telemetry.sniffing?.totalSubnets || 0} 网段 /{' '}
                    {telemetry.sniffing?.totalCountries || 0} 国
                  </Badge>
                </div>

                <div className="flex flex-wrap items-center gap-2">
                  <SegmentedTabs
                    value={sniffTab}
                    onChange={(k) => setSniffTab(k as 'ip' | 'subnet' | 'country')}
                    items={[
                      { key: 'ip', label: `嗅探 IP (${telemetry.sniffing?.topIPs?.length || 0})` },
                      { key: 'subnet', label: `IP段 (${telemetry.sniffing?.topSubnets?.length || 0})` },
                      { key: 'country', label: `国家 (${telemetry.sniffing?.topCountries?.length || 0})` },
                    ]}
                  />
                  <Button
                    size="xs"
                    variant="secondary"
                    icon={<ArrowRight className="w-3 h-3" />}
                    onClick={() => onNavigate('security')}
                  >
                    安全中心处置
                  </Button>
                </div>
              </div>

              {sniffTab === 'ip' && (
                <>
                  {!telemetry.sniffing?.topIPs || telemetry.sniffing.topIPs.length === 0 ? (
                    <div className="text-center text-xs text-muted py-4 font-mono">
                      当前暂无外部异常嗅探 IP，防火墙与伪装层静默守护中
                    </div>
                  ) : (
                    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-2">
                      {telemetry.sniffing.topIPs.slice(0, 12).map((item) => (
                        <div
                          key={item.ip}
                          className="px-3 py-2 rounded-xl bg-surface1 border border-subtle flex flex-col justify-between gap-1 text-[11px] font-mono"
                        >
                          <div className="flex items-center justify-between gap-1.5">
                            <span className="text-primary font-semibold truncate">
                              {item.flag ? `${item.flag} ` : ''}
                              {item.ip}
                            </span>
                            <Badge tone={item.status === 'banned' ? 'danger' : 'warn'}>
                              {item.status === 'banned' ? '已封禁' : '已回落'}
                            </Badge>
                          </div>
                          <div className="flex items-center justify-between gap-1 text-[10px] text-secondary font-sans">
                            <span className="truncate">
                              {item.scannerTag ? `[${item.scannerTag}] ` : ''}
                              {item.vector}
                            </span>
                            <span className="font-mono tnum text-muted shrink-0">{item.hits} 次</span>
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
                    <div className="text-center text-xs text-muted py-4 font-mono">当前暂无聚集性 /24 嗅探网段</div>
                  ) : (
                    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-2">
                      {telemetry.sniffing.topSubnets.slice(0, 12).map((subItem) => (
                        <div
                          key={subItem.cidr}
                          className="px-3 py-2 rounded-xl bg-surface1 border border-subtle flex flex-col justify-between gap-1 text-[11px] font-mono"
                        >
                          <div className="flex items-center justify-between gap-1.5">
                            <span className="text-amber-400 font-semibold truncate">
                              {subItem.flag ? `${subItem.flag} ` : ''}
                              {subItem.cidr}
                            </span>
                            <Badge tone="neutral">{subItem.uniqueIPs} IP</Badge>
                          </div>
                          <div className="flex items-center justify-between gap-1 text-[10px] text-muted font-sans">
                            <span className="truncate">
                              {subItem.scannerTag || subItem.country || subItem.isp || '外部探测网段'}
                            </span>
                            <span className="font-mono tnum shrink-0">{subItem.totalHits} 次</span>
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </>
              )}

              {sniffTab === 'country' && (
                <>
                  {!telemetry.sniffing?.topCountries || telemetry.sniffing.topCountries.length === 0 ? (
                    <div className="text-center text-xs text-muted py-4 font-mono">当前暂无国家分布数据</div>
                  ) : (
                    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-2">
                      {telemetry.sniffing.topCountries.map((c) => (
                        <div
                          key={c.countryCode}
                          className="px-3 py-2 rounded-xl bg-surface1 border border-subtle flex flex-col justify-between gap-1.5 text-[11px]"
                        >
                          <div className="flex items-center justify-between gap-1.5">
                            <span className="text-primary font-medium truncate">
                              {c.flag ? `${c.flag} ` : ''}
                              {c.country}
                            </span>
                            <span className="font-mono tnum text-accent font-semibold shrink-0">
                              {c.ratioPercent}%
                            </span>
                          </div>
                          <div className="w-full h-1.5 bg-surface2 rounded-full overflow-hidden">
                            <div
                              className="bg-sky-500 h-full rounded-full"
                              style={{ width: `${Math.min(100, Math.max(4, c.ratioPercent))}%` }}
                            />
                          </div>
                          <div className="flex items-center justify-between text-[10px] font-mono tnum text-muted">
                            <span>
                              {c.uniqueIPs} IP ({c.uniqueSubnets} 段)
                            </span>
                            <span>{c.totalHits} 次</span>
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </>
              )}
            </div>
          </div>
        </SectionCard>
      ) : null}

      {/* 4 Core Services Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {services.map((s) => {
          const isRunning = Boolean(s.detail?.running);
          const isLoading = loadingAction === s.key;
          return (
            <SectionCard
              key={s.key}
              title={s.name}
              badge={
                <Badge tone={isRunning ? 'ok' : 'danger'} dot pulse={isRunning}>
                  {isRunning ? '运行中' : '已停止'}
                </Badge>
              }
            >
              <p className="text-xs text-secondary">{s.desc}</p>
              <div className="mt-3 text-xs font-mono tnum text-secondary space-y-1 bg-surface2/70 p-2.5 rounded-xl border border-subtle">
                <div className="flex justify-between">
                  <span className="text-muted">端口</span>
                  <span className="text-primary">{s.ports}</span>
                </div>
                {s.detail?.pid && (
                  <div className="flex justify-between">
                    <span className="text-muted">PID</span>
                    <span className="text-primary">{s.detail.pid}</span>
                  </div>
                )}
                {s.detail?.uptime && (
                  <div className="flex justify-between">
                    <span className="text-muted">在线时长</span>
                    <span className="text-primary">{s.detail.uptime}</span>
                  </div>
                )}
              </div>

              <div className="mt-3 pt-3 border-t border-subtle flex items-center justify-between">
                <Button
                  size="xs"
                  variant="ghost"
                  icon={<ArrowRight className="w-3 h-3" />}
                  onClick={() => onNavigate('services')}
                >
                  详细管控
                </Button>
                <Button
                  size="xs"
                  variant="secondary"
                  loading={isLoading}
                  title="快速重启此服务"
                  icon={<RefreshCw className="w-3 h-3" />}
                  onClick={() => handleQuickRestart(s.key)}
                >
                  重启
                </Button>
              </div>
            </SectionCard>
          );
        })}
      </div>

      {/* Hardware Metrics */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <SectionCard title="CPU 负载 (LoadAvg)" icon={<Cpu className="w-4 h-4" />}>
          <div className="text-lg font-bold text-primary font-mono tnum">
            {status?.system?.loadAvg || '0.00, 0.00, 0.00'}
          </div>
          <div className="grid grid-cols-3 gap-2 mt-4 text-center">
            {[
              { label: '1 分钟', val: status?.system?.load1 || '0.00' },
              { label: '5 分钟', val: status?.system?.load5 || '0.00' },
              { label: '15 分钟', val: status?.system?.load15 || '0.00' },
            ].map((item) => (
              <div key={item.label} className="bg-surface2/70 p-2 rounded-xl border border-subtle">
                <div className="text-[10px] text-muted">{item.label}</div>
                <div className="text-xs font-mono tnum font-semibold text-primary mt-0.5">{item.val}</div>
              </div>
            ))}
          </div>
        </SectionCard>

        <SectionCard
          title="物理内存占用"
          icon={<MemoryStick className="w-4 h-4" />}
          badge={<Badge tone="accent">{status?.system?.memUsagePercent || '0%'}</Badge>}
        >
          <div className="text-lg font-bold text-primary font-mono tnum">
            {status?.system?.memUsedMB || 0} MB / {status?.system?.memTotalMB || 0} MB
          </div>
          <div className="w-full bg-surface2 h-2.5 rounded-full overflow-hidden mt-4 border border-subtle">
            <div
              className="bg-emerald-500 h-full rounded-full transition-all duration-500"
              style={{ width: `${Math.min(memPercentNum, 100)}%` }}
            />
          </div>
        </SectionCard>

        <SectionCard
          title="根系统盘容量"
          icon={<HardDrive className="w-4 h-4" />}
          badge={<Badge tone="neutral">{status?.system?.diskPercent || '0%'}</Badge>}
        >
          <div className="text-lg font-bold text-primary font-mono tnum">
            {status?.system?.diskUsed || '0G'} / {status?.system?.diskTotal || '0G'}
          </div>
          <div className="w-full bg-surface2 h-2.5 rounded-full overflow-hidden mt-4 border border-subtle">
            <div
              className="bg-sky-500 h-full rounded-full transition-all duration-500"
              style={{ width: `${Math.min(diskPercentNum, 100)}%` }}
            />
          </div>
          <div className="mt-4 pt-3 border-t border-subtle flex items-center justify-between text-xs font-mono text-muted">
            <span className="flex items-center gap-1.5">
              <Clock className="w-3.5 h-3.5" />
              系统运行
            </span>
            <span className="text-primary">{status?.system?.uptime || '正常'}</span>
          </div>
        </SectionCard>
      </div>

      {/* Doctor Health SlideDrawer */}
      <SlideDrawer
        open={Boolean(showDoctorDrawer && doctorReport)}
        onClose={() => setShowDoctorDrawer(false)}
        size="lg"
        title="全链路健康体检报告"
        subtitle={doctorReport ? `体检时间: ${doctorReport.checkedAt}` : ''}
        headerExtra={
          doctorReport ? (
            <Badge
              tone={
                doctorReport.score >= 90 ? 'ok' : doctorReport.score >= 60 ? 'warn' : 'danger'
              }
            >
              综合评分 {doctorReport.score} / 100
            </Badge>
          ) : null
        }
        footer={
          <div className="flex items-center justify-between w-full">
            <span className="text-xs text-muted">
              终端命令行支持 <code className="font-mono text-accent">singctl sr doctor</code>
            </span>
            <Button variant="secondary" onClick={() => setShowDoctorDrawer(false)}>
              关闭报告
            </Button>
          </div>
        }
      >
        {doctorReport && (
          <div className="space-y-4">
            <div
              className={`p-3.5 rounded-xl border text-xs leading-relaxed ${
                doctorReport.score >= 90
                  ? 'bg-emerald-500/10 border-emerald-500/25 text-primary'
                  : doctorReport.score >= 60
                  ? 'bg-amber-500/10 border-amber-500/25 text-primary'
                  : 'bg-rose-500/10 border-rose-500/25 text-primary'
              }`}
            >
              {doctorReport.summary}
            </div>

            <div className="space-y-2.5">
              {doctorReport.items.map((item, idx) => (
                <div
                  key={idx}
                  className="p-3.5 rounded-xl bg-surface2/60 border border-subtle flex items-start justify-between gap-3 text-xs"
                >
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2">
                      {item.status === 'ok' ? (
                        <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                      ) : item.status === 'warn' ? (
                        <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0" />
                      ) : (
                        <XCircle className="w-4 h-4 text-rose-400 shrink-0" />
                      )}
                      <span className="font-semibold text-primary">{item.name}</span>
                    </div>
                    <p className="text-secondary font-mono mt-1 text-[11px] pl-6">{item.summary}</p>
                    {item.detail && <p className="text-muted text-[11px] mt-0.5 pl-6">{item.detail}</p>}
                  </div>
                  <Badge
                    tone={item.status === 'ok' ? 'ok' : item.status === 'warn' ? 'warn' : 'danger'}
                  >
                    {item.status === 'ok' ? '正常' : item.status === 'warn' ? '建议优化' : '异常'}
                  </Badge>
                </div>
              ))}
            </div>
          </div>
        )}
      </SlideDrawer>

      <ConfirmDialog
        open={confirmRestartAll}
        title="确认重启所有核心服务？"
        description="将依次重启 Caddy、sing-box、SubHub 与 WARP，短暂中断现有代理连接约 1~3 秒。"
        confirmText="确认全部重启"
        danger
        loading={loadingAction === 'all'}
        onCancel={() => setConfirmRestartAll(false)}
        onConfirm={handleRestartAll}
      />
    </div>
  );
};

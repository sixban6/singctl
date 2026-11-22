import React, { useEffect, useState } from 'react';
import { ServerStatusResponse, DoctorReport, TelemetrySnapshot } from '../types';
import { api, getBasePath } from '../api';
import { useToast } from '../../ui';
import { RefreshCw, Stethoscope } from 'lucide-react';
import { TabKey } from './Navigation';
import { TelemetryCockpit } from './overview/TelemetryCockpit';
import { CertHealthStrip, CoreServicesSummaryGrid, HardwareMetricsGrid } from './overview/SystemAndServiceCards';
import { DoctorReportModal } from './overview/DoctorReportModal';

export interface OverviewTabProps {
  status: ServerStatusResponse | null;
  onRefresh: () => void;
  onNavigate: (tab: TabKey) => void;
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
  const [switchingDomain, setSwitchingDomain] = useState<string | null>(null);

  const isTelemetryEnabled = Boolean(telemetry?.enabled);

  useEffect(() => {
    let cancelled = false;
    const fetchInitial = async () => {
      try {
        const snap = await api.getTelemetrySnapshot();
        if (!cancelled) {
          setTelemetry(snap);
        }
      } catch {
        // silent
      }
    };
    void fetchInitial();
    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    if (!isTelemetryEnabled) return;
    let cancelled = false;
    let es: EventSource | null = null;
    let fallbackTimer: ReturnType<typeof setInterval> | null = null;

    const stopConnections = (markOffline: boolean) => {
      if (es) {
        es.close();
        es = null;
      }
      if (fallbackTimer) {
        clearInterval(fallbackTimer);
        fallbackTimer = null;
      }
      if (markOffline && !cancelled) {
        setTelemetryStreamLive(false);
      }
    };

    const fetchOnce = async () => {
      try {
        const snap = await api.getTelemetrySnapshot();
        if (!cancelled) {
          setTelemetry(snap);
        }
      } catch {
        // silent
      }
    };

    const startFallbackPolling = () => {
      if (fallbackTimer || cancelled || document.visibilityState !== 'visible') return;
      void fetchOnce();
      fallbackTimer = setInterval(() => {
        if (document.visibilityState === 'visible') {
          void fetchOnce();
        }
      }, 2500);
    };

    const startStream = () => {
      stopConnections(false);
      if (cancelled || document.visibilityState !== 'visible') return;
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
          stopConnections(true);
          startFallbackPolling();
        };
      } catch {
        startFallbackPolling();
      }
    };

    // 标签页切到后台隐藏时断开 SSE 持久推送与兜底轮询；回到前台时立刻重连恢复
    const onVisibilityChange = () => {
      if (document.visibilityState === 'visible') {
        startStream();
      } else {
        stopConnections(true);
      }
    };

    startStream();
    document.addEventListener('visibilitychange', onVisibilityChange);

    return () => {
      cancelled = true;
      document.removeEventListener('visibilitychange', onVisibilityChange);
      stopConnections(false);
    };
  }, [isTelemetryEnabled]);

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

  const handleQuickSwitchDomain = async (domain: string, currentOutbound: string) => {
    if (!domain || domain === 'unknown') return;
    const nextOutbound: 'WARP' | 'DC' = currentOutbound === 'WARP' ? 'DC' : 'WARP';
    setSwitchingDomain(domain);
    try {
      const res = await api.quickSwitchWarpTarget(domain, nextOutbound);
      success(res.message);
      const snap = await api.getTelemetrySnapshot().catch(() => null);
      if (snap) setTelemetry(snap);
    } catch (err: any) {
      error(err.message || '切换目标出口失败');
    } finally {
      setSwitchingDomain(null);
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

      {/* TLS Certificate Health Strip */}
      <CertHealthStrip certs={status?.certs} onNavigate={onNavigate} />

      {/* Live Telemetry Cockpit */}
      <TelemetryCockpit
        telemetry={telemetry}
        telemetryStreamLive={telemetryStreamLive}
        enablingTelemetry={enablingTelemetry}
        switchingDomain={switchingDomain}
        onEnableTelemetry={handleEnableTelemetry}
        onQuickSwitchDomain={handleQuickSwitchDomain}
        onNavigate={onNavigate}
      />

      {/* Services Grid */}
      <CoreServicesSummaryGrid
        status={status}
        loadingAction={loadingAction}
        onQuickRestart={handleQuickRestart}
        onNavigate={onNavigate}
      />

      {/* Hardware Metrics Dashboard */}
      <HardwareMetricsGrid status={status} />

      {/* Doctor Health Report Modal */}
      {showDoctorModal && doctorReport && (
        <DoctorReportModal doctorReport={doctorReport} onClose={() => setShowDoctorModal(false)} />
      )}
    </div>
  );
};

import React, { useState } from 'react';
import { ServerStatusResponse, DoctorReport } from '../types';
import { api } from '../api';
import { useToast } from './Toast';
import { Cpu, HardDrive, MemoryStick, Clock, RefreshCw, CheckCircle2, XCircle, ArrowRight, Stethoscope, AlertTriangle, X } from 'lucide-react';
import { TabKey } from './Navigation';

interface OverviewTabProps {
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
      desc: 'Reality & Shadowsocks 代理中继',
      detail: status?.services?.singbox,
      ports: '2080, 8443',
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
            监控守护四大核心组件，支持独立运维控制与资源实时指标
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
                支持在终端执行: <code className="text-purple-300 font-mono">singctl doctor</code>
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

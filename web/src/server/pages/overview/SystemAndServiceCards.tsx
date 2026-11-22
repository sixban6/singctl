import React from 'react';
import { CertHealthItem, ServerStatusResponse, TabKey } from '../../types';
import {
  ArrowRight,
  CheckCircle2,
  Clock,
  Cpu,
  Globe,
  HardDrive,
  MemoryStick,
  RefreshCw,
  XCircle,
} from 'lucide-react';

export const CertHealthStrip: React.FC<{
  certs?: CertHealthItem[];
  onNavigate: (tab: TabKey) => void;
}> = ({ certs, onNavigate }) => {
  if (!certs || certs.length === 0) return null;

  return (
    <div className="p-4 rounded-2xl glass-card border border-slate-800/80 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
      <div className="flex items-center gap-2.5">
        <div className="p-2 rounded-xl bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 shrink-0">
          <Globe className="w-4 h-4" />
        </div>
        <div>
          <div className="text-xs font-semibold text-white">ACME TLS 证书健康度</div>
          <div className="text-[11px] text-slate-400">自动巡检节点与订阅域名证书到期时间</div>
        </div>
      </div>
      <div className="flex flex-wrap items-center gap-2">
        {certs.map((cert) => {
          const badgeClass =
            cert.status === 'healthy'
              ? 'bg-emerald-500/10 text-emerald-300 border-emerald-500/25'
              : cert.status === 'expiring'
              ? 'bg-amber-500/15 text-amber-300 border-amber-500/30 animate-pulse'
              : cert.status === 'expired'
              ? 'bg-rose-500/20 text-rose-300 border-rose-500/35 animate-pulse'
              : 'bg-slate-800/80 text-slate-400 border-slate-700';
          const statusText =
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
              className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-xl border text-xs font-mono transition-colors ${badgeClass}`}
            >
              <span className="font-semibold">{cert.domain}</span>
              <span className="opacity-80">· {statusText}</span>
            </button>
          );
        })}
      </div>
    </div>
  );
};

export const CoreServicesSummaryGrid: React.FC<{
  status: ServerStatusResponse | null;
  loadingAction: string | null;
  onQuickRestart: (service: string) => void;
  onNavigate: (tab: TabKey) => void;
}> = ({ status, loadingAction, onQuickRestart, onNavigate }) => {
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
      desc: 'Go 原生多协议节点转换与聚合分发',
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

  return (
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
                onClick={() => onQuickRestart(s.key)}
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
  );
};

export const HardwareMetricsGrid: React.FC<{ status: ServerStatusResponse | null }> = ({ status }) => {
  const memPercentNum = parseFloat(status?.system?.memUsagePercent?.replace('%', '') || '0');
  const diskPercentNum = parseFloat(status?.system?.diskPercent?.replace('%', '') || '0');

  return (
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
  );
};

import React from 'react';
import { Clock, Cpu, HardDrive, Server } from 'lucide-react';
import { Badge } from '../../../ui';
import { HostTelemetry } from '../../types';

export interface HostMetricsStripProps {
  telemetry?: HostTelemetry | null;
}

function formatUptime(sec: number): string {
  const s = Math.max(0, Math.floor(Number(sec) || 0));
  if (s <= 0) return '—';
  const days = Math.floor(s / 86400);
  const hours = Math.floor((s % 86400) / 3600);
  const mins = Math.floor((s % 3600) / 60);
  const remSecs = s % 60;
  if (days > 0) {
    return `${days}天 ${String(hours).padStart(2, '0')}小时`;
  }
  if (hours > 0) {
    return `${hours}小时 ${String(mins).padStart(2, '0')}分`;
  }
  if (mins > 0) {
    return `${mins}分 ${String(remSecs).padStart(2, '0')}秒`;
  }
  return `${remSecs}秒`;
}

function formatBinaryBytes(bytes?: number): string {
  const val = Math.max(0, Number(bytes) || 0);
  const KiB = 1024;
  const MiB = 1024 * KiB;
  const GiB = 1024 * MiB;
  const TiB = 1024 * GiB;
  if (val >= TiB) return `${(val / TiB).toFixed(2)} TiB`;
  if (val >= GiB) return `${(val / GiB).toFixed(2)} GiB`;
  if (val >= MiB) return `${(val / MiB).toFixed(val >= 100 * MiB ? 0 : 1)} MiB`;
  if (val >= KiB) return `${(val / KiB).toFixed(0)} KiB`;
  return `${Math.round(val)} B`;
}

function usageColor(pct: number, warnAt: number, dangerAt: number): {
  bar: string;
  text: string;
} {
  if (pct >= dangerAt) {
    return { bar: 'bg-rose-500', text: 'text-rose-400' };
  }
  if (pct >= warnAt) {
    return { bar: 'bg-amber-400', text: 'text-amber-300' };
  }
  return { bar: 'bg-emerald-500', text: 'text-emerald-400' };
}

export const HostMetricsStrip: React.FC<HostMetricsStripProps> = ({ telemetry }) => {
  if (!telemetry) return null;

  const cores = Math.max(0, Number(telemetry.cpuCores) || 0);
  const load = Array.isArray(telemetry.loadAvg) ? telemetry.loadAvg : [0, 0, 0];
  const loadStr = `${(load[0] ?? 0).toFixed(2)} / ${(load[1] ?? 0).toFixed(2)} / ${(load[2] ?? 0).toFixed(2)}`;
  const highLoad = cores > 0 && (load[0] ?? 0) >= cores * 1.5;

  const cpuPct = Math.min(100, Math.max(0, Number(telemetry.cpuPercent) || 0));
  const cpuTone = usageColor(cpuPct, 65, 85);

  const mem = telemetry.mem;
  const memPct = Math.min(100, Math.max(0, Number(mem?.usedPercent) || 0));
  const memTone = usageColor(memPct, 70, 85);
  const hasSwap = Boolean(mem && mem.swapTotalBytes > 0);

  const disk = telemetry.disk;
  const diskPct = Math.min(100, Math.max(0, Number(disk?.usedPercent) || 0));
  const diskTone = usageColor(diskPct, 70, 85);
  const diskLabel = disk?.label || (telemetry.isOpenWrt ? 'Flash (/overlay)' : '磁盘 (/)');
  const tmpDisk = telemetry.tmpDisk && telemetry.tmpDisk.totalBytes > 0 ? telemetry.tmpDisk : null;

  return (
    <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
      {/* 1. Uptime & Load */}
      <div className="console-card rounded-2xl px-3.5 py-3 flex flex-col justify-between gap-2 min-w-0">
        <div className="flex items-center justify-between gap-2">
          <div className="flex items-center gap-1.5 min-w-0">
            <span className="w-6 h-6 rounded-lg bg-sky-500/10 border border-sky-500/20 text-sky-400 flex items-center justify-center shrink-0">
              <Clock className="w-3.5 h-3.5" />
            </span>
            <span className="text-[11px] font-medium text-secondary truncate">运行时间 & 负载</span>
          </div>
          {cores > 0 && (
            <Badge tone={highLoad ? 'warn' : 'neutral'} className="shrink-0 !px-1.5 !py-0 !text-[10px]">
              {cores}核
            </Badge>
          )}
        </div>
        <div className="text-sm sm:text-base font-bold text-primary font-mono tnum truncate">
          {formatUptime(telemetry.uptimeSec)}
        </div>
        <div
          className="text-[11px] font-mono text-muted tnum truncate"
          title={`1m / 5m / 15m 平均负载: ${loadStr}`}
        >
          Load <span className={highLoad ? 'text-amber-300' : 'text-secondary'}>{loadStr}</span>
        </div>
      </div>

      {/* 2. CPU Usage */}
      <div className="console-card rounded-2xl px-3.5 py-3 flex flex-col justify-between gap-2 min-w-0">
        <div className="flex items-center justify-between gap-2">
          <div className="flex items-center gap-1.5 min-w-0">
            <span className="w-6 h-6 rounded-lg bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 flex items-center justify-center shrink-0">
              <Cpu className="w-3.5 h-3.5" />
            </span>
            <span className="text-[11px] font-medium text-secondary truncate">CPU 占用率</span>
          </div>
          <span
            className={`text-xs font-mono font-semibold tnum shrink-0 ${
              telemetry.cpuReady ? cpuTone.text : 'text-muted'
            }`}
          >
            {telemetry.cpuReady ? `${cpuPct.toFixed(1)}%` : '采样中…'}
          </span>
        </div>
        <div className="space-y-1.5">
          <div className="w-full h-1.5 rounded-full bg-slate-900/90 border border-slate-800/80 overflow-hidden">
            {telemetry.cpuReady ? (
              <div
                className={`h-full rounded-full transition-all duration-300 ${cpuTone.bar}`}
                style={{ width: `${Math.max(2, cpuPct)}%` }}
              />
            ) : (
              <div className="h-full w-1/3 rounded-full bg-slate-700 animate-pulse" />
            )}
          </div>
          <div className="text-[11px] text-muted truncate tnum">
            {telemetry.cpuReady
              ? `${cores > 0 ? `${cores} 核` : 'CPU'} · ${telemetry.isOpenWrt ? 'OpenWrt 网关' : 'Linux 主机'}`
              : '正在建立首轮采样基线'}
          </div>
        </div>
      </div>

      {/* 3. Memory Usage */}
      <div className="console-card rounded-2xl px-3.5 py-3 flex flex-col justify-between gap-2 min-w-0">
        <div className="flex items-center justify-between gap-1.5">
          <div className="flex items-center gap-1.5 min-w-0">
            <span className="w-6 h-6 rounded-lg bg-cyan-500/10 border border-cyan-500/20 text-cyan-400 flex items-center justify-center shrink-0">
              <Server className="w-3.5 h-3.5" />
            </span>
            <span className="text-[11px] font-medium text-secondary truncate">内存使用</span>
            {mem?.lowMemory && (
              <Badge tone="warn" className="shrink-0 !px-1.5 !py-0 !text-[10px]">
                轻量
              </Badge>
            )}
          </div>
          <span className={`text-xs font-mono font-semibold tnum shrink-0 ${memTone.text}`}>
            {mem && mem.totalBytes > 0 ? `${memPct}%` : '—'}
          </span>
        </div>
        <div className="space-y-1.5">
          <div className="text-xs sm:text-sm font-semibold font-mono text-primary tnum truncate">
            {mem && mem.totalBytes > 0
              ? `${formatBinaryBytes(mem.usedBytes)} / ${formatBinaryBytes(mem.totalBytes)}`
              : '暂不可用'}
          </div>
          <div className="w-full h-1.5 rounded-full bg-slate-900/90 border border-slate-800/80 overflow-hidden">
            <div
              className={`h-full rounded-full transition-all duration-300 ${memTone.bar}`}
              style={{ width: `${mem && mem.totalBytes > 0 ? Math.max(2, memPct) : 0}%` }}
            />
          </div>
          <div className="text-[11px] font-mono text-muted tnum truncate">
            {mem && mem.totalBytes > 0
              ? hasSwap
                ? `可用 ${formatBinaryBytes(mem.availBytes)} · Swap ${formatBinaryBytes(mem.swapUsedBytes)}`
                : `可用 ${formatBinaryBytes(mem.availBytes)}`
              : '等待内存遥测'}
          </div>
        </div>
      </div>

      {/* 4. Disk / Flash Space */}
      <div className="console-card rounded-2xl px-3.5 py-3 flex flex-col justify-between gap-2 min-w-0">
        <div className="flex items-center justify-between gap-1.5">
          <div className="flex items-center gap-1.5 min-w-0">
            <span className="w-6 h-6 rounded-lg bg-violet-500/10 border border-violet-500/20 text-violet-400 flex items-center justify-center shrink-0">
              <HardDrive className="w-3.5 h-3.5" />
            </span>
            <span className="text-[11px] font-medium text-secondary truncate" title={disk?.mountPath || diskLabel}>
              {diskLabel}
            </span>
          </div>
          <span className={`text-xs font-mono font-semibold tnum shrink-0 ${diskTone.text}`}>
            {disk && disk.totalBytes > 0 ? `${diskPct}%` : '—'}
          </span>
        </div>
        <div className="space-y-1.5">
          <div className="text-xs sm:text-sm font-semibold font-mono text-primary tnum truncate">
            {disk && disk.totalBytes > 0
              ? `${formatBinaryBytes(disk.usedBytes)} / ${formatBinaryBytes(disk.totalBytes)}`
              : '暂不可用'}
          </div>
          <div className="w-full h-1.5 rounded-full bg-slate-900/90 border border-slate-800/80 overflow-hidden">
            <div
              className={`h-full rounded-full transition-all duration-300 ${diskTone.bar}`}
              style={{ width: `${disk && disk.totalBytes > 0 ? Math.max(2, diskPct) : 0}%` }}
            />
          </div>
          <div
            className="text-[11px] font-mono text-muted tnum truncate"
            title={
              tmpDisk
                ? `${disk?.mountPath || '/'} 剩余 ${formatBinaryBytes(disk?.availBytes)} · /tmp 剩余 ${formatBinaryBytes(tmpDisk.availBytes)}`
                : undefined
            }
          >
            {disk && disk.totalBytes > 0
              ? tmpDisk
                ? `剩 ${formatBinaryBytes(disk.availBytes)} · /tmp ${formatBinaryBytes(tmpDisk.availBytes)}`
                : `剩余可用 ${formatBinaryBytes(disk.availBytes)}`
              : '等待磁盘遥测'}
          </div>
        </div>
      </div>
    </div>
  );
};

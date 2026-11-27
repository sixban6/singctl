import React from 'react';
import { Cpu, Gauge, Laptop, Signal, Zap } from 'lucide-react';
import { Badge, Button, SectionCard } from '../../../../ui';
import { WifiChassisStatus, WifiClientInfo } from '../../../types';

interface WifiClientsAndChassisProps {
  clients: WifiClientInfo[];
  chassis: WifiChassisStatus;
  privacyMask: boolean;
  busy: boolean;
  chassisBusy: boolean;
  onApplyChassis: (enableRps: boolean, tuneConntrack: boolean) => void;
}

function maskMac(mac: string, mask: boolean): string {
  if (!mask) return mac;
  return mac.replace(/^([0-9a-f]{2}:[0-9a-f]{2}:).+(:[0-9a-f]{2})$/i, '$1**:**:**$2');
}

function maskIP(ip: string | undefined, mask: boolean): string {
  if (!ip) return '-';
  if (!mask) return ip;
  const parts = ip.split('.');
  if (parts.length === 4) return `${parts[0]}.${parts[1]}.*.*`;
  return '***';
}

export const WifiClientsAndChassis: React.FC<WifiClientsAndChassisProps> = ({
  clients: rawClients,
  chassis,
  privacyMask,
  busy,
  chassisBusy,
  onApplyChassis,
}) => {
  const clients = rawClients ?? [];
  const rpsInterfaces = chassis?.rpsInterfaces ?? [];
  const sortedClients = [...clients].sort((a, b) => {
    if (a.band !== b.band) return a.band === '5g' ? -1 : 1;
    return b.signalDbm - a.signalDbm;
  });

  const count5g = clients.filter((c) => c.band === '5g').length;
  const count2g = clients.filter((c) => c.band !== '5g').length;

  return (
    <div className="grid grid-cols-1 xl:grid-cols-3 gap-4">
      <SectionCard
        className="xl:col-span-2"
        title={
          <span className="flex items-center gap-2">
            <Laptop className="w-4 h-4 text-emerald-400" />
            <span>在线无线终端 ({clients.length})</span>
            <Badge tone="accent">5G: {count5g}</Badge>
            <Badge tone="neutral">2.4G: {count2g}</Badge>
          </span>
        }
        subtitle="实时查看各终端所在频段、信号强度与协商速率，快速识别拖慢整网的弱信号低速设备"
      >
        {sortedClients.length === 0 ? (
          <div className="text-xs text-secondary py-6 text-center">当前暂无在线无线客户端。</div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-xs text-left">
              <thead>
                <tr className="text-[11px] text-secondary border-b border-white/10">
                  <th className="py-2 pr-3 font-medium">设备 / IP</th>
                  <th className="py-2 pr-3 font-medium">热点 / 频段</th>
                  <th className="py-2 pr-3 font-medium">信号强度</th>
                  <th className="py-2 pr-3 font-medium">协商速率 (RX / TX)</th>
                  <th className="py-2 font-medium">状态</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/5">
                {sortedClients.map((c) => (
                  <tr key={`${c.ifname}-${c.mac}`} className="hover:bg-white/[0.02]">
                    <td className="py-2.5 pr-3">
                      <div className="font-medium text-primary">
                        {privacyMask ? '已遮挡设备' : c.hostname || maskMac(c.mac, false)}
                      </div>
                      <div className="text-[11px] font-mono text-secondary">
                        {maskIP(c.ip, privacyMask)} · {maskMac(c.mac, privacyMask)}
                      </div>
                    </td>
                    <td className="py-2.5 pr-3">
                      <div className="flex items-center gap-1.5">
                        <Badge tone={c.band === '5g' ? 'accent' : 'neutral'}>
                          {c.band === '5g' ? '5G' : '2.4G'}
                        </Badge>
                        <span className="text-primary">{c.ssid}</span>
                      </div>
                      <div className="text-[11px] text-secondary font-mono">
                        {c.ifname}
                        {c.bandwidthMhz ? ` · ${c.bandwidthMhz}MHz` : ''}
                      </div>
                    </td>
                    <td className="py-2.5 pr-3 font-mono">
                      <span
                        className={`inline-flex items-center gap-1 ${
                          c.signalDbm >= -68
                            ? 'text-emerald-300'
                            : c.signalDbm >= -80
                              ? 'text-sky-300'
                              : 'text-amber-300'
                        }`}
                      >
                        <Signal className="w-3.5 h-3.5" />
                        {c.signalDbm} dBm
                      </span>
                    </td>
                    <td className="py-2.5 pr-3 font-mono text-primary">
                      {Math.round(c.rxMbps)} / {Math.round(c.txMbps)} Mbps
                    </td>
                    <td className="py-2.5">
                      {c.weakSignal ? (
                        <Badge tone="warn">弱信号/低速</Badge>
                      ) : (
                        <Badge tone="ok">良好</Badge>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </SectionCard>

      <SectionCard
        title={
          <span className="flex items-center gap-2">
            <Gauge className="w-4 h-4 text-amber-400" />
            <span>高并发底盘加速</span>
            <Badge tone={chassis.optimal ? 'ok' : 'warn'}>
              {chassis.optimal ? '已达最优' : '可提速'}
            </Badge>
          </span>
        }
        subtitle={`CPU ${chassis.cpuCores} 核 · 内存 ${chassis.totalMemMb || '-'} MB · 持久化生效`}
      >
        {!chassis.supported ? (
          <div className="text-xs text-secondary py-4">当前环境不支持 Linux RPS / Conntrack 底盘调优。</div>
        ) : (
          <div className="space-y-3 text-xs">
            <div className="rounded-xl border border-white/10 bg-white/[0.02] p-3 space-y-1.5">
              <div className="flex items-center justify-between">
                <span className="font-medium text-primary flex items-center gap-1.5">
                  <Cpu className="w-3.5 h-3.5 text-sky-400" />
                  网卡多核 RPS 均衡
                </span>
                <Badge tone={chassis.rpsOptimal ? 'ok' : 'warn'}>
                  {chassis.rpsOptimal ? '已均衡' : '单核瓶颈'}
                </Badge>
              </div>
              <div className="text-[11px] text-secondary leading-relaxed">
                将有线主网口软中断平摊到全部 {chassis.cpuCores} 核，避免多设备高速下载时 CPU0 软中断打满。
              </div>
              {rpsInterfaces.length > 0 && (
                <div className="flex flex-wrap gap-1.5 pt-1 font-mono text-[11px]">
                  {rpsInterfaces.map((item) => (
                    <span
                      key={item.interface}
                      className="px-2 py-0.5 rounded bg-white/5 border border-white/10 text-secondary"
                    >
                      {item.interface}: {item.currentMask} → {item.targetMask}
                    </span>
                  ))}
                </div>
              )}
            </div>

            <div className="rounded-xl border border-white/10 bg-white/[0.02] p-3 space-y-1.5">
              <div className="flex items-center justify-between">
                <span className="font-medium text-primary">连接追踪表上限 (Conntrack)</span>
                <Badge tone={chassis.conntrackOptimal ? 'ok' : 'warn'}>
                  {chassis.conntrackOptimal ? '充裕' : '偏小'}
                </Badge>
              </div>
              <div className="font-mono text-[11px] text-secondary">
                当前占用 {chassis.conntrackCount.toLocaleString()} / 上限{' '}
                <strong className="text-primary">{chassis.conntrackMax.toLocaleString()}</strong>
                {!chassis.conntrackOptimal && (
                  <span className="text-emerald-300">
                    {' '}
                    → 推荐 {chassis.recommendedConntrack.toLocaleString()}
                  </span>
                )}
              </div>
            </div>

            <Button
              size="sm"
              variant={chassis.optimal ? 'secondary' : 'primary'}
              className="w-full"
              loading={chassisBusy}
              disabled={busy || chassis.optimal}
              icon={<Zap className="w-3.5 h-3.5" />}
              onClick={() => onApplyChassis(!chassis.rpsOptimal, !chassis.conntrackOptimal)}
            >
              {chassis.optimal
                ? '底盘已处于高并发最优状态'
                : !chassis.rpsOptimal && !chassis.conntrackOptimal
                  ? '一键开启多核 RPS 与连接表扩容'
                  : !chassis.rpsOptimal
                    ? '一键开启多核 RPS 均衡'
                    : '一键扩容 Conntrack 连接表'}
            </Button>
          </div>
        )}
      </SectionCard>
    </div>
  );
};

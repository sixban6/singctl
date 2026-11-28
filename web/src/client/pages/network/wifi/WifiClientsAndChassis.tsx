import React from 'react';
import { Laptop, Signal } from 'lucide-react';
import { Badge, SectionCard } from '../../../../ui';
import { WifiClientInfo } from '../../../types';

interface WifiClientsAndChassisProps {
  clients: WifiClientInfo[];
  privacyMask: boolean;
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
  privacyMask,
}) => {
  const clients = rawClients ?? [];
  const sortedClients = [...clients].sort((a, b) => {
    if (a.band !== b.band) return a.band === '5g' ? -1 : 1;
    return b.signalDbm - a.signalDbm;
  });

  const count5g = clients.filter((c) => c.band === '5g').length;
  const count2g = clients.filter((c) => c.band !== '5g').length;

  return (
    <SectionCard
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
  );
};

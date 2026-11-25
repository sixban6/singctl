import React from 'react';
import {
  Cable,
  Globe,
  KeyRound,
  Lock,
  Settings2,
  Share2,
  Trash2,
  Wifi,
  Zap,
} from 'lucide-react';
import { Badge, Button } from '../../../../ui';
import { VlanSegment } from '../../../types';
import { getSegmentTheme, maskVlanText } from './vlanHelpers';

export interface VlanSegmentCardProps {
  seg: VlanSegment;
  sideRouterIp?: string;
  proMode: boolean;
  privacyMask: boolean;
  busy: boolean;
  revealingSegId: string | null;
  onEdit: (seg: VlanSegment) => void;
  onDelete: (seg: VlanSegment) => void;
  onRevealWifiSecret: (seg: VlanSegment) => void;
}

export const VlanSegmentCard: React.FC<VlanSegmentCardProps> = ({
  seg,
  sideRouterIp = '',
  proMode,
  privacyMask,
  busy,
  revealingSegId,
  onEdit,
  onDelete,
  onRevealWifiSecret,
}) => {
  const theme = getSegmentTheme(seg.id, seg.preset);
  const assignedPorts = Object.entries(seg.ports ?? {});

  return (
    <div
      className={`relative rounded-2xl border ${theme.border} bg-slate-900/60 overflow-hidden flex flex-col justify-between`}
    >
      <div className={`h-1 w-full ${theme.bar} opacity-80`} />
      <div className="p-4 space-y-3">
        <div className="flex items-start justify-between gap-2">
          <div className="min-w-0">
            <div className="flex items-center gap-2 flex-wrap">
              <span className={`w-2 h-2 rounded-full ${theme.dot} shrink-0`} />
              <h3 className="text-sm font-bold text-white truncate">{seg.displayName}</h3>
              {seg.isCallerMgmt && (
                <Badge tone="warn">
                  <Lock className="w-2.5 h-2.5" />
                  当前管理会话
                </Badge>
              )}
            </div>
            <div className="flex items-center gap-2 mt-1 text-[11px] font-mono text-slate-400 flex-wrap">
              <span>{maskVlanText(seg.cidr || seg.ipAddr, privacyMask)}</span>
              {proMode && seg.vlanId > 0 && <span>· VLAN {seg.vlanId}</span>}
              {proMode && seg.device && <span>· {seg.device}</span>}
            </div>
          </div>

          <div className="flex items-center gap-1.5 shrink-0">
            <Badge tone={seg.onlineClients > 0 ? 'ok' : 'neutral'}>
              {seg.onlineClients} 台在线
            </Badge>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-1.5">
          {seg.proxyMode === 'side_router' ? (
            <Badge tone="accent">
              <Share2 className="w-3 h-3 text-cyan-300" />
              旁路由分流{sideRouterIp ? ` · ${maskVlanText(sideRouterIp, privacyMask)}` : ''}
            </Badge>
          ) : seg.proxyMode === 'direct' ? (
            <Badge tone="warn">
              <Zap className="w-3 h-3" />
              纯直连 · 绕过代理
            </Badge>
          ) : (
            <Badge tone="accent">
              <Globe className="w-3 h-3" />
              跟随网关转发
            </Badge>
          )}

          {seg.wireless?.enabled && seg.wireless.ssid && (
            <Badge tone="neutral">
              <Wifi className="w-3 h-3 text-sky-400" />
              {maskVlanText(seg.wireless.ssid, privacyMask)}
              {seg.wireless.band === '5g' ? ' (5G)' : seg.wireless.band === '2g' ? ' (2.4G)' : ''}
              {seg.wireless.isolate ? ' · 隔离' : ''}
            </Badge>
          )}

          {seg.dhcpDns && seg.dhcpDns.length > 0 && (
            <Badge tone="accent">
              DNS: {maskVlanText(seg.dhcpDns.join(', '), privacyMask)}
            </Badge>
          )}

          {assignedPorts.map(([pName, pMode]) => (
            <span
              key={pName}
              className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[11px] font-mono border border-slate-700/80 bg-slate-950/70 text-slate-300"
            >
              <Cable className="w-2.5 h-2.5 text-slate-400" />
              {pName.toUpperCase()}
              {proMode && pMode === 'trunk' ? ' (Trunk)' : ''}
            </span>
          ))}
        </div>

        {seg.relations && seg.relations.length > 0 && (
          <div className="flex flex-wrap items-center gap-1.5 pt-1">
            {seg.relations.map((rel, idx) => (
              <Badge key={idx} tone={rel.tone}>
                {rel.text}
              </Badge>
            ))}
          </div>
        )}

        {proMode && (
          <div className="pt-2 border-t border-slate-800/70 text-[11px] font-mono text-slate-400 flex flex-wrap gap-x-3 gap-y-1">
            <span>DHCP: .{seg.dhcpStart}~.{seg.dhcpStart + seg.dhcpLimit} ({seg.leaseTime})</span>
            <span>IPv6: {seg.ipv6Mode || 'off'}</span>
            {seg.policy.trustedSourceIps && seg.policy.trustedSourceIps.length > 0 && (
              <span>
                放行主控: {maskVlanText(seg.policy.trustedSourceIps.join(', '), privacyMask)}
              </span>
            )}
          </div>
        )}
      </div>

      <div className="px-4 py-2.5 border-t border-slate-800/70 bg-slate-950/40 flex items-center justify-between gap-2">
        <span className="text-[11px] text-slate-400">
          {seg.isPrimaryLan
            ? '默认兜底主网（不可删除）'
            : seg.managedBySingCtl
              ? '由 SingCtl 托管'
              : '现网识别（支持接管编辑）'}
        </span>
        <div className="flex items-center gap-1.5">
          {seg.isPrimaryLan && seg.wireless?.passwordConfigured && (
            <Button
              size="xs"
              variant="secondary"
              disabled={busy}
              loading={revealingSegId === seg.id}
              icon={<KeyRound className="w-3 h-3" />}
              onClick={() => onRevealWifiSecret(seg)}
            >
              查看 Wi-Fi 密码
            </Button>
          )}
          {!seg.isPrimaryLan && (
            <Button
              size="xs"
              variant="secondary"
              disabled={busy}
              icon={<Settings2 className="w-3 h-3" />}
              onClick={() => onEdit(seg)}
            >
              配置
            </Button>
          )}
          {!seg.isPrimaryLan && !seg.isCallerMgmt && (
            <Button
              size="xs"
              variant="danger"
              disabled={busy}
              icon={<Trash2 className="w-3 h-3" />}
              onClick={() => onDelete(seg)}
            >
              删除
            </Button>
          )}
        </div>
      </div>
    </div>
  );
};

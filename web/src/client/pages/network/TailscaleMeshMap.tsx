import React, { useState } from 'react';
import {
  ChevronDown,
  ChevronUp,
  Home,
  Laptop,
  Shield,
  SlidersHorizontal,
  Zap,
} from 'lucide-react';
import { Badge, Button } from '../../../ui';
import { maskFullIP } from '../../../lib/privacyMask';
import {
  ClientTailscaleStatus,
  TailscaleLocalNetworkDTO,
  TailscaleP2PPeerView,
  TailscaleSubnetScope,
} from '../../types';
import {
  LocalSubnetDraft,
  TailscaleLocalScopeCard,
} from './TailscaleLocalScopeCard';

export interface PeerPolicyDraft {
  id: string;
  name: string;
  tailscaleIP: string;
  jitEnabled: boolean;
  accessMode: 'bidirectional' | 'outbound_only';
  allowedLanTargetsText: string;
}

export interface TailscaleMeshMapProps {
  mode: string;
  localNetworks: TailscaleLocalNetworkDTO[];
  customSubnets: string[];
  subnetDrafts: Record<string, LocalSubnetDraft>;
  gatewayPeers: TailscaleP2PPeerView[];
  personalDevices: TailscaleP2PPeerView[];
  peerDrafts: Record<string, PeerPolicyDraft>;
  tsStatus?: ClientTailscaleStatus;
  p2pLiveEnabled: boolean;
  pokingKey: string;
  privacyMask: boolean;
  onToggleSubnet: (cidr: string) => void;
  onAddCustomSubnet: (cidr: string) => void;
  onRemoveCustomSubnet: (cidr: string) => void;
  onChangeScope: (cidr: string, scope: TailscaleSubnetScope) => void;
  onToggleDevice: (cidr: string, deviceIP: string) => void;
  onAddManualDevice: (cidr: string, deviceIP: string) => void;
  onUpdatePeerPolicy: (peerKey: string, patch: Partial<PeerPolicyDraft>) => void;
  onPokePeer: (peer: TailscaleP2PPeerView) => void;
}

export function meshPeerKey(p: TailscaleP2PPeerView): string {
  return p.id || p.tailscaleIPs?.[0] || p.name || p.shortName;
}

export const TailscaleMeshMap: React.FC<TailscaleMeshMapProps> = ({
  mode,
  localNetworks,
  customSubnets,
  subnetDrafts,
  gatewayPeers,
  personalDevices,
  peerDrafts,
  tsStatus,
  p2pLiveEnabled,
  pokingKey,
  privacyMask,
  onToggleSubnet,
  onAddCustomSubnet,
  onRemoveCustomSubnet,
  onChangeScope,
  onToggleDevice,
  onAddManualDevice,
  onUpdatePeerPolicy,
  onPokePeer,
}) => {
  const [personalExpanded, setPersonalExpanded] = useState(false);
  const [expandedExceptions, setExpandedExceptions] = useState<Record<string, boolean>>({});

  return (
    <div className="grid grid-cols-1 lg:grid-cols-2 gap-3.5 sm:gap-4 items-stretch">
      <TailscaleLocalScopeCard
        mode={mode}
        localNetworks={localNetworks}
        customSubnets={customSubnets}
        subnetDrafts={subnetDrafts}
        tsStatus={tsStatus}
        privacyMask={privacyMask}
        onToggleSubnet={onToggleSubnet}
        onAddCustomSubnet={onAddCustomSubnet}
        onRemoveCustomSubnet={onRemoveCustomSubnet}
        onChangeScope={onChangeScope}
        onToggleDevice={onToggleDevice}
        onAddManualDevice={onAddManualDevice}
      />

      {/* 右栏：远端组网节点 */}
      <div className="console-card rounded-2xl p-3.5 sm:p-4 flex flex-col justify-between gap-3">
        <div className="space-y-3">
          <div className="flex items-start justify-between gap-2">
            <div className="min-w-0">
              <div className="flex items-center gap-2 text-xs sm:text-sm font-semibold text-primary">
                <Home className="w-4 h-4 text-[var(--accent)] shrink-0" />
                <span>远端组网节点</span>
              </div>
              <p className="text-[11px] text-secondary mt-1 leading-relaxed">
                设置异地路由器的访问关系；自己的手机、电脑等随身设备默认直通左侧已允许设备。
              </p>
            </div>
            <Badge tone="neutral" className="shrink-0">
              {gatewayPeers.length} 个网关
            </Badge>
          </div>

          <div className="space-y-2.5">
            {gatewayPeers.length === 0 ? (
              <div className="p-3.5 rounded-xl bg-surface2 border border-subtle text-xs text-secondary leading-relaxed">
                暂未发现其他携带内网子网路由的路由器节点。当另一台路由器上线并通告子网后，将自动出现在这里。
              </div>
            ) : (
              gatewayPeers.map((peer, idx) => {
                const key = meshPeerKey(peer);
                const draft = peerDrafts[key] || {
                  id: peer.id,
                  name: peer.shortName || peer.name || key,
                  tailscaleIP: peer.tailscaleIPs?.[0] || '',
                  jitEnabled: true,
                  accessMode:
                    peer.effectiveAccessMode === 'bidirectional' ||
                    peer.effectiveAccessMode === 'bidirectional_timed'
                      ? 'bidirectional'
                      : 'outbound_only',
                  allowedLanTargetsText: (peer.allowedLanTargets || []).join(', '),
                };
                const isBidir = draft.accessMode === 'bidirectional';
                const isDirect = Boolean(peer.curAddr);
                const excOpen =
                  expandedExceptions[key] ?? Boolean(draft.allowedLanTargetsText.trim());

                return (
                  <div
                    key={key}
                    className="p-3 sm:p-3.5 rounded-xl border border-subtle bg-surface2/80 space-y-3"
                  >
                    <div className="flex items-start justify-between gap-2">
                      <div className="min-w-0 space-y-1">
                        <div className="flex flex-wrap items-center gap-1.5">
                          <span className="text-xs sm:text-sm font-semibold text-primary truncate">
                            {privacyMask
                              ? `远端网关 #${idx + 1}`
                              : peer.shortName || peer.name || peer.hostName || key}
                          </span>
                          <Badge tone={peer.online ? 'ok' : 'neutral'} dot>
                            {peer.online ? '在线' : '离线'}
                          </Badge>
                          {peer.online && (
                            <Badge tone={isDirect ? 'ok' : 'warn'}>
                              {isDirect ? 'P2P 直连' : `中继${!privacyMask && peer.relay ? ` (${peer.relay})` : ''}`}
                            </Badge>
                          )}
                        </div>
                        <div className="text-[11px] font-mono text-secondary flex flex-wrap items-center gap-x-2.5 break-all">
                          <span>{maskFullIP(peer.tailscaleIPs?.[0], privacyMask)}</span>
                          {peer.primaryRoutes && peer.primaryRoutes.length > 0 && (
                            <span className="text-primary">
                              对端网段: {privacyMask ? '••••••••' : peer.primaryRoutes.join(', ')}
                            </span>
                          )}
                        </div>
                      </div>

                      <Button
                        type="button"
                        size="xs"
                        variant="ghost"
                        disabled={!p2pLiveEnabled || !peer.online || pokingKey === key}
                        onClick={() => onPokePeer(peer)}
                        title="触发 DISCO 瞬时打洞探测并升级 P2P 直连"
                        className="shrink-0"
                        icon={<Zap className="w-3.5 h-3.5" />}
                      >
                        {pokingKey === key ? '打洞中…' : '测直连'}
                      </Button>
                    </div>

                    <div className="grid grid-cols-2 gap-2">
                      <button
                        type="button"
                        onClick={() => onUpdatePeerPolicy(key, { accessMode: 'bidirectional' })}
                        style={
                          isBidir
                            ? { backgroundColor: 'var(--accent-soft)', borderColor: 'var(--accent)' }
                            : undefined
                        }
                        className={`min-h-[58px] p-2.5 rounded-xl border text-left transition-all cursor-pointer active:scale-[0.99] ${
                          isBidir ? '' : 'bg-surface1/60 border-subtle hover:border-strong'
                        }`}
                      >
                        <div className="flex items-center gap-1.5 text-xs font-semibold text-primary">
                          <Home className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                          <span>互通</span>
                          <span className="text-[10px] font-normal text-secondary">· 家庭网络</span>
                        </div>
                        <div className="text-[10.5px] text-secondary mt-1 leading-snug">
                          两地设备双向直通
                        </div>
                      </button>

                      <button
                        type="button"
                        onClick={() => onUpdatePeerPolicy(key, { accessMode: 'outbound_only' })}
                        style={
                          !isBidir
                            ? { backgroundColor: 'rgba(14,165,233,0.12)', borderColor: 'rgb(56,189,248)' }
                            : undefined
                        }
                        className={`min-h-[58px] p-2.5 rounded-xl border text-left transition-all cursor-pointer active:scale-[0.99] ${
                          !isBidir ? '' : 'bg-surface1/60 border-subtle hover:border-strong'
                        }`}
                      >
                        <div className="flex items-center gap-1.5 text-xs font-semibold text-primary">
                          <Shield className="w-3.5 h-3.5 text-sky-400 shrink-0" />
                          <span>单向</span>
                          <span className="text-[10px] font-normal text-secondary">· 公共网络</span>
                        </div>
                        <div className="text-[10.5px] text-secondary mt-1 leading-snug">
                          只允许本机连过去
                        </div>
                      </button>
                    </div>

                    {isBidir && (
                      <div className="pt-0.5">
                        <button
                          type="button"
                          onClick={() =>
                            setExpandedExceptions((prev) => ({ ...prev, [key]: !excOpen }))
                          }
                          className="inline-flex items-center gap-1 text-[11px] text-secondary hover:text-primary py-1 cursor-pointer"
                        >
                          <SlidersHorizontal className="w-3 h-3" />
                          <span>
                            {excOpen ? '收起端口级精确例外' : '例外：仅向该对端开放指定端口/IP（可选）'}
                          </span>
                        </button>
                        {excOpen && (
                          <div className="mt-1.5">
                            <input
                              type={privacyMask ? 'password' : 'text'}
                              readOnly={privacyMask}
                              value={draft.allowedLanTargetsText}
                              onChange={(e) =>
                                onUpdatePeerPolicy(key, { allowedLanTargetsText: e.target.value })
                              }
                              placeholder={
                                privacyMask
                                  ? '••••••••'
                                  : '留空跟随左侧范围；也可限定 tcp/192.168.31.10:8090'
                              }
                              className="w-full h-10 sm:h-8 px-2.5 rounded-lg bg-surface1 border border-subtle text-base sm:text-xs font-mono text-primary focus:outline-none focus:border-strong"
                            />
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                );
              })
            )}
          </div>
        </div>

        <div className="rounded-xl border border-subtle bg-surface2/50 overflow-hidden">
          <button
            type="button"
            onClick={() => setPersonalExpanded((v) => !v)}
            className="w-full min-h-[44px] px-3 py-2 flex items-center justify-between gap-2 text-left hover:bg-surface2 transition-colors cursor-pointer"
          >
            <div className="flex flex-wrap items-center gap-2 text-xs text-primary min-w-0">
              <Laptop className="w-3.5 h-3.5 text-[var(--accent)] shrink-0" />
              <span className="font-medium">
                📱 个人随身设备（{personalDevices.length} 台）
              </span>
              <Badge tone="ok">默认直通已允许设备</Badge>
            </div>
            {personalExpanded ? (
              <ChevronUp className="w-4 h-4 text-secondary shrink-0" />
            ) : (
              <ChevronDown className="w-4 h-4 text-secondary shrink-0" />
            )}
          </button>

          {personalExpanded && (
            <div className="px-3 pb-2.5 pt-2 border-t border-subtle space-y-1.5 text-[11px]">
              {personalDevices.length === 0 ? (
                <div className="text-secondary">
                  暂无仅作为随身终端在线的个人设备（手机/电脑登录同账号后自动直通左侧已允许的设备与路由器后台）。
                </div>
              ) : (
                personalDevices.map((dev, i) => (
                  <div
                    key={meshPeerKey(dev)}
                    className="flex flex-wrap items-center justify-between gap-2 py-1 border-b border-subtle/50 last:border-b-0"
                  >
                    <div className="flex items-center gap-1.5 min-w-0">
                      <span
                        className={`w-2 h-2 rounded-full ${
                          dev.online ? 'bg-emerald-400' : 'bg-slate-500'
                        }`}
                      />
                      <span className="font-medium text-primary truncate">
                        {privacyMask ? `个人设备 #${i + 1}` : dev.shortName || dev.name || dev.hostName}
                      </span>
                      <span className="font-mono text-secondary">
                        {maskFullIP(dev.tailscaleIPs?.[0], privacyMask)}
                      </span>
                    </div>
                    <Badge tone="neutral">
                      {dev.online ? (dev.curAddr ? 'P2P 直连' : '在线 · 直通') : '离线 · 直通'}
                    </Badge>
                  </div>
                ))
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

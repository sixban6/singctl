import React, { useState } from 'react';
import {
  ChevronDown,
  ChevronUp,
  Info,
  Laptop,
  Network,
  Plus,
  Router,
  Wifi,
  X,
} from 'lucide-react';
import { Badge, Button } from '../../../ui';
import { maskFullIP } from '../../../lib/privacyMask';
import {
  ClientTailscaleStatus,
  TailscaleLocalDeviceDTO,
  TailscaleLocalNetworkDTO,
  TailscaleSubnetScope,
} from '../../types';
import { TailscaleCloudAclAlert } from './TailscaleCloudAclAlert';

export interface LocalSubnetDraft {
  cidr: string;
  selected: boolean;
  scope: TailscaleSubnetScope;
  devices: Set<string>;
}

export interface TailscaleLocalScopeCardProps {
  mode: string;
  localNetworks: TailscaleLocalNetworkDTO[];
  customSubnets: string[];
  subnetDrafts: Record<string, LocalSubnetDraft>;
  tsStatus?: ClientTailscaleStatus;
  privacyMask: boolean;
  onToggleSubnet: (cidr: string) => void;
  onAddCustomSubnet: (cidr: string) => void;
  onRemoveCustomSubnet: (cidr: string) => void;
  onChangeScope: (cidr: string, scope: TailscaleSubnetScope) => void;
  onToggleDevice: (cidr: string, deviceIP: string) => void;
  onAddManualDevice: (cidr: string, deviceIP: string) => void;
}

const SCOPE_OPTIONS: { value: TailscaleSubnetScope; label: string }[] = [
  { value: 'all', label: '全部设备' },
  { value: 'allowlist', label: '仅指定设备' },
  { value: 'denylist', label: '排除个别设备' },
];

function networkKindBadge(kind: string): { label: string; tone: 'accent' | 'ok' | 'neutral' } {
  switch (kind) {
    case 'primary_lan':
      return { label: '主网直连', tone: 'accent' };
    case 'vlan':
      return { label: 'VLAN 分段', tone: 'ok' };
    case 'downstream_subnet':
      return { label: '下级路由子网', tone: 'neutral' };
    default:
      return { label: '自定义网段', tone: 'neutral' };
  }
}

export const TailscaleLocalScopeCard: React.FC<TailscaleLocalScopeCardProps> = ({
  mode,
  localNetworks,
  customSubnets,
  subnetDrafts,
  tsStatus,
  privacyMask,
  onToggleSubnet,
  onAddCustomSubnet,
  onRemoveCustomSubnet,
  onChangeScope,
  onToggleDevice,
  onAddManualDevice,
}) => {
  const [newSubnetInput, setNewSubnetInput] = useState('');
  const [subnetInputErr, setSubnetInputErr] = useState('');
  const [manualDevInputs, setManualDevInputs] = useState<Record<string, string>>({});
  const [manualDevErrs, setManualDevErrs] = useState<Record<string, string>>({});
  const [expandedAllList, setExpandedAllList] = useState<Record<string, boolean>>({});

  const isSubnetRole = mode === 'router' || mode === 'gateway';
  const knownCIDRs = new Set(localNetworks.map((n) => n.cidr));
  const mergedNetworks: TailscaleLocalNetworkDTO[] = [
    ...localNetworks,
    ...customSubnets
      .filter((c) => !knownCIDRs.has(c))
      .map((c) => ({
        cidr: c,
        kind: 'custom',
        label: '手动添加网段',
        selected: Boolean(subnetDrafts[c]?.selected),
      })),
  ];

  const selectedCount = mergedNetworks.filter((n) => subnetDrafts[n.cidr]?.selected).length;
  const aclBlockedCidrs =
    isSubnetRole && tsStatus?.running
      ? mergedNetworks
          .filter(
            (n) =>
              Boolean(subnetDrafts[n.cidr]?.selected) &&
              Boolean(n.approved) &&
              n.aclStatus === 'blocked',
          )
          .map((n) => n.cidr)
      : [];

  const handleAddSubnet = () => {
    const val = newSubnetInput.trim();
    if (!val) return;
    if (!/^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/.test(val)) {
      setSubnetInputErr('请输入标准 IPv4 网段，例如 192.168.50.0/24');
      return;
    }
    setSubnetInputErr('');
    onAddCustomSubnet(val);
    setNewSubnetInput('');
  };

  const handleAddDevice = (cidr: string) => {
    const raw = (manualDevInputs[cidr] || '').trim();
    if (!raw) return;
    if (!/^(\d{1,3}\.){3}\d{1,3}$/.test(raw)) {
      setManualDevErrs((p) => ({ ...p, [cidr]: '请输入合法 IPv4 地址' }));
      return;
    }
    setManualDevErrs((p) => ({ ...p, [cidr]: '' }));
    onAddManualDevice(cidr, raw);
    setManualDevInputs((p) => ({ ...p, [cidr]: '' }));
  };

  return (
    <div className="console-card rounded-2xl p-3.5 sm:p-4 flex flex-col justify-between gap-3">
      <div className="space-y-3">
        <div className="flex items-start justify-between gap-2">
          <div className="min-w-0">
            <div className="flex items-center gap-2 text-xs sm:text-sm font-semibold text-primary">
              <Network className="w-4 h-4 text-[var(--accent)] shrink-0" />
              <span>本机开放范围</span>
            </div>
            <p className="text-[11px] text-secondary mt-1 leading-relaxed">
              勾选允许参与组网的网段，可进一步展开精确允许或排除单台设备（进出双向生效）。
            </p>
          </div>
          <Badge tone={isSubnetRole ? 'accent' : 'neutral'} className="shrink-0">
            {isSubnetRole ? `${selectedCount} 个已选` : '未广播内网'}
          </Badge>
        </div>

        {!isSubnetRole && (
          <div className="p-2.5 rounded-xl border border-sky-500/25 bg-sky-500/10 text-[11px] text-sky-200/90 flex items-start gap-2 leading-relaxed">
            <Info className="w-3.5 h-3.5 text-sky-300 shrink-0 mt-0.5" />
            <span>
              当前角色为「{mode === 'exit' ? '出口节点' : '默认客户端'}」，不广播本机网段；勾选下方任意网段将自动切换为「{mode === 'exit' ? '全能网关' : '子网路由器'}」。
            </span>
          </div>
        )}

        <TailscaleCloudAclAlert blockedCidrs={aclBlockedCidrs} privacyMask={privacyMask} />

        <div className="space-y-2.5">
          {mergedNetworks.length === 0 ? (
            <div className="p-3 rounded-xl bg-surface2 border border-subtle text-xs text-secondary">
              暂未探测到本机内网子网，可在下方手动添加 CIDR。
            </div>
          ) : (
            mergedNetworks.map((net) => {
              const draft = subnetDrafts[net.cidr] || {
                cidr: net.cidr,
                selected: net.selected,
                scope: (net.scope as TailscaleSubnetScope) || 'all',
                devices: new Set(net.selectedDevices || []),
              };
              const checked = draft.selected;
              const activeInNet = checked && isSubnetRole;
              const kindMeta = networkKindBadge(net.kind);
              const knownIPs = new Set((net.devices || []).map((d) => d.ip));
              const extraDevices: TailscaleLocalDeviceDTO[] = Array.from(draft.devices)
                .filter((ip) => !knownIPs.has(ip))
                .map((ip) => ({ ip, name: '手动添加设备', online: false, staticLease: true }));
              const allDevices = [...(net.devices || []), ...extraDevices];
              const showDevices =
                activeInNet && (draft.scope !== 'all' || Boolean(expandedAllList[net.cidr]));

              return (
                <div
                  key={net.cidr}
                  style={
                    activeInNet
                      ? { backgroundColor: 'var(--accent-soft)', borderColor: 'var(--accent)' }
                      : undefined
                  }
                  className={`p-3 rounded-xl border transition-all space-y-2.5 ${
                    activeInNet ? '' : 'bg-surface2/80 border-subtle'
                  }`}
                >
                  <div
                    onClick={() => !privacyMask && onToggleSubnet(net.cidr)}
                    className={`flex items-start justify-between gap-2.5 ${
                      privacyMask ? 'cursor-default' : 'cursor-pointer active:scale-[0.995]'
                    }`}
                  >
                    <div className="flex items-start gap-2.5 min-w-0">
                      <input
                        type="checkbox"
                        checked={checked}
                        disabled={privacyMask}
                        onChange={() => onToggleSubnet(net.cidr)}
                        onClick={(e) => e.stopPropagation()}
                        aria-label={`选择网段 ${net.label} ${net.cidr}`}
                        className="accent-[var(--accent)] w-4 h-4 mt-0.5 shrink-0"
                      />
                      <div className="min-w-0">
                        <div className="flex flex-wrap items-center gap-1.5">
                          <span className="text-xs font-semibold text-primary">{net.label}</span>
                          <Badge tone={kindMeta.tone}>{kindMeta.label}</Badge>
                          {tsStatus?.running && activeInNet && (
                            net.approved ? (
                              net.aclStatus === 'blocked' ? (
                                <Badge tone="danger">云端 ACL 未放行</Badge>
                              ) : net.aclStatus === 'partial' ? (
                                <Badge tone="warn">云端 ACL 部分放行</Badge>
                              ) : (
                                <Badge tone="ok">已生效</Badge>
                              )
                            ) : net.selected ? (
                              <Badge tone="warn">待后台批准</Badge>
                            ) : null
                          )}
                          {net.ssid && (
                            <span className="inline-flex items-center gap-1 text-[10px] px-1.5 py-0.5 rounded bg-surface1 border border-subtle text-secondary">
                              <Wifi className="w-2.5 h-2.5" />
                              {net.ssid}
                            </span>
                          )}
                        </div>
                        <div className="text-[11px] font-mono text-secondary mt-1 flex flex-wrap items-center gap-x-2 break-all">
                          <span className="text-primary font-medium">{maskFullIP(net.cidr, privacyMask)}</span>
                          {net.interface && <span>({net.interface})</span>}
                          {net.viaGateway && (
                            <span className="text-sky-300/90">
                              经 {maskFullIP(net.viaGateway, privacyMask)}
                            </span>
                          )}
                        </div>
                      </div>
                    </div>

                    {net.kind === 'custom' && !privacyMask && (
                      <button
                        type="button"
                        onClick={(e) => {
                          e.stopPropagation();
                          onRemoveCustomSubnet(net.cidr);
                        }}
                        title="移除自定义网段"
                        className="text-secondary hover:text-rose-400 p-1 rounded cursor-pointer shrink-0"
                      >
                        <X className="w-4 h-4" />
                      </button>
                    )}
                  </div>

                  {tsStatus?.running && activeInNet && net.approved && net.aclStatus === 'blocked' && (
                    <div className="text-[10.5px] text-rose-300/95 pl-6 leading-relaxed">
                      已获批通告，但云端 ACL 未放行该网段，远端设备访问将被 tailscaled 丢弃 (no rules matched)。
                    </div>
                  )}

                  {tsStatus?.running && activeInNet && net.approved && net.aclStatus === 'partial' && (
                    <div className="text-[10.5px] text-amber-300/95 pl-6 leading-relaxed">
                      云端 ACL 仅放行部分地址/端口
                      {!privacyMask && net.aclMatchedRanges?.length
                        ? `（${net.aclMatchedRanges.join('、')}）`
                        : ''}
                      ，其余访问将被拦截。
                    </div>
                  )}

                  {tsStatus?.running && activeInNet && net.selected && !net.approved && (
                    <div className="text-[10.5px] text-amber-300/90 pl-6 leading-relaxed">
                      {net.aclStatus === 'blocked'
                        ? '首次通告需在 Tailscale 网页后台 Edit route settings 批准，并在 Access Controls (ACL) 中放行该网段后生效。'
                        : '首次通告需在 Tailscale 网页后台 Edit route settings 批准后生效。'}
                    </div>
                  )}

                  {activeInNet && (
                    <div className="pl-0 sm:pl-6 space-y-2 pt-1 border-t border-subtle/60">
                      <div className="flex flex-wrap items-center justify-between gap-2">
                        <div className="grid grid-cols-3 gap-1.5 w-full sm:w-auto flex-1">
                          {SCOPE_OPTIONS.map((opt) => {
                            const selected = draft.scope === opt.value;
                            return (
                              <button
                                key={opt.value}
                                type="button"
                                onClick={() => onChangeScope(net.cidr, opt.value)}
                                className={`h-8 sm:h-7 px-2 rounded-lg text-[11px] font-medium border transition-colors cursor-pointer ${
                                  selected
                                    ? opt.value === 'denylist'
                                      ? 'bg-rose-500/20 border-rose-400/60 text-rose-200'
                                      : 'bg-[var(--accent)]/20 border-[var(--accent)] text-primary'
                                    : 'bg-surface1/80 border-subtle text-secondary hover:text-primary'
                                }`}
                              >
                                {opt.label}
                              </button>
                            );
                          })}
                        </div>
                        {draft.scope === 'all' && allDevices.length > 0 && (
                          <button
                            type="button"
                            onClick={() =>
                              setExpandedAllList((p) => ({ ...p, [net.cidr]: !p[net.cidr] }))
                            }
                            className="inline-flex items-center gap-1 text-[11px] text-secondary hover:text-primary py-1 cursor-pointer shrink-0"
                          >
                            <span>查看设备 ({allDevices.length})</span>
                            {expandedAllList[net.cidr] ? (
                              <ChevronUp className="w-3.5 h-3.5" />
                            ) : (
                              <ChevronDown className="w-3.5 h-3.5" />
                            )}
                          </button>
                        )}
                      </div>

                      {showDevices && (
                        <div className="p-2.5 rounded-xl bg-surface1/85 border border-subtle space-y-2">
                          <div className="text-[10.5px] text-secondary leading-relaxed">
                            {draft.scope === 'allowlist'
                              ? `仅下列勾选设备可双向访问组网（已选 ${draft.devices.size} 台），同网段其余设备双向隔离：`
                              : draft.scope === 'denylist'
                                ? `下列勾选设备将被双向禁止接入组网（已排除 ${draft.devices.size} 台），其余设备正常互通：`
                                : '当前为「全部设备」开放。切换为「仅指定设备」或「排除个别设备」即可勾选管控单台机器：'}
                          </div>

                          <div className="space-y-1 max-h-56 overflow-y-auto pr-0.5">
                            {allDevices.length === 0 ? (
                              <div className="text-[11px] text-secondary py-1">
                                暂未发现活跃设备，可在下方手动填写本网段内 IP。
                              </div>
                            ) : (
                              allDevices.map((dev) => {
                                const isChecked = draft.scope === 'all' ? true : draft.devices.has(dev.ip);
                                return (
                                  <div
                                    key={dev.ip}
                                    onClick={() =>
                                      draft.scope !== 'all' && !privacyMask && onToggleDevice(net.cidr, dev.ip)
                                    }
                                    className={`min-h-[40px] px-2.5 py-1.5 rounded-lg border flex items-center justify-between gap-2 transition-colors ${
                                      draft.scope === 'all'
                                        ? 'border-subtle/50 bg-surface2/40 opacity-85'
                                        : privacyMask
                                          ? 'border-subtle bg-surface2/60 cursor-default'
                                          : isChecked
                                            ? draft.scope === 'denylist'
                                              ? 'border-rose-400/50 bg-rose-500/10 cursor-pointer'
                                              : 'border-[var(--accent)]/60 bg-[var(--accent-soft)] cursor-pointer'
                                            : 'border-subtle/70 bg-surface2/60 hover:border-strong cursor-pointer'
                                    }`}
                                  >
                                    <div className="flex items-center gap-2 min-w-0">
                                      <input
                                        type="checkbox"
                                        checked={isChecked}
                                        disabled={draft.scope === 'all' || privacyMask}
                                        onChange={() =>
                                          draft.scope !== 'all' && onToggleDevice(net.cidr, dev.ip)
                                        }
                                        onClick={(e) => e.stopPropagation()}
                                        className={`w-4 h-4 shrink-0 ${
                                          draft.scope === 'denylist'
                                            ? 'accent-rose-500'
                                            : 'accent-[var(--accent)]'
                                        }`}
                                      />
                                      <span
                                        className={`w-2 h-2 rounded-full shrink-0 ${
                                          dev.online ? 'bg-emerald-400' : 'bg-slate-500'
                                        }`}
                                      />
                                      {dev.isDownstream ? (
                                        <Router className="w-3.5 h-3.5 text-sky-400 shrink-0" />
                                      ) : (
                                        <Laptop className="w-3.5 h-3.5 text-secondary shrink-0" />
                                      )}
                                      <div className="min-w-0">
                                        <div className="flex flex-wrap items-center gap-1.5">
                                          <span className="text-xs font-medium text-primary truncate">
                                            {privacyMask ? '内网设备' : dev.name}
                                          </span>
                                          {dev.isDownstream && <Badge tone="neutral">下级路由</Badge>}
                                          {!dev.staticLease && !dev.isDownstream && (
                                            <span className="text-[10px] px-1 py-0.5 rounded bg-amber-500/15 text-amber-300">
                                              动态IP
                                            </span>
                                          )}
                                        </div>
                                        <div className="text-[11px] font-mono text-secondary">
                                          {maskFullIP(dev.ip, privacyMask)}
                                        </div>
                                      </div>
                                    </div>
                                  </div>
                                );
                              })
                            )}
                          </div>

                          {draft.scope !== 'all' && (
                            <div className="pt-1 space-y-1">
                              <div className="flex items-center gap-1.5">
                                <input
                                  type={privacyMask ? 'password' : 'text'}
                                  readOnly={privacyMask}
                                  value={manualDevInputs[net.cidr] || ''}
                                  onChange={(e) => {
                                    const v = e.target.value;
                                    setManualDevInputs((p) => ({ ...p, [net.cidr]: v }));
                                    setManualDevErrs((p) => ({ ...p, [net.cidr]: '' }));
                                  }}
                                  onKeyDown={(e) => {
                                    if (e.key === 'Enter') {
                                      e.preventDefault();
                                      handleAddDevice(net.cidr);
                                    }
                                  }}
                                  placeholder={privacyMask ? '••••••••' : '手动补充该网段内设备 IP...'}
                                  className="flex-1 h-10 sm:h-8 px-2.5 rounded-lg bg-surface2 border border-subtle text-base sm:text-xs font-mono text-primary focus:outline-none focus:border-strong"
                                />
                                <Button
                                  type="button"
                                  size="xs"
                                  variant="secondary"
                                  disabled={privacyMask || !(manualDevInputs[net.cidr] || '').trim()}
                                  onClick={() => handleAddDevice(net.cidr)}
                                  icon={<Plus className="w-3.5 h-3.5" />}
                                >
                                  添加
                                </Button>
                              </div>
                              {manualDevErrs[net.cidr] && (
                                <div className="text-[11px] text-rose-400">{manualDevErrs[net.cidr]}</div>
                              )}
                            </div>
                          )}
                        </div>
                      )}

                      {net.kind === 'downstream_subnet' && (
                        <div className="text-[10.5px] text-secondary leading-relaxed">
                          注：下级子网允许远端反向连入；若下级路由开启了 WAN NAT，其出站组网权限将跟随上级直连路由网段中该路由器节点（{maskFullIP(net.viaGateway, privacyMask)}）的权限。
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

      <div className="pt-2 border-t border-subtle space-y-1.5">
        <div className="flex items-center gap-2">
          <input
            type={privacyMask ? 'password' : 'text'}
            readOnly={privacyMask}
            value={newSubnetInput}
            onChange={(e) => {
              setNewSubnetInput(e.target.value);
              setSubnetInputErr('');
            }}
            onKeyDown={(e) => {
              if (e.key === 'Enter') {
                e.preventDefault();
                handleAddSubnet();
              }
            }}
            placeholder={privacyMask ? '••••••••' : '手动补充其他内网网段，如 192.168.50.0/24'}
            className="flex-1 h-10 sm:h-8 px-2.5 rounded-lg bg-surface1 border border-subtle text-base sm:text-xs font-mono text-primary focus:outline-none focus:border-strong"
          />
          <Button
            type="button"
            size="xs"
            variant="secondary"
            disabled={privacyMask || !newSubnetInput.trim()}
            onClick={handleAddSubnet}
            icon={<Plus className="w-3.5 h-3.5" />}
          >
            添加网段
          </Button>
        </div>
        {subnetInputErr && <div className="text-[11px] text-rose-400">{subnetInputErr}</div>}
      </div>
    </div>
  );
};

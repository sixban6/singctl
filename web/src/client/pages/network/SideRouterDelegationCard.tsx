import React, { useEffect, useState } from 'react';
import {
  Activity,
  CheckCircle2,
  ExternalLink,
  Network,
  RotateCcw,
  Save,
  Share2,
  ShieldCheck,
  Unlink,
} from 'lucide-react';
import { Badge, Button, SectionCard } from '../../../ui';
import { maskFullIP } from '../../../lib/privacyMask';
import { SideRouterStatusInfo } from '../../types';

export interface SideRouterDelegationCardProps {
  sideRouterIP?: string;
  sideRouterFailover: boolean;
  sideRouterStatus?: SideRouterStatusInfo | null;
  saving: boolean;
  busy: boolean;
  privacyMask?: boolean;
  onSaveSideRouter: (nextIP: string, nextFailover: boolean) => Promise<boolean>;
  onGoVlan?: () => void;
}

export const SideRouterDelegationCard: React.FC<SideRouterDelegationCardProps> = ({
  sideRouterIP = '',
  sideRouterFailover,
  sideRouterStatus,
  saving,
  busy,
  privacyMask = false,
  onSaveSideRouter,
  onGoVlan,
}) => {
  const [ipInput, setIpInput] = useState(sideRouterIP);
  const [failover, setFailover] = useState(sideRouterFailover);
  const [dirty, setDirty] = useState(false);

  useEffect(() => {
    if (!dirty) {
      setIpInput(sideRouterIP);
      setFailover(sideRouterFailover);
    }
  }, [sideRouterIP, sideRouterFailover, dirty]);

  const trimmedIP = ipInput.trim();
  const savedTrimmed = sideRouterIP.trim();
  const ipChanged = trimmedIP !== savedTrimmed;
  const failoverChanged = failover !== sideRouterFailover;
  const hasChanges = ipChanged || failoverChanged;
  const canOpenPeer = Boolean(savedTrimmed) && !privacyMask;

  const submitSave = async (nextIP: string, nextFailover: boolean) => {
    const ok = await onSaveSideRouter(nextIP, nextFailover);
    if (ok) {
      setDirty(false);
    }
  };

  const resetDraft = () => {
    setIpInput(sideRouterIP);
    setFailover(sideRouterFailover);
    setDirty(false);
  };

  const saveLabel = !trimmedIP && savedTrimmed
    ? '解除绑定并恢复本机运行'
    : ipChanged
      ? '保存并交由旁路由托管'
      : '保存容灾设置';

  return (
    <SectionCard
      title="旁路由协同托管中心"
      icon={<Share2 className="w-4 h-4" />}
      subtitle="绑定局域网旁路由（如 N1）后，主路由将自动停用本机代理并按 Wi-Fi / VLAN 精准把流量转交旁路由分流"
      actions={
        <div className="flex items-center gap-2 flex-wrap">
          {sideRouterStatus?.configured ? (
            <Badge tone={sideRouterStatus.online ? 'ok' : 'warn'} dot pulse={sideRouterStatus.online}>
              {sideRouterStatus.online
                ? `旁路由在线${sideRouterStatus.latencyMs ? ` · ${sideRouterStatus.latencyMs}ms` : ''}`
                : '旁路由暂不可达'}
            </Badge>
          ) : (
            <Badge tone="neutral">未绑定旁路由</Badge>
          )}
          {canOpenPeer && (
            <a
              href={`http://${savedTrimmed}:8090`}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-1 px-2.5 py-1 rounded-lg bg-cyan-500/15 hover:bg-cyan-500/25 border border-cyan-500/35 text-cyan-300 text-xs font-medium transition-colors"
            >
              <span>打开旁路由分流面板</span>
              <ExternalLink className="w-3 h-3" />
            </a>
          )}
        </div>
      }
    >
      <div className="space-y-4">
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">
          <div className="rounded-xl bg-surface2 border border-subtle p-3.5 space-y-2">
            <div className="flex items-center justify-between gap-2">
              <label htmlFor="side-router-ip-input" className="block text-xs font-semibold text-primary">
                旁路由局域网 IPv4 地址
              </label>
              {hasChanges ? (
                <span className="text-[10px] px-1.5 py-0.5 rounded bg-amber-500/15 text-amber-300 border border-amber-500/35">
                  待保存
                </span>
              ) : savedTrimmed ? (
                <span className="text-[10px] px-1.5 py-0.5 rounded bg-emerald-500/15 text-emerald-300 border border-emerald-500/35">
                  ✓ 当前生效
                </span>
              ) : null}
            </div>
            <input
              id="side-router-ip-input"
              type={privacyMask ? 'password' : 'text'}
              readOnly={privacyMask}
              value={ipInput}
              onChange={(e) => {
                setIpInput(e.target.value);
                setDirty(true);
              }}
              placeholder={privacyMask ? '••••••••' : '例如 192.168.55.88（留空或点击解绑可恢复本机运行）'}
              className="sc-input w-full h-9 px-3 text-xs sm:text-sm font-mono"
            />
            <p className="text-[11px] text-secondary leading-relaxed">
              绑定旁路由 IP 后，主路由将自动停用本机 sing-box 释放内存，交由旁路由透明分流；解除绑定后自动恢复主路由本机运行。
            </p>
          </div>

          <div className="rounded-xl bg-surface2 border border-subtle p-3.5 space-y-2">
            <div className="flex items-center justify-between gap-2">
              <span className="text-xs font-semibold text-primary flex items-center gap-1.5">
                <Activity className="w-3.5 h-3.5 text-emerald-400" />
                主旁连通性与主网 DHCP 状态
              </span>
              {sideRouterStatus?.configured && (
                <div className="flex items-center gap-1.5 text-[10px]">
                  <Badge tone={sideRouterStatus.dnsReady ? 'ok' : 'neutral'}>
                    DNS :53 {sideRouterStatus.dnsReady ? '✓' : '×'}
                  </Badge>
                  <Badge tone={sideRouterStatus.webuiReady ? 'ok' : 'neutral'}>
                    面板 :8090 {sideRouterStatus.webuiReady ? '✓' : '×'}
                  </Badge>
                </div>
              )}
            </div>
            <div className="text-xs text-secondary leading-relaxed">
              {sideRouterStatus?.lanDhcpHint ? (
                <span>
                  {sideRouterStatus.lanDhcpHint}（旁路由：
                  <code className="font-mono text-primary">{maskFullIP(sideRouterStatus.ip, privacyMask)}</code>）
                </span>
              ) : (
                <span>绑定旁路由 IP 并保存后，系统将自动探测其 :53 / :8090 在线状态与主网 DHCP 接管模式。</span>
              )}
            </div>
          </div>
        </div>

        <label className="flex items-start justify-between gap-3 rounded-xl border border-subtle bg-surface2 px-3.5 py-2.5 cursor-pointer hover:border-strong transition-colors">
          <div className="min-w-0">
            <div className="text-xs font-semibold text-primary flex items-center gap-1.5">
              <ShieldCheck className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
              旁路由离线自动回退主路由直连（防断网救生艇）
            </div>
            <div className="text-[11px] text-secondary mt-0.5 leading-relaxed">
              看门狗每 15 秒探测旁路由存活性：若旁路由重启或断线，自动暂挂策略路由让托管 Wi-Fi 瞬间恢复主路由直连上网；旁路由恢复后自动无感切回。
            </div>
          </div>
          <input
            type="checkbox"
            checked={failover}
            disabled={privacyMask}
            onChange={(e) => {
              setFailover(e.target.checked);
              setDirty(true);
            }}
            className="mt-1 h-4 w-4 rounded accent-emerald-500 shrink-0 cursor-pointer"
          />
        </label>

        <div className="flex flex-wrap items-center justify-between gap-2.5 pt-2 border-t border-subtle">
          <div className="flex items-center gap-2 flex-wrap">
            {onGoVlan && (
              <Button size="xs" variant="secondary" icon={<Network className="w-3.5 h-3.5" />} onClick={onGoVlan}>
                前往子网隔离 (VLAN) 分配 Wi-Fi 分流
              </Button>
            )}
          </div>
          <div className="flex items-center gap-2 flex-wrap">
            {hasChanges && !saving && (
              <Button
                size="sm"
                variant="ghost"
                disabled={busy || privacyMask}
                icon={<RotateCcw className="w-3.5 h-3.5" />}
                onClick={resetDraft}
              >
                撤销更改
              </Button>
            )}

            {hasChanges ? (
              <Button
                size="sm"
                variant="primary"
                loading={saving}
                disabled={busy || saving || privacyMask}
                icon={<Save className="w-3.5 h-3.5" />}
                onClick={() => void submitSave(trimmedIP, failover)}
              >
                {saveLabel}
              </Button>
            ) : savedTrimmed ? (
              <>
                <Button
                  size="sm"
                  variant="secondary"
                  loading={saving}
                  disabled={busy || saving || privacyMask}
                  icon={<Unlink className="w-3.5 h-3.5" />}
                  onClick={() => void submitSave('', failover)}
                >
                  解除绑定
                </Button>
                <Button
                  size="sm"
                  variant="secondary"
                  disabled
                  icon={<CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />}
                >
                  已托管至旁路由 ({maskFullIP(savedTrimmed, privacyMask)})
                </Button>
              </>
            ) : (
              <Button size="sm" variant="secondary" disabled>
                填写旁路由 IP 后可绑定托管
              </Button>
            )}
          </div>
        </div>
      </div>
    </SectionCard>
  );
};

import React, { useState } from 'react';
import { ChevronDown, ChevronUp, ShieldCheck } from 'lucide-react';
import { Badge } from '../../../ui';
import { redactInlineSensitive } from '../../../lib/privacyMask';
import { TailscaleP2PReport } from '../../types';

export interface TailscaleAdvancedDrawerProps {
  p2pReport?: TailscaleP2PReport;
  privacyMask: boolean;
  jitWindowSec: number;
  cooldownSec: number;
  sandboxUjail: boolean;
  downstreamAssist: boolean;
  onJitWindowChange: (sec: number) => void;
  onCooldownChange: (sec: number) => void;
  onSandboxUjailChange: (enabled: boolean) => void;
  onDownstreamAssistChange: (enabled: boolean) => void;
}

export const TailscaleAdvancedDrawer: React.FC<TailscaleAdvancedDrawerProps> = ({
  p2pReport,
  privacyMask,
  jitWindowSec,
  cooldownSec,
  sandboxUjail,
  downstreamAssist,
  onJitWindowChange,
  onCooldownChange,
  onSandboxUjailChange,
  onDownstreamAssistChange,
}) => {
  const [open, setOpen] = useState(false);
  const p2pLiveEnabled = Boolean(p2pReport?.config?.enabled);

  return (
    <div className="console-card rounded-2xl overflow-hidden">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        className="w-full min-h-[52px] px-4 py-3 flex items-center justify-between gap-2 text-left hover:bg-surface2/60 transition-colors cursor-pointer"
      >
        <div className="flex flex-wrap items-center gap-2 min-w-0">
          <ShieldCheck className="w-4 h-4 text-[var(--accent)] shrink-0" />
          <span className="text-xs sm:text-sm font-semibold text-primary">
            P2P 直连防线 · 零常驻暴露 (JIT)
          </span>
          <span className="text-[11px] text-secondary hidden lg:inline">
            闲置与直连期间 UDP :41641 公网零暴露
          </span>
        </div>

        <div className="flex items-center gap-2 shrink-0">
          {p2pReport && (
            <Badge tone={p2pReport.openPinholes > 0 ? 'warn' : p2pLiveEnabled ? 'ok' : 'neutral'} dot>
              {p2pReport.openPinholes > 0
                ? `瞬时放行 ${p2pReport.openPinholes} 个 IP`
                : p2pLiveEnabled
                  ? '0 开放 · 零暴露'
                  : '未开启'}
            </Badge>
          )}
          <span className="hidden sm:inline-flex">
            <Badge tone="neutral">
              {jitWindowSec}s / {cooldownSec}s
            </Badge>
          </span>
          {open ? (
            <ChevronUp className="w-4 h-4 text-secondary" />
          ) : (
            <ChevronDown className="w-4 h-4 text-secondary" />
          )}
        </div>
      </button>

      {open && (
        <div className="px-3.5 sm:px-4 pb-4 pt-3 border-t border-subtle space-y-4">
          <p className="text-xs text-secondary leading-relaxed">
            闲置与直连期间 WAN 侧 UDP :41641 零暴露；仅在授权节点按需直连时瞬时放行 3~10s 并在连上后毫秒级自动关门。
          </p>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-2.5 sm:gap-3 text-xs">
            <div
              className="flex items-center justify-between gap-3 p-3.5 rounded-xl border border-subtle bg-surface2 cursor-default"
              title="核心防线默认强制开启，确保 UDP :41641 不长期裸露公网"
            >
              <div className="min-w-0">
                <div className="font-semibold text-primary flex items-center gap-1.5 flex-wrap">
                  <span>启用防线守护</span>
                  <span className="text-[10px] px-1.5 py-0.5 rounded bg-[var(--accent)]/15 text-[var(--accent)] font-medium">
                    必选
                  </span>
                </div>
                <div className="text-[11px] text-secondary mt-1 truncate">
                  {p2pReport?.fw4Available
                    ? p2pReport.runtime?.applyMode === 'nft_direct'
                      ? 'OpenWrt nftables 原子注入就绪'
                      : 'OpenWrt fw4 原生热重载就绪'
                    : '未检测到 inet fw4 表'}
                </div>
              </div>
              <input
                type="checkbox"
                checked
                readOnly
                tabIndex={-1}
                aria-label="启用防线守护（必选）"
                className="accent-[var(--accent)] w-4 h-4 shrink-0 pointer-events-none"
              />
            </div>

            <div
              className="flex items-center justify-between gap-3 p-3.5 rounded-xl border border-subtle bg-surface2 cursor-default"
              title="核心安全拦截默认强制开启，仅放行 STUN / DISCO / WireGuard 合法载荷"
            >
              <div className="min-w-0">
                <div className="font-semibold text-primary flex items-center gap-1.5 flex-wrap">
                  <span>Layer 2 载荷魔法头过滤</span>
                  <span className="text-[10px] px-1.5 py-0.5 rounded bg-[var(--accent)]/15 text-[var(--accent)] font-medium">
                    必选
                  </span>
                </div>
                <div className="text-[11px] text-secondary mt-1 truncate">
                  UDP :41641 仅放行 STUN / DISCO / WireGuard
                </div>
              </div>
              <input
                type="checkbox"
                checked
                readOnly
                tabIndex={-1}
                aria-label="Layer 2 载荷魔法头过滤（必选）"
                className="accent-[var(--accent)] w-4 h-4 shrink-0 pointer-events-none"
              />
            </div>

            <label
              className={`flex items-center justify-between gap-3 p-3.5 rounded-xl border border-subtle bg-surface2 ${
                p2pReport?.ujailAvailable ? 'cursor-pointer' : 'opacity-60 cursor-not-allowed'
              }`}
              title={
                p2pReport?.ujailAvailable ? '重启 tailscaled 进入 OpenWrt ujail 沙盒' : '当前环境无 /sbin/ujail'
              }
            >
              <div className="min-w-0">
                <div className="font-semibold text-primary flex items-center gap-1.5 flex-wrap">
                  <span>Layer 3 ujail 沙盒隔离</span>
                  <span className="text-[10px] px-1.5 py-0.5 rounded bg-surface1 text-secondary border border-subtle font-medium">
                    {p2pReport?.ujailAvailable ? '默认开启 · 可取消' : '不可用'}
                  </span>
                </div>
                <div className="text-[11px] text-secondary mt-1 truncate">
                  {p2pReport?.ujailAvailable
                    ? '裁剪 Capabilities 并隔离敏感配置目录'
                    : '当前环境无 /sbin/ujail'}
                </div>
              </div>
              <input
                type="checkbox"
                disabled={!p2pReport?.ujailAvailable}
                checked={sandboxUjail}
                onChange={(e) => onSandboxUjailChange(e.target.checked)}
                aria-label="Layer 3 ujail 沙盒隔离"
                className="accent-[var(--accent)] w-4 h-4 shrink-0"
              />
            </label>

            <label
              className="flex items-center justify-between gap-3 p-3.5 rounded-xl border border-subtle bg-surface2 cursor-pointer"
              title="平时 0 字节进内网；仅在下级路由/NAS 主动外发 Tailscale 打洞包时，在边界为该单对端 IP 开启瞬时微窗"
            >
              <div className="min-w-0">
                <div className="font-semibold text-primary flex items-center gap-1.5 flex-wrap">
                  <span>下游设备边界微窗</span>
                  <span className="text-[10px] px-1.5 py-0.5 rounded bg-surface1 text-secondary border border-subtle font-medium">
                    {p2pReport?.runtime?.downstreamV4Active
                      ? `协助中 · ${jitWindowSec}s`
                      : p2pReport?.runtime?.downstreamV6Active
                        ? 'IPv6 协助就绪'
                        : '默认开启 · 可取消'}
                  </span>
                </div>
                <div className="text-[11px] text-secondary mt-1 truncate">
                  {p2pReport?.runtime?.downstreamV4Active
                    ? '本机未跑 Tailscale，正零暴露协助下游路由/NAS 直连'
                    : '协助内网二级路由/NAS 穿透对称 NAT（平时 0 包进内网）'}
                </div>
              </div>
              <input
                type="checkbox"
                checked={downstreamAssist}
                onChange={(e) => onDownstreamAssistChange(e.target.checked)}
                aria-label="下游设备边界微窗"
                className="accent-[var(--accent)] w-4 h-4 shrink-0"
              />
            </label>
          </div>

          <div className="grid grid-cols-2 gap-2.5 sm:gap-3 text-xs">
            <div className="p-3 rounded-xl border border-subtle bg-surface2">
              <label className="block font-semibold text-primary mb-1.5">JIT 瞬时窗口（秒）</label>
              <input
                type="number"
                min={3}
                max={10}
                value={jitWindowSec}
                onChange={(e) => onJitWindowChange(Number(e.target.value))}
                className="w-full h-10 sm:h-8 px-2.5 rounded-lg border border-subtle bg-surface1 font-mono text-base sm:text-xs text-primary focus:outline-none focus:border-[var(--accent)]"
              />
            </div>

            <div className="p-3 rounded-xl border border-subtle bg-surface2">
              <label className="block font-semibold text-primary mb-1.5">失败冷却退避（秒）</label>
              <input
                type="number"
                min={30}
                max={3600}
                value={cooldownSec}
                onChange={(e) => onCooldownChange(Number(e.target.value))}
                className="w-full h-10 sm:h-8 px-2.5 rounded-lg border border-subtle bg-surface1 font-mono text-base sm:text-xs text-primary focus:outline-none focus:border-[var(--accent)]"
              />
            </div>
          </div>

          <div className="text-[11px] text-secondary font-mono flex flex-wrap items-center justify-between gap-2 pt-1 border-t border-subtle/60">
            <span>
              {p2pReport?.runtime?.lastError
                ? `最近状态异常: ${redactInlineSensitive(p2pReport.runtime.lastError, privacyMask)}`
                : p2pReport?.runtime?.updatedAt
                  ? `最近守护收敛: ${p2pReport.runtime.updatedAt}`
                  : '调整上述防线参数后，点击页面保存按钮即刻热下发'}
            </span>
          </div>
        </div>
      )}
    </div>
  );
};

import React from 'react';
import {
  AlertTriangle,
  Ban,
  CheckCircle2,
  Flame,
  Lock,
  ShieldAlert,
  ShieldCheck,
} from 'lucide-react';
import { Badge, Button, SectionCard, formatBytes } from '../../../ui';
import { FirewallOverviewResponse } from '../../types';
import { BanScopeFilter, fmtNum, maskDisplayIP, RuleTabKey } from './firewallHelpers';

export interface FirewallOverviewSectionProps {
  overview: FirewallOverviewResponse | null;
  supported: boolean;
  kernelActive: boolean;
  autostartEnabled: boolean;
  drifted: boolean;
  acting: boolean;
  isDisabledAll: boolean;
  privacyMask: boolean;
  modeInput: 'standard' | 'minimal';
  onSelectMode: (mode: 'standard' | 'minimal') => void;
  onApplyAndReload: () => void;
  onOpenDisableConfirm: () => void;
  onJumpToTab: (tab: RuleTabKey, scope?: BanScopeFilter) => void;
}

export const FirewallOverviewSection: React.FC<FirewallOverviewSectionProps> = ({
  overview,
  supported,
  kernelActive,
  autostartEnabled,
  drifted,
  acting,
  isDisabledAll,
  privacyMask,
  modeInput,
  onSelectMode,
  onApplyAndReload,
  onOpenDisableConfirm,
  onJumpToTab,
}) => {
  const stats = overview?.stats;
  const preflight = overview?.preflight;

  const trapPackets =
    (stats?.honeypotTcpV4?.packets || 0) +
    (stats?.honeypotUdpV4?.packets || 0) +
    (stats?.honeypotTcpV6?.packets || 0) +
    (stats?.honeypotUdpV6?.packets || 0);
  const dynamicPackets = (stats?.dynamicV4Blocked?.packets || 0) + (stats?.dynamicV6Blocked?.packets || 0);

  return (
    <>
      {drifted && (
        <div className="rounded-2xl border border-amber-500/35 bg-amber-500/10 p-4 flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-start gap-3 text-xs leading-relaxed text-secondary">
            <AlertTriangle className="w-5 h-5 text-amber-400 shrink-0 mt-0.5" />
            <div>
              <strong className="text-primary">
                {kernelActive ? '检测到内核规则存活但缺少开机自启：' : '检测到自启脚本存在但内核安全表未加载：'}
              </strong>
              {kernelActive
                ? '路由器重启后防火墙加固可能不会自动恢复，建议点击右侧重新下发以注册自启。'
                : '当前网关处于无公网防火墙保护状态，可能因开机早期内核模块未就绪或规则被冲刷导致。'}
            </div>
          </div>
          <Button
            size="sm"
            variant="primary"
            disabled={isDisabledAll}
            onClick={onApplyAndReload}
          >
            {kernelActive ? '补齐自启保护' : '一键恢复内核表'}
          </Button>
        </div>
      )}

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
        <div className="rounded-2xl border border-subtle bg-surface1 p-4 space-y-1">
          <div className="text-[11px] text-muted flex items-center justify-between">
            <span>累计拦截攻击包</span>
            <ShieldAlert className="w-3.5 h-3.5 text-rose-400" />
          </div>
          <div className="text-xl font-bold font-mono tnum text-primary">
            {kernelActive ? `${fmtNum(stats?.totalBlockedPackets)} 次` : '未加载'}
          </div>
          <div className="text-[11px] text-muted truncate">
            {kernelActive
              ? `${formatBytes(stats?.totalBlockedBytes || 0)} · 永久 ${fmtNum(stats?.foreverBlocked?.packets)} / 动态 ${fmtNum(dynamicPackets)} / 诱捕 ${fmtNum(trapPackets)}`
              : '启用后将实时统计全网公网扫描拦截战果'}
          </div>
        </div>

        <button
          type="button"
          onClick={() => onJumpToTab('bans', 'dynamic_v4')}
          className="text-left rounded-2xl border border-subtle bg-surface1 hover:border-accent/40 transition-colors p-4 space-y-1 cursor-pointer"
        >
          <div className="text-[11px] text-muted flex items-center justify-between">
            <span>动态关押扫描器</span>
            <Flame className="w-3.5 h-3.5 text-amber-400" />
          </div>
          <div className="text-xl font-bold font-mono tnum text-primary">
            {kernelActive ? `${stats?.dynamicV4Count || 0} / ${stats?.dynamicV6Count || 0}` : '0 / 0'}
          </div>
          <div className="text-[11px] text-muted truncate">
            IPv4 / IPv6 活跃封禁 · 命中诱捕自动关 {overview?.config?.banTimeoutDays || 7} 天
          </div>
        </button>

        <button
          type="button"
          onClick={() => onJumpToTab('bans', 'forever')}
          className="text-left rounded-2xl border border-subtle bg-surface1 hover:border-accent/40 transition-colors p-4 space-y-1 cursor-pointer"
        >
          <div className="text-[11px] text-muted flex items-center justify-between">
            <span>永久威胁黑段</span>
            <Ban className="w-3.5 h-3.5 text-rose-400" />
          </div>
          <div className="text-xl font-bold font-mono tnum text-primary">
            {kernelActive ? `${stats?.foreverCount || 0} 条` : '19 条预设'}
          </div>
          <div className="text-[11px] text-muted truncate">
            内置恶意扫描段 + 自定义永久封禁网段
          </div>
        </button>

        <button
          type="button"
          onClick={() => onJumpToTab('whitelist')}
          className="text-left rounded-2xl border border-subtle bg-surface1 hover:border-accent/40 transition-colors p-4 space-y-1 cursor-pointer"
        >
          <div className="text-[11px] text-muted flex items-center justify-between">
            <span>防自锁免检护栏</span>
            <Lock className="w-3.5 h-3.5 text-emerald-400" />
          </div>
          <div className="text-xl font-bold font-mono tnum text-primary truncate">
            SSH {preflight?.detectedSSHPorts?.length ? `:${preflight.detectedSSHPorts.join(',')}` : '已保护'}
          </div>
          <div className="text-[11px] text-muted truncate">
            自动放行私网 · Tailscale · 白名单 {kernelActive ? stats?.whitelistCount || 4 : 4} 项
          </div>
        </button>
      </div>

      <SectionCard
        title="安全策略与防自锁预检"
        subtitle="每次启用或热重载均自动迁移保留现有 7 天动态黑名单与自定义白名单"
        icon={<ShieldCheck className="w-4 h-4 text-emerald-400" />}
        collapsible={kernelActive}
        defaultOpen={!kernelActive || drifted}
      >
        <div className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-2.5 text-xs">
            <div className="flex items-start gap-2 rounded-xl border border-emerald-500/20 bg-emerald-500/5 px-3 py-2.5">
              <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
              <div className="text-secondary leading-relaxed">
                <span className="font-semibold text-primary">SSH 端口自动豁免：</span>
                已探测活跃 SSH 端口{' '}
                <code className="font-mono text-emerald-300">
                  {preflight?.detectedSSHPorts?.join(', ') || '22'}
                </code>
                ，不会纳入高危诱捕池。
              </div>
            </div>
            <div className="flex items-start gap-2 rounded-xl border border-emerald-500/20 bg-emerald-500/5 px-3 py-2.5">
              <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
              <div className="text-secondary leading-relaxed">
                <span className="font-semibold text-primary">内网与隧道全放行：</span>
                自动放行 <code className="font-mono">lo</code> / <code className="font-mono">tailscale0</code> /{' '}
                <code className="font-mono">100.64.0.0/10</code> 及 RFC1918 私网
                {preflight?.callerIp ? `（当前来源 ${maskDisplayIP(preflight.callerIp, privacyMask)}）` : ''}。
              </div>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {[
              {
                key: 'standard' as const,
                title: '🛡️ 标准公网护盾（推荐）',
                desc: '永久威胁段拦截 + 高危管理端口诱捕（命中自动关 7 天）+ Ping 限频 + 白名单放行。',
              },
              {
                key: 'minimal' as const,
                title: '🧱 极简黑名单模式',
                desc: '零端口诱捕，仅保留恶意网段 / 手动黑名单拦截与白名单放行，适合公网暴露非常规多端口场景。',
              },
            ].map((item) => {
              const selected = modeInput === item.key;
              return (
                <button
                  key={item.key}
                  type="button"
                  onClick={() => onSelectMode(item.key)}
                  className={`text-left rounded-xl border p-3.5 transition-all cursor-pointer ${
                    selected
                      ? 'border-accent bg-accent/10 shadow-sm'
                      : 'border-subtle bg-surface2/50 hover:border-strong'
                  }`}
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-xs font-semibold text-primary">{item.title}</span>
                    {selected && <Badge tone="accent">已选模式</Badge>}
                  </div>
                  <p className="mt-1.5 text-[11px] text-secondary leading-relaxed">{item.desc}</p>
                </button>
              );
            })}
          </div>

          <div className="flex flex-wrap items-center justify-between gap-3 pt-1">
            <div className="flex flex-wrap items-center gap-2.5">
              <Button
                variant="primary"
                disabled={isDisabledAll}
                loading={acting}
                onClick={onApplyAndReload}
              >
                {kernelActive ? '热重载并保留现有黑名单' : '启用防火墙加固'}
              </Button>
              {(kernelActive || autostartEnabled) && (
                <Button
                  variant="danger"
                  disabled={isDisabledAll}
                  onClick={onOpenDisableConfirm}
                >
                  禁用并移除规则
                </Button>
              )}
            </div>
            {!supported && (
              <span className="text-xs text-muted">提示：nftables 护盾仅适用于 Linux / OpenWrt 网关。</span>
            )}
          </div>
        </div>
      </SectionCard>
    </>
  );
};

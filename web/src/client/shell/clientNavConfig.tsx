import React from 'react';
import {
  Activity,
  Download,
  FileText,
  HeartPulse,
  Network,
  RefreshCw,
  RotateCw,
  ShieldAlert,
  ShieldCheck,
  Terminal,
  Wrench,
  Zap,
} from 'lucide-react';
import { Button, CommandItem, NavGroupConfig, StatusDot } from '../../ui';
import { getEngineDisplayName, getStatusDNS } from '../pages/adguard/adguardHelpers';
import { ClientStatusResponse } from '../types';

export const CLIENT_TABS = ['dash', 'sb', 'dns', 'audit', 'dm', 'net', 'logs', 'sys'] as const;
export type ClientTab = (typeof CLIENT_TABS)[number];

export const MOBILE_PRIMARY_TABS: readonly ClientTab[] = ['dash', 'sb', 'dns', 'audit'];

export interface TsSwapBannerState {
  active: boolean;
  phase: string;
  message: string;
  timedOut: boolean;
}

export function buildClientNavGroups(status?: ClientStatusResponse | null): NavGroupConfig<ClientTab>[] {
  // 遵循「常态零绿点、仅异常微标提醒」规范：健康运行时选项卡视觉完全统一对称
  const sbBadge =
    status && status.singbox.installed && !status.singbox.running ? (
      <StatusDot tone="danger" />
    ) : undefined;
  const dmBadge = status?.daemon?.staleBinary ? <StatusDot tone="warn" /> : undefined;
  const dns = getStatusDNS(status);
  const dnsEngineLabel = getEngineDisplayName(dns?.activeEngine, dns?.activeEngineLabel);
  const dnsBadge =
    dns && dns.installed && dns.enabled && !dns.dnsHealthy ? (
      <StatusDot tone="danger" />
    ) : undefined;

  return [
    {
      title: '运行与核心',
      items: [
        {
          key: 'dash',
          label: '总览与监控',
          shortLabel: '总览',
          desc: '核心服务运行状态与一键运维操作',
          icon: Activity,
        },
        {
          key: 'sb',
          label: 'sing-box',
          shortLabel: '核心',
          desc: '智能分流开关、策略组节点选择测速、模式切换与内核控制',
          icon: Zap,
          badge: sbBadge,
        },
        {
          key: 'dns',
          label: '防劫持 DNS',
          shortLabel: 'DNS',
          desc: dns?.installed && dns?.activeEngine
            ? `当前引擎：${dnsEngineLabel} · 加密防劫持、防误伤暂停与内网重写`
            : 'SmartDNS / AdGuard Home 加密防劫持、防误伤暂停与内网域名重写',
          icon: ShieldCheck,
          badge: dnsBadge,
        },
        {
          key: 'audit',
          label: '行为与审计',
          shortLabel: '审计',
          desc: '局域网异常流量识别、AI 研判与一键封禁',
          icon: ShieldAlert,
        },
        {
          key: 'dm',
          label: '看门狗自愈',
          shortLabel: '看门狗',
          desc: '自动巡检保活、订阅同步与故障切换配置',
          icon: HeartPulse,
          badge: dmBadge,
        },
      ],
    },
    {
      title: '代理与网络',
      items: [
        {
          key: 'net',
          label: '网络与组网',
          shortLabel: '组网',
          desc: 'Tailscale 异地子网组网与 nftables 防火墙加固',
          icon: Network,
        },
      ],
    },
    {
      title: '运维与日志',
      items: [
        {
          key: 'logs',
          label: '系统日志',
          shortLabel: '日志',
          desc: '查看守护进程、事件与 Web 审计日志',
          icon: FileText,
        },
        {
          key: 'sys',
          label: '系统维护',
          shortLabel: '运维',
          desc: '全局加速、源码编辑、加密备份与自更新',
          icon: Wrench,
        },
      ],
    },
  ];
}

export function buildClientExtraCommands(
  requestAction: (name: string, params?: Record<string, unknown>, confirmMsg?: string) => void,
  onOpenConsole: () => void,
): CommandItem[] {
  return [
    {
      id: 'act-sb-restart',
      label: '重启 sing-box 代理核心',
      hint: 'singctl',
      group: '快捷操作',
      icon: <RotateCw className="w-3.5 h-3.5" />,
      keywords: 'restart singbox proxy core',
      onSelect: () => requestAction('sb-restart'),
    },
    {
      id: 'act-sb-gen',
      label: '更新订阅并生成最新 sing-box 配置',
      hint: 'sync',
      group: '快捷操作',
      icon: <Download className="w-3.5 h-3.5" />,
      keywords: 'gen subscribe update config',
      onSelect: () => requestAction('sb-gen'),
    },
    {
      id: 'act-dm-restart',
      label: '重启看门狗守护进程',
      hint: 'daemon',
      group: '快捷操作',
      icon: <HeartPulse className="w-3.5 h-3.5" />,
      keywords: 'watchdog daemon restart',
      onSelect: () => requestAction('dm-restart'),
    },
    {
      id: 'act-dns-restart',
      label: '重启当前防劫持 DNS 引擎',
      hint: 'dns',
      group: '快捷操作',
      icon: <ShieldCheck className="w-3.5 h-3.5" />,
      keywords: 'dns smartdns adguard doh restart',
      onSelect: () => requestAction('dns-restart'),
    },
    {
      id: 'act-open-console',
      label: '打开任务执行终端控制台',
      hint: 'console',
      group: '快捷操作',
      icon: <Terminal className="w-3.5 h-3.5" />,
      keywords: 'terminal console log task',
      onSelect: onOpenConsole,
    },
  ];
}

export const ClientStatusPill: React.FC<{
  status: ClientStatusResponse;
  onOpenGatewayMode?: () => void;
}> = ({ status, onOpenGatewayMode }) => {
  const workMode = status.gateway?.effectiveWorkMode;
  const isAudit = workMode === 'audit';
  const pillHealthy = status.singbox.running;
  const modeText = status.singbox.running
    ? isAudit
      ? '审计模式'
      : '代理模式'
    : isAudit
      ? '审计已停'
      : '内核已停';
  return (
    <div className="hidden md:flex items-center gap-2 text-xs font-mono text-slate-400">
      <button
        type="button"
        onClick={onOpenGatewayMode}
        title="点击前往「网关模式」切换审计模式 / 代理模式"
        className="flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-slate-900 hover:bg-slate-800/90 border border-slate-800 hover:border-slate-700 transition-colors cursor-pointer"
      >
        <StatusDot tone={pillHealthy ? 'ok' : 'danger'} pulse={status.singbox.running} />
        <span className="text-slate-400">网关</span>
        <span className={pillHealthy ? 'text-emerald-400 font-semibold' : 'text-rose-400 font-semibold'}>
          {modeText}
        </span>
      </button>
      <div className="hidden lg:flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-slate-900 border border-slate-800">
        <span className="text-slate-400">看门狗</span>
        <span className={status.daemon.running ? 'text-emerald-400 font-semibold' : 'text-slate-300 font-semibold'}>
          {status.daemon.running ? '守护中' : '未运行'}
        </span>
      </div>
      {status.host.lanIP && (
        <div className="hidden xl:flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-slate-900 border border-slate-800">
          <span className="text-slate-400">地址</span>
          <span className="text-slate-200 font-semibold">{status.host.lanIP}</span>
        </div>
      )}
    </div>
  );
};

export interface ClientTopbarBannersProps {
  status?: ClientStatusResponse | null;
  busy: boolean;
  tsSwapBanner: TsSwapBannerState | null;
  restartingBanner: boolean;
  restartTimedOut: boolean;
  onRepollTailscale: () => void;
  onDismissTsBanner: () => void;
  onReloadPage: () => void;
  onRestartDaemon: () => void;
}

export const ClientTopbarBanners: React.FC<ClientTopbarBannersProps> = ({
  status,
  busy,
  tsSwapBanner,
  restartingBanner,
  restartTimedOut,
  onRepollTailscale,
  onDismissTsBanner,
  onReloadPage,
  onRestartDaemon,
}) => (
  <>
    {tsSwapBanner && (
      <div
        className={`rounded-xl border px-4 py-2.5 text-xs flex flex-wrap items-center justify-between gap-2 ${
          tsSwapBanner.timedOut
            ? 'border-amber-500/35 bg-amber-500/10 text-amber-200'
            : 'border-sky-500/35 bg-sky-500/10 text-sky-200'
        }`}
      >
        <div className="flex items-center gap-2">
          <RefreshCw className={`w-4 h-4 shrink-0 ${tsSwapBanner.timedOut ? '' : 'animate-spin'}`} />
          <span>{tsSwapBanner.message}</span>
        </div>
        {tsSwapBanner.timedOut && (
          <div className="flex items-center gap-2">
            <Button size="xs" variant="secondary" onClick={onRepollTailscale}>
              重新检测
            </Button>
            <Button size="xs" variant="ghost" onClick={onDismissTsBanner}>
              关闭
            </Button>
          </div>
        )}
      </div>
    )}
    {restartingBanner && (
      <div
        className={`rounded-xl border px-4 py-2.5 text-xs flex flex-wrap items-center justify-between gap-2 ${
          restartTimedOut
            ? 'border-amber-500/35 bg-amber-500/10 text-amber-200'
            : 'border-emerald-500/30 bg-emerald-500/10 text-emerald-300'
        }`}
      >
        <div className="flex items-center gap-2">
          <RefreshCw className={`w-4 h-4 shrink-0 ${restartTimedOut ? '' : 'animate-spin'}`} />
          <span>
            {restartTimedOut
              ? '服务重启等待超时，若新版进程已完成启动，可点击右侧按钮手动重连刷新。'
              : '程序已完成自我更新并正在平滑重启 Web 服务，恢复后将自动刷新加载最新版本…'}
          </span>
        </div>
        <Button size="xs" variant="secondary" onClick={onReloadPage}>
          立即重连 / 刷新页面
        </Button>
      </div>
    )}
    {status?.daemon?.staleBinary && (
      <div className="rounded-xl border border-amber-500/30 bg-amber-500/10 px-4 py-2.5 flex flex-wrap items-center justify-between gap-2 text-xs">
        <span className="text-amber-200">
          检测到看门狗守护进程仍在运行旧版本二进制 ({status.daemon.daemonVersion || '未知'} →{' '}
          {status.singctlVersion})，建议重启看门狗使其加载新特性。
        </span>
        <Button size="xs" variant="secondary" loading={busy} onClick={onRestartDaemon}>
          立即重启看门狗
        </Button>
      </div>
    )}
  </>
);

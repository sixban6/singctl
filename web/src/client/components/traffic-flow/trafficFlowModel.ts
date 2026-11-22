import { useEffect, useState } from 'react';
import {
  ClientHealthResponse,
  ClientStatusResponse,
  SbProxiesSnapshot,
} from '../../types';

export type HoverBranch = 'lan' | 'cn' | 'proxy' | null;

// 桌面端单画布全景 SVG 路径常量（DNS 净网 + 智能分流 + 三车道合一）
export const D_SEG_1 = 'M 136 128 L 196 128';
export const D_SEG_2 = 'M 304 128 L 366 128';
export const D_LANE_LAN = 'M 492 110 C 576 110, 616 48, 708 48';
export const D_LANE_CN = 'M 492 128 L 708 128';
export const D_LANE_PROXY = 'M 492 146 C 576 146, 616 208, 708 208';

// 手机竖屏单画布纵向 SVG 路径常量
export const M_SEG_1 = 'M 180 64 L 180 90';
export const M_SEG_2 = 'M 180 148 L 180 174';
export const M_LANE_LAN = 'M 156 236 C 156 268, 62 264, 62 300';
export const M_LANE_CN = 'M 180 236 L 180 300';
export const M_LANE_PROXY = 'M 204 236 C 204 268, 298 264, 298 300';

export const ROSE = '#fb7185';
export const ROSE_SOFT = 'rgba(244,63,94,0.16)';
export const ROSE_BORDER = 'rgba(251,113,133,0.5)';

export function truncateLabel(text: string, maxLen: number): string {
  if (!text) return '';
  return text.length > maxLen ? `${text.slice(0, maxLen - 1)}…` : text;
}

export function usePrefersReducedMotion(): boolean {
  const [reduced, setReduced] = useState(false);
  useEffect(() => {
    if (typeof window === 'undefined' || !window.matchMedia) return;
    const mq = window.matchMedia('(prefers-reduced-motion: reduce)');
    setReduced(mq.matches);
    const handler = (e: MediaQueryListEvent) => setReduced(e.matches);
    mq.addEventListener?.('change', handler);
    return () => mq.removeEventListener?.('change', handler);
  }, []);
  return reduced;
}

export interface TrafficFlowViewModel {
  sbRunning: boolean;
  dmRunning: boolean;
  failoverActive: boolean;
  tsConnected: boolean;
  gwRoleText: string;
  lanIP: string;
  dnsFault: boolean;
  proxyFault: boolean;
  coreFault: boolean;
  cnFault: boolean;
  cnLaneFlowing: boolean;
  proxyLaneFlowing: boolean;
  modeTitle: string;
  modeTone: string;
  shieldTone: string;
  shieldFill: string;
  shieldPillText: string;
  primaryNodeLabel: string;
  primaryDelayColor: string;
  headerBadgeTone: 'danger' | 'warn' | 'ok';
  headerBadgeText: string;
  animate: boolean;
}

export function deriveTrafficFlowViewModel(
  status: ClientStatusResponse,
  proxySnap: SbProxiesSnapshot | null,
  health: ClientHealthResponse | null,
  reducedMotion: boolean,
): TrafficFlowViewModel {
  const sbRunning = Boolean(status.singbox?.running);
  const proxyMode = (proxySnap?.mode || 'rule').toLowerCase();
  const isGlobal = sbRunning && proxyMode === 'global';
  const isDirect = sbRunning && proxyMode === 'direct';

  const dmRunning = Boolean(status.daemon?.running);
  const failoverActive = dmRunning && (status.daemon?.activeFailoverCount || 0) > 0;
  const dmHealthFailed =
    dmRunning &&
    Boolean(status.daemon?.lastHealthAt) &&
    status.daemon?.lastHealthOK === false;
  const manualHealthFailed = health !== null && !health.healthy;

  const tsConnected =
    Boolean(status.tailscale?.running) && status.tailscale?.state === 'Running';
  const gwRoleText = status.gateway?.mode === 'side' ? '旁路由' : '主路由';

  const dns = status.dns ?? status.adguard;
  const dnsEngine = dns?.activeEngine || (dns?.installed ? 'adguard' : 'singbox');
  const externalExpectedButDown = Boolean(
    dnsEngine !== 'singbox' && dns?.installed && dns?.enabled && !dns?.dnsHealthy,
  );
  const dnsFault =
    externalExpectedButDown ||
    (health !== null && !health.dnsOK) ||
    (sbRunning && dmHealthFailed);
  const externalHealthy =
    !dnsFault &&
    dnsEngine !== 'singbox' &&
    Boolean(dns?.dnsHealthy && dns?.singboxLinked);
  const singboxDnsHealthy = !dnsFault && dnsEngine === 'singbox' && sbRunning;

  const primaryNodeMeta =
    proxySnap?.primaryNode && proxySnap?.nodes
      ? proxySnap.nodes[proxySnap.primaryNode]
      : undefined;
  const primaryNodeTimedOut = Boolean(
    sbRunning &&
      !isDirect &&
      primaryNodeMeta?.tested &&
      (primaryNodeMeta.delay ?? 0) <= 0,
  );

  const proxyFault =
    !sbRunning ||
    (!isDirect && (dmHealthFailed || manualHealthFailed || primaryNodeTimedOut));

  const coreFault = !sbRunning || dmHealthFailed || manualHealthFailed;

  const cnFault = !sbRunning || dnsFault;
  const cnLaneFlowing = !cnFault && !isGlobal;
  const proxyLaneFlowing = sbRunning && !isDirect && !proxyFault;

  const modeTitle = !sbRunning
    ? '核心已停止'
    : coreFault
      ? '网络异常'
      : isGlobal
        ? '全局代理'
        : isDirect
          ? '全局直连'
          : '智能分流';

  const modeTone = coreFault
    ? ROSE
    : isGlobal
      ? '#818cf8'
      : isDirect
        ? '#fbbf24'
        : '#34d399';

  const shieldTone = dnsFault
    ? ROSE
    : externalHealthy || singboxDnsHealthy
      ? '#34d399'
      : '#38bdf8';
  const shieldFill = dnsFault
    ? ROSE_SOFT
    : externalHealthy || singboxDnsHealthy
      ? 'rgba(16,185,129,0.18)'
      : 'rgba(56,189,248,0.15)';
  const shieldPillText = dnsFault
    ? externalExpectedButDown
      ? dnsEngine === 'smartdns'
        ? 'SmartDNS 异常'
        : 'AdGuard 异常'
      : '解析异常'
    : externalHealthy
      ? dnsEngine === 'smartdns'
        ? 'SmartDNS 加速'
        : 'AdGuard 净化'
      : singboxDnsHealthy
        ? 'sing-box 净化'
        : '加密防抢答';

  const primaryNodeLabel = !sbRunning
    ? '核心已停止'
    : isDirect
      ? '已切直连'
      : primaryNodeTimedOut
        ? `${truncateLabel(proxySnap?.primaryNode || '节点', 7)} · 超时`
        : proxyFault
          ? '连接中断'
          : proxySnap?.primaryNode
            ? `${truncateLabel(proxySnap.primaryNode, 10)}${
                proxySnap.primaryDelay && proxySnap.primaryDelay > 0
                  ? ` · ${proxySnap.primaryDelay}ms`
                  : ''
              }`
            : '自动选线中';

  const primaryDelayColor = proxyFault
    ? ROSE
    : isDirect
      ? '#64748b'
      : proxySnap?.primaryDelay && proxySnap.primaryDelay > 300
        ? '#fbbf24'
        : '#34d399';

  const headerBadgeTone: 'danger' | 'warn' | 'ok' =
    coreFault || dnsFault || proxyFault ? 'danger' : failoverActive ? 'warn' : 'ok';
  const headerBadgeText = !sbRunning
    ? '核心已停止'
    : dnsFault && !proxyFault
      ? 'DNS 解析异常'
      : proxyFault
        ? '出口连接异常'
        : failoverActive
          ? '容灾守护中'
          : modeTitle;

  return {
    sbRunning,
    dmRunning,
    failoverActive,
    tsConnected,
    gwRoleText,
    lanIP: status.host?.lanIP || '',
    dnsFault,
    proxyFault,
    coreFault,
    cnFault,
    cnLaneFlowing,
    proxyLaneFlowing,
    modeTitle,
    modeTone,
    shieldTone,
    shieldFill,
    shieldPillText,
    primaryNodeLabel,
    primaryDelayColor,
    headerBadgeTone,
    headerBadgeText,
    animate: !reducedMotion,
  };
}

import React, { useEffect, useState } from 'react';
import { GitBranch } from 'lucide-react';
import { Badge, SectionCard } from '../../ui';
import {
  ClientHealthResponse,
  ClientStatusResponse,
  SbProxiesSnapshot,
} from '../types';

export interface TrafficFlowCardProps {
  status: ClientStatusResponse;
  proxySnap: SbProxiesSnapshot | null;
  health?: ClientHealthResponse | null;
  onNavigate: (tab: string, sub?: string) => void;
}

type HoverBranch = 'lan' | 'cn' | 'proxy' | null;

// 桌面端单画布全景 SVG 路径常量（DNS 净网 + 智能分流 + 三车道合一）
const D_SEG_1 = 'M 136 128 L 196 128';
const D_SEG_2 = 'M 304 128 L 366 128';
const D_LANE_LAN = 'M 492 110 C 576 110, 616 48, 708 48';
const D_LANE_CN = 'M 492 128 L 708 128';
const D_LANE_PROXY = 'M 492 146 C 576 146, 616 208, 708 208';

// 手机竖屏单画布纵向 SVG 路径常量
const M_SEG_1 = 'M 180 64 L 180 90';
const M_SEG_2 = 'M 180 148 L 180 174';
const M_LANE_LAN = 'M 156 236 C 156 268, 62 264, 62 300';
const M_LANE_CN = 'M 180 236 L 180 300';
const M_LANE_PROXY = 'M 204 236 C 204 268, 298 264, 298 300';

const ROSE = '#fb7185';
const ROSE_SOFT = 'rgba(244,63,94,0.16)';
const ROSE_BORDER = 'rgba(251,113,133,0.5)';

function truncateLabel(text: string, maxLen: number): string {
  if (!text) return '';
  return text.length > maxLen ? `${text.slice(0, maxLen - 1)}…` : text;
}

function usePrefersReducedMotion(): boolean {
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

export const TrafficFlowCard: React.FC<TrafficFlowCardProps> = ({
  status,
  proxySnap,
  health = null,
  onNavigate,
}) => {
  const [hovered, setHovered] = useState<HoverBranch>(null);
  const reducedMotion = usePrefersReducedMotion();

  const sbRunning = Boolean(status.singbox?.running);
  const proxyMode = (proxySnap?.mode || 'rule').toLowerCase();
  const isGlobal = sbRunning && proxyMode === 'global';
  const isDirect = sbRunning && proxyMode === 'direct';

  const dmRunning = Boolean(status.daemon?.running);
  const failoverActive = dmRunning && (status.daemon?.activeFailoverCount || 0) > 0;
  // 看门狗仅在已完成至少一次真实巡检 (lastHealthAt 非空) 且判定失败时才视为异常
  const dmHealthFailed =
    dmRunning &&
    Boolean(status.daemon?.lastHealthAt) &&
    status.daemon?.lastHealthOK === false;
  const manualHealthFailed = health !== null && !health.healthy;

  const tsConnected =
    Boolean(status.tailscale?.running) && status.tailscale?.state === 'Running';
  const gwRoleText = status.gateway?.mode === 'side' ? '旁路由' : '主路由';

  // ── 分段故障判定（哪段断了红哪段） ──
  const aghExpectedButDown = Boolean(
    status.adguard?.installed && status.adguard?.enabled && !status.adguard?.dnsHealthy,
  );
  const dnsFault =
    aghExpectedButDown ||
    (health !== null && !health.dnsOK) ||
    (sbRunning && dmHealthFailed);
  const aghHealthy =
    !dnsFault && Boolean(status.adguard?.dnsHealthy && status.adguard?.singboxLinked);

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

  // 海外隧道断流：核心未运行 / 巡检失败 / 当前主节点实测超时
  const proxyFault =
    !sbRunning ||
    (!isDirect && (dmHealthFailed || manualHealthFailed || primaryNodeTimedOut));

  // 中枢核心故障：核心停止 或 巡检判定整体断流
  const coreFault = !sbRunning || dmHealthFailed || manualHealthFailed;

  // 国内车道状态：核心停止或 DNS 挂掉时受阻变红；全局代理时变暗旁路
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

  const shieldTone = dnsFault ? ROSE : aghHealthy ? '#34d399' : '#38bdf8';
  const shieldFill = dnsFault
    ? ROSE_SOFT
    : aghHealthy
      ? 'rgba(16,185,129,0.18)'
      : 'rgba(56,189,248,0.15)';
  const shieldPillText = dnsFault
    ? aghExpectedButDown
      ? 'AdGuard 异常'
      : '解析异常'
    : aghHealthy
      ? 'AdGuard 净化'
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

  const animate = !reducedMotion;

  const dimOpacity = (branch: Exclude<HoverBranch, null>) =>
    hovered && hovered !== branch ? 0.26 : 1;

  return (
    <SectionCard
      title="全屋流量路径"
      icon={<GitBranch className="w-4 h-4" />}
      badge={
        <Badge tone={headerBadgeTone} dot pulse={!reducedMotion}>
          {headerBadgeText}
        </Badge>
      }
      actions={
        <span className="hidden sm:inline text-[11px] text-slate-500">
          点击节点可直达对应设置
        </span>
      }
      noPadding
    >
      <div className="relative px-2 sm:px-4 py-2 sm:py-3 select-none overflow-hidden">
        {/* ═══════════════ 桌面与平板端：单画布全景 SVG (>= md) ═══════════════ */}
        <svg
          viewBox="0 0 940 256"
          className="hidden md:block w-full h-auto"
          role="img"
          aria-label="全屋流量路径全景图"
        >
          <defs>
            <pattern id="sc-flow-grid" width="22" height="22" patternUnits="userSpaceOnUse">
              <circle cx="2" cy="2" r="1" fill="rgba(148,163,184,0.08)" />
            </pattern>
            <radialGradient id="sc-prism-glow" cx="50%" cy="50%" r="50%">
              <stop offset="0%" stopColor={modeTone} stopOpacity="0.2" />
              <stop offset="100%" stopColor={modeTone} stopOpacity="0" />
            </radialGradient>
            <linearGradient id="sc-cn-sheath" x1="0%" y1="0%" x2="100%" y2="0%">
              <stop offset="0%" stopColor="#10b981" stopOpacity="0.16" />
              <stop offset="100%" stopColor="#34d399" stopOpacity="0.22" />
            </linearGradient>
            <linearGradient id="sc-proxy-sheath" x1="0%" y1="0%" x2="100%" y2="0%">
              <stop offset="0%" stopColor="#6366f1" stopOpacity="0.22" />
              <stop offset="100%" stopColor="#06b6d4" stopOpacity="0.26" />
            </linearGradient>
            <linearGradient id="sc-proxy-core" x1="0%" y1="0%" x2="100%" y2="0%">
              <stop offset="0%" stopColor="#818cf8" />
              <stop offset="100%" stopColor="#22d3ee" />
            </linearGradient>
            <filter id="sc-particle-glow" x="-80%" y="-80%" width="260%" height="260%">
              <feGaussianBlur stdDeviation="2.4" result="blur" />
              <feMerge>
                <feMergeNode in="blur" />
                <feMergeNode in="SourceGraphic" />
              </feMerge>
            </filter>
          </defs>

          {/* 点阵底纹与核心光晕 */}
          <rect x="8" y="6" width="924" height="244" rx="18" fill="url(#sc-flow-grid)" />
          <circle cx="429" cy="128" r="88" fill="url(#sc-prism-glow)" />

          {/* ── 前段连线：家里设备 -> 净网盾 -> 智能分流 ── */}
          <path
            d={D_SEG_1}
            stroke={!sbRunning ? ROSE_SOFT : 'rgba(56,189,248,0.14)'}
            strokeWidth="8"
            strokeLinecap="round"
            fill="none"
          />
          <path
            d={D_SEG_1}
            stroke={!sbRunning ? ROSE : '#38bdf8'}
            strokeWidth="2.2"
            strokeDasharray={!sbRunning ? '4 5' : undefined}
            strokeOpacity="0.8"
            fill="none"
          />

          <path
            d={D_SEG_2}
            stroke={dnsFault || !sbRunning ? ROSE_SOFT : 'rgba(52,211,153,0.14)'}
            strokeWidth="8"
            strokeLinecap="round"
            fill="none"
          />
          <path
            d={D_SEG_2}
            stroke={dnsFault || !sbRunning ? ROSE : '#34d399'}
            strokeWidth="2.2"
            strokeDasharray={dnsFault || !sbRunning ? '4 5' : undefined}
            strokeOpacity="0.82"
            fill="none"
          />

          {animate && sbRunning && (
            <>
              <circle r="3.3" fill="#38bdf8" filter="url(#sc-particle-glow)">
                <animateMotion path={D_SEG_1} dur="1.3s" repeatCount="indefinite" />
              </circle>
              {!dnsFault && (
                <circle r="3.3" fill="#34d399" filter="url(#sc-particle-glow)">
                  <animateMotion
                    path={D_SEG_2}
                    dur="1.3s"
                    begin="0.45s"
                    repeatCount="indefinite"
                  />
                </circle>
              )}
            </>
          )}

          {/* ── 出口分支 1：内网 · 组网 (上轨：即使外网断了，局域网依然青色畅通) ── */}
          <g style={{ opacity: dimOpacity('lan'), transition: 'opacity 0.2s' }}>
            <path d={D_LANE_LAN} stroke="rgba(34,211,238,0.12)" strokeWidth="7" fill="none" />
            <path
              d={D_LANE_LAN}
              stroke="#22d3ee"
              strokeWidth={hovered === 'lan' ? '2.8' : '2'}
              strokeDasharray="6 5"
              strokeOpacity="0.82"
              fill="none"
            />
            {animate && (
              <circle r="3.2" fill="#22d3ee" filter="url(#sc-particle-glow)">
                <animateMotion path={D_LANE_LAN} dur="2s" repeatCount="indefinite" />
              </circle>
            )}

            <g
              transform="translate(708, 18)"
              className="cursor-pointer"
              onMouseEnter={() => setHovered('lan')}
              onMouseLeave={() => setHovered(null)}
              onClick={() => onNavigate('net', 'ts')}
            >
              <rect
                width="210"
                height="60"
                rx="16"
                fill="#0b1325"
                stroke={hovered === 'lan' ? '#22d3ee' : 'rgba(148,163,184,0.16)'}
                strokeWidth="1.4"
              />
              <g transform="translate(30, 30)">
                <rect
                  x="-15"
                  y="-15"
                  width="30"
                  height="30"
                  rx="9"
                  fill="rgba(34,211,238,0.12)"
                />
                <rect
                  x="-8"
                  y="-7"
                  width="16"
                  height="6"
                  rx="1.5"
                  fill="none"
                  stroke="#22d3ee"
                  strokeWidth="1.5"
                />
                <rect
                  x="-8"
                  y="1"
                  width="16"
                  height="6"
                  rx="1.5"
                  fill="none"
                  stroke="#22d3ee"
                  strokeWidth="1.5"
                />
                <circle cx="-4.5" cy="-4" r="1" fill="#22d3ee" />
                <circle cx="-4.5" cy="4" r="1" fill="#22d3ee" />
              </g>
              <text x="56" y="26" fill="#f8fafc" fontSize="13" fontWeight="600">
                内网 · 组网
              </text>
              <circle cx="60" cy="42" r="3" fill={tsConnected ? '#34d399' : '#38bdf8'} />
              <text x="68" y="45.5" fill="#94a3b8" fontSize="11">
                {tsConnected ? 'Tailscale 已通' : '局域网直达'}
              </text>
            </g>
          </g>

          {/* ── 出口分支 2：国内快车道 (中轨：加密 DoH + 宽带满速直连) ── */}
          <g style={{ opacity: dimOpacity('cn'), transition: 'opacity 0.2s' }}>
            <path
              d={D_LANE_CN}
              stroke={cnFault ? ROSE_SOFT : cnLaneFlowing ? 'url(#sc-cn-sheath)' : 'transparent'}
              strokeWidth="10"
              strokeLinecap="round"
              fill="none"
            />
            <path
              d={D_LANE_CN}
              stroke={cnFault ? ROSE : cnLaneFlowing ? '#10b981' : '#334155'}
              strokeWidth={hovered === 'cn' ? '2.8' : '2.2'}
              strokeDasharray={cnLaneFlowing ? undefined : '4 5'}
              strokeOpacity={cnFault || cnLaneFlowing ? 0.88 : 0.45}
              fill="none"
            />
            {animate && cnLaneFlowing && (
              <>
                <circle r="3.4" fill="#34d399" filter="url(#sc-particle-glow)">
                  <animateMotion path={D_LANE_CN} dur="1.85s" repeatCount="indefinite" />
                </circle>
                <circle r="2.8" fill="#6ee7b7">
                  <animateMotion
                    path={D_LANE_CN}
                    dur="1.85s"
                    begin="0.92s"
                    repeatCount="indefinite"
                  />
                </circle>
              </>
            )}

            {/* 中轨胶囊微标：🔒 DoH */}
            <g
              transform="translate(600, 128)"
              className="cursor-pointer"
              onClick={(e) => {
                e.stopPropagation();
                onNavigate('dns');
              }}
            >
              <title>国内纯 IP 加密 DoH · 本地缓存就近解析（点击管理）</title>
              <rect
                x="-32"
                y="-11"
                width="64"
                height="22"
                rx="11"
                fill="#0b1325"
                stroke={
                  cnFault
                    ? ROSE_BORDER
                    : cnLaneFlowing
                      ? 'rgba(52,211,153,0.5)'
                      : '#334155'
                }
                strokeWidth="1.2"
              />
              <g transform="translate(-17, 0)">
                <rect
                  x="-3.5"
                  y="-0.5"
                  width="7"
                  height="5.2"
                  rx="1"
                  fill="none"
                  stroke={cnFault ? ROSE : cnLaneFlowing ? '#34d399' : '#64748b'}
                  strokeWidth="1.2"
                />
                <path
                  d="M -2 -0.5 V -2.3 C -2 -3.8 2 -3.8 2 -2.3 V -0.5"
                  fill="none"
                  stroke={cnFault ? ROSE : cnLaneFlowing ? '#34d399' : '#64748b'}
                  strokeWidth="1.2"
                />
              </g>
              <text
                x="6"
                y="3.8"
                textAnchor="middle"
                fill={cnFault ? ROSE : cnLaneFlowing ? '#6ee7b7' : '#64748b'}
                fontSize="10"
                fontWeight="600"
              >
                DoH
              </text>
            </g>

            <g
              transform="translate(708, 98)"
              className="cursor-pointer"
              onMouseEnter={() => setHovered('cn')}
              onMouseLeave={() => setHovered(null)}
              onClick={() => onNavigate('sb')}
            >
              <rect
                width="210"
                height="60"
                rx="16"
                fill="#0b1325"
                stroke={
                  cnFault
                    ? ROSE_BORDER
                    : hovered === 'cn'
                      ? '#34d399'
                      : cnLaneFlowing
                        ? 'rgba(52,211,153,0.24)'
                        : 'rgba(148,163,184,0.12)'
                }
                strokeWidth="1.4"
              />
              <g transform="translate(30, 30)">
                <rect
                  x="-15"
                  y="-15"
                  width="30"
                  height="30"
                  rx="9"
                  fill={
                    cnFault
                      ? ROSE_SOFT
                      : cnLaneFlowing
                        ? 'rgba(16,185,129,0.14)'
                        : 'rgba(51,65,85,0.3)'
                  }
                />
                <path
                  d="M 1 -9 L -7 1 H 0 L -1 9 L 7 -1 H 0 Z"
                  fill="none"
                  stroke={cnFault ? ROSE : cnLaneFlowing ? '#34d399' : '#64748b'}
                  strokeWidth="1.6"
                  strokeLinejoin="round"
                />
              </g>
              <text
                x="56"
                y="26"
                fill={cnLaneFlowing || cnFault ? '#f8fafc' : '#94a3b8'}
                fontSize="13"
                fontWeight="600"
              >
                国内直连
              </text>
              <circle
                cx="60"
                cy="42"
                r="3"
                fill={cnFault ? ROSE : cnLaneFlowing ? '#34d399' : '#475569'}
              />
              <text x="68" y="45.5" fill={cnFault ? ROSE : '#94a3b8'} fontSize="11">
                {!sbRunning
                  ? '核心已停止'
                  : dnsFault
                    ? 'DNS 解析受阻'
                    : cnLaneFlowing
                      ? '就近 IP · 宽带满速'
                      : '全局代理旁路'}
              </text>
            </g>
          </g>

          {/* ── 出口分支 3：海外 · AI 加密护套隧道 (断网时变玫瑰红断续虚线、光点停摆) ── */}
          <g style={{ opacity: dimOpacity('proxy'), transition: 'opacity 0.2s' }}>
            <path
              d={D_LANE_PROXY}
              stroke={
                proxyFault
                  ? ROSE_SOFT
                  : proxyLaneFlowing
                    ? 'url(#sc-proxy-sheath)'
                    : 'rgba(51,65,85,0.2)'
              }
              strokeWidth="13"
              strokeLinecap="round"
              fill="none"
            />
            <path
              d={D_LANE_PROXY}
              stroke={
                proxyFault
                  ? 'rgba(251,113,133,0.35)'
                  : proxyLaneFlowing
                    ? 'rgba(129,140,248,0.4)'
                    : '#334155'
              }
              strokeWidth="13"
              strokeDasharray="2 6"
              strokeLinecap="round"
              fill="none"
            />
            <path
              d={D_LANE_PROXY}
              stroke={
                proxyFault ? ROSE : proxyLaneFlowing ? 'url(#sc-proxy-core)' : '#475569'
              }
              strokeWidth={hovered === 'proxy' ? '3' : '2.2'}
              strokeDasharray={proxyFault ? '5 5' : undefined}
              strokeOpacity={proxyFault || proxyLaneFlowing ? 0.95 : 0.45}
              fill="none"
            />
            {animate && proxyLaneFlowing && (
              <>
                <circle r="3.6" fill="#22d3ee" filter="url(#sc-particle-glow)">
                  <animateMotion path={D_LANE_PROXY} dur="2s" repeatCount="indefinite" />
                </circle>
                <circle r="3.2" fill="#a78bfa" filter="url(#sc-particle-glow)">
                  <animateMotion
                    path={D_LANE_PROXY}
                    dur="2s"
                    begin="1s"
                    repeatCount="indefinite"
                  />
                </circle>
              </>
            )}

            {/* 隧道胶囊微标 1：🔒 零污染 */}
            <g transform="translate(572, 173)">
              <title>远端零污染 DNS 解析 + TLS / Reality 加密隧道</title>
              <rect
                x="-35"
                y="-11"
                width="70"
                height="22"
                rx="11"
                fill="#0b1325"
                stroke={
                  proxyFault
                    ? ROSE_BORDER
                    : proxyLaneFlowing
                      ? 'rgba(129,140,248,0.55)'
                      : '#334155'
                }
                strokeWidth="1.2"
              />
              <g transform="translate(-21, 0)">
                <rect
                  x="-3.5"
                  y="-0.5"
                  width="7"
                  height="5.2"
                  rx="1"
                  fill="none"
                  stroke={proxyFault ? ROSE : proxyLaneFlowing ? '#a5b4fc' : '#64748b'}
                  strokeWidth="1.2"
                />
                <path
                  d="M -2 -0.5 V -2.3 C -2 -3.8 2 -3.8 2 -2.3 V -0.5"
                  fill="none"
                  stroke={proxyFault ? ROSE : proxyLaneFlowing ? '#a5b4fc' : '#64748b'}
                  strokeWidth="1.2"
                />
              </g>
              <text
                x="6"
                y="3.8"
                textAnchor="middle"
                fill={proxyFault ? ROSE : proxyLaneFlowing ? '#c7d2fe' : '#64748b'}
                fontSize="10"
                fontWeight="600"
              >
                零污染
              </text>
            </g>

            {/* 隧道微标 2：看门狗心电守护徽标 */}
            <g
              transform="translate(642, 199)"
              className="cursor-pointer"
              onClick={(e) => {
                e.stopPropagation();
                onNavigate('dm');
              }}
            >
              <title>
                {!dmRunning
                  ? '看门狗未运行（点击管理）'
                  : proxyFault
                    ? '检测到出口断流，点击查看看门狗自愈状态'
                    : failoverActive
                      ? '看门狗已自动切备（点击查看）'
                      : '看门狗故障自动换线守护中'}
              </title>
              {(failoverActive || (dmRunning && proxyFault)) && animate && (
                <circle
                  r="15"
                  fill="none"
                  stroke={proxyFault ? ROSE : '#fbbf24'}
                  strokeWidth="1.4"
                >
                  <animate attributeName="r" values="11;18" dur="1.6s" repeatCount="indefinite" />
                  <animate
                    attributeName="opacity"
                    values="0.8;0"
                    dur="1.6s"
                    repeatCount="indefinite"
                  />
                </circle>
              )}
              <circle
                r="11.5"
                fill="#0b1325"
                stroke={
                  proxyFault
                    ? ROSE
                    : !dmRunning
                      ? '#475569'
                      : failoverActive
                        ? '#fbbf24'
                        : 'rgba(52,211,153,0.6)'
                }
                strokeWidth="1.3"
              />
              <path
                d="M -5 0 H -2 L -0.8 -3.5 L 1 3.5 L 2.3 0 H 5"
                fill="none"
                stroke={
                  proxyFault
                    ? ROSE
                    : !dmRunning
                      ? '#64748b'
                      : failoverActive
                        ? '#fbbf24'
                        : '#34d399'
                }
                strokeWidth="1.4"
                strokeLinecap="round"
                strokeLinejoin="round"
              />
            </g>

            <g
              transform="translate(708, 178)"
              className="cursor-pointer"
              onMouseEnter={() => setHovered('proxy')}
              onMouseLeave={() => setHovered(null)}
              onClick={() => onNavigate('sb', 'nodes')}
            >
              <rect
                width="210"
                height="60"
                rx="16"
                fill="#0b1325"
                stroke={
                  proxyFault
                    ? ROSE
                    : hovered === 'proxy'
                      ? '#818cf8'
                      : proxyLaneFlowing
                        ? 'rgba(129,140,248,0.34)'
                        : 'rgba(148,163,184,0.12)'
                }
                strokeWidth="1.5"
              />
              <g transform="translate(30, 30)">
                <rect
                  x="-15"
                  y="-15"
                  width="30"
                  height="30"
                  rx="9"
                  fill={
                    proxyFault
                      ? ROSE_SOFT
                      : proxyLaneFlowing
                        ? 'rgba(99,102,241,0.16)'
                        : 'rgba(51,65,85,0.3)'
                  }
                />
                <circle
                  r="8"
                  fill="none"
                  stroke={proxyFault ? ROSE : proxyLaneFlowing ? '#818cf8' : '#64748b'}
                  strokeWidth="1.5"
                />
                <ellipse
                  rx="3.8"
                  ry="8"
                  fill="none"
                  stroke={proxyFault ? ROSE : proxyLaneFlowing ? '#818cf8' : '#64748b'}
                  strokeWidth="1.2"
                />
                <line
                  x1="-8"
                  y1="0"
                  x2="8"
                  y2="0"
                  stroke={proxyFault ? ROSE : proxyLaneFlowing ? '#818cf8' : '#64748b'}
                  strokeWidth="1.2"
                />
                <path
                  d="M 8 -9 L 9 -6.5 L 11.5 -5.5 L 9 -4.5 L 8 -2 L 7 -4.5 L 4.5 -5.5 L 7 -6.5 Z"
                  fill={proxyFault ? ROSE : proxyLaneFlowing ? '#22d3ee' : '#64748b'}
                />
              </g>
              <text
                x="56"
                y="25"
                fill={proxyLaneFlowing || proxyFault ? '#f8fafc' : '#94a3b8'}
                fontSize="13"
                fontWeight="600"
              >
                海外 · AI
              </text>
              <circle cx="60" cy="42" r="3" fill={primaryDelayColor} />
              <text x="68" y="45.5" fill={primaryDelayColor} fontSize="11" fontWeight="500">
                {primaryNodeLabel}
              </text>
            </g>
          </g>

          {/* ── 阶段 1：家里设备 ── */}
          <g
            transform="translate(22, 80)"
            className="cursor-pointer"
            onClick={() => onNavigate('net')}
          >
            <title>查看主路由 / 旁路由网关模式</title>
            <rect
              width="114"
              height="96"
              rx="20"
              fill="#0b1325"
              stroke="rgba(56,189,248,0.28)"
              strokeWidth="1.5"
            />
            <g transform="translate(57, 33)">
              <rect
                x="-20"
                y="-11"
                width="24"
                height="16"
                rx="2.5"
                fill="none"
                stroke="#38bdf8"
                strokeWidth="1.6"
              />
              <line
                x1="-24"
                y1="8"
                x2="7"
                y2="8"
                stroke="#38bdf8"
                strokeWidth="1.8"
                strokeLinecap="round"
              />
              <rect
                x="9"
                y="-8"
                width="11"
                height="17"
                rx="2.5"
                fill="#0b1325"
                stroke="#34d399"
                strokeWidth="1.6"
              />
              <circle cx="14.5" cy="6" r="0.9" fill="#34d399" />
            </g>
            <text x="57" y="64" textAnchor="middle" fill="#f8fafc" fontSize="13" fontWeight="600">
              家里设备
            </text>
            <rect x="27" y="72" width="60" height="16" rx="8" fill="rgba(56,189,248,0.12)" />
            <text x="57" y="83" textAnchor="middle" fill="#38bdf8" fontSize="10.5" fontWeight="500">
              {gwRoleText}
            </text>
          </g>

          {/* ── 阶段 2：净网防劫持盾 (DNS 异常时直接标红警示) ── */}
          <g
            transform="translate(196, 80)"
            className="cursor-pointer"
            onClick={() => onNavigate('dns')}
          >
            <title>管理 AdGuard Home 防劫持 DNS 与广告过滤</title>
            <rect
              width="108"
              height="96"
              rx="22"
              fill="#0d172a"
              stroke={shieldTone}
              strokeWidth="1.6"
            />
            <g transform="translate(54, 32)">
              <path
                d="M 0 -13 L 11 -8 V 1 C 11 8 6 12.5 0 14.5 C -6 12.5 -11 8 -11 1 V -8 Z"
                fill={shieldFill}
                stroke={shieldTone}
                strokeWidth="1.7"
                strokeLinejoin="round"
              />
              {dnsFault ? (
                <path
                  d="M -3.5 -3 L 3.5 4 M 3.5 -3 L -3.5 4"
                  fill="none"
                  stroke={ROSE}
                  strokeWidth="1.8"
                  strokeLinecap="round"
                />
              ) : (
                <path
                  d="M -4 0.5 L -1 3.5 L 4.5 -2.5"
                  fill="none"
                  stroke={shieldTone}
                  strokeWidth="1.8"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                />
              )}
            </g>
            <text x="54" y="64" textAnchor="middle" fill="#f8fafc" fontSize="12.5" fontWeight="600">
              净网防劫持
            </text>
            <rect
              x="16"
              y="72"
              width="76"
              height="16"
              rx="8"
              fill={dnsFault ? ROSE_SOFT : 'rgba(16,185,129,0.12)'}
            />
            <text
              x="54"
              y="83"
              textAnchor="middle"
              fill={shieldTone}
              fontSize="10"
              fontWeight="500"
            >
              {shieldPillText}
            </text>
          </g>

          {/* ── 阶段 3：智能分流一分三路由核 (核心停止或断流时变红) ── */}
          <g
            transform="translate(366, 74)"
            className="cursor-pointer"
            onClick={() => onNavigate('sb')}
          >
            <title>配置 25 项应用智能分流开关（DNS 与流量同步生效）</title>
            {animate && (sbRunning || coreFault) && (
              <rect
                x="-4"
                y="-4"
                width="134"
                height="116"
                rx="26"
                fill="none"
                stroke={modeTone}
                strokeWidth="1.2"
              >
                <animate
                  attributeName="opacity"
                  values="0.45;0.08;0.45"
                  dur={coreFault ? '1.8s' : '3s'}
                  repeatCount="indefinite"
                />
              </rect>
            )}
            <rect
              width="126"
              height="108"
              rx="22"
              fill="#0d172a"
              stroke={modeTone}
              strokeWidth="1.7"
            />
            <g transform="translate(63, 34)">
              <rect
                x="-16"
                y="-15"
                width="32"
                height="30"
                rx="9"
                fill={coreFault ? ROSE_SOFT : 'rgba(52,211,153,0.1)'}
                stroke="rgba(148,163,184,0.2)"
                strokeWidth="1.2"
              />
              <path
                d="M -9 0 C -2 0, 0 -7.5, 7.5 -7.5"
                fill="none"
                stroke="#22d3ee"
                strokeWidth="1.7"
                strokeLinecap="round"
              />
              <path
                d="M -9 0 L 8 0"
                fill="none"
                stroke={cnFault ? ROSE : '#34d399'}
                strokeWidth="1.7"
                strokeLinecap="round"
              />
              <path
                d="M -9 0 C -2 0, 0 7.5, 7.5 7.5"
                fill="none"
                stroke={proxyFault ? ROSE : '#818cf8'}
                strokeWidth="1.7"
                strokeLinecap="round"
              />
              <circle cx="-9" cy="0" r="2.4" fill="#f8fafc" />
              <circle cx="8.5" cy="-7.5" r="2" fill="#22d3ee" />
              <circle cx="8.5" cy="0" r="2" fill={cnFault ? ROSE : '#34d399'} />
              <circle cx="8.5" cy="7.5" r="2" fill={proxyFault ? ROSE : '#818cf8'} />
            </g>
            <text x="63" y="71" textAnchor="middle" fill="#f8fafc" fontSize="13.5" fontWeight="700">
              {modeTitle}
            </text>
            <rect
              x="23"
              y="80"
              width="80"
              height="17"
              rx="8.5"
              fill={coreFault ? ROSE_SOFT : 'rgba(148,163,184,0.1)'}
            />
            <text
              x="63"
              y="91.5"
              textAnchor="middle"
              fill={coreFault ? ROSE : '#94a3b8'}
              fontSize="10.5"
            >
              {!sbRunning ? '点击去启动' : coreFault ? '连通性受阻' : '25 项应用分流'}
            </text>
          </g>
        </svg>

        {/* ═══════════════ 手机竖屏端：单画布纵向全景 SVG (< md) ═══════════════ */}
        <svg
          viewBox="0 0 360 400"
          className="md:hidden w-full h-auto"
          role="img"
          aria-label="全屋流量路径全景图"
        >
          {/* 前段纵向连线 */}
          <path
            d={M_SEG_1}
            stroke={!sbRunning ? ROSE : '#38bdf8'}
            strokeWidth="2.2"
            strokeDasharray={!sbRunning ? '4 4' : undefined}
            strokeOpacity="0.8"
            fill="none"
          />
          <path
            d={M_SEG_2}
            stroke={dnsFault || !sbRunning ? ROSE : '#34d399'}
            strokeWidth="2.2"
            strokeDasharray={dnsFault || !sbRunning ? '4 4' : undefined}
            strokeOpacity="0.82"
            fill="none"
          />

          {/* 三条分流弧线 */}
          <path
            d={M_LANE_LAN}
            stroke="#22d3ee"
            strokeWidth="2"
            strokeDasharray="5 4"
            fill="none"
          />
          <path
            d={M_LANE_CN}
            stroke={cnFault ? ROSE_SOFT : cnLaneFlowing ? 'rgba(16,185,129,0.18)' : 'transparent'}
            strokeWidth="8"
            strokeLinecap="round"
            fill="none"
          />
          <path
            d={M_LANE_CN}
            stroke={cnFault ? ROSE : cnLaneFlowing ? '#10b981' : '#334155'}
            strokeWidth="2.2"
            strokeDasharray={cnLaneFlowing ? undefined : '4 4'}
            fill="none"
          />
          <path
            d={M_LANE_PROXY}
            stroke={
              proxyFault
                ? ROSE_SOFT
                : proxyLaneFlowing
                  ? 'rgba(129,140,248,0.24)'
                  : 'transparent'
            }
            strokeWidth="9"
            strokeLinecap="round"
            fill="none"
          />
          <path
            d={M_LANE_PROXY}
            stroke={proxyFault ? ROSE : proxyLaneFlowing ? '#818cf8' : '#475569'}
            strokeWidth="2.2"
            strokeDasharray={proxyFault ? '4 4' : undefined}
            fill="none"
          />

          {animate && (
            <>
              {sbRunning && (
                <>
                  <circle r="2.8" fill="#38bdf8">
                    <animateMotion path={M_SEG_1} dur="1.1s" repeatCount="indefinite" />
                  </circle>
                  {!dnsFault && (
                    <circle r="2.8" fill="#34d399">
                      <animateMotion
                        path={M_SEG_2}
                        dur="1.1s"
                        begin="0.35s"
                        repeatCount="indefinite"
                      />
                    </circle>
                  )}
                </>
              )}
              <circle r="2.8" fill="#22d3ee">
                <animateMotion path={M_LANE_LAN} dur="1.9s" repeatCount="indefinite" />
              </circle>
              {cnLaneFlowing && (
                <circle r="3" fill="#34d399">
                  <animateMotion path={M_LANE_CN} dur="1.7s" repeatCount="indefinite" />
                </circle>
              )}
              {proxyLaneFlowing && (
                <circle r="3.2" fill="#22d3ee">
                  <animateMotion path={M_LANE_PROXY} dur="1.9s" repeatCount="indefinite" />
                </circle>
              )}
            </>
          )}

          {/* 手机中轨与右轨加密微标 */}
          <g transform="translate(180, 268)" onClick={() => onNavigate('dns')}>
            <rect
              x="-22"
              y="-9"
              width="44"
              height="18"
              rx="9"
              fill="#0b1325"
              stroke={cnFault ? ROSE_BORDER : 'rgba(52,211,153,0.45)'}
            />
            <text
              x="0"
              y="3.5"
              textAnchor="middle"
              fill={cnFault ? ROSE : '#6ee7b7'}
              fontSize="9.5"
              fontWeight="600"
            >
              🔒DoH
            </text>
          </g>
          <g transform="translate(262, 268)" onClick={() => onNavigate('dm')}>
            <rect
              x="-26"
              y="-9"
              width="52"
              height="18"
              rx="9"
              fill="#0b1325"
              stroke={
                proxyFault
                  ? ROSE_BORDER
                  : failoverActive
                    ? '#fbbf24'
                    : 'rgba(129,140,248,0.5)'
              }
            />
            <text
              x="0"
              y="3.5"
              textAnchor="middle"
              fill={proxyFault ? ROSE : failoverActive ? '#fbbf24' : '#c7d2fe'}
              fontSize="9.5"
              fontWeight="600"
            >
              🔒零污染
            </text>
          </g>

          {/* 1. 顶：家里设备 */}
          <g transform="translate(104, 10)" onClick={() => onNavigate('net')}>
            <rect
              width="152"
              height="54"
              rx="15"
              fill="#0b1325"
              stroke="rgba(56,189,248,0.3)"
              strokeWidth="1.4"
            />
            <text x="76" y="25" textAnchor="middle" fill="#f8fafc" fontSize="13" fontWeight="600">
              家里设备
            </text>
            <text x="76" y="42" textAnchor="middle" fill="#38bdf8" fontSize="10.5">
              {gwRoleText} · {status.host?.lanIP || '网关'}
            </text>
          </g>

          {/* 2. 净网防劫持盾 */}
          <g transform="translate(112, 90)" onClick={() => onNavigate('dns')}>
            <rect
              width="136"
              height="58"
              rx="16"
              fill="#0d172a"
              stroke={shieldTone}
              strokeWidth="1.5"
            />
            <text x="68" y="26" textAnchor="middle" fill="#f8fafc" fontSize="12.5" fontWeight="600">
              🛡️ 净网防劫持
            </text>
            <text x="68" y="44" textAnchor="middle" fill={shieldTone} fontSize="10">
              {shieldPillText}
            </text>
          </g>

          {/* 3. 智能分流棱镜 */}
          <g transform="translate(100, 174)" onClick={() => onNavigate('sb')}>
            <rect
              width="160"
              height="62"
              rx="17"
              fill="#0d172a"
              stroke={modeTone}
              strokeWidth="1.6"
            />
            <text x="80" y="28" textAnchor="middle" fill="#f8fafc" fontSize="13" fontWeight="700">
              {modeTitle}
            </text>
            <text
              x="80"
              y="46"
              textAnchor="middle"
              fill={coreFault ? ROSE : '#94a3b8'}
              fontSize="10"
            >
              {!sbRunning ? '点击启动内核' : coreFault ? '连通性受阻' : '25 项应用分流'}
            </text>
          </g>

          {/* 4. 底三列出口：内网 / 国内 / 海外 */}
          <g transform="translate(8, 300)" onClick={() => onNavigate('net', 'ts')}>
            <rect
              width="108"
              height="88"
              rx="15"
              fill="#0b1325"
              stroke="rgba(34,211,238,0.28)"
              strokeWidth="1.3"
            />
            <circle cx="54" cy="24" r="8.5" fill="rgba(34,211,238,0.15)" />
            <circle cx="54" cy="24" r="3.2" fill="#22d3ee" />
            <text x="54" y="51" textAnchor="middle" fill="#f8fafc" fontSize="12" fontWeight="600">
              内网组网
            </text>
            <text x="54" y="70" textAnchor="middle" fill="#94a3b8" fontSize="10">
              {tsConnected ? '已组网' : '局域网直达'}
            </text>
          </g>

          <g transform="translate(126, 300)" onClick={() => onNavigate('sb')}>
            <rect
              width="108"
              height="88"
              rx="15"
              fill="#0b1325"
              stroke={
                cnFault
                  ? ROSE_BORDER
                  : cnLaneFlowing
                    ? 'rgba(52,211,153,0.3)'
                    : 'rgba(148,163,184,0.14)'
              }
              strokeWidth="1.3"
            />
            <circle cx="54" cy="24" r="8.5" fill={cnFault ? ROSE_SOFT : 'rgba(16,185,129,0.15)'} />
            <circle
              cx="54"
              cy="24"
              r="3.2"
              fill={cnFault ? ROSE : cnLaneFlowing ? '#34d399' : '#64748b'}
            />
            <text x="54" y="51" textAnchor="middle" fill="#f8fafc" fontSize="12" fontWeight="600">
              国内直连
            </text>
            <text
              x="54"
              y="70"
              textAnchor="middle"
              fill={cnFault ? ROSE : '#94a3b8'}
              fontSize="10"
            >
              {!sbRunning ? '已停止' : dnsFault ? '解析受阻' : cnLaneFlowing ? '宽带满速' : '全局旁路'}
            </text>
          </g>

          <g transform="translate(244, 300)" onClick={() => onNavigate('sb', 'nodes')}>
            <rect
              width="108"
              height="88"
              rx="15"
              fill="#0b1325"
              stroke={
                proxyFault
                  ? ROSE
                  : proxyLaneFlowing
                    ? 'rgba(129,140,248,0.4)'
                    : 'rgba(148,163,184,0.14)'
              }
              strokeWidth="1.4"
            />
            <circle
              cx="54"
              cy="24"
              r="8.5"
              fill={proxyFault ? ROSE_SOFT : 'rgba(99,102,241,0.18)'}
            />
            <circle cx="54" cy="24" r="3.2" fill={primaryDelayColor} />
            <text x="54" y="51" textAnchor="middle" fill="#f8fafc" fontSize="12" fontWeight="600">
              海外 · AI
            </text>
            <text
              x="54"
              y="70"
              textAnchor="middle"
              fill={primaryDelayColor}
              fontSize="10"
              fontWeight="500"
            >
              {truncateLabel(primaryNodeLabel, 11)}
            </text>
          </g>
        </svg>
      </div>
    </SectionCard>
  );
};

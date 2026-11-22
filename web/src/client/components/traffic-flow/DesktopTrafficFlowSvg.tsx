import React from 'react';
import { DesktopStageNodes } from './DesktopStageNodes';
import {
  D_LANE_CN,
  D_LANE_LAN,
  D_LANE_PROXY,
  D_SEG_1,
  D_SEG_2,
  HoverBranch,
  ROSE,
  ROSE_BORDER,
  ROSE_SOFT,
  TrafficFlowViewModel,
} from './trafficFlowModel';

export interface DesktopTrafficFlowSvgProps {
  vm: TrafficFlowViewModel;
  hovered: HoverBranch;
  onHoverChange: (next: HoverBranch) => void;
  onNavigate: (tab: string, sub?: string) => void;
}

export const DesktopTrafficFlowSvg: React.FC<DesktopTrafficFlowSvgProps> = ({
  vm,
  hovered,
  onHoverChange,
  onNavigate,
}) => {
  const {
    sbRunning,
    dmRunning,
    failoverActive,
    tsConnected,
    dnsFault,
    proxyFault,
    cnFault,
    cnLaneFlowing,
    proxyLaneFlowing,
    modeTone,
    primaryNodeLabel,
    primaryDelayColor,
    animate,
  } = vm;

  const dimOpacity = (branch: Exclude<HoverBranch, null>) =>
    hovered && hovered !== branch ? 0.26 : 1;

  return (
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

      {/* ── 出口分支 1：内网 · 组网 (上轨) ── */}
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
          onMouseEnter={() => onHoverChange('lan')}
          onMouseLeave={() => onHoverChange(null)}
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

      {/* ── 出口分支 2：国内快车道 (中轨) ── */}
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
          onMouseEnter={() => onHoverChange('cn')}
          onMouseLeave={() => onHoverChange(null)}
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

      {/* ── 出口分支 3：海外 · AI 加密护套隧道 ── */}
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
          stroke={proxyFault ? ROSE : proxyLaneFlowing ? 'url(#sc-proxy-core)' : '#475569'}
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
          onMouseEnter={() => onHoverChange('proxy')}
          onMouseLeave={() => onHoverChange(null)}
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

      <DesktopStageNodes vm={vm} onNavigate={onNavigate} />
    </svg>
  );
};

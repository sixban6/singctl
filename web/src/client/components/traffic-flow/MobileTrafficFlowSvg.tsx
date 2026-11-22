import React from 'react';
import {
  M_LANE_CN,
  M_LANE_LAN,
  M_LANE_PROXY,
  M_SEG_1,
  M_SEG_2,
  ROSE,
  ROSE_BORDER,
  ROSE_SOFT,
  TrafficFlowViewModel,
  truncateLabel,
} from './trafficFlowModel';

export interface MobileTrafficFlowSvgProps {
  vm: TrafficFlowViewModel;
  onNavigate: (tab: string, sub?: string) => void;
}

export const MobileTrafficFlowSvg: React.FC<MobileTrafficFlowSvgProps> = ({ vm, onNavigate }) => {
  const {
    sbRunning,
    failoverActive,
    tsConnected,
    gwRoleText,
    lanIP,
    dnsFault,
    proxyFault,
    coreFault,
    cnFault,
    cnLaneFlowing,
    proxyLaneFlowing,
    modeTitle,
    modeTone,
    shieldTone,
    shieldPillText,
    primaryNodeLabel,
    primaryDelayColor,
    animate,
  } = vm;

  return (
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
          {gwRoleText} · {lanIP || '网关'}
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
  );
};

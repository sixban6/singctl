import React from 'react';
import { ROSE, ROSE_SOFT, TrafficFlowViewModel } from './trafficFlowModel';

export interface DesktopStageNodesProps {
  vm: TrafficFlowViewModel;
  onNavigate: (tab: string, sub?: string) => void;
}

export const DesktopStageNodes: React.FC<DesktopStageNodesProps> = ({ vm, onNavigate }) => {
  const {
    sbRunning,
    gwRoleText,
    dnsFault,
    proxyFault,
    coreFault,
    cnFault,
    modeTitle,
    modeTone,
    shieldTone,
    shieldFill,
    shieldPillText,
    animate,
  } = vm;

  return (
    <>
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
        <title>管理三引擎防劫持 DNS 与广告过滤</title>
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
    </>
  );
};

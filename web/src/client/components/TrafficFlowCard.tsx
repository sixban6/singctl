import React, { useState } from 'react';
import { GitBranch } from 'lucide-react';
import { Badge, SectionCard } from '../../ui';
import {
  ClientHealthResponse,
  ClientStatusResponse,
  SbProxiesSnapshot,
} from '../types';
import { DesktopTrafficFlowSvg } from './traffic-flow/DesktopTrafficFlowSvg';
import { MobileTrafficFlowSvg } from './traffic-flow/MobileTrafficFlowSvg';
import {
  deriveTrafficFlowViewModel,
  HoverBranch,
  usePrefersReducedMotion,
} from './traffic-flow/trafficFlowModel';

export interface TrafficFlowCardProps {
  status: ClientStatusResponse;
  proxySnap: SbProxiesSnapshot | null;
  health?: ClientHealthResponse | null;
  onNavigate: (tab: string, sub?: string) => void;
}

export const TrafficFlowCard: React.FC<TrafficFlowCardProps> = ({
  status,
  proxySnap,
  health = null,
  onNavigate,
}) => {
  const [hovered, setHovered] = useState<HoverBranch>(null);
  const reducedMotion = usePrefersReducedMotion();
  const vm = deriveTrafficFlowViewModel(status, proxySnap, health, reducedMotion);

  return (
    <SectionCard
      title="全屋流量路径"
      icon={<GitBranch className="w-4 h-4" />}
      badge={
        <Badge tone={vm.headerBadgeTone} dot pulse={!reducedMotion}>
          {vm.headerBadgeText}
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
        <DesktopTrafficFlowSvg
          vm={vm}
          hovered={hovered}
          onHoverChange={setHovered}
          onNavigate={onNavigate}
        />
        <MobileTrafficFlowSvg vm={vm} onNavigate={onNavigate} />
      </div>
    </SectionCard>
  );
};

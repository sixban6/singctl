import React, { useEffect, useState } from 'react';
import { Globe, Share2 } from 'lucide-react';
import { SegmentedTabs } from '../../../ui';
import { ClientStatusResponse } from '../../types';
import { TailscalePage } from './TailscalePage';
import { HomeDomainSection } from './homedomain/HomeDomainSection';

export type MeshDomainView = 'ts' | 'home';

export interface MeshAndDomainSectionProps {
  status: ClientStatusResponse | null;
  busy: boolean;
  privacyMask: boolean;
  initialView?: MeshDomainView;
  onViewChange?: (view: MeshDomainView) => void;
  onAction: (name: string, params?: Record<string, unknown>, confirmMsg?: string) => void;
  onRefreshStatus?: () => void;
}

export const MeshAndDomainSection: React.FC<MeshAndDomainSectionProps> = ({
  status,
  busy,
  privacyMask,
  initialView = 'ts',
  onViewChange,
  onAction,
  onRefreshStatus,
}) => {
  const [view, setView] = useState<MeshDomainView>(initialView);

  useEffect(() => {
    setView(initialView);
  }, [initialView]);

  const handleSelectView = (next: MeshDomainView) => {
    setView(next);
    onViewChange?.(next);
  };

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <SegmentedTabs
          value={view}
          onChange={(k) => handleSelectView(k as MeshDomainView)}
          items={[
            {
              key: 'ts',
              label: 'Tailscale 异地组网',
              icon: <Share2 className="w-3.5 h-3.5" />,
            },
            {
              key: 'home',
              label: '本地域名 (.home)',
              icon: <Globe className="w-3.5 h-3.5" />,
            },
          ]}
        />
        <span className="text-[11px] text-secondary">
          {view === 'ts'
            ? '跨公网点对点直连、子网穿透与接入控制'
            : '统一的 .home 内网短域名映射与跨 Tailscale Split-DNS 解析'}
        </span>
      </div>

      {view === 'ts' ? (
        <TailscalePage
          status={status}
          busy={busy}
          privacyMask={privacyMask}
          onAction={onAction}
          onRefreshStatus={onRefreshStatus}
        />
      ) : (
        <HomeDomainSection
          busy={busy}
          privacyMask={privacyMask}
          onRefreshStatus={onRefreshStatus}
        />
      )}
    </div>
  );
};

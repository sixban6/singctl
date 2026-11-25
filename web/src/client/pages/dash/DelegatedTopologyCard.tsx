import React from 'react';
import { ArrowRight, ExternalLink, Network, Router, Share2 } from 'lucide-react';
import { Badge, Button, SectionCard } from '../../../ui';
import { ClientStatusResponse } from '../../types';

export interface DelegatedTopologyCardProps {
  status: ClientStatusResponse;
  onNavigate: (tab: string, sub?: string) => void;
}

export const DelegatedTopologyCard: React.FC<DelegatedTopologyCardProps> = ({
  status,
  onNavigate,
}) => {
  const gw = status.gateway;
  if (!gw || gw.effectiveWorkMode !== 'delegated') return null;

  const sideIP = (gw.sideRouterIP || '').trim();
  const mainIP = status.host?.lanIP || '主路由';

  return (
    <SectionCard
      title="主旁协同托管总览（纯网关直通）"
      icon={<Share2 className="w-4 h-4" />}
      subtitle="主路由仅承担 WAN 拨号、交换端口、Wi-Fi 与 VLAN 隔离，不运行本地代理内核"
      badge={
        <Badge tone="ok" dot>
          主路由零负担直通
        </Badge>
      }
      actions={
        <div className="flex items-center gap-2 flex-wrap">
          <Button
            size="xs"
            variant="secondary"
            icon={<Network className="w-3.5 h-3.5" />}
            onClick={() => onNavigate('net', 'vlan')}
          >
            管理子网 / Wi-Fi 分流
          </Button>
          {sideIP && (
            <a
              href={`http://${sideIP}:8090`}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-1 px-2.5 py-1 rounded-lg bg-cyan-500/15 hover:bg-cyan-500/25 border border-cyan-500/35 text-cyan-300 text-xs font-medium transition-colors"
            >
              <span>旁路由分流面板</span>
              <ExternalLink className="w-3 h-3" />
            </a>
          )}
        </div>
      }
    >
      <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3">
        <div className="flex-1 rounded-xl border border-subtle bg-surface2 p-3 flex items-center gap-3">
          <div className="w-9 h-9 rounded-xl bg-emerald-500/12 border border-emerald-500/30 flex items-center justify-center shrink-0">
            <Router className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="min-w-0">
            <div className="text-xs font-semibold text-primary">本机（主路由纯直通）</div>
            <div className="text-[11px] font-mono text-secondary truncate">
              {mainIP} · 硬件/内核直转 · sing-box 已省内存停用
            </div>
          </div>
        </div>

        <ArrowRight className="w-4 h-4 text-cyan-400 shrink-0 self-center rotate-90 sm:rotate-0" />

        <div className="flex-1 rounded-xl border border-cyan-500/30 bg-cyan-500/8 p-3 flex items-center justify-between gap-3">
          <div className="min-w-0">
            <div className="text-xs font-semibold text-primary">旁路由分流与审计中心</div>
            <div className="text-[11px] font-mono text-cyan-300 truncate">
              {sideIP ? `${sideIP} · 负责科学分流 / AdGuard / 审计` : '尚未绑定旁路由 IP（点右上角配置）'}
            </div>
          </div>
          <Button size="xs" variant="ghost" onClick={() => onNavigate('net', 'gw')}>
            协同设置
          </Button>
        </div>
      </div>
    </SectionCard>
  );
};

import React from 'react';
import { ArrowRightLeft, Laptop, Trash2 } from 'lucide-react';
import { Badge, Button } from '../../../ui';
import {
  AuditRouteRuleDeleteRequest,
  AuditRouteRuleUpsertRequest,
  ClientRoutingReport,
} from '../../types';

export interface SmartRoutingCustomRulesCardProps {
  routing: ClientRoutingReport;
  busy?: boolean;
  onChangeOutbound: (req: AuditRouteRuleUpsertRequest) => void;
  onDeleteRule: (req: AuditRouteRuleDeleteRequest) => void;
}

function matchBadgeLabel(mt?: string): string {
  switch (mt) {
    case 'domain':
      return '精确域名';
    case 'ip_cidr':
      return 'IP/CIDR';
    default:
      return '主域名';
  }
}

export const SmartRoutingCustomRulesCard: React.FC<SmartRoutingCustomRulesCardProps> = ({
  routing,
  busy = false,
  onChangeOutbound,
  onDeleteRule,
}) => {
  const rules = routing.customRules || [];
  if (rules.length === 0) return null;

  const groups = routing.groups || [];
  const directTag = routing.directTag || '#DC';

  return (
    <div className="pt-3 border-t border-subtle space-y-2.5">
      <div className="flex items-center justify-between gap-2 flex-wrap">
        <div className="flex items-center gap-2 text-xs font-semibold text-primary">
          <ArrowRightLeft className="w-3.5 h-3.5 text-accent" />
          <span>审计页快捷定向出口规则 ({rules.length})</span>
        </div>
        <span className="text-[11px] text-muted">
          优先级高于上方内置预设（同时作用于路由与 DNS）
        </span>
      </div>

      <div className="divide-y divide-subtle rounded-xl border border-subtle bg-surface1 overflow-hidden">
        {rules.map((r) => {
          const key = `${r.matchType || 'domain_suffix'}|${r.target}|${r.sourceIp || ''}`;
          return (
            <div
              key={key}
              className="flex flex-col sm:flex-row sm:items-center justify-between gap-2.5 px-3.5 py-2.5 hover:bg-surface2/40 transition-colors"
            >
              <div className="flex items-center gap-1.5 flex-wrap min-w-0">
                <span className="font-mono text-xs font-semibold text-primary break-all">
                  {r.target}
                </span>
                <Badge tone="neutral">{matchBadgeLabel(r.matchType)}</Badge>
                {r.sourceIp && (
                  <Badge tone="accent">
                    <span className="inline-flex items-center gap-1 font-mono">
                      <Laptop className="w-2.5 h-2.5" />
                      {r.sourceIp}
                    </span>
                  </Badge>
                )}
              </div>

              <div className="flex items-center gap-2 shrink-0">
                <select
                  aria-label={`修改 ${r.target} 定向出口`}
                  disabled={busy}
                  value={r.outbound}
                  onChange={(e) => {
                    const nextOut = e.target.value;
                    if (!nextOut || nextOut === r.outbound) return;
                    onChangeOutbound({
                      target: r.target,
                      matchType: r.matchType,
                      outbound: nextOut,
                      sourceIp: r.sourceIp,
                      closeConnections: true,
                    });
                  }}
                  className="sc-input h-8 px-2 text-xs font-mono min-w-[110px]"
                >
                  <option value="direct">直连 {directTag}</option>
                  {groups.map((g) => (
                    <option key={g.tag} value={g.tag}>
                      {g.tag}
                    </option>
                  ))}
                </select>
                <Button
                  size="xs"
                  variant="ghost"
                  disabled={busy}
                  icon={<Trash2 className="w-3.5 h-3.5 text-rose-400" />}
                  onClick={() =>
                    onDeleteRule({
                      target: r.target,
                      matchType: r.matchType,
                      sourceIp: r.sourceIp,
                      closeConnections: true,
                    })
                  }
                  title="移除规则并恢复默认分流"
                >
                  移除
                </Button>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};

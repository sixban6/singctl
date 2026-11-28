import React from 'react';
import { ArrowRightLeft, Laptop, Trash2 } from 'lucide-react';
import { Badge, Button, SlideDrawer } from '../../../ui';
import {
  AuditRouteRuleDeleteRequest,
  AuditRouteRuleUpsertRequest,
  ClientRoutingReport,
} from '../../types';

export interface AuditCustomRoutesDrawerProps {
  open: boolean;
  routingReport: ClientRoutingReport | null;
  busy: boolean;
  onClose: () => void;
  onChangeOutbound: (req: AuditRouteRuleUpsertRequest) => void;
  onDeleteRule: (req: AuditRouteRuleDeleteRequest) => void;
}

function matchTypeLabel(mt?: string): string {
  switch (mt) {
    case 'domain':
      return '精确域名';
    case 'ip_cidr':
      return 'IP / CIDR';
    default:
      return '主域名后缀';
  }
}

export const AuditCustomRoutesDrawer: React.FC<AuditCustomRoutesDrawerProps> = ({
  open,
  routingReport,
  busy,
  onClose,
  onChangeOutbound,
  onDeleteRule,
}) => {
  const rules = routingReport?.customRules || [];
  const groups = routingReport?.groups || [];
  const directTag = routingReport?.directTag || '#DC';

  return (
    <SlideDrawer
      open={open}
      onClose={onClose}
      size="md"
      title={
        <div className="flex items-center gap-2">
          <ArrowRightLeft className="w-4 h-4 text-accent" />
          <span>自定义定向出口规则 ({rules.length})</span>
        </div>
      }
      subtitle="审计页一键固定出口的规则列表 · 支持实时改组或移除并同步 DNS/Route"
    >
      {rules.length === 0 ? (
        <div className="py-12 px-4 text-center text-xs text-muted leading-relaxed">
          暂无自定义定向出口规则。在连接明细中点击「改出口」即可直接为指定域名或设备固定出站节点组，修改后自动热重载并断开旧连接。
        </div>
      ) : (
        <div className="space-y-2.5">
          {rules.map((r) => {
            const key = `${r.matchType || 'domain_suffix'}|${r.target}|${r.sourceIp || ''}`;
            return (
              <div
                key={key}
                className="rounded-xl border border-subtle bg-surface2/60 p-3 flex flex-col sm:flex-row sm:items-center justify-between gap-2.5"
              >
                <div className="min-w-0 space-y-1">
                  <div className="flex items-center gap-1.5 flex-wrap">
                    <span className="font-mono text-xs font-semibold text-primary break-all">
                      {r.target}
                    </span>
                    <Badge tone="neutral">{matchTypeLabel(r.matchType)}</Badge>
                    {r.sourceIp && (
                      <Badge tone="accent">
                        <span className="inline-flex items-center gap-1 font-mono">
                          <Laptop className="w-2.5 h-2.5" />
                          {r.sourceIp}
                        </span>
                      </Badge>
                    )}
                  </div>
                  {r.createdAt && (
                    <div className="text-[10.5px] font-mono text-muted">
                      添加于 {r.createdAt.replace('T', ' ').replace('Z', ' UTC')}
                    </div>
                  )}
                </div>

                <div className="flex items-center gap-2 shrink-0">
                  <select
                    aria-label={`修改 ${r.target} 出口`}
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
                    <option value="direct">直连 ({directTag})</option>
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
                    title="移除该固定出口规则并恢复默认分流"
                  >
                    删除
                  </Button>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </SlideDrawer>
  );
};

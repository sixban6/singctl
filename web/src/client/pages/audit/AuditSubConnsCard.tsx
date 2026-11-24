import React, { useState } from 'react';
import { Activity, Clock, Unplug } from 'lucide-react';
import { Badge, Button, formatBytes as fmtBytes } from '../../../ui';
import { AuditActiveConnDetail } from '../../types';
import { formatCompactRule, formatShortDuration } from './auditFlowModel';
import { fmtBps } from './auditHelpers';

export interface AuditSubConnsCardProps {
  activeConns: number;
  details?: AuditActiveConnDetail[];
  onCloseSingleSubConn: (connId: string, label?: string) => Promise<void> | void;
}

export const AuditSubConnsCard: React.FC<AuditSubConnsCardProps> = ({
  activeConns,
  details,
  onCloseSingleSubConn,
}) => {
  const [closingId, setClosingId] = useState<string | null>(null);
  const list = details || [];

  if (activeConns <= 0 && list.length === 0) {
    return null;
  }

  const handleClose = async (conn: AuditActiveConnDetail) => {
    setClosingId(conn.id);
    try {
      const label = conn.sourcePort ? `:${conn.sourcePort}` : conn.id.slice(0, 8);
      await onCloseSingleSubConn(conn.id, label);
    } finally {
      setClosingId(null);
    }
  };

  return (
    <div className="rounded-xl border border-emerald-500/25 bg-emerald-500/[0.04] p-3.5 space-y-2.5">
      <div className="flex items-center justify-between gap-2">
        <div className="flex items-center gap-1.5 text-xs font-semibold text-primary">
          <Activity className="w-3.5 h-3.5 text-emerald-400" />
          <span>活跃子连接显微镜</span>
          <Badge tone="ok" dot>
            {Math.max(activeConns, list.length)} 条活跃
          </Badge>
        </div>
        {activeConns > list.length && list.length > 0 && (
          <span className="text-[10.5px] text-muted">展示速率最高的前 {list.length} 条</span>
        )}
      </div>

      {list.length === 0 ? (
        <div className="text-[11px] text-muted">
          当前流有 {activeConns} 条活跃句柄，等待下一轮实时采样回传子连接快照…
        </div>
      ) : (
        <div className="space-y-1.5">
          {list.map((c) => {
            const chainText = c.chains && c.chains.length > 0 ? c.chains.join(' → ') : '';
            return (
              <div
                key={c.id}
                className="rounded-lg border border-subtle bg-surface1/80 px-2.5 py-2 flex flex-wrap items-center justify-between gap-2 text-[11px]"
              >
                <div className="min-w-0 flex-1 space-y-1">
                  <div className="flex items-center gap-1.5 flex-wrap font-mono">
                    <span className="text-primary font-semibold">
                      :{c.sourcePort || '?'} → {c.destIp || '*'}
                      {c.destPort ? `:${c.destPort}` : ''}
                    </span>
                    {c.inboundType && (
                      <span className="px-1.5 py-0.2 rounded bg-surface2 border border-subtle text-[10px] text-secondary uppercase">
                        {c.inboundType}
                      </span>
                    )}
                    <span className="inline-flex items-center gap-0.5 text-muted">
                      <Clock className="w-2.5 h-2.5" />
                      {formatShortDuration(c.durationSec)}
                    </span>
                  </div>
                  <div className="flex items-center gap-2 flex-wrap text-[10.5px] text-muted">
                    {chainText && <span className="text-secondary">{chainText}</span>}
                    {c.rule && (
                      <span className="font-mono truncate max-w-[200px]" title={c.rule}>
                        规则: {formatCompactRule(c.rule)}
                      </span>
                    )}
                  </div>
                </div>

                <div className="flex items-center gap-2.5 shrink-0">
                  <div className="text-right font-mono tnum">
                    <div className="text-[11px]">
                      <span className="text-emerald-400 font-semibold">↑{fmtBps(c.uploadBps)}</span>{' '}
                      <span className="text-sky-400">↓{fmtBps(c.downloadBps)}</span>
                    </div>
                    <div className="text-[10px] text-muted">
                      ↑{fmtBytes(c.upload)} / ↓{fmtBytes(c.download)}
                    </div>
                  </div>
                  <Button
                    size="xs"
                    variant="secondary"
                    loading={closingId === c.id}
                    icon={<Unplug className="w-3 h-3" />}
                    onClick={() => void handleClose(c)}
                    title="仅断开这一条子连接"
                  >
                    断开
                  </Button>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
};

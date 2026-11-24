import React from 'react';
import { Bot, CheckSquare, Globe, Laptop, ShieldCheck, Unplug, X } from 'lucide-react';
import { Button } from '../../../ui';

export interface AuditBulkBarProps {
  selectedCount: number;
  selectedActiveCount: number;
  visibleCount: number;
  busy: boolean;
  onSelectAllVisible: () => void;
  onClearSelection: () => void;
  onBlockBatch: (deviceOnly: boolean) => void;
  onWhitelistBatch: () => void;
  onReviewBatch: () => void;
  onCloseBatchConnections: () => void;
}

export const AuditBulkBar: React.FC<AuditBulkBarProps> = ({
  selectedCount,
  selectedActiveCount,
  visibleCount,
  busy,
  onSelectAllVisible,
  onClearSelection,
  onBlockBatch,
  onWhitelistBatch,
  onReviewBatch,
  onCloseBatchConnections,
}) => {
  if (selectedCount === 0) return null;

  return (
    <div className="sticky bottom-3 z-30 mx-3 sm:mx-4 mb-3 rounded-2xl border border-accent/45 bg-slate-900/95 backdrop-blur-xl shadow-2xl px-3.5 py-2.5 flex flex-wrap items-center justify-between gap-2.5 animate-sc-in">
      <div className="flex items-center gap-2.5 text-xs">
        <span className="inline-flex items-center gap-1.5 font-semibold text-primary">
          <CheckSquare className="w-4 h-4 text-accent" />
          已选 <span className="font-mono tnum text-accent">{selectedCount}</span> 条
        </span>
        {selectedCount < visibleCount && (
          <button
            type="button"
            onClick={onSelectAllVisible}
            className="text-accent hover:underline cursor-pointer"
          >
            全选当前可见 ({visibleCount})
          </button>
        )}
        <button
          type="button"
          onClick={onClearSelection}
          className="inline-flex items-center gap-0.5 text-muted hover:text-primary cursor-pointer"
        >
          <X className="w-3.5 h-3.5" />
          清空
        </button>
      </div>

      <div className="flex flex-wrap items-center gap-1.5">
        <Button
          size="xs"
          variant="danger"
          loading={busy}
          icon={<Laptop className="w-3 h-3" />}
          onClick={() => onBlockBatch(true)}
          title="仅对所选记录的来源设备批量添加阻断规则（单次原子重载）"
        >
          仅设备批量拉黑
        </Button>
        <Button
          size="xs"
          variant="secondary"
          className="border-rose-500/35 text-rose-300 hover:bg-rose-500/15"
          disabled={busy}
          icon={<Globe className="w-3 h-3" />}
          onClick={() => onBlockBatch(false)}
          title="对所选目标执行全屋批量拉黑（单次原子重载）"
        >
          全屋拉黑
        </Button>
        <Button
          size="xs"
          variant="secondary"
          disabled={busy}
          icon={<ShieldCheck className="w-3 h-3" />}
          onClick={onWhitelistBatch}
        >
          批量放行
        </Button>
        <Button
          size="xs"
          variant="secondary"
          disabled={busy}
          icon={<Bot className="w-3 h-3" />}
          onClick={onReviewBatch}
        >
          批量 AI 研判
        </Button>
        {selectedActiveCount > 0 && (
          <Button
            size="xs"
            variant="secondary"
            disabled={busy}
            icon={<Unplug className="w-3 h-3" />}
            onClick={onCloseBatchConnections}
          >
            断开活跃 ({selectedActiveCount})
          </Button>
        )}
      </div>
    </div>
  );
};

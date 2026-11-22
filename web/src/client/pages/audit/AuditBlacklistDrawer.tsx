import React, { useState } from 'react';
import { Plus, RotateCw, ShieldCheck, Trash2, X } from 'lucide-react';
import { Badge, Button, SlideDrawer } from '../../../ui';
import { AuditBlockRule } from '../../types';
import { PRESET_RULESETS } from './auditHelpers';

export interface AuditBlacklistDrawerProps {
  open: boolean;
  blockRules: AuditBlockRule[];
  whitelist: string[];
  blockBusy: boolean;
  onClose: () => void;
  onManualBlock: (target: string, sourceDevice: string, reason?: string) => Promise<boolean>;
  onUnblock: (rule: AuditBlockRule) => void;
  onWhitelist: (action: 'add' | 'remove', target: string) => Promise<boolean>;
}

export const AuditBlacklistDrawer: React.FC<AuditBlacklistDrawerProps> = ({
  open,
  blockRules,
  whitelist,
  blockBusy,
  onClose,
  onManualBlock,
  onUnblock,
  onWhitelist,
}) => {
  const [presetUrl, setPresetUrl] = useState('');
  const [presetReason, setPresetReason] = useState('');
  const [manualTarget, setManualTarget] = useState('');
  const [manualDevice, setManualDevice] = useState('');

  const submitManualBlock = async () => {
    const ok = await onManualBlock(manualTarget, manualDevice, presetReason || undefined);
    if (ok) {
      setManualTarget('');
      setManualDevice('');
      setPresetUrl('');
      setPresetReason('');
    }
  };

  const submitWhitelistAdd = async () => {
    const ok = await onWhitelist('add', manualTarget);
    if (ok) {
      setManualTarget('');
    }
  };

  return (
    <SlideDrawer
      open={open}
      onClose={onClose}
      size="lg"
      title="黑名单、规则集与白名单管理"
      subtitle="支持单条域名 / IP / CIDR 与 sing-box .srs / .json 远程规则集整包挂载阻断"
    >
      <div className="space-y-5">
        <div className="rounded-xl border border-subtle bg-surface2/60 p-4 space-y-3">
          <div className="text-xs font-semibold text-primary">添加封禁规则或规则集</div>
          <select
            value={presetUrl}
            onChange={(e) => {
              const url = e.target.value;
              setPresetUrl(url);
              const found = PRESET_RULESETS.find((p) => p.url === url);
              setManualTarget(url);
              setPresetReason(found?.reason || '');
            }}
            className="sc-input w-full px-3 py-2 text-xs"
          >
            <option value="">常用 GitHub 规则集快捷导入…</option>
            {PRESET_RULESETS.map((p) => (
              <option key={p.url} value={p.url}>
                {p.label}
              </option>
            ))}
          </select>

          <div className="grid grid-cols-1 sm:grid-cols-3 gap-2">
            <input
              type="text"
              value={manualTarget}
              onChange={(e) => setManualTarget(e.target.value)}
              placeholder="域名 / IP / .srs 或 .json URL…"
              className="sc-input sm:col-span-2 px-3 py-2 text-xs font-mono"
            />
            <input
              type="text"
              value={manualDevice}
              onChange={(e) => setManualDevice(e.target.value)}
              placeholder="限定设备 IP (可留空=全局)"
              className="sc-input px-3 py-2 text-xs font-mono"
            />
          </div>

          <div className="flex flex-wrap gap-2">
            <Button
              size="sm"
              variant="danger"
              loading={blockBusy}
              icon={<Plus className="w-3.5 h-3.5" />}
              onClick={() => void submitManualBlock()}
            >
              导入 / 拉黑
            </Button>
            <Button
              size="sm"
              variant="secondary"
              icon={<ShieldCheck className="w-3.5 h-3.5" />}
              onClick={() => void submitWhitelistAdd()}
            >
              加入信任白名单
            </Button>
          </div>
        </div>

        <div className="space-y-2.5">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-primary">
              当前生效黑名单 ({blockRules.length})
            </span>
          </div>

          {blockRules.length === 0 ? (
            <div className="py-6 text-center text-xs text-muted border border-subtle rounded-xl">
              当前暂无封禁规则
            </div>
          ) : (
            <div className="divide-y divide-subtle border border-subtle rounded-xl overflow-hidden">
              {blockRules.map((r, idx) => {
                const isRS = String(r.target || '').toLowerCase().startsWith('ruleset:');
                const rsTag = isRS ? String(r.target).slice(8) : r.target;
                return (
                  <div
                    key={`${r.target}-${r.source_ip || 'global'}-${idx}`}
                    className="p-3 bg-surface1 flex items-start justify-between gap-3"
                  >
                    <div className="min-w-0 space-y-1">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="font-mono text-xs font-semibold text-primary break-all">
                          {isRS ? `规则集: ${rsTag}` : rsTag}
                        </span>
                        {isRS && (
                          <Badge tone="accent">
                            {r.rule_count ? `含 ${r.rule_count} 条` : '原生 .srs'}
                          </Badge>
                        )}
                        <Badge tone="neutral">{r.source_ip || '全局'}</Badge>
                      </div>
                      {r.reason && <div className="text-[11px] text-secondary">{r.reason}</div>}
                      {isRS && r.ruleset_url && (
                        <div className="font-mono text-[10.5px] text-muted truncate max-w-md" title={r.ruleset_url}>
                          {r.ruleset_url}
                        </div>
                      )}
                      {isRS && r.preview && (
                        <div className="font-mono text-[10.5px] text-muted truncate max-w-md" title={r.preview}>
                          摘要: {r.preview}
                        </div>
                      )}
                    </div>
                    <div className="flex items-center gap-1.5 shrink-0">
                      {isRS && r.ruleset_url && (
                        <Button
                          size="xs"
                          variant="secondary"
                          title="重新拉取远程规则集"
                          icon={<RotateCw className="w-3 h-3" />}
                          onClick={() => void onManualBlock(r.ruleset_url!, r.source_ip || '', r.reason || '刷新规则集')}
                        >
                          更新
                        </Button>
                      )}
                      <Button
                        size="xs"
                        variant="ghost"
                        className="text-rose-400"
                        icon={<Trash2 className="w-3 h-3" />}
                        onClick={() => onUnblock(r)}
                      >
                        解封
                      </Button>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>

        <div className="space-y-2">
          <div className="text-xs font-semibold text-primary">
            已配置放行白名单 ({whitelist.length})
          </div>
          {whitelist.length === 0 ? (
            <div className="text-xs text-muted">暂无手动白名单条目</div>
          ) : (
            <div className="flex flex-wrap gap-1.5">
              {whitelist.map((w) => (
                <span
                  key={w}
                  className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-mono bg-emerald-500/10 text-emerald-400 border border-emerald-500/25"
                >
                  <span>{w}</span>
                  <button
                    type="button"
                    onClick={() => void onWhitelist('remove', w)}
                    className="hover:text-rose-400 cursor-pointer"
                    title="移出白名单"
                  >
                    <X className="w-3 h-3" />
                  </button>
                </span>
              ))}
            </div>
          )}
        </div>
      </div>
    </SlideDrawer>
  );
};

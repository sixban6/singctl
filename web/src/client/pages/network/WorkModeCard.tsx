import React, { useEffect, useState } from 'react';
import { ArrowRight, Globe, Layers, Radar, Save } from 'lucide-react';
import { Badge, Button, SectionCard } from '../../../ui';
import { EffectiveGatewayWorkMode, GatewayWorkMode } from '../../types';

export function getWorkModeLabel(mode?: string): string {
  switch (mode) {
    case 'proxy':
      return '代理模式';
    case 'audit':
    default:
      return '审计模式';
  }
}

export interface WorkModeCardProps {
  configuredWorkMode?: GatewayWorkMode;
  effectiveWorkMode?: EffectiveGatewayWorkMode;
  hasSubs: boolean;
  saving: boolean;
  busy: boolean;
  privacyMask?: boolean;
  onSaveWorkMode: (next: EffectiveGatewayWorkMode) => void;
  onGoSubs?: () => void;
}

interface WorkModeOption {
  key: EffectiveGatewayWorkMode;
  title: string;
  tag: string;
  desc: string;
  hint: string;
  requiresSubs?: boolean;
  icon: React.ReactNode;
}

const WORK_MODE_OPTIONS: WorkModeOption[] = [
  {
    key: 'audit',
    title: '审计模式',
    tag: '免订阅 · 强劫持',
    desc: '无需订阅，纯直连透明劫持全屋 DNS、四层防 DoH/HTTPDNS 绕过、实时设备审计与防 PCDN。',
    hint: '切换后将免订阅启动轻量直连内核，完整开启设备行为审计、去广告与防绕过 DNS 劫持。',
    icon: <Radar className="w-4 h-4" />,
  },
  {
    key: 'proxy',
    title: '代理模式',
    tag: '需订阅 · 全功能',
    desc: '透明代理智能分流 + 完整设备行为审计 + 四层防绕过 DNS 劫持，需先添加订阅链接。',
    hint: '切换后将使用已配置的订阅链接生成完整分流配置并启动透明代理。',
    requiresSubs: true,
    icon: <Globe className="w-4 h-4" />,
  },
];

export const WorkModeCard: React.FC<WorkModeCardProps> = ({
  configuredWorkMode,
  effectiveWorkMode,
  hasSubs,
  saving,
  busy,
  privacyMask = false,
  onSaveWorkMode,
  onGoSubs,
}) => {
  const currentEffective: EffectiveGatewayWorkMode = effectiveWorkMode || (hasSubs ? 'proxy' : 'audit');
  const [selected, setSelected] = useState<EffectiveGatewayWorkMode>(currentEffective);
  const [dirty, setDirty] = useState(false);

  useEffect(() => {
    if (!dirty) {
      setSelected(currentEffective);
    }
  }, [currentEffective, dirty]);

  const activeOpt = WORK_MODE_OPTIONS.find((item) => item.key === selected) || WORK_MODE_OPTIONS[0];
  const blockedByNoSubs = Boolean(activeOpt.requiresSubs && !hasSubs);
  const unchanged = selected === currentEffective && configuredWorkMode !== 'auto';

  const handleSelect = (opt: WorkModeOption) => {
    if (opt.requiresSubs && !hasSubs) return;
    setSelected(opt.key);
    setDirty(opt.key !== currentEffective);
  };

  return (
    <SectionCard
      title="运行模式"
      icon={<Layers className="w-4 h-4" />}
      subtitle="不配订阅也能用防劫持 DNS 与设备审计，按需一键切换"
      actions={
        <Badge tone={currentEffective === 'proxy' ? 'accent' : 'ok'} dot>
          当前：{getWorkModeLabel(currentEffective)}
          {configuredWorkMode === 'auto' ? '（自动）' : ''}
        </Badge>
      }
    >
      <div className="space-y-4">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          {WORK_MODE_OPTIONS.map((opt) => {
            const isSelected = selected === opt.key;
            const isCurrent = currentEffective === opt.key;
            const disabled = Boolean(opt.requiresSubs && !hasSubs);
            return (
              <div
                key={opt.key}
                role="button"
                tabIndex={disabled ? -1 : 0}
                aria-disabled={disabled}
                aria-pressed={isSelected}
                onClick={() => handleSelect(opt)}
                onKeyDown={(ev) => {
                  if (!disabled && (ev.key === 'Enter' || ev.key === ' ')) {
                    ev.preventDefault();
                    handleSelect(opt);
                  }
                }}
                style={
                  isSelected
                    ? {
                        backgroundColor: 'var(--accent-soft)',
                        borderColor: 'var(--accent)',
                      }
                    : undefined
                }
                className={`p-4 rounded-xl border text-left transition-all flex flex-col justify-between gap-2.5 ${
                  disabled
                    ? 'bg-surface2/60 border-subtle opacity-75 cursor-not-allowed'
                    : isSelected
                      ? 'cursor-pointer'
                      : 'bg-surface2 border-subtle hover:border-strong cursor-pointer'
                }`}
              >
                <div className="space-y-2">
                  <div className="flex items-center justify-between gap-2">
                    <div className="flex items-center gap-2 min-w-0">
                      <span className={isSelected ? 'text-accent' : 'text-secondary'}>{opt.icon}</span>
                      <span className="text-sm font-semibold text-primary">{opt.title}</span>
                      {isCurrent && (
                        <span className="text-[10px] px-1.5 py-0.5 rounded bg-emerald-500/15 text-emerald-300 border border-emerald-500/30">
                          生效中
                        </span>
                      )}
                    </div>
                    <span className="text-[10px] px-1.5 py-0.5 rounded bg-surface1 text-secondary border border-subtle shrink-0">
                      {opt.tag}
                    </span>
                  </div>
                  <p className="text-xs text-secondary leading-relaxed">{opt.desc}</p>
                </div>

                {disabled && (
                  <div className="flex items-center justify-between gap-2 pt-1.5 border-t border-subtle text-[11px] text-amber-300">
                    <span>尚未添加订阅链接</span>
                    {onGoSubs && (
                      <button
                        type="button"
                        onClick={(ev) => {
                          ev.stopPropagation();
                          onGoSubs();
                        }}
                        className="inline-flex items-center gap-0.5 text-cyan-300 hover:underline cursor-pointer"
                      >
                        去添加
                        <ArrowRight className="w-3 h-3" />
                      </button>
                    )}
                  </div>
                )}
              </div>
            );
          })}
        </div>

        <div className="flex flex-wrap items-center justify-between gap-3 pt-2 border-t border-subtle">
          <span className="text-xs text-secondary">{activeOpt.hint}</span>
          <Button
            variant="primary"
            loading={saving}
            disabled={busy || saving || privacyMask || blockedByNoSubs || unchanged}
            title={privacyMask ? '隐私完全遮挡开启期间已锁定修改' : undefined}
            icon={<Save className="w-3.5 h-3.5" />}
            onClick={() => {
              setDirty(false);
              onSaveWorkMode(selected);
            }}
          >
            {selected === currentEffective ? `保持${activeOpt.title}` : `切换为${activeOpt.title}`}
          </Button>
        </div>
      </div>
    </SectionCard>
  );
};

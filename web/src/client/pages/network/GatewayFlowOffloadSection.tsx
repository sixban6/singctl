import React, { useState } from 'react';
import {
  AlertTriangle,
  CheckCircle2,
  Cpu,
  RotateCcw,
  Save,
  ShieldCheck,
  Zap,
} from 'lucide-react';
import { Badge, Button, ConfirmDialog, SectionCard } from '../../../ui';
import { FlowOffloadStatusInfo } from '../../types';

export interface GatewayFlowOffloadSectionProps {
  flowStatus?: FlowOffloadStatusInfo;
  hasConflictRisk: boolean;
  saving: boolean;
  busy: boolean;
  privacyMask: boolean;
  rebootNotice?: string | null;
  onApply: (enable: boolean) => Promise<boolean>;
}

export const GatewayFlowOffloadSection: React.FC<GatewayFlowOffloadSectionProps> = ({
  flowStatus,
  hasConflictRisk,
  saving,
  busy,
  privacyMask,
  rebootNotice,
  onApply,
}) => {
  const [pendingToggle, setPendingToggle] = useState<boolean | null>(null);
  const [confirmEnableOpen, setConfirmEnableOpen] = useState(false);

  if (flowStatus && !flowStatus.supported && !flowStatus.enabled) {
    return (
      <SectionCard
        title="软硬件流量卸载控制"
        icon={<Zap className="w-4 h-4" />}
        subtitle="控制系统级 NAT 快速转发（Flow Offloading / HNAT / SFE），避免流量绕过透明代理与分流链路"
        actions={
          <Badge tone="ok" dot>
            当前生效：原生纯净转发
          </Badge>
        }
      >
        <div className="flex items-center gap-2 text-xs text-secondary">
          <ShieldCheck className="w-4 h-4 text-emerald-400 shrink-0" />
          <span>当前宿主机未启用 OpenWrt / 固件流量卸载，连接转发路径纯净，无需额外操作。</span>
        </div>
      </SectionCard>
    );
  }

  const savedEnabled = flowStatus ? flowStatus.enabled : null;
  const effectiveSelected = pendingToggle !== null ? pendingToggle : savedEnabled;
  const hasChanges = pendingToggle !== null && savedEnabled !== null && pendingToggle !== savedEnabled;

  const handleSelect = (nextEnable: boolean) => {
    if (savedEnabled === null) return;
    if (nextEnable === savedEnabled) {
      setPendingToggle(null);
      return;
    }
    setPendingToggle(nextEnable);
  };

  const executeApply = async (enable: boolean) => {
    const ok = await onApply(enable);
    if (ok) {
      setPendingToggle(null);
    }
  };

  const handleClickSave = () => {
    if (!hasChanges || effectiveSelected === null || privacyMask) return;
    if (effectiveSelected && hasConflictRisk) {
      setConfirmEnableOpen(true);
      return;
    }
    void executeApply(effectiveSelected);
  };

  const headerBadgeTone = !flowStatus
    ? 'neutral'
    : !savedEnabled
      ? 'ok'
      : hasConflictRisk
        ? 'warn'
        : 'accent';

  const headerBadgeLabel = !flowStatus
    ? '读取加速状态中…'
    : !savedEnabled
      ? '当前生效：已关闭（转发路径纯净）'
      : hasConflictRisk
        ? '当前生效：已开启（存在绕行风险）'
        : '当前生效：已开启加速';

  const hwEngineBadgeText = (() => {
    if (!flowStatus) return '';
    if (flowStatus.hnatActive) return 'MediaTek HNAT 运行中';
    if (flowStatus.sfeActive) return 'SFE 快捷转发运行中';
    if (flowStatus.turboaccFastpath && flowStatus.turboaccFastpath !== 'none' && flowStatus.turboaccFastpath !== '0') {
      return `${flowStatus.turboaccFastpath} 配置开启`;
    }
    return '已停用（保留原参数记忆）';
  })();

  const hwEngineActive = Boolean(flowStatus?.hnatActive || flowStatus?.sfeActive);

  const cardSubtitle = (() => {
    if (flowStatus?.hnatSupported || flowStatus?.hnatActive) {
      return '统一管理 OpenWrt 防火墙软/硬件卸载、TurboACC 与 MediaTek HNAT；支持在线热关闭与 1:1 热恢复，无需重启路由器';
    }
    if (
      flowStatus?.sfeActive ||
      flowStatus?.turboaccFastpath === 'fast_classifier' ||
      flowStatus?.turboaccFastpath === 'shortcut_fe_cm'
    ) {
      return '统一管理 OpenWrt 防火墙软/硬件卸载、TurboACC 与 SFE 快捷转发；支持在线热关闭与 1:1 热恢复，无需重启路由器';
    }
    return '统一管理 OpenWrt 防火墙软/硬件流量卸载与固件网络加速；支持在线热关闭与 1:1 热恢复，无需重启路由器';
  })();

  return (
    <>
      <SectionCard
        title="软硬件流量卸载控制"
        icon={<Zap className="w-4 h-4" />}
        subtitle={cardSubtitle}
        actions={
          <Badge tone={headerBadgeTone} dot={Boolean(flowStatus)}>
            {headerBadgeLabel}
          </Badge>
        }
      >
        <div className="space-y-4">
          {flowStatus && savedEnabled && hasConflictRisk && (
            <div className="rounded-xl border border-amber-500/35 bg-amber-500/10 px-3.5 py-2.5 text-xs text-amber-200 flex items-start gap-2">
              <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
              <span>
                检测到当前设备运行在透明代理、行为审计或旁路由协同分流模式，但系统仍开启着{' '}
                <strong className="text-amber-100">
                  {flowStatus.activeEngines && flowStatus.activeEngines.length > 0
                    ? flowStatus.activeEngines.join(' / ')
                    : '软硬件流量卸载'}
                </strong>
                。建议下方切换为「关闭流量卸载」并保存生效，以防部分连接绕过规则或异常断流。
              </span>
            </div>
          )}

          {rebootNotice && (
            <div className="rounded-xl border border-amber-500/35 bg-amber-500/10 px-3.5 py-2.5 text-xs text-amber-200 flex items-start gap-2">
              <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
              <span>{rebootNotice}</span>
            </div>
          )}

          {flowStatus && (
            <div className="rounded-xl border border-subtle bg-surface2/60 px-3.5 py-2.5 space-y-2 text-xs">
              <div className="flex flex-wrap items-center gap-x-4 gap-y-1.5">
                <div className="flex items-center gap-1.5">
                  <span className="text-muted">UCI 软件卸载:</span>
                  <Badge tone={flowStatus.uciSoftware ? 'warn' : 'ok'}>
                    {flowStatus.uciSoftware ? '已开启' : '已关闭'}
                  </Badge>
                </div>
                <div className="flex items-center gap-1.5">
                  <span className="text-muted">UCI 硬件卸载:</span>
                  <Badge tone={flowStatus.uciHardware ? 'warn' : 'ok'}>
                    {flowStatus.uciHardware ? '已开启' : '已关闭'}
                  </Badge>
                </div>
                {(flowStatus.turboaccPresent || flowStatus.hnatSupported || flowStatus.hnatActive || flowStatus.sfeActive) && (
                  <div className="flex items-center gap-1.5">
                    <span className="text-muted">固件硬件加速:</span>
                    <Badge tone={hwEngineActive ? 'warn' : 'ok'}>{hwEngineBadgeText}</Badge>
                  </div>
                )}
              </div>

              <div className="flex flex-wrap items-center gap-2 text-[11px] text-secondary">
                <Cpu className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                <span>
                  关闭时仅摘除数据包绕行加速钩子，不触碰无线驱动；
                  {flowStatus.preservedFeatures && flowStatus.preservedFeatures.length > 0
                    ? `自动保留已启用的 ${flowStatus.preservedFeatures.join('、')}。`
                    : '如原配置包含 TCP BBR / FullCone NAT 将自动保留。'}
                </span>
              </div>
            </div>
          )}

          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {[
              {
                key: false,
                title: '关闭流量卸载（纯净分流模式）',
                tag: '分流推荐',
                desc: '确保所有新连接完整经过透明代理、策略路由表与旁路由跨网段分流，彻底消除规则绕行、断流及回程丢包；再次开启可在线热恢复。',
              },
              {
                key: true,
                title: '开启流量卸载（NAT 加速模式）',
                tag: '纯直连适用',
                desc: '恢复并启用本机软/硬件 NAT 快速转发以降低高带宽 CPU 占用（支持新建连接在线热恢复，无需重启路由）；仅推荐无透明分流的纯直连路由。',
              },
            ].map((opt) => {
              const selected = effectiveSelected !== null && effectiveSelected === opt.key;
              const isSavedOpt = savedEnabled !== null && savedEnabled === opt.key;
              return (
                <button
                  key={String(opt.key)}
                  type="button"
                  disabled={savedEnabled === null || saving}
                  onClick={() => handleSelect(opt.key)}
                  style={
                    selected
                      ? {
                          backgroundColor: 'var(--accent-soft)',
                          borderColor: 'var(--accent)',
                        }
                      : undefined
                  }
                  className={`p-4 rounded-xl border text-left transition-all ${
                    savedEnabled === null || saving
                      ? 'opacity-50 cursor-not-allowed bg-surface2 border-subtle'
                      : selected
                        ? 'cursor-pointer'
                        : 'bg-surface2 border-subtle hover:border-strong cursor-pointer'
                  }`}
                >
                  <div className="flex items-center justify-between gap-2">
                    <div className="flex items-center gap-1.5 min-w-0 flex-wrap">
                      <span className="text-xs sm:text-sm font-semibold text-primary">{opt.title}</span>
                      {isSavedOpt && selected && (
                        <span className="text-[10px] px-1.5 py-0.5 rounded bg-emerald-500/15 text-emerald-300 border border-emerald-500/35">
                          ✓ 当前生效
                        </span>
                      )}
                      {selected && !isSavedOpt && savedEnabled !== null && (
                        <span className="text-[10px] px-1.5 py-0.5 rounded bg-amber-500/15 text-amber-300 border border-amber-500/35">
                          待保存
                        </span>
                      )}
                      {!selected && isSavedOpt && (
                        <span className="text-[10px] px-1.5 py-0.5 rounded bg-emerald-500/10 text-emerald-400/80 border border-emerald-500/25">
                          当前生效
                        </span>
                      )}
                    </div>
                    <span className="text-[10px] px-1.5 py-0.5 rounded bg-surface1 text-secondary border border-subtle shrink-0">
                      {opt.tag}
                    </span>
                  </div>
                  <p className="text-[11px] sm:text-xs text-secondary mt-1.5 leading-relaxed">{opt.desc}</p>
                </button>
              );
            })}
          </div>

          <div className="flex flex-wrap items-center justify-between gap-3 pt-2 border-t border-subtle">
            <span className="text-[11px] text-muted">
              {hasChanges
                ? effectiveSelected
                  ? '即将恢复并开启流量卸载（热重载防火墙后对新连接立即生效，老长连接重连后进入加速）。'
                  : '即将在线热关闭软/硬件流量卸载，原加速配置将保存 0600 快照以便随时恢复。'
                : '支持随时在线热切换且无需重启路由器，不会修改 singctl 旁路与 DNS 防环规则。'}
            </span>

            <div className="flex items-center gap-2 flex-wrap">
              {hasChanges && !saving && (
                <Button
                  variant="ghost"
                  size="sm"
                  disabled={busy || privacyMask}
                  icon={<RotateCcw className="w-3.5 h-3.5" />}
                  onClick={() => setPendingToggle(null)}
                >
                  撤销更改
                </Button>
              )}
              <Button
                variant={hasChanges ? 'primary' : 'secondary'}
                loading={saving}
                disabled={busy || savedEnabled === null || privacyMask || !hasChanges}
                title={privacyMask ? '隐私完全遮挡开启期间已锁定修改，避免误改网络配置' : undefined}
                icon={
                  hasChanges ? (
                    <Save className="w-3.5 h-3.5" />
                  ) : (
                    <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                  )
                }
                onClick={handleClickSave}
              >
                {saving
                  ? '正在应用流量卸载策略…'
                  : savedEnabled === null
                    ? '读取状态中…'
                    : hasChanges
                      ? effectiveSelected
                        ? '开启流量卸载并立即生效'
                        : '关闭流量卸载并立即生效'
                      : savedEnabled
                        ? '当前已生效：已开启流量卸载'
                        : '当前已生效：已关闭流量卸载'}
              </Button>
            </div>
          </div>
        </div>
      </SectionCard>

      <ConfirmDialog
        open={confirmEnableOpen}
        title="确认重新开启软硬件流量卸载？"
        description={
          <div className="space-y-2 text-xs leading-relaxed">
            <p>当前路由器处于透明代理、审计或旁路由分流场景。</p>
            <p className="text-amber-300">
              开启流表/硬件卸载后，部分已建立的连接可能直接走硬件快转从而绕过分流与审计；新建连接立即热生效，如需纯净分流可随时再次一键关闭（无需重启）。
            </p>
          </div>
        }
        confirmText="确认开启流量卸载"
        cancelText="取消"
        danger={true}
        loading={saving}
        onConfirm={() => {
          setConfirmEnableOpen(false);
          void executeApply(true);
        }}
        onCancel={() => setConfirmEnableOpen(false)}
      />
    </>
  );
};

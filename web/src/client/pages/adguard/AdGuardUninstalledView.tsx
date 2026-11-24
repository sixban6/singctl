import React from 'react';
import {
  AlertTriangle,
  CheckCircle2,
  Download,
  Gauge,
  HardDrive,
  MemoryStick,
  ShieldCheck,
  Sparkles,
} from 'lucide-react';
import { Badge, Button, PageHeader, SectionCard } from '../../../ui';
import { DNSEnginePreference, DNSOverviewSnapshot } from '../../types';
import {
  getEngineDisplayName,
  isMemoryOnlyBlocked,
  resolveActiveEngine,
  resolveEngineOptions,
} from './adguardHelpers';
import { DNSEngineDropdown } from './DNSEngineDropdown';

export interface AdGuardUninstalledViewProps {
  snap: DNSOverviewSnapshot;
  busy: boolean;
  mutating: boolean;
  switchingEngine: DNSEnginePreference | null;
  headerBadge: React.ReactNode;
  onSwitchEngine: (engine: DNSEnginePreference, forceLowMemory?: boolean) => Promise<boolean>;
  onAction: (name: string, params?: Record<string, unknown>, confirmMsg?: string) => void;
}

export const AdGuardUninstalledView: React.FC<AdGuardUninstalledViewProps> = ({
  snap,
  busy,
  mutating,
  switchingEngine,
  headerBadge,
  onSwitchEngine,
  onAction,
}) => {
  const activeEngine = resolveActiveEngine(snap);
  const engineLabel = getEngineDisplayName(activeEngine, snap.activeEngineLabel);
  const engines = resolveEngineOptions(snap);
  const selectedOpt = engines.find((e) => e.id === activeEngine) || engines[0];
  const altOpt = engines.find((e) => e.id !== activeEngine && e.eligible);

  const memOnlyBlocked = Boolean(
    selectedOpt && !selectedOpt.eligible && isMemoryOnlyBlocked(selectedOpt),
  );
  const hardBlocked = Boolean(
    !snap.supported || (selectedOpt && !selectedOpt.eligible && !memOnlyBlocked),
  );
  const blockedReason = selectedOpt && !selectedOpt.eligible ? selectedOpt.blockedReason : undefined;
  const fallbackDoHActive = snap.fallbackDoHActive !== false;

  const triggerForceInstall = () => {
    onAction(
      'dns-switch',
      { engine: activeEngine, forceLowMemory: true },
      `当前设备可用内存偏低（${blockedReason || '触发低内存保护'}），强行运行 ${engineLabel} 可能导致路由器 OOM 死机断网。确定要忽略低内存保护并强制安装吗？`,
    );
  };

  return (
    <div className="space-y-5">
      <PageHeader
        title="防劫持 DNS"
        description={`当前已选 ${engineLabel}（尚未安装）· 支持 SmartDNS 与 AdGuard Home 双引擎切换`}
        badge={headerBadge}
        actions={
          <DNSEngineDropdown
            snap={snap}
            busy={busy}
            mutating={mutating}
            switchingEngine={switchingEngine}
            onSwitchEngine={onSwitchEngine}
            onAction={onAction}
          />
        }
      />

      {fallbackDoHActive && (
        <div
          className="console-card rounded-2xl p-4 flex items-start gap-3 border animate-sc-in"
          style={{
            borderColor: 'color-mix(in srgb, var(--status-ok) 35%, transparent)',
            backgroundColor: 'var(--status-ok-soft)',
          }}
        >
          <CheckCircle2
            className="w-5 h-5 shrink-0 mt-0.5"
            style={{ color: 'var(--status-ok)' }}
          />
          <div className="text-xs sm:text-sm space-y-0.5 min-w-0">
            <div className="font-semibold text-primary">
              底层 sing-box 正在使用纯 IP 加密 DoH 应急防劫持兜底，安装期间全屋零断网
            </div>
            <div className="text-secondary leading-relaxed">
              当前尚未安装本地独立防劫持 DNS 引擎，网关已自动通过内置加密 DoH 阻断运营商明文 DNS 抢答；完成下方引擎安装并验活后，将两阶段原子平滑接管。
            </div>
          </div>
        </div>
      )}

      <SectionCard
        title={`部署防劫持 DNS 引擎 · ${engineLabel}`}
        icon={
          activeEngine === 'smartdns' ? (
            <Gauge className="w-4 h-4" />
          ) : (
            <ShieldCheck className="w-4 h-4" />
          )
        }
        subtitle={
          snap.recommendedReason ||
          '安装与切换全程免向导自动配置，验活本地加密解析就绪后再热切 sing-box，确保零断网'
        }
        actions={
          <div className="flex flex-wrap items-center gap-1.5">
            {selectedOpt?.recommended && (
              <Badge tone="accent">
                <Sparkles className="w-2.5 h-2.5" />
                硬件推荐
              </Badge>
            )}
            {hardBlocked ? (
              <Badge tone="danger">硬件门槛受限</Badge>
            ) : memOnlyBlocked ? (
              <Badge tone="warn">低内存保护</Badge>
            ) : (
              <Badge tone="ok">硬件适配通过</Badge>
            )}
          </div>
        }
      >
        <div className="space-y-5">
          {selectedOpt && (
            <div className="rounded-xl p-3.5 bg-surface2 border border-subtle flex flex-col sm:flex-row sm:items-center justify-between gap-3">
              <div className="space-y-1 min-w-0">
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="text-sm font-semibold text-primary">{selectedOpt.name}</span>
                  <Badge tone="neutral">未安装</Badge>
                </div>
                <p className="text-xs text-secondary leading-relaxed">{selectedOpt.tagline}</p>
              </div>
              <div className="flex flex-wrap items-center gap-2 shrink-0 text-[11px] font-mono text-muted tnum">
                <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded-lg bg-surface1 border border-subtle">
                  <HardDrive className="w-3 h-3" />
                  闪存 {selectedOpt.diskHint}
                </span>
                <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded-lg bg-surface1 border border-subtle">
                  <MemoryStick className="w-3 h-3" />
                  内存 {selectedOpt.ramHint}
                </span>
              </div>
            </div>
          )}

          {(hardBlocked || memOnlyBlocked) && blockedReason && (
            <div
              className="rounded-xl p-3.5 border flex items-start gap-2.5 animate-sc-in"
              style={{
                borderColor: hardBlocked ? 'var(--status-danger)' : 'var(--status-warn)',
                backgroundColor: hardBlocked
                  ? 'var(--status-danger-soft)'
                  : 'var(--status-warn-soft)',
              }}
            >
              <AlertTriangle
                className="w-4 h-4 shrink-0 mt-0.5"
                style={{
                  color: hardBlocked ? 'var(--status-danger)' : 'var(--status-warn)',
                }}
              />
              <div className="text-xs sm:text-sm space-y-1 min-w-0">
                <div className="font-semibold text-primary">
                  {hardBlocked
                    ? `${engineLabel} 当前硬件条件不满足`
                    : `${engineLabel} 已触发小内存防 OOM 保护`}
                </div>
                <div className="text-secondary leading-relaxed break-words">{blockedReason}</div>
                {altOpt && (
                  <div className="text-secondary text-[11px] sm:text-xs">
                    建议直接改选轻量化 <strong className="text-primary">{altOpt.name}</strong>{' '}
                    （闪存 {altOpt.diskHint} / 内存 {altOpt.ramHint}），或通过右上角引擎下拉菜单切换安装。
                  </div>
                )}
              </div>
            </div>
          )}

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            {[
              {
                title: '纯 IP 加密 DoH / DoT 防运营商抢答',
                desc: '接管 sing-box 国内分流与代理节点引导解析，并发查询阿里/腾讯纯 IP 加密上游，杜绝 UDP 53 污染。',
              },
              {
                title: 'SmartDNS / AdGuard Home 双引擎自由切换',
                desc: '中小闪存与轻量软路由优选 SmartDNS，大内存高配设备可选 AdGuard Home，随时通过顶部下拉菜单零断网切换。',
              },
              {
                title: '控制台一体化管理',
                desc: '直接在当前页面一键临时暂停去广告、实测加密上游、放行误拦域名、配置内网 NAS 域名映射。',
              },
              {
                title: '软路由闪存保护 + 永不断网兜底',
                desc: 'OpenWrt 全程零查询日志落盘保护闪存；停用、卸载或异常时底层 sing-box 自动回退内置加密 DoH 兜底。',
              },
            ].map((item) => (
              <div
                key={item.title}
                className="p-3.5 rounded-xl bg-surface2 border border-subtle space-y-1"
              >
                <div className="text-xs sm:text-sm font-semibold text-primary">{item.title}</div>
                <div className="text-[11px] sm:text-xs text-secondary leading-relaxed">
                  {item.desc}
                </div>
              </div>
            ))}
          </div>

          <div className="flex flex-wrap items-center gap-3 pt-2 border-t border-subtle">
            {!snap.supported ? (
              <>
                <Button variant="secondary" disabled icon={<Download className="w-4 h-4" />}>
                  当前平台暂不支持本地引擎
                </Button>
                <span className="text-xs text-muted">
                  请在 Linux / OpenWrt 网关设备上部署 SmartDNS 或 AdGuard Home。
                </span>
              </>
            ) : hardBlocked ? (
              <>
                {altOpt ? (
                  <Button
                    variant="primary"
                    disabled={busy}
                    icon={<Download className="w-4 h-4" />}
                    onClick={() => onAction('dns-switch', { engine: altOpt.id })}
                  >
                    改选并一键安装 {altOpt.name}
                  </Button>
                ) : (
                  <Button variant="secondary" disabled>
                    硬件门槛不满足 · 保持内置 DoH 兜底
                  </Button>
                )}
              </>
            ) : memOnlyBlocked ? (
              <>
                {altOpt && (
                  <Button
                    variant="primary"
                    disabled={busy}
                    icon={<Download className="w-4 h-4" />}
                    onClick={() => onAction('dns-switch', { engine: altOpt.id })}
                  >
                    改选并安装推荐引擎 ({altOpt.name})
                  </Button>
                )}
                <Button
                  variant="ghost"
                  disabled={busy}
                  onClick={triggerForceInstall}
                >
                  已知晓 OOM 风险，仍强制安装 {engineLabel}
                </Button>
              </>
            ) : (
              <>
                <Button
                  variant="primary"
                  disabled={busy}
                  icon={<Download className="w-4 h-4" />}
                  onClick={() => onAction('dns-switch', { engine: activeEngine })}
                >
                  一键安装并接管 {engineLabel}
                </Button>
                <span className="text-xs text-muted">
                  也可点击右上角引擎下拉菜单改选另一个引擎安装
                </span>
              </>
            )}
          </div>
        </div>
      </SectionCard>
    </div>
  );
};

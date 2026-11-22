import React from 'react';
import {
  AlertTriangle,
  CheckCircle2,
  Cpu,
  Download,
  Gauge,
  HardDrive,
  MemoryStick,
  RotateCcw,
  ShieldCheck,
  Sparkles,
  ArrowRightLeft,
} from 'lucide-react';
import { Badge, Button, SectionCard } from '../../../ui';
import {
  DNSEngineID,
  DNSEngineOption,
  DNSEnginePreference,
  DNSOverviewSnapshot,
} from '../../types';
import {
  getEngineDisplayName,
  isMemoryOnlyBlocked,
  resolveActiveEngine,
} from './adguardHelpers';

export interface DNSEngineSwitcherCardProps {
  snap: DNSOverviewSnapshot | null;
  busy: boolean;
  mutating: boolean;
  switchingEngine: DNSEnginePreference | null;
  onSwitchEngine: (engine: DNSEnginePreference, forceLowMemory?: boolean) => Promise<boolean>;
  onAction: (name: string, params?: Record<string, unknown>, confirmMsg?: string) => void;
}

function getEngineIcon(id: DNSEngineID): React.ReactNode {
  switch (id) {
    case 'singbox':
      return <Cpu className="w-4 h-4" />;
    case 'smartdns':
      return <Gauge className="w-4 h-4" />;
    case 'adguard':
      return <ShieldCheck className="w-4 h-4" />;
  }
}

function buildFallbackEngines(snap: DNSOverviewSnapshot | null): DNSEngineOption[] {
  const active = resolveActiveEngine(snap);
  const rec = snap?.recommendedEngine || 'singbox';
  return [
    {
      id: 'singbox',
      name: 'sing-box 加强版',
      tagline: '内核内置纯 IP 加密 DoH/DoT + 轻量去广告，零额外进程与闪存开销',
      installed: true,
      active: active === 'singbox',
      recommended: rec === 'singbox',
      eligible: true,
      diskHint: '0 KB',
      ramHint: '0 MB',
    },
    {
      id: 'smartdns',
      name: 'SmartDNS',
      tagline: '极速 C 引擎并发优选最快 IP + 内存盘逐包审计，适合中小闪存软路由',
      installed: active === 'smartdns' && Boolean(snap?.installed),
      active: active === 'smartdns',
      recommended: rec === 'smartdns',
      eligible: Boolean(snap?.supported !== false),
      diskHint: '~3 MB',
      ramHint: '~10 MB',
    },
    {
      id: 'adguard',
      name: 'AdGuard Home',
      tagline: '全功能独立可视化防劫持与多规则去广告中心，含原生 Web 面板',
      installed: active === 'adguard' && Boolean(snap?.installed),
      active: active === 'adguard',
      recommended: rec === 'adguard',
      eligible: Boolean(snap?.supported !== false && !snap?.lowMemoryBlocked),
      blockedReason: snap?.lowMemoryBlocked ? snap.lowMemoryWarning : undefined,
      diskHint: '~80 MB',
      ramHint: '~100 MB',
    },
  ];
}

export const DNSEngineSwitcherCard: React.FC<DNSEngineSwitcherCardProps> = ({
  snap,
  busy,
  mutating,
  switchingEngine,
  onSwitchEngine,
  onAction,
}) => {
  const activeEngine = resolveActiveEngine(snap);
  const configuredEngine = snap?.configuredEngine || 'auto';
  const engines = snap?.engines && snap.engines.length > 0 ? snap.engines : buildFallbackEngines(snap);
  const isSwitching = switchingEngine !== null;
  const anyDisabled = busy || mutating || isSwitching;

  const handleCardAction = (opt: DNSEngineOption) => {
    if (opt.active || anyDisabled) return;

    if (!opt.eligible) {
      if (!isMemoryOnlyBlocked(opt)) return;
      onAction(
        'dns-switch',
        { engine: opt.id, forceLowMemory: true },
        `当前设备可用内存偏低（${opt.blockedReason || '触发低内存保护'}），强行运行 ${opt.name} 可能导致路由器 OOM 死机断网。确定要忽略低内存保护并强制切换吗？`,
      );
      return;
    }

    if (opt.installed || opt.id === 'singbox') {
      void onSwitchEngine(opt.id, false);
      return;
    }

    onAction('dns-switch', { engine: opt.id });
  };

  return (
    <SectionCard
      title="底层 DNS 引擎切换"
      icon={<ArrowRightLeft className="w-4 h-4" />}
      subtitle={
        snap?.recommendedReason ||
        '根据设备可用内存与闪存空间自动评估最优防劫持引擎，切换全程采用两阶段原子接管保证零断网'
      }
      actions={
        <div className="flex flex-wrap items-center gap-2">
          <Badge tone={configuredEngine === 'auto' ? 'accent' : 'neutral'}>
            {configuredEngine === 'auto'
              ? '自动选型 (auto)'
              : `已固定：${getEngineDisplayName(configuredEngine)}`}
          </Badge>
          {configuredEngine !== 'auto' && (
            <Button
              size="xs"
              variant="secondary"
              loading={switchingEngine === 'auto'}
              disabled={anyDisabled}
              icon={<RotateCcw className="w-3 h-3" />}
              onClick={() => void onSwitchEngine('auto', false)}
            >
              恢复自动选型 (auto)
            </Button>
          )}
        </div>
      }
    >
      <div className="grid grid-cols-1 md:grid-cols-3 gap-3.5">
        {engines.map((opt) => {
          const isActive = opt.active || opt.id === activeEngine;
          const memOnlyBlocked = !opt.eligible && isMemoryOnlyBlocked(opt);
          const hardBlocked = !opt.eligible && !memOnlyBlocked;
          const needsInstall = !opt.installed && opt.id !== 'singbox';

          return (
            <div
              key={opt.id}
              className={`rounded-2xl p-4 border flex flex-col justify-between gap-3.5 transition-all ${
                isActive
                  ? 'bg-surface2/90 shadow-sm'
                  : hardBlocked
                    ? 'bg-surface2/40 opacity-80 border-subtle'
                    : 'bg-surface2/60 border-subtle hover:border-strong'
              }`}
              style={
                isActive
                  ? {
                      borderColor: 'var(--status-ok)',
                      boxShadow: '0 0 0 1px color-mix(in srgb, var(--status-ok) 25%, transparent)',
                    }
                  : undefined
              }
            >
              <div className="space-y-2.5">
                <div className="flex items-start justify-between gap-2">
                  <div className="flex items-center gap-2 min-w-0">
                    <div
                      className="w-8 h-8 rounded-xl flex items-center justify-center shrink-0"
                      style={{
                        backgroundColor: isActive
                          ? 'var(--status-ok-soft)'
                          : opt.recommended
                            ? 'var(--accent-soft)'
                            : 'var(--bg-surface-1)',
                        color: isActive
                          ? 'var(--status-ok)'
                          : opt.recommended
                            ? 'var(--accent)'
                            : 'var(--text-secondary)',
                      }}
                    >
                      {getEngineIcon(opt.id)}
                    </div>
                    <div className="min-w-0">
                      <div className="text-sm font-semibold text-primary truncate">{opt.name}</div>
                      {opt.version && (
                        <div className="text-[11px] font-mono text-muted truncate tnum">
                          {opt.version}
                        </div>
                      )}
                    </div>
                  </div>
                </div>

                <div className="flex flex-wrap items-center gap-1.5">
                  {isActive && (
                    <Badge tone="ok" dot pulse>
                      当前运行
                    </Badge>
                  )}
                  {opt.recommended && (
                    <Badge tone="accent">
                      <Sparkles className="w-2.5 h-2.5" />
                      硬件推荐
                    </Badge>
                  )}
                  {!isActive && opt.installed && (
                    <Badge tone="neutral">{opt.id === 'singbox' ? '内置免装' : '已安装'}</Badge>
                  )}
                  {!opt.installed && opt.id !== 'singbox' && opt.eligible && (
                    <Badge tone="neutral">未安装</Badge>
                  )}
                </div>

                <p className="text-xs text-secondary leading-relaxed">{opt.tagline}</p>

                <div className="flex flex-wrap items-center gap-2 pt-0.5 text-[11px] font-mono text-muted tnum">
                  <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md bg-surface1 border border-subtle">
                    <HardDrive className="w-3 h-3" />
                    闪存 {opt.diskHint}
                  </span>
                  <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md bg-surface1 border border-subtle">
                    <MemoryStick className="w-3 h-3" />
                    内存 {opt.ramHint}
                  </span>
                </div>

                {!opt.eligible && opt.blockedReason && (
                  <div
                    className="rounded-xl px-2.5 py-2 border text-[11px] leading-relaxed flex items-start gap-1.5"
                    style={{
                      borderColor: hardBlocked ? 'var(--status-danger)' : 'var(--status-warn)',
                      backgroundColor: hardBlocked
                        ? 'var(--status-danger-soft)'
                        : 'var(--status-warn-soft)',
                    }}
                  >
                    <AlertTriangle
                      className="w-3.5 h-3.5 shrink-0 mt-0.5"
                      style={{
                        color: hardBlocked ? 'var(--status-danger)' : 'var(--status-warn)',
                      }}
                    />
                    <span className="text-primary break-words">{opt.blockedReason}</span>
                  </div>
                )}
              </div>

              <div className="pt-2.5 border-t border-subtle">
                {isActive ? (
                  <div className="flex items-center gap-1.5 text-xs font-medium text-secondary py-1">
                    <CheckCircle2
                      className="w-3.5 h-3.5 shrink-0"
                      style={{ color: 'var(--status-ok)' }}
                    />
                    <span>正在接管防劫持 DNS 解析</span>
                  </div>
                ) : hardBlocked ? (
                  <Button size="xs" variant="secondary" className="w-full" disabled>
                    硬件门槛不满足 · 已禁止
                  </Button>
                ) : memOnlyBlocked ? (
                  <Button
                    size="xs"
                    variant="ghost"
                    className="w-full"
                    disabled={anyDisabled}
                    onClick={() => handleCardAction(opt)}
                  >
                    忽略低内存保护 · 强制切换
                  </Button>
                ) : needsInstall ? (
                  <Button
                    size="xs"
                    variant={opt.recommended ? 'primary' : 'secondary'}
                    className="w-full"
                    disabled={anyDisabled}
                    icon={<Download className="w-3.5 h-3.5" />}
                    onClick={() => handleCardAction(opt)}
                  >
                    安装并零断网切换
                  </Button>
                ) : (
                  <Button
                    size="xs"
                    variant={opt.recommended ? 'primary' : 'secondary'}
                    className="w-full"
                    loading={switchingEngine === opt.id}
                    disabled={anyDisabled}
                    icon={<ArrowRightLeft className="w-3.5 h-3.5" />}
                    onClick={() => handleCardAction(opt)}
                  >
                    零断网切换至此引擎
                  </Button>
                )}
              </div>
            </div>
          );
        })}
      </div>
    </SectionCard>
  );
};

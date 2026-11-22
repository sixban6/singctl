import React, { useMemo } from 'react';
import {
  AlertTriangle,
  FileCode2,
  KeyRound,
  PauseCircle,
  PlayCircle,
  Power,
  RefreshCw,
  ShieldCheck,
  Zap,
} from 'lucide-react';
import { Badge, Button, PageHeader, SectionCard } from '../../ui';
import { DNSLeakTestCard } from '../components/DNSLeakTestCard';
import { ClientStatusResponse } from '../types';
import {
  AdGuardCredentialsDrawer,
  AdGuardLifecycleSection,
} from './adguard/AdGuardCredentialsDrawer';
import {
  canClearEngineCache,
  canMutateEngine,
  formatDurationSec,
  getEngineDisplayName,
  getEngineShortName,
  resolveActiveEngine,
  resolveDNSCapabilities,
} from './adguard/adguardHelpers';
import { AdGuardRulesAndRewritesSection } from './adguard/AdGuardRulesAndRewritesSection';
import { AdGuardUninstalledView } from './adguard/AdGuardUninstalledView';
import { AdGuardUpstreamsCard } from './adguard/AdGuardUpstreamsCard';
import { DNSEngineSwitcherCard } from './adguard/DNSEngineSwitcherCard';
import { DNSStatsCard } from './adguard/DNSStatsCard';
import { useAdGuardController } from './adguard/useAdGuardController';

export interface AdGuardPageProps {
  active?: boolean;
  status: ClientStatusResponse | null;
  busy: boolean;
  onAction: (name: string, params?: Record<string, unknown>, confirmMsg?: string) => void;
  onRefreshStatus: () => void;
}

export const AdGuardPage: React.FC<AdGuardPageProps> = ({
  active = true,
  status,
  busy,
  onAction,
  onRefreshStatus,
}) => {
  const {
    snap,
    loading,
    mutating,
    switchingEngine,
    togglingBlockAAAA,
    probe,
    probing,
    pauseRemainSec,
    savingUpstreams,
    credOpen,
    setCredOpen,
    credData,
    credLoading,
    resettingPwd,
    configPreview,
    configPreviewLoading,
    configPreviewError,
    loadConfigPreview,
    runProbe,
    handleSwitchEngine,
    handleProtection,
    handleToggleBlockAAAA,
    handleClearCache,
    handleWhitelist,
    handleAddRewrite,
    handleDeleteRewrite,
    handleFilterToggle,
    handleAddCustomFilter,
    handleRemoveCustomFilter,
    handleRefreshFilters,
    openCredentialsDrawer,
    handleResetPassword,
    handleUpdateUpstreams,
    handleToggleUpstreamPreset,
    handleRemoveUpstream,
  } = useAdGuardController(active, status, onRefreshStatus);

  const activeEngine = resolveActiveEngine(snap);
  const engineLabel = getEngineDisplayName(activeEngine, snap?.activeEngineLabel);
  const engineShort = getEngineShortName(activeEngine);
  const capabilities = useMemo(() => resolveDNSCapabilities(snap), [snap]);
  const canMutate = useMemo(() => canMutateEngine(snap), [snap]);
  const canClearCache = useMemo(
    () => canClearEngineCache(snap, capabilities),
    [snap, capabilities],
  );

  const headerBadge = useMemo(() => {
    if (!snap) return <Badge tone="neutral">加载中</Badge>;
    if (activeEngine === 'singbox') {
      if (!snap.dnsHealthy) return <Badge tone="warn">sing-box 内核未运行</Badge>;
      if (!snap.protectionEnabled) {
        return (
          <Badge tone="warn" dot>
            防劫持在线 · 暂停去广告中
          </Badge>
        );
      }
      return (
        <Badge tone="ok" dot pulse>
          防劫持接管中 · sing-box 加强版
        </Badge>
      );
    }
    if (!snap.supported) return <Badge tone="warn">当前平台不支持外部引擎</Badge>;
    if (!snap.installed) {
      return snap.lowMemoryBlocked ? (
        <Badge tone="warn">低内存保护 · 内置 DoH</Badge>
      ) : (
        <Badge tone="neutral">未安装</Badge>
      );
    }
    if (!snap.dnsHealthy) return <Badge tone="danger">{engineShort} 未运行</Badge>;
    if (!snap.singboxLinked) {
      return (
        <Badge tone="warn" dot>
          {engineShort} 运行中 · 待接管 sing-box
        </Badge>
      );
    }
    if (!snap.protectionEnabled) {
      return (
        <Badge tone="warn" dot>
          防劫持在线 · 暂停去广告中
        </Badge>
      );
    }
    return (
      <Badge tone="ok" dot pulse>
        防劫持接管中 · {engineShort} ({snap.dnsAddr})
      </Badge>
    );
  }, [snap, activeEngine, engineShort]);

  const headerDesc = useMemo(() => {
    if (!snap) return '正在读取防劫持 DNS 引擎与解析遥测…';
    const parts: string[] = [engineLabel];
    if (snap.version) parts.push(snap.version);
    if (activeEngine === 'singbox') {
      parts.push(snap.dnsAddr || '内置纯 IP 加密 DoH 接管');
    } else {
      parts.push(`监听 ${snap.dnsAddr || '127.0.0.1:5353'}`);
    }
    if (snap.isOpenWrt) parts.push('OpenWrt 闪存保护已开启');
    return parts.join(' · ');
  }, [snap, activeEngine, engineLabel]);

  if (loading && !snap) {
    return (
      <div className="space-y-5">
        <PageHeader title="防劫持 DNS" description="正在读取防劫持 DNS 引擎与解析遥测…" />
      </div>
    );
  }

  // sing-box 加强版零开销开箱即用；仅在极少数旧快照无 engines 且外部引擎未安装时回退引导页
  if (snap && !snap.installed && activeEngine !== 'singbox' && !(snap.engines && snap.engines.length > 0)) {
    return (
      <AdGuardUninstalledView
        supported={snap.supported}
        busy={busy}
        headerBadge={headerBadge}
        lowMemoryBlocked={snap.lowMemoryBlocked}
        lowMemoryWarning={snap.lowMemoryWarning}
        onInstall={() => onAction('dns-install')}
        onForceInstall={() =>
          onAction(
            'dns-install',
            { forceLowMemory: true },
            '当前设备可用内存较低，强行运行外部 DNS 引擎可能导致路由器 OOM 死机断网。确定要忽略保护强制安装吗？',
          )
        }
      />
    );
  }

  const showQuickControls = Boolean(
    snap &&
      (snap.dnsHealthy || activeEngine === 'singbox') &&
      (capabilities.hasPauseProtection || capabilities.hasBlockAAAA),
  );

  return (
    <div className="space-y-5">
      <PageHeader
        title="防劫持 DNS"
        description={headerDesc}
        badge={headerBadge}
        actions={
          <>
            <Button
              size="sm"
              variant="secondary"
              loading={probing}
              disabled={!snap || (activeEngine !== 'singbox' && !snap.dnsHealthy)}
              onClick={() => void runProbe(false)}
              icon={<Zap className="w-3.5 h-3.5" />}
            >
              实测上游
            </Button>
            {capabilities.canClearCache && (
              <Button
                size="sm"
                variant="secondary"
                disabled={mutating || !canClearCache}
                onClick={() => void handleClearCache()}
                icon={<RefreshCw className="w-3.5 h-3.5" />}
              >
                清 DNS 缓存
              </Button>
            )}
            {(capabilities.hasNativeWebPanel || capabilities.hasConfigPreview) && (
              <Button
                size="sm"
                variant="primary"
                onClick={() => void openCredentialsDrawer()}
                icon={
                  capabilities.hasNativeWebPanel ? (
                    <KeyRound className="w-3.5 h-3.5" />
                  ) : (
                    <FileCode2 className="w-3.5 h-3.5" />
                  )
                }
              >
                {capabilities.hasNativeWebPanel ? '原生面板与凭据' : '生效配置与诊断'}
              </Button>
            )}
          </>
        }
      />

      {snap && capabilities.hasPauseProtection && snap.dnsHealthy && !snap.protectionEnabled && (
        <div
          className="console-card rounded-2xl p-4 flex flex-wrap items-center justify-between gap-3 border animate-sc-in"
          style={{
            borderColor: 'var(--status-warn)',
            backgroundColor: 'var(--status-warn-soft)',
          }}
        >
          <div className="flex items-start gap-2.5 min-w-0">
            <PauseCircle
              className="w-5 h-5 shrink-0 mt-0.5"
              style={{ color: 'var(--status-warn)' }}
            />
            <div className="text-xs sm:text-sm">
              <div className="font-semibold text-primary">
                去广告规则过滤已临时暂停
                {pauseRemainSec > 0 ? `（剩余 ${formatDurationSec(pauseRemainSec)} 自动恢复）` : ''}
              </div>
              <div className="text-secondary mt-0.5">
                {engineLabel} 纯 IP 加密防劫持 DoH 解析仍在正常运行中，全屋网络不受任何影响。
              </div>
            </div>
          </div>
          <Button
            size="sm"
            variant="primary"
            disabled={mutating || !canMutate}
            icon={<PlayCircle className="w-3.5 h-3.5" />}
            onClick={() => void handleProtection(true, 0)}
          >
            立即恢复拦截
          </Button>
        </div>
      )}

      {snap && activeEngine !== 'singbox' && (!snap.installed || !snap.dnsHealthy || !snap.singboxLinked) && (
        <div
          className="console-card rounded-2xl p-4 flex flex-wrap items-center justify-between gap-3 border"
          style={{
            borderColor: 'var(--status-warn)',
            backgroundColor: 'var(--status-warn-soft)',
          }}
        >
          <div className="flex items-start gap-2.5 min-w-0">
            <AlertTriangle
              className="w-5 h-5 shrink-0 mt-0.5"
              style={{ color: 'var(--status-warn)' }}
            />
            <div className="text-xs sm:text-sm">
              <div className="font-semibold text-primary">
                {!snap.installed
                  ? `${engineLabel} 尚未安装（网关正在使用 sing-box 加强版内置纯 IP 加密 DoH 兜底）`
                  : !snap.dnsHealthy
                    ? `${engineLabel} 当前处于停止状态（网关正在使用 sing-box 加强版内置纯 IP 加密 DoH 兜底）`
                    : `${engineLabel} 已运行，但当前 sing-box 尚未将 dns_local 切换至本地接管`}
              </div>
              <div className="text-secondary mt-0.5">
                {!snap.installed
                  ? '点击右侧按钮即可在终端抽屉中实时完成安装、验活与零断网切换。'
                  : '点击右侧按钮即可在确认本地加密解析就绪后，平滑热重载 sing-box 完成零断网接管。'}
              </div>
            </div>
          </div>
          <Button
            size="sm"
            variant="primary"
            disabled={busy}
            icon={<Power className="w-3.5 h-3.5" />}
            onClick={() =>
              !snap.installed
                ? onAction('dns-switch', { engine: activeEngine })
                : onAction('dns-start')
            }
          >
            {!snap.installed ? `安装并接管 ${engineShort}` : '启动并接管 DNS'}
          </Button>
        </div>
      )}

      {snap && activeEngine === 'singbox' && !snap.dnsHealthy && (
        <div
          className="console-card rounded-2xl p-4 flex flex-wrap items-center justify-between gap-3 border"
          style={{
            borderColor: 'var(--status-warn)',
            backgroundColor: 'var(--status-warn-soft)',
          }}
        >
          <div className="flex items-start gap-2.5 min-w-0">
            <AlertTriangle
              className="w-5 h-5 shrink-0 mt-0.5"
              style={{ color: 'var(--status-warn)' }}
            />
            <div className="text-xs sm:text-sm">
              <div className="font-semibold text-primary">
                sing-box 内核当前未运行，启动内核后内置防劫持 DNS 将立即接管
              </div>
              <div className="text-secondary mt-0.5">
                你仍可提前调整上游服务器、白名单与内网域名重写，启动内核时将自动编译生效。
              </div>
            </div>
          </div>
          <Button
            size="sm"
            variant="primary"
            disabled={busy}
            icon={<Power className="w-3.5 h-3.5" />}
            onClick={() => onAction('sb-start')}
          >
            启动 sing-box
          </Button>
        </div>
      )}

      <DNSEngineSwitcherCard
        snap={snap}
        busy={busy}
        mutating={mutating}
        switchingEngine={switchingEngine}
        onSwitchEngine={handleSwitchEngine}
        onAction={onAction}
      />

      {capabilities.hasQueryStats && (
        <DNSStatsCard
          snap={snap}
          probe={probe}
          probing={probing}
          mutating={mutating}
          canMutate={canMutate}
          onWhitelist={handleWhitelist}
        />
      )}

      {showQuickControls && snap && (
        <SectionCard
          title="防误伤与解析快捷控制"
          icon={<ShieldCheck className="w-4 h-4" />}
          subtitle="遇到小程序、电商活动或视频激励加载异常时可一键临时放行广告拦截（不断网），到点自动恢复"
        >
          <div className="space-y-3.5">
            {capabilities.hasPauseProtection && (
              <div className="flex flex-wrap items-center justify-between gap-3">
                <div className="flex flex-wrap items-center gap-2">
                  {snap.protectionEnabled ? (
                    <>
                      <Button
                        size="sm"
                        variant="secondary"
                        disabled={mutating || !canMutate}
                        icon={<PauseCircle className="w-3.5 h-3.5" />}
                        onClick={() => void handleProtection(false, 5)}
                      >
                        暂停过滤 5 分钟
                      </Button>
                      <Button
                        size="sm"
                        variant="secondary"
                        disabled={mutating || !canMutate}
                        onClick={() => void handleProtection(false, 30)}
                      >
                        暂停 30 分钟
                      </Button>
                      <Button
                        size="sm"
                        variant="secondary"
                        disabled={mutating || !canMutate}
                        onClick={() => void handleProtection(false, 60)}
                      >
                        暂停 1 小时
                      </Button>
                    </>
                  ) : (
                    <Button
                      size="sm"
                      variant="primary"
                      disabled={mutating || !canMutate}
                      icon={<PlayCircle className="w-3.5 h-3.5" />}
                      onClick={() => void handleProtection(true, 0)}
                    >
                      立即恢复去广告保护
                    </Button>
                  )}
                </div>

                <div className="flex flex-wrap items-center gap-2 text-xs text-secondary">
                  {(snap.autoWhitelistedSubs?.length || 0) > 0 && (
                    <Badge tone="ok">
                      已自动保护 {snap.autoWhitelistedSubs.length} 个订阅域名
                    </Badge>
                  )}
                  {(snap.auditManagedCount || 0) > 0 && (
                    <Badge tone="accent">行为审计联动阻断 {snap.auditManagedCount} 条</Badge>
                  )}
                </div>
              </div>
            )}

            {capabilities.hasBlockAAAA && (
              <div className="pt-3 border-t border-subtle flex flex-wrap items-center justify-between gap-3">
                <div className="min-w-0 space-y-0.5">
                  <div className="flex items-center gap-2">
                    <span className="text-xs sm:text-sm font-semibold text-primary">
                      屏蔽 AAAA (IPv6) 解析
                    </span>
                    <Badge tone={snap.blockAAAA ? 'ok' : 'neutral'}>
                      {snap.blockAAAA ? '已屏蔽 IPv6 解析' : '允许 IPv6 解析'}
                    </Badge>
                  </div>
                  <div className="text-[11px] sm:text-xs text-secondary">
                    无公网 IPv6 或 IPv6 链路质量差时建议开启，直接返回空 AAAA 消除双栈连接等待超时。
                  </div>
                </div>
                <button
                  type="button"
                  role="switch"
                  aria-checked={Boolean(snap.blockAAAA)}
                  disabled={togglingBlockAAAA || mutating || !canMutate}
                  onClick={() => void handleToggleBlockAAAA(!snap.blockAAAA)}
                  className={`relative inline-flex h-6 w-11 shrink-0 items-center rounded-full border transition-colors cursor-pointer disabled:opacity-50 ${
                    snap.blockAAAA
                      ? 'bg-emerald-500 border-emerald-400'
                      : 'bg-surface2 border-strong'
                  }`}
                >
                  <span
                    className={`inline-block h-4 w-4 rounded-full bg-white shadow transition-transform ${
                      snap.blockAAAA ? 'translate-x-5' : 'translate-x-1'
                    }`}
                  />
                </button>
              </div>
            )}
          </div>
        </SectionCard>
      )}

      <AdGuardUpstreamsCard
        snap={snap}
        probe={probe}
        probing={probing}
        savingUpstreams={savingUpstreams}
        mutating={mutating}
        canMutate={canMutate}
        onRunProbe={() => void runProbe(false)}
        onUpdateUpstreams={handleUpdateUpstreams}
        onTogglePreset={handleToggleUpstreamPreset}
        onRemoveUpstream={handleRemoveUpstream}
      />

      <DNSLeakTestCard />

      <AdGuardRulesAndRewritesSection
        snap={snap}
        capabilities={capabilities}
        canMutate={canMutate}
        mutating={mutating}
        onWhitelist={handleWhitelist}
        onAddRewrite={handleAddRewrite}
        onDeleteRewrite={(domain, answer) => void handleDeleteRewrite(domain, answer)}
        onFilterToggle={(url, name, enabled) => void handleFilterToggle(url, name, enabled)}
        onAddCustomFilter={handleAddCustomFilter}
        onRemoveCustomFilter={(url, name) => void handleRemoveCustomFilter(url, name)}
        onRefreshFilters={() => void handleRefreshFilters()}
      />

      <AdGuardLifecycleSection
        snap={snap}
        capabilities={capabilities}
        busy={busy}
        onAction={onAction}
      />

      <AdGuardCredentialsDrawer
        open={credOpen}
        snap={snap}
        capabilities={capabilities}
        credData={credData}
        credLoading={credLoading}
        resettingPwd={resettingPwd}
        configPreview={configPreview}
        configPreviewLoading={configPreviewLoading}
        configPreviewError={configPreviewError}
        onClose={() => setCredOpen(false)}
        onResetPassword={handleResetPassword}
        onRefreshConfigPreview={loadConfigPreview}
      />
    </div>
  );
};

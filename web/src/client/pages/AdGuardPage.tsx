import React, { useMemo } from 'react';
import {
  AlertTriangle,
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
import { formatDurationSec } from './adguard/adguardHelpers';
import { AdGuardRulesAndRewritesSection } from './adguard/AdGuardRulesAndRewritesSection';
import { AdGuardUninstalledView } from './adguard/AdGuardUninstalledView';
import { AdGuardUpstreamsCard } from './adguard/AdGuardUpstreamsCard';
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
    probe,
    probing,
    pauseRemainSec,
    savingUpstreams,
    credOpen,
    setCredOpen,
    credData,
    credLoading,
    resettingPwd,
    runProbe,
    handleProtection,
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

  const headerBadge = useMemo(() => {
    if (!snap) return <Badge tone="neutral">加载中</Badge>;
    if (!snap.supported) return <Badge tone="warn">当前平台不支持</Badge>;
    if (!snap.installed) {
      return snap.lowMemoryBlocked ? (
        <Badge tone="warn">低内存保护 · 内置 DoH</Badge>
      ) : (
        <Badge tone="neutral">未安装</Badge>
      );
    }
    if (!snap.dnsHealthy) return <Badge tone="danger">未运行</Badge>;
    if (!snap.singboxLinked) {
      return (
        <Badge tone="warn" dot>
          运行中 · 待接管 sing-box
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
        防劫持接管中 · {snap.dnsAddr}
      </Badge>
    );
  }, [snap]);

  if (loading && !snap) {
    return (
      <div className="space-y-5">
        <PageHeader title="防劫持 DNS (AdGuard Home)" description="正在读取本地防劫持引擎与解析遥测…" />
      </div>
    );
  }

  if (snap && !snap.installed) {
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
            '当前设备可用内存较低，强行运行 AdGuard Home 可能导致路由器 OOM 死机断网。确定要忽略保护强制安装吗？',
          )
        }
      />
    );
  }

  return (
    <div className="space-y-5">
      <PageHeader
        title="防劫持 DNS (AdGuard Home)"
        description={`${snap?.version ? `${snap.version} · ` : ''}引擎监听 ${snap?.dnsAddr || '127.0.0.1:5353'}${snap?.isOpenWrt ? ' · OpenWrt 闪存保护已开启' : ''}`}
        badge={headerBadge}
        actions={
          <>
            <Button
              size="sm"
              variant="secondary"
              loading={probing}
              disabled={!snap?.dnsHealthy}
              onClick={() => void runProbe(false)}
              icon={<Zap className="w-3.5 h-3.5" />}
            >
              实测上游
            </Button>
            <Button
              size="sm"
              variant="secondary"
              disabled={mutating || !snap?.webHealthy}
              onClick={() => void handleClearCache()}
              icon={<RefreshCw className="w-3.5 h-3.5" />}
            >
              清 DNS 缓存
            </Button>
            <Button
              size="sm"
              variant="primary"
              onClick={() => void openCredentialsDrawer()}
              icon={<KeyRound className="w-3.5 h-3.5" />}
            >
              原生面板与凭据
            </Button>
          </>
        }
      />

      {snap && snap.dnsHealthy && !snap.protectionEnabled && (
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
                本地 {snap.dnsAddr} 加密防劫持 DoH 解析仍在正常运行中，全屋网络不受任何影响。
              </div>
            </div>
          </div>
          <Button
            size="sm"
            variant="primary"
            disabled={mutating}
            icon={<PlayCircle className="w-3.5 h-3.5" />}
            onClick={() => void handleProtection(true, 0)}
          >
            立即恢复拦截
          </Button>
        </div>
      )}

      {snap && (!snap.dnsHealthy || !snap.singboxLinked) && (
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
                {!snap.dnsHealthy
                  ? 'AdGuard Home 当前处于停止状态（网关正在使用内置纯 IP 加密 DoH 兜底）'
                  : 'AdGuard Home 已运行，但当前 sing-box 尚未将 dns_local 切换至本地接管'}
              </div>
              <div className="text-secondary mt-0.5">
                点击右侧按钮即可在确认本地加密解析就绪后，平滑热重载 sing-box 完成零断网接管。
              </div>
            </div>
          </div>
          <Button
            size="sm"
            variant="primary"
            disabled={busy}
            icon={<Power className="w-3.5 h-3.5" />}
            onClick={() => onAction('dns-start')}
          >
            启动并接管 DNS
          </Button>
        </div>
      )}

      {snap?.dnsHealthy && (
        <SectionCard
          title="防误伤快捷控制"
          icon={<ShieldCheck className="w-4 h-4" />}
          subtitle="遇到小程序、电商活动或视频激励加载异常时，一键临时放行广告拦截（不断网），到点自动恢复"
        >
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div className="flex flex-wrap items-center gap-2">
              {snap.protectionEnabled ? (
                <>
                  <Button
                    size="sm"
                    variant="secondary"
                    disabled={mutating || !snap.webHealthy}
                    icon={<PauseCircle className="w-3.5 h-3.5" />}
                    onClick={() => void handleProtection(false, 5)}
                  >
                    暂停过滤 5 分钟
                  </Button>
                  <Button
                    size="sm"
                    variant="secondary"
                    disabled={mutating || !snap.webHealthy}
                    onClick={() => void handleProtection(false, 30)}
                  >
                    暂停 30 分钟
                  </Button>
                  <Button
                    size="sm"
                    variant="secondary"
                    disabled={mutating || !snap.webHealthy}
                    onClick={() => void handleProtection(false, 60)}
                  >
                    暂停 1 小时
                  </Button>
                </>
              ) : (
                <Button
                  size="sm"
                  variant="primary"
                  disabled={mutating || !snap.webHealthy}
                  icon={<PlayCircle className="w-3.5 h-3.5" />}
                  onClick={() => void handleProtection(true, 0)}
                >
                  立即恢复去广告保护
                </Button>
              )}
            </div>

            <div className="flex flex-wrap items-center gap-2 text-xs text-secondary">
              {snap.autoWhitelistedSubs.length > 0 && (
                <Badge tone="ok">已自动保护 {snap.autoWhitelistedSubs.length} 个订阅域名</Badge>
              )}
              {snap.auditManagedCount > 0 && (
                <Badge tone="accent">行为审计联动阻断 {snap.auditManagedCount} 条</Badge>
              )}
            </div>
          </div>
        </SectionCard>
      )}

      <AdGuardUpstreamsCard
        snap={snap}
        probe={probe}
        probing={probing}
        savingUpstreams={savingUpstreams}
        mutating={mutating}
        onRunProbe={() => void runProbe(false)}
        onUpdateUpstreams={handleUpdateUpstreams}
        onTogglePreset={handleToggleUpstreamPreset}
        onRemoveUpstream={handleRemoveUpstream}
      />

      <DNSLeakTestCard />

      <AdGuardRulesAndRewritesSection
        snap={snap}
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
        dnsHealthy={Boolean(snap?.dnsHealthy)}
        busy={busy}
        onAction={onAction}
      />

      <AdGuardCredentialsDrawer
        open={credOpen}
        snap={snap}
        credData={credData}
        credLoading={credLoading}
        resettingPwd={resettingPwd}
        onClose={() => setCredOpen(false)}
        onResetPassword={handleResetPassword}
      />
    </div>
  );
};

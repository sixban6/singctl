import React, { useEffect, useState } from 'react';
import {
  AlertTriangle,
  CheckCircle2,
  Clock,
  Cpu,
  HardDrive,
  Layers,
  Network,
  RefreshCw,
  ShieldCheck,
  X,
  Zap,
} from 'lucide-react';
import { api } from '../../api';
import { FleetHealReport, HealStatusReport } from '../../types';
import { Badge, Button, CardSkeleton, ConfirmDialog, SectionCard, useToast } from '../../ui';

interface SelfHealSubTabProps {
  onRefresh: () => void;
}

export const SelfHealSubTab: React.FC<SelfHealSubTabProps> = ({ onRefresh }) => {
  const { success, error } = useToast();
  const [healStatus, setHealStatus] = useState<HealStatusReport | null>(null);
  const [loadingHeal, setLoadingHeal] = useState(true);
  const [runningHealScope, setRunningHealScope] = useState<'local' | 'fleet' | null>(null);
  const [savingPolicy, setSavingPolicy] = useState(false);
  const [syncPolicyToFleet, setSyncPolicyToFleet] = useState(true);
  const [lastFleetHeal, setLastFleetHeal] = useState<FleetHealReport | null>(null);
  const [confirmFleetHeal, setConfirmFleetHeal] = useState(false);

  const fetchHealStatus = async (silent = false) => {
    if (!silent) setLoadingHeal(true);
    try {
      const rep = await api.getHealStatus();
      setHealStatus(rep);
    } catch {
      // non-fatal
    } finally {
      if (!silent) setLoadingHeal(false);
    }
  };

  useEffect(() => {
    void fetchHealStatus();
  }, []);

  const executeHeal = async (scope: 'local' | 'fleet') => {
    setRunningHealScope(scope);
    try {
      const res = await api.runHeal({
        scope,
        allowReboot: scope === 'fleet',
      });
      success(res.message);
      setHealStatus(res.status);
      if (res.fleetReport) {
        setLastFleetHeal(res.fleetReport);
      }
      onRefresh();
    } catch (err: unknown) {
      error(err instanceof Error ? err.message : '执行安全自愈失败');
    } finally {
      setRunningHealScope(null);
    }
  };

  const handleTogglePolicy = async (nextEnabled: boolean, nextAutoReboot: boolean) => {
    setSavingPolicy(true);
    try {
      const res = await api.updateHealPolicy({
        autoHealEnabled: nextEnabled,
        schedule: healStatus?.policy?.schedule || '*-*-* 04:00:00',
        autoReboot: nextAutoReboot,
        applyToFleet: syncPolicyToFleet,
      });
      success(res.message);
      setHealStatus(res.status);
    } catch (err: unknown) {
      error(err instanceof Error ? err.message : '保存自动自愈策略失败');
    } finally {
      setSavingPolicy(false);
    }
  };

  if (loadingHeal && !healStatus) {
    return <CardSkeleton rows={5} />;
  }

  const postureTone: 'ok' | 'accent' | 'warn' | 'neutral' = !healStatus
    ? 'neutral'
    : healStatus.posture === 'healthy'
    ? 'ok'
    : healStatus.posture === 'reboot_required'
    ? 'accent'
    : 'warn';

  const postureText = !healStatus
    ? '正在扫描…'
    : healStatus.postureLabel ||
      (healStatus.posture === 'healthy'
        ? '三层防线已全面免疫'
        : healStatus.posture === 'reboot_required'
        ? '补丁已装 · 待滚动重启生效'
        : '发现待修复安全更新');

  return (
    <div className="space-y-6">
      <SectionCard
        title="三层自动化安全漏洞自愈中心"
        subtitle="核心二进制采用「SHA-256 校验 + 沙盒配置预检 + 异常秒级回滚」，系统补丁严格保护自定义 SSH 2222 配置并热重载动态库，多节点内核采用单台串行滚动重启与故障熔断"
        icon={<ShieldCheck className="w-4 h-4" />}
        badge={
          <Badge tone={postureTone} dot={Boolean(healStatus)}>
            {postureText}
          </Badge>
        }
        actions={
          <div className="flex flex-wrap items-center gap-2">
            <Button
              size="sm"
              variant="primary"
              loading={runningHealScope === 'local'}
              disabled={Boolean(runningHealScope)}
              onClick={() => void executeHeal('local')}
              icon={<Zap className="w-3.5 h-3.5" />}
            >
              {runningHealScope === 'local' ? '本机自愈中…' : '立即自愈本机'}
            </Button>
            <Button
              size="sm"
              variant="secondary"
              loading={runningHealScope === 'fleet'}
              disabled={Boolean(runningHealScope)}
              onClick={() => setConfirmFleetHeal(true)}
              icon={<Network className="w-3.5 h-3.5" />}
            >
              {runningHealScope === 'fleet' ? '全网自愈中…' : '全舰队协同自愈'}
            </Button>
            <Button
              size="sm"
              variant="ghost"
              loading={loadingHeal}
              disabled={Boolean(runningHealScope)}
              onClick={() => void fetchHealStatus(false)}
              icon={<RefreshCw className="w-3.5 h-3.5" />}
            >
              重新扫描
            </Button>
          </div>
        }
      >
        <div className="space-y-5">
          {/* 3 Defense Layer Cards */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3.5">
            {/* Layer 1: Core Stack */}
            <div className="p-4 rounded-xl bg-surface2 border border-subtle space-y-3 flex flex-col justify-between">
              <div className="space-y-2.5">
                <div className="flex items-center justify-between gap-2">
                  <div className="flex items-center gap-2 text-xs font-semibold text-primary">
                    <Layers className="w-4 h-4 text-accent" />
                    <span>第一层 · 核心代理栈</span>
                  </div>
                  <Badge tone={healStatus?.core?.healthy ? 'ok' : 'warn'}>
                    {healStatus
                      ? healStatus.core.healthy
                        ? '全部最新 ✓'
                        : `${healStatus.core.pendingCount} 项待升`
                      : '--'}
                  </Badge>
                </div>
                <div className="space-y-1.5 text-xs font-mono">
                  {(healStatus?.core?.components || [])
                    .filter((c) => c.installed)
                    .map((c) => (
                      <div key={c.name} className="flex items-center justify-between gap-2 text-[11px]">
                        <span className="text-secondary truncate">{c.displayName}</span>
                        {c.hasUpdate ? (
                          <span style={{ color: 'var(--status-warn)' }}>
                            v{c.currentVersion} → v{c.latestVersion}
                          </span>
                        ) : (
                          <span style={{ color: 'var(--status-ok)' }}>v{c.currentVersion} ✓</span>
                        )}
                      </div>
                    ))}
                </div>
              </div>
              <div className="text-[11px] text-muted pt-2 border-t border-subtle">
                金丝雀校验 + <code className="font-mono text-secondary">.heal.bak</code> 15s 秒级回滚
              </div>
            </div>

            {/* Layer 2: OS & Shared Libs */}
            <div className="p-4 rounded-xl bg-surface2 border border-subtle space-y-3 flex flex-col justify-between">
              <div className="space-y-2.5">
                <div className="flex items-center justify-between gap-2">
                  <div className="flex items-center gap-2 text-xs font-semibold text-primary">
                    <HardDrive className="w-4 h-4 text-accent" />
                    <span>第二层 · 系统与应用库</span>
                  </div>
                  <Badge tone={healStatus?.os?.healthy ? 'ok' : 'warn'}>
                    {healStatus ? (healStatus.os.healthy ? '零高危漏洞 ✓' : '待热修补') : '--'}
                  </Badge>
                </div>
                <div className="space-y-1.5 text-[11px] font-mono">
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-muted">发行版环境</span>
                    <span className="text-primary truncate max-w-[160px]">
                      {healStatus?.os?.distro || '--'}
                    </span>
                  </div>
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-muted">安全仓库补丁</span>
                    <span
                      style={{
                        color: healStatus?.os?.securityCount
                          ? 'var(--status-warn)'
                          : 'var(--status-ok)',
                      }}
                    >
                      {healStatus ? `${healStatus.os.securityCount} 个待装` : '--'}
                    </span>
                  </div>
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-muted">内存残留旧 .so</span>
                    <span
                      style={{
                        color: healStatus?.os?.staleServices?.length
                          ? 'var(--status-warn)'
                          : 'var(--status-ok)',
                      }}
                    >
                      {healStatus
                        ? healStatus.os.staleServices?.length
                          ? healStatus.os.staleServices.join(', ')
                          : '干净无残留 ✓'
                        : '--'}
                    </span>
                  </div>
                </div>
              </div>
              <div className="text-[11px] text-muted pt-2 border-t border-subtle">
                强制 <code className="font-mono text-secondary">--force-confold</code> 保护 SSH 2222 配置
              </div>
            </div>

            {/* Layer 3: Kernel & Rolling Reboot */}
            <div className="p-4 rounded-xl bg-surface2 border border-subtle space-y-3 flex flex-col justify-between">
              <div className="space-y-2.5">
                <div className="flex items-center justify-between gap-2">
                  <div className="flex items-center gap-2 text-xs font-semibold text-primary">
                    <Cpu className="w-4 h-4 text-accent" />
                    <span>第三层 · 内核与滚动重启</span>
                  </div>
                  <Badge tone={healStatus?.kernel?.healthy ? 'ok' : 'accent'}>
                    {healStatus
                      ? healStatus.kernel.rebootRequired
                        ? '待重启加载'
                        : '无需重启 ✓'
                      : '--'}
                  </Badge>
                </div>
                <div className="space-y-1.5 text-[11px] font-mono">
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-muted">当前运行内核</span>
                    <span className="text-primary truncate max-w-[165px]">
                      {healStatus?.kernel?.runningKernel || '--'}
                    </span>
                  </div>
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-muted">磁盘最新内核</span>
                    <span className="text-secondary truncate max-w-[165px]">
                      {healStatus?.kernel?.installedKernel ||
                        healStatus?.kernel?.runningKernel ||
                        '--'}
                    </span>
                  </div>
                  {healStatus?.kernel?.rebootReason && (
                    <div className="text-accent text-[10px] leading-snug pt-0.5">
                      {healStatus.kernel.rebootReason}
                    </div>
                  )}
                </div>
              </div>
              <div className="text-[11px] text-muted pt-2 border-t border-subtle">
                舰队每次最多重启 1 台 · 超时自动熔断中止
              </div>
            </div>
          </div>

          {/* Automated Daily 04:00 Timer Policy Bar */}
          <div className="p-4 rounded-xl bg-surface2 border border-subtle flex flex-col lg:flex-row lg:items-center justify-between gap-3.5">
            <div className="space-y-1">
              <div className="flex flex-wrap items-center gap-2 text-xs font-semibold text-primary">
                <Clock className="w-4 h-4 text-accent" />
                <span>凌晨维护窗口自动巡检与自愈守护 (systemd timer)</span>
                {healStatus?.timer?.enabled && (
                  <Badge tone="ok">已启用 · {healStatus.timer.schedule}</Badge>
                )}
              </div>
              <p className="text-[11px] text-secondary">
                默认每日凌晨 <code className="font-mono text-primary">04:00</code>{' '}
                低峰期自动唤醒巡检修复，执行完毕即退出，平时常驻内存为 0MB
                {healStatus?.timer?.nextRun ? `（下次触发: ${healStatus.timer.nextRun}）` : ''}
              </p>
            </div>

            <div className="flex flex-wrap items-center gap-3 text-xs">
              <label className="inline-flex items-center gap-1.5 text-secondary cursor-pointer select-none">
                <input
                  type="checkbox"
                  checked={syncPolicyToFleet}
                  onChange={(e) => setSyncPolicyToFleet(e.target.checked)}
                  className="accent-[var(--accent)]"
                />
                <span>同步下发至全部子节点</span>
              </label>

              <label className="inline-flex items-center gap-1.5 text-secondary cursor-pointer select-none">
                <input
                  type="checkbox"
                  disabled={savingPolicy}
                  checked={Boolean(healStatus?.policy?.autoReboot)}
                  onChange={(e) =>
                    void handleTogglePolicy(
                      healStatus?.policy?.autoHealEnabled ?? true,
                      e.target.checked
                    )
                  }
                  className="accent-[var(--accent)]"
                />
                <span>允许凌晨窗口自动重启新内核</span>
              </label>

              <Button
                size="xs"
                variant={healStatus?.policy?.autoHealEnabled ? 'danger' : 'primary'}
                loading={savingPolicy}
                onClick={() =>
                  void handleTogglePolicy(
                    !healStatus?.policy?.autoHealEnabled,
                    Boolean(healStatus?.policy?.autoReboot)
                  )
                }
              >
                {healStatus?.policy?.autoHealEnabled ? '关闭定时自愈' : '开启每日 04:00 自动自愈'}
              </Button>
            </div>
          </div>

          {/* Fleet Heal Result Summary if Triggered */}
          {lastFleetHeal && lastFleetHeal.results.length > 0 && (
            <div className="p-4 rounded-xl bg-[var(--accent-soft)] border border-[var(--accent)] space-y-2.5 text-xs font-mono">
              <div className="flex items-center justify-between text-primary font-semibold">
                <span>
                  最近一次舰队协同自愈结果 ({lastFleetHeal.healthyNodes}/
                  {lastFleetHeal.totalNodes} 健康)
                </span>
                <button
                  type="button"
                  onClick={() => setLastFleetHeal(null)}
                  className="p-1 text-muted hover:text-primary cursor-pointer"
                  aria-label="关闭结果"
                >
                  <X className="w-3.5 h-3.5" />
                </button>
              </div>
              {lastFleetHeal.circuitBreakerHit && (
                <div className="p-2.5 rounded-lg bg-[var(--status-danger-soft)] border border-[var(--status-danger)] text-primary flex items-center gap-2">
                  <AlertTriangle className="w-4 h-4 shrink-0" />
                  <span>{lastFleetHeal.circuitBreakerNote}</span>
                </div>
              )}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                {lastFleetHeal.results.map((r) => (
                  <div
                    key={r.id}
                    className="p-2.5 rounded-lg bg-surface1 border border-subtle flex items-start gap-2"
                  >
                    {r.success ? (
                      <CheckCircle2
                        className="w-3.5 h-3.5 shrink-0 mt-0.5"
                        style={{ color: 'var(--status-ok)' }}
                      />
                    ) : (
                      <AlertTriangle
                        className="w-3.5 h-3.5 shrink-0 mt-0.5"
                        style={{ color: 'var(--status-danger)' }}
                      />
                    )}
                    <div className="min-w-0">
                      <div className="font-semibold text-primary">
                        {r.name} (#{r.id})
                      </div>
                      <div className="text-[11px] text-secondary break-words">{r.summary}</div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Recent Self-Healing History */}
          {healStatus?.history && healStatus.history.length > 0 && (
            <div className="space-y-2">
              <div className="text-xs font-semibold text-muted">最近自愈记录</div>
              <div className="space-y-1.5 max-h-48 overflow-y-auto pr-1">
                {healStatus.history.slice(0, 6).map((h, i) => (
                  <div
                    key={`${h.timestamp}-${i}`}
                    className="px-3 py-2 rounded-xl bg-surface2 border border-subtle flex flex-col sm:flex-row sm:items-center justify-between gap-1 text-xs font-mono"
                  >
                    <div className="flex items-center gap-2 min-w-0">
                      <span
                        style={{
                          color: h.success ? 'var(--status-ok)' : 'var(--status-warn)',
                        }}
                      >
                        {h.success ? '✓' : '!'}
                      </span>
                      <span className="text-primary font-sans truncate">{h.summary}</span>
                    </div>
                    <div className="text-[11px] text-muted shrink-0">
                      [{h.trigger}] {new Date(h.timestamp).toLocaleString()}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </SectionCard>

      <ConfirmDialog
        open={confirmFleetHeal}
        title="确认对全舰队与本机执行「三层自动化安全自愈」？"
        description="核心组件与系统安全补丁将在后台并发无感热修复（失败秒级回滚）；需加载新内核的子节点将按单台串行滚动重启并启用异常熔断保护。"
        confirmText="立即全网自愈"
        onConfirm={() => {
          setConfirmFleetHeal(false);
          void executeHeal('fleet');
        }}
        onCancel={() => setConfirmFleetHeal(false)}
      />
    </div>
  );
};

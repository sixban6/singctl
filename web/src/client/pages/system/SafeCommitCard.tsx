import React, { useCallback, useEffect, useState } from 'react';
import {
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  History,
  Play,
  RefreshCw,
  RotateCcw,
  Save,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Timer,
} from 'lucide-react';
import { Badge, Button, ConfirmDialog, SectionCard, useToast } from '../../../ui';
import { clientApi } from '../../api';
import { SafeCommitStatusReport, SafeCommitStatusResponse } from '../../types';

export interface SafeCommitCardProps {
  liveSafeCommit?: SafeCommitStatusReport | null;
  busy?: boolean;
  onRefreshStatus?: () => void | Promise<void>;
}

const TTL_PRESETS = [120, 180, 300] as const;

function formatUnixTime(unixSec?: number): string {
  if (!unixSec || unixSec <= 0) return '—';
  try {
    return new Date(unixSec * 1000).toLocaleString();
  } catch {
    return String(unixSec);
  }
}

function formatTrigger(trigger?: string): string {
  switch (trigger) {
    case 'timeout':
      return '倒计时超时自动回滚';
    case 'manual':
      return '手动触发回滚';
    default:
      return trigger || '未知来源';
  }
}

export const SafeCommitCard: React.FC<SafeCommitCardProps> = ({
  liveSafeCommit,
  busy = false,
  onRefreshStatus,
}) => {
  const { success, error } = useToast();
  const [data, setData] = useState<SafeCommitStatusResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [defaultTtlSec, setDefaultTtlSec] = useState(180);
  const [protectTailscaleOom, setProtectTailscaleOom] = useState(true);
  const [saving, setSaving] = useState(false);
  const [protectingOom, setProtectingOom] = useState(false);
  const [arming, setArming] = useState(false);
  const [armReason, setArmReason] = useState('');
  const [confirming, setConfirming] = useState(false);
  const [rollingBack, setRollingBack] = useState(false);
  const [rollbackOpen, setRollbackOpen] = useState(false);
  const [historyOpen, setHistoryOpen] = useState(false);

  const loadStatus = useCallback(async (silent = false) => {
    if (!silent) setLoading(true);
    try {
      const res = await clientApi.getSafeCommitStatus();
      setData(res);
      if (res.config) {
        setDefaultTtlSec(Math.min(600, Math.max(60, res.config.defaultTtlSec || 180)));
        setProtectTailscaleOom(Boolean(res.config.protectTailscaleOom));
      }
    } catch (err: unknown) {
      if (!silent) {
        error(`读取安全回滚状态失败：${err instanceof Error ? err.message : '未知错误'}`);
      }
    } finally {
      if (!silent) setLoading(false);
    }
  }, [error]);

  useEffect(() => {
    void loadStatus(false);
  }, [loadStatus]);

  // 全局状态中的 safeCommit 变化时静默同步本卡片
  useEffect(() => {
    if (liveSafeCommit) {
      setData((prev) =>
        prev
          ? {
              ...prev,
              active: liveSafeCommit.active,
              state: liveSafeCommit.state,
              remainingSec: liveSafeCommit.remainingSec,
              lastRollback: liveSafeCommit.lastRollback,
              tailscaleOom: liveSafeCommit.tailscaleOom,
            }
          : prev,
      );
    }
  }, [liveSafeCommit]);

  const handleSaveConfig = async (e: React.FormEvent) => {
    e.preventDefault();
    const clampedTtl = Math.min(600, Math.max(60, Math.round(defaultTtlSec)));
    setSaving(true);
    try {
      const res = await clientApi.saveSafeCommitConfig({
        defaultTtlSec: clampedTtl,
        protectTailscaleOom,
      });
      setDefaultTtlSec(res.config.defaultTtlSec);
      setProtectTailscaleOom(res.config.protectTailscaleOom);
      setData((prev) =>
        prev ? { ...prev, config: res.config, tailscaleOom: res.tailscaleOom } : prev,
      );
      success('安全回滚与 OOM 免疫策略已保存');
      await onRefreshStatus?.();
    } catch (err: unknown) {
      error(`保存安全回滚策略失败：${err instanceof Error ? err.message : '未知错误'}`);
    } finally {
      setSaving(false);
    }
  };

  const handleProtectOOM = async () => {
    setProtectingOom(true);
    try {
      const res = await clientApi.protectTailscaleOOM();
      setData((prev) => (prev ? { ...prev, tailscaleOom: res.tailscaleOom } : prev));
      if (res.ok) {
        success(`已为 tailscaled (PID ${res.tailscaleOom.pid ?? '-'}) 应用 OOM 免疫 (-1000)`);
      } else {
        error(res.error || res.tailscaleOom?.message || '未发现运行中的 tailscaled 进程');
      }
      await onRefreshStatus?.();
    } catch (err: unknown) {
      error(`应用 tailscaled OOM 免疫失败：${err instanceof Error ? err.message : '未知错误'}`);
    } finally {
      setProtectingOom(false);
    }
  };

  const handleArm = async () => {
    setArming(true);
    try {
      const res = await clientApi.armSafeCommit({
        ttlSec: Math.min(600, Math.max(60, Math.round(defaultTtlSec))),
        reason: armReason.trim() || '手动开启高危调试保护',
      });
      setData(res.status);
      setArmReason('');
      success(`安全回滚保险丝已开启（倒计时 ${res.status.state?.ttlSec || defaultTtlSec} 秒）`);
      await onRefreshStatus?.();
    } catch (err: unknown) {
      error(`开启安全回滚倒计时失败：${err instanceof Error ? err.message : '未知错误'}`);
    } finally {
      setArming(false);
    }
  };

  const handleConfirm = async () => {
    setConfirming(true);
    try {
      const res = await clientApi.confirmSafeCommit(data?.state?.token);
      setData(res.status);
      success('已确认保留当前配置，保险丝已解除');
      await onRefreshStatus?.();
    } catch (err: unknown) {
      error(`确认保留配置失败：${err instanceof Error ? err.message : '未知错误'}`);
    } finally {
      setConfirming(false);
    }
  };

  const handleRollback = async () => {
    setRollingBack(true);
    try {
      const res = await clientApi.rollbackSafeCommit('manual');
      setRollbackOpen(false);
      setData(res.status);
      if (res.record?.success) {
        success('网关已立即回滚至安全快照');
      } else {
        error(`回滚未完全成功：${res.record?.error || '请查看系统日志'}`);
      }
      await onRefreshStatus?.();
    } catch (err: unknown) {
      error(`立即回滚失败：${err instanceof Error ? err.message : '未知错误'}`);
    } finally {
      setRollingBack(false);
    }
  };

  const active = Boolean(data?.active);
  const oom = data?.tailscaleOom;
  const lastRollback = data?.lastRollback;

  return (
    <>
      <SectionCard
        title="安全回滚保险丝与 OOM 免疫"
        icon={<ShieldAlert className="w-4 h-4" />}
        subtitle="远端高危网络/防火墙变更防失联保险丝（/tmp 内存盘快照）与 tailscaled 进程 OOM 免疫保护"
        badge={
          active ? (
            <Badge tone="warn" dot pulse>
              倒计时保护中
            </Badge>
          ) : (
            <Badge tone="ok" dot>
              就绪待命
            </Badge>
          )
        }
        actions={
          <Button
            size="xs"
            variant="ghost"
            disabled={loading}
            onClick={() => void loadStatus(false)}
            icon={<RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />}
          >
            刷新
          </Button>
        }
      >
        <div className="space-y-4">
          {/* Status Dual-Panel */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-3.5">
            {/* Safe Commit Fuse Status */}
            <div className="p-3.5 rounded-xl bg-surface2 border border-subtle flex flex-col justify-between gap-3">
              <div className="flex items-start justify-between gap-2">
                <div className="flex items-center gap-2">
                  <Timer className={`w-4 h-4 ${active ? 'text-amber-400' : 'text-emerald-400'}`} />
                  <span className="text-xs sm:text-sm font-semibold text-primary">
                    Safe Commit 保险丝状态
                  </span>
                </div>
                <Badge tone={active ? 'warn' : 'neutral'} dot={active} pulse={active}>
                  {active ? `剩余 ${data?.remainingSec ?? 0}s` : '未激活'}
                </Badge>
              </div>

              {active && data?.state ? (
                <div className="space-y-1.5 text-xs">
                  <div className="text-amber-200 font-medium">
                    原因：{data.state.reason || '高危变更保护中'}
                  </div>
                  <div className="text-[11px] font-mono text-muted tnum">
                    TTL {data.state.ttlSec}s · Token {data.state.token.slice(0, 8)}…
                    {data.state.watcherPid ? ` · Watcher PID ${data.state.watcherPid}` : ''}
                  </div>
                  <div className="flex flex-wrap gap-2 pt-1.5">
                    <Button
                      size="xs"
                      variant="primary"
                      loading={confirming}
                      disabled={rollingBack || busy}
                      onClick={() => void handleConfirm()}
                      icon={<CheckCircle2 className="w-3.5 h-3.5" />}
                    >
                      确认保留当前配置
                    </Button>
                    <Button
                      size="xs"
                      variant="danger"
                      loading={rollingBack}
                      disabled={confirming || busy}
                      onClick={() => setRollbackOpen(true)}
                      icon={<RotateCcw className="w-3.5 h-3.5" />}
                    >
                      立即回滚
                    </Button>
                  </div>
                </div>
              ) : (
                <div className="space-y-2.5">
                  <p className="text-xs text-secondary leading-relaxed">
                    远端修改代理/防火墙/DNS 前可手动上保险，超时未确认将自动回滚至变更前快照。
                  </p>
                  <div className="flex flex-col sm:flex-row gap-2">
                    <input
                      type="text"
                      value={armReason}
                      onChange={(e) => setArmReason(e.target.value)}
                      placeholder="备注原因（可选，如：调试防火墙规则）"
                      className="flex-1 h-8 px-2.5 rounded-lg bg-surface1 border border-subtle text-xs text-primary focus:outline-none focus:border-strong"
                    />
                    <Button
                      size="xs"
                      variant="secondary"
                      loading={arming}
                      disabled={busy || loading}
                      onClick={() => void handleArm()}
                      icon={<Play className="w-3 h-3" />}
                    >
                      手动开启一次安全回滚倒计时
                    </Button>
                  </div>
                </div>
              )}
            </div>

            {/* tailscaled OOM Shield Status */}
            <div className="p-3.5 rounded-xl bg-surface2 border border-subtle flex flex-col justify-between gap-3">
              <div className="flex items-start justify-between gap-2">
                <div className="flex items-center gap-2">
                  {oom?.protected ? (
                    <ShieldCheck className="w-4 h-4 text-emerald-400" />
                  ) : (
                    <Shield className="w-4 h-4 text-slate-400" />
                  )}
                  <span className="text-xs sm:text-sm font-semibold text-primary">
                    tailscaled OOM 免疫保护
                  </span>
                </div>
                <Badge
                  tone={oom?.protected ? 'ok' : oom?.found ? 'warn' : 'neutral'}
                  dot={Boolean(oom?.found)}
                >
                  {oom?.protected ? '已免疫 (-1000)' : oom?.found ? '未免疫' : '未运行'}
                </Badge>
              </div>

              <div className="space-y-1 text-xs">
                <div className="flex flex-wrap items-center gap-x-4 gap-y-1 font-mono text-secondary tnum">
                  <span>进程：{oom?.found ? `PID ${oom.pid ?? '-'}` : '未发现 tailscaled'}</span>
                  {oom?.found && (
                    <span>
                      oom_score_adj:{' '}
                      <strong className={oom.scoreAdj <= -1000 ? 'text-emerald-400' : 'text-amber-300'}>
                        {oom.scoreAdj}
                      </strong>
                    </span>
                  )}
                </div>
                <p className="text-[11px] text-muted leading-relaxed">
                  {oom?.message ||
                    '将 tailscaled 的 oom_score_adj 锁定为 -1000，避免小内存路由器触发 OOM Killer 导致远程失联。'}
                </p>
              </div>

              <div>
                <Button
                  size="xs"
                  variant={oom?.protected ? 'secondary' : 'primary'}
                  loading={protectingOom}
                  disabled={busy || loading}
                  onClick={() => void handleProtectOOM()}
                  icon={<ShieldCheck className="w-3.5 h-3.5" />}
                >
                  立即保护 tailscaled OOM
                </Button>
              </div>
            </div>
          </div>

          {/* Policy Form */}
          <form
            onSubmit={(e) => void handleSaveConfig(e)}
            className="p-3.5 rounded-xl bg-surface2 border border-subtle space-y-3"
          >
            <div className="grid grid-cols-1 lg:grid-cols-12 gap-4 items-center">
              <div className="lg:col-span-7 space-y-2">
                <div className="flex items-center justify-between gap-2 text-xs">
                  <span className="text-secondary font-medium">默认回滚倒计时（60 ~ 600 秒）</span>
                  <span className="font-mono font-semibold text-emerald-400 tnum">
                    {defaultTtlSec} 秒 ({(defaultTtlSec / 60).toFixed(defaultTtlSec % 60 === 0 ? 0 : 1)} 分钟)
                  </span>
                </div>
                <div className="flex flex-wrap items-center gap-3">
                  <input
                    type="range"
                    min={60}
                    max={600}
                    step={10}
                    value={defaultTtlSec}
                    onChange={(e) => setDefaultTtlSec(Number(e.target.value))}
                    className="flex-1 min-w-[140px] accent-emerald-500 cursor-pointer"
                  />
                  <div className="inline-flex items-center gap-1">
                    {TTL_PRESETS.map((sec) => (
                      <button
                        key={sec}
                        type="button"
                        onClick={() => setDefaultTtlSec(sec)}
                        className={`px-2 py-1 rounded-lg text-[11px] font-mono border transition-colors cursor-pointer ${
                          defaultTtlSec === sec
                            ? 'bg-emerald-500/15 text-emerald-300 border-emerald-500/40 font-semibold'
                            : 'bg-surface1 text-secondary border-subtle hover:text-primary'
                        }`}
                      >
                        {sec}s
                      </button>
                    ))}
                  </div>
                </div>
              </div>

              <div className="lg:col-span-5 flex flex-col sm:flex-row lg:flex-col xl:flex-row sm:items-center justify-between gap-3">
                <label className="flex items-start gap-2 text-xs text-secondary cursor-pointer select-none">
                  <input
                    type="checkbox"
                    checked={protectTailscaleOom}
                    onChange={(e) => setProtectTailscaleOom(e.target.checked)}
                    className="mt-0.5 rounded border-subtle bg-surface1 accent-emerald-500"
                  />
                  <span className="leading-snug">守护进程自动维护 tailscaled OOM 免疫</span>
                </label>

                <Button
                  type="submit"
                  size="sm"
                  variant="primary"
                  loading={saving}
                  disabled={loading || busy}
                  icon={<Save className="w-3.5 h-3.5" />}
                >
                  保存策略
                </Button>
              </div>
            </div>
          </form>

          {/* Collapsible Last Rollback Record */}
          <div className="rounded-xl bg-surface2 border border-subtle overflow-hidden">
            <button
              type="button"
              onClick={() => setHistoryOpen((v) => !v)}
              className="w-full px-3.5 py-2.5 flex items-center justify-between gap-2 text-xs hover:bg-slate-800/30 transition-colors cursor-pointer"
              aria-expanded={historyOpen}
            >
              <div className="flex items-center gap-2 min-w-0">
                {historyOpen ? (
                  <ChevronDown className="w-3.5 h-3.5 text-slate-400 shrink-0" />
                ) : (
                  <ChevronRight className="w-3.5 h-3.5 text-slate-400 shrink-0" />
                )}
                <History className="w-3.5 h-3.5 text-slate-400 shrink-0" />
                <span className="font-medium text-primary">最近一次回滚记录</span>
              </div>
              {lastRollback ? (
                <div className="flex items-center gap-2 shrink-0">
                  <span className="hidden sm:inline font-mono text-[11px] text-muted tnum">
                    {formatUnixTime(lastRollback.rolledBackAt)}
                  </span>
                  <Badge tone={lastRollback.success ? 'ok' : 'danger'}>
                    {lastRollback.success ? '回滚成功' : '回滚异常'}
                  </Badge>
                </div>
              ) : (
                <span className="text-[11px] text-muted">暂无记录</span>
              )}
            </button>

            {historyOpen && (
              <div className="px-3.5 pb-3.5 pt-2 border-t border-subtle text-xs space-y-2">
                {lastRollback ? (
                  <>
                    <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-secondary">
                      <span>触发方式：{formatTrigger(lastRollback.trigger)}</span>
                      <span className="font-mono tnum">
                        时间：{formatUnixTime(lastRollback.rolledBackAt)}
                      </span>
                      {lastRollback.reason && <span>原因：{lastRollback.reason}</span>}
                    </div>
                    {lastRollback.actions && lastRollback.actions.length > 0 && (
                      <ul className="list-disc pl-5 space-y-0.5 font-mono text-[11px] text-slate-300">
                        {lastRollback.actions.map((act, i) => (
                          <li key={i}>{act}</li>
                        ))}
                      </ul>
                    )}
                    {lastRollback.error && (
                      <div className="p-2 rounded-lg bg-rose-500/10 border border-rose-500/25 text-rose-300 font-mono text-[11px]">
                        错误：{lastRollback.error}
                      </div>
                    )}
                  </>
                ) : (
                  <p className="text-muted">尚未触发过安全回滚操作。</p>
                )}
              </div>
            )}
          </div>
        </div>
      </SectionCard>

      <ConfirmDialog
        open={rollbackOpen}
        title="确认立即回滚网关配置"
        description="将立即把配置恢复至开启 Safe Commit 保险丝前的快照并重载服务。确认继续？"
        confirmText="立即回滚"
        danger
        loading={rollingBack}
        onConfirm={() => void handleRollback()}
        onCancel={() => setRollbackOpen(false)}
      />
    </>
  );
};

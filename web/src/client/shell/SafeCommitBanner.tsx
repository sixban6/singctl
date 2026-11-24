import React, { useEffect, useRef, useState } from 'react';
import { CheckCircle2, RotateCcw, ShieldAlert, Timer } from 'lucide-react';
import { Button, ConfirmDialog, useToast } from '../../ui';
import { clientApi } from '../api';
import { SafeCommitStatusReport } from '../types';

export interface SafeCommitBannerProps {
  safeCommit?: SafeCommitStatusReport | null;
  onRefreshStatus: () => void | Promise<void>;
}

function formatCountdown(sec: number): string {
  const clamped = Math.max(0, Math.floor(sec));
  const mins = Math.floor(clamped / 60);
  const rem = clamped % 60;
  return `${String(mins).padStart(2, '0')}:${String(rem).padStart(2, '0')}`;
}

export const SafeCommitBanner: React.FC<SafeCommitBannerProps> = ({
  safeCommit,
  onRefreshStatus,
}) => {
  const { success, error } = useToast();
  const [confirming, setConfirming] = useState(false);
  const [rollingBack, setRollingBack] = useState(false);
  const [rollbackDialogOpen, setRollbackDialogOpen] = useState(false);
  const [remainingSec, setRemainingSec] = useState(0);

  // 记录浏览器本地时钟与网关时钟偏差，确保基于 deadlineUnix 的每秒倒计时不受路由器 NTP 偏差干扰
  const skewRef = useRef(0);
  const expiredRefreshedRef = useRef(false);

  const active = Boolean(safeCommit?.active);
  const deadlineUnix = safeCommit?.state?.deadlineUnix ?? 0;
  const serverRemaining = safeCommit?.remainingSec ?? 0;
  const ttlSec = Math.max(1, safeCommit?.state?.ttlSec ?? 180);
  const token = safeCommit?.state?.token;
  const reason = safeCommit?.state?.reason;

  useEffect(() => {
    if (!active) {
      setRemainingSec(0);
      expiredRefreshedRef.current = false;
      return;
    }

    const nowSec = Math.floor(Date.now() / 1000);
    if (deadlineUnix > 0 && serverRemaining >= 0) {
      const estimatedServerNow = deadlineUnix - serverRemaining;
      const rawSkew = estimatedServerNow - nowSec;
      skewRef.current = Math.abs(rawSkew) > 5 ? rawSkew : 0;
    } else {
      skewRef.current = 0;
    }
    expiredRefreshedRef.current = false;

    const computeRemaining = () => {
      if (deadlineUnix > 0) {
        const estNow = Math.floor(Date.now() / 1000) + skewRef.current;
        return Math.max(0, deadlineUnix - estNow);
      }
      return Math.max(0, serverRemaining);
    };

    setRemainingSec(computeRemaining());

    const timer = window.setInterval(() => {
      const next = computeRemaining();
      setRemainingSec(next);
      if (next === 0 && !expiredRefreshedRef.current) {
        expiredRefreshedRef.current = true;
        window.setTimeout(() => {
          void onRefreshStatus();
        }, 1500);
      }
    }, 1000);

    return () => window.clearInterval(timer);
  }, [active, deadlineUnix, serverRemaining, onRefreshStatus]);

  if (!active) return null;

  const urgent = remainingSec <= 30;
  const progressPct = Math.min(100, Math.max(0, Math.round((remainingSec / ttlSec) * 100)));

  const handleConfirm = async () => {
    setConfirming(true);
    try {
      const res = await clientApi.confirmSafeCommit(token);
      success(res.confirmed ? '已确认保留当前配置，安全回滚保险丝已解除' : '当前无激活保险丝');
      await onRefreshStatus();
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
      setRollbackDialogOpen(false);
      if (res.record?.success) {
        const actionSummary = res.record.actions?.length
          ? `（已执行 ${res.record.actions.length} 项恢复动作）`
          : '';
        success(`配置已立即回滚至安全快照${actionSummary}`, 6000);
      } else {
        error(`回滚执行存在异常：${res.record?.error || '请检查系统日志'}`);
      }
      await onRefreshStatus();
    } catch (err: unknown) {
      error(`立即回滚失败：${err instanceof Error ? err.message : '未知错误'}`);
    } finally {
      setRollingBack(false);
    }
  };

  return (
    <>
      <div className="max-w-[1440px] mx-auto px-page-safe pb-2.5 pt-0.5">
        <div
          role="alert"
          className={`rounded-2xl border backdrop-blur-xl shadow-xl overflow-hidden animate-sc-in transition-colors ${
            urgent
              ? 'border-rose-500/60 bg-gradient-to-r from-rose-950/95 via-orange-950/90 to-amber-950/90 shadow-rose-950/40'
              : 'border-amber-500/45 bg-gradient-to-r from-amber-950/90 via-orange-950/85 to-slate-900/90 shadow-amber-950/35'
          }`}
        >
          <div className="px-3 py-2 sm:px-4 sm:py-2.5 flex flex-col md:flex-row md:items-center justify-between gap-2.5">
            <div className="flex items-start sm:items-center gap-2.5 sm:gap-3 min-w-0">
              <div
                className={`w-8 h-8 sm:w-9 sm:h-9 rounded-xl flex items-center justify-center shrink-0 border ${
                  urgent
                    ? 'bg-rose-500/20 border-rose-400/40 text-rose-300 animate-pulse'
                    : 'bg-amber-500/20 border-amber-400/35 text-amber-300'
                }`}
              >
                <ShieldAlert className="w-4 h-4 sm:w-5 sm:h-5" />
              </div>

              <div className="min-w-0 space-y-0.5">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="text-xs sm:text-sm font-bold text-amber-100">
                    安全回滚保险丝已激活
                  </span>
                  <span
                    className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-mono font-bold tnum border ${
                      urgent
                        ? 'bg-rose-500/25 text-rose-200 border-rose-400/50'
                        : 'bg-amber-500/20 text-amber-200 border-amber-400/35'
                    }`}
                  >
                    <Timer className="w-3.5 h-3.5" />
                    {remainingSec > 0 ? `剩余 ${formatCountdown(remainingSec)}` : '正在触发自动回滚…'}
                  </span>
                </div>
                <p className="text-[11px] sm:text-xs text-amber-200/85 truncate" title={reason || '网络/防火墙高危配置保护中'}>
                  {reason ? `改动原因：${reason} · ` : ''}
                  若倒计时归零前未确认，网关将自动恢复变更前快照防止远端失联。
                </p>
              </div>
            </div>

            <div className="flex items-center gap-2 shrink-0 flex-wrap">
              <Button
                size="sm"
                variant="primary"
                loading={confirming}
                disabled={rollingBack}
                onClick={() => void handleConfirm()}
                icon={<CheckCircle2 className="w-3.5 h-3.5" />}
              >
                确认保留当前配置
              </Button>
              <Button
                size="sm"
                variant="danger"
                loading={rollingBack}
                disabled={confirming}
                onClick={() => setRollbackDialogOpen(true)}
                icon={<RotateCcw className="w-3.5 h-3.5" />}
              >
                立即回滚
              </Button>
            </div>
          </div>

          <div className="h-1 w-full bg-slate-950/70">
            <div
              className={`h-full transition-all duration-1000 ease-linear ${
                urgent ? 'bg-rose-500' : 'bg-amber-400'
              }`}
              style={{ width: `${progressPct}%` }}
            />
          </div>
        </div>
      </div>

      <ConfirmDialog
        open={rollbackDialogOpen}
        title="确认立即回滚网关配置"
        description="系统将立即把 singctl.yaml、OpenWrt 网络/VLAN、sing-box 与 DNS 配置恢复到激活保险丝前的快照，并按原基线重载相关服务。确认执行？"
        confirmText="立即回滚"
        danger
        loading={rollingBack}
        onConfirm={() => void handleRollback()}
        onCancel={() => setRollbackDialogOpen(false)}
      />
    </>
  );
};

import React, { useMemo, useState } from 'react';
import {
  AlertTriangle,
  CheckCircle2,
  Info,
  Radar,
  RefreshCw,
  ShieldCheck,
  Sparkles,
  WifiOff,
} from 'lucide-react';
import { Badge, Button, CardSkeleton, ConfirmDialog, SectionCard, useToast } from '../../../../ui';
import { useCachedQuery } from '../../../../hooks/useCachedQuery';
import { clientApi } from '../../../api';
import { WIFI_OVERVIEW_CACHE_KEY } from '../../../cacheKeys';
import {
  SafeCommitStatusReport,
  WifiApplyRequest,
  WifiOptimizationStep,
  WifiOverview,
  WifiRadioPatch,
  WifiScanResult,
} from '../../../types';
import { WifiChannelChart } from './WifiChannelChart';
import { WifiClientsAndChassis } from './WifiClientsAndChassis';
import { WifiRadioCards } from './WifiRadioCards';

export interface WifiOptSectionProps {
  busy: boolean;
  privacyMask: boolean;
  onRefreshStatus?: () => void;
  onSafeCommitUpdated?: (sc: SafeCommitStatusReport) => void;
}

export const WifiOptSection: React.FC<WifiOptSectionProps> = ({
  busy,
  privacyMask,
  onRefreshStatus,
  onSafeCommitUpdated,
}) => {
  const { success, error: toastError, toast } = useToast();
  const {
    data: overview,
    loading,
    refreshing,
    error,
    setData,
    refetch,
  } = useCachedQuery<WifiOverview>(WIFI_OVERVIEW_CACHE_KEY, () => clientApi.getWifiOverview(false));

  const [scanResult, setScanResult] = useState<WifiScanResult | null>(null);
  const [scanning, setScanning] = useState(false);
  const [applying, setApplying] = useState(false);
  const [chassisBusy, setChassisBusy] = useState(false);

  const [pendingReq, setPendingReq] = useState<WifiApplyRequest | null>(null);
  const [pendingChanges, setPendingChanges] = useState<WifiOptimizationStep[]>([]);
  const [pendingTitle, setPendingTitle] = useState('');

  const allBusy = busy || applying || scanning || chassisBusy;

  const scoreTone = useMemo(() => {
    const lv = overview?.healthLevel;
    if (lv === 'excellent' || lv === 'good') return 'ok';
    if (lv === 'warn') return 'warn';
    return 'danger';
  }, [overview?.healthLevel]);

  const handleRefresh = async () => {
    try {
      const fresh = await clientApi.getWifiOverview(true);
      setData(fresh);
    } catch (err: unknown) {
      toastError(err instanceof Error ? err.message : '刷新 Wi-Fi 状态失败');
    }
  };

  const handleScan = async () => {
    setScanning(true);
    try {
      const res = await clientApi.scanWifiChannels();
      setScanResult(res);
      success(res.summary || '周边信道扫描完成');
    } catch (err: unknown) {
      toastError(err instanceof Error ? err.message : '扫描周边信道失败');
    } finally {
      setScanning(false);
    }
  };

  const openApplyPreview = async (title: string, req: WifiApplyRequest) => {
    setApplying(true);
    try {
      const preview = await clientApi.applyWifiOptimize({ ...req, dryRun: true });
      if (!preview.changes || preview.changes.length === 0) {
        toast(preview.summary || '当前配置已是最优状态，无需修改', 'info');
        return;
      }
      setPendingTitle(title);
      setPendingReq(req);
      setPendingChanges(preview.changes);
    } catch (err: unknown) {
      toastError(err instanceof Error ? err.message : '生成无线优化预览失败');
    } finally {
      setApplying(false);
    }
  };

  const confirmApply = async () => {
    if (!pendingReq) return;
    const req = pendingReq;
    setPendingReq(null);
    setApplying(true);
    try {
      const res = await clientApi.applyWifiOptimize({ ...req, dryRun: false });
      if (res.overview) {
        setData(res.overview);
      } else {
        await refetch(true);
      }
      if (res.safeCommit && onSafeCommitUpdated) {
        onSafeCommitUpdated(res.safeCommit);
      }
      onRefreshStatus?.();
      success(
        `${res.summary}（已启动 ${res.safeCommitTtlSec || 180} 秒防失联倒计时，确认正常后请点顶部「确认生效」）`,
      );
    } catch (err: unknown) {
      toastError(err instanceof Error ? err.message : '应用无线优化失败（已自动回滚原配置）');
      await refetch(true);
    } finally {
      setApplying(false);
    }
  };

  const handleApplyChassis = async (enableRps: boolean, tuneConntrack: boolean) => {
    setChassisBusy(true);
    try {
      const res = await clientApi.applyWifiChassis({ enableRps, tuneConntrack });
      if (overview) {
        setData({ ...overview, chassis: res.chassis });
      }
      success(`底盘加速已生效：${res.actions.join('；')}`);
    } catch (err: unknown) {
      toastError(err instanceof Error ? err.message : '应用底盘加速失败');
    } finally {
      setChassisBusy(false);
    }
  };

  if (loading && !overview) {
    return (
      <div className="space-y-4">
        <CardSkeleton rows={3} />
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          <CardSkeleton rows={5} />
          <CardSkeleton rows={5} />
        </div>
      </div>
    );
  }

  if (error && !overview) {
    return (
      <SectionCard title="Wi-Fi 调优加载失败">
        <div className="py-6 text-center space-y-3">
          <p className="text-xs text-rose-300">{error}</p>
          <Button size="sm" variant="primary" icon={<RefreshCw className="w-3.5 h-3.5" />} onClick={() => void refetch(false)}>
            立即重试
          </Button>
        </div>
      </SectionCard>
    );
  }

  if (!overview) return null;

  return (
    <div className="space-y-4">
      {!overview.supported ? (
        <SectionCard
          title={
            <span className="flex items-center gap-2">
              <WifiOff className="w-4 h-4 text-secondary" />
              <span>当前设备无 OpenWrt 无线射频</span>
            </span>
          }
          subtitle={overview.unsupportedHint || 'Wi-Fi 体检与调优仅适用于带无线网卡的 OpenWrt 路由器'}
        >
          <p className="text-xs text-secondary">
            如当前为旁路由（如 N1 / x86 软路由），下方仍可直接查看并一键开启「高并发底盘加速（多核 RPS 与 Conntrack 扩容）」。
          </p>
        </SectionCard>
      ) : (
        <>
          <div className="rounded-2xl border border-white/10 bg-gradient-to-br from-slate-900/90 via-slate-900/75 to-sky-950/40 p-5 flex flex-col lg:flex-row lg:items-center justify-between gap-4">
            <div className="flex items-start gap-4">
              <div
                className={`w-16 h-16 rounded-2xl border flex flex-col items-center justify-center shrink-0 ${
                  scoreTone === 'ok'
                    ? 'border-emerald-400/40 bg-emerald-500/15 text-emerald-300'
                    : scoreTone === 'warn'
                      ? 'border-amber-400/40 bg-amber-500/15 text-amber-300'
                      : 'border-rose-400/45 bg-rose-500/15 text-rose-300'
                }`}
              >
                <span className="text-2xl font-bold font-mono leading-none">{overview.healthScore}</span>
                <span className="text-[10px] opacity-85 mt-0.5">健康分</span>
              </div>
              <div className="space-y-1.5">
                <div className="flex flex-wrap items-center gap-2">
                  <h3 className="text-sm font-semibold text-primary">Wi-Fi 智能体检与一键调优</h3>
                  <Badge tone={scoreTone}>
                    {overview.healthLevel === 'excellent'
                      ? '极佳'
                      : overview.healthLevel === 'good'
                        ? '良好'
                        : overview.healthLevel === 'warn'
                          ? '待优化'
                          : '高危瓶颈'}
                  </Badge>
                  <Badge tone="neutral">
                    <ShieldCheck className="w-3 h-3 mr-1 inline" />
                    双重防断网自动回滚保护
                  </Badge>
                </div>
                <p className="text-xs text-secondary leading-relaxed">{overview.healthSummary}</p>
              </div>
            </div>

            <div className="flex flex-wrap items-center gap-2 shrink-0">
              <Button
                size="sm"
                variant="secondary"
                loading={refreshing}
                disabled={allBusy}
                icon={<RefreshCw className="w-3.5 h-3.5" />}
                onClick={() => void handleRefresh()}
              >
                刷新状态
              </Button>
              <Button
                size="sm"
                variant="secondary"
                loading={scanning}
                disabled={allBusy}
                icon={<Radar className="w-3.5 h-3.5" />}
                onClick={() => void handleScan()}
              >
                扫描周边干扰
              </Button>
              <Button
                size="sm"
                variant="primary"
                loading={applying}
                disabled={allBusy || overview.autoOptimizePlan.length === 0}
                icon={<Sparkles className="w-3.5 h-3.5" />}
                onClick={() =>
                  void openApplyPreview('一键全自动无线优化', {
                    action: 'auto_optimize',
                    recommended2gChannel: scanResult?.recommended2gChannel,
                    recommended5gChannel: scanResult?.recommended5gChannel,
                  })
                }
              >
                {overview.autoOptimizePlan.length > 0
                  ? `一键全自动优化 (${overview.autoOptimizePlan.length} 项)`
                  : '已处于推荐最优'}
              </Button>
            </div>
          </div>

          {overview.diagnostics.length > 0 && (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              {overview.diagnostics.map((d) => (
                <div
                  key={d.id}
                  className={`rounded-xl border p-3.5 flex items-start gap-2.5 text-xs ${
                    d.severity === 'critical'
                      ? 'border-rose-500/35 bg-rose-500/10'
                      : d.severity === 'warn'
                        ? 'border-amber-500/35 bg-amber-500/10'
                        : 'border-sky-500/25 bg-sky-500/5'
                  }`}
                >
                  {d.severity === 'critical' ? (
                    <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
                  ) : d.severity === 'warn' ? (
                    <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
                  ) : (
                    <Info className="w-4 h-4 text-sky-400 shrink-0 mt-0.5" />
                  )}
                  <div className="space-y-1 min-w-0">
                    <div className="font-semibold text-primary flex items-center gap-1.5 flex-wrap">
                      <span>{d.title}</span>
                      {d.autoFix && <Badge tone="ok">支持一键修复</Badge>}
                    </div>
                    <p className="text-[11px] text-secondary leading-relaxed">{d.detail}</p>
                    {d.actionHint && <p className="text-[11px] text-sky-200/90">建议：{d.actionHint}</p>}
                  </div>
                </div>
              ))}
            </div>
          )}

          <WifiRadioCards
            radios={overview.radios}
            ssids={overview.ssids}
            busy={allBusy}
            recommended2gCh={scanResult?.recommended2gChannel}
            recommended5gCh={scanResult?.recommended5gChannel}
            onDualBandMerge={(section, ssid) =>
              void openApplyPreview(`将「${ssid}」升级为双频合一`, {
                action: 'dual_band_merge',
                sourceSection: section,
                recommended5gChannel: scanResult?.recommended5gChannel,
              })
            }
            onTuneRadio={(patch: WifiRadioPatch) =>
              void openApplyPreview(`微调射频 ${patch.device}`, {
                action: 'tune_radio',
                radios: [patch],
              })
            }
          />

          <WifiChannelChart
            scan={scanResult}
            scanning={scanning}
            busy={allBusy}
            onScan={() => void handleScan()}
            onApplyRecommended={(ch2g, ch5g) => {
              const radios: WifiRadioPatch[] = [];
              for (const r of overview.radios) {
                if (r.band === '2g' && !r.disabled && ch2g) {
                  radios.push({ device: r.device, channel: String(ch2g), htmode: 'HE20' });
                }
                if (r.band === '5g' && !r.disabled && ch5g) {
                  radios.push({ device: r.device, channel: String(ch5g), htmode: 'HE80' });
                }
              }
              if (radios.length > 0) {
                void openApplyPreview('一键切换至扫描推荐最优信道', { action: 'tune_radio', radios });
              }
            }}
          />
        </>
      )}

      <WifiClientsAndChassis
        clients={overview.clients}
        chassis={overview.chassis}
        privacyMask={privacyMask}
        busy={allBusy}
        chassisBusy={chassisBusy}
        onApplyChassis={(rps, ct) => void handleApplyChassis(rps, ct)}
      />

      <ConfirmDialog
        open={pendingReq !== null}
        title={pendingTitle || '确认应用 Wi-Fi 优化'}
        confirmText="确认安全应用（带自动回滚）"
        cancelText="取消"
        danger={false}
        onCancel={() => setPendingReq(null)}
        onConfirm={() => void confirmApply()}
        description={
          <div className="space-y-3 text-xs">
            <div className="rounded-xl border border-emerald-500/30 bg-emerald-500/10 p-3 flex items-start gap-2 text-emerald-100">
              <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
              <div className="leading-relaxed">
                本次只修改无线配置并单次重载（约 8 秒瞬断），<strong>绝不触碰有线/WAN/Tailscale/SSH</strong>。
                若重载后网桥校验未通过将当场秒级回滚；生效后同时启动 180 秒倒计时保险丝，超时未确认自动还原。
              </div>
            </div>

            <div className="space-y-1.5 max-h-60 overflow-y-auto">
              {pendingChanges.map((ch, idx) => (
                <div
                  key={idx}
                  className="rounded-lg border border-white/10 bg-white/[0.03] px-3 py-2 space-y-0.5"
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="font-medium text-primary">
                      {ch.target} · {ch.field}
                    </span>
                  </div>
                  <div className="font-mono text-[11px]">
                    <span className="text-secondary line-through">{ch.before}</span>
                    <span className="text-secondary mx-1.5">→</span>
                    <span className="text-emerald-300">{ch.after}</span>
                  </div>
                  <div className="text-[11px] text-secondary">{ch.reason}</div>
                </div>
              ))}
            </div>
          </div>
        }
      />
    </div>
  );
};

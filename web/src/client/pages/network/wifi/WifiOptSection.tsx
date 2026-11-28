import React, { useMemo, useState } from 'react';
import {
  Activity,
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
  const [retesting, setRetesting] = useState(false);
  const [applying, setApplying] = useState(false);

  const [pendingReq, setPendingReq] = useState<WifiApplyRequest | null>(null);
  const [pendingChanges, setPendingChanges] = useState<WifiOptimizationStep[]>([]);
  const [pendingTitle, setPendingTitle] = useState('');

  const allBusy = busy || applying || scanning || retesting;

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

  const handleRetestStats = async () => {
    setRetesting(true);
    try {
      const fresh = await clientApi.retestWifiStats();
      setData(fresh);
      success('已重置计数基准并完成 3 秒实时丢包/错帧采样');
    } catch (err: unknown) {
      toastError(err instanceof Error ? err.message : '重测实时丢包率失败');
    } finally {
      setRetesting(false);
    }
  };

  const openApplyPreview = async (
    title: string,
    req: WifiApplyRequest,
    options?: { autoScanIfNeeded?: boolean },
  ) => {
    setApplying(true);
    try {
      let effectiveReq = req;
      const shouldAutoScan =
        Boolean(options?.autoScanIfNeeded) &&
        (!scanResult || Date.now() / 1000 - scanResult.scannedAt > 300);

      if (shouldAutoScan) {
        toast('正在自动扫描周边信道干扰以优选最佳信道，请稍候…', 'info');
        setScanning(true);
        try {
          const freshScan = await clientApi.scanWifiChannels();
          setScanResult(freshScan);
          effectiveReq = {
            ...req,
            recommended2gChannel: req.recommended2gChannel ?? freshScan.recommended2gChannel,
            recommended5gChannel: req.recommended5gChannel ?? freshScan.recommended5gChannel,
          };
        } catch {
          // 扫描失败不阻断优化流程，平滑回退默认正交/非 DFS 信道
        } finally {
          setScanning(false);
        }
      }

      const preview = await clientApi.applyWifiOptimize({ ...effectiveReq, dryRun: true });
      if (!preview.changes || preview.changes.length === 0) {
        toast(preview.summary || '当前配置已是最优状态，无需修改', 'info');
        return;
      }
      setPendingTitle(title);
      setPendingReq(effectiveReq);
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
      if (res.asyncReload) {
        success(
          `无线配置已提交，正在平滑重载（约 8 秒瞬断）。已启动 ${res.safeCommitTtlSec || 180} 秒防失联倒计时，重连后请点顶部「确认生效」`,
        );
        window.setTimeout(() => {
          void clientApi
            .getWifiOverview(true)
            .then((fresh) => setData(fresh))
            .catch(() => void refetch(true));
          onRefreshStatus?.();
        }, 12000);
      } else {
        success(
          `${res.summary}（已启动 ${res.safeCommitTtlSec || 180} 秒防失联倒计时，确认正常后请点顶部「确认生效」）`,
        );
      }
    } catch (err: unknown) {
      toastError(err instanceof Error ? err.message : '应用无线优化失败（已自动回滚原配置）');
      await refetch(true);
    } finally {
      setApplying(false);
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

  const radios = overview.radios ?? [];
  const ssids = overview.ssids ?? [];
  const clients = overview.clients ?? [];
  const diagnostics = overview.diagnostics ?? [];
  const autoPlan = overview.autoOptimizePlan ?? [];

  const statsScopeText = (() => {
    const win = overview.statsWindowSec ?? 0;
    const winLabel = win >= 60 ? `${Math.floor(win / 60)}分${win % 60}秒` : `${win}秒`;
    if (overview.statsScope === 'post_optimize') return `优化后实时 (${winLabel})`;
    if (overview.statsScope === 'retest') return `重测实时 (${winLabel})`;
    return '自开机累计';
  })();

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
            当前设备无可用无线网卡。如需调整多核 RPS、Conntrack 或 QUIC/UDP Socket 缓冲，请前往「网关模式 (主/旁路由)」。
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
                  <Badge tone={overview.statsScope && overview.statsScope !== 'boot' ? 'accent' : 'neutral'}>
                    统计：{statsScopeText}
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
                loading={retesting}
                disabled={allBusy}
                icon={<Activity className="w-3.5 h-3.5" />}
                onClick={() => void handleRetestStats()}
              >
                重测丢包率
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
                disabled={allBusy || autoPlan.length === 0}
                icon={<Sparkles className="w-3.5 h-3.5" />}
                onClick={() =>
                  void openApplyPreview(
                    '一键全自动无线优化',
                    {
                      action: 'auto_optimize',
                      recommended2gChannel: scanResult?.recommended2gChannel,
                      recommended5gChannel: scanResult?.recommended5gChannel,
                    },
                    { autoScanIfNeeded: true },
                  )
                }
              >
                {autoPlan.length > 0
                  ? `一键全自动优化 (${autoPlan.length} 项)`
                  : '已处于推荐最优'}
              </Button>
            </div>
          </div>

          {diagnostics.length > 0 && (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              {diagnostics.map((d) => (
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
            radios={radios}
            ssids={ssids}
            statsScope={overview.statsScope}
            busy={allBusy}
            recommended2gCh={scanResult?.recommended2gChannel}
            recommended5gCh={scanResult?.recommended5gChannel}
            onDualBandMerge={(section, ssid) =>
              void openApplyPreview(
                `将「${ssid}」升级为双频合一`,
                {
                  action: 'dual_band_merge',
                  sourceSection: section,
                  recommended5gChannel: scanResult?.recommended5gChannel,
                },
                { autoScanIfNeeded: true },
              )
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
              const targetRadios: WifiRadioPatch[] = [];
              for (const r of radios) {
                if (r.band === '2g' && !r.disabled && ch2g) {
                  targetRadios.push({ device: r.device, channel: String(ch2g), htmode: 'HE20' });
                }
                if (r.band === '5g' && !r.disabled && ch5g) {
                  targetRadios.push({ device: r.device, channel: String(ch5g), htmode: 'HE80' });
                }
              }
              if (targetRadios.length > 0) {
                void openApplyPreview('一键切换至扫描推荐最优信道', { action: 'tune_radio', radios: targetRadios });
              }
            }}
          />
        </>
      )}

      {overview.supported && (
        <WifiClientsAndChassis clients={clients} privacyMask={privacyMask} />
      )}

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

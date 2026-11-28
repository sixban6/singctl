import React, { useState } from 'react';
import { Activity, Cpu, Gauge, RefreshCw, RotateCw, Zap } from 'lucide-react';
import { Badge, Button, CardSkeleton, SectionCard, formatSocketBytes, useToast } from '../../../ui';
import { useCachedQuery } from '../../../hooks/useCachedQuery';
import { clientApi } from '../../api';
import { CHASSIS_CACHE_KEY } from '../../cacheKeys';
import { WifiChassisStatus } from '../../types';

export interface ChassisAccelCardProps {
  busy: boolean;
  supportedHint?: boolean;
  onAction?: (name: string, params?: Record<string, unknown>, confirmMsg?: string) => void;
}

export const ChassisAccelCard: React.FC<ChassisAccelCardProps> = ({
  busy,
  supportedHint,
  onAction,
}) => {
  const { success, error: toastError } = useToast();
  const {
    data: chassis,
    loading,
    error,
    setData,
    refetch,
  } = useCachedQuery<WifiChassisStatus>(CHASSIS_CACHE_KEY, () => clientApi.getChassis());

  const [applying, setApplying] = useState(false);
  const [needRestartSingBox, setNeedRestartSingBox] = useState(false);

  if (supportedHint === false && !chassis) {
    return null;
  }

  if (loading && !chassis) {
    return <CardSkeleton rows={3} />;
  }

  if (error && !chassis) {
    return (
      <SectionCard title="高并发底盘与 Socket 加速">
        <div className="py-3 flex flex-wrap items-center justify-between gap-2 text-xs">
          <span className="text-rose-300">读取底盘性能参数失败：{error}</span>
          <Button size="xs" variant="secondary" icon={<RefreshCw className="w-3 h-3" />} onClick={() => void refetch(true)}>
            立即重试
          </Button>
        </div>
      </SectionCard>
    );
  }

  if (!chassis || !chassis.supported) {
    return null;
  }

  const rpsInterfaces = chassis.rpsInterfaces ?? [];
  const sb = chassis.socketBuffer;
  const needRps = !chassis.rpsOptimal;
  const needConntrack = !chassis.conntrackOptimal;
  const needSocketBuf = Boolean(sb?.supported && !sb.optimal);
  const pendingCount = Number(needRps) + Number(needConntrack) + Number(needSocketBuf);

  const applyButtonLabel = (() => {
    if (chassis.optimal) return '底盘与 QUIC Socket 已处于高并发最优状态';
    if (pendingCount > 1) return `一键应用全部高并发加速 (${pendingCount} 项)`;
    if (needSocketBuf) {
      return sb?.excessiveDefault ? '一键收敛 QUIC 缓冲并优化 BBR' : '一键优化 QUIC/UDP 缓冲与 BBR';
    }
    if (needRps) return '一键开启多核 RPS 均衡';
    return '一键扩容 Conntrack 连接表';
  })();

  const handleApply = async () => {
    setApplying(true);
    try {
      const res = await clientApi.applyWifiChassis({
        enableRps: needRps,
        tuneConntrack: needConntrack,
        tuneSocketBuffer: needSocketBuf,
      });
      setData(res.chassis);
      if (res.restartSingBoxRecommended) {
        setNeedRestartSingBox(true);
      }
      const warnSuffix = res.warnings?.length ? `（提示：${res.warnings.join('；')}）` : '';
      success(`底盘加速已生效：${res.actions.join('；')}${warnSuffix}`);
    } catch (err: unknown) {
      toastError(err instanceof Error ? err.message : '应用高并发底盘加速失败');
    } finally {
      setApplying(false);
    }
  };

  return (
    <SectionCard
      title={
        <span className="flex items-center gap-2 flex-wrap">
          <Gauge className="w-4 h-4 text-amber-400" />
          <span>高并发底盘与 QUIC Socket 加速</span>
          <Badge tone={chassis.optimal ? 'ok' : 'warn'}>
            {chassis.optimal ? '已达最优' : '可提速'}
          </Badge>
        </span>
      }
      subtitle={`CPU ${chassis.cpuCores} 核 · 内存 ${chassis.totalMemMb || '-'} MB · sysctl 持久化开机生效`}
    >
      <div className="space-y-3 text-xs">
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-3">
          {(rpsInterfaces.length > 0 || chassis.cpuCores > 1) && (
            <div className="rounded-xl border border-white/10 bg-white/[0.02] p-3 space-y-1.5">
              <div className="flex items-center justify-between gap-2">
                <span className="font-medium text-primary flex items-center gap-1.5">
                  <Cpu className="w-3.5 h-3.5 text-sky-400" />
                  网卡多核 RPS 均衡
                </span>
                <Badge tone={chassis.rpsOptimal ? 'ok' : 'warn'}>
                  {chassis.rpsOptimal ? '已均衡' : '单核瓶颈'}
                </Badge>
              </div>
              <div className="text-[11px] text-secondary leading-relaxed">
                将主网口软中断平摊到全部 {chassis.cpuCores} 核，避免高速转发时单核 CPU 打满。
              </div>
              {rpsInterfaces.length > 0 && (
                <div className="flex flex-wrap gap-1.5 pt-1 font-mono text-[11px]">
                  {rpsInterfaces.map((item) => (
                    <span
                      key={item.interface}
                      className="px-2 py-0.5 rounded bg-white/5 border border-white/10 text-secondary"
                    >
                      {item.interface}: {item.currentMask} → {item.targetMask}
                    </span>
                  ))}
                </div>
              )}
            </div>
          )}

          {chassis.conntrackMax > 0 && (
            <div className="rounded-xl border border-white/10 bg-white/[0.02] p-3 space-y-1.5">
              <div className="flex items-center justify-between gap-2">
                <span className="font-medium text-primary">连接追踪表上限 (Conntrack)</span>
                <Badge tone={chassis.conntrackOptimal ? 'ok' : 'warn'}>
                  {chassis.conntrackOptimal ? '充裕' : '偏小'}
                </Badge>
              </div>
              <div className="font-mono text-[11px] text-secondary">
                当前占用 {chassis.conntrackCount.toLocaleString()} / 上限{' '}
                <strong className="text-primary">{chassis.conntrackMax.toLocaleString()}</strong>
                {!chassis.conntrackOptimal && (
                  <span className="text-emerald-300">
                    {' '}
                    → 推荐 {chassis.recommendedConntrack.toLocaleString()}
                  </span>
                )}
              </div>
              <div className="text-[11px] text-secondary leading-relaxed">
                按本机物理内存自动分档匹配并发连接追踪表，防高并发下新连接被丢弃。
              </div>
            </div>
          )}

          {sb?.supported && (
            <div className="rounded-xl border border-white/10 bg-white/[0.02] p-3 space-y-1.5">
              <div className="flex items-center justify-between gap-2">
                <span className="font-medium text-primary flex items-center gap-1.5">
                  <Activity className="w-3.5 h-3.5 text-emerald-400" />
                  QUIC/UDP 缓冲 & BBR
                </span>
                <Badge tone={sb.optimal ? 'ok' : sb.excessiveDefault ? 'danger' : 'warn'}>
                  {sb.optimal ? '已优化' : sb.excessiveDefault ? '默认过大' : '可提速'}
                </Badge>
              </div>
              <div className="font-mono text-[11px] text-secondary space-y-1">
                <div>
                  上限: <strong className="text-primary">{formatSocketBytes(sb.rmemMax)}</strong>
                  {!sb.maxBufferOptimal && (
                    <span className="text-emerald-300"> → {formatSocketBytes(sb.recommendedRmemMax)}</span>
                  )}
                  <span className="mx-1.5 text-white/20">|</span>
                  默认:{' '}
                  <strong className={sb.excessiveDefault ? 'text-rose-300' : 'text-primary'}>
                    {formatSocketBytes(sb.rmemDefault)}
                  </strong>
                  {sb.excessiveDefault && (
                    <span className="text-amber-300"> → {formatSocketBytes(sb.recommendedRmemDefault)}</span>
                  )}
                </div>
                <div className="flex flex-wrap items-center gap-x-3 gap-y-0.5">
                  <span>
                    {sb.defaultQdisc || '-'} + {sb.tcpCongestion || '-'}
                    {sb.bbrAvailable && !sb.bbrEnabled && (
                      <span className="text-emerald-300"> → bbr</span>
                    )}
                    {!sb.bbrAvailable && <span className="text-slate-400"> (无 BBR)</span>}
                  </span>
                  <span>
                    UDP 丢包:{' '}
                    <strong className={sb.udpRcvbufErrors > 0 ? 'text-amber-300' : 'text-emerald-300'}>
                      {sb.udpRcvbufErrors.toLocaleString()}
                    </strong>
                  </span>
                </div>
              </div>
            </div>
          )}
        </div>

        <div className="flex flex-wrap items-center justify-between gap-2 pt-1">
          <Button
            size="sm"
            variant={chassis.optimal ? 'secondary' : 'primary'}
            loading={applying}
            disabled={busy || chassis.optimal}
            icon={<Zap className="w-3.5 h-3.5" />}
            onClick={() => void handleApply()}
          >
            {applyButtonLabel}
          </Button>
          {sb?.supported && (
            <span className="text-[11px] text-secondary">{sb.summary}</span>
          )}
        </div>

        {needRestartSingBox && onAction && (
          <div className="rounded-xl border border-sky-500/30 bg-sky-500/10 p-2.5 flex flex-wrap items-center justify-between gap-2 text-[11px] text-sky-100">
            <span>新 Socket 缓冲参数已写入内核，建议平滑重启 sing-box 让运行中的 QUIC 连接立即生效。</span>
            <Button
              size="xs"
              variant="secondary"
              disabled={busy}
              icon={<RotateCw className="w-3 h-3" />}
              onClick={() => {
                setNeedRestartSingBox(false);
                onAction('sb-restart');
              }}
            >
              平滑重启 sing-box
            </Button>
          </div>
        )}
      </div>
    </SectionCard>
  );
};

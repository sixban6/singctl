import React, { useCallback, useEffect, useMemo, useState } from 'react';
import {
  Activity,
  AlertTriangle,
  Bot,
  ChevronDown,
  ChevronRight,
  Clock,
  Filter,
  HardDrive,
  Laptop,
  Network,
  RefreshCw,
  Sparkles,
} from 'lucide-react';
import {
  Badge,
  Button,
  CardSkeleton,
  SlideDrawer,
  formatBytes as fmtBytes,
} from '../../../ui';
import { auditApi } from '../../api';
import {
  AuditDeviceAppStat,
  AuditDeviceProfile,
  AuditDeviceProfileAISummary,
  AuditDeviceProfileRange,
  AuditDeviceSummary,
} from '../../types';
import { AuditSelectedDevice } from './auditFlowModel';
import { formatDeviceRoleLabel } from './auditHelpers';

export interface AuditDeviceProfileDrawerProps {
  device: AuditDeviceSummary | null;
  onClose: () => void;
  onFilterByDevice: (device: AuditSelectedDevice) => void;
  onFilterByApp: (device: AuditSelectedDevice, appName: string) => void;
}

type AppSortMode = 'duration' | 'bytes' | 'sessions';

const CATEGORY_COLORS: Record<string, string> = {
  video: 'bg-rose-400',
  social: 'bg-sky-400',
  ai_dev: 'bg-emerald-400',
  shopping: 'bg-amber-400',
  gaming_music: 'bg-violet-400',
  other: 'bg-slate-400',
  system: 'bg-slate-600',
};

function formatDwellMinutes(mins: number, compact = false): string {
  const safe = Math.max(0, Math.round(mins));
  if (safe < 60) {
    return compact ? `${safe}m` : `${safe} 分钟`;
  }
  const h = Math.floor(safe / 60);
  const m = safe % 60;
  if (m === 0) {
    return compact ? `${h}h` : `${h} 小时`;
  }
  return compact ? `${h}h ${m}m` : `${h} 小时 ${m} 分钟`;
}

export const AuditDeviceProfileDrawer: React.FC<AuditDeviceProfileDrawerProps> = ({
  device,
  onClose,
  onFilterByDevice,
  onFilterByApp,
}) => {
  const [range, setRange] = useState<AuditDeviceProfileRange>('24h');
  const [profile, setProfile] = useState<AuditDeviceProfile | null>(null);
  const [loading, setLoading] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [appSort, setAppSort] = useState<AppSortMode>('duration');
  const [showSystemApps, setShowSystemApps] = useState(false);
  const [aiSummary, setAiSummary] = useState<AuditDeviceProfileAISummary | null>(null);
  const [aiLoading, setAiLoading] = useState(false);
  const [aiError, setAiError] = useState<string | null>(null);

  const loadProfile = useCallback(
    async (ip: string, rng: AuditDeviceProfileRange, signal?: AbortSignal) => {
      setLoading(true);
      setErrorMsg(null);
      try {
        const res = await auditApi.getAuditDeviceProfile(ip, rng, signal);
        setProfile(res);
      } catch (err) {
        if ((err as Error)?.name === 'AbortError') return;
        setErrorMsg((err as Error)?.message || '加载设备行为画像失败');
      } finally {
        setLoading(false);
      }
    },
    [],
  );

  useEffect(() => {
    if (!device?.deviceIp) {
      setProfile(null);
      setErrorMsg(null);
      setAiSummary(null);
      setAiError(null);
      return;
    }
    setAiSummary(null);
    setAiError(null);
    const ac = new AbortController();
    void loadProfile(device.deviceIp, range, ac.signal);
    return () => ac.abort();
  }, [device?.deviceIp, range, loadProfile]);

  const handleSummarizeAI = async () => {
    if (!device?.deviceIp) return;
    setAiLoading(true);
    setAiError(null);
    try {
      const res = await auditApi.summarizeAuditDeviceProfile(device.deviceIp, range);
      setAiSummary(res);
    } catch (err) {
      setAiError((err as Error)?.message || 'AI 总结请求失败');
    } finally {
      setAiLoading(false);
    }
  };

  const sortedTopApps = useMemo(() => {
    const apps = profile?.topApps || [];
    return [...apps].sort((a, b) => {
      if (appSort === 'bytes') {
        return b.downloadBytes + b.uploadBytes - (a.downloadBytes + a.uploadBytes);
      }
      if (appSort === 'sessions') {
        if (b.sessions !== a.sessions) return b.sessions - a.sessions;
        return b.foregroundMinutes - a.foregroundMinutes;
      }
      if (b.foregroundMinutes !== a.foregroundMinutes) {
        return b.foregroundMinutes - a.foregroundMinutes;
      }
      return b.downloadBytes + b.uploadBytes - (a.downloadBytes + a.uploadBytes);
    });
  }, [profile?.topApps, appSort]);

  const maxAppMetric = useMemo(() => {
    if (!sortedTopApps.length) return 1;
    if (appSort === 'bytes') {
      return Math.max(1, ...sortedTopApps.map((a) => a.uploadBytes + a.downloadBytes));
    }
    if (appSort === 'sessions') {
      return Math.max(1, ...sortedTopApps.map((a) => a.sessions));
    }
    return Math.max(1, ...sortedTopApps.map((a) => a.foregroundMinutes));
  }, [sortedTopApps, appSort]);

  const hourlyMaxMins = useMemo(() => {
    const hrs = profile?.hourlyTimeline || [];
    return Math.max(1, ...hrs.map((h) => h.foregroundMinutes));
  }, [profile?.hourlyTimeline]);

  const dailyMaxMins = useMemo(() => {
    const days = profile?.dailyTrend || [];
    return Math.max(1, ...days.map((d) => d.foregroundMinutes));
  }, [profile?.dailyTrend]);

  const selectedPayload: AuditSelectedDevice | null = device
    ? {
        ip: device.deviceIp,
        label: profile?.deviceName || device.deviceName || device.deviceIp,
        mac: profile?.deviceMac || device.deviceMac,
      }
    : null;

  const badgeTone = (t: string): 'accent' | 'ok' | 'warn' | 'neutral' => {
    if (t === 'ok' || t === 'warn' || t === 'accent') return t;
    return 'neutral';
  };

  const handleClickAppRow = (app: AuditDeviceAppStat) => {
    if (!selectedPayload) return;
    onFilterByApp(selectedPayload, app.appName);
    onClose();
  };

  return (
    <SlideDrawer
      open={Boolean(device)}
      onClose={onClose}
      size="lg"
      title={
        <div className="flex items-center gap-2 min-w-0">
          <Laptop className="w-4 h-4 text-accent shrink-0" />
          <span className="truncate">{profile?.deviceName || device?.deviceName || device?.deviceIp}</span>
          <Badge tone="neutral">{formatDeviceRoleLabel(profile?.deviceRole || device?.deviceRole)}</Badge>
        </div>
      }
      subtitle={
        device
          ? `${device.deviceIp}${device.deviceMac ? ` · ${device.deviceMac}` : ''}${
              profile?.peakHourLabel ? ` · 活跃高峰 ${profile.peakHourLabel}` : ''
            }`
          : undefined
      }
      headerExtra={
        device ? (
          <div className="flex items-center gap-1.5">
            <div className="inline-flex items-center p-0.5 rounded-lg bg-surface2 border border-subtle text-[11px]">
              {(
                [
                  { id: '24h', label: '近 24h' },
                  { id: '7d', label: '近 7 天' },
                ] as const
              ).map((item) => (
                <button
                  key={item.id}
                  type="button"
                  onClick={() => setRange(item.id)}
                  className={`px-2 py-0.5 rounded-md transition-colors cursor-pointer ${
                    range === item.id
                      ? 'bg-accent/20 text-accent font-semibold'
                      : 'text-muted hover:text-primary'
                  }`}
                >
                  {item.label}
                </button>
              ))}
            </div>
            <Button
              size="xs"
              variant="secondary"
              loading={loading}
              icon={<RefreshCw className="w-3 h-3" />}
              onClick={() => void loadProfile(device.deviceIp, range)}
              title="刷新设备画像"
            >
              刷新
            </Button>
          </div>
        ) : undefined
      }
      footer={
        device && selectedPayload ? (
          <div className="flex flex-wrap items-center justify-between gap-2 w-full">
            <span className="text-[11px] text-muted flex items-center gap-1.5">
              <HardDrive className="w-3.5 h-3.5 shrink-0" />
              {profile?.storage
                ? `7天历史自动清理：已留存 ${profile.storage.historyDays}/${profile.storage.retentionDays} 天 · 占 ${fmtBytes(profile.storage.historyBytes)} / ${fmtBytes(profile.storage.maxHistoryBytes)}`
                : '基于 1 分钟前景去噪位图自动聚合，7 天外数据自动淘汰'}
            </span>
            <div className="flex items-center gap-2">
              <Button
                size="xs"
                variant="secondary"
                icon={<Filter className="w-3 h-3" />}
                onClick={() => {
                  onFilterByDevice(selectedPayload);
                  onClose();
                }}
              >
                仅看此设备连接明细
              </Button>
              <Button size="xs" variant="primary" onClick={onClose}>
                关闭
              </Button>
            </div>
          </div>
        ) : undefined
      }
    >
      {loading && !profile && <CardSkeleton rows={4} />}

      {errorMsg && (
        <div className="rounded-xl border border-rose-500/35 bg-rose-500/10 p-4 flex items-center justify-between gap-3">
          <div className="flex items-center gap-2 text-xs text-rose-200">
            <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0" />
            <span>{errorMsg}</span>
          </div>
          {device && (
            <Button
              size="xs"
              variant="secondary"
              onClick={() => void loadProfile(device.deviceIp, range)}
            >
              立即重试
            </Button>
          )}
        </div>
      )}

      {profile && (
        <div className="space-y-4">
          {profile.isNatSubRouter && (
            <div className="rounded-xl border border-amber-500/35 bg-amber-500/10 p-3 flex items-start gap-2.5 text-xs text-amber-100/90 leading-relaxed">
              <Network className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
              <div>
                <strong>下级路由 NAT 汇聚提示：</strong>
                该 IP 承载了多台下级终端的 NAT 合并流量，以下画像反映该子网的整体作息与偏好（如需看具体单机，可切换下级路由为 AP 模式或在其本机 WebUI 查看）。
              </div>
            </div>
          )}

          {/* 核心 KPI 概览 */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-2.5">
            <div className="rounded-xl bg-surface2/60 border border-subtle p-3">
              <div className="text-[11px] text-muted">估算前台停留</div>
              <div className="text-base font-bold text-primary mt-0.5 tnum">
                {formatDwellMinutes(profile.totalForegroundMinutes)}
              </div>
              <div className="text-[10.5px] text-muted mt-0.5">
                {range === '7d' ? '过去 7 天合计' : '过去 24h 去重时长'}
              </div>
            </div>

            <div className="rounded-xl bg-surface2/60 border border-subtle p-3">
              <div className="text-[11px] text-muted">常看应用数</div>
              <div className="text-base font-bold text-primary mt-0.5 tnum">
                {profile.activeAppCount} 个
              </div>
              <div className="text-[10.5px] text-muted mt-0.5">已自动剥离底座/心跳</div>
            </div>

            <div className="rounded-xl bg-surface2/60 border border-subtle p-3">
              <div className="text-[11px] text-muted">累计流量</div>
              <div className="text-base font-bold text-primary mt-0.5 tnum">
                {fmtBytes((profile.uploadBytes || 0) + (profile.downloadBytes || 0))}
              </div>
              <div className="text-[10.5px] text-muted mt-0.5 tnum">
                出海代理占 {Number(profile.proxySharePct || 0).toFixed(0)}%
              </div>
            </div>

            <div className="rounded-xl bg-surface2/60 border border-subtle p-3">
              <div className="text-[11px] text-muted">后台静默活跃</div>
              <div className="text-base font-bold text-secondary mt-0.5 tnum">
                {formatDwellMinutes(profile.totalBackgroundMinutes)}
              </div>
              <div className="text-[10.5px] text-muted mt-0.5">推送/底座未计入前台</div>
            </div>
          </div>

          {/* 行为特征标签 + 手动 AI 总结 */}
          <div className="rounded-xl bg-surface2/45 border border-subtle p-3 space-y-2.5">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div className="flex flex-wrap items-center gap-1.5">
                {profile.personaTags.length > 0 ? (
                  profile.personaTags.map((tag) => (
                    <Badge key={tag.id} tone={badgeTone(tag.tone)} title={tag.detail}>
                      {tag.label}
                    </Badge>
                  ))
                ) : (
                  <span className="text-xs text-muted">当前样本较少，暂未形成明显特征标签</span>
                )}
              </div>
              <Button
                size="xs"
                variant="secondary"
                loading={aiLoading}
                icon={<Sparkles className="w-3 h-3 text-accent" />}
                onClick={() => void handleSummarizeAI()}
              >
                AI 一句话总结
              </Button>
            </div>
            {aiError && <p className="text-xs text-rose-300">{aiError}</p>}
            {aiSummary && (
              <div className="rounded-lg bg-accent/10 border border-accent/25 px-3 py-2 text-xs text-primary leading-relaxed flex items-start gap-2">
                <Bot className="w-4 h-4 text-accent shrink-0 mt-0.5" />
                <div className="min-w-0 flex-1">
                  <p>{aiSummary.summary}</p>
                  <span className="text-[10px] text-muted mt-0.5 block">
                    {aiSummary.source} · {aiSummary.generatedAt}
                  </span>
                </div>
              </div>
            )}
          </div>

          {/* 7 天趋势 / 24h 作息时间轴 */}
          {range === '7d' && profile.dailyTrend.length > 0 && (
            <div className="rounded-xl bg-surface2/45 border border-subtle p-3 space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-xs font-semibold text-primary flex items-center gap-1.5">
                  <Activity className="w-3.5 h-3.5 text-accent" />
                  近 7 天日使用趋势
                </span>
                <span className="text-[11px] text-muted">悬停柱条查看当日最常看 App</span>
              </div>
              <div className="grid grid-cols-7 gap-2 items-end h-24 pt-2">
                {profile.dailyTrend.map((d) => {
                  const pct = Math.max(6, Math.round((d.foregroundMinutes / dailyMaxMins) * 100));
                  const shortDate = d.date.slice(5);
                  return (
                    <div
                      key={d.date}
                      title={`${d.date} · 前台 ${formatDwellMinutes(d.foregroundMinutes)} · 流量 ${fmtBytes(d.uploadBytes + d.downloadBytes)}${
                        d.topApp ? ` · 最常用: ${d.topApp} (${d.topAppMinutes || 0}m)` : ''
                      }`}
                      className="flex flex-col items-center justify-end h-full gap-1 group"
                    >
                      <span className="text-[10px] font-mono tnum text-muted group-hover:text-primary">
                        {d.foregroundMinutes > 0 ? `${d.foregroundMinutes}m` : '-'}
                      </span>
                      <div className="w-full max-w-[30px] flex-1 flex items-end">
                        <div
                          className={`w-full rounded-t-md transition-all ${
                            d.foregroundMinutes > 0
                              ? 'bg-accent/75 group-hover:bg-accent'
                              : 'bg-surface2'
                          }`}
                          style={{ height: d.foregroundMinutes > 0 ? `${pct}%` : '4px' }}
                        />
                      </div>
                      <span className="text-[10px] font-mono tnum text-muted">{shortDate}</span>
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          <div className="rounded-xl bg-surface2/45 border border-subtle p-3 space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold text-primary flex items-center gap-1.5">
                <Clock className="w-3.5 h-3.5 text-accent" />
                {range === '7d' ? '7 天累计分时作息热力' : '24 小时分时活跃分布'}
              </span>
              {profile.peakHourLabel && (
                <span className="text-[11px] text-muted">高峰：{profile.peakHourLabel}</span>
              )}
            </div>
            <div className="grid grid-cols-[repeat(24,minmax(0,1fr))] gap-1 items-end h-16 pt-1">
              {profile.hourlyTimeline.map((h) => {
                const isNight = h.hour >= 1 && h.hour <= 5;
                const hPct =
                  h.foregroundMinutes > 0
                    ? Math.max(12, Math.round((h.foregroundMinutes / hourlyMaxMins) * 100))
                    : 6;
                return (
                  <div
                    key={h.hour}
                    title={`${String(h.hour).padStart(2, '0')}:00 · 前台 ${h.foregroundMinutes} 分钟${
                      h.bytes > 0 ? ` · 流量 ${fmtBytes(h.bytes)}` : ''
                    }`}
                    className="flex flex-col items-center justify-end h-full group"
                  >
                    <div
                      className={`w-full rounded-t-sm transition-all ${
                        h.foregroundMinutes === 0
                          ? 'bg-surface2'
                          : isNight
                            ? 'bg-amber-400/80 group-hover:bg-amber-300'
                            : 'bg-sky-400/75 group-hover:bg-sky-300'
                      }`}
                      style={{ height: `${hPct}%` }}
                    />
                  </div>
                );
              })}
            </div>
            <div className="flex justify-between text-[10px] font-mono tnum text-muted">
              <span>00:00</span>
              <span>06:00</span>
              <span>12:00</span>
              <span>18:00</span>
              <span>23:00</span>
            </div>
          </div>

          {/* 兴趣品类分布 */}
          {profile.categories.length > 0 && (
            <div className="rounded-xl bg-surface2/45 border border-subtle p-3 space-y-2">
              <div className="text-xs font-semibold text-primary">使用品类偏好</div>
              <div className="h-2.5 w-full rounded-full bg-surface2 overflow-hidden flex">
                {profile.categories.map((cat) => (
                  <div
                    key={cat.category}
                    title={`${cat.label}: ${cat.sharePct}% (${cat.minutes} 分钟)`}
                    className={`${CATEGORY_COLORS[cat.category] || 'bg-slate-400'} h-full transition-all`}
                    style={{ width: `${Math.max(2, cat.sharePct)}%` }}
                  />
                ))}
              </div>
              <div className="flex flex-wrap gap-x-3 gap-y-1 text-[11px]">
                {profile.categories.map((cat) => (
                  <span key={cat.category} className="inline-flex items-center gap-1.5 text-secondary">
                    <span
                      className={`w-2 h-2 rounded-full ${CATEGORY_COLORS[cat.category] || 'bg-slate-400'}`}
                    />
                    <span>{cat.label}</span>
                    <span className="font-mono tnum text-muted">{cat.sharePct}%</span>
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* 喜欢看的 App 排行 */}
          <div className="rounded-xl bg-surface2/45 border border-subtle p-3 space-y-2.5">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div>
                <div className="text-xs font-semibold text-primary">常看 App 与停留时长排行</div>
                <div className="text-[11px] text-muted">
                  点击任意 App 可直接筛选下方「连接明细」，快捷改出口或拉黑
                </div>
              </div>
              <div className="inline-flex items-center p-0.5 rounded-lg bg-surface2 border border-subtle text-[11px]">
                {(
                  [
                    { id: 'duration', label: '按停留' },
                    { id: 'bytes', label: '按流量' },
                    { id: 'sessions', label: '按次数' },
                  ] as const
                ).map((item) => (
                  <button
                    key={item.id}
                    type="button"
                    onClick={() => setAppSort(item.id)}
                    className={`px-2 py-0.5 rounded-md transition-colors cursor-pointer ${
                      appSort === item.id
                        ? 'bg-accent/20 text-accent font-semibold'
                        : 'text-muted hover:text-primary'
                    }`}
                  >
                    {item.label}
                  </button>
                ))}
              </div>
            </div>

            {sortedTopApps.length === 0 ? (
              <p className="text-xs text-muted py-4 text-center">
                暂无明确的前景应用停留记录（多为系统后台或待机状态）
              </p>
            ) : (
              <div className="space-y-2">
                {sortedTopApps.map((app, idx) => {
                  const metricVal =
                    appSort === 'bytes'
                      ? app.uploadBytes + app.downloadBytes
                      : appSort === 'sessions'
                        ? app.sessions
                        : app.foregroundMinutes;
                  const barPct = Math.max(6, Math.round((metricVal / maxAppMetric) * 100));
                  return (
                    <button
                      key={app.appName}
                      type="button"
                      onClick={() => handleClickAppRow(app)}
                      className="w-full text-left rounded-xl bg-surface1/70 hover:bg-surface2/90 border border-subtle/80 hover:border-accent/40 p-2.5 transition-all cursor-pointer group"
                    >
                      <div className="flex items-center justify-between gap-2">
                        <div className="flex items-center gap-2 min-w-0">
                          <span className="text-[11px] font-mono tnum text-muted w-5 shrink-0">
                            #{idx + 1}
                          </span>
                          <span className="text-xs font-semibold text-primary truncate group-hover:text-accent">
                            {app.appName}
                          </span>
                          <Badge tone="neutral">{app.categoryLabel}</Badge>
                          {app.peakPeriod && (
                            <span className="hidden sm:inline text-[10px] text-muted">
                              {app.peakPeriod}
                            </span>
                          )}
                        </div>
                        <div className="text-xs font-semibold text-accent tnum shrink-0">
                          {formatDwellMinutes(app.foregroundMinutes)}
                        </div>
                      </div>
                      <div className="mt-1.5 h-1.5 rounded-full bg-surface2 overflow-hidden">
                        <div
                          className={`h-full rounded-full ${CATEGORY_COLORS[app.category] || 'bg-accent'}`}
                          style={{ width: `${barPct}%` }}
                        />
                      </div>
                      <div className="mt-1.5 flex flex-wrap items-center justify-between gap-2 text-[10.5px] text-muted font-mono tnum">
                        <span>
                          {app.sessions} 次打开 · 最长连续 {app.longestSessionMin}m
                          {app.backgroundMinutes > 0 ? ` · 后台 ${app.backgroundMinutes}m` : ''}
                        </span>
                        <span>
                          ↑ {fmtBytes(app.uploadBytes)} / ↓ {fmtBytes(app.downloadBytes)}
                        </span>
                      </div>
                    </button>
                  );
                })}
              </div>
            )}
          </div>

          {/* 折叠区：系统底座与静默后台流量 */}
          {profile.systemApps.length > 0 && (
            <div className="rounded-xl bg-surface2/35 border border-subtle overflow-hidden">
              <button
                type="button"
                onClick={() => setShowSystemApps((v) => !v)}
                className="w-full px-3 py-2.5 flex items-center justify-between text-xs text-secondary hover:text-primary cursor-pointer"
              >
                <span className="inline-flex items-center gap-1.5 font-medium">
                  {showSystemApps ? (
                    <ChevronDown className="w-3.5 h-3.5" />
                  ) : (
                    <ChevronRight className="w-3.5 h-3.5" />
                  )}
                  系统底座与后台静默服务（{profile.systemApps.length} 项）
                </span>
                <span className="text-[11px] text-muted">未计入前方 App 停留时长</span>
              </button>
              {showSystemApps && (
                <div className="px-3 pb-3 space-y-1.5 border-t border-subtle/60 pt-2">
                  {profile.systemApps.map((app) => (
                    <div
                      key={app.appName}
                      className="flex items-center justify-between gap-2 text-[11px] py-1"
                    >
                      <div className="flex items-center gap-2 min-w-0">
                        <span className="text-secondary truncate">{app.appName}</span>
                        <Badge tone="neutral">{app.categoryLabel}</Badge>
                      </div>
                      <span className="font-mono tnum text-muted shrink-0">
                        后台 {app.backgroundMinutes}m · ↑{fmtBytes(app.uploadBytes)} / ↓
                        {fmtBytes(app.downloadBytes)}
                      </span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </SlideDrawer>
  );
};

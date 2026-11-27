import React, { useCallback, useEffect, useState } from 'react';
import { AlertTriangle, Clock, RefreshCw, Sparkles } from 'lucide-react';
import { Badge, Button, SectionCard, useToast } from '../../../ui';
import { clientApi } from '../../api';
import type {
  AutoUpdateComponentID,
  ClientAutoUpdateComponentItem,
  ClientAutoUpdateSaveRequest,
  ClientAutoUpdateStatus,
} from '../../types';

export interface AutoUpdateCardProps {
  busy?: boolean;
  daemonRunning?: boolean;
}

const INTERVAL_OPTIONS: { value: number; label: string }[] = [
  { value: 12, label: '每 12 小时' },
  { value: 24, label: '每 24 小时 (默认)' },
  { value: 72, label: '每 3 天' },
  { value: 168, label: '每 7 天' },
];

function payloadForToggle(id: AutoUpdateComponentID, next: boolean): ClientAutoUpdateSaveRequest {
  switch (id) {
    case 'singctl':
      return { singctl: next };
    case 'singbox':
      return { singbox: next };
    case 'adguard_home':
      return { adguardHome: next };
    case 'tailscale':
      return { tailscale: next };
  }
}

function statusBadge(item: ClientAutoUpdateComponentItem): {
  tone: 'ok' | 'warn' | 'danger' | 'neutral';
  label: string;
} | null {
  switch (item.status) {
    case 'updated':
      return { tone: 'ok', label: '已更新' };
    case 'up_to_date':
      return { tone: 'ok', label: '已是最新' };
    case 'skipped':
      return { tone: 'neutral', label: '已跳过' };
    case 'failed':
      return { tone: 'danger', label: '上次失败' };
    default:
      return null;
  }
}

function formatVersionBadge(item: ClientAutoUpdateComponentItem): string {
  if (!item.installed) return '未安装';
  const v = (item.currentVersion || '').trim();
  if (!v) return '已安装';
  return v.startsWith('v') || v === 'dev' ? v : `v${v}`;
}

export const AutoUpdateCard: React.FC<AutoUpdateCardProps> = ({
  busy = false,
  daemonRunning,
}) => {
  const { success, error } = useToast();
  const [data, setData] = useState<ClientAutoUpdateStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [savingKey, setSavingKey] = useState<string | null>(null);

  const loadStatus = useCallback(
    async (silent = false) => {
      if (!silent) setLoading(true);
      try {
        const res = await clientApi.getAutoUpdate();
        setData(res);
      } catch (err: unknown) {
        if (!silent) {
          error(`读取组件自动更新状态失败：${err instanceof Error ? err.message : '未知错误'}`);
        }
      } finally {
        if (!silent) setLoading(false);
      }
    },
    [error],
  );

  useEffect(() => {
    void loadStatus(false);
  }, [loadStatus]);

  const handleToggle = async (item: ClientAutoUpdateComponentItem) => {
    const next = !item.enabled;
    setSavingKey(item.id);
    try {
      const res = await clientApi.saveAutoUpdate(payloadForToggle(item.id, next));
      setData(res.status);
      success(res.message || `${next ? '已开启' : '已关闭'} ${item.name} 自动更新`);
    } catch (err: unknown) {
      error(`切换 ${item.name} 自动更新失败：${err instanceof Error ? err.message : '未知错误'}`);
    } finally {
      setSavingKey(null);
    }
  };

  const handleIntervalChange = async (hours: number) => {
    setSavingKey('interval');
    try {
      const res = await clientApi.saveAutoUpdate({ intervalHours: hours });
      setData(res.status);
      success(res.message || `已更新定时检查周期为每 ${hours} 小时`);
    } catch (err: unknown) {
      error(`修改检查周期失败：${err instanceof Error ? err.message : '未知错误'}`);
    } finally {
      setSavingKey(null);
    }
  };

  const components = data?.components ?? [];
  const enabledCount = components.filter((c) => c.enabled).length;
  const effectiveDaemonRunning = daemonRunning ?? data?.daemonRunning ?? true;
  const intervalValue = data?.intervalHours ?? 24;

  return (
    <SectionCard
      title="核心组件定时自动更新"
      icon={<Sparkles className="w-4 h-4" />}
      subtitle="默认全部关闭 · 按需单独开启后由看门狗定期静默检查 GitHub Release，命中新版自动校验并平滑切换"
      badge={
        <Badge tone={enabledCount > 0 ? 'ok' : 'neutral'} dot={enabledCount > 0}>
          {enabledCount > 0 ? `已启用 ${enabledCount}/${components.length || 4} 项` : '全部关闭'}
        </Badge>
      }
      actions={
        <div className="flex items-center gap-2">
          <div className="flex items-center gap-1.5 text-xs text-secondary">
            <Clock className="w-3.5 h-3.5 text-muted hidden sm:block" />
            <select
              aria-label="组件自动更新检查周期"
              disabled={busy || loading || savingKey !== null}
              value={
                INTERVAL_OPTIONS.some((o) => o.value === intervalValue) ? intervalValue : 24
              }
              onChange={(e) => void handleIntervalChange(Number(e.target.value))}
              className="h-7 px-2 rounded-lg bg-surface2 border border-subtle text-xs text-primary focus:outline-none focus:border-strong disabled:opacity-50"
            >
              {INTERVAL_OPTIONS.map((opt) => (
                <option key={opt.value} value={opt.value}>
                  {opt.label}
                </option>
              ))}
            </select>
          </div>
          <Button
            size="xs"
            variant="ghost"
            disabled={loading || savingKey !== null}
            onClick={() => void loadStatus(false)}
            icon={<RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />}
          >
            刷新
          </Button>
        </div>
      }
    >
      <div className="space-y-2.5">
        {loading && components.length === 0 ? (
          <div className="py-6 text-center text-xs text-muted">正在读取组件自动更新配置…</div>
        ) : (
          components.map((item) => {
            const isSaving = savingKey === item.id;
            const stBadge = statusBadge(item);
            return (
              <div
                key={item.id}
                className="p-3.5 rounded-xl bg-surface2 border border-subtle flex flex-col sm:flex-row sm:items-center justify-between gap-3"
              >
                <div className="space-y-1 min-w-0">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="text-xs sm:text-sm font-medium text-primary">
                      {item.name}
                    </span>
                    <Badge tone={item.installed ? 'neutral' : 'warn'}>
                      {formatVersionBadge(item)}
                    </Badge>
                    {stBadge && <Badge tone={stBadge.tone}>{stBadge.label}</Badge>}
                  </div>
                  <p className="text-xs text-secondary leading-relaxed">{item.description}</p>
                  {(item.lastCheckedAt || item.message || item.lastError) && (
                    <div className="text-[11px] font-mono text-muted flex flex-wrap gap-x-3 gap-y-0.5">
                      {item.lastCheckedAt && <span>最近检查：{item.lastCheckedAt}</span>}
                      {item.lastError ? (
                        <span className="text-rose-400">错误：{item.lastError}</span>
                      ) : item.message ? (
                        <span>结果：{item.message}</span>
                      ) : null}
                    </div>
                  )}
                </div>

                <div className="flex items-center gap-3 shrink-0 self-end sm:self-center">
                  <button
                    type="button"
                    role="switch"
                    aria-checked={item.enabled}
                    aria-label={`${item.name}自动更新开关`}
                    disabled={busy || loading || savingKey !== null}
                    onClick={() => void handleToggle(item)}
                    className={`relative inline-flex h-6 w-11 shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out focus:outline-none disabled:opacity-50 disabled:cursor-not-allowed ${
                      item.enabled ? 'bg-emerald-500' : 'bg-slate-600'
                    }`}
                  >
                    <span
                      className={`pointer-events-none inline-block h-5 w-5 transform rounded-full bg-white shadow transition duration-200 ease-in-out ${
                        item.enabled ? 'translate-x-5' : 'translate-x-0'
                      }`}
                    />
                  </button>
                  <span className="text-xs font-medium text-primary min-w-[3rem]">
                    {isSaving ? '保存中…' : item.enabled ? '已开启' : '已关闭'}
                  </span>
                </div>
              </div>
            );
          })
        )}

        {enabledCount > 0 && !effectiveDaemonRunning && (
          <div className="p-3 rounded-xl bg-amber-500/10 border border-amber-500/30 flex items-start gap-2.5 text-xs text-amber-300">
            <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5" />
            <span>
              当前看门狗守护进程（<code className="font-mono">singctl dm</code>）未运行，定时自动更新将在启动看门狗后自动生效。
            </span>
          </div>
        )}
      </div>
    </SectionCard>
  );
};

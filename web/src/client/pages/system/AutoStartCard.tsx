import React, { useCallback, useEffect, useState } from 'react';
import { Power, RefreshCw, ShieldCheck } from 'lucide-react';
import { Badge, Button, SectionCard, useToast } from '../../../ui';
import { clientApi } from '../../api';
import { ClientAutoStartStatus } from '../../types';

export interface AutoStartCardProps {
  liveAutoStart?: ClientAutoStartStatus | null;
  busy?: boolean;
  onRefreshStatus?: () => void | Promise<void>;
}

function formatInitLabel(st: ClientAutoStartStatus | null): string {
  if (!st || !st.supported) return '当前系统无需配置';
  if (!st.enabled) {
    return st.configEnabled ? '待激活' : '已关闭';
  }
  switch (st.initSystem) {
    case 'procd':
      return '已启用 (OpenWrt procd · S99)';
    case 'systemd':
      return '已启用 (systemd)';
    default:
      return '已启用';
  }
}

export const AutoStartCard: React.FC<AutoStartCardProps> = ({
  liveAutoStart,
  busy = false,
  onRefreshStatus,
}) => {
  const { success, error } = useToast();
  const [data, setData] = useState<ClientAutoStartStatus | null>(liveAutoStart ?? null);
  const [loading, setLoading] = useState(!liveAutoStart);
  const [toggling, setToggling] = useState(false);

  const loadStatus = useCallback(
    async (silent = false) => {
      if (!silent) setLoading(true);
      try {
        const res = await clientApi.getAutoStart();
        setData(res);
      } catch (err: unknown) {
        if (!silent) {
          error(`读取开机自启状态失败：${err instanceof Error ? err.message : '未知错误'}`);
        }
      } finally {
        if (!silent) setLoading(false);
      }
    },
    [error],
  );

  useEffect(() => {
    void loadStatus(Boolean(liveAutoStart));
  }, [loadStatus, liveAutoStart]);

  useEffect(() => {
    if (liveAutoStart) {
      setData(liveAutoStart);
      setLoading(false);
    }
  }, [liveAutoStart]);

  const effectiveEnabled = data ? data.configEnabled && (!data.supported || data.serviceEnabled) : true;
  const supported = data?.supported ?? true;

  const handleToggle = async (nextEnabled: boolean) => {
    setToggling(true);
    try {
      const res = await clientApi.setAutoStart(nextEnabled);
      setData(res.status);
      success(res.message || (nextEnabled ? '已开启开机自启动与掉电恢复' : '已关闭开机自启动'));
      await onRefreshStatus?.();
    } catch (err: unknown) {
      error(`切换开机自启动失败：${err instanceof Error ? err.message : '未知错误'}`);
    } finally {
      setToggling(false);
    }
  };

  const badgeTone = !supported ? 'neutral' : effectiveEnabled ? 'ok' : 'warn';

  return (
    <SectionCard
      title="开机自启动与掉电恢复"
      icon={<Power className="w-4 h-4" />}
      subtitle="默认开启 · 路由器断电重启后自动恢复 sing-box 透明代理、看门狗与 Web 管理面板"
      badge={
        <Badge tone={badgeTone} dot={supported}>
          {formatInitLabel(data)}
        </Badge>
      }
      actions={
        <Button
          size="xs"
          variant="ghost"
          disabled={loading || toggling}
          onClick={() => void loadStatus(false)}
          icon={<RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />}
        >
          刷新
        </Button>
      }
    >
      <div className="p-3.5 rounded-xl bg-surface2 border border-subtle flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div className="space-y-1.5 text-xs">
          <div className="flex items-center gap-2 font-medium text-primary">
            <ShieldCheck className={`w-4 h-4 ${effectiveEnabled ? 'text-emerald-400' : 'text-amber-400'}`} />
            <span>
              {data?.lowMemory || data?.mode === 'unified_low_memory'
                ? '低内存单进程合体恢复模式（sing-box + Netlink 路由/防火墙 + 看门狗内嵌 :8090 WebUI）'
                : '标准网关恢复模式（sing-box + Netlink 路由/防火墙 + 看门狗 + WebUI :8090）'}
            </span>
          </div>
          <p className="text-secondary leading-relaxed">
            {data?.summary ||
              '通电开机等待接口就绪后自动拉起代理内核与看门狗，即使冷重启前曾触发低内存合体也不会丢失 WebUI 入口。'}
          </p>
          {data?.unitPath && (
            <div className="text-[11px] font-mono text-muted">
              托管单元：{data.unitPath}
              {data.initSystem === 'procd' && data.serviceEnabled ? ' → /etc/rc.d/S99singctl-autostart' : ''}
            </div>
          )}
        </div>

        <div className="flex items-center gap-3 shrink-0">
          <button
            type="button"
            role="switch"
            aria-checked={effectiveEnabled}
            aria-label="开机自启动与掉电恢复开关"
            disabled={!supported || busy || loading || toggling}
            onClick={() => void handleToggle(!effectiveEnabled)}
            className={`relative inline-flex h-6 w-11 shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out focus:outline-none disabled:opacity-50 disabled:cursor-not-allowed ${
              effectiveEnabled ? 'bg-emerald-500' : 'bg-slate-600'
            }`}
          >
            <span
              className={`pointer-events-none inline-block h-5 w-5 transform rounded-full bg-white shadow transition duration-200 ease-in-out ${
                effectiveEnabled ? 'translate-x-5' : 'translate-x-0'
              }`}
            />
          </button>
          <span className="text-xs font-medium text-primary min-w-[3rem]">
            {toggling ? '应用中…' : effectiveEnabled ? '已开启' : '已关闭'}
          </span>
        </div>
      </div>
    </SectionCard>
  );
};

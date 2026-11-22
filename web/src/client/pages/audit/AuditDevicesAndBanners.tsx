import React, { useMemo } from 'react';
import { AlertTriangle, Laptop, Network, Search, ShieldCheck, X } from 'lucide-react';
import {
  Badge,
  Button,
  DataColumn,
  DataTable,
  SectionCard,
  formatBytes as fmtBytes,
} from '../../../ui';
import { AuditDeviceSummary, AuditReport } from '../../types';
import { formatDeviceRoleLabel } from './auditHelpers';

export interface AuditDevicesAndBannersProps {
  report: AuditReport | null;
  loading: boolean;
  deviceFilter: string;
  onDeviceFilterChange: (v: string) => void;
  networkFilter: '' | 'tcp' | 'udp';
  onNetworkFilterChange: (v: '' | 'tcp' | 'udp') => void;
  axisFilter: '' | 'security' | 'privacy';
  onAxisFilterChange: (v: '' | 'security' | 'privacy') => void;
  onlyActive: boolean;
  onOnlyActiveChange: (v: boolean) => void;
  onlySuspect: boolean;
  onOnlySuspectChange: (v: boolean) => void;
  autoRefresh: boolean;
  onAutoRefreshChange: (v: boolean) => void;
  aiEnabled: boolean;
  onToggleAI: (v: boolean) => void;
  pcdnToggleBusy: boolean;
  pcdnBannerDismissed: boolean;
  onDismissPcdnBanner: () => void;
  onEnablePCDNBlock: () => void;
}

export const AuditDevicesAndBanners: React.FC<AuditDevicesAndBannersProps> = ({
  report,
  loading,
  deviceFilter,
  onDeviceFilterChange,
  networkFilter,
  onNetworkFilterChange,
  axisFilter,
  onAxisFilterChange,
  onlyActive,
  onOnlyActiveChange,
  onlySuspect,
  onOnlySuspectChange,
  autoRefresh,
  onAutoRefreshChange,
  aiEnabled,
  onToggleAI,
  pcdnToggleBusy,
  pcdnBannerDismissed,
  onDismissPcdnBanner,
  onEnablePCDNBlock,
}) => {
  const natSubRouter = useMemo(() => {
    const total = Number(report?.totalFlows || 0);
    if (total < 20 || !report?.devices) return null;
    return (
      report.devices.find(
        (d) =>
          d.deviceRole === 'router' &&
          d.deviceIp !== '127.0.0.1' &&
          (d.flowCount || 0) / total >= 0.7,
      ) || null
    );
  }, [report]);

  const deviceColumns: DataColumn<AuditDeviceSummary>[] = [
    {
      key: 'device',
      header: '局域网设备',
      render: (d) => (
        <div>
          <div className="font-semibold text-xs text-primary">{d.deviceName || d.deviceIp}</div>
          <div className="font-mono text-[11px] text-muted">
            {d.deviceIp}
            {d.deviceMac ? ` · ${d.deviceMac}` : ''}
          </div>
        </div>
      ),
    },
    {
      key: 'role',
      header: '角色 / 活跃',
      render: (d) => (
        <div className="space-y-0.5 whitespace-nowrap">
          <Badge tone="neutral">{formatDeviceRoleLabel(d.deviceRole)}</Badge>
          <div className="text-[10.5px] font-mono tnum text-muted">
            {d.activeConns ? `${d.activeConns} 活跃 / ` : ''}
            {d.flowCount || 0} 条流
          </div>
        </div>
      ),
    },
    {
      key: 'up',
      header: '累计上传 ↑',
      align: 'right',
      render: (d) => <span className="font-mono tnum text-xs">{fmtBytes(d.uploadBytes)}</span>,
    },
    {
      key: 'down',
      header: '累计下载 ↓',
      align: 'right',
      render: (d) => <span className="font-mono tnum text-xs text-secondary">{fmtBytes(d.downloadBytes)}</span>,
    },
    {
      key: 'ratio',
      header: '上/下比',
      align: 'right',
      render: (d) => (
        <span className="font-mono tnum text-xs">{Number(d.uploadRatio || 0).toFixed(1)}x</span>
      ),
    },
    {
      key: 'susp',
      header: '可疑连接',
      align: 'right',
      render: (d) => (
        <span className="font-mono tnum text-xs font-semibold">
          {(d.suspiciousCount || 0) + (d.highRiskCount || 0)}
        </span>
      ),
    },
    {
      key: 'risk',
      header: '最高评分',
      render: (d) => {
        const tone =
          d.maxRiskScore >= 80
            ? 'danger'
            : d.maxRiskScore >= 60
              ? 'warn'
              : d.maxRiskScore >= 35
                ? 'accent'
                : 'ok';
        return (
          <div className="space-y-0.5 whitespace-nowrap">
            <Badge tone={tone}>总 {d.maxRiskScore || 0} 分</Badge>
            <div className="text-[10.5px] font-mono tnum text-muted">
              安:{d.maxSecurityScore || 0} · 隐:{d.maxPrivacyScore || 0}
            </div>
          </div>
        );
      },
    },
    {
      key: 'filter',
      header: '操作',
      align: 'right',
      render: (d) => {
        const active = deviceFilter.trim() === d.deviceIp;
        return (
          <Button
            size="xs"
            variant={active ? 'primary' : 'secondary'}
            onClick={() => onDeviceFilterChange(active ? '' : d.deviceIp)}
          >
            {active ? '取消筛选' : '只看此设备'}
          </Button>
        );
      },
    },
  ];

  return (
    <>
      <SectionCard>
        <div className="flex flex-wrap items-center gap-2.5">
          <div className="relative flex-1 min-w-[180px] max-w-xs">
            <Search className="w-3.5 h-3.5 text-muted absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none" />
            <input
              type="text"
              value={deviceFilter}
              onChange={(e) => onDeviceFilterChange(e.target.value)}
              placeholder="搜索域名、IP、设备、节点或规则…"
              className="sc-input w-full pl-8 pr-7 py-1.5 text-xs"
            />
            {deviceFilter && (
              <button
                type="button"
                onClick={() => onDeviceFilterChange('')}
                className="absolute right-2 top-1/2 -translate-y-1/2 text-muted hover:text-primary cursor-pointer"
              >
                <X className="w-3.5 h-3.5" />
              </button>
            )}
          </div>

          <select
            aria-label="按传输协议筛选"
            value={networkFilter}
            onChange={(e) => onNetworkFilterChange(e.target.value as '' | 'tcp' | 'udp')}
            className="sc-input px-2.5 py-1.5 text-xs"
          >
            <option value="">全部协议</option>
            <option value="tcp">仅 TCP</option>
            <option value="udp">仅 UDP / QUIC</option>
          </select>

          <select
            value={axisFilter}
            onChange={(e) => onAxisFilterChange(e.target.value as '' | 'security' | 'privacy')}
            className="sc-input px-2.5 py-1.5 text-xs"
          >
            <option value="">全部类型 (安全 + 隐私)</option>
            <option value="security">仅看安全异常</option>
            <option value="privacy">仅看隐私追踪</option>
          </select>

          <label className="inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-xl border border-subtle bg-surface2 text-xs text-secondary cursor-pointer select-none">
            <input
              type="checkbox"
              checked={onlyActive}
              onChange={(e) => onOnlyActiveChange(e.target.checked)}
              className="accent-emerald-500"
            />
            仅看当前活跃
          </label>

          <label className="inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-xl border border-subtle bg-surface2 text-xs text-secondary cursor-pointer select-none">
            <input
              type="checkbox"
              checked={onlySuspect}
              onChange={(e) => onOnlySuspectChange(e.target.checked)}
              className="accent-emerald-500"
            />
            仅看关注/高危
          </label>

          <label className="inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-xl border border-subtle bg-surface2 text-xs text-secondary cursor-pointer select-none">
            <input
              type="checkbox"
              checked={autoRefresh}
              onChange={(e) => onAutoRefreshChange(e.target.checked)}
              className="accent-emerald-500"
            />
            自动刷新 (5s)
          </label>

          <label className="inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-xl border border-subtle bg-surface2 text-xs text-secondary cursor-pointer select-none">
            <input
              type="checkbox"
              checked={aiEnabled}
              onChange={(e) => onToggleAI(e.target.checked)}
              className="accent-emerald-500"
            />
            AI 深度研判
          </label>
        </div>
      </SectionCard>

      {report &&
        report.pcdnBlockEnabled === false &&
        (report.pcdnDetectedFlows || 0) > 0 &&
        !pcdnBannerDismissed && (
          <div className="rounded-2xl border border-amber-500/35 bg-amber-500/10 p-4 flex flex-wrap items-center justify-between gap-3">
            <div className="flex items-start gap-3 text-xs leading-relaxed text-secondary">
              <AlertTriangle className="w-5 h-5 text-amber-400 shrink-0 mt-0.5" />
              <div>
                <strong className="text-primary">检测到 {report.pcdnDetectedFlows} 条 PCDN 节点流量：</strong>
                当前已关闭「内置防 PCDN 拦截」，部分视频请求正在经由商业 PCDN / MCDN 节点通信，可能造成跨网卡顿或后台上行占用。
              </div>
            </div>
            <div className="flex items-center gap-2 shrink-0">
              <Button
                size="xs"
                variant="primary"
                loading={pcdnToggleBusy}
                icon={<ShieldCheck className="w-3.5 h-3.5" />}
                onClick={onEnablePCDNBlock}
              >
                一键重新开启防 PCDN
              </Button>
              <button
                type="button"
                onClick={onDismissPcdnBanner}
                title="暂不提示"
                className="text-muted hover:text-primary p-1 cursor-pointer"
              >
                <X className="w-4 h-4" />
              </button>
            </div>
          </div>
        )}

      {natSubRouter && (
        <div className="rounded-2xl border border-amber-500/30 bg-amber-500/10 p-4 flex items-start gap-3">
          <Network className="w-5 h-5 text-amber-400 shrink-0 mt-0.5" />
          <div className="text-xs leading-relaxed text-secondary">
            <strong className="text-primary">下级路由 NAT 汇聚提示：</strong>
            检测到下级路由{' '}
            <span className="font-semibold text-primary">
              {natSubRouter.deviceName || natSubRouter.deviceIp} ({natSubRouter.deviceIp})
            </span>{' '}
            汇聚了全网{' '}
            <strong className="text-amber-300">
              {Math.round(((natSubRouter.flowCount || 0) / (report?.totalFlows || 1)) * 100)}%
            </strong>{' '}
            的连接（{natSubRouter.flowCount}/{report?.totalFlows} 条）。若需精准区分终端设备并按设备拉黑，建议将下级路由切换为{' '}
            <strong>AP（无线交换机 / 桥接）模式</strong>。
          </div>
        </div>
      )}

      <SectionCard
        title="局域网设备活跃排行"
        subtitle={`共 ${report?.devices?.length || 0} 台活跃设备，默认展示前 12 台`}
        icon={<Laptop className="w-4 h-4" />}
        collapsible
        defaultOpen
        noPadding
      >
        <DataTable
          columns={deviceColumns}
          rows={(report?.devices || []).slice(0, 12)}
          rowKey={(d) => d.deviceIp}
          loading={loading}
          emptyText="暂无局域网设备活跃流量"
          compact
        />
      </SectionCard>
    </>
  );
};

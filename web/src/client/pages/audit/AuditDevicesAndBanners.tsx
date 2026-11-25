import React, { useMemo } from 'react';
import { AlertTriangle, Laptop, Network, Pencil, ShieldCheck, X } from 'lucide-react';
import {
  Badge,
  Button,
  DataColumn,
  DataTable,
  SectionCard,
  formatBytes as fmtBytes,
} from '../../../ui';
import { AuditDeviceSummary, AuditReport } from '../../types';
import { AuditSelectedDevice } from './auditFlowModel';
import { formatDeviceRoleLabel } from './auditHelpers';

export interface AuditDevicesAndBannersProps {
  report: AuditReport | null;
  loading: boolean;
  selectedDevice: AuditSelectedDevice | null;
  onSelectDevice: (device: AuditSelectedDevice | null) => void;
  onRenameDevice?: (device: AuditDeviceSummary) => void;
  pcdnToggleBusy: boolean;
  pcdnBannerDismissed: boolean;
  onDismissPcdnBanner: () => void;
  onEnablePCDNBlock: () => void;
}

export const AuditDevicesAndBanners: React.FC<AuditDevicesAndBannersProps> = ({
  report,
  loading,
  selectedDevice,
  onSelectDevice,
  onRenameDevice,
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
        <div className="flex items-start justify-between gap-2 group">
          <div className="min-w-0">
            <div className="font-semibold text-xs text-primary truncate">{d.deviceName || d.deviceIp}</div>
            <div className="font-mono text-[11px] text-muted">
              {d.deviceIp}
              {d.deviceMac ? ` · ${d.deviceMac}` : ''}
            </div>
          </div>
          {onRenameDevice && d.deviceIp && d.deviceIp !== '127.0.0.1' && (
            <button
              type="button"
              onClick={(e) => {
                e.stopPropagation();
                onRenameDevice(d);
              }}
              title="设昵称并绑定 .home 本地域名"
              className="p-1 rounded-md text-muted hover:text-sky-300 hover:bg-sky-500/15 transition-colors shrink-0 cursor-pointer"
            >
              <Pencil className="w-3 h-3" />
            </button>
          )}
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
      header: '待关注',
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
        const active = selectedDevice?.ip.toLowerCase() === d.deviceIp.toLowerCase();
        return (
          <Button
            size="xs"
            variant={active ? 'primary' : 'secondary'}
            onClick={() =>
              onSelectDevice(
                active
                  ? null
                  : {
                      ip: d.deviceIp,
                      label: d.deviceName || d.deviceIp,
                      mac: d.deviceMac,
                    },
              )
            }
          >
            {active ? '取消筛选' : '只看此设备'}
          </Button>
        );
      },
    },
  ];

  return (
    <>
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
        subtitle={`共 ${report?.devices?.length || 0} 台活跃设备，默认展示前 12 台 · 点击「只看此设备」联动下方明细`}
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

import React, { useMemo, useState } from 'react';
import {
  Activity,
  AlertTriangle,
  ChevronDown,
  ChevronUp,
  ExternalLink,
  Filter,
  Globe,
  Home,
  Laptop,
  Network,
  Pencil,
  Search,
  ShieldCheck,
  X,
} from 'lucide-react';
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

const DEFAULT_VISIBLE_DEVICES = 8;

type DeviceQuickFilter = 'all' | 'risky' | 'direct';
type DeviceSortKey = 'default' | 'upload' | 'download' | 'risk';

export interface AuditDevicesAndBannersProps {
  report: AuditReport | null;
  loading: boolean;
  selectedDevice: AuditSelectedDevice | null;
  onSelectDevice: (device: AuditSelectedDevice | null) => void;
  onOpenProfile?: (device: AuditDeviceSummary) => void;
  onRenameDevice?: (device: AuditDeviceSummary) => void;
  isAuditOnlyMode?: boolean;
  isDelegatedMode?: boolean;
  sideRouterIP?: string;
  busyDeviceIps?: Set<string>;
  onToggleDeviceOverseas?: (device: AuditDeviceSummary, allowOverseas: boolean) => void;
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
  onOpenProfile,
  onRenameDevice,
  isAuditOnlyMode = false,
  isDelegatedMode = false,
  sideRouterIP = '',
  busyDeviceIps,
  onToggleDeviceOverseas,
  pcdnToggleBusy,
  pcdnBannerDismissed,
  onDismissPcdnBanner,
  onEnablePCDNBlock,
}) => {
  const [expanded, setExpanded] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const [quickFilter, setQuickFilter] = useState<DeviceQuickFilter>('all');
  const [sortBy, setSortBy] = useState<DeviceSortKey>('default');
  const [sortDir, setSortDir] = useState<'desc' | 'asc'>('desc');

  const allDevices = report?.devices || [];
  const totalDevices = allDevices.length;

  const natSubRouter = useMemo(() => {
    const total = Number(report?.totalFlows || 0);
    if (total < 20 || !allDevices.length) return null;
    return (
      allDevices.find(
        (d) =>
          d.deviceRole === 'router' &&
          d.deviceIp !== '127.0.0.1' &&
          (d.flowCount || 0) / total >= 0.7,
      ) || null
    );
  }, [report?.totalFlows, allDevices]);

  const filteredDevices = useMemo(() => {
    const q = searchQuery.trim().toLowerCase();
    let list = allDevices.filter((d) => {
      if (quickFilter === 'risky') {
        const hasRisk =
          (d.highRiskCount || 0) + (d.suspiciousCount || 0) > 0 || (d.maxRiskScore || 0) >= 35;
        if (!hasRisk) return false;
      } else if (quickFilter === 'direct') {
        if (d.allowOverseas !== false) return false;
      }
      if (!q) return true;
      return (
        (d.deviceName || '').toLowerCase().includes(q) ||
        (d.deviceIp || '').toLowerCase().includes(q) ||
        (d.deviceMac || '').toLowerCase().includes(q)
      );
    });

    if (sortBy !== 'default') {
      const dir = sortDir === 'asc' ? 1 : -1;
      list = [...list].sort((a, b) => {
        if (sortBy === 'upload') return dir * ((a.uploadBytes || 0) - (b.uploadBytes || 0));
        if (sortBy === 'download') return dir * ((a.downloadBytes || 0) - (b.downloadBytes || 0));
        return dir * ((a.maxRiskScore || 0) - (b.maxRiskScore || 0));
      });
    }
    return list;
  }, [allDevices, quickFilter, searchQuery, sortBy, sortDir]);

  const isFiltering = searchQuery.trim() !== '' || quickFilter !== 'all';

  const displayedDevices = useMemo(() => {
    if (expanded || isFiltering || filteredDevices.length <= DEFAULT_VISIBLE_DEVICES) {
      return filteredDevices;
    }
    const base = filteredDevices.slice(0, DEFAULT_VISIBLE_DEVICES);
    if (selectedDevice?.ip) {
      const targetIP = selectedDevice.ip.toLowerCase();
      const inBase = base.some((d) => d.deviceIp.toLowerCase() === targetIP);
      if (!inBase) {
        const pinned = filteredDevices.find((d) => d.deviceIp.toLowerCase() === targetIP);
        if (pinned) {
          return [...base, pinned];
        }
      }
    }
    return base;
  }, [expanded, isFiltering, filteredDevices, selectedDevice?.ip]);

  const handleSort = (key: string) => {
    const next = key as DeviceSortKey;
    if (sortBy === next) {
      setSortDir((prev) => (prev === 'desc' ? 'asc' : 'desc'));
    } else {
      setSortBy(next);
      setSortDir('desc');
    }
  };

  const deviceColumns: DataColumn<AuditDeviceSummary>[] = [
    {
      key: 'device',
      header: '局域网设备',
      render: (d) => (
        <div className="flex items-start justify-between gap-2 group">
          <div className="min-w-0">
            <div className="font-semibold text-xs text-primary truncate group-hover:text-accent transition-colors">
              {d.deviceName || d.deviceIp}
            </div>
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
      sortKey: 'upload',
      render: (d) => <span className="font-mono tnum text-xs">{fmtBytes(d.uploadBytes)}</span>,
    },
    {
      key: 'down',
      header: '累计下载 ↓',
      align: 'right',
      sortKey: 'download',
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
      sortKey: 'risk',
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
      key: 'overseas',
      header: '外网权限',
      render: (d) => {
        if (!d.deviceIp || d.deviceIp === '127.0.0.1' || d.deviceIp === '::1') {
          return <Badge tone="neutral">本机网关</Badge>;
        }
        if (isDelegatedMode) {
          const cleanSideIP = sideRouterIP.trim();
          if (cleanSideIP) {
            return (
              <a
                href={`http://${cleanSideIP}:8090/#/audit`}
                target="_blank"
                rel="noopener noreferrer"
                onClick={(e) => e.stopPropagation()}
                title={`当前主路由处于旁路由托管模式，请前往旁路由 ${cleanSideIP}:8090 统一设置单设备外网/直连分流`}
                className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md text-[11px] bg-cyan-500/15 hover:bg-cyan-500/25 border border-cyan-500/35 text-cyan-200 font-medium whitespace-nowrap transition-colors"
              >
                <span>去旁路由设置</span>
                <ExternalLink className="w-3 h-3" />
              </a>
            );
          }
          return <Badge tone="neutral">已由旁路由接管</Badge>;
        }
        const allowed = d.allowOverseas !== false;
        const devBusy = Boolean(busyDeviceIps?.has(d.deviceIp));
        const disabled = devBusy || !onToggleDeviceOverseas;
        if (devBusy) {
          return <Badge tone="neutral">切换中…</Badge>;
        }
        const auditModeHint = isAuditOnlyMode
          ? '（当前无海外订阅，配置会提前写入，开启分流后立即按此生效）'
          : '';
        return (
          <div
            role="group"
            aria-label="设备外网访问权限"
            onClick={(e) => e.stopPropagation()}
            className="inline-flex items-center p-0.5 rounded-lg bg-surface2/80 border border-subtle whitespace-nowrap"
          >
            <button
              type="button"
              disabled={disabled}
              aria-pressed={allowed}
              onClick={(e) => {
                e.stopPropagation();
                if (!allowed && !disabled) {
                  onToggleDeviceOverseas?.(d, true);
                }
              }}
              title={
                allowed
                  ? `当前已选：允许外网（走 sing-box 智能分流）${auditModeHint}`
                  : `点击切换为「允许外网」（恢复 sing-box 智能分流）${auditModeHint}`
              }
              className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-md text-[11px] border transition-colors ${
                disabled ? 'opacity-55 cursor-not-allowed' : allowed ? 'cursor-default' : 'cursor-pointer'
              } ${
                allowed
                  ? 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40 font-semibold shadow-sm'
                  : 'text-muted hover:text-primary border-transparent'
              }`}
            >
              <Globe className="w-3 h-3" />
              <span>允许外网</span>
            </button>
            <button
              type="button"
              disabled={disabled}
              aria-pressed={!allowed}
              onClick={(e) => {
                e.stopPropagation();
                if (allowed && !disabled) {
                  onToggleDeviceOverseas?.(d, false);
                }
              }}
              title={
                !allowed
                  ? `当前已选：仅限直连（全部流量走 Direct，仍保留去广告/防 PCDN/审计）${auditModeHint}`
                  : `点击切换为「仅限直连」（禁止访问海外代理节点）${auditModeHint}`
              }
              className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-md text-[11px] border transition-colors ${
                disabled ? 'opacity-55 cursor-not-allowed' : !allowed ? 'cursor-default' : 'cursor-pointer'
              } ${
                !allowed
                  ? 'bg-amber-500/20 text-amber-300 border-amber-500/40 font-semibold shadow-sm'
                  : 'text-muted hover:text-primary border-transparent'
              }`}
            >
              <Home className="w-3 h-3" />
              <span>仅限直连</span>
            </button>
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
          <div
            className="inline-flex items-center justify-end gap-1.5 whitespace-nowrap"
            onClick={(e) => e.stopPropagation()}
          >
            {onOpenProfile && (
              <Button
                size="xs"
                variant="secondary"
                icon={<Activity className="w-3 h-3 text-accent" />}
                onClick={() => onOpenProfile(d)}
                title="查看该设备近 24h / 7 天偏好 App 与停留时长画像"
              >
                画像
              </Button>
            )}
            <Button
              size="xs"
              variant={active ? 'primary' : 'secondary'}
              icon={<Filter className="w-3 h-3" />}
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
              {active ? '取消筛选' : '只看'}
            </Button>
          </div>
        );
      },
    },
  ];

  const subtitle =
    totalDevices <= DEFAULT_VISIBLE_DEVICES
      ? `共 ${totalDevices} 台活跃设备 · 点击任意设备查看行为画像，或点「只看」联动下方连接明细`
      : expanded || isFiltering
        ? `共 ${totalDevices} 台活跃设备（当前显示 ${displayedDevices.length} 台）· 点击设备查看行为画像`
        : `共 ${totalDevices} 台活跃设备，默认展示前 ${DEFAULT_VISIBLE_DEVICES} 台 · 可搜索筛选或底部展开全部`;

  const remainingHidden = Math.max(0, filteredDevices.length - displayedDevices.length);
  const canToggleExpand = !isFiltering && filteredDevices.length > DEFAULT_VISIBLE_DEVICES;

  return (
    <>
      {isDelegatedMode && (
        <div className="rounded-2xl border border-cyan-500/35 bg-cyan-500/10 p-4 flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-start gap-3 text-xs leading-relaxed text-secondary">
            <Network className="w-5 h-5 text-cyan-400 shrink-0 mt-0.5" />
            <div>
              <strong className="text-primary">当前主路由处于「旁路由托管」模式（已启用三层真实终端 IP 透传）：</strong>
              本机已停用 sing-box，跨子网设备的真实 IP 与设备名已透传至旁路由。全屋流量统计、风险封禁及单设备「允许外网 / 仅限直连」均由旁路由统一接管，本页仅保留历史本地快照。
            </div>
          </div>
          {sideRouterIP.trim() && (
            <a
              href={`http://${sideRouterIP.trim()}:8090/#/audit`}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-xl bg-cyan-500/20 hover:bg-cyan-500/30 border border-cyan-500/40 text-xs text-cyan-200 font-semibold shrink-0 transition-colors"
            >
              <span>前往旁路由行为与审计 ({sideRouterIP.trim()}:8090)</span>
              <ExternalLink className="w-3.5 h-3.5" />
            </a>
          )}
        </div>
      )}

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
        subtitle={subtitle}
        icon={<Laptop className="w-4 h-4" />}
        collapsible
        defaultOpen
        noPadding
        actions={
          totalDevices > DEFAULT_VISIBLE_DEVICES ? (
            <div className="flex flex-wrap items-center gap-2">
              <div className="relative">
                <Search className="w-3.5 h-3.5 text-muted absolute left-2.5 top-1/2 -translate-y-1/2 pointer-events-none" />
                <input
                  type="text"
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  placeholder="搜设备 / IP / MAC"
                  className="pl-7 pr-6 py-1 rounded-lg bg-surface2/80 border border-subtle text-xs text-primary placeholder:text-muted focus:outline-none focus:border-accent w-40 sm:w-44"
                />
                {searchQuery && (
                  <button
                    type="button"
                    onClick={() => setSearchQuery('')}
                    className="absolute right-1.5 top-1/2 -translate-y-1/2 text-muted hover:text-primary cursor-pointer"
                    aria-label="清空设备搜索"
                  >
                    <X className="w-3 h-3" />
                  </button>
                )}
              </div>
              <div className="inline-flex items-center p-0.5 rounded-lg bg-surface2/80 border border-subtle text-[11px]">
                {(
                  [
                    { id: 'all', label: '全部' },
                    { id: 'risky', label: '有风险' },
                    { id: 'direct', label: '仅限直连' },
                  ] as const
                ).map((item) => (
                  <button
                    key={item.id}
                    type="button"
                    onClick={() => setQuickFilter(item.id)}
                    className={`px-2 py-0.5 rounded-md transition-colors cursor-pointer ${
                      quickFilter === item.id
                        ? 'bg-accent/20 text-accent font-semibold'
                        : 'text-muted hover:text-primary'
                    }`}
                  >
                    {item.label}
                  </button>
                ))}
              </div>
            </div>
          ) : undefined
        }
      >
        <DataTable
          columns={deviceColumns}
          rows={displayedDevices}
          rowKey={(d) => d.deviceIp}
          loading={loading}
          emptyText={isFiltering ? '未找到匹配条件的设备' : '暂无局域网设备活跃流量'}
          emptyAction={
            isFiltering ? (
              <Button
                size="xs"
                variant="secondary"
                onClick={() => {
                  setSearchQuery('');
                  setQuickFilter('all');
                }}
              >
                清除设备过滤
              </Button>
            ) : undefined
          }
          compact
          sortBy={sortBy === 'default' ? undefined : sortBy}
          sortDir={sortDir}
          onSort={handleSort}
          onRowClick={onOpenProfile}
          rowClassName={(d) => {
            const selected =
              selectedDevice?.ip.toLowerCase() === d.deviceIp.toLowerCase()
                ? 'bg-accent/10'
                : '';
            const clickable = onOpenProfile ? 'cursor-pointer' : '';
            return `${clickable} ${selected}`.trim();
          }}
          maxHeightClassName={expanded && displayedDevices.length > 10 ? 'max-h-[460px] overflow-y-auto' : undefined}
          stickyHeader={expanded && displayedDevices.length > 10}
          footerSlot={
            canToggleExpand ? (
              <div className="px-4 py-2 border-t border-subtle/60 bg-surface2/30 flex items-center justify-center">
                <button
                  type="button"
                  onClick={() => setExpanded((v) => !v)}
                  className="inline-flex items-center gap-1.5 text-xs font-medium text-accent hover:text-primary transition-colors cursor-pointer py-0.5 px-3 rounded-lg hover:bg-surface2"
                >
                  {expanded ? (
                    <>
                      <ChevronUp className="w-3.5 h-3.5" />
                      <span>收起为前 {DEFAULT_VISIBLE_DEVICES} 台</span>
                    </>
                  ) : (
                    <>
                      <ChevronDown className="w-3.5 h-3.5" />
                      <span>
                        展开剩余 {remainingHidden} 台（共 {filteredDevices.length} 台）
                      </span>
                    </>
                  )}
                </button>
              </div>
            ) : undefined
          }
        />
      </SectionCard>
    </>
  );
};

import React, { useEffect, useMemo, useState } from 'react';
import {
  AlertOctagon,
  Ban,
  ClipboardList,
  RefreshCw,
  Search,
  Server,
  ShieldAlert,
  ShieldCheck,
  Unlock,
} from 'lucide-react';
import { api } from '../../api';
import {
  AuditLogItem,
  BannedIP,
  ServerStatusResponse,
  SniffIPStat,
  SniffSubnetStat,
  SniffSummary,
} from '../../types';
import {
  Badge,
  Button,
  ConfirmDialog,
  DataColumn,
  DataTable,
  SectionCard,
  SegmentedTabs,
  useToast,
} from '../../ui';

interface SnifferGuardSubTabProps {
  status: ServerStatusResponse | null;
}

const AUDIT_CATEGORY_OPTIONS = [
  { key: 'all', label: '全部' },
  { key: 'login', label: '登录认证' },
  { key: 'security', label: '安全封禁' },
  { key: 'fleet', label: '舰队编排' },
  { key: 'subscription', label: '订阅管理' },
  { key: 'service', label: '服务运维' },
];

function inferAuditCategory(log: AuditLogItem): string {
  if (log.category) return log.category;
  const act = log.action || '';
  if (act.includes('登录') || act.includes('密码') || act.includes('凭证') || act.includes('路径')) {
    return 'login';
  }
  if (
    act.includes('拉黑') ||
    act.includes('封禁') ||
    act.includes('解封') ||
    act.includes('自愈') ||
    act.includes('抗探测') ||
    act.includes('快照')
  ) {
    return 'security';
  }
  if (act.includes('舰队') || act.includes('子节点')) return 'fleet';
  if (act.includes('订阅')) return 'subscription';
  return 'service';
}

export const SnifferGuardSubTab: React.FC<SnifferGuardSubTabProps> = ({ status }) => {
  const { success, error } = useToast();

  // Active Sniffing State
  const [sniffSummary, setSniffSummary] = useState<SniffSummary | null>(null);
  const [loadingSniff, setLoadingSniff] = useState(false);
  const [selectedSniffNode, setSelectedSniffNode] = useState<string>('all');
  const [sniffViewTab, setSniffViewTab] = useState<'ip' | 'subnet' | 'country'>('ip');
  const [sniffSearch, setSniffSearch] = useState('');
  const [sniffStatusFilter, setSniffStatusFilter] = useState<
    'all' | 'banned' | 'masqueraded' | 'observing'
  >('all');
  const [sniffSortBy, setSniffSortBy] = useState<'hits' | 'lastSeen' | 'firstSeen'>('lastSeen');
  const [sniffPageSize, setSniffPageSize] = useState<number>(20);
  const [sniffPage, setSniffPage] = useState<number>(1);
  const [syncBlockCluster, setSyncBlockCluster] = useState<boolean>(true);
  const [blockingTarget, setBlockingTarget] = useState<string | null>(null);
  const [manualBlockInput, setManualBlockInput] = useState('');

  // Bans State
  const [bans, setBans] = useState<BannedIP[]>([]);
  const [banSourceFilter, setBanSourceFilter] = useState<'all' | 'login_fail' | 'manual_sniff'>('all');
  const [loadingBans, setLoadingBans] = useState(false);
  const [unbanningIP, setUnbanningIP] = useState<string | null>(null);
  const [confirmUnbanAll, setConfirmUnbanAll] = useState(false);

  // Audit Logs State
  const [auditLogs, setAuditLogs] = useState<AuditLogItem[]>(status?.auditLogs || []);
  const [auditCategoryFilter, setAuditCategoryFilter] = useState<string>('all');
  const [loadingAudit, setLoadingAudit] = useState(false);

  const fetchBans = async () => {
    setLoadingBans(true);
    try {
      const res = await api.getBans();
      setBans(res.bans || []);
    } catch {
      // silent
    } finally {
      setLoadingBans(false);
    }
  };

  const fetchSniffers = async (nodeScope = selectedSniffNode, forceRefresh = false) => {
    setLoadingSniff(true);
    try {
      const res = await api.getSniffers(nodeScope, forceRefresh);
      setSniffSummary(res);
    } catch {
      // silent
    } finally {
      setLoadingSniff(false);
    }
  };

  const fetchAuditLogs = async () => {
    setLoadingAudit(true);
    try {
      const res = await api.getAuditLogs();
      setAuditLogs(res.logs || []);
    } catch {
      // silent
    } finally {
      setLoadingAudit(false);
    }
  };

  useEffect(() => {
    void fetchBans();
    void fetchSniffers('all', false);
    void fetchAuditLogs();
  }, []);

  useEffect(() => {
    if (status?.auditLogs) {
      setAuditLogs(status.auditLogs);
    }
  }, [status?.auditLogs]);

  const handleSelectSniffNode = (nodeId: string) => {
    setSelectedSniffNode(nodeId);
    setSniffPage(1);
    void fetchSniffers(nodeId, false);
  };

  const executeUnban = async (ip: string) => {
    setUnbanningIP(ip);
    try {
      const unbanScope = syncBlockCluster ? 'all' : selectedSniffNode;
      const res = await api.unban(ip, unbanScope, selectedSniffNode);
      success(res.message || `已成功解除 ${ip} 的封锁`);
      if (res.summary) {
        setSniffSummary(res.summary);
      } else {
        await fetchSniffers(selectedSniffNode, false);
      }
      await fetchBans();
      await fetchAuditLogs();
    } catch (err: unknown) {
      error(err instanceof Error ? err.message : '解封失败');
    } finally {
      setUnbanningIP(null);
    }
  };

  const handleBlockSniffer = async (target: string) => {
    const trimmed = target.trim();
    if (!trimmed) {
      error('请输入要封禁的 IP 地址或 /24 网段');
      return;
    }
    const blockScope = syncBlockCluster ? 'all' : selectedSniffNode;
    setBlockingTarget(trimmed);
    try {
      const res = await api.blockSniffer(trimmed, blockScope, selectedSniffNode);
      success(res.message || `已封禁 ${trimmed}`);
      setSniffSummary(res.summary);
      setManualBlockInput('');
      await fetchBans();
      await fetchAuditLogs();
    } catch (err: unknown) {
      error(err instanceof Error ? err.message : '封禁失败');
    } finally {
      setBlockingTarget(null);
    }
  };

  const sniffNodeOptions =
    sniffSummary?.nodes && sniffSummary.nodes.length > 0
      ? sniffSummary.nodes
      : [
          {
            id: 'all',
            name: '全集群汇总',
            online: true,
            totalSniffIPs: sniffSummary?.totalSniffIPs || 0,
            totalSubnets: sniffSummary?.totalSubnets || 0,
            totalBanned: sniffSummary?.totalBannedIPs || 0,
          },
          {
            id: 'local',
            name: '本机网关',
            online: true,
            totalSniffIPs: sniffSummary?.totalSniffIPs || 0,
            totalSubnets: sniffSummary?.totalSubnets || 0,
            totalBanned: sniffSummary?.totalBannedIPs || 0,
          },
        ];

  const filteredSniffIPs = useMemo(() => {
    const raw = sniffSummary?.topIPs || [];
    const q = sniffSearch.trim().toLowerCase();
    const filtered = raw.filter((item) => {
      if (sniffStatusFilter !== 'all' && item.status !== sniffStatusFilter) return false;
      if (!q) return true;
      const nodeNames = (item.nodes || []).map((n) => `${n.name} ${n.id} ${n.host || ''}`).join(' ');
      const hay = `${item.ip} ${item.subnet} ${item.vector} ${item.scannerTag || ''} ${item.country || ''} ${
        item.geo || ''
      } ${item.isp || ''} ${nodeNames}`.toLowerCase();
      return hay.includes(q);
    });
    return [...filtered].sort((a, b) => {
      if (sniffSortBy === 'lastSeen') {
        const cmpLast = (b.lastSeen || '').localeCompare(a.lastSeen || '');
        if (cmpLast !== 0) return cmpLast;
      } else if (sniffSortBy === 'firstSeen') {
        const cmpFirst = (b.firstSeen || '').localeCompare(a.firstSeen || '');
        if (cmpFirst !== 0) return cmpFirst;
      }
      if (b.hits !== a.hits) return b.hits - a.hits;
      return (b.lastSeen || '').localeCompare(a.lastSeen || '');
    });
  }, [sniffSummary?.topIPs, sniffSearch, sniffStatusFilter, sniffSortBy]);

  const filteredSniffSubnets = useMemo(() => {
    const raw = sniffSummary?.topSubnets || [];
    const q = sniffSearch.trim().toLowerCase();
    const filtered = raw.filter((sub) => {
      if (sniffStatusFilter === 'banned' && sub.status !== 'banned') return false;
      if (sniffStatusFilter === 'masqueraded' && sub.status === 'banned') return false;
      if (!q) return true;
      const nodeNames = (sub.nodes || []).map((n) => `${n.name} ${n.id}`).join(' ');
      const hay = `${sub.cidr} ${sub.country || ''} ${sub.isp || ''} ${sub.scannerTag || ''} ${(
        sub.sampleIPs || []
      ).join(' ')} ${nodeNames}`.toLowerCase();
      return hay.includes(q);
    });
    return [...filtered].sort((a, b) => {
      if (sniffSortBy === 'lastSeen') {
        const cmpLast = (b.lastSeen || '').localeCompare(a.lastSeen || '');
        if (cmpLast !== 0) return cmpLast;
      } else if (sniffSortBy === 'firstSeen') {
        const cmpFirst = (b.firstSeen || '').localeCompare(a.firstSeen || '');
        if (cmpFirst !== 0) return cmpFirst;
      }
      if (b.uniqueIPs !== a.uniqueIPs) return b.uniqueIPs - a.uniqueIPs;
      return b.totalHits - a.totalHits;
    });
  }, [sniffSummary?.topSubnets, sniffSearch, sniffStatusFilter, sniffSortBy]);

  const totalIPPages =
    sniffPageSize > 0 ? Math.max(1, Math.ceil(filteredSniffIPs.length / sniffPageSize)) : 1;
  const safeIPPage = Math.min(sniffPage, totalIPPages);
  const pagedSniffIPs =
    sniffPageSize > 0
      ? filteredSniffIPs.slice((safeIPPage - 1) * sniffPageSize, safeIPPage * sniffPageSize)
      : filteredSniffIPs;

  const totalSubnetPages =
    sniffPageSize > 0 ? Math.max(1, Math.ceil(filteredSniffSubnets.length / sniffPageSize)) : 1;
  const safeSubnetPage = Math.min(sniffPage, totalSubnetPages);
  const pagedSniffSubnets =
    sniffPageSize > 0
      ? filteredSniffSubnets.slice((safeSubnetPage - 1) * sniffPageSize, safeSubnetPage * sniffPageSize)
      : filteredSniffSubnets;

  const loginBanCount = useMemo(
    () => bans.filter((b) => (b.source || 'login_fail') !== 'manual_sniff').length,
    [bans]
  );
  const manualBanCount = useMemo(
    () => bans.filter((b) => b.source === 'manual_sniff').length,
    [bans]
  );
  const filteredBans = useMemo(() => {
    if (banSourceFilter === 'all') return bans;
    if (banSourceFilter === 'manual_sniff') return bans.filter((b) => b.source === 'manual_sniff');
    return bans.filter((b) => (b.source || 'login_fail') !== 'manual_sniff');
  }, [bans, banSourceFilter]);

  const filteredAuditLogs = useMemo(() => {
    if (auditCategoryFilter === 'all') return auditLogs;
    return auditLogs.filter((l) => inferAuditCategory(l) === auditCategoryFilter);
  }, [auditLogs, auditCategoryFilter]);

  const sniffIPColumns: DataColumn<SniffIPStat>[] = [
    {
      key: 'ip',
      header: '嗅探源 IP / 归属地',
      render: (item) => (
        <div className="space-y-0.5">
          <div className="font-mono font-semibold text-xs text-primary">{item.ip}</div>
          {(item.flag || item.geo || item.isp) && (
            <div className="text-[11px] text-muted">
              {item.flag ? `${item.flag} ` : ''}
              {item.geo || ''}
              {item.isp ? ` · ${item.isp}` : ''}
            </div>
          )}
        </div>
      ),
    },
    {
      key: 'nodes',
      header: '受探主机',
      render: (item) => (
        <div className="flex flex-wrap gap-1">
          {(item.nodes && item.nodes.length > 0
            ? item.nodes
            : [{ id: 'local', name: '本机网关' }]
          ).map((n) => (
            <Badge key={n.id} tone="accent">
              {n.name}
            </Badge>
          ))}
        </div>
      ),
    },
    {
      key: 'subnet',
      header: '/24 网段',
      render: (item) => <span className="font-mono text-xs text-secondary">{item.subnet}</span>,
    },
    {
      key: 'vector',
      header: '探测指纹',
      render: (item) => (
        <div className="flex items-center gap-1.5 flex-wrap text-xs">
          {item.scannerTag && <Badge tone="warn">{item.scannerTag}</Badge>}
          <span className="text-secondary font-mono">{item.vector}</span>
        </div>
      ),
    },
    {
      key: 'hits',
      header: '命中 / 时间',
      render: (item) => (
        <div className="font-mono text-[11px] tnum space-y-0.5">
          <div className="text-primary font-semibold">{item.hits} 次</div>
          <div className="text-muted">最近: {item.lastSeen || '--'}</div>
        </div>
      ),
    },
    {
      key: 'status',
      header: '状态',
      render: (item) => (
        <Badge
          tone={
            item.status === 'banned'
              ? 'danger'
              : item.status === 'masqueraded'
              ? 'warn'
              : 'neutral'
          }
        >
          {item.status === 'banned'
            ? '已拉黑拦截'
            : item.status === 'masqueraded'
            ? '已回落伪装'
            : '观察中'}
        </Badge>
      ),
    },
    {
      key: 'actions',
      header: '操作',
      align: 'right',
      render: (item) => (
        <div className="inline-flex items-center justify-end gap-1.5 whitespace-nowrap">
          {item.status === 'banned' ? (
            <Button
              size="xs"
              variant="secondary"
              loading={unbanningIP === item.ip}
              onClick={() => void executeUnban(item.ip)}
            >
              解除封禁
            </Button>
          ) : (
            <Button
              size="xs"
              variant="danger"
              loading={blockingTarget === item.ip}
              onClick={() => void handleBlockSniffer(item.ip)}
            >
              拉黑 IP
            </Button>
          )}
          {item.subnet && (
            <Button
              size="xs"
              variant="ghost"
              loading={blockingTarget === item.subnet}
              onClick={() => void handleBlockSniffer(item.subnet)}
            >
              封 /24 段
            </Button>
          )}
        </div>
      ),
    },
  ];

  const sniffSubnetColumns: DataColumn<SniffSubnetStat>[] = [
    {
      key: 'cidr',
      header: '活跃 /24 网段',
      render: (sub) => <span className="font-mono font-semibold text-xs text-primary">{sub.cidr}</span>,
    },
    {
      key: 'nodes',
      header: '受探主机',
      render: (sub) => (
        <div className="flex flex-wrap gap-1">
          {(sub.nodes && sub.nodes.length > 0
            ? sub.nodes
            : [{ id: 'local', name: '本机网关' }]
          ).map((n) => (
            <Badge key={n.id} tone="accent">
              {n.name}
            </Badge>
          ))}
        </div>
      ),
    },
    {
      key: 'counts',
      header: '独立 IP / 命中',
      render: (sub) => (
        <span className="font-mono text-xs text-secondary tnum">
          {sub.uniqueIPs} IP · {sub.totalHits} 次
        </span>
      ),
    },
    {
      key: 'geo',
      header: '归属与指纹',
      render: (sub) => (
        <div className="flex items-center gap-1.5 flex-wrap text-xs">
          {sub.flag && <span>{sub.flag}</span>}
          {sub.country && <span className="text-primary">{sub.country}</span>}
          {sub.scannerTag && <Badge tone="warn">{sub.scannerTag}</Badge>}
          {sub.isp && <span className="text-muted text-[11px]">· {sub.isp}</span>}
        </div>
      ),
    },
    {
      key: 'status',
      header: '状态',
      render: (sub) => (
        <Badge tone={sub.status === 'banned' ? 'danger' : 'warn'}>
          {sub.status === 'banned'
            ? '全段已封禁'
            : sub.status === 'partial'
            ? `部分已封 (${sub.bannedCount}/${sub.uniqueIPs})`
            : '活跃扫描段'}
        </Badge>
      ),
    },
    {
      key: 'actions',
      header: '网段处置',
      align: 'right',
      render: (sub) =>
        sub.status === 'banned' ? (
          <Button
            size="xs"
            variant="secondary"
            loading={unbanningIP === sub.cidr}
            onClick={() => void executeUnban(sub.cidr)}
          >
            解除网段封禁
          </Button>
        ) : (
          <Button
            size="xs"
            variant="danger"
            loading={blockingTarget === sub.cidr}
            onClick={() => void handleBlockSniffer(sub.cidr)}
          >
            一键拉黑 /24
          </Button>
        ),
    },
  ];

  const banColumns: DataColumn<BannedIP>[] = [
    {
      key: 'ip',
      header: '受限源 IP',
      render: (b) => (
        <div className="space-y-0.5">
          <div className="font-mono font-semibold text-xs text-primary">{b.ip}</div>
          {(b.flag || b.geo || b.isp) && (
            <div className="text-[11px] text-muted">
              {b.flag} {b.geo} {b.isp ? `· ${b.isp}` : ''}
            </div>
          )}
        </div>
      ),
    },
    {
      key: 'reason',
      header: '封禁来源与原因',
      render: (b) => {
        const isManual = b.source === 'manual_sniff';
        return (
          <div className="flex items-center gap-2 flex-wrap text-xs">
            <Badge tone={isManual ? 'warn' : 'danger'}>
              {b.sourceLabel || (isManual ? '嗅探手动封禁' : '密码试错拦截')}
            </Badge>
            <span className="text-secondary">
              {b.reason || (isManual ? '嗅探雷达手动拉黑 (nftables + 429)' : '后台登录密码连续输错')}
            </span>
          </div>
        );
      },
    },
    {
      key: 'ttl',
      header: '剩余时长',
      render: (b) => (
        <div className="font-mono text-xs tnum">
          <div style={{ color: 'var(--status-warn)' }}>
            {b.remainingText || `约 ${b.remainingMinutes} 分钟`}
          </div>
          {b.bannedUntil && <div className="text-[11px] text-muted">至 {b.bannedUntil}</div>}
        </div>
      ),
    },
    {
      key: 'actions',
      header: '操作',
      align: 'right',
      render: (b) => (
        <Button
          size="xs"
          variant="secondary"
          loading={unbanningIP === b.ip}
          onClick={() => void executeUnban(b.ip)}
        >
          全链路解封
        </Button>
      ),
    },
  ];

  const auditColumns: DataColumn<AuditLogItem>[] = [
    {
      key: 'time',
      header: '操作时间',
      render: (log) => (
        <span className="font-mono text-xs text-muted whitespace-nowrap">{log.time}</span>
      ),
    },
    {
      key: 'action',
      header: '管理动作',
      render: (log) => <span className="text-xs font-medium text-primary">{log.action}</span>,
    },
    {
      key: 'ip',
      header: '来源客户端 IP',
      align: 'right',
      render: (log) => (
        <div className="inline-flex items-center justify-end gap-1.5 flex-wrap font-mono text-xs">
          <span className="text-accent font-semibold">{log.ip}</span>
          {(log.flag || log.geo || log.isp) && (
            <span className="text-[11px] text-muted">
              {log.flag && `${log.flag} `}
              {log.geo}
              {log.isp ? ` · ${log.isp}` : ''}
            </span>
          )}
        </div>
      ),
    },
  ];

  return (
    <div className="space-y-6">
      {/* 1. Active Sniffing & Block Card */}
      <SectionCard
        title="集群活跃嗅探追踪与网段防御"
        subtitle="支持全集群与单主机视角切换，自动剔除合法代理客户端，支持一键封禁单 IP 或 /24 网段"
        icon={<ShieldAlert className="w-4 h-4" />}
        badge={
          <Badge tone={(sniffSummary?.totalSniffIPs || 0) > 0 ? 'warn' : 'ok'}>
            {sniffSummary?.totalSniffIPs || 0} IP · {sniffSummary?.totalSubnets || 0} 网段 ·{' '}
            {sniffSummary?.totalCountries || 0} 国家
          </Badge>
        }
        actions={
          <Button
            size="xs"
            variant="secondary"
            loading={loadingSniff}
            onClick={() => void fetchSniffers(selectedSniffNode, true)}
            icon={<RefreshCw className="w-3.5 h-3.5" />}
          >
            刷新态势
          </Button>
        }
      >
        <div className="space-y-4">
          {/* Host scope + View Mode */}
          <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-3">
            <div className="flex flex-wrap items-center gap-1.5">
              <span className="inline-flex items-center gap-1 text-xs font-medium text-muted mr-1">
                <Server className="w-3.5 h-3.5" /> 主机视角:
              </span>
              {sniffNodeOptions.map((node) => {
                const active = selectedSniffNode === node.id;
                return (
                  <button
                    key={node.id}
                    type="button"
                    onClick={() => handleSelectSniffNode(node.id)}
                    style={
                      active
                        ? { backgroundColor: 'var(--accent-soft)', borderColor: 'var(--accent)' }
                        : undefined
                    }
                    className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg border text-xs transition-all cursor-pointer ${
                      active ? 'text-primary font-semibold' : 'bg-surface2 border-subtle text-secondary hover:text-primary'
                    }`}
                  >
                    <span
                      className="w-1.5 h-1.5 rounded-full"
                      style={{
                        backgroundColor:
                          node.online !== false ? 'var(--status-ok)' : 'var(--text-muted)',
                      }}
                    />
                    <span>{node.name}</span>
                    <span className="font-mono text-[10px] text-muted">{node.totalSniffIPs}</span>
                  </button>
                );
              })}
            </div>

            <SegmentedTabs
              items={[
                { key: 'ip', label: `嗅探 IP (${sniffSummary?.topIPs?.length || 0})` },
                { key: 'subnet', label: `/24 网段 (${sniffSummary?.topSubnets?.length || 0})` },
                { key: 'country', label: `国家分布 (${sniffSummary?.topCountries?.length || 0})` },
              ]}
              value={sniffViewTab}
              onChange={(k) => {
                setSniffViewTab(k as 'ip' | 'subnet' | 'country');
                setSniffPage(1);
              }}
            />
          </div>

          {/* Manual Block + Filter Bar */}
          <div className="grid grid-cols-1 xl:grid-cols-12 gap-3">
            <div className="xl:col-span-6 flex flex-col sm:flex-row sm:items-center gap-2 p-2.5 rounded-xl bg-surface2 border border-subtle">
              <input
                type="text"
                value={manualBlockInput}
                onChange={(e) => setManualBlockInput(e.target.value)}
                placeholder="输入异常嗅探 IP 或 /24 网段 (如 198.51.100.42 或 198.51.100.0/24)"
                className="sc-input flex-1 px-3 py-1.5 text-xs font-mono"
              />
              <label className="inline-flex items-center gap-1.5 text-[11px] text-secondary cursor-pointer select-none px-1 shrink-0">
                <input
                  type="checkbox"
                  checked={syncBlockCluster}
                  onChange={(e) => setSyncBlockCluster(e.target.checked)}
                  className="accent-[var(--accent)]"
                />
                <span>全集群同步</span>
              </label>
              <Button
                size="xs"
                variant="danger"
                disabled={!manualBlockInput.trim() || blockingTarget !== null}
                loading={Boolean(blockingTarget && blockingTarget === manualBlockInput.trim())}
                onClick={() => void handleBlockSniffer(manualBlockInput)}
                icon={<Ban className="w-3.5 h-3.5" />}
              >
                一键拉黑
              </Button>
            </div>

            <div className="xl:col-span-6 flex flex-wrap items-center gap-2 p-2.5 rounded-xl bg-surface2 border border-subtle">
              <div className="relative flex-1 min-w-[160px]">
                <Search className="w-3.5 h-3.5 text-muted absolute left-2.5 top-1/2 -translate-y-1/2 pointer-events-none" />
                <input
                  type="text"
                  value={sniffSearch}
                  onChange={(e) => {
                    setSniffSearch(e.target.value);
                    setSniffPage(1);
                  }}
                  placeholder="筛选 IP / 网段 / 国家 / 指纹…"
                  className="sc-input w-full pl-8 pr-2.5 py-1.5 text-xs font-mono"
                />
              </div>
              <select
                value={sniffStatusFilter}
                onChange={(e) => {
                  setSniffStatusFilter(
                    e.target.value as 'all' | 'banned' | 'masqueraded' | 'observing'
                  );
                  setSniffPage(1);
                }}
                className="sc-input px-2.5 py-1.5 text-xs"
              >
                <option value="all">全部状态</option>
                <option value="banned">已拉黑</option>
                <option value="masqueraded">已回落伪装</option>
                <option value="observing">观察中</option>
              </select>
              <select
                value={sniffSortBy}
                onChange={(e) => {
                  setSniffSortBy(e.target.value as 'hits' | 'lastSeen' | 'firstSeen');
                  setSniffPage(1);
                }}
                className="sc-input px-2.5 py-1.5 text-xs"
              >
                <option value="lastSeen">按最近时间</option>
                <option value="firstSeen">按开始时间</option>
                <option value="hits">按命中次数</option>
              </select>
              <select
                value={sniffPageSize}
                onChange={(e) => {
                  setSniffPageSize(Number(e.target.value));
                  setSniffPage(1);
                }}
                className="sc-input px-2.5 py-1.5 text-xs"
              >
                <option value={20}>20/页</option>
                <option value={50}>50/页</option>
                <option value={100}>100/页</option>
                <option value={0}>全部</option>
              </select>
            </div>
          </div>

          {/* Data View */}
          {sniffViewTab === 'ip' && (
            <>
              <DataTable
                columns={sniffIPColumns}
                rows={pagedSniffIPs}
                rowKey={(item) => item.ip}
                loading={loadingSniff}
                emptyText={
                  sniffSearch || sniffStatusFilter !== 'all'
                    ? '未找到匹配筛选条件的嗅探 IP'
                    : '当前视角未捕获到外部活跃嗅探 IP'
                }
                compact
              />
              {filteredSniffIPs.length > 0 && (
                <div className="flex items-center justify-between text-xs text-muted pt-1">
                  <span>
                    共 {filteredSniffIPs.length} 个嗅探 IP
                    {sniffPageSize > 0 && `（第 ${safeIPPage} / ${totalIPPages} 页）`}
                  </span>
                  {sniffPageSize > 0 && totalIPPages > 1 && (
                    <div className="flex items-center gap-1.5">
                      <Button
                        size="xs"
                        variant="secondary"
                        disabled={safeIPPage <= 1}
                        onClick={() => setSniffPage((p) => Math.max(1, p - 1))}
                      >
                        上一页
                      </Button>
                      <Button
                        size="xs"
                        variant="secondary"
                        disabled={safeIPPage >= totalIPPages}
                        onClick={() => setSniffPage((p) => Math.min(totalIPPages, p + 1))}
                      >
                        下一页
                      </Button>
                    </div>
                  )}
                </div>
              )}
            </>
          )}

          {sniffViewTab === 'subnet' && (
            <>
              <DataTable
                columns={sniffSubnetColumns}
                rows={pagedSniffSubnets}
                rowKey={(sub) => sub.cidr}
                loading={loadingSniff}
                emptyText="当前视角暂无活跃 /24 嗅探网段记录"
                compact
              />
              {filteredSniffSubnets.length > 0 && (
                <div className="flex items-center justify-between text-xs text-muted pt-1">
                  <span>
                    共 {filteredSniffSubnets.length} 个活跃 /24 网段
                    {sniffPageSize > 0 && `（第 ${safeSubnetPage} / ${totalSubnetPages} 页）`}
                  </span>
                  {sniffPageSize > 0 && totalSubnetPages > 1 && (
                    <div className="flex items-center gap-1.5">
                      <Button
                        size="xs"
                        variant="secondary"
                        disabled={safeSubnetPage <= 1}
                        onClick={() => setSniffPage((p) => Math.max(1, p - 1))}
                      >
                        上一页
                      </Button>
                      <Button
                        size="xs"
                        variant="secondary"
                        disabled={safeSubnetPage >= totalSubnetPages}
                        onClick={() => setSniffPage((p) => Math.min(totalSubnetPages, p + 1))}
                      >
                        下一页
                      </Button>
                    </div>
                  )}
                </div>
              )}
            </>
          )}

          {sniffViewTab === 'country' && (
            <>
              {!sniffSummary?.topCountries || sniffSummary.topCountries.length === 0 ? (
                <div className="py-8 text-center rounded-xl bg-surface2 border border-subtle text-xs text-muted">
                  当前暂无活跃嗅探国统计数据
                </div>
              ) : (
                <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
                  {sniffSummary.topCountries.map((c) => (
                    <div
                      key={c.countryCode}
                      className="p-3.5 rounded-xl bg-surface2 border border-subtle space-y-2"
                    >
                      <div className="flex items-center justify-between">
                        <span className="text-sm font-semibold text-primary">
                          {c.flag ? `${c.flag} ` : ''}
                          {c.country}
                        </span>
                        <span className="text-xs font-mono font-bold text-accent tnum">
                          {c.ratioPercent}%
                        </span>
                      </div>
                      <div className="w-full h-2 bg-surface1 rounded-full overflow-hidden">
                        <div
                          className="h-full rounded-full"
                          style={{
                            width: `${Math.min(100, Math.max(5, c.ratioPercent))}%`,
                            backgroundColor: 'var(--accent)',
                          }}
                        />
                      </div>
                      <div className="flex items-center justify-between text-[11px] font-mono text-muted tnum">
                        <span>IP: {c.uniqueIPs}</span>
                        <span>/24: {c.uniqueSubnets}</span>
                        <span>命中: {c.totalHits}</span>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </>
          )}
        </div>
      </SectionCard>

      {/* 2. Bans Pool */}
      <SectionCard
        title="安全封禁与防爆破看板"
        subtitle="区分「后台输错密码 3 次自动封锁 15 分钟」与「嗅探雷达手动拉黑 7 天」，解封将全链路清理防火墙与限流表"
        icon={<AlertOctagon className="w-4 h-4" />}
        badge={
          bans.length > 0 ? (
            <Badge tone="danger">
              试错 {loginBanCount} · 手动 {manualBanCount}
            </Badge>
          ) : (
            <Badge tone="ok" dot>
              全绿无拦截
            </Badge>
          )
        }
        actions={
          <div className="flex flex-wrap items-center gap-2">
            {bans.length > 0 && (
              <SegmentedTabs
                items={[
                  { key: 'all', label: `全部 (${bans.length})` },
                  { key: 'login_fail', label: `试错 (${loginBanCount})` },
                  { key: 'manual_sniff', label: `手动 (${manualBanCount})` },
                ]}
                value={banSourceFilter}
                onChange={(k) =>
                  setBanSourceFilter(k as 'all' | 'login_fail' | 'manual_sniff')
                }
              />
            )}
            <Button
              size="xs"
              variant="secondary"
              loading={loadingBans}
              onClick={() => void fetchBans()}
              icon={<RefreshCw className="w-3.5 h-3.5" />}
            >
              刷新
            </Button>
            {bans.length > 0 && (
              <Button
                size="xs"
                variant="danger"
                loading={unbanningIP === 'all'}
                onClick={() => setConfirmUnbanAll(true)}
                icon={<Unlock className="w-3.5 h-3.5" />}
              >
                全链路解封
              </Button>
            )}
          </div>
        }
        noPadding
      >
        <DataTable
          columns={banColumns}
          rows={filteredBans}
          rowKey={(b) => b.ip}
          loading={loadingBans}
          emptyText={bans.length === 0 ? '当前系统安全，无活跃封禁 IP' : '当前筛选分类下暂无记录'}
          compact
        />
      </SectionCard>

      {/* 3. Management Operations Audit */}
      <SectionCard
        title="最近管理操作审计"
        subtitle="保留最近 200 条关键管理操作的时间、动作与来源 IP，绝不记录任何明文密码或秘钥"
        icon={<ClipboardList className="w-4 h-4" />}
        badge={
          <Badge tone="neutral">
            {auditCategoryFilter === 'all'
              ? `共 ${auditLogs.length} 条`
              : `${filteredAuditLogs.length} / ${auditLogs.length} 条`}
          </Badge>
        }
        actions={
          <div className="flex flex-wrap items-center gap-2">
            <SegmentedTabs
              items={AUDIT_CATEGORY_OPTIONS}
              value={auditCategoryFilter}
              onChange={(k) => setAuditCategoryFilter(k)}
            />
            <Button
              size="xs"
              variant="secondary"
              loading={loadingAudit}
              onClick={() => void fetchAuditLogs()}
              icon={<RefreshCw className="w-3.5 h-3.5" />}
            >
              刷新
            </Button>
          </div>
        }
        noPadding
      >
        <DataTable
          columns={auditColumns}
          rows={filteredAuditLogs}
          rowKey={(log, idx) => `${log.time}-${idx}`}
          loading={loadingAudit}
          emptyText="暂无匹配的管理操作记录"
          compact
        />
      </SectionCard>

      <ConfirmDialog
        open={confirmUnbanAll}
        title="确认全链路解封所有当前拦截 IP 及封禁网段？"
        description="该操作会立刻清理本机（及全集群 sync 开关下全部子节点）的登录防爆破黑名单与嗅探 nftables 规则表。"
        confirmText="确认全部解封"
        danger
        onConfirm={() => {
          setConfirmUnbanAll(false);
          void executeUnban('all');
        }}
        onCancel={() => setConfirmUnbanAll(false)}
      />
    </div>
  );
};

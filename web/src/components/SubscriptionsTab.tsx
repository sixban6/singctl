import React, { useEffect, useState } from 'react';
import {
  Ban,
  Check,
  Copy,
  Download,
  Edit3,
  ExternalLink,
  Eye,
  FileText,
  Globe,
  Link2,
  Plus,
  QrCode,
  RefreshCw,
  RotateCcw,
  Server,
  ShieldAlert,
  ShieldCheck,
  Trash2,
} from 'lucide-react';
import { api } from '../api';
import {
  SourceUpsertInput,
  SubscriptionAccessLogItem,
  SubscriptionPreviewResponse,
  SubscriptionRiskSummary,
  SubscriptionSourceItem,
  SubscriptionsResponse,
} from '../types';
import {
  Badge,
  Button,
  CardSkeleton,
  ConfirmDialog,
  DataColumn,
  DataTable,
  PageHeader,
  QRCodeBox,
  SectionCard,
  SegmentedTabs,
  SlideDrawer,
  useToast,
} from '../ui';

const PREVIEW_TARGETS = [
  { key: 'ClashMeta', label: 'Clash / Mihomo' },
  { key: 'Sing-Box', label: 'Sing-Box 1.14' },
  { key: 'Shadowrocket', label: 'Shadowrocket' },
  { key: 'Surge', label: 'Surge' },
  { key: 'Loon', label: 'Loon' },
  { key: 'plain', label: '明文 URI' },
];

const UA_PRESETS = [
  { value: 'auto', label: '自动自适应探测 (推荐：v2rayNG → Shadowrocket → Mihomo)' },
  { value: 'v2rayng', label: '强制伪装 v2rayNG' },
  { value: 'shadowrocket', label: '强制伪装 Shadowrocket (iOS)' },
  { value: 'clashmeta', label: '强制伪装 ClashMeta / Mihomo' },
  { value: 'singbox', label: '强制伪装 Sing-Box (SFA)' },
  { value: 'custom', label: '自定义 User-Agent 字符串…' },
];

const PROXY_MODE_OPTIONS = [
  { value: 'auto', label: '自动回退 (直连失败时切换 WARP)' },
  { value: 'direct', label: '仅直连拉取' },
  { value: 'warp', label: '强制经由本机 WARP 拉取' },
];

const formatEffectiveUA = (ua?: string): string => {
  if (!ua) return '';
  const low = ua.toLowerCase();
  if (low.includes('v2rayng')) return 'v2rayNG';
  if (low.includes('shadowrocket')) return 'Shadowrocket';
  if (low.includes('clash') || low.includes('mihomo')) return 'ClashMeta';
  if (low.includes('sfa') || low.includes('sfi') || low.includes('sing-box')) return 'Sing-Box';
  return ua.length > 20 ? `${ua.slice(0, 18)}…` : ua;
};

type ConfirmState =
  | { kind: 'rotateKey' }
  | { kind: 'deleteSource'; item: SubscriptionSourceItem }
  | { kind: 'clearAudit' }
  | null;

export const SubscriptionsTab: React.FC = () => {
  const { success, error } = useToast();
  const [data, setData] = useState<SubscriptionsResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const [qrModal, setQrModal] = useState<{ title: string; url: string } | null>(null);

  const [editingSource, setEditingSource] = useState<SourceUpsertInput | null>(null);
  const [customUAInput, setCustomUAInput] = useState('');
  const [isAutoManagedEdit, setIsAutoManagedEdit] = useState(false);
  const [savingSource, setSavingSource] = useState(false);
  const [refreshingSource, setRefreshingSource] = useState<string | null>(null);
  const [rotatingKey, setRotatingKey] = useState(false);

  const [showPreviewDrawer, setShowPreviewDrawer] = useState(false);
  const [previewTarget, setPreviewTarget] = useState('ClashMeta');
  const [previewData, setPreviewData] = useState<SubscriptionPreviewResponse | null>(null);
  const [loadingPreview, setLoadingPreview] = useState(false);

  const [auditLogs, setAuditLogs] = useState<SubscriptionAccessLogItem[]>([]);
  const [riskSummary, setRiskSummary] = useState<SubscriptionRiskSummary | null>(null);
  const [bannedIps, setBannedIps] = useState<Set<string>>(new Set());
  const [blockingIP, setBlockingIP] = useState<string | null>(null);
  const [loadingAudit, setLoadingAudit] = useState(false);
  const [clearingAudit, setClearingAudit] = useState(false);
  const [confirmAction, setConfirmAction] = useState<ConfirmState>(null);

  const loadData = async (silent = false) => {
    if (!silent) setLoading(true);
    try {
      const res = await api.getSubscriptions();
      setData(res);
    } catch (err: unknown) {
      error(err instanceof Error ? err.message : '加载订阅配置失败');
    } finally {
      if (!silent) setLoading(false);
    }
  };

  const loadAuditLogs = async (silent = false) => {
    if (!silent) setLoadingAudit(true);
    try {
      const res = await api.getSubscriptionAuditLogs();
      setAuditLogs(res.logs || []);
      setRiskSummary(res.riskSummary || null);
      setBannedIps(new Set(res.bannedIps || []));
    } catch (err: unknown) {
      if (!silent) {
        error(err instanceof Error ? err.message : '加载订阅审计记录失败');
      }
    } finally {
      if (!silent) setLoadingAudit(false);
    }
  };

  useEffect(() => {
    void loadData();
    void loadAuditLogs(true);
  }, []);

  const copyText = async (text: string, key: string) => {
    if (!text) return;
    try {
      await navigator.clipboard.writeText(text);
      setCopiedKey(key);
      success('已复制到剪贴板');
      window.setTimeout(() => setCopiedKey((prev) => (prev === key ? null : prev)), 2000);
    } catch {
      error('复制失败，请手动复制');
    }
  };

  const openAddSourceModal = () => {
    setIsAutoManagedEdit(false);
    setCustomUAInput('');
    setEditingSource({
      displayName: '',
      source: 'remote',
      url: '',
      content: '',
      remark: '',
      userAgent: 'auto',
      proxyMode: 'auto',
      enabled: true,
    });
  };

  const openEditSourceModal = (item: SubscriptionSourceItem) => {
    const rawUA = item.userAgent || 'auto';
    const isPreset = ['auto', 'v2rayng', 'shadowrocket', 'clashmeta', 'singbox'].includes(rawUA);
    setIsAutoManagedEdit(Boolean(item.autoManaged));
    setCustomUAInput(isPreset ? '' : rawUA);
    setEditingSource({
      name: item.name,
      displayName: item.displayName,
      source: item.source,
      url: item.url || '',
      content: item.content || '',
      remark: item.remark || '',
      userAgent: isPreset ? rawUA : 'custom',
      proxyMode: item.proxyMode || 'auto',
      enabled: item.enabled,
    });
  };

  const handleSaveSource = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!editingSource) return;

    const ua =
      editingSource.userAgent === 'custom'
        ? customUAInput.trim() || 'auto'
        : editingSource.userAgent || 'auto';

    setSavingSource(true);
    try {
      const res = await api.upsertSubSource({
        ...editingSource,
        userAgent: ua,
      });
      success(res.message || '订阅源已保存');
      setEditingSource(null);
      await loadData(true);
    } catch (err: unknown) {
      error(err instanceof Error ? err.message : '保存订阅源失败');
    } finally {
      setSavingSource(false);
    }
  };

  const handleRefreshSources = async (targetName?: string) => {
    setRefreshingSource(targetName || '__all__');
    try {
      const res = await api.refreshSubSources(targetName);
      success(res.message || '订阅源已刷新');
      await loadData(true);
    } catch (err: unknown) {
      error(err instanceof Error ? err.message : '刷新订阅源失败');
    } finally {
      setRefreshingSource(null);
    }
  };

  const handleToggleSourceEnabled = async (item: SubscriptionSourceItem) => {
    try {
      await api.upsertSubSource({
        name: item.name,
        displayName: item.displayName,
        source: item.source,
        url: item.url,
        content: item.content,
        remark: item.remark,
        userAgent: item.userAgent || 'auto',
        proxyMode: item.proxyMode || 'auto',
        enabled: !item.enabled,
      });
      success(`${item.displayName} 已${item.enabled ? '停用' : '启用'}`);
      await loadData(true);
    } catch (err: unknown) {
      error(err instanceof Error ? err.message : '切换状态失败');
    }
  };

  const executeConfirm = async () => {
    if (!confirmAction) return;
    if (confirmAction.kind === 'deleteSource') {
      const { item } = confirmAction;
      setConfirmAction(null);
      try {
        const res = await api.deleteSubSource(item.name);
        success(res.message || '订阅源已移除');
        await loadData(true);
      } catch (err: unknown) {
        error(err instanceof Error ? err.message : '删除订阅源失败');
      }
      return;
    }

    if (confirmAction.kind === 'rotateKey') {
      setConfirmAction(null);
      setRotatingKey(true);
      try {
        const res = await api.rotateSubKey();
        success(res.message || '订阅密钥已轮换');
        await loadData(true);
      } catch (err: unknown) {
        error(err instanceof Error ? err.message : '轮换密钥失败');
      } finally {
        setRotatingKey(false);
      }
      return;
    }

    if (confirmAction.kind === 'clearAudit') {
      setConfirmAction(null);
      setClearingAudit(true);
      try {
        const res = await api.clearSubscriptionAuditLogs();
        success(res.message || '订阅拉取记录已清空');
        await loadAuditLogs(true);
      } catch (err: unknown) {
        error(err instanceof Error ? err.message : '清空审计记录失败');
      } finally {
        setClearingAudit(false);
      }
    }
  };

  const fetchPreview = async (target: string) => {
    setPreviewTarget(target);
    setShowPreviewDrawer(true);
    setLoadingPreview(true);
    try {
      const res = await api.previewSubscription(target);
      setPreviewData(res);
    } catch (err: unknown) {
      error(err instanceof Error ? err.message : '生成实时预览失败');
    } finally {
      setLoadingPreview(false);
    }
  };

  const handleDownloadPreview = () => {
    if (!previewData) return;
    const blob = new Blob([previewData.content], {
      type: previewData.contentType || 'text/plain;charset=utf-8',
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = previewData.filename || `singctl-${previewTarget}.txt`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  };

  const handleBlockSubIP = async (ip: string) => {
    const trimmed = ip.trim();
    if (!trimmed) return;
    setBlockingIP(trimmed);
    try {
      const res = await api.blockSniffer(trimmed, 'all', 'all');
      success(res.message || `已拉黑 IP: ${trimmed}`);
      setBannedIps((prev) => new Set(prev).add(trimmed));
      await loadAuditLogs(true);
    } catch (err: unknown) {
      error(err instanceof Error ? err.message : '拉黑 IP 失败');
    } finally {
      setBlockingIP(null);
    }
  };

  if (loading && !data) {
    return (
      <div className="space-y-4">
        <CardSkeleton rows={3} />
        <CardSkeleton rows={5} />
      </div>
    );
  }

  const sources = data?.sources || [];
  const totalNodes = sources.reduce((acc, s) => (s.enabled ? acc + (s.nodeCount || 0) : acc), 0);

  const clients = [
    {
      key: 'shadowrocket',
      name: 'Shadowrocket',
      desc: 'iOS 跨协议网络客户端',
      icon: '🚀',
      scheme: data?.importLinks?.shadowrocket || '',
    },
    {
      key: 'clash',
      name: 'Clash Verge / Mihomo',
      desc: '跨平台 Clash.Meta 内核客户端',
      icon: '⚡',
      scheme: data?.importLinks?.clash || '',
    },
    {
      key: 'singbox',
      name: 'Sing-Box 官方客户端',
      desc: 'iOS SFI / Android SFA / 桌面端 v1.14',
      icon: '📦',
      scheme: data?.importLinks?.singbox || '',
    },
    {
      key: 'surge',
      name: 'Surge',
      desc: '高级网络分析与托管配置客户端',
      icon: '🌊',
      scheme: data?.importLinks?.surge || '',
    },
    {
      key: 'loon',
      name: 'Loon',
      desc: '支持 VLESS Reality 与 Hysteria2',
      icon: '🎈',
      scheme: data?.importLinks?.loon || '',
    },
  ];

  const auditColumns: DataColumn<SubscriptionAccessLogItem>[] = [
    {
      key: 'time',
      header: '时间',
      render: (log) => {
        const d = new Date(log.timestamp);
        return (
          <span className="font-mono text-xs text-secondary tnum whitespace-nowrap">
            {Number.isNaN(d.getTime()) ? log.timestamp : d.toLocaleString()}
          </span>
        );
      },
    },
    {
      key: 'client',
      header: '客户端 / UA',
      render: (log) => (
        <span
          className="inline-flex px-2 py-0.5 rounded-md bg-surface2 border border-subtle text-[11px] font-mono text-primary"
          title={log.userAgent || ''}
        >
          {log.clientApp || 'Unknown'}
        </span>
      ),
    },
    {
      key: 'ip',
      header: '来源 IP / 归属地',
      render: (log) => (
        <div className="font-mono text-xs text-primary whitespace-nowrap">
          <span className="mr-1.5">{log.flag || '🌐'}</span>
          <span>{log.ip || '-'}</span>
          {log.geo && <span className="text-muted ml-1.5">({log.geo})</span>}
        </div>
      ),
    },
    {
      key: 'target',
      header: '格式 / 节点数',
      render: (log) => (
        <span className="font-mono text-xs text-secondary whitespace-nowrap">
          {log.target}
          {log.status !== 'denied' && log.nodeCount > 0 ? ` · ${log.nodeCount} 节点` : ''}
        </span>
      ),
    },
    {
      key: 'status',
      header: '状态与处置',
      align: 'right',
      render: (log) => {
        const isDenied = log.status === 'denied';
        return (
          <div className="inline-flex items-center justify-end gap-1.5 whitespace-nowrap">
            <Badge tone={isDenied ? 'danger' : 'ok'}>
              {isDenied ? '密钥拦截' : '正常下发'}
            </Badge>
            {log.ip &&
              (bannedIps.has(log.ip) ? (
                <Badge tone="neutral">已拉黑</Badge>
              ) : (
                <Button
                  size="xs"
                  variant="danger"
                  loading={blockingIP === log.ip}
                  onClick={() => handleBlockSubIP(log.ip)}
                  icon={<Ban className="w-3 h-3" />}
                >
                  拉黑 IP
                </Button>
              ))}
          </div>
        );
      },
    },
  ];

  const sourceTypeBadge = (item: SubscriptionSourceItem) => {
    if (item.autoManaged) return <Badge tone="ok">本机自动同步</Badge>;
    if (item.name.startsWith('fleet_')) return <Badge tone="accent">舰队自动同步</Badge>;
    if (item.source === 'remote') return <Badge tone="accent">远程订阅</Badge>;
    return <Badge tone="neutral">自定义节点</Badge>;
  };

  return (
    <div className="space-y-6">
      <PageHeader
        title="订阅分发中心"
        description="Native Go SubHub · 单链接自适应渲染多端格式并聚合节点源池"
        badge={
          <Badge tone={totalNodes > 0 ? 'ok' : 'warn'} dot pulse={totalNodes > 0}>
            {totalNodes} 节点已聚合
          </Badge>
        }
        actions={
          <>
            <Button
              size="sm"
              variant="secondary"
              loading={refreshingSource === '__all__'}
              onClick={() => handleRefreshSources()}
              icon={<RefreshCw className="w-3.5 h-3.5" />}
            >
              刷新远程源
            </Button>
            <Button
              size="sm"
              variant="secondary"
              onClick={() => fetchPreview(previewTarget)}
              icon={<Eye className="w-3.5 h-3.5" />}
            >
              实时渲染预览
            </Button>
            <Button
              size="sm"
              variant="primary"
              onClick={openAddSourceModal}
              icon={<Plus className="w-3.5 h-3.5" />}
            >
              添加节点源
            </Button>
          </>
        }
      />

      {/* Unified Subscription Hero Card */}
      <div
        className="console-card rounded-2xl p-5 sm:p-6 relative overflow-hidden"
        style={{
          backgroundImage:
            'radial-gradient(ellipse at top right, var(--accent-soft), transparent 60%)',
        }}
      >
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div className="space-y-1.5 min-w-0">
            <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wider text-accent">
              <Link2 className="w-3.5 h-3.5" />
              <span>统一全平台订阅链接</span>
            </div>
            <p className="text-xs sm:text-sm text-secondary leading-relaxed">
              根据客户端 <span className="font-mono text-primary">User-Agent</span> 或{' '}
              <span className="font-mono text-primary">?target=</span> 自动下发最优内核配置（Sing-Box 1.14 / Mihomo / Shadowrocket / Surge / Loon）。
            </p>
          </div>
          <div className="flex flex-wrap items-center gap-2 shrink-0">
            <Button
              size="sm"
              variant="secondary"
              onClick={() =>
                setQrModal({
                  title: '统一订阅二维码',
                  url: data?.subscriptionUrl || '',
                })
              }
              icon={<QrCode className="w-3.5 h-3.5" />}
            >
              扫码导入
            </Button>
            <Button
              size="sm"
              variant="danger"
              loading={rotatingKey}
              onClick={() => setConfirmAction({ kind: 'rotateKey' })}
              icon={<RotateCcw className="w-3.5 h-3.5" />}
            >
              轮换订阅密钥
            </Button>
          </div>
        </div>

        <div className="mt-4 p-3 rounded-xl bg-surface2 border border-subtle flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <code className="font-mono text-xs text-primary break-all select-all flex-1">
            {data?.subscriptionUrl || '尚未生成订阅地址，请检查域名与 SubHub 配置'}
          </code>
          <Button
            size="xs"
            variant="primary"
            disabled={!data?.subscriptionUrl}
            onClick={() => copyText(data?.subscriptionUrl || '', 'main-sub')}
            icon={
              copiedKey === 'main-sub' ? (
                <Check className="w-3.5 h-3.5" />
              ) : (
                <Copy className="w-3.5 h-3.5" />
              )
            }
          >
            {copiedKey === 'main-sub' ? '已复制' : '复制订阅链接'}
          </Button>
        </div>

        {data?.substoreAdminUrl && (
          <div className="mt-3 flex flex-wrap items-center justify-between gap-2 text-xs text-muted">
            <span>原生内置引擎：{data.engine || 'native-go'}（零外部 Node.js / Sub-Store 依赖）</span>
            <a
              href={data.substoreAdminUrl}
              target="_blank"
              rel="noreferrer"
              className="inline-flex items-center gap-1 text-accent hover:underline font-mono"
            >
              <span>Web 管理入口</span>
              <ExternalLink className="w-3 h-3" />
            </a>
          </div>
        )}
      </div>

      {/* Aggregation Sources */}
      <SectionCard
        title="聚合节点源池 (SubHub Sources)"
        subtitle={`共 ${sources.length} 个订阅源 · ${sources.filter((s) => s.enabled).length} 个已启用 · 当前聚合 ${totalNodes} 条出站节点`}
        icon={<Server className="w-4 h-4" />}
      >
        {sources.length === 0 ? (
          <div className="p-6 text-center text-xs text-muted bg-surface2 rounded-xl border border-subtle">
            当前暂无订阅源记录，点击右上角「添加节点源」或执行{' '}
            <code className="text-primary font-mono">singctl sr sync</code> 同步本机节点
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3.5">
            {sources.map((item) => (
              <div
                key={item.name}
                className={`p-4 rounded-xl border transition-all flex flex-col justify-between gap-3 bg-surface2 ${
                  item.enabled ? 'border-subtle hover:border-strong' : 'border-subtle opacity-60'
                }`}
              >
                <div className="space-y-2">
                  <div className="flex items-start justify-between gap-2">
                    <div className="min-w-0">
                      <div className="flex items-center gap-1.5 flex-wrap">
                        <span className="font-semibold text-sm text-primary truncate">
                          {item.displayName}
                        </span>
                        {sourceTypeBadge(item)}
                        <Badge tone={item.nodeCount > 0 ? 'neutral' : 'warn'}>
                          {item.nodeCount} 节点
                        </Badge>
                        {item.source === 'remote' && item.effectiveUa && (
                          <Badge tone="neutral">
                            {formatEffectiveUA(item.effectiveUa)}
                            {item.usedProxy === 'warp' ? ' · WARP' : ''}
                          </Badge>
                        )}
                      </div>
                      <p className="text-[11px] text-muted font-mono mt-1.5 truncate">
                        {item.source === 'remote' ? item.url : item.remark || `标识: ${item.name}`}
                      </p>
                    </div>
                  </div>

                  {item.lastError && (
                    <div className="text-[11px] px-2.5 py-1.5 rounded-lg bg-[var(--status-danger-soft)] text-[var(--status-danger)] border border-rose-500/20 break-words">
                      最近拉取异常: {item.lastError}
                    </div>
                  )}
                </div>

                <div className="pt-2.5 border-t border-subtle flex flex-wrap items-center justify-between gap-2 text-xs">
                  <span className="text-[11px] font-mono text-muted truncate">
                    {item.lastFetchedAt
                      ? `更新: ${new Date(item.lastFetchedAt).toLocaleString()}`
                      : item.autoManaged
                      ? '由核心配置实时生成'
                      : '本地静态 / 手动维护'}
                  </span>
                  <div className="flex items-center gap-1 shrink-0">
                    <Button
                      size="xs"
                      variant={item.enabled ? 'secondary' : 'primary'}
                      onClick={() => handleToggleSourceEnabled(item)}
                    >
                      {item.enabled ? '停用' : '启用'}
                    </Button>
                    {item.source === 'remote' && (
                      <Button
                        size="xs"
                        variant="ghost"
                        loading={refreshingSource === item.name}
                        onClick={() => handleRefreshSources(item.name)}
                        icon={<RefreshCw className="w-3 h-3" />}
                      >
                        拉取
                      </Button>
                    )}
                    <Button
                      size="xs"
                      variant="ghost"
                      onClick={() => openEditSourceModal(item)}
                      icon={<Edit3 className="w-3 h-3" />}
                    >
                      编辑
                    </Button>
                    {!item.autoManaged && !item.name.startsWith('fleet_') && (
                      <Button
                        size="xs"
                        variant="ghost"
                        onClick={() => setConfirmAction({ kind: 'deleteSource', item })}
                        icon={<Trash2 className="w-3 h-3 text-rose-400" />}
                        aria-label="删除订阅源"
                      />
                    )}
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </SectionCard>

      {/* One-Click Client Import Cards */}
      <SectionCard
        title="客户端一键导入 (URL Scheme)"
        subtitle="支持移动端及桌面端直接拉起客户端或复制对应协议导入链接"
        icon={<Globe className="w-4 h-4" />}
      >
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3.5">
          {clients.map((c) => (
            <div
              key={c.key}
              className="p-4 rounded-xl bg-surface2 border border-subtle hover:border-strong transition-colors flex flex-col justify-between gap-3"
            >
              <div className="flex items-start gap-2.5">
                <span className="text-xl leading-none mt-0.5">{c.icon}</span>
                <div className="min-w-0">
                  <div className="font-semibold text-sm text-primary">{c.name}</div>
                  <div className="text-xs text-muted mt-0.5">{c.desc}</div>
                </div>
              </div>
              <div className="flex items-center gap-1.5 pt-2 border-t border-subtle">
                <Button
                  size="xs"
                  variant="primary"
                  disabled={!c.scheme}
                  onClick={() => {
                    if (c.scheme) window.location.href = c.scheme;
                  }}
                  className="flex-1"
                >
                  一键导入
                </Button>
                <Button
                  size="xs"
                  variant="secondary"
                  disabled={!c.scheme}
                  onClick={() => copyText(c.scheme, `client-${c.key}`)}
                  icon={
                    copiedKey === `client-${c.key}` ? (
                      <Check className="w-3 h-3" />
                    ) : (
                      <Copy className="w-3 h-3" />
                    )
                  }
                >
                  复制
                </Button>
                <Button
                  size="xs"
                  variant="ghost"
                  disabled={!c.scheme}
                  onClick={() => setQrModal({ title: `${c.name} 导入二维码`, url: c.scheme })}
                  icon={<QrCode className="w-3.5 h-3.5" />}
                  aria-label="二维码"
                />
              </div>
            </div>
          ))}
        </div>
      </SectionCard>

      {/* Local Direct URIs */}
      {(data?.nodes?.hy2?.link || data?.nodes?.vless?.link) && (
        <SectionCard
          title="本机单节点直连链接 (URI)"
          subtitle="适合单节点临时测试或不支持托管订阅的客户端"
          icon={<FileText className="w-4 h-4" />}
        >
          <div className="space-y-3">
            {data.nodes?.hy2?.link && (
              <div className="p-3.5 rounded-xl bg-surface2 border border-subtle space-y-2">
                <div className="flex items-center justify-between gap-2">
                  <div className="flex items-center gap-2">
                    <Badge tone="ok">Hysteria2</Badge>
                    <span className="font-mono text-xs text-secondary">
                      {data.nodes.hy2.domain}:{data.nodes.hy2.port}
                    </span>
                  </div>
                  <div className="flex items-center gap-1.5">
                    <Button
                      size="xs"
                      variant="secondary"
                      onClick={() => copyText(data.nodes.hy2.link, 'hy2')}
                      icon={copiedKey === 'hy2' ? <Check className="w-3 h-3" /> : <Copy className="w-3 h-3" />}
                    >
                      复制 URI
                    </Button>
                    <Button
                      size="xs"
                      variant="ghost"
                      onClick={() =>
                        setQrModal({ title: 'Hysteria2 节点二维码', url: data.nodes.hy2.link })
                      }
                      icon={<QrCode className="w-3.5 h-3.5" />}
                    />
                  </div>
                </div>
                <div className="font-mono text-[11px] text-muted break-all select-all">
                  {data.nodes.hy2.link}
                </div>
              </div>
            )}

            {data.nodes?.vless?.link && (
              <div className="p-3.5 rounded-xl bg-surface2 border border-subtle space-y-2">
                <div className="flex items-center justify-between gap-2">
                  <div className="flex items-center gap-2">
                    <Badge tone="accent">VLESS Reality</Badge>
                    <span className="font-mono text-xs text-secondary">
                      SNI: {data.nodes.vless.sni} · Port {data.nodes.vless.port}
                    </span>
                  </div>
                  <div className="flex items-center gap-1.5">
                    <Button
                      size="xs"
                      variant="secondary"
                      onClick={() => copyText(data.nodes.vless.link, 'vless')}
                      icon={
                        copiedKey === 'vless' ? <Check className="w-3 h-3" /> : <Copy className="w-3 h-3" />
                      }
                    >
                      复制 URI
                    </Button>
                    <Button
                      size="xs"
                      variant="ghost"
                      onClick={() =>
                        setQrModal({
                          title: 'VLESS Reality 节点二维码',
                          url: data.nodes.vless.link,
                        })
                      }
                      icon={<QrCode className="w-3.5 h-3.5" />}
                    />
                  </div>
                </div>
                <div className="font-mono text-[11px] text-muted break-all select-all">
                  {data.nodes.vless.link}
                </div>
              </div>
            )}
          </div>
        </SectionCard>
      )}

      {/* Subscription Access Audit */}
      <SectionCard
        title="订阅拉取与防盗刷审计"
        subtitle="实时记录每次订阅密钥下发与拦截详情，异常并发 IP 可一键全集群拉黑"
        icon={<ShieldCheck className="w-4 h-4" />}
        noPadding
        actions={
          <div className="flex items-center gap-2">
            <Button
              size="xs"
              variant="secondary"
              loading={loadingAudit}
              onClick={() => loadAuditLogs()}
              icon={<RefreshCw className="w-3 h-3" />}
            >
              刷新
            </Button>
            <Button
              size="xs"
              variant="danger"
              loading={clearingAudit}
              disabled={auditLogs.length === 0}
              onClick={() => setConfirmAction({ kind: 'clearAudit' })}
              icon={<Trash2 className="w-3 h-3" />}
            >
              清空记录
            </Button>
          </div>
        }
      >
        {riskSummary && riskSummary.level !== 'safe' && (
          <div
            className="mx-4 mt-4 p-3.5 rounded-xl border text-xs space-y-1.5"
            style={{
              backgroundColor:
                riskSummary.level === 'high'
                  ? 'var(--status-danger-soft)'
                  : 'var(--status-warn-soft)',
              borderColor:
                riskSummary.level === 'high' ? 'var(--status-danger)' : 'var(--status-warn)',
            }}
          >
            <div className="flex flex-wrap items-center justify-between gap-2 font-semibold text-primary">
              <span className="inline-flex items-center gap-1.5">
                <ShieldAlert className="w-4 h-4" />
                {riskSummary.level === 'high'
                  ? '检测到高风险订阅拉取行为，建议立即轮换订阅密钥'
                  : '检测到异常拉取特征，请核对是否为本人设备'}
              </span>
              <span className="font-mono text-[11px] text-secondary">
                24h 独立 IP: {riskSummary.uniqueIps24h} · 国家/地区: {riskSummary.uniqueCountries24h}
              </span>
            </div>
            {riskSummary.reasons.length > 0 && (
              <ul className="list-disc pl-5 text-secondary space-y-0.5">
                {riskSummary.reasons.map((r, i) => (
                  <li key={i}>{r}</li>
                ))}
              </ul>
            )}
          </div>
        )}

        <DataTable
          columns={auditColumns}
          rows={auditLogs}
          rowKey={(log, idx) => `${log.timestamp}-${log.ip}-${idx}`}
          loading={loadingAudit}
          emptyText="近期暂无客户端订阅拉取或密钥拦截记录"
          compact
        />
      </SectionCard>

      {/* Add / Edit Source SlideDrawer */}
      <SlideDrawer
        open={Boolean(editingSource)}
        onClose={() => setEditingSource(null)}
        title={editingSource?.name ? `编辑节点源 · ${editingSource.displayName}` : '添加节点源 / 外部订阅'}
        subtitle="支持远程机场订阅自动更新或手动粘贴节点 URI"
        size="lg"
        footer={
          <div className="flex justify-end gap-2">
            <Button variant="secondary" onClick={() => setEditingSource(null)}>
              取消
            </Button>
            <Button
              variant="primary"
              loading={savingSource}
              onClick={() => {
                const form = document.getElementById('sc-source-form') as HTMLFormElement | null;
                form?.requestSubmit();
              }}
            >
              保存订阅源
            </Button>
          </div>
        }
      >
        {editingSource && (
          <form id="sc-source-form" onSubmit={handleSaveSource} className="space-y-4 text-xs sm:text-sm">
            <div>
              <label className="block text-xs font-medium text-secondary mb-1.5">显示名称</label>
              <input
                type="text"
                required
                value={editingSource.displayName}
                onChange={(e) =>
                  setEditingSource({ ...editingSource, displayName: e.target.value })
                }
                placeholder="例如：日本备用机场 / 自建中转组"
                className="sc-input w-full px-3 py-2 text-sm"
              />
            </div>

            {!editingSource.name && (
              <div>
                <label className="block text-xs font-medium text-secondary mb-1.5">节点源类型</label>
                <div className="grid grid-cols-2 gap-2.5">
                  {[
                    { key: 'remote', title: '远程订阅 URL', desc: '定时或手动从外部订阅地址拉取' },
                    { key: 'local', title: '自定义节点 URI', desc: '直接粘贴 vless:// / hysteria2:// 链接' },
                  ].map((opt) => {
                    const active = editingSource.source === opt.key;
                    return (
                      <button
                        key={opt.key}
                        type="button"
                        onClick={() =>
                          setEditingSource({
                            ...editingSource,
                            source: opt.key as 'remote' | 'local',
                          })
                        }
                        style={
                          active
                            ? { backgroundColor: 'var(--accent-soft)', borderColor: 'var(--accent)' }
                            : undefined
                        }
                        className={`p-3 rounded-xl border text-left transition-all cursor-pointer ${
                          active ? '' : 'bg-surface2 border-subtle hover:border-strong'
                        }`}
                      >
                        <div className="font-semibold text-xs text-primary">{opt.title}</div>
                        <div className="text-[11px] text-muted mt-0.5">{opt.desc}</div>
                      </button>
                    );
                  })}
                </div>
              </div>
            )}

            {editingSource.source === 'remote' ? (
              <>
                <div>
                  <label className="block text-xs font-medium text-secondary mb-1.5">远程订阅 URL</label>
                  <input
                    type="url"
                    required
                    disabled={isAutoManagedEdit}
                    value={editingSource.url || ''}
                    onChange={(e) => setEditingSource({ ...editingSource, url: e.target.value })}
                    placeholder="https://sub.example.com/api/v1/client/subscribe?token=your_token"
                    className="sc-input w-full px-3 py-2 text-xs font-mono"
                  />
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                  <div>
                    <label className="block text-xs font-medium text-secondary mb-1.5">
                      拉取伪装 User-Agent
                    </label>
                    <select
                      value={editingSource.userAgent || 'auto'}
                      onChange={(e) =>
                        setEditingSource({ ...editingSource, userAgent: e.target.value })
                      }
                      className="sc-input w-full px-3 py-2 text-xs"
                    >
                      {UA_PRESETS.map((u) => (
                        <option key={u.value} value={u.value}>
                          {u.label}
                        </option>
                      ))}
                    </select>
                  </div>
                  <div>
                    <label className="block text-xs font-medium text-secondary mb-1.5">
                      拉取出口网络路径
                    </label>
                    <select
                      value={editingSource.proxyMode || 'auto'}
                      onChange={(e) =>
                        setEditingSource({ ...editingSource, proxyMode: e.target.value })
                      }
                      className="sc-input w-full px-3 py-2 text-xs"
                    >
                      {PROXY_MODE_OPTIONS.map((p) => (
                        <option key={p.value} value={p.value}>
                          {p.label}
                        </option>
                      ))}
                    </select>
                  </div>
                </div>

                {editingSource.userAgent === 'custom' && (
                  <div>
                    <label className="block text-xs font-medium text-secondary mb-1.5">
                      自定义 User-Agent 内容
                    </label>
                    <input
                      type="text"
                      value={customUAInput}
                      onChange={(e) => setCustomUAInput(e.target.value)}
                      placeholder="例如：ClashMetaForAndroid/2.10.1.Meta"
                      className="sc-input w-full px-3 py-2 text-xs font-mono"
                    />
                  </div>
                )}
              </>
            ) : (
              <div>
                <label className="block text-xs font-medium text-secondary mb-1.5">
                  节点 URI 列表（每行一条或 Base64）
                </label>
                <textarea
                  rows={6}
                  required={!isAutoManagedEdit}
                  disabled={isAutoManagedEdit}
                  value={editingSource.content || ''}
                  onChange={(e) => setEditingSource({ ...editingSource, content: e.target.value })}
                  placeholder={
                    'vless://11111111-1111-1111-1111-111111111111@node.example.com:443?security=reality&sni=www.bing.com#Node-1\nhysteria2://password@203.0.113.10:443/?sni=node.example.com#Node-2'
                  }
                  className="sc-input w-full px-3 py-2 text-xs font-mono"
                />
              </div>
            )}

            <div>
              <label className="block text-xs font-medium text-secondary mb-1.5">备注</label>
              <input
                type="text"
                value={editingSource.remark || ''}
                onChange={(e) => setEditingSource({ ...editingSource, remark: e.target.value })}
                placeholder="可选备注说明"
                className="sc-input w-full px-3 py-2 text-xs"
              />
            </div>

            <label className="inline-flex items-center gap-2 text-xs text-primary cursor-pointer select-none">
              <input
                type="checkbox"
                checked={editingSource.enabled !== false}
                onChange={(e) => setEditingSource({ ...editingSource, enabled: e.target.checked })}
                className="accent-[var(--accent)] w-4 h-4"
              />
              <span>启用并参与聚合下发</span>
            </label>
          </form>
        )}
      </SlideDrawer>

      {/* Live Preview SlideDrawer */}
      <SlideDrawer
        open={showPreviewDrawer}
        onClose={() => setShowPreviewDrawer(false)}
        title="多端订阅配置实时预览"
        subtitle={previewData?.filename || '选择目标格式查看 SubHub 实时渲染结果'}
        size="xl"
        headerExtra={
          previewData && (
            <div className="flex items-center gap-2">
              <Badge tone="neutral">{previewData.nodeCount} 节点</Badge>
              <Button
                size="xs"
                variant="secondary"
                onClick={() => copyText(previewData.content, 'preview-copy')}
                icon={
                  copiedKey === 'preview-copy' ? (
                    <Check className="w-3.5 h-3.5" />
                  ) : (
                    <Copy className="w-3.5 h-3.5" />
                  )
                }
              >
                复制内容
              </Button>
              <Button
                size="xs"
                variant="primary"
                onClick={handleDownloadPreview}
                icon={<Download className="w-3.5 h-3.5" />}
              >
                下载配置
              </Button>
            </div>
          )
        }
      >
        <div className="space-y-4">
          <SegmentedTabs
            items={PREVIEW_TARGETS}
            value={previewTarget}
            onChange={(t) => void fetchPreview(t)}
          />
          <div className="rounded-xl border border-subtle bg-[#060913] text-slate-200 font-mono text-xs p-4 min-h-[360px] max-h-[65vh] overflow-y-auto">
            {loadingPreview ? (
              <div className="py-16 text-center text-slate-400">
                <RefreshCw className="w-5 h-5 animate-spin mx-auto mb-2 text-accent" />
                <span>正在实时生成 {previewTarget} 配置…</span>
              </div>
            ) : (
              <pre className="whitespace-pre-wrap break-all leading-relaxed select-text">
                {previewData?.content || ''}
              </pre>
            )}
          </div>
        </div>
      </SlideDrawer>

      {/* QR Code SlideDrawer */}
      <SlideDrawer
        open={Boolean(qrModal)}
        onClose={() => setQrModal(null)}
        title={qrModal?.title || '扫码导入'}
        subtitle="使用 Shadowrocket / Sing-Box / Clash 客户端扫描下方二维码"
        size="md"
      >
        {qrModal && (
          <div className="flex flex-col items-center text-center space-y-4 py-4">
            <div className="p-4 rounded-2xl bg-white border border-subtle shadow-sm">
              <QRCodeBox value={qrModal.url} size={220} />
            </div>
            <p className="font-mono text-[11px] text-secondary break-all bg-surface2 border border-subtle rounded-xl p-3 w-full text-left select-all">
              {qrModal.url}
            </p>
            <Button
              variant="primary"
              size="sm"
              onClick={() => copyText(qrModal.url, 'qr-copy')}
              icon={copiedKey === 'qr-copy' ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
            >
              复制链接地址
            </Button>
          </div>
        )}
      </SlideDrawer>

      {/* ConfirmDialog */}
      <ConfirmDialog
        open={Boolean(confirmAction)}
        title={
          confirmAction?.kind === 'rotateKey'
            ? '确认轮换订阅访问密钥？'
            : confirmAction?.kind === 'clearAudit'
            ? '确认清空订阅拉取审计日志？'
            : `确认移除订阅源「${confirmAction?.kind === 'deleteSource' ? confirmAction.item.displayName : ''}」？`
        }
        description={
          confirmAction?.kind === 'rotateKey'
            ? '轮换后将生成全新随机订阅密钥，所有设备原旧订阅链接会立即失效，需重新扫码或导入新链接。'
            : confirmAction?.kind === 'clearAudit'
            ? '清空后近期订阅下发与密钥拦截记录将不可恢复，已触发的防火墙 IP 封禁不受影响。'
            : '移除后该订阅源包含的节点将从下次及实时聚合下发中移除。'
        }
        confirmText={confirmAction?.kind === 'rotateKey' ? '确认轮换' : '确认移除'}
        danger
        onConfirm={executeConfirm}
        onCancel={() => setConfirmAction(null)}
      />
    </div>
  );
};

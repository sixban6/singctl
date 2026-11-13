import React, { useEffect, useState } from 'react';
import {
  ArrowUpCircle,
  CheckCircle2,
  ChevronDown,
  ChevronUp,
  Clock,
  Edit3,
  Globe,
  Network,
  Plus,
  RefreshCw,
  Rocket,
  RotateCcw,
  Search,
  Server,
  ShieldAlert,
  Sparkles,
  Stethoscope,
  Terminal,
  Trash2,
  XCircle,
  Zap,
} from 'lucide-react';
import { api } from '../api';
import {
  FleetActionResult,
  FleetAuthType,
  FleetBootstrapDefaults,
  FleetBootstrapInput,
  FleetBootstrapPlan,
  FleetNode,
  FleetSummary,
  FleetUpsertInput,
} from '../types';
import {
  Badge,
  Button,
  CardSkeleton,
  ConfirmDialog,
  DataColumn,
  DataTable,
  PageHeader,
  SectionCard,
  SegmentedTabs,
  SlideDrawer,
  useToast,
} from '../ui';

type ModalMode = 'existing' | 'bootstrap';
type ViewMode = 'cards' | 'table';

const DEFAULT_SUMMARY: FleetSummary = {
  total: 0,
  online: 0,
  totalSyncedEndpoints: 0,
  avgDoctorScore: 0,
};

function authTypeLabel(t: FleetAuthType): string {
  switch (t) {
    case 'inline_key':
      return '托管私钥 (0600)';
    case 'key_file':
      return '主控免密密钥';
    case 'ssh_alias':
      return 'SSH Config 别名';
    case 'password':
      return 'SSH 密码认证';
    default:
      return t;
  }
}

type ConfirmState =
  | { kind: 'reset'; ids?: string[]; label: string }
  | { kind: 'healAll' }
  | { kind: 'deleteNode'; node: FleetNode }
  | null;

export const FleetTab: React.FC = () => {
  const { success, error } = useToast();
  const [nodes, setNodes] = useState<FleetNode[]>([]);
  const [summary, setSummary] = useState<FleetSummary>(DEFAULT_SUMMARY);
  const [defaults, setDefaults] = useState<FleetBootstrapDefaults | null>(null);
  const [loading, setLoading] = useState(true);
  const [viewMode, setViewMode] = useState<ViewMode>('cards');

  const [runningKey, setRunningKey] = useState<string | null>(null);
  const [resultsDrawerOpen, setResultsDrawerOpen] = useState(false);
  const [actionResults, setActionResults] = useState<FleetActionResult[] | null>(null);
  const [actionBannerTitle, setActionBannerTitle] = useState('');
  const [confirmState, setConfirmState] = useState<ConfirmState>(null);

  // Add / Bootstrap / Edit Drawer State
  const [showDrawer, setShowDrawer] = useState(false);
  const [modalMode, setModalMode] = useState<ModalMode>('bootstrap');
  const [isEditingExisting, setIsEditingExisting] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [showAdvancedBootstrap, setShowAdvancedBootstrap] = useState(false);
  const [previewPlan, setPreviewPlan] = useState<FleetBootstrapPlan | null>(null);
  const [previewLoading, setPreviewLoading] = useState(false);

  const [form, setForm] = useState<FleetBootstrapInput>({
    id: '',
    name: '',
    host: '',
    port: 22,
    user: 'root',
    authType: 'password',
    sshAlias: '',
    keyPath: '~/.ssh/id_ed25519',
    privateKey: '',
    password: '',
    autoSync: true,
    nodeDomain: '',
    substoreDomain: '',
    cfDnsKey: '',
    nodeTag: '',
    sni: '',
    hardenSsh: true,
    targetSshPort: 2222,
    extraAuthorizedKeys: '',
  });

  const triggerSilentProbe = async () => {
    try {
      const res = await api.probeFleet();
      if (res && Array.isArray(res.nodes)) {
        setNodes(res.nodes);
        if (res.summary) setSummary(res.summary);
      }
    } catch {
      // ignore silent patrol error
    }
  };

  const loadFleet = async (silent = false) => {
    if (!silent) setLoading(true);
    try {
      const res = await api.getFleet();
      setNodes(res.nodes || []);
      setSummary(res.summary || DEFAULT_SUMMARY);
    } catch (err: unknown) {
      if (!silent) error(err instanceof Error ? err.message : '加载节点舰队失败');
    } finally {
      if (!silent) setLoading(false);
    }
  };

  useEffect(() => {
    void loadFleet().then(() => {
      void triggerSilentProbe();
    });
    api
      .getFleetDefaults()
      .then((d) => setDefaults(d))
      .catch(() => {});

    const timer = window.setInterval(() => {
      if (document.visibilityState === 'visible') {
        void triggerSilentProbe();
      }
    }, 60_000);
    return () => window.clearInterval(timer);
  }, []);

  const openAddDrawer = (mode: ModalMode = 'bootstrap') => {
    setIsEditingExisting(false);
    setModalMode(mode);
    setShowAdvancedBootstrap(false);
    setPreviewPlan(null);
    setForm({
      id: '',
      name: '',
      host: '',
      port: mode === 'bootstrap' ? 22 : 2222,
      user: 'root',
      authType: mode === 'bootstrap' ? 'password' : 'inline_key',
      sshAlias: '',
      keyPath: '~/.ssh/id_ed25519',
      privateKey: '',
      password: '',
      autoSync: true,
      nodeDomain: '',
      substoreDomain: '',
      cfDnsKey: '',
      nodeTag: '',
      sni: '',
      hardenSsh: true,
      targetSshPort: defaults?.defaultTargetSshPort || 2222,
      extraAuthorizedKeys: '',
    });
    setShowDrawer(true);
  };

  const openEditDrawer = (n: FleetNode) => {
    setIsEditingExisting(true);
    setModalMode('existing');
    setPreviewPlan(null);
    setForm({
      id: n.id,
      name: n.name,
      host: n.host,
      port: n.port || 2222,
      user: n.user || 'root',
      authType: n.authType || 'key_file',
      sshAlias: n.sshAlias || '',
      keyPath: n.keyPath || '~/.ssh/id_ed25519',
      privateKey: '',
      password: '',
      autoSync: true,
      nodeDomain: n.domain || '',
      substoreDomain: '',
      cfDnsKey: '',
      nodeTag: '',
      sni: '',
    });
    setShowDrawer(true);
  };

  const handlePreviewBootstrap = async () => {
    if (!form.host.trim() && !(form.sshAlias || '').trim()) {
      error('请先输入新服务器公网 IP 地址');
      return;
    }
    setPreviewLoading(true);
    try {
      const plan = await api.previewFleetBootstrap(form);
      setPreviewPlan(plan);
    } catch (err: unknown) {
      error(err instanceof Error ? err.message : '自动推导预览失败');
    } finally {
      setPreviewLoading(false);
    }
  };

  const handleSubmitDrawer = async (e: React.FormEvent) => {
    e.preventDefault();
    setSubmitting(true);
    try {
      if (modalMode === 'bootstrap') {
        const res = await api.bootstrapFleetNode(form);
        success(res.message || '新节点已完成裸机加固部署并自动汇入订阅池');
        if (res.result) {
          setActionBannerTitle(`裸机智能开荒结果 · ${res.result.name}`);
          setActionResults([res.result]);
          setResultsDrawerOpen(true);
        }
      } else {
        const payload: FleetUpsertInput = {
          id: (form.id || '').trim(),
          name: (form.name || '').trim(),
          host: form.host,
          port: form.port,
          user: form.user,
          authType: form.authType || 'inline_key',
          sshAlias: form.sshAlias,
          keyPath: form.keyPath,
          privateKey: form.privateKey,
          password: form.password,
          autoSync: form.autoSync,
        };
        const res = await api.upsertFleetNode(payload);
        success(res.message || '子节点已保存');
        if (res.syncResult) {
          setActionBannerTitle(`子节点连接与同步结果 · ${res.node.name}`);
          setActionResults([res.syncResult]);
          setResultsDrawerOpen(true);
        }
      }
      setShowDrawer(false);
      await loadFleet(true);
    } catch (err: unknown) {
      error(err instanceof Error ? err.message : '提交失败');
    } finally {
      setSubmitting(false);
    }
  };

  const executeRunAction = async (
    action: 'sync' | 'probe' | 'doctor' | 'reset' | 'update',
    ids?: string[],
    label?: string
  ) => {
    const key = ids && ids.length === 1 ? `${action}:${ids[0]}` : `${action}:all`;
    setRunningKey(key);
    try {
      const res = await api.runFleetAction(action, ids);
      success(res.message);
      setActionBannerTitle(label || `批量指令 [${action}] 执行报告`);
      setActionResults(res.results || []);
      setResultsDrawerOpen(true);
      await loadFleet(true);
    } catch (err: unknown) {
      error(err instanceof Error ? err.message : '执行舰队操作失败');
    } finally {
      setRunningKey(null);
    }
  };

  const executeFleetHeal = async () => {
    setRunningKey('heal:all');
    try {
      const res = await api.runHeal({ scope: 'fleet', allowReboot: true });
      success(res.message);
      if (res.fleetReport) {
        setActionBannerTitle(
          res.fleetReport.circuitBreakerHit
            ? '全舰队安全自愈报告（触发熔断保护）'
            : `全舰队三层安全自愈报告（健康 ${res.fleetReport.healthyNodes}/${res.fleetReport.totalNodes}）`
        );
        setActionResults(
          res.fleetReport.results.map((r) => ({
            id: r.id,
            name: r.name,
            success: r.success,
            latencyMs: 0,
            doctorScore: r.doctorScoreAfterReboot,
            message: r.summary,
            output:
              r.actions && r.actions.length > 0
                ? r.actions
                    .map((a) => `${a.success ? '✓' : '✗'} [${a.layer}/${a.target}] ${a.message}`)
                    .join('\n')
                : undefined,
          }))
        );
        setResultsDrawerOpen(true);
      }
      await loadFleet(true);
    } catch (err: unknown) {
      error(err instanceof Error ? err.message : '全舰队安全自愈执行失败');
    } finally {
      setRunningKey(null);
    }
  };

  const executeDeleteNode = async (n: FleetNode) => {
    setRunningKey(`del:${n.id}`);
    try {
      const res = await api.deleteFleetNode(n.id, false);
      success(res.message || '已移除子节点');
      await loadFleet(true);
    } catch (err: unknown) {
      error(err instanceof Error ? err.message : '移除子节点失败');
    } finally {
      setRunningKey(null);
    }
  };

  const handleConfirm = async () => {
    const state = confirmState;
    if (!state) return;
    setConfirmState(null);
    if (state.kind === 'reset') {
      await executeRunAction('reset', state.ids, state.label);
    } else if (state.kind === 'healAll') {
      await executeFleetHeal();
    } else if (state.kind === 'deleteNode') {
      await executeDeleteNode(state.node);
    }
  };

  if (loading && nodes.length === 0) {
    return (
      <div className="space-y-4">
        <CardSkeleton rows={3} />
        <CardSkeleton rows={5} />
      </div>
    );
  }

  const columns: DataColumn<FleetNode>[] = [
    {
      key: 'name',
      header: '节点 / 连接方式',
      render: (n) => (
        <div className="min-w-0">
          <div className="flex items-center gap-1.5 flex-wrap">
            <span className="font-semibold text-xs text-primary">{n.name}</span>
            <Badge tone="neutral">#{n.id}</Badge>
          </div>
          <div className="font-mono text-[11px] text-muted mt-0.5">
            {n.authType === 'ssh_alias'
              ? `SSH Alias: ${n.sshAlias || n.host}`
              : `${n.user}@${n.host}:${n.port || 22}`}
          </div>
          {n.domain && (
            <div className="font-mono text-[11px] text-accent mt-0.5">
              {n.domain}
              {typeof n.certDaysLeft === 'number' && n.certDaysLeft > 0 ? ` · 证书 ${n.certDaysLeft}d` : ''}
            </div>
          )}
        </div>
      ),
    },
    {
      key: 'status',
      header: '状态 / 延迟',
      render: (n) => (
        <div className="flex flex-col gap-1 items-start">
          <Badge tone={n.online ? 'ok' : 'neutral'} dot={n.online}>
            {n.online ? `在线 ${n.latencyMs > 0 ? `${n.latencyMs}ms` : ''}` : '待同步'}
          </Badge>
          {n.doctorScore > 0 && (
            <Badge tone={n.doctorScore >= 90 ? 'ok' : 'warn'}>{n.doctorScore} 分</Badge>
          )}
        </div>
      ),
    },
    {
      key: 'metrics',
      header: '版本 / 负载 / 节点数',
      render: (n) => (
        <div className="font-mono text-[11px] text-secondary space-y-0.5 tnum">
          <div>
            {n.syncedNodes} 节点 · {n.singctlVersion || '--'}
          </div>
          <div className="text-muted">
            Load {n.cpuLoad ? n.cpuLoad.split(' ')[0] : '--'} · Mem{' '}
            {n.memPercent > 0 ? `${n.memPercent.toFixed(0)}%` : '--'}
            {n.bbrEnabled ? ' · BBR' : ''}
          </div>
        </div>
      ),
    },
    {
      key: 'actions',
      header: '操作',
      align: 'right',
      render: (n) => (
        <div className="inline-flex items-center justify-end gap-1 whitespace-nowrap">
          <Button
            size="xs"
            variant="secondary"
            loading={runningKey === `sync:${n.id}`}
            disabled={Boolean(runningKey)}
            onClick={() => void executeRunAction('sync', [n.id], `同步节点 · ${n.name}`)}
          >
            同步
          </Button>
          <Button
            size="xs"
            variant="ghost"
            loading={runningKey === `doctor:${n.id}`}
            disabled={Boolean(runningKey)}
            onClick={() => void executeRunAction('doctor', [n.id], `健康体检 · ${n.name}`)}
          >
            体检
          </Button>
          <Button
            size="xs"
            variant="ghost"
            disabled={Boolean(runningKey)}
            onClick={() =>
              setConfirmState({
                kind: 'reset',
                ids: [n.id],
                label: `凭据换血 · ${n.name}`,
              })
            }
          >
            换血
          </Button>
          <Button
            size="xs"
            variant="ghost"
            onClick={() => openEditDrawer(n)}
            icon={<Edit3 className="w-3 h-3" />}
            aria-label="编辑子节点"
          />
          <Button
            size="xs"
            variant="ghost"
            onClick={() => setConfirmState({ kind: 'deleteNode', node: n })}
            icon={<Trash2 className="w-3 h-3 text-rose-400" />}
            aria-label="移除子节点"
          />
        </div>
      ),
    },
  ];

  return (
    <div className="space-y-6">
      <PageHeader
        title="全球多节点舰队中枢"
        description="新购裸机只需输入 IP 与初始密码，自动创建灰云 DNS、完成 SSH 22→2222 免密加固并汇入 SubHub"
        badge={
          <Badge tone={summary.online > 0 ? 'ok' : 'neutral'} dot={summary.online > 0}>
            {summary.online} / {summary.total} 在线
          </Badge>
        }
        actions={
          <>
            <Button
              size="sm"
              variant="primary"
              onClick={() => openAddDrawer('bootstrap')}
              icon={<Rocket className="w-3.5 h-3.5" />}
            >
              新机零配置开荒
            </Button>
            <Button
              size="sm"
              variant="secondary"
              onClick={() => openAddDrawer('existing')}
              icon={<Plus className="w-3.5 h-3.5" />}
            >
              纳管已有节点
            </Button>
            {actionResults && actionResults.length > 0 && (
              <Button
                size="sm"
                variant="ghost"
                onClick={() => setResultsDrawerOpen(true)}
                icon={<Terminal className="w-3.5 h-3.5" />}
              >
                查看最近报告
              </Button>
            )}
          </>
        }
      />

      {/* Top KPI Strip */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3.5">
        <div className="console-card rounded-2xl p-4">
          <div className="text-xs text-muted">纳管子节点总数</div>
          <div className="text-2xl font-bold font-mono tnum text-primary mt-1">{summary.total}</div>
          <div className="text-[11px] text-muted mt-1 font-mono truncate">无 Agent 原生 SSH 编排</div>
        </div>
        <div className="console-card rounded-2xl p-4">
          <div className="text-xs text-muted">在线健康节点</div>
          <div
            className="text-2xl font-bold font-mono tnum mt-1"
            style={{ color: 'var(--status-ok)' }}
          >
            {summary.online}{' '}
            <span className="text-sm font-normal text-muted">/ {summary.total}</span>
          </div>
          <div className="text-[11px] text-muted mt-1 font-mono truncate">HTTPS :443 零日志自动巡检</div>
        </div>
        <div className="console-card rounded-2xl p-4">
          <div className="text-xs text-muted">全网平均健康分</div>
          <div className="text-2xl font-bold font-mono tnum text-accent mt-1">
            {summary.avgDoctorScore > 0 ? `${summary.avgDoctorScore} / 100` : '--'}
          </div>
          <div className="text-[11px] text-muted mt-1 font-mono truncate">并发全链路 Doctor 评分</div>
        </div>
        <div className="console-card rounded-2xl p-4">
          <div className="text-xs text-muted">已自动汇入 SubHub</div>
          <div className="text-2xl font-bold font-mono tnum text-primary mt-1">
            {summary.totalSyncedEndpoints}
          </div>
          <div className="text-[11px] text-muted mt-1 font-mono truncate">一条订阅链接统管全球</div>
        </div>
      </div>

      {/* Batch Command Toolbar */}
      {nodes.length > 0 && (
        <SectionCard
          title="全舰队批量编排指令"
          subtitle="并发调度全网已纳管子节点执行探活、同步、自愈与凭据轮换"
          icon={<Network className="w-4 h-4" />}
          actions={
            <SegmentedTabs
              items={[
                { key: 'cards', label: '卡片视图' },
                { key: 'table', label: '表格对比' },
              ]}
              value={viewMode}
              onChange={(k) => setViewMode(k as ViewMode)}
            />
          }
        >
          <div className="flex flex-wrap items-center gap-2">
            <Button
              size="sm"
              variant="primary"
              loading={runningKey === 'heal:all'}
              disabled={Boolean(runningKey)}
              onClick={() => setConfirmState({ kind: 'healAll' })}
              icon={<ShieldAlert className="w-3.5 h-3.5" />}
            >
              {runningKey === 'heal:all' ? '全网自愈中…' : '全网安全自愈'}
            </Button>
            <Button
              size="sm"
              variant="secondary"
              loading={runningKey === 'probe:all'}
              disabled={Boolean(runningKey)}
              onClick={() =>
                void executeRunAction('probe', undefined, '全网 HTTPS :443 毫秒级探活报告')
              }
              icon={<Zap className="w-3.5 h-3.5" />}
            >
              秒级探活
            </Button>
            <Button
              size="sm"
              variant="secondary"
              loading={runningKey === 'sync:all'}
              disabled={Boolean(runningKey)}
              onClick={() => void executeRunAction('sync', undefined, '全网节点同步报告')}
              icon={<RefreshCw className="w-3.5 h-3.5" />}
            >
              同步订阅
            </Button>
            <Button
              size="sm"
              variant="secondary"
              loading={runningKey === 'doctor:all'}
              disabled={Boolean(runningKey)}
              onClick={() => void executeRunAction('doctor', undefined, '全网并发体检报告')}
              icon={<Stethoscope className="w-3.5 h-3.5" />}
            >
              全网体检
            </Button>
            <Button
              size="sm"
              variant="danger"
              loading={runningKey === 'reset:all'}
              disabled={Boolean(runningKey)}
              onClick={() =>
                setConfirmState({ kind: 'reset', label: '全网凭据换血与自动同步报告' })
              }
              icon={<RotateCcw className="w-3.5 h-3.5" />}
            >
              全网换血
            </Button>
            <Button
              size="sm"
              variant="secondary"
              loading={runningKey === 'update:all'}
              disabled={Boolean(runningKey)}
              onClick={() => void executeRunAction('update', undefined, '全网 SingCtl 升级报告')}
              icon={<ArrowUpCircle className="w-3.5 h-3.5" />}
            >
              升级版本
            </Button>
          </div>
        </SectionCard>
      )}

      {/* Nodes List / Grid / Empty Onboarding */}
      {nodes.length === 0 ? (
        <div className="console-card rounded-2xl p-8 sm:p-10 text-center space-y-4">
          <div className="w-12 h-12 rounded-2xl bg-[var(--accent-soft)] flex items-center justify-center text-accent mx-auto">
            <Server className="w-6 h-6" />
          </div>
          <div className="max-w-lg mx-auto space-y-1.5">
            <h3 className="text-base font-semibold text-primary">尚未纳管任何远程子节点</h3>
            <p className="text-xs text-secondary leading-relaxed">
              新买任何空白 Linux VPS，只需填入 <strong>IP 地址</strong> 和{' '}
              <strong>初始 root 密码</strong>，主控将自动按归属地命名、自动在 Cloudflare 创建灰云解析、切换 SSH 2222 免密并装好四核服务汇入总订阅。
            </p>
          </div>
          <div className="flex flex-wrap items-center justify-center gap-3 pt-1">
            <Button
              variant="primary"
              onClick={() => openAddDrawer('bootstrap')}
              icon={<Rocket className="w-4 h-4" />}
            >
              新机零配置 60s 开荒纳管
            </Button>
            <Button
              variant="secondary"
              onClick={() => openAddDrawer('existing')}
              icon={<Plus className="w-4 h-4" />}
            >
              纳管已有 SingCtl 节点
            </Button>
          </div>
          <p className="text-[11px] text-muted font-mono break-all">
            SSH 命令行同样支持零参数向导: <code className="text-accent">singctl fl new</code>
          </p>
        </div>
      ) : viewMode === 'table' ? (
        <SectionCard title="子节点对比清单" subtitle={`共 ${nodes.length} 台子节点`} noPadding>
          <DataTable
            columns={columns}
            rows={nodes}
            rowKey={(n) => n.id}
            emptyText="暂无子节点"
            compact
          />
        </SectionCard>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 2xl:grid-cols-3 gap-4">
          {nodes.map((n) => {
            const isSyncing = runningKey === `sync:${n.id}`;
            const isDoctoring = runningKey === `doctor:${n.id}`;
            const isResetting = runningKey === `reset:${n.id}`;
            const isUpdating = runningKey === `update:${n.id}`;
            return (
              <div
                key={n.id}
                className="console-card rounded-2xl p-4 sm:p-5 flex flex-col justify-between gap-4"
              >
                <div className="space-y-3">
                  <div className="flex items-start justify-between gap-2">
                    <div className="min-w-0">
                      <div className="flex items-center gap-1.5 flex-wrap">
                        <span className="text-base font-bold text-primary truncate">{n.name}</span>
                        <Badge tone="accent">#{n.id}</Badge>
                        <Badge tone="neutral">{authTypeLabel(n.authType)}</Badge>
                      </div>
                      <div className="text-xs font-mono text-secondary mt-1 break-all">
                        {n.authType === 'ssh_alias'
                          ? `SSH Alias: ${n.sshAlias || n.host}`
                          : `${n.user}@${n.host}:${n.port || 22}`}
                      </div>
                      {n.domain && (
                        <div className="inline-flex items-center gap-1.5 mt-1.5 px-2 py-0.5 rounded-md bg-[var(--accent-soft)] text-[11px] font-mono text-accent break-all">
                          <Globe className="w-3 h-3 shrink-0" />
                          <span>{n.domain}</span>
                          {n.dnsAutoManaged && <span className="opacity-80">· 自动灰云</span>}
                          {typeof n.certDaysLeft === 'number' && n.certDaysLeft > 0 && (
                            <span
                              style={{
                                color:
                                  n.certDaysLeft <= 7 ? 'var(--status-warn)' : 'var(--status-ok)',
                              }}
                            >
                              · 证书{n.certDaysLeft}天
                            </span>
                          )}
                        </div>
                      )}
                    </div>

                    <div className="flex flex-col items-end gap-1.5 shrink-0">
                      <Badge tone={n.online ? 'ok' : 'neutral'} dot={n.online}>
                        {n.online ? (
                          <span>在线 {n.latencyMs > 0 ? `${n.latencyMs}ms` : ''}</span>
                        ) : (
                          <span className="inline-flex items-center gap-1">
                            <Clock className="w-3 h-3" /> 待同步
                          </span>
                        )}
                      </Badge>
                      {n.doctorScore > 0 && (
                        <Badge tone={n.doctorScore >= 90 ? 'ok' : 'warn'}>{n.doctorScore} 分</Badge>
                      )}
                    </div>
                  </div>

                  {/* Runtime Metrics Box */}
                  <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 p-3 rounded-xl bg-surface2 border border-subtle text-xs font-mono tnum">
                    <div>
                      <div className="text-[10px] text-muted">已同步节点</div>
                      <div className="font-semibold mt-0.5 truncate" style={{ color: 'var(--status-ok)' }}>
                        {n.syncedNodes} 个
                      </div>
                    </div>
                    <div>
                      <div className="text-[10px] text-muted">版本</div>
                      <div className="text-primary mt-0.5 truncate">{n.singctlVersion || '--'}</div>
                    </div>
                    <div>
                      <div className="text-[10px] text-muted">CPU / 内存</div>
                      <div className="text-primary mt-0.5 truncate">
                        {n.cpuLoad ? n.cpuLoad.split(' ')[0] : '--'} /{' '}
                        {n.memPercent > 0 ? `${n.memPercent.toFixed(0)}%` : '--'}
                      </div>
                    </div>
                    <div>
                      <div className="text-[10px] text-muted">BBR 加速</div>
                      <div
                        className="mt-0.5"
                        style={{ color: n.bbrEnabled ? 'var(--status-ok)' : 'var(--text-muted)' }}
                      >
                        {n.bbrEnabled ? '已开启' : '--'}
                      </div>
                    </div>
                  </div>

                  {n.lastError && (
                    <div
                      className="px-3 py-2 rounded-xl border text-[11px] font-mono break-words"
                      style={{
                        backgroundColor: 'var(--status-danger-soft)',
                        borderColor: 'var(--status-danger)',
                        color: 'var(--status-danger)',
                      }}
                    >
                      上次异常: {n.lastError}
                    </div>
                  )}
                </div>

                <div className="pt-3 border-t border-subtle flex flex-wrap items-center justify-between gap-2">
                  <div className="flex flex-wrap items-center gap-1">
                    <Button
                      size="xs"
                      variant="secondary"
                      loading={isSyncing}
                      disabled={Boolean(runningKey)}
                      onClick={() => void executeRunAction('sync', [n.id], `同步节点 · ${n.name}`)}
                      icon={<RefreshCw className="w-3 h-3" />}
                    >
                      同步
                    </Button>
                    <Button
                      size="xs"
                      variant="ghost"
                      loading={isDoctoring}
                      disabled={Boolean(runningKey)}
                      onClick={() =>
                        void executeRunAction('doctor', [n.id], `健康体检 · ${n.name}`)
                      }
                      icon={<Stethoscope className="w-3 h-3" />}
                    >
                      体检
                    </Button>
                    <Button
                      size="xs"
                      variant="ghost"
                      loading={isResetting}
                      disabled={Boolean(runningKey)}
                      onClick={() =>
                        setConfirmState({
                          kind: 'reset',
                          ids: [n.id],
                          label: `凭据换血 · ${n.name}`,
                        })
                      }
                      icon={<RotateCcw className="w-3 h-3" />}
                    >
                      换血
                    </Button>
                    <Button
                      size="xs"
                      variant="ghost"
                      loading={isUpdating}
                      disabled={Boolean(runningKey)}
                      onClick={() =>
                        void executeRunAction('update', [n.id], `升级 SingCtl · ${n.name}`)
                      }
                      icon={<ArrowUpCircle className="w-3 h-3" />}
                    >
                      升级
                    </Button>
                  </div>

                  <div className="flex items-center gap-1">
                    <Button
                      size="xs"
                      variant="ghost"
                      onClick={() => openEditDrawer(n)}
                      icon={<Edit3 className="w-3.5 h-3.5" />}
                      aria-label="编辑连接信息"
                    />
                    <Button
                      size="xs"
                      variant="ghost"
                      onClick={() => setConfirmState({ kind: 'deleteNode', node: n })}
                      icon={<Trash2 className="w-3.5 h-3.5 text-rose-400" />}
                      aria-label="从舰队及订阅池移除"
                    />
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* Action Results SlideDrawer */}
      <SlideDrawer
        open={resultsDrawerOpen && Boolean(actionResults && actionResults.length > 0)}
        onClose={() => setResultsDrawerOpen(false)}
        title={actionBannerTitle || '舰队指令执行结果'}
        subtitle="远程 SSH 并发编排逐台执行回执"
        size="lg"
      >
        <div className="space-y-3">
          {(actionResults || []).map((r) => (
            <div
              key={r.id}
              className="p-3.5 rounded-xl border text-xs font-mono space-y-2"
              style={{
                backgroundColor: r.success ? 'var(--status-ok-soft)' : 'var(--status-danger-soft)',
                borderColor: r.success ? 'var(--status-ok)' : 'var(--status-danger)',
              }}
            >
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div className="flex items-center gap-2 font-semibold text-primary">
                  {r.success ? (
                    <CheckCircle2 className="w-4 h-4 shrink-0" style={{ color: 'var(--status-ok)' }} />
                  ) : (
                    <XCircle className="w-4 h-4 shrink-0" style={{ color: 'var(--status-danger)' }} />
                  )}
                  <span>
                    {r.name} ({r.id})
                  </span>
                  {r.latencyMs > 0 && <span className="text-muted font-normal">· SSH {r.latencyMs}ms</span>}
                </div>
                {typeof r.doctorScore === 'number' && r.doctorScore > 0 && (
                  <Badge tone={r.doctorScore >= 90 ? 'ok' : 'warn'}>健康分 {r.doctorScore}/100</Badge>
                )}
              </div>
              <p className="text-[11px] text-secondary break-words">{r.message}</p>
              {r.output && (
                <pre className="p-2.5 rounded-lg bg-[#060913] text-slate-300 border border-subtle text-[11px] whitespace-pre-wrap break-all max-h-48 overflow-y-auto">
                  {r.output}
                </pre>
              )}
            </div>
          ))}
        </div>
      </SlideDrawer>

      {/* Add / Bootstrap / Edit SlideDrawer */}
      <SlideDrawer
        open={showDrawer}
        onClose={() => setShowDrawer(false)}
        title={
          modalMode === 'bootstrap'
            ? '新购裸机智能零配置开荒纳管'
            : isEditingExisting
            ? `编辑舰队子节点 #${form.id}`
            : '纳管已有 SingCtl 子节点'
        }
        subtitle="凭据以 0600 权限保存在主控 /etc/singctl/，加固后自动擦除初始明文密码"
        size="lg"
        footer={
          <div className="flex justify-end gap-2">
            <Button variant="secondary" disabled={submitting} onClick={() => setShowDrawer(false)}>
              取消
            </Button>
            <Button
              variant="primary"
              loading={submitting}
              onClick={() => {
                const formEl = document.getElementById('sc-fleet-form') as HTMLFormElement | null;
                formEl?.requestSubmit();
              }}
            >
              {submitting
                ? modalMode === 'bootstrap'
                  ? '正在全自动加固与部署 (40-90s)…'
                  : '正在连接并保存…'
                : modalMode === 'bootstrap'
                ? '一键开荒并汇入总订阅'
                : '保存子节点'}
            </Button>
          </div>
        }
      >
        <form id="sc-fleet-form" onSubmit={handleSubmitDrawer} className="space-y-4">
          {!isEditingExisting && (
            <SegmentedTabs
              items={[
                { key: 'bootstrap', label: '新机 60s 零配置开荒' },
                { key: 'existing', label: '纳管已安装节点' },
              ]}
              value={modalMode}
              onChange={(next) => {
                const mode = next as ModalMode;
                setModalMode(mode);
                setPreviewPlan(null);
                setForm((prev) =>
                  mode === 'bootstrap'
                    ? { ...prev, port: 22, authType: 'password' }
                    : {
                        ...prev,
                        port: prev.port === 22 ? 2222 : prev.port,
                        authType:
                          prev.authType === 'password' && !prev.password
                            ? 'inline_key'
                            : prev.authType,
                      }
                );
              }}
            />
          )}

          {modalMode === 'bootstrap' ? (
            <>
              <div
                className="p-3.5 rounded-xl border space-y-1.5"
                style={{
                  backgroundColor: 'var(--status-ok-soft)',
                  borderColor: 'var(--status-ok)',
                }}
              >
                <div className="flex items-center gap-1.5 text-xs font-semibold text-primary">
                  <Sparkles className="w-3.5 h-3.5 shrink-0" style={{ color: 'var(--status-ok)' }} />
                  <span>已自动继承本机主控配置（只需填新机 IP 与初始密码）</span>
                </div>
                <p className="text-[11px] text-secondary leading-relaxed font-mono">
                  • 节点代号与中文名：按新机 IP 归属地自动分配（同地区多台自动递增如 sg2）
                  <br />• 节点域名与解析：
                  {defaults?.hasMasterCfToken
                    ? `自动在 *.cdn.${defaults.suggestedRootZone || '主控根域名'} 下创建灰云仅 DNS 解析`
                    : '主控未检出 CF Token，请在下方高级选项填入'}
                  <br />• 安全与协议参数：SSH 22→{form.targetSshPort || 2222} 免密禁密码 · SNI=
                  {defaults?.defaultSni || 'swdist.apple.com'} · HY2={defaults?.hy2Up || 50}/
                  {defaults?.hy2Down || 300}M
                </p>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3.5">
                <div>
                  <label className="block text-xs font-medium text-secondary mb-1.5">
                    1. 新服务器公网 IP 地址 <span className="text-rose-400">*</span>
                  </label>
                  <input
                    type="text"
                    required={form.authType !== 'ssh_alias'}
                    value={form.host}
                    onChange={(e) => {
                      setForm({ ...form, host: e.target.value });
                      setPreviewPlan(null);
                    }}
                    placeholder="例如: 203.0.113.10"
                    className="sc-input w-full px-3.5 py-2 text-xs font-mono"
                  />
                </div>

                {form.authType === 'password' ? (
                  <div>
                    <label className="block text-xs font-medium text-secondary mb-1.5">
                      2. root 初始 SSH 密码 <span className="text-rose-400">*</span>
                    </label>
                    <input
                      type="password"
                      required
                      value={form.password || ''}
                      onChange={(e) => setForm({ ...form, password: e.target.value })}
                      placeholder="粘贴云厂商初始 root 密码"
                      className="sc-input w-full px-3.5 py-2 text-xs font-mono"
                    />
                  </div>
                ) : (
                  <div>
                    <label className="block text-xs font-medium text-secondary mb-1.5">
                      2. SSH 私钥路径 / 凭据
                    </label>
                    <input
                      type="text"
                      value={form.keyPath || ''}
                      onChange={(e) => setForm({ ...form, keyPath: e.target.value })}
                      placeholder="~/.ssh/id_ed25519"
                      className="sc-input w-full px-3.5 py-2 text-xs font-mono"
                    />
                  </div>
                )}
              </div>

              <div className="flex flex-wrap items-center justify-between gap-2">
                <Button
                  type="button"
                  size="xs"
                  variant="secondary"
                  loading={previewLoading}
                  disabled={!form.host.trim()}
                  onClick={handlePreviewBootstrap}
                  icon={<Search className="w-3.5 h-3.5" />}
                >
                  {previewLoading ? '正在探测 IP 归属地与根域名…' : '预览将自动分配的代号与域名'}
                </Button>

                <button
                  type="button"
                  onClick={() => setShowAdvancedBootstrap((v) => !v)}
                  className="inline-flex items-center gap-1 text-xs text-muted hover:text-primary cursor-pointer"
                >
                  <span>高级自定义选项（可选）</span>
                  {showAdvancedBootstrap ? (
                    <ChevronUp className="w-3.5 h-3.5" />
                  ) : (
                    <ChevronDown className="w-3.5 h-3.5" />
                  )}
                </button>
              </div>

              {previewPlan && (
                <div className="p-3.5 rounded-xl bg-[var(--accent-soft)] border border-[var(--accent)] text-xs font-mono space-y-1 text-primary">
                  <div>
                    • 自动识别代号与名称 :{' '}
                    <span className="font-semibold" style={{ color: 'var(--status-ok)' }}>
                      {previewPlan.id} ({previewPlan.name})
                    </span>
                  </div>
                  <div>
                    • 自动绑定灰云域名 :{' '}
                    <span className="font-semibold text-accent">
                      {previewPlan.domain || '需手动指定'}
                    </span>
                  </div>
                  <div>
                    • 安全基线与伪装参数 : SSH {form.port || 22}→{previewPlan.targetSshPort} · SNI=
                    {previewPlan.sni}
                  </div>
                </div>
              )}

              {showAdvancedBootstrap && (
                <div className="p-4 rounded-xl bg-surface2 border border-subtle space-y-3.5">
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                    <div>
                      <label className="block text-xs text-secondary mb-1">
                        自定义代号 ID (留空按归属地自动分配)
                      </label>
                      <input
                        type="text"
                        value={form.id || ''}
                        onChange={(e) => setForm({ ...form, id: e.target.value })}
                        placeholder="例如: jp1 或 sg2"
                        className="sc-input w-full px-3 py-2 text-xs font-mono"
                      />
                    </div>
                    <div>
                      <label className="block text-xs text-secondary mb-1">
                        自定义显示名称 (留空自动生成中文名)
                      </label>
                      <input
                        type="text"
                        value={form.name || ''}
                        onChange={(e) => setForm({ ...form, name: e.target.value })}
                        placeholder="例如: 日本·东京"
                        className="sc-input w-full px-3 py-2 text-xs"
                      />
                    </div>
                  </div>

                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                    <div>
                      <label className="block text-xs text-secondary mb-1">
                        自定义绑定域名 (留空自动分配并创建 DNS)
                      </label>
                      <input
                        type="text"
                        value={form.nodeDomain || ''}
                        onChange={(e) => setForm({ ...form, nodeDomain: e.target.value })}
                        placeholder={
                          defaults?.suggestedRootZone
                            ? `留空自动分配 <id>.${defaults.suggestedRootZone}`
                            : 'jp1.example.com'
                        }
                        className="sc-input w-full px-3 py-2 text-xs font-mono"
                      />
                    </div>
                    <div>
                      <label className="block text-xs text-secondary mb-1">
                        Cloudflare Token {defaults?.hasMasterCfToken ? '(留空复用主控)' : '*'}
                      </label>
                      <input
                        type="password"
                        required={!defaults?.hasMasterCfToken}
                        value={form.cfDnsKey || ''}
                        onChange={(e) => setForm({ ...form, cfDnsKey: e.target.value })}
                        placeholder={
                          defaults?.hasMasterCfToken
                            ? '已默认继承主控 cf_dns_key'
                            : '输入 Cloudflare DNS Token'
                        }
                        className="sc-input w-full px-3 py-2 text-xs font-mono"
                      />
                    </div>
                  </div>

                  <div className="grid grid-cols-3 gap-3">
                    <div>
                      <label className="block text-xs text-secondary mb-1">初始 SSH 端口</label>
                      <input
                        type="number"
                        value={form.port || 22}
                        onChange={(e) => setForm({ ...form, port: Number(e.target.value) || 22 })}
                        className="sc-input w-full px-3 py-2 text-xs font-mono"
                      />
                    </div>
                    <div>
                      <label className="block text-xs text-secondary mb-1">加固收敛端口</label>
                      <input
                        type="number"
                        value={form.targetSshPort || 2222}
                        onChange={(e) =>
                          setForm({ ...form, targetSshPort: Number(e.target.value) || 2222 })
                        }
                        className="sc-input w-full px-3 py-2 text-xs font-mono"
                      />
                    </div>
                    <div>
                      <label className="block text-xs text-secondary mb-1">伪装 SNI</label>
                      <input
                        type="text"
                        value={form.sni || ''}
                        onChange={(e) => setForm({ ...form, sni: e.target.value })}
                        placeholder={defaults?.defaultSni || 'swdist.apple.com'}
                        className="sc-input w-full px-3 py-2 text-xs font-mono"
                      />
                    </div>
                  </div>

                  <label className="inline-flex items-center gap-2 text-xs text-primary cursor-pointer select-none">
                    <input
                      type="checkbox"
                      checked={form.hardenSsh !== false}
                      onChange={(e) => setForm({ ...form, hardenSsh: e.target.checked })}
                      className="accent-[var(--accent)] w-4 h-4"
                    />
                    <span>自动注入主控免密公钥、验证切换 SSH 端口并禁用密码登录</span>
                  </label>
                </div>
              )}
            </>
          ) : (
            <>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs text-secondary mb-1">
                    节点代号 ID (英文/数字，唯一) *
                  </label>
                  <input
                    type="text"
                    required
                    disabled={isEditingExisting}
                    value={form.id || ''}
                    onChange={(e) => setForm({ ...form, id: e.target.value })}
                    placeholder="例如: jp 或 us-lax"
                    className="sc-input w-full px-3 py-2 text-xs font-mono disabled:opacity-60"
                  />
                </div>
                <div>
                  <label className="block text-xs text-secondary mb-1">节点显示名称 *</label>
                  <input
                    type="text"
                    required
                    value={form.name || ''}
                    onChange={(e) => setForm({ ...form, name: e.target.value })}
                    placeholder="例如: 日本东京"
                    className="sc-input w-full px-3 py-2 text-xs"
                  />
                </div>
              </div>

              <div>
                <label className="block text-xs text-secondary mb-1.5">SSH 认证方式</label>
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-xs">
                  {(
                    [
                      { k: 'inline_key', label: '粘贴 SSH 私钥' },
                      { k: 'key_file', label: '主控密钥路径' },
                      { k: 'ssh_alias', label: 'SSH Config 别名' },
                      { k: 'password', label: 'SSH 密码' },
                    ] as { k: FleetAuthType; label: string }[]
                  ).map((opt) => {
                    const active = form.authType === opt.k;
                    return (
                      <button
                        key={opt.k}
                        type="button"
                        onClick={() => setForm({ ...form, authType: opt.k })}
                        style={
                          active
                            ? { backgroundColor: 'var(--accent-soft)', borderColor: 'var(--accent)' }
                            : undefined
                        }
                        className={`py-2 px-2 rounded-xl border font-medium transition-colors cursor-pointer ${
                          active ? 'text-primary' : 'bg-surface2 border-subtle text-secondary hover:text-primary'
                        }`}
                      >
                        {opt.label}
                      </button>
                    );
                  })}
                </div>
              </div>

              {form.authType === 'ssh_alias' ? (
                <div>
                  <label className="block text-xs text-secondary mb-1">
                    主控 ~/.ssh/config 主机别名 *
                  </label>
                  <input
                    type="text"
                    required
                    value={form.sshAlias || ''}
                    onChange={(e) =>
                      setForm({ ...form, sshAlias: e.target.value, host: e.target.value })
                    }
                    placeholder="例如: tokyo-vps"
                    className="sc-input w-full px-3 py-2 text-xs font-mono"
                  />
                </div>
              ) : (
                <div className="grid grid-cols-1 sm:grid-cols-4 gap-3">
                  <div className="sm:col-span-2">
                    <label className="block text-xs text-secondary mb-1">服务器公网 IP 或域名 *</label>
                    <input
                      type="text"
                      required
                      value={form.host}
                      onChange={(e) => setForm({ ...form, host: e.target.value })}
                      placeholder="203.0.113.10"
                      className="sc-input w-full px-3 py-2 text-xs font-mono"
                    />
                  </div>
                  <div>
                    <label className="block text-xs text-secondary mb-1">SSH 端口</label>
                    <input
                      type="number"
                      value={form.port || 2222}
                      onChange={(e) => setForm({ ...form, port: Number(e.target.value) || 2222 })}
                      className="sc-input w-full px-3 py-2 text-xs font-mono"
                    />
                  </div>
                  <div>
                    <label className="block text-xs text-secondary mb-1">SSH 用户</label>
                    <input
                      type="text"
                      value={form.user || 'root'}
                      onChange={(e) => setForm({ ...form, user: e.target.value })}
                      className="sc-input w-full px-3 py-2 text-xs font-mono"
                    />
                  </div>
                </div>
              )}

              {form.authType === 'inline_key' && (
                <div>
                  <label className="block text-xs text-secondary mb-1">
                    SSH 私钥内容 (PEM) {isEditingExisting ? '（留空则保留原托管私钥）' : '*'}
                  </label>
                  <textarea
                    rows={4}
                    required={!isEditingExisting}
                    value={form.privateKey || ''}
                    onChange={(e) => setForm({ ...form, privateKey: e.target.value })}
                    placeholder={'-----BEGIN OPENSSH PRIVATE KEY-----\n...'}
                    className="sc-input w-full p-3 text-xs font-mono"
                  />
                </div>
              )}

              {form.authType === 'password' && (
                <div>
                  <label className="block text-xs text-secondary mb-1">
                    SSH 登录密码 {isEditingExisting ? '（留空则保留原密码）' : '*'}
                  </label>
                  <input
                    type="password"
                    required={!isEditingExisting}
                    value={form.password || ''}
                    onChange={(e) => setForm({ ...form, password: e.target.value })}
                    placeholder="输入目标服务器 SSH 密码"
                    className="sc-input w-full px-3 py-2 text-xs font-mono"
                  />
                </div>
              )}

              {form.authType === 'key_file' && (
                <div>
                  <label className="block text-xs text-secondary mb-1">
                    主控服务器上的私钥路径 *
                  </label>
                  <input
                    type="text"
                    required
                    value={form.keyPath || ''}
                    onChange={(e) => setForm({ ...form, keyPath: e.target.value })}
                    placeholder="/etc/singctl/fleet_keys/master_ed25519"
                    className="sc-input w-full px-3 py-2 text-xs font-mono"
                  />
                </div>
              )}

              <label className="inline-flex items-center gap-2 text-xs text-primary cursor-pointer select-none pt-1">
                <input
                  type="checkbox"
                  checked={Boolean(form.autoSync)}
                  onChange={(e) => setForm({ ...form, autoSync: e.target.checked })}
                  className="accent-[var(--accent)] w-4 h-4"
                />
                <span>保存后立即通过 SSH 提取该节点 HY2 / Reality 链接并汇入本机总订阅</span>
              </label>
            </>
          )}
        </form>
      </SlideDrawer>

      {/* ConfirmDialog for Reset / HealAll / Delete */}
      <ConfirmDialog
        open={Boolean(confirmState)}
        title={
          confirmState?.kind === 'reset'
            ? confirmState.ids && confirmState.ids.length === 1
              ? `确认对子节点 [${confirmState.ids[0]}] 凭据换血？`
              : '确认对全部在线子节点执行「一键换血重置凭据」？'
            : confirmState?.kind === 'healAll'
            ? '确认对全舰队执行「三层安全漏洞自愈」？'
            : confirmState?.kind === 'deleteNode'
            ? `确认从舰队移除「${confirmState.node.name} (${confirmState.node.id})」？`
            : ''
        }
        description={
          confirmState?.kind === 'reset'
            ? '将在目标服务器重新生成 UUID、Reality 密钥对与 Hysteria2 密码，并自动将全新节点同步回主控 SubHub 订阅池（客户端刷新订阅即可无感恢复）。'
            : confirmState?.kind === 'healAll'
            ? '第一层：金丝雀校验升级核心组件；第二层：安装系统安全仓库补丁并热重载动态库；第三层：如有新内核待生效，将按单台串行滚动重启与异常熔断方式执行。'
            : confirmState?.kind === 'deleteNode'
            ? `自动从本机 SubHub 总订阅清理关联节点 (fleet_${confirmState.node.id})${
                confirmState.node.dnsAutoManaged && confirmState.node.domain
                  ? `，并同步清理 Cloudflare 灰云记录 (${confirmState.node.domain})`
                  : ''
              }，不会卸载远端服务。`
            : ''
        }
        confirmText="确认执行"
        danger={confirmState?.kind !== 'healAll'}
        onConfirm={() => void handleConfirm()}
        onCancel={() => setConfirmState(null)}
      />
    </div>
  );
};

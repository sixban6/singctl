import React, { useEffect, useState } from 'react';
import {
  FleetNode,
  FleetSummary,
  FleetUpsertInput,
  FleetBootstrapInput,
  FleetBootstrapDefaults,
  FleetBootstrapPlan,
  FleetAuthType,
  FleetActionResult,
} from '../types';
import { api } from '../api';
import { useToast } from './Toast';
import {
  Network,
  Plus,
  RefreshCw,
  Stethoscope,
  RotateCcw,
  ArrowUpCircle,
  Trash2,
  Edit3,
  CheckCircle2,
  XCircle,
  Rocket,
  Server,
  X,
  Terminal,
  ShieldCheck,
  ShieldAlert,
  Clock,
  Sparkles,
  ChevronDown,
  ChevronUp,
  Globe,
  Search,
  Zap,
} from 'lucide-react';

type ModalMode = 'existing' | 'bootstrap';

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

export const FleetTab: React.FC = () => {
  const { success, error } = useToast();
  const [nodes, setNodes] = useState<FleetNode[]>([]);
  const [summary, setSummary] = useState<FleetSummary>(DEFAULT_SUMMARY);
  const [defaults, setDefaults] = useState<FleetBootstrapDefaults | null>(null);
  const [loading, setLoading] = useState(true);
  const [runningKey, setRunningKey] = useState<string | null>(null);
  const [actionResults, setActionResults] = useState<FleetActionResult[] | null>(null);
  const [actionBannerTitle, setActionBannerTitle] = useState<string>('');

  // Modal state
  const [showModal, setShowModal] = useState(false);
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

  useEffect(() => {
    loadFleet().then(() => {
      triggerSilentProbe();
    });
    api
      .getFleetDefaults()
      .then((d) => setDefaults(d))
      .catch(() => {});

    const timer = window.setInterval(() => {
      if (document.visibilityState === 'visible') {
        triggerSilentProbe();
      }
    }, 60_000);
    return () => window.clearInterval(timer);
  }, []);

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
    } catch (err: any) {
      if (!silent) error(err.message || '加载节点舰队失败');
    } finally {
      if (!silent) setLoading(false);
    }
  };

  const openAddModal = (mode: ModalMode = 'bootstrap') => {
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
    setShowModal(true);
  };

  const openEditModal = (n: FleetNode) => {
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
    setShowModal(true);
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
    } catch (err: any) {
      error(err.message || '自动推导预览失败');
    } finally {
      setPreviewLoading(false);
    }
  };

  const handleSubmitModal = async (e: React.FormEvent) => {
    e.preventDefault();
    setSubmitting(true);
    try {
      if (modalMode === 'bootstrap') {
        const res = await api.bootstrapFleetNode(form);
        success(res.message || '新节点已完成裸机加固部署并自动汇入订阅池');
        if (res.result) {
          setActionBannerTitle(`裸机智能开荒结果 · ${res.result.name}`);
          setActionResults([res.result]);
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
        }
      }
      setShowModal(false);
      await loadFleet(true);
    } catch (err: any) {
      error(err.message || '提交失败');
    } finally {
      setSubmitting(false);
    }
  };

  const handleRunAction = async (
    action: 'sync' | 'probe' | 'doctor' | 'reset' | 'update',
    ids?: string[],
    label?: string
  ) => {
    if (action === 'reset') {
      const scopeText = ids && ids.length === 1 ? `子节点 [${ids[0]}]` : '全部在线子节点';
      if (
        !window.confirm(
          `确定要对 ${scopeText} 执行「一键换血重置凭据」吗？\n\n该操作将在目标服务器重新生成 UUID、Reality 密钥对与 Hysteria2 密码，并自动将全新节点同步回主控 SubHub 订阅池（客户端刷新订阅即可无感恢复）。`
        )
      ) {
        return;
      }
    }

    const key = ids && ids.length === 1 ? `${action}:${ids[0]}` : `${action}:all`;
    setRunningKey(key);
    try {
      const res = await api.runFleetAction(action, ids);
      success(res.message);
      setActionBannerTitle(label || `批量指令 [${action}] 执行报告`);
      setActionResults(res.results || []);
      await loadFleet(true);
    } catch (err: any) {
      error(err.message || '执行舰队操作失败');
    } finally {
      setRunningKey(null);
    }
  };

  const handleFleetHeal = async () => {
    if (
      !window.confirm(
        '确定对全舰队执行「三层安全漏洞自愈」吗？\n\n• 第一层：金丝雀校验升级核心组件（失败秒级回滚）\n• 第二层：安装系统安全仓库补丁并热重载残留 .so 动态库\n• 第三层：如有新内核待生效，将按【单台串行滚动重启 + 异常熔断】方式执行，保障全网永不断流。'
      )
    ) {
      return;
    }
    setRunningKey('heal:all');
    try {
      const res = await api.runHeal({ scope: 'fleet', allowReboot: true });
      success(res.message);
      if (res.fleetReport) {
        setActionBannerTitle(
          res.fleetReport.circuitBreakerHit
            ? `🚨 全舰队安全自愈报告（触发熔断保护）`
            : `🛡️ 全舰队三层安全自愈报告（健康 ${res.fleetReport.healthyNodes}/${res.fleetReport.totalNodes}）`
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
                ? r.actions.map((a) => `${a.success ? '✓' : '✗'} [${a.layer}/${a.target}] ${a.message}`).join('\n')
                : undefined,
          }))
        );
      }
      await loadFleet(true);
    } catch (err: any) {
      error(err.message || '全舰队安全自愈执行失败');
    } finally {
      setRunningKey(null);
    }
  };

  const handleDeleteNode = async (n: FleetNode) => {
    const dnsHint = n.dnsAutoManaged && n.domain ? `\n• 同时自动清理 Cloudflare 上的灰云解析记录 (${n.domain})` : '';
    if (
      !window.confirm(
        `确定要从舰队移除「${n.name} (${n.id})」吗？\n\n• 自动从本机 SubHub 总订阅清理关联节点 (fleet_${n.id})${dnsHint}\n• 不会卸载远端服务器已有服务`
      )
    ) {
      return;
    }
    setRunningKey(`del:${n.id}`);
    try {
      const res = await api.deleteFleetNode(n.id, false);
      success(res.message || '已移除子节点');
      await loadFleet(true);
    } catch (err: any) {
      error(err.message || '移除子节点失败');
    } finally {
      setRunningKey(null);
    }
  };

  if (loading && nodes.length === 0) {
    return (
      <div className="p-10 sm:p-12 text-center text-slate-400 glass-card rounded-2xl">
        <div className="animate-spin w-6 h-6 border-2 border-emerald-500 border-t-transparent rounded-full mx-auto mb-3"></div>
        <span>正在读取全球节点舰队编排状态...</span>
      </div>
    );
  }

  return (
    <div className="space-y-5 sm:space-y-6">
      {/* Top KPI Strip */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3 sm:gap-4">
        <div className="p-3.5 sm:p-4 rounded-2xl glass-card">
          <div className="text-xs text-slate-400">纳管子节点总数</div>
          <div className="text-xl sm:text-2xl font-bold font-mono text-white mt-1">{summary.total}</div>
          <div className="text-[11px] text-slate-500 mt-1 font-mono truncate">无 Agent 原生 SSH 编排</div>
        </div>
        <div className="p-3.5 sm:p-4 rounded-2xl glass-card">
          <div className="text-xs text-slate-400">在线健康节点</div>
          <div className="text-xl sm:text-2xl font-bold font-mono text-emerald-400 mt-1">
            {summary.online} <span className="text-sm text-slate-500">/ {summary.total}</span>
          </div>
          <div className="text-[11px] text-slate-500 mt-1 font-mono truncate">HTTPS :443 零日志自动巡检</div>
        </div>
        <div className="p-3.5 sm:p-4 rounded-2xl glass-card">
          <div className="text-xs text-slate-400">全网平均健康分</div>
          <div className="text-xl sm:text-2xl font-bold font-mono text-purple-300 mt-1">
            {summary.avgDoctorScore > 0 ? `${summary.avgDoctorScore} / 100` : '--'}
          </div>
          <div className="text-[11px] text-slate-500 mt-1 font-mono truncate">并发全链路 Doctor 评分</div>
        </div>
        <div className="p-3.5 sm:p-4 rounded-2xl glass-card">
          <div className="text-xs text-slate-400">已自动汇入 SubHub</div>
          <div className="text-xl sm:text-2xl font-bold font-mono text-sky-300 mt-1">{summary.totalSyncedEndpoints}</div>
          <div className="text-[11px] text-slate-500 mt-1 font-mono truncate">一条订阅链接统管全球</div>
        </div>
      </div>

      {/* Fleet Command Toolbar */}
      <div className="p-4 sm:p-5 rounded-2xl glass-card flex flex-col xl:flex-row xl:items-center justify-between gap-4">
        <div>
          <h2 className="text-base sm:text-lg font-semibold text-white tracking-tight flex items-center gap-2">
            <Network className="w-5 h-5 text-emerald-400 shrink-0" />
            <span>全球多节点舰队中枢</span>
          </h2>
          <p className="text-xs text-slate-400 mt-0.5 leading-relaxed">
            新购裸机只需输入 IP 与初始密码，自动复用主控配置创建灰云 DNS、完成 22→2222 免密加固并汇入总订阅
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <button
            onClick={() => openAddModal('bootstrap')}
            className="flex items-center gap-1.5 px-3.5 py-2 rounded-xl bg-sky-500 hover:bg-sky-600 text-slate-950 font-semibold text-xs transition-colors shadow-lg shadow-sky-500/15"
          >
            <Rocket className="w-3.5 h-3.5" />
            <span>新机零配置开荒</span>
          </button>
          <button
            onClick={() => openAddModal('existing')}
            className="flex items-center gap-1.5 px-3 py-2 rounded-xl bg-emerald-500/15 hover:bg-emerald-500/25 border border-emerald-500/30 text-emerald-300 font-semibold text-xs transition-colors"
          >
            <Plus className="w-3.5 h-3.5" />
            <span>纳管已有节点</span>
          </button>

          {nodes.length > 0 && (
            <>
              <button
                onClick={handleFleetHeal}
                disabled={!!runningKey}
                className="flex items-center gap-1.5 px-3 py-2 rounded-xl bg-emerald-500/15 hover:bg-emerald-500/25 border border-emerald-500/30 text-xs text-emerald-200 font-semibold transition-colors disabled:opacity-50"
              >
                <ShieldAlert className={`w-3.5 h-3.5 text-emerald-400 ${runningKey === 'heal:all' ? 'animate-pulse' : ''}`} />
                <span>{runningKey === 'heal:all' ? '正在全网自愈...' : '全网安全自愈'}</span>
              </button>
              <button
                onClick={() => handleRunAction('probe', undefined, '全网 HTTPS :443 毫秒级探活报告')}
                disabled={!!runningKey}
                className="flex items-center gap-1.5 px-3 py-2 rounded-xl bg-sky-500/15 hover:bg-sky-500/25 border border-sky-500/30 text-xs text-sky-200 font-medium transition-colors disabled:opacity-50"
              >
                <Zap className={`w-3.5 h-3.5 text-sky-400 ${runningKey === 'probe:all' ? 'animate-pulse' : ''}`} />
                <span>秒级探活</span>
              </button>
              <button
                onClick={() => handleRunAction('sync', undefined, '全网节点同步报告')}
                disabled={!!runningKey}
                className="flex items-center gap-1.5 px-3 py-2 rounded-xl bg-slate-900 hover:bg-slate-800 border border-slate-700/70 text-xs text-slate-200 transition-colors disabled:opacity-50"
              >
                <RefreshCw className={`w-3.5 h-3.5 ${runningKey === 'sync:all' ? 'animate-spin text-emerald-400' : ''}`} />
                <span>同步订阅</span>
              </button>
              <button
                onClick={() => handleRunAction('doctor', undefined, '全网并发体检报告')}
                disabled={!!runningKey}
                className="flex items-center gap-1.5 px-3 py-2 rounded-xl bg-purple-500/15 hover:bg-purple-500/25 border border-purple-500/30 text-xs text-purple-200 font-medium transition-colors disabled:opacity-50"
              >
                <Stethoscope className={`w-3.5 h-3.5 ${runningKey === 'doctor:all' ? 'animate-spin' : ''}`} />
                <span>全网体检</span>
              </button>
              <button
                onClick={() => handleRunAction('reset', undefined, '全网凭据换血与自动同步报告')}
                disabled={!!runningKey}
                className="flex items-center gap-1.5 px-3 py-2 rounded-xl bg-amber-500/10 hover:bg-amber-500/20 border border-amber-500/30 text-xs text-amber-200 font-medium transition-colors disabled:opacity-50"
              >
                <RotateCcw className={`w-3.5 h-3.5 ${runningKey === 'reset:all' ? 'animate-spin' : ''}`} />
                <span>全网换血</span>
              </button>
              <button
                onClick={() => handleRunAction('update', undefined, '全网 SingCtl 升级报告')}
                disabled={!!runningKey}
                className="flex items-center gap-1.5 px-3 py-2 rounded-xl bg-slate-900 hover:bg-slate-800 border border-slate-700/70 text-xs text-slate-300 transition-colors disabled:opacity-50"
              >
                <ArrowUpCircle className={`w-3.5 h-3.5 ${runningKey === 'update:all' ? 'animate-spin text-sky-400' : ''}`} />
                <span>升级版本</span>
              </button>
            </>
          )}
        </div>
      </div>

      {/* Execution Output Drawer */}
      {actionResults && actionResults.length > 0 && (
        <div className="p-4 sm:p-5 rounded-2xl glass-card border border-emerald-500/25 space-y-3">
          <div className="flex items-center justify-between gap-2">
            <div className="flex items-center gap-2 text-xs font-semibold text-white min-w-0">
              <Terminal className="w-4 h-4 text-emerald-400 shrink-0" />
              <span className="truncate">{actionBannerTitle || '舰队指令执行结果'}</span>
            </div>
            <button
              onClick={() => setActionResults(null)}
              className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 shrink-0"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
          <div className="space-y-2 max-h-72 overflow-y-auto pr-1">
            {actionResults.map((r) => (
              <div
                key={r.id}
                className={`p-3 rounded-xl border text-xs font-mono ${
                  r.success
                    ? 'bg-emerald-950/20 border-emerald-500/25 text-slate-200'
                    : 'bg-rose-950/20 border-rose-500/30 text-rose-200'
                }`}
              >
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="flex items-center gap-2 font-semibold">
                    {r.success ? (
                      <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                    ) : (
                      <XCircle className="w-3.5 h-3.5 text-rose-400 shrink-0" />
                    )}
                    <span>
                      {r.name} ({r.id})
                    </span>
                    {r.latencyMs > 0 && <span className="text-slate-400 font-normal">· SSH {r.latencyMs}ms</span>}
                  </div>
                  {typeof r.doctorScore === 'number' && r.doctorScore > 0 && (
                    <span className="px-2 py-0.5 rounded bg-purple-500/20 text-purple-200 text-[11px]">
                      健康分 {r.doctorScore}/100
                    </span>
                  )}
                </div>
                <p className="mt-1 text-[11px] text-slate-300 break-words">{r.message}</p>
                {r.output && (
                  <pre className="mt-2 p-2.5 rounded-lg bg-slate-950/80 border border-slate-800/80 text-[11px] text-slate-400 whitespace-pre-wrap break-all max-h-40 overflow-y-auto">
                    {r.output}
                  </pre>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Nodes Grid or Empty Onboarding Card */}
      {nodes.length === 0 ? (
        <div className="p-8 sm:p-10 rounded-2xl glass-card text-center space-y-4">
          <div className="w-12 h-12 rounded-2xl bg-sky-500/10 border border-sky-500/20 flex items-center justify-center text-sky-400 mx-auto">
            <Server className="w-6 h-6" />
          </div>
          <div className="max-w-lg mx-auto space-y-1.5">
            <h3 className="text-base font-semibold text-white">尚未纳管任何远程子节点</h3>
            <p className="text-xs text-slate-400 leading-relaxed">
              新买任何空白 Linux VPS，只需填入 <strong>IP 地址</strong> 和 <strong>初始 root 密码</strong>，主控将自动按归属地命名、自动在 Cloudflare 创建灰云解析、切换 SSH 2222 免密并装好四核服务汇入总订阅。
            </p>
          </div>
          <div className="flex flex-wrap items-center justify-center gap-3 pt-1">
            <button
              onClick={() => openAddModal('bootstrap')}
              className="flex items-center gap-1.5 px-4 py-2.5 rounded-xl bg-sky-500 hover:bg-sky-600 text-slate-950 font-semibold text-xs transition-colors"
            >
              <Rocket className="w-4 h-4" />
              <span>新机零配置 60s 开荒纳管</span>
            </button>
            <button
              onClick={() => openAddModal('existing')}
              className="flex items-center gap-1.5 px-4 py-2.5 rounded-xl bg-emerald-500/15 hover:bg-emerald-500/25 border border-emerald-500/30 text-emerald-300 font-semibold text-xs transition-colors"
            >
              <Plus className="w-4 h-4" />
              <span>纳管已有 SingCtl 节点</span>
            </button>
          </div>
          <p className="text-[11px] text-slate-500 font-mono break-all">
            SSH 命令行同样支持零参数向导: <code className="text-emerald-300">singctl fl bootstrap</code>
          </p>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 2xl:grid-cols-3 gap-4">
          {nodes.map((n) => {
            const isSyncing = runningKey === `sync:${n.id}`;
            const isDoctoring = runningKey === `doctor:${n.id}`;
            const isResetting = runningKey === `reset:${n.id}`;
            const isUpdating = runningKey === `update:${n.id}`;
            return (
              <div key={n.id} className="p-4 sm:p-5 rounded-2xl glass-card flex flex-col justify-between gap-4">
                <div className="space-y-3">
                  <div className="flex items-start justify-between gap-2">
                    <div className="min-w-0">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="text-base font-bold text-white">{n.name}</span>
                        <span className="px-2 py-0.5 rounded-md text-[10px] font-mono bg-slate-800 text-emerald-300">
                          #{n.id}
                        </span>
                        <span className="px-2 py-0.5 rounded-md text-[10px] font-mono bg-slate-900 border border-slate-700/80 text-slate-400">
                          {authTypeLabel(n.authType)}
                        </span>
                      </div>
                      <div className="text-xs font-mono text-slate-400 mt-1 break-all">
                        {n.authType === 'ssh_alias'
                          ? `SSH Alias: ${n.sshAlias || n.host}`
                          : `${n.user}@${n.host}:${n.port || 22}`}
                      </div>
                      {n.domain && (
                        <div className="inline-flex items-center gap-1.5 mt-1.5 px-2 py-0.5 rounded-md bg-sky-500/10 border border-sky-500/20 text-[11px] font-mono text-sky-300 break-all">
                          <Globe className="w-3 h-3 shrink-0" />
                          <span>{n.domain}</span>
                          {n.dnsAutoManaged && <span className="text-[10px] text-sky-400/80">· 自动灰云</span>}
                          {typeof n.certDaysLeft === 'number' && n.certDaysLeft > 0 && (
                            <span
                              className={`text-[10px] ${
                                n.certDaysLeft <= 7 ? 'text-amber-300 font-semibold' : 'text-emerald-300/80'
                              }`}
                            >
                              · 证书{n.certDaysLeft}天
                            </span>
                          )}
                        </div>
                      )}
                    </div>

                    <div className="flex flex-col sm:flex-row items-end sm:items-center gap-1.5 shrink-0">
                      {n.doctorScore > 0 && (
                        <span
                          className={`px-2 py-0.5 rounded-full text-[11px] font-mono border ${
                            n.doctorScore >= 90
                              ? 'bg-purple-500/15 text-purple-200 border-purple-500/30'
                              : 'bg-amber-500/15 text-amber-200 border-amber-500/30'
                          }`}
                        >
                          {n.doctorScore}分
                        </span>
                      )}
                      <span
                        className={`inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-[11px] font-medium border ${
                          n.online
                            ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/25'
                            : 'bg-slate-800/80 text-slate-400 border-slate-700'
                        }`}
                      >
                        {n.online ? (
                          <>
                            <CheckCircle2 className="w-3 h-3" />
                            <span>在线 {n.latencyMs > 0 ? `${n.latencyMs}ms` : ''}</span>
                          </>
                        ) : (
                          <>
                            <Clock className="w-3 h-3" />
                            <span>待同步</span>
                          </>
                        )}
                      </span>
                    </div>
                  </div>

                  {/* Runtime Metrics Box */}
                  <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 p-3 rounded-xl bg-slate-950/60 border border-slate-800/80 text-xs font-mono">
                    <div>
                      <div className="text-[10px] text-slate-500">已同步节点</div>
                      <div className="text-emerald-300 font-semibold mt-0.5 truncate">
                        {n.syncedNodes} 个
                      </div>
                    </div>
                    <div>
                      <div className="text-[10px] text-slate-500">版本</div>
                      <div className="text-slate-200 mt-0.5 truncate">{n.singctlVersion || '--'}</div>
                    </div>
                    <div>
                      <div className="text-[10px] text-slate-500">CPU / 内存</div>
                      <div className="text-slate-200 mt-0.5 truncate">
                        {n.cpuLoad ? n.cpuLoad.split(' ')[0] : '--'} / {n.memPercent > 0 ? `${n.memPercent.toFixed(0)}%` : '--'}
                      </div>
                    </div>
                    <div>
                      <div className="text-[10px] text-slate-500">BBR 加速</div>
                      <div className={n.bbrEnabled ? 'text-emerald-400 mt-0.5' : 'text-slate-400 mt-0.5'}>
                        {n.bbrEnabled ? '已开启' : '--'}
                      </div>
                    </div>
                  </div>

                  {n.lastError && (
                    <div className="px-3 py-2 rounded-xl bg-rose-950/30 border border-rose-500/30 text-[11px] font-mono text-rose-300 break-words">
                      上次异常: {n.lastError}
                    </div>
                  )}
                </div>

                <div className="pt-3 border-t border-slate-800 flex flex-wrap items-center justify-between gap-2 text-xs">
                  <div className="flex flex-wrap items-center gap-1.5">
                    <button
                      onClick={() => handleRunAction('sync', [n.id], `同步节点 · ${n.name}`)}
                      disabled={!!runningKey}
                      className="flex items-center gap-1 px-2.5 py-1.5 rounded-lg bg-emerald-500/10 hover:bg-emerald-500/20 border border-emerald-500/25 text-emerald-300 transition-colors disabled:opacity-50"
                    >
                      <RefreshCw className={`w-3 h-3 ${isSyncing ? 'animate-spin' : ''}`} />
                      <span>同步</span>
                    </button>
                    <button
                      onClick={() => handleRunAction('doctor', [n.id], `健康体检 · ${n.name}`)}
                      disabled={!!runningKey}
                      className="flex items-center gap-1 px-2.5 py-1.5 rounded-lg bg-purple-500/10 hover:bg-purple-500/20 border border-purple-500/25 text-purple-200 transition-colors disabled:opacity-50"
                    >
                      <Stethoscope className={`w-3 h-3 ${isDoctoring ? 'animate-spin' : ''}`} />
                      <span>体检</span>
                    </button>
                    <button
                      onClick={() => handleRunAction('reset', [n.id], `凭据换血 · ${n.name}`)}
                      disabled={!!runningKey}
                      className="flex items-center gap-1 px-2.5 py-1.5 rounded-lg bg-amber-500/10 hover:bg-amber-500/20 border border-amber-500/25 text-amber-200 transition-colors disabled:opacity-50"
                    >
                      <RotateCcw className={`w-3 h-3 ${isResetting ? 'animate-spin' : ''}`} />
                      <span>换血</span>
                    </button>
                    <button
                      onClick={() => handleRunAction('update', [n.id], `升级 SingCtl · ${n.name}`)}
                      disabled={!!runningKey}
                      className="flex items-center gap-1 px-2.5 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-800 text-slate-300 transition-colors disabled:opacity-50"
                    >
                      <ArrowUpCircle className={`w-3 h-3 ${isUpdating ? 'animate-spin' : ''}`} />
                      <span>升级</span>
                    </button>
                  </div>

                  <div className="flex items-center gap-1.5">
                    <button
                      onClick={() => openEditModal(n)}
                      className="p-2 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-800 text-slate-400 hover:text-white transition-colors"
                      title="编辑连接信息"
                    >
                      <Edit3 className="w-3.5 h-3.5" />
                    </button>
                    <button
                      onClick={() => handleDeleteNode(n)}
                      className="p-2 rounded-lg bg-rose-500/10 hover:bg-rose-500/20 border border-rose-500/20 text-rose-300 transition-colors"
                      title="从舰队及订阅池移除"
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                    </button>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* Responsive Modal (Bottom Sheet on Mobile < 640px, Centered Dialog on Tablet/Desktop) */}
      {showModal && (
        <div className="fixed inset-0 z-50 flex items-end sm:items-center justify-center sm:p-4 bg-slate-950/85 backdrop-blur-md">
          <form
            onSubmit={handleSubmitModal}
            className="bg-slate-900 border-t sm:border border-slate-800 rounded-t-3xl sm:rounded-3xl w-full max-w-2xl max-h-[92dvh] sm:max-h-[90vh] flex flex-col overflow-hidden shadow-2xl"
          >
            <div className="flex items-center justify-between px-5 sm:px-6 py-4 border-b border-slate-800 shrink-0">
              <div className="min-w-0">
                <h4 className="text-sm sm:text-base font-bold text-white flex items-center gap-2">
                  {modalMode === 'bootstrap' ? (
                    <>
                      <Rocket className="w-4 h-4 text-sky-400 shrink-0" />
                      <span>新购裸机智能零配置开荒纳管</span>
                    </>
                  ) : (
                    <>
                      <ShieldCheck className="w-4 h-4 text-emerald-400 shrink-0" />
                      <span>{isEditingExisting ? `编辑舰队子节点 #${form.id}` : '纳管已有 SingCtl 子节点'}</span>
                    </>
                  )}
                </h4>
                <p className="text-[11px] sm:text-xs text-slate-400 mt-0.5">
                  凭据以 0600 权限保存在主控 <code className="text-slate-300">/etc/singctl/</code>，加固后自动擦除初始明文密码
                </p>
              </div>
              <button
                type="button"
                onClick={() => setShowModal(false)}
                className="p-2 rounded-xl hover:bg-slate-800 text-slate-400 hover:text-white shrink-0"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="p-5 sm:p-6 overflow-y-auto space-y-4">
              {!isEditingExisting && (
                <div className="grid grid-cols-2 gap-2 p-1 rounded-xl bg-slate-950 border border-slate-800 text-xs">
                  <button
                    type="button"
                    onClick={() => {
                      setModalMode('bootstrap');
                      setPreviewPlan(null);
                      setForm((prev) => ({
                        ...prev,
                        port: 22,
                        authType: 'password',
                      }));
                    }}
                    className={`py-2 rounded-lg font-semibold transition-colors ${
                      modalMode === 'bootstrap'
                        ? 'bg-sky-500/20 text-sky-200 border border-sky-500/30'
                        : 'text-slate-400 hover:text-white'
                    }`}
                  >
                    新机 60s 零配置开荒
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      setModalMode('existing');
                      setForm((prev) => ({
                        ...prev,
                        port: prev.port === 22 ? 2222 : prev.port,
                        authType: prev.authType === 'password' && !prev.password ? 'inline_key' : prev.authType,
                      }));
                    }}
                    className={`py-2 rounded-lg font-semibold transition-colors ${
                      modalMode === 'existing'
                        ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30'
                        : 'text-slate-400 hover:text-white'
                    }`}
                  >
                    纳管已安装节点
                  </button>
                </div>
              )}

              {modalMode === 'bootstrap' ? (
                <>
                  {/* Master Auto-Inheritance Banner */}
                  <div className="p-3.5 rounded-2xl bg-emerald-500/10 border border-emerald-500/25 space-y-1.5">
                    <div className="flex items-center gap-1.5 text-xs font-semibold text-emerald-300">
                      <Sparkles className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                      <span>已自动继承本机主控配置（只需填新机 IP 与初始密码）</span>
                    </div>
                    <p className="text-[11px] text-slate-300 leading-relaxed font-mono">
                      • 节点代号与中文名：按新机 IP 归属地自动分配（同地区多台自动递增如 sg2）
                      <br />• 节点域名与解析：
                      {defaults?.hasMasterCfToken
                        ? `自动在 *.cdn.${defaults.suggestedRootZone || '主控根域名'} 下创建灰云仅 DNS 解析`
                        : '主控未检出 CF Token，请在下方高级选项填入'}
                      <br />• 安全与协议参数：SSH 22→{form.targetSshPort || 2222} 免密禁密码 · SNI={defaults?.defaultSni || 'swdist.apple.com'} · HY2={defaults?.hy2Up || 50}/{defaults?.hy2Down || 300}M
                    </p>
                  </div>

                  {/* Minimal 2 Primary Inputs */}
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-3.5">
                    <div>
                      <label className="block text-xs font-medium text-slate-300 mb-1.5">
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
                        className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3.5 py-2.5 text-xs font-mono text-white focus:outline-none focus:border-sky-500"
                      />
                    </div>

                    {form.authType === 'password' ? (
                      <div>
                        <label className="block text-xs font-medium text-slate-300 mb-1.5">
                          2. root 初始 SSH 密码 <span className="text-rose-400">*</span>
                        </label>
                        <input
                          type="password"
                          required
                          value={form.password || ''}
                          onChange={(e) => setForm({ ...form, password: e.target.value })}
                          placeholder="粘贴云厂商初始 root 密码"
                          className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3.5 py-2.5 text-xs font-mono text-white focus:outline-none focus:border-sky-500"
                        />
                      </div>
                    ) : (
                      <div>
                        <label className="block text-xs font-medium text-slate-300 mb-1.5">
                          2. SSH 私钥路径 / 凭据
                        </label>
                        <input
                          type="text"
                          value={form.keyPath || ''}
                          onChange={(e) => setForm({ ...form, keyPath: e.target.value })}
                          placeholder="~/.ssh/id_ed25519"
                          className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3.5 py-2.5 text-xs font-mono text-white focus:outline-none focus:border-sky-500"
                        />
                      </div>
                    )}
                  </div>

                  {/* Instant Preview Button & Plan Card */}
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <button
                      type="button"
                      onClick={handlePreviewBootstrap}
                      disabled={previewLoading || !form.host.trim()}
                      className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-xl bg-slate-950 hover:bg-slate-800 border border-slate-800 text-xs text-sky-300 transition-colors disabled:opacity-50"
                    >
                      <Search className={`w-3.5 h-3.5 ${previewLoading ? 'animate-spin' : ''}`} />
                      <span>{previewLoading ? '正在探测 IP 归属地与根域名...' : '预览将自动分配的代号与域名'}</span>
                    </button>

                    <button
                      type="button"
                      onClick={() => setShowAdvancedBootstrap((v) => !v)}
                      className="inline-flex items-center gap-1 text-xs text-slate-400 hover:text-slate-200"
                    >
                      <span>高级自定义选项（可选）</span>
                      {showAdvancedBootstrap ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
                    </button>
                  </div>

                  {previewPlan && (
                    <div className="p-3.5 rounded-2xl bg-sky-950/25 border border-sky-500/30 text-xs font-mono space-y-1 text-slate-200">
                      <div>
                        • 自动识别代号与名称 :{' '}
                        <span className="text-emerald-300 font-semibold">
                          {previewPlan.id} ({previewPlan.name})
                        </span>
                      </div>
                      <div>
                        • 自动绑定灰云域名   : <span className="text-sky-300 font-semibold">{previewPlan.domain || '需手动指定'}</span>
                      </div>
                      <div>
                        • 安全基线与伪装参数 : SSH {form.port || 22}→{previewPlan.targetSshPort} · SNI={previewPlan.sni}
                      </div>
                    </div>
                  )}

                  {/* Collapsible Optional Overrides */}
                  {showAdvancedBootstrap && (
                    <div className="p-4 rounded-2xl bg-slate-950/80 border border-slate-800 space-y-3.5">
                      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                        <div>
                          <label className="block text-xs text-slate-400 mb-1">自定义代号 ID (留空按归属地自动分配)</label>
                          <input
                            type="text"
                            value={form.id || ''}
                            onChange={(e) => setForm({ ...form, id: e.target.value })}
                            placeholder="例如: jp1 或 sg2"
                            className="w-full bg-slate-900 border border-slate-800 rounded-xl px-3 py-2 text-xs font-mono text-white"
                          />
                        </div>
                        <div>
                          <label className="block text-xs text-slate-400 mb-1">自定义显示名称 (留空自动生成中文名)</label>
                          <input
                            type="text"
                            value={form.name || ''}
                            onChange={(e) => setForm({ ...form, name: e.target.value })}
                            placeholder="例如: 日本·东京"
                            className="w-full bg-slate-900 border border-slate-800 rounded-xl px-3 py-2 text-xs text-white"
                          />
                        </div>
                      </div>

                      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                        <div>
                          <label className="block text-xs text-slate-400 mb-1">自定义绑定域名 (留空自动分配并创建 DNS)</label>
                          <input
                            type="text"
                            value={form.nodeDomain || ''}
                            onChange={(e) => setForm({ ...form, nodeDomain: e.target.value })}
                            placeholder={
                              defaults?.suggestedRootZone ? `留空自动分配 <id>.${defaults.suggestedRootZone}` : 'jp1.example.com'
                            }
                            className="w-full bg-slate-900 border border-slate-800 rounded-xl px-3 py-2 text-xs font-mono text-white"
                          />
                        </div>
                        <div>
                          <label className="block text-xs text-slate-400 mb-1">
                            Cloudflare Token {defaults?.hasMasterCfToken ? '(留空复用主控)' : '*'}
                          </label>
                          <input
                            type="password"
                            required={!defaults?.hasMasterCfToken}
                            value={form.cfDnsKey || ''}
                            onChange={(e) => setForm({ ...form, cfDnsKey: e.target.value })}
                            placeholder={defaults?.hasMasterCfToken ? '已默认继承主控 cf_dns_key' : '输入 Cloudflare DNS Token'}
                            className="w-full bg-slate-900 border border-slate-800 rounded-xl px-3 py-2 text-xs font-mono text-white"
                          />
                        </div>
                      </div>

                      <div className="grid grid-cols-3 gap-3">
                        <div>
                          <label className="block text-xs text-slate-400 mb-1">初始 SSH 端口</label>
                          <input
                            type="number"
                            value={form.port || 22}
                            onChange={(e) => setForm({ ...form, port: Number(e.target.value) || 22 })}
                            className="w-full bg-slate-900 border border-slate-800 rounded-xl px-3 py-2 text-xs font-mono text-white"
                          />
                        </div>
                        <div>
                          <label className="block text-xs text-slate-400 mb-1">加固收敛端口</label>
                          <input
                            type="number"
                            value={form.targetSshPort || 2222}
                            onChange={(e) => setForm({ ...form, targetSshPort: Number(e.target.value) || 2222 })}
                            className="w-full bg-slate-900 border border-slate-800 rounded-xl px-3 py-2 text-xs font-mono text-white"
                          />
                        </div>
                        <div>
                          <label className="block text-xs text-slate-400 mb-1">伪装 SNI</label>
                          <input
                            type="text"
                            value={form.sni || ''}
                            onChange={(e) => setForm({ ...form, sni: e.target.value })}
                            placeholder={defaults?.defaultSni || 'swdist.apple.com'}
                            className="w-full bg-slate-900 border border-slate-800 rounded-xl px-3 py-2 text-xs font-mono text-white"
                          />
                        </div>
                      </div>

                      <label className="flex items-center gap-2 text-xs text-emerald-300 cursor-pointer select-none">
                        <input
                          type="checkbox"
                          checked={form.hardenSsh !== false}
                          onChange={(e) => setForm({ ...form, hardenSsh: e.target.checked })}
                          className="rounded border-slate-700 bg-slate-900 text-emerald-500"
                        />
                        <span>自动注入主控免密公钥、验证切换 SSH 端口并禁用密码登录</span>
                      </label>
                    </div>
                  )}
                </>
              ) : (
                /* Existing Node Upsert Mode */
                <>
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                    <div>
                      <label className="block text-xs text-slate-400 mb-1">节点代号 ID (英文/数字，唯一) *</label>
                      <input
                        type="text"
                        required
                        disabled={isEditingExisting}
                        value={form.id || ''}
                        onChange={(e) => setForm({ ...form, id: e.target.value })}
                        placeholder="例如: jp 或 us-lax"
                        className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-xs font-mono text-white focus:outline-none focus:border-emerald-500 disabled:opacity-60"
                      />
                    </div>
                    <div>
                      <label className="block text-xs text-slate-400 mb-1">节点显示名称 *</label>
                      <input
                        type="text"
                        required
                        value={form.name || ''}
                        onChange={(e) => setForm({ ...form, name: e.target.value })}
                        placeholder="例如: 日本东京"
                        className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-xs text-white focus:outline-none focus:border-emerald-500"
                      />
                    </div>
                  </div>

                  <div>
                    <label className="block text-xs text-slate-400 mb-1">SSH 认证方式</label>
                    <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-xs">
                      {(
                        [
                          { k: 'inline_key', label: '粘贴 SSH 私钥' },
                          { k: 'key_file', label: '主控密钥路径' },
                          { k: 'ssh_alias', label: 'SSH Config 别名' },
                          { k: 'password', label: 'SSH 密码' },
                        ] as { k: FleetAuthType; label: string }[]
                      ).map((opt) => (
                        <button
                          key={opt.k}
                          type="button"
                          onClick={() => setForm({ ...form, authType: opt.k })}
                          className={`py-2 px-2 rounded-xl border font-medium transition-colors ${
                            form.authType === opt.k
                              ? 'bg-emerald-500/15 border-emerald-500/40 text-emerald-300'
                              : 'bg-slate-950 border-slate-800 text-slate-400 hover:text-white'
                          }`}
                        >
                          {opt.label}
                        </button>
                      ))}
                    </div>
                  </div>

                  {form.authType === 'ssh_alias' ? (
                    <div>
                      <label className="block text-xs text-slate-400 mb-1">主控 ~/.ssh/config 主机别名 *</label>
                      <input
                        type="text"
                        required
                        value={form.sshAlias || ''}
                        onChange={(e) => setForm({ ...form, sshAlias: e.target.value, host: e.target.value })}
                        placeholder="例如: tokyo-vps"
                        className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-xs font-mono text-white focus:outline-none focus:border-emerald-500"
                      />
                    </div>
                  ) : (
                    <div className="grid grid-cols-1 sm:grid-cols-4 gap-3">
                      <div className="sm:col-span-2">
                        <label className="block text-xs text-slate-400 mb-1">服务器公网 IP 或域名 *</label>
                        <input
                          type="text"
                          required
                          value={form.host}
                          onChange={(e) => setForm({ ...form, host: e.target.value })}
                          placeholder="203.0.113.10"
                          className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-xs font-mono text-white focus:outline-none focus:border-emerald-500"
                        />
                      </div>
                      <div>
                        <label className="block text-xs text-slate-400 mb-1">SSH 端口</label>
                        <input
                          type="number"
                          value={form.port || 2222}
                          onChange={(e) => setForm({ ...form, port: Number(e.target.value) || 2222 })}
                          className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-xs font-mono text-white focus:outline-none focus:border-emerald-500"
                        />
                      </div>
                      <div>
                        <label className="block text-xs text-slate-400 mb-1">SSH 用户</label>
                        <input
                          type="text"
                          value={form.user || 'root'}
                          onChange={(e) => setForm({ ...form, user: e.target.value })}
                          className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-xs font-mono text-white focus:outline-none focus:border-emerald-500"
                        />
                      </div>
                    </div>
                  )}

                  {form.authType === 'inline_key' && (
                    <div>
                      <label className="block text-xs text-slate-400 mb-1">
                        SSH 私钥内容 (PEM) {isEditingExisting ? '（留空则保留原托管私钥）' : '*'}
                      </label>
                      <textarea
                        rows={4}
                        required={!isEditingExisting}
                        value={form.privateKey || ''}
                        onChange={(e) => setForm({ ...form, privateKey: e.target.value })}
                        placeholder="-----BEGIN OPENSSH PRIVATE KEY-----&#10;..."
                        className="w-full bg-slate-950 border border-slate-800 rounded-xl p-3 text-xs font-mono text-emerald-300 focus:outline-none focus:border-emerald-500"
                      />
                    </div>
                  )}

                  {form.authType === 'password' && (
                    <div>
                      <label className="block text-xs text-slate-400 mb-1">
                        SSH 登录密码 {isEditingExisting ? '（留空则保留原密码）' : '*'}
                      </label>
                      <input
                        type="password"
                        required={!isEditingExisting}
                        value={form.password || ''}
                        onChange={(e) => setForm({ ...form, password: e.target.value })}
                        placeholder="输入目标服务器 SSH 密码"
                        className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-xs font-mono text-white focus:outline-none focus:border-emerald-500"
                      />
                    </div>
                  )}

                  {form.authType === 'key_file' && (
                    <div>
                      <label className="block text-xs text-slate-400 mb-1">主控服务器上的私钥路径 *</label>
                      <input
                        type="text"
                        required
                        value={form.keyPath || ''}
                        onChange={(e) => setForm({ ...form, keyPath: e.target.value })}
                        placeholder="/etc/singctl/fleet_keys/master_ed25519"
                        className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-xs font-mono text-white focus:outline-none focus:border-emerald-500"
                      />
                    </div>
                  )}

                  <label className="flex items-center gap-2 text-xs text-slate-300 cursor-pointer select-none pt-1">
                    <input
                      type="checkbox"
                      checked={!!form.autoSync}
                      onChange={(e) => setForm({ ...form, autoSync: e.target.checked })}
                      className="rounded border-slate-700 bg-slate-950 text-emerald-500"
                    />
                    <span>保存后立即通过 SSH 提取该节点 HY2 / Reality 链接并汇入本机总订阅</span>
                  </label>
                </>
              )}
            </div>

            <div className="px-5 sm:px-6 py-4 pb-safe bg-slate-950/80 border-t border-slate-800 flex items-center justify-end gap-2.5 shrink-0">
              <button
                type="button"
                onClick={() => setShowModal(false)}
                disabled={submitting}
                className="px-4 py-2 rounded-xl text-xs text-slate-400 hover:text-white hover:bg-slate-800"
              >
                取消
              </button>
              <button
                type="submit"
                disabled={submitting}
                className={`flex items-center gap-1.5 px-4 py-2.5 rounded-xl font-semibold text-xs transition-colors disabled:opacity-50 ${
                  modalMode === 'bootstrap'
                    ? 'bg-sky-500 hover:bg-sky-600 text-slate-950'
                    : 'bg-emerald-500 hover:bg-emerald-600 text-slate-950'
                }`}
              >
                {submitting && <RefreshCw className="w-3.5 h-3.5 animate-spin" />}
                <span>
                  {submitting
                    ? modalMode === 'bootstrap'
                      ? '正在全自动加固与部署 (约40-90秒)...'
                      : '正在连接并保存...'
                    : modalMode === 'bootstrap'
                    ? '一键开荒并汇入总订阅'
                    : '保存子节点'}
                </span>
              </button>
            </div>
          </form>
        </div>
      )}
    </div>
  );
};

import React, { useEffect, useState } from 'react';
import {
  FleetNode,
  FleetSummary,
  FleetUpsertInput,
  FleetBootstrapInput,
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
  Clock,
} from 'lucide-react';

type ModalMode = 'existing' | 'bootstrap';

const DEFAULT_Summary: FleetSummary = {
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
      return '本机密钥路径';
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
  const [summary, setSummary] = useState<FleetSummary>(DEFAULT_Summary);
  const [loading, setLoading] = useState(true);
  const [runningKey, setRunningKey] = useState<string | null>(null);
  const [actionResults, setActionResults] = useState<FleetActionResult[] | null>(null);
  const [actionBannerTitle, setActionBannerTitle] = useState<string>('');

  // Modal state
  const [showModal, setShowModal] = useState(false);
  const [modalMode, setModalMode] = useState<ModalMode>('existing');
  const [isEditingExisting, setIsEditingExisting] = useState(false);
  const [submitting, setSubmitting] = useState(false);

  const [form, setForm] = useState<FleetBootstrapInput>({
    id: '',
    name: '',
    host: '',
    port: 22,
    user: 'root',
    authType: 'inline_key',
    sshAlias: '',
    keyPath: '~/.ssh/id_ed25519',
    privateKey: '',
    password: '',
    autoSync: true,
    nodeDomain: '',
    substoreDomain: '',
    cfDnsKey: '',
    nodeTag: '',
    sni: 'swdist.apple.com',
    hardenSsh: true,
    targetSshPort: 2222,
    extraAuthorizedKeys: '',
  });

  useEffect(() => {
    loadFleet();
  }, []);

  const loadFleet = async (silent = false) => {
    if (!silent) setLoading(true);
    try {
      const res = await api.getFleet();
      setNodes(res.nodes || []);
      setSummary(res.summary || DEFAULT_Summary);
    } catch (err: any) {
      if (!silent) error(err.message || '加载节点舰队失败');
    } finally {
      if (!silent) setLoading(false);
    }
  };

  const openAddModal = (mode: ModalMode = 'existing') => {
    setIsEditingExisting(false);
    setModalMode(mode);
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
      sni: 'swdist.apple.com',
      hardenSsh: true,
      targetSshPort: 2222,
      extraAuthorizedKeys: '',
    });
    setShowModal(true);
  };

  const openEditModal = (n: FleetNode) => {
    setIsEditingExisting(true);
    setModalMode('existing');
    setForm({
      id: n.id,
      name: n.name,
      host: n.host,
      port: n.port || 22,
      user: n.user || 'root',
      authType: n.authType || 'inline_key',
      sshAlias: n.sshAlias || '',
      keyPath: n.keyPath || '~/.ssh/id_ed25519',
      privateKey: '',
      password: '',
      autoSync: true,
      nodeDomain: '',
      substoreDomain: '',
      cfDnsKey: '',
      nodeTag: '',
      sni: 'www.microsoft.com',
    });
    setShowModal(true);
  };

  const handleSubmitModal = async (e: React.FormEvent) => {
    e.preventDefault();
    setSubmitting(true);
    try {
      if (modalMode === 'bootstrap') {
        const res = await api.bootstrapFleetNode(form);
        success(res.message || '新节点已完成裸机初始化并自动汇入订阅池');
        if (res.result) {
          setActionBannerTitle(`裸机一键部署结果 · ${res.result.name}`);
          setActionResults([res.result]);
        }
      } else {
        const payload: FleetUpsertInput = {
          id: form.id,
          name: form.name,
          host: form.host,
          port: form.port,
          user: form.user,
          authType: form.authType,
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
    action: 'sync' | 'doctor' | 'reset' | 'update',
    ids?: string[],
    label?: string
  ) => {
    if (action === 'reset') {
      const scopeText = ids && ids.length === 1 ? `子节点 [${ids[0]}]` : '全部在线子节点';
      if (
        !window.confirm(
          `确定要对 ${scopeText} 执行「一键换血重置凭据」吗？\n\n该操作将在目标服务器重新生成 UUID、Reality 密钥对与 Hysteria2 密码，并自动将全新节点同步回主控 SubHub 订阅池（客户端只需刷新订阅即可无感恢复，无需换订阅链接）。`
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

  const handleDeleteNode = async (n: FleetNode) => {
    if (
      !window.confirm(
        `确定要从舰队移除「${n.name} (${n.id})」吗？\n\n同时将从本机 SubHub 聚合节点池中清理关联的 fleet_${n.id} 节点（不会卸载远程服务器上的代理服务）。`
      )
    ) {
      return;
    }
    setRunningKey(`del:${n.id}`);
    try {
      const res = await api.deleteFleetNode(n.id);
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
      <div className="p-12 text-center text-slate-400 glass-card rounded-2xl">
        <div className="animate-spin w-6 h-6 border-2 border-emerald-500 border-t-transparent rounded-full mx-auto mb-3"></div>
        <span>正在读取全球节点舰队编排状态...</span>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Top KPI Strip */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="p-4 rounded-2xl glass-card">
          <div className="text-xs text-slate-400">纳管子节点总数</div>
          <div className="text-2xl font-bold font-mono text-white mt-1">{summary.total}</div>
          <div className="text-[11px] text-slate-500 mt-1 font-mono">无 Agent 原生 SSH 编排</div>
        </div>
        <div className="p-4 rounded-2xl glass-card">
          <div className="text-xs text-slate-400">在线健康节点</div>
          <div className="text-2xl font-bold font-mono text-emerald-400 mt-1">
            {summary.online} <span className="text-sm text-slate-500">/ {summary.total}</span>
          </div>
          <div className="text-[11px] text-slate-500 mt-1 font-mono">子节点零常驻内存开销</div>
        </div>
        <div className="p-4 rounded-2xl glass-card">
          <div className="text-xs text-slate-400">全网平均健康分</div>
          <div className="text-2xl font-bold font-mono text-purple-300 mt-1">
            {summary.avgDoctorScore > 0 ? `${summary.avgDoctorScore} / 100` : '--'}
          </div>
          <div className="text-[11px] text-slate-500 mt-1 font-mono">并发全链路 Doctor 评分</div>
        </div>
        <div className="p-4 rounded-2xl glass-card">
          <div className="text-xs text-slate-400">已自动汇入 SubHub 节点</div>
          <div className="text-2xl font-bold font-mono text-sky-300 mt-1">{summary.totalSyncedEndpoints}</div>
          <div className="text-[11px] text-slate-500 mt-1 font-mono">一条主控订阅链接统管全球</div>
        </div>
      </div>

      {/* Fleet Command Toolbar */}
      <div className="p-5 rounded-2xl glass-card flex flex-col lg:flex-row lg:items-center justify-between gap-4">
        <div>
          <h2 className="text-lg font-semibold text-white tracking-tight flex items-center gap-2">
            <Network className="w-5 h-5 text-emerald-400" />
            <span>全球多节点舰队中枢 (Agentless Fleet)</span>
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            主控通过加密 SSH 按需并发连接各台子节点，自动提取 HY2 / VLESS Reality 链接并实时汇入本机 SubHub 全平台订阅池
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <button
            onClick={() => openAddModal('existing')}
            className="flex items-center gap-1.5 px-3.5 py-2 rounded-xl bg-emerald-500 hover:bg-emerald-600 text-slate-950 font-semibold text-xs transition-colors"
          >
            <Plus className="w-3.5 h-3.5" />
            <span>纳管已有节点</span>
          </button>
          <button
            onClick={() => openAddModal('bootstrap')}
            className="flex items-center gap-1.5 px-3.5 py-2 rounded-xl bg-sky-500/15 hover:bg-sky-500/25 border border-sky-500/30 text-sky-200 font-semibold text-xs transition-colors"
          >
            <Rocket className="w-3.5 h-3.5 text-sky-400" />
            <span>裸机 60s 部署纳管</span>
          </button>

          {nodes.length > 0 && (
            <>
              <button
                onClick={() => handleRunAction('sync', undefined, '全网节点同步报告')}
                disabled={!!runningKey}
                className="flex items-center gap-1.5 px-3 py-2 rounded-xl bg-slate-900 hover:bg-slate-800 border border-slate-700/70 text-xs text-slate-200 transition-colors disabled:opacity-50"
              >
                <RefreshCw className={`w-3.5 h-3.5 ${runningKey === 'sync:all' ? 'animate-spin text-emerald-400' : ''}`} />
                <span>全网同步订阅</span>
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
                <span>全网升级</span>
              </button>
            </>
          )}
        </div>
      </div>

      {/* Execution Output Drawer */}
      {actionResults && actionResults.length > 0 && (
        <div className="p-5 rounded-2xl glass-card border border-emerald-500/25 space-y-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2 text-xs font-semibold text-white">
              <Terminal className="w-4 h-4 text-emerald-400" />
              <span>{actionBannerTitle || '舰队指令执行结果'}</span>
            </div>
            <button
              onClick={() => setActionResults(null)}
              className="p-1 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
          <div className="space-y-2 max-h-64 overflow-y-auto pr-1">
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
                      <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                    ) : (
                      <XCircle className="w-3.5 h-3.5 text-rose-400" />
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
                <p className="mt-1 text-[11px] text-slate-300">{r.message}</p>
                {r.output && (
                  <pre className="mt-2 p-2.5 rounded-lg bg-slate-950/80 border border-slate-800/80 text-[11px] text-slate-400 whitespace-pre-wrap break-all max-h-36 overflow-y-auto">
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
        <div className="p-10 rounded-2xl glass-card text-center space-y-4">
          <div className="w-12 h-12 rounded-2xl bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center text-emerald-400 mx-auto">
            <Server className="w-6 h-6" />
          </div>
          <div className="max-w-lg mx-auto space-y-1.5">
            <h3 className="text-base font-semibold text-white">尚未纳管任何远程子节点</h3>
            <p className="text-xs text-slate-400 leading-relaxed">
              你可以将已部署 SingCtl 的多地区 VPS（如日本、美国、欧洲）纳入舰队统一体检与换血，也可以输入一台全新裸机 VPS 的 IP 与 Cloudflare Token，60 秒全自动装好 BBR + Caddy + Sing-Box 并汇入当前主控订阅链接。
            </p>
          </div>
          <div className="flex flex-wrap items-center justify-center gap-3 pt-1">
            <button
              onClick={() => openAddModal('existing')}
              className="flex items-center gap-1.5 px-4 py-2 rounded-xl bg-emerald-500 hover:bg-emerald-600 text-slate-950 font-semibold text-xs transition-colors"
            >
              <Plus className="w-4 h-4" />
              <span>纳管已有 SingCtl 节点</span>
            </button>
            <button
              onClick={() => openAddModal('bootstrap')}
              className="flex items-center gap-1.5 px-4 py-2 rounded-xl bg-sky-500/15 hover:bg-sky-500/25 border border-sky-500/30 text-sky-200 font-semibold text-xs transition-colors"
            >
              <Rocket className="w-4 h-4 text-sky-400" />
              <span>裸机 60s 一键部署纳管</span>
            </button>
          </div>
          <p className="text-[11px] text-slate-500 font-mono">
            本地电脑终端同样支持: <code className="text-emerald-300">singctl fleet add tokyo --alias my-vps --sync</code>
          </p>
        </div>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          {nodes.map((n) => {
            const isSyncing = runningKey === `sync:${n.id}`;
            const isDoctoring = runningKey === `doctor:${n.id}`;
            const isResetting = runningKey === `reset:${n.id}`;
            const isUpdating = runningKey === `update:${n.id}`;
            return (
              <div key={n.id} className="p-5 rounded-2xl glass-card flex flex-col justify-between gap-4">
                <div className="space-y-3">
                  <div className="flex items-start justify-between gap-2">
                    <div>
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="text-base font-bold text-white">{n.name}</span>
                        <span className="px-2 py-0.5 rounded-md text-[10px] font-mono bg-slate-800 text-slate-300">
                          #{n.id}
                        </span>
                        <span className="px-2 py-0.5 rounded-md text-[10px] font-mono bg-slate-900 border border-slate-700/80 text-slate-400">
                          {authTypeLabel(n.authType)}
                        </span>
                      </div>
                      <div className="text-xs font-mono text-slate-400 mt-1">
                        {n.authType === 'ssh_alias'
                          ? `SSH Alias: ${n.sshAlias || n.host}`
                          : `${n.user}@${n.host}:${n.port || 22}`}
                      </div>
                    </div>

                    <div className="flex items-center gap-1.5 shrink-0">
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
                            <span>待同步/离线</span>
                          </>
                        )}
                      </span>
                    </div>
                  </div>

                  {/* Runtime Metrics Box */}
                  <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 p-3 rounded-xl bg-slate-950/60 border border-slate-800/80 text-xs font-mono">
                    <div>
                      <div className="text-[10px] text-slate-500">已同步节点</div>
                      <div className="text-emerald-300 font-semibold mt-0.5">
                        {n.syncedNodes} 个 {n.protocols && n.protocols.length > 0 ? `(${n.protocols.join('/')})` : ''}
                      </div>
                    </div>
                    <div>
                      <div className="text-[10px] text-slate-500">SingCtl 版本</div>
                      <div className="text-slate-200 mt-0.5">{n.singctlVersion || '--'}</div>
                    </div>
                    <div>
                      <div className="text-[10px] text-slate-500">CPU / 内存</div>
                      <div className="text-slate-200 mt-0.5">
                        {n.cpuLoad || '--'} / {n.memPercent > 0 ? `${n.memPercent.toFixed(0)}%` : '--'}
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
                    <div className="px-3 py-2 rounded-xl bg-rose-950/30 border border-rose-500/30 text-[11px] font-mono text-rose-300">
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
                      className="p-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-800 text-slate-400 hover:text-white transition-colors"
                      title="编辑连接信息"
                    >
                      <Edit3 className="w-3.5 h-3.5" />
                    </button>
                    <button
                      onClick={() => handleDeleteNode(n)}
                      className="p-1.5 rounded-lg bg-rose-500/10 hover:bg-rose-500/20 border border-rose-500/20 text-rose-300 transition-colors"
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

      {/* Add / Edit / Bootstrap Modal */}
      {showModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/85 backdrop-blur-md">
          <form
            onSubmit={handleSubmitModal}
            className="bg-slate-900 border border-slate-800 rounded-3xl w-full max-w-2xl max-h-[90vh] flex flex-col overflow-hidden shadow-2xl"
          >
            <div className="flex items-center justify-between px-6 py-4 border-b border-slate-800">
              <div>
                <h4 className="text-base font-bold text-white flex items-center gap-2">
                  {modalMode === 'bootstrap' ? (
                    <>
                      <Rocket className="w-4 h-4 text-sky-400" />
                      <span>裸机 60s 一键全自动部署并纳管</span>
                    </>
                  ) : (
                    <>
                      <ShieldCheck className="w-4 h-4 text-emerald-400" />
                      <span>{isEditingExisting ? `编辑舰队子节点 #${form.id}` : '纳管已有 SingCtl 子节点'}</span>
                    </>
                  )}
                </h4>
                <p className="text-xs text-slate-400 mt-0.5">
                  凭据以 0600 权限加密存放在主控 <code className="text-slate-300">/etc/singctl/</code>，绝不在接口响应中回显明文
                </p>
              </div>
              <button
                type="button"
                onClick={() => setShowModal(false)}
                className="p-1.5 rounded-xl hover:bg-slate-800 text-slate-400 hover:text-white"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="p-6 overflow-y-auto space-y-4">
              {!isEditingExisting && (
                <div className="grid grid-cols-2 gap-2 p-1 rounded-xl bg-slate-950 border border-slate-800 text-xs">
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
                    纳管已安装 SingCtl 的节点
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      setModalMode('bootstrap');
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
                    裸机 VPS 60s 全自动开荒部署
                  </button>
                </div>
              )}

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs text-slate-400 mb-1">节点代号 ID (英文/数字，唯一) *</label>
                  <input
                    type="text"
                    required
                    disabled={isEditingExisting}
                    value={form.id}
                    onChange={(e) => setForm({ ...form, id: e.target.value })}
                    placeholder="例如: tokyo-01 或 us-lax"
                    className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-xs font-mono text-white focus:outline-none focus:border-emerald-500 disabled:opacity-60"
                  />
                </div>
                <div>
                  <label className="block text-xs text-slate-400 mb-1">节点显示名称 *</label>
                  <input
                    type="text"
                    required
                    value={form.name}
                    onChange={(e) => setForm({ ...form, name: e.target.value })}
                    placeholder="例如: 东京 IIJ 高速节点"
                    className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-xs text-white focus:outline-none focus:border-emerald-500"
                  />
                </div>
              </div>

              {/* Auth Mode Selector */}
              <div>
                <label className="block text-xs text-slate-400 mb-1">SSH 认证方式</label>
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-xs">
                  {(
                    [
                      { k: 'inline_key', label: '粘贴 SSH 私钥' },
                      { k: 'password', label: 'SSH 密码' },
                      { k: 'key_file', label: '服务器密钥路径' },
                      { k: 'ssh_alias', label: 'SSH Config 别名' },
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
                      placeholder="例如: 203.0.113.10"
                      className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-xs font-mono text-white focus:outline-none focus:border-emerald-500"
                    />
                  </div>
                  <div>
                    <label className="block text-xs text-slate-400 mb-1">SSH 端口</label>
                    <input
                      type="number"
                      value={form.port || 22}
                      onChange={(e) => setForm({ ...form, port: Number(e.target.value) || 22 })}
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
                    placeholder="~/.ssh/id_ed25519"
                    className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-xs font-mono text-white focus:outline-none focus:border-emerald-500"
                  />
                </div>
              )}

              {modalMode === 'bootstrap' ? (
                <div className="p-4 rounded-2xl bg-sky-950/20 border border-sky-500/25 space-y-3">
                  <div className="text-xs font-semibold text-sky-300">
                    裸机自动建站与 SSH 安全加固参数（需要该域名托管在 Cloudflare）
                  </div>
                  {form.authType !== 'ssh_alias' && (
                    <div className="p-3 rounded-xl bg-slate-950/70 border border-slate-800 space-y-2.5">
                      <label className="flex items-center justify-between gap-2 text-xs text-emerald-300 cursor-pointer select-none">
                        <span className="flex items-center gap-2 font-medium">
                          <input
                            type="checkbox"
                            checked={form.hardenSsh !== false}
                            onChange={(e) => setForm({ ...form, hardenSsh: e.target.checked })}
                            className="rounded border-slate-700 bg-slate-950 text-emerald-500 focus:ring-emerald-500"
                          />
                          <span>自动完成 SSH 免密注入（含本机公钥）、安全切换端口并禁用密码登录</span>
                        </span>
                        {form.hardenSsh !== false && (
                          <span className="flex items-center gap-1.5 text-slate-400">
                            <span>收敛端口:</span>
                            <input
                              type="number"
                              value={form.targetSshPort || 2222}
                              onChange={(e) => setForm({ ...form, targetSshPort: Number(e.target.value) || 2222 })}
                              className="w-20 bg-slate-900 border border-slate-700 rounded-lg px-2 py-1 text-xs font-mono text-white"
                            />
                          </span>
                        )}
                      </label>
                    </div>
                  )}
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                    <div>
                      <label className="block text-xs text-slate-400 mb-1">子节点已解析域名 *</label>
                      <input
                        type="text"
                        required
                        value={form.nodeDomain}
                        onChange={(e) => setForm({ ...form, nodeDomain: e.target.value })}
                        placeholder="例如: jp1.example.com"
                        className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-xs font-mono text-white focus:outline-none focus:border-sky-500"
                      />
                    </div>
                    <div>
                      <label className="block text-xs text-slate-400 mb-1">节点标签后缀 (Node Tag)</label>
                      <input
                        type="text"
                        value={form.nodeTag || ''}
                        onChange={(e) => setForm({ ...form, nodeTag: e.target.value })}
                        placeholder="默认使用节点显示名称"
                        className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-xs text-white focus:outline-none focus:border-sky-500"
                      />
                    </div>
                  </div>
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                    <div>
                      <label className="block text-xs text-slate-400 mb-1">Cloudflare DNS API Token *</label>
                      <input
                        type="password"
                        required
                        value={form.cfDnsKey}
                        onChange={(e) => setForm({ ...form, cfDnsKey: e.target.value })}
                        placeholder="具备 Zone.DNS 编辑权限的 Token"
                        className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-xs font-mono text-white focus:outline-none focus:border-sky-500"
                      />
                    </div>
                    <div>
                      <label className="block text-xs text-slate-400 mb-1">Reality 偷取伪装 SNI</label>
                      <input
                        type="text"
                        value={form.sni || ''}
                        onChange={(e) => setForm({ ...form, sni: e.target.value })}
                        placeholder="www.microsoft.com"
                        className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-xs font-mono text-white focus:outline-none focus:border-sky-500"
                      />
                    </div>
                  </div>
                </div>
              ) : (
                <label className="flex items-center gap-2 text-xs text-slate-300 cursor-pointer select-none pt-1">
                  <input
                    type="checkbox"
                    checked={!!form.autoSync}
                    onChange={(e) => setForm({ ...form, autoSync: e.target.checked })}
                    className="rounded border-slate-700 bg-slate-950 text-emerald-500 focus:ring-emerald-500"
                  />
                  <span>保存后立即通过 SSH 提取该节点 HY2 / Reality 链接并汇入本机 SubHub 订阅池</span>
                </label>
              )}
            </div>

            <div className="px-6 py-4 bg-slate-950/60 border-t border-slate-800 flex items-center justify-end gap-2.5">
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
                className={`flex items-center gap-1.5 px-4 py-2 rounded-xl font-semibold text-xs transition-colors disabled:opacity-50 ${
                  modalMode === 'bootstrap'
                    ? 'bg-sky-500 hover:bg-sky-600 text-slate-950'
                    : 'bg-emerald-500 hover:bg-emerald-600 text-slate-950'
                }`}
              >
                {submitting && <RefreshCw className="w-3.5 h-3.5 animate-spin" />}
                <span>
                  {submitting
                    ? modalMode === 'bootstrap'
                      ? '正在全自动部署新节点 (约30-90秒)...'
                      : '正在连接并保存...'
                    : modalMode === 'bootstrap'
                    ? '开始裸机一键部署并汇入订阅'
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

import React, { useEffect, useRef, useState } from 'react';
import {
  FleetNode,
  FleetSummary,
  FleetUpsertInput,
  FleetBootstrapInput,
  FleetBootstrapDefaults,
  FleetBootstrapPlan,
  FleetActionResult,
} from '../types';
import { api } from '../api';
import { FLEET_CACHE_KEY, FLEET_DEFAULTS_CACHE_KEY } from '../prefetch';
import { peekCachedQuery, useVisibilityInterval, writeCachedQuery } from '../../hooks';
import { useToast } from '../../ui';
import {
  CachedFleetList,
  createInitialFleetForm,
  DEFAULT_SUMMARY,
  FLEET_PROBE_COOLDOWN_MS,
  ModalMode,
} from './fleet/helpers';
import { FleetToolbarAndDrawer } from './fleet/FleetToolbarAndDrawer';
import { FleetNodesGrid } from './fleet/FleetNodesGrid';
import { FleetUpsertModal } from './fleet/FleetUpsertModal';

export const FleetTab: React.FC<{ active?: boolean }> = ({ active = true }) => {
  const { success, error } = useToast();
  const cachedFleet = peekCachedQuery<CachedFleetList>(FLEET_CACHE_KEY);
  const [nodes, setNodes] = useState<FleetNode[]>(() => cachedFleet?.nodes || []);
  const [summary, setSummary] = useState<FleetSummary>(() => cachedFleet?.summary || DEFAULT_SUMMARY);
  const [defaults, setDefaults] = useState<FleetBootstrapDefaults | null>(
    () => peekCachedQuery<FleetBootstrapDefaults>(FLEET_DEFAULTS_CACHE_KEY) ?? null,
  );
  const [loading, setLoading] = useState(() => !cachedFleet);
  const lastProbeAtRef = useRef<number>(0);
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

  const [form, setForm] = useState<FleetBootstrapInput>(() => createInitialFleetForm('bootstrap', 2222));

  const triggerSilentProbe = async (force = false) => {
    const now = Date.now();
    if (!force && now - lastProbeAtRef.current < FLEET_PROBE_COOLDOWN_MS) {
      return;
    }
    lastProbeAtRef.current = now;
    try {
      const res = await api.probeFleet();
      if (res && Array.isArray(res.nodes)) {
        const nextSummary = res.summary || DEFAULT_SUMMARY;
        setNodes(res.nodes);
        setSummary(nextSummary);
        writeCachedQuery(FLEET_CACHE_KEY, { nodes: res.nodes, summary: nextSummary });
      }
    } catch {
      // ignore silent patrol error
    }
  };

  const loadFleet = async (silent = false) => {
    if (!silent && !peekCachedQuery(FLEET_CACHE_KEY)) setLoading(true);
    try {
      const res = await api.getFleet();
      const nextNodes = res.nodes || [];
      const nextSummary = res.summary || DEFAULT_SUMMARY;
      setNodes(nextNodes);
      setSummary(nextSummary);
      writeCachedQuery(FLEET_CACHE_KEY, { nodes: nextNodes, summary: nextSummary });
    } catch (err: any) {
      if (!silent) error(err.message || '加载节点舰队失败');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (!active) return;
    const hasCache = Boolean(peekCachedQuery(FLEET_CACHE_KEY));
    void loadFleet(hasCache).then(() => {
      void triggerSilentProbe(false);
    });
    if (!peekCachedQuery(FLEET_DEFAULTS_CACHE_KEY)) {
      api
        .getFleetDefaults()
        .then((d) => {
          setDefaults(d);
          writeCachedQuery(FLEET_DEFAULTS_CACHE_KEY, d);
        })
        .catch(() => {});
    }
  }, [active]);

  useVisibilityInterval(
    () => {
      void triggerSilentProbe(false);
    },
    active ? 60_000 : null,
    { refreshOnVisible: false },
  );

  const openAddModal = (mode: ModalMode = 'bootstrap') => {
    setIsEditingExisting(false);
    setModalMode(mode);
    setShowAdvancedBootstrap(false);
    setPreviewPlan(null);
    setForm(createInitialFleetForm(mode, defaults?.defaultTargetSshPort || 2222));
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
    label?: string,
  ) => {
    if (action === 'reset') {
      const scopeText = ids && ids.length === 1 ? `子节点 [${ids[0]}]` : '全部在线子节点';
      if (
        !window.confirm(
          `确定要对 ${scopeText} 执行「一键换血重置凭据」吗？\n\n该操作将在目标服务器重新生成 UUID、Reality 密钥对与 Hysteria2 密码，并自动将全新节点同步回主控 SubHub 订阅池（客户端刷新订阅即可无感恢复）。`,
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
        '确定对全舰队执行「三层安全漏洞自愈」吗？\n\n• 第一层：金丝雀校验升级核心组件（失败秒级回滚）\n• 第二层：安装系统安全仓库补丁并热重载残留 .so 动态库\n• 第三层：如有新内核待生效，将按【单台串行滚动重启 + 异常熔断】方式执行，保障全网永不断流。',
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
            : `🛡️ 全舰队三层安全自愈报告（健康 ${res.fleetReport.healthyNodes}/${res.fleetReport.totalNodes}）`,
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
          })),
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
        `确定要从舰队移除「${n.name} (${n.id})」吗？\n\n• 自动从本机 SubHub 总订阅清理关联节点 (fleet_${n.id})${dnsHint}\n• 不会卸载远端服务器已有服务`,
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
      <FleetToolbarAndDrawer
        summary={summary}
        hasNodes={nodes.length > 0}
        runningKey={runningKey}
        actionResults={actionResults}
        actionBannerTitle={actionBannerTitle}
        onClearResults={() => setActionResults(null)}
        onOpenAddModal={openAddModal}
        onFleetHeal={handleFleetHeal}
        onRunAction={handleRunAction}
      />

      <FleetNodesGrid
        nodes={nodes}
        runningKey={runningKey}
        onOpenAddModal={openAddModal}
        onOpenEditModal={openEditModal}
        onDeleteNode={handleDeleteNode}
        onRunAction={handleRunAction}
      />

      {showModal && (
        <FleetUpsertModal
          modalMode={modalMode}
          setModalMode={setModalMode}
          isEditingExisting={isEditingExisting}
          submitting={submitting}
          form={form}
          setForm={setForm}
          defaults={defaults}
          previewPlan={previewPlan}
          setPreviewPlan={setPreviewPlan}
          previewLoading={previewLoading}
          showAdvancedBootstrap={showAdvancedBootstrap}
          setShowAdvancedBootstrap={setShowAdvancedBootstrap}
          onPreviewBootstrap={handlePreviewBootstrap}
          onSubmit={handleSubmitModal}
          onClose={() => setShowModal(false)}
        />
      )}
    </div>
  );
};

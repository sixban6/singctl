import React, { useEffect, useState, useRef } from 'react';
import {
  SubscriptionsResponse,
  SubscriptionSourceItem,
  SourceUpsertInput,
  SubscriptionPreviewResponse,
} from '../types';
import { api } from '../api';
import { useToast } from './Toast';
import {
  Copy,
  QrCode,
  Check,
  Download,
  Sparkles,
  X,
  RefreshCw,
  Info,
  Plus,
  Trash2,
  Edit3,
  KeyRound,
  FileCode2,
  Globe,
  Server,
  Layers,
} from 'lucide-react';
import QRCode from 'qrcode';

const PREVIEW_TARGETS = [
  { key: 'ClashMeta', label: 'Clash.Meta / Mihomo' },
  { key: 'Sing-Box', label: 'Sing-box v1.14' },
  { key: 'Shadowrocket', label: 'Base64 通用订阅' },
  { key: 'Surge', label: 'Surge' },
  { key: 'Loon', label: 'Loon' },
  { key: 'plain', label: '明文 URI 列表' },
];

export const SubscriptionsTab: React.FC = () => {
  const { success, error } = useToast();
  const [data, setData] = useState<SubscriptionsResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const [qrModalURL, setQrModalURL] = useState<string | null>(null);
  const qrCanvasRef = useRef<HTMLCanvasElement | null>(null);

  // Source CRUD modal state
  const [editingSource, setEditingSource] = useState<SourceUpsertInput | null>(null);
  const [isAutoManagedEdit, setIsAutoManagedEdit] = useState(false);
  const [savingSource, setSavingSource] = useState(false);
  const [rotatingKey, setRotatingKey] = useState(false);

  // Live conversion preview modal state
  const [showPreviewModal, setShowPreviewModal] = useState(false);
  const [previewTarget, setPreviewTarget] = useState('ClashMeta');
  const [previewData, setPreviewData] = useState<SubscriptionPreviewResponse | null>(null);
  const [loadingPreview, setLoadingPreview] = useState(false);

  useEffect(() => {
    loadData();
  }, []);

  const loadData = async () => {
    setLoading(true);
    try {
      const res = await api.getSubscriptions();
      setData(res);
    } catch (err: any) {
      error(err.message || '获取订阅信息失败');
    } finally {
      setLoading(false);
    }
  };

  const copyText = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    success('已复制到剪贴板');
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const showQRCode = (url: string) => {
    setQrModalURL(url);
  };

  useEffect(() => {
    if (qrModalURL && qrCanvasRef.current) {
      QRCode.toCanvas(qrCanvasRef.current, qrModalURL, {
        width: 256,
        margin: 2,
        color: {
          dark: '#0f172a',
          light: '#ffffff',
        },
      });
    }
  }, [qrModalURL]);

  const openAddSourceModal = () => {
    setIsAutoManagedEdit(false);
    setEditingSource({
      displayName: '',
      source: 'local',
      url: '',
      content: '',
      remark: '',
      enabled: true,
    });
  };

  const openEditSourceModal = (item: SubscriptionSourceItem) => {
    setIsAutoManagedEdit(item.autoManaged);
    setEditingSource({
      name: item.name,
      displayName: item.displayName,
      source: item.source,
      url: item.url,
      content: item.content,
      remark: item.remark,
      enabled: item.enabled,
    });
  };

  const handleSaveSource = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!editingSource) return;
    setSavingSource(true);
    try {
      const res = await api.upsertSubSource(editingSource);
      success(res.message || '订阅源已保存');
      setEditingSource(null);
      await loadData();
    } catch (err: any) {
      error(err.message || '保存订阅源失败');
    } finally {
      setSavingSource(false);
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
        enabled: !item.enabled,
      });
      success(item.enabled ? `已停用订阅源「${item.displayName}」` : `已启用订阅源「${item.displayName}」`);
      await loadData();
    } catch (err: any) {
      error(err.message || '更新状态失败');
    }
  };

  const handleDeleteSource = async (item: SubscriptionSourceItem) => {
    if (!window.confirm(`确定要从聚合节点池中移除「${item.displayName}」吗？`)) return;
    try {
      const res = await api.deleteSubSource(item.name);
      success(res.message || '已删除订阅源');
      await loadData();
    } catch (err: any) {
      error(err.message || '删除订阅源失败');
    }
  };

  const handleRotateKey = async () => {
    if (
      !window.confirm(
        '确定要轮换订阅访问密钥吗？\n\n轮换后，旧订阅链接将立即失效，所有手机/电脑客户端需重新复制或扫码导入新订阅地址。'
      )
    ) {
      return;
    }
    setRotatingKey(true);
    try {
      const res = await api.rotateSubKey();
      success(res.message || '订阅密钥已轮换');
      await loadData();
    } catch (err: any) {
      error(err.message || '轮换订阅密钥失败');
    } finally {
      setRotatingKey(false);
    }
  };

  const fetchPreview = async (target: string) => {
    setPreviewTarget(target);
    setShowPreviewModal(true);
    setLoadingPreview(true);
    try {
      const res = await api.previewSubscription(target);
      setPreviewData(res);
    } catch (err: any) {
      error(err.message || '生成预览失败');
    } finally {
      setLoadingPreview(false);
    }
  };

  const handleDownloadPreview = () => {
    if (!previewData) return;
    const blob = new Blob([previewData.content], { type: previewData.contentType || 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = previewData.filename || `subhub-${previewData.target}.txt`;
    a.click();
    URL.revokeObjectURL(url);
    success(`已下载 ${previewData.filename}`);
  };

  if (loading && !data) {
    return (
      <div className="p-12 text-center text-slate-400 glass-card rounded-2xl">
        <div className="animate-spin w-6 h-6 border-2 border-emerald-500 border-t-transparent rounded-full mx-auto mb-3"></div>
        <span>正在读取节点与订阅配置...</span>
      </div>
    );
  }

  const clients = [
    {
      name: 'Shadowrocket',
      desc: 'iOS 跨协议网络客户端',
      icon: '🚀',
      scheme: data?.importLinks?.shadowrocket,
    },
    {
      name: 'Clash Verge / Mihomo',
      desc: '跨平台 Clash.Meta 内核客户端',
      icon: '⚡',
      scheme: data?.importLinks?.clash,
    },
    {
      name: 'Sing-box 官方客户端',
      desc: 'iOS SFI / Android SFA / 桌面端 v1.14',
      icon: '📦',
      scheme: data?.importLinks?.singbox,
    },
    {
      name: 'Surge',
      desc: '高级网络分析与托管配置客户端',
      icon: '🌊',
      scheme: data?.importLinks?.surge,
    },
    {
      name: 'Loon',
      desc: '支持 VLESS Reality 与 Hysteria2',
      icon: '🎈',
      scheme: data?.importLinks?.loon,
    },
  ];

  const sources = data?.sources || [];
  const totalNodes = sources.reduce((acc, s) => (s.enabled ? acc + (s.nodeCount || 0) : acc), 0);

  return (
    <div className="space-y-6">
      {/* Top Card: Unified Subscription */}
      <div className="p-6 rounded-2xl glass-card relative overflow-hidden">
        <div className="absolute top-0 right-0 w-64 h-64 bg-emerald-500/10 rounded-full blur-3xl pointer-events-none"></div>

        <div className="flex flex-wrap items-center justify-between gap-2 mb-2">
          <div className="flex items-center gap-2 text-emerald-400 text-xs font-semibold uppercase tracking-wider">
            <Sparkles className="w-3.5 h-3.5" />
            <span>Go 原生聚合分发中枢 (SubHub · 零容器依赖)</span>
          </div>
          <span className="px-2.5 py-0.5 rounded-full text-[11px] font-mono bg-emerald-500/10 text-emerald-300 border border-emerald-500/20">
            已聚合 {totalNodes} 个可用节点
          </span>
        </div>

        <h2 className="text-xl font-bold text-white tracking-tight">统一全平台订阅链接</h2>
        <p className="text-xs text-slate-400 mt-1 max-w-2xl">
          由 SingCtl 内置 Go 引擎实时聚合本机 Reality / Hysteria2 节点与自定义外部订阅源，支持根据客户端类型自动下发对应格式配置
        </p>

        {/* URL Bar */}
        <div className="mt-5 p-3 rounded-xl bg-slate-950/70 border border-slate-800 flex flex-col lg:flex-row items-stretch lg:items-center justify-between gap-3 font-mono text-xs text-slate-300">
          <span className="truncate select-all">{data?.subscriptionUrl || '订阅地址生成中...'}</span>
          <div className="flex flex-wrap items-center gap-2 shrink-0">
            <button
              onClick={() => copyText(data?.subscriptionUrl || '', 'sub-url')}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-emerald-500 hover:bg-emerald-600 text-slate-950 font-semibold text-xs transition-colors"
            >
              {copiedKey === 'sub-url' ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
              <span>{copiedKey === 'sub-url' ? '已复制' : '复制订阅'}</span>
            </button>
            <button
              onClick={() => showQRCode(data?.subscriptionUrl || '')}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs transition-colors"
            >
              <QrCode className="w-3.5 h-3.5" />
              <span>二维码</span>
            </button>
            <button
              onClick={() => fetchPreview('ClashMeta')}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-purple-500/20 hover:bg-purple-500/30 border border-purple-500/30 text-purple-200 text-xs font-semibold transition-colors"
              title="在线预览 Clash.Meta、Sing-box、Surge、Loon 等目标转换结果"
            >
              <FileCode2 className="w-3.5 h-3.5 text-purple-400" />
              <span>预览转换配置</span>
            </button>
            <button
              onClick={handleRotateKey}
              disabled={rotatingKey}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-amber-500/10 hover:bg-amber-500/20 border border-amber-500/30 text-amber-300 text-xs font-medium transition-colors disabled:opacity-50"
              title="重置随机订阅路径密钥，使泄露的旧订阅链接立即失效"
            >
              <KeyRound className={`w-3.5 h-3.5 ${rotatingKey ? 'animate-spin' : ''}`} />
              <span>轮换密钥</span>
            </button>
            <button
              onClick={loadData}
              title="刷新订阅状态"
              className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-white transition-colors"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            </button>
          </div>
        </div>

        {/* Sync Hint Banner */}
        <div className="mt-3.5 flex items-center gap-2 text-xs text-slate-400 bg-emerald-950/20 border border-emerald-500/20 rounded-xl px-3.5 py-2">
          <Info className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
          <span>
            支持通过 URL 参数强制指定输出格式：<code className="text-emerald-300">?target=ClashMeta</code>、
            <code className="text-emerald-300">?target=Sing-Box</code>、<code className="text-emerald-300">?target=Surge</code>、
            <code className="text-emerald-300">?target=Loon</code> 或按客户端 User-Agent 自动识别。
          </span>
        </div>
      </div>

      {/* Multi-Source Aggregation Pool Manager */}
      <div className="p-5 rounded-2xl glass-card space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-slate-800">
          <div>
            <h3 className="text-sm font-semibold text-white flex items-center gap-2">
              <Layers className="w-4 h-4 text-emerald-400" />
              <span>多源聚合节点池 (Aggregated Sources)</span>
            </h3>
            <p className="text-xs text-slate-400 mt-0.5">
              除本机自动同步节点外，可添加其他自建 VPS 节点链接或第三方远程订阅链接统一合并下发
            </p>
          </div>
          <button
            onClick={openAddSourceModal}
            className="flex items-center justify-center gap-1.5 px-3.5 py-2 rounded-xl bg-emerald-500/15 hover:bg-emerald-500/25 border border-emerald-500/30 text-emerald-300 text-xs font-semibold transition-colors shrink-0"
          >
            <Plus className="w-3.5 h-3.5" />
            <span>添加节点源 / 外部订阅</span>
          </button>
        </div>

        {sources.length === 0 ? (
          <div className="p-6 text-center text-xs text-slate-500 bg-slate-950/40 rounded-xl border border-slate-800/70">
            当前暂无订阅源记录，点击右上角「添加节点源」或执行 <code className="text-slate-300">singctl sr sync</code> 同步本机节点
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {sources.map((item) => (
              <div
                key={item.name}
                className={`p-4 rounded-xl border transition-all flex flex-col justify-between gap-3 ${
                  item.enabled
                    ? 'bg-slate-950/60 border-slate-800'
                    : 'bg-slate-950/30 border-slate-800/50 opacity-65'
                }`}
              >
                <div className="flex items-start justify-between gap-2">
                  <div className="min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="font-semibold text-sm text-white truncate">{item.displayName}</span>
                      {item.autoManaged ? (
                        <span className="px-2 py-0.5 rounded-md text-[10px] font-mono bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                          本机自动同步
                        </span>
                      ) : item.source === 'remote' ? (
                        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md text-[10px] font-mono bg-blue-500/10 text-blue-400 border border-blue-500/20">
                          <Globe className="w-2.5 h-2.5" />
                          远程订阅
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md text-[10px] font-mono bg-purple-500/10 text-purple-300 border border-purple-500/20">
                          <Server className="w-2.5 h-2.5" />
                          自定义节点
                        </span>
                      )}
                      <span className="px-2 py-0.5 rounded-md text-[10px] font-mono bg-slate-800 text-slate-300">
                        {item.nodeCount} 节点
                      </span>
                    </div>
                    <p className="text-[11px] text-slate-500 font-mono mt-1 truncate">
                      {item.source === 'remote' ? item.url : item.remark || `标识: ${item.name}`}
                    </p>
                  </div>

                  <button
                    type="button"
                    onClick={() => handleToggleSourceEnabled(item)}
                    className={`px-2.5 py-1 rounded-lg text-[11px] font-mono border shrink-0 transition-colors ${
                      item.enabled
                        ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30 hover:bg-emerald-500/20'
                        : 'bg-slate-900 text-slate-400 border-slate-700 hover:text-white'
                    }`}
                  >
                    {item.enabled ? '已启用' : '已停用'}
                  </button>
                </div>

                <div className="pt-2.5 border-t border-slate-800/70 flex items-center justify-between text-xs">
                  <span className="text-[11px] text-slate-500 font-mono truncate">{item.name}</span>
                  <div className="flex items-center gap-1.5">
                    <button
                      type="button"
                      onClick={() => openEditSourceModal(item)}
                      className="flex items-center gap-1 px-2.5 py-1 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-800 text-slate-300 hover:text-white transition-colors"
                    >
                      <Edit3 className="w-3 h-3" />
                      <span>编辑</span>
                    </button>
                    {!item.autoManaged && (
                      <button
                        type="button"
                        onClick={() => handleDeleteSource(item)}
                        className="flex items-center gap-1 px-2.5 py-1 rounded-lg bg-rose-500/10 hover:bg-rose-500/20 border border-rose-500/20 text-rose-300 transition-colors"
                      >
                        <Trash2 className="w-3 h-3" />
                        <span>移除</span>
                      </button>
                    )}
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* One-Click Import Clients Grid */}
      <div>
        <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider mb-3 px-1">
          客户端一键导入 (DeepLink 唤醒)
        </h3>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
          {clients.map((c) => (
            <div key={c.name} className="p-4 rounded-2xl glass-card glass-card-hover flex flex-col justify-between">
              <div>
                <div className="flex items-center gap-2.5">
                  <span className="text-2xl">{c.icon}</span>
                  <div>
                    <h4 className="font-semibold text-sm text-white">{c.name}</h4>
                    <p className="text-[11px] text-slate-400">{c.desc}</p>
                  </div>
                </div>
              </div>
              <div className="mt-4 pt-3 border-t border-slate-800 flex items-center justify-between">
                <a
                  href={c.scheme}
                  className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-emerald-500/10 hover:bg-emerald-500/20 text-emerald-300 border border-emerald-500/20 text-xs font-semibold transition-all"
                >
                  <Download className="w-3.5 h-3.5" />
                  <span>一键导入配置</span>
                </a>
                <button
                  onClick={() => showQRCode(c.scheme || '')}
                  className="p-1.5 text-slate-400 hover:text-white rounded-lg hover:bg-slate-800 transition-colors"
                  title="查看导入二维码"
                >
                  <QrCode className="w-4 h-4" />
                </button>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Direct Node Links */}
      <div className="p-5 rounded-2xl glass-card space-y-4">
        <h3 className="text-sm font-semibold text-white">本机单节点直连链接 (URI)</h3>
        <div className="space-y-3">
          {data?.nodes?.hy2?.link && (
            <div className="p-3 rounded-xl bg-slate-950/60 border border-slate-800 flex items-center justify-between gap-3 text-xs font-mono">
              <div className="truncate text-slate-300">
                <span className="text-emerald-400 font-semibold mr-2">[Hysteria 2]</span>
                {data.nodes.hy2.link}
              </div>
              <button
                onClick={() => copyText(data.nodes.hy2.link, 'hy2')}
                className="px-2.5 py-1 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 shrink-0 text-xs flex items-center gap-1"
              >
                {copiedKey === 'hy2' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                <span>复制</span>
              </button>
            </div>
          )}
          {data?.nodes?.vless?.link && (
            <div className="p-3 rounded-xl bg-slate-950/60 border border-slate-800 flex items-center justify-between gap-3 text-xs font-mono">
              <div className="truncate text-slate-300">
                <span className="text-purple-400 font-semibold mr-2">[VLESS Reality]</span>
                {data.nodes.vless.link}
              </div>
              <button
                onClick={() => copyText(data.nodes.vless.link, 'vless')}
                className="px-2.5 py-1 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 shrink-0 text-xs flex items-center gap-1"
              >
                {copiedKey === 'vless' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                <span>复制</span>
              </button>
            </div>
          )}
        </div>
      </div>

      {/* Add / Edit Subscription Source Modal */}
      {editingSource && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/85 backdrop-blur-md">
          <form
            onSubmit={handleSaveSource}
            className="bg-slate-900 border border-slate-800 rounded-3xl w-full max-w-xl overflow-hidden shadow-2xl"
          >
            <div className="flex items-center justify-between px-6 py-4 border-b border-slate-800">
              <div>
                <h4 className="text-base font-bold text-white">
                  {editingSource.name ? '编辑聚合节点源' : '添加节点源 / 外部订阅'}
                </h4>
                <p className="text-xs text-slate-400 mt-0.5">
                  保存后无需重启容器，SubHub 将立即合并进全平台订阅链接
                </p>
              </div>
              <button
                type="button"
                onClick={() => setEditingSource(null)}
                className="p-1.5 rounded-xl hover:bg-slate-800 text-slate-400 hover:text-white"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="p-6 space-y-4">
              {!isAutoManagedEdit && (
                <div className="grid grid-cols-2 gap-2 p-1 rounded-xl bg-slate-950 border border-slate-800 text-xs">
                  <button
                    type="button"
                    onClick={() => setEditingSource({ ...editingSource, source: 'local' })}
                    className={`py-2 rounded-lg font-semibold transition-colors ${
                      editingSource.source === 'local'
                        ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30'
                        : 'text-slate-400 hover:text-white'
                    }`}
                  >
                    粘贴节点链接 (Local URIs)
                  </button>
                  <button
                    type="button"
                    onClick={() => setEditingSource({ ...editingSource, source: 'remote' })}
                    className={`py-2 rounded-lg font-semibold transition-colors ${
                      editingSource.source === 'remote'
                        ? 'bg-blue-500/20 text-blue-300 border border-blue-500/30'
                        : 'text-slate-400 hover:text-white'
                    }`}
                  >
                    远程外部订阅 (HTTP/HTTPS)
                  </button>
                </div>
              )}

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs text-slate-400 mb-1">显示名称 *</label>
                  <input
                    type="text"
                    required
                    value={editingSource.displayName}
                    onChange={(e) => setEditingSource({ ...editingSource, displayName: e.target.value })}
                    placeholder="例如: 日本备用 VPS / 主力机场"
                    className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-xs text-white focus:outline-none focus:border-emerald-500"
                  />
                </div>
                <div>
                  <label className="block text-xs text-slate-400 mb-1">备注说明 (可选)</label>
                  <input
                    type="text"
                    value={editingSource.remark || ''}
                    onChange={(e) => setEditingSource({ ...editingSource, remark: e.target.value })}
                    placeholder="例如: 东京 CN2 GIA"
                    className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-xs text-white focus:outline-none focus:border-emerald-500"
                  />
                </div>
              </div>

              {editingSource.source === 'remote' ? (
                <div>
                  <label className="block text-xs text-slate-400 mb-1">远程订阅 URL *</label>
                  <input
                    type="url"
                    required
                    value={editingSource.url || ''}
                    onChange={(e) => setEditingSource({ ...editingSource, url: e.target.value })}
                    placeholder="https://example.com/api/v1/client/subscribe?token=..."
                    className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-xs font-mono text-emerald-300 focus:outline-none focus:border-blue-500"
                  />
                  <p className="text-[11px] text-slate-500 mt-1.5">
                    支持 Base64 URI 列表或 Clash YAML 订阅，内置 SSRF 私网防护与 10 分钟容灾缓存。
                  </p>
                </div>
              ) : (
                <div>
                  <label className="block text-xs text-slate-400 mb-1">
                    节点分享链接 (每行一条 URI，或粘贴 Base64 / Clash YAML) *
                  </label>
                  <textarea
                    rows={6}
                    required
                    value={editingSource.content || ''}
                    onChange={(e) => setEditingSource({ ...editingSource, content: e.target.value })}
                    placeholder={'vless://uuid@host:443?security=reality&sni=...#Node-1\nhysteria2://pass@host:443/?sni=...#Node-2'}
                    className="w-full bg-slate-950 border border-slate-800 rounded-xl p-3 text-xs font-mono text-emerald-300 focus:outline-none focus:border-emerald-500"
                  />
                </div>
              )}
            </div>

            <div className="px-6 py-4 bg-slate-950/60 border-t border-slate-800 flex items-center justify-end gap-2.5">
              <button
                type="button"
                onClick={() => setEditingSource(null)}
                className="px-4 py-2 rounded-xl text-xs text-slate-400 hover:text-white hover:bg-slate-800"
              >
                取消
              </button>
              <button
                type="submit"
                disabled={savingSource}
                className="flex items-center gap-1.5 px-4 py-2 rounded-xl bg-emerald-500 hover:bg-emerald-600 text-slate-950 font-semibold text-xs transition-colors disabled:opacity-50"
              >
                {savingSource && <RefreshCw className="w-3.5 h-3.5 animate-spin" />}
                <span>{savingSource ? '正在校验并保存...' : '保存节点源'}</span>
              </button>
            </div>
          </form>
        </div>
      )}

      {/* Live Target Config Preview Modal */}
      {showPreviewModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/85 backdrop-blur-md">
          <div className="bg-slate-900 border border-slate-800 rounded-3xl w-full max-w-4xl max-h-[88vh] flex flex-col overflow-hidden shadow-2xl">
            <div className="flex items-center justify-between px-6 py-4 border-b border-slate-800">
              <div>
                <h4 className="text-base font-bold text-white flex items-center gap-2">
                  <FileCode2 className="w-4 h-4 text-purple-400" />
                  <span>多客户端订阅实时转换预览</span>
                  {previewData && (
                    <span className="px-2 py-0.5 rounded-md text-[11px] font-mono bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                      {previewData.nodeCount} 个节点
                    </span>
                  )}
                </h4>
                <p className="text-xs text-slate-400 mt-0.5 font-mono">
                  {previewData?.filename || '选择目标格式查看 SubHub 实时渲染结果'}
                </p>
              </div>
              <button
                onClick={() => setShowPreviewModal(false)}
                className="p-1.5 rounded-xl hover:bg-slate-800 text-slate-400 hover:text-white"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="px-6 py-3 bg-slate-950/60 border-b border-slate-800 flex flex-wrap items-center justify-between gap-2">
              <div className="flex flex-wrap items-center gap-1.5">
                {PREVIEW_TARGETS.map((t) => (
                  <button
                    key={t.key}
                    onClick={() => fetchPreview(t.key)}
                    className={`px-3 py-1.5 rounded-xl text-xs font-mono transition-colors ${
                      previewTarget === t.key
                        ? 'bg-purple-500/20 text-purple-200 border border-purple-500/40 font-semibold'
                        : 'bg-slate-900 text-slate-400 hover:text-white border border-slate-800'
                    }`}
                  >
                    {t.label}
                  </button>
                ))}
              </div>
              {previewData && (
                <div className="flex items-center gap-2">
                  <button
                    onClick={() => copyText(previewData.content, 'preview-copy')}
                    className="flex items-center gap-1.5 px-3 py-1.5 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs"
                  >
                    {copiedKey === 'preview-copy' ? (
                      <Check className="w-3.5 h-3.5 text-emerald-400" />
                    ) : (
                      <Copy className="w-3.5 h-3.5" />
                    )}
                    <span>复制内容</span>
                  </button>
                  <button
                    onClick={handleDownloadPreview}
                    className="flex items-center gap-1.5 px-3 py-1.5 rounded-xl bg-emerald-500/15 hover:bg-emerald-500/25 border border-emerald-500/30 text-emerald-300 text-xs font-semibold"
                  >
                    <Download className="w-3.5 h-3.5" />
                    <span>下载文件</span>
                  </button>
                </div>
              )}
            </div>

            <div className="p-5 flex-1 overflow-y-auto bg-[#060913] font-mono text-xs text-slate-300">
              {loadingPreview ? (
                <div className="py-16 text-center text-slate-400">
                  <RefreshCw className="w-5 h-5 animate-spin mx-auto mb-2 text-purple-400" />
                  <span>正在实时生成 {previewTarget} 配置...</span>
                </div>
              ) : (
                <pre className="whitespace-pre-wrap break-all leading-relaxed">{previewData?.content || ''}</pre>
              )}
            </div>
          </div>
        </div>
      )}

      {/* QR Code Modal */}
      {qrModalURL && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-md">
          <div className="bg-slate-900 border border-slate-800 rounded-3xl p-6 max-w-sm w-full flex flex-col items-center text-center shadow-2xl relative">
            <button
              onClick={() => setQrModalURL(null)}
              className="absolute top-4 right-4 p-1.5 rounded-xl hover:bg-slate-800 text-slate-400 hover:text-white transition-colors"
            >
              <X className="w-4 h-4" />
            </button>
            <h4 className="text-base font-bold text-white mt-1">手机扫码快速导入</h4>
            <p className="text-xs text-slate-400 mt-1">使用 Shadowrocket 或支持二维码的客户端扫码</p>
            <div className="mt-5 p-3 bg-white rounded-2xl shadow-inner">
              <canvas ref={qrCanvasRef} className="rounded-lg"></canvas>
            </div>
            <p className="text-[11px] font-mono text-slate-400 mt-4 break-all max-w-xs line-clamp-2">
              {qrModalURL}
            </p>
          </div>
        </div>
      )}
    </div>
  );
};

import React, { useEffect, useState } from 'react';
import {
  SubscriptionsResponse,
  SubscriptionSourceItem,
  SourceUpsertInput,
  SubscriptionPreviewResponse,
  SubscriptionAccessLogItem,
  SubscriptionRiskSummary,
} from '../types';
import { api } from '../api';
import { SUBS_AUDIT_CACHE_KEY, SUBS_CACHE_KEY } from '../prefetch';
import { peekCachedQuery, writeCachedQuery } from '../../hooks';
import { useToast } from '../../ui';
import { copyToClipboard } from '../../lib/clipboard';
import { CachedSubAudit } from './subscriptions/helpers';
import { ClientImportsAndDirectLinks, UnifiedSubscriptionCard } from './subscriptions/SubscriptionLinksSection';
import { SourcesPoolCard } from './subscriptions/SourcesPoolCard';
import { AccessAuditCard } from './subscriptions/AccessAuditCard';
import { ConversionPreviewModal, QRCodeModal, SourceUpsertModal } from './subscriptions/SubscriptionModals';

export const SubscriptionsTab: React.FC<{ active?: boolean }> = ({ active = true }) => {
  const { success, error } = useToast();
  const cachedAudit = peekCachedQuery<CachedSubAudit>(SUBS_AUDIT_CACHE_KEY);
  const [data, setData] = useState<SubscriptionsResponse | null>(
    () => peekCachedQuery<SubscriptionsResponse>(SUBS_CACHE_KEY) ?? null,
  );
  const [loading, setLoading] = useState(() => !peekCachedQuery(SUBS_CACHE_KEY));
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const [qrModalURL, setQrModalURL] = useState<string | null>(null);

  // Source CRUD modal state
  const [editingSource, setEditingSource] = useState<SourceUpsertInput | null>(null);
  const [isAutoManagedEdit, setIsAutoManagedEdit] = useState(false);
  const [savingSource, setSavingSource] = useState(false);
  const [refreshingSource, setRefreshingSource] = useState<string | null>(null);
  const [rotatingKey, setRotatingKey] = useState(false);

  // Live conversion preview modal state
  const [showPreviewModal, setShowPreviewModal] = useState(false);
  const [previewTarget, setPreviewTarget] = useState('ClashMeta');
  const [previewData, setPreviewData] = useState<SubscriptionPreviewResponse | null>(null);
  const [loadingPreview, setLoadingPreview] = useState(false);

  // Subscription access audit state
  const [auditLogs, setAuditLogs] = useState<SubscriptionAccessLogItem[]>(
    () => cachedAudit?.logs || [],
  );
  const [riskSummary, setRiskSummary] = useState<SubscriptionRiskSummary | null>(
    () => cachedAudit?.riskSummary || null,
  );
  const [bannedIps, setBannedIps] = useState<Set<string>>(
    () => new Set(cachedAudit?.bannedIps || []),
  );
  const [blockingIP, setBlockingIP] = useState<string | null>(null);
  const [loadingAudit, setLoadingAudit] = useState(false);
  const [clearingAudit, setClearingAudit] = useState(false);

  const loadData = async (silent?: boolean | React.SyntheticEvent) => {
    const isSilent = silent === true;
    if (!isSilent && !data) setLoading(true);
    try {
      const res = await api.getSubscriptions();
      setData(res);
      writeCachedQuery(SUBS_CACHE_KEY, res);
    } catch (err: any) {
      if (!isSilent) error(err.message || '获取订阅信息失败');
    } finally {
      setLoading(false);
    }
  };

  const loadAuditLogs = async (silent?: boolean | React.SyntheticEvent) => {
    const isSilent = silent === true;
    if (!isSilent) setLoadingAudit(true);
    try {
      const res = await api.getSubscriptionAuditLogs();
      setAuditLogs(res.logs || []);
      setRiskSummary(res.riskSummary || null);
      setBannedIps(new Set(res.bannedIps || []));
      writeCachedQuery(SUBS_AUDIT_CACHE_KEY, res);
    } catch {
      // non-fatal
    } finally {
      if (!isSilent) setLoadingAudit(false);
    }
  };

  useEffect(() => {
    if (!active) return;
    const hasCache = Boolean(peekCachedQuery(SUBS_CACHE_KEY));
    void loadData(hasCache);
    void loadAuditLogs(Boolean(peekCachedQuery(SUBS_AUDIT_CACHE_KEY)));
  }, [active]);

  const handleBlockSubIP = async (ip: string) => {
    const trimmed = ip.trim();
    if (!trimmed || trimmed === '-') return;
    setBlockingIP(trimmed);
    try {
      const res = await api.blockSniffer(trimmed, 'all', 'all');
      success(res.message || `已全集群拉黑异常订阅拉取 IP: ${trimmed}`);
      setBannedIps((prev) => new Set([...prev, trimmed]));
    } catch (err: any) {
      error(err.message || '拉黑 IP 失败');
    } finally {
      setBlockingIP(null);
    }
  };

  const handleClearAuditLogs = async () => {
    if (!window.confirm('确定要清空近期订阅拉取与拦截记录吗？')) return;
    setClearingAudit(true);
    try {
      const res = await api.clearSubscriptionAuditLogs();
      success(res.message || '订阅审计记录已清空');
      setAuditLogs([]);
      setRiskSummary(null);
    } catch (err: any) {
      error(err.message || '清空审计记录失败');
    } finally {
      setClearingAudit(false);
    }
  };

  const copyText = (text: string, key: string) => {
    void copyToClipboard(text)
      .then(() => {
        setCopiedKey(key);
        success('已复制到剪贴板');
        setTimeout(() => setCopiedKey(null), 2000);
      })
      .catch(() => {
        error('复制失败，请手动复制');
      });
  };

  const openAddSourceModal = () => {
    setIsAutoManagedEdit(false);
    setEditingSource({
      displayName: '',
      source: 'local',
      url: '',
      content: '',
      remark: '',
      userAgent: 'auto',
      proxyMode: 'auto',
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
      userAgent: item.userAgent || 'auto',
      proxyMode: item.proxyMode || 'auto',
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

  const handleRefreshSources = async (targetName?: string) => {
    const key = targetName || '__all__';
    setRefreshingSource(key);
    try {
      const res = await api.refreshSubSources(targetName);
      if (res.sources) {
        setData((prev) => (prev ? { ...prev, sources: res.sources } : prev));
      }
      success(res.message || '远程订阅源已刷新');
    } catch (err: any) {
      error(err.message || '刷新远程订阅源失败');
      await loadData();
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
        '确定要轮换订阅访问密钥吗？\n\n轮换后，旧订阅链接将立即失效，所有手机/电脑客户端需重新复制或扫码导入新订阅地址。',
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

  const sources = data?.sources || [];
  const totalNodes = sources.reduce((acc, s) => (s.enabled ? acc + (s.nodeCount || 0) : acc), 0);

  return (
    <div className="space-y-6">
      <UnifiedSubscriptionCard
        data={data}
        totalNodes={totalNodes}
        copiedKey={copiedKey}
        rotatingKey={rotatingKey}
        loading={loading}
        onCopyText={copyText}
        onShowQRCode={(url) => setQrModalURL(url)}
        onFetchPreview={fetchPreview}
        onRotateKey={handleRotateKey}
        onReload={() => void loadData()}
      />

      <SourcesPoolCard
        sources={sources}
        refreshingSource={refreshingSource}
        onRefreshSources={handleRefreshSources}
        onAddSource={openAddSourceModal}
        onEditSource={openEditSourceModal}
        onToggleSourceEnabled={handleToggleSourceEnabled}
        onDeleteSource={handleDeleteSource}
      />

      <ClientImportsAndDirectLinks
        data={data}
        copiedKey={copiedKey}
        onCopyText={copyText}
        onShowQRCode={(url) => setQrModalURL(url)}
      />

      <AccessAuditCard
        auditLogs={auditLogs}
        riskSummary={riskSummary}
        bannedIps={bannedIps}
        blockingIP={blockingIP}
        loadingAudit={loadingAudit}
        clearingAudit={clearingAudit}
        rotatingKey={rotatingKey}
        onRefreshAudit={() => void loadAuditLogs()}
        onClearAudit={handleClearAuditLogs}
        onRotateKey={handleRotateKey}
        onBlockIP={handleBlockSubIP}
      />

      {editingSource && (
        <SourceUpsertModal
          editingSource={editingSource}
          setEditingSource={setEditingSource}
          isAutoManagedEdit={isAutoManagedEdit}
          savingSource={savingSource}
          onSave={handleSaveSource}
        />
      )}

      {showPreviewModal && (
        <ConversionPreviewModal
          previewTarget={previewTarget}
          previewData={previewData}
          loadingPreview={loadingPreview}
          copiedKey={copiedKey}
          onSelectTarget={fetchPreview}
          onCopyContent={() => previewData && copyText(previewData.content, 'preview-copy')}
          onDownload={handleDownloadPreview}
          onClose={() => setShowPreviewModal(false)}
        />
      )}

      {qrModalURL && <QRCodeModal url={qrModalURL} onClose={() => setQrModalURL(null)} />}
    </div>
  );
};

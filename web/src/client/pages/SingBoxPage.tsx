import React, { useState, useEffect, useCallback } from 'react';
import { Box, RefreshCw, Database, FileCode, RotateCcw, ExternalLink, Save, Sparkles } from 'lucide-react';
import {
  Badge,
  Button,
  ConfirmDialog,
  DataColumn,
  DataTable,
  PageHeader,
  SectionCard,
  SegmentedTabs,
  useToast,
} from '../../ui';
import { clientApi } from '../api';
import { CacheEntry, CacheResponse, ClientStatusResponse, SbConfigResponse } from '../types';

export interface SingBoxPageProps {
  status: ClientStatusResponse | null;
  busy: boolean;
  onAction: (name: string, params?: Record<string, unknown>, confirmMsg?: string) => void;
  onNavigate: (tab: string) => void;
}

type SbSubTab = 'overview' | 'editor';

export const SingBoxPage: React.FC<SingBoxPageProps> = ({ status, busy, onAction, onNavigate }) => {
  const { success, error, warn } = useToast();
  const [sub, setSub] = useState<SbSubTab>('overview');
  const [cache, setCache] = useState<CacheResponse | null>(null);
  const [cacheLoading, setCacheLoading] = useState(false);

  const [sbCfg, setSbCfg] = useState<SbConfigResponse | null>(null);
  const [jsonText, setJsonText] = useState('');
  const [selectedBackup, setSelectedBackup] = useState('');
  const [savingCfg, setSavingCfg] = useState(false);
  const [restoreConfirmOpen, setRestoreConfirmOpen] = useState(false);

  const loadCache = useCallback(async () => {
    setCacheLoading(true);
    try {
      setCache(await clientApi.getCache());
    } catch (err: unknown) {
      error(err instanceof Error ? err.message : '加载规则集缓存失败');
    } finally {
      setCacheLoading(false);
    }
  }, [error]);

  const loadSbConfig = useCallback(async () => {
    try {
      const d = await clientApi.getSbConfig();
      setSbCfg(d);
      setJsonText(d.content || '');
      if (!d.checkable) {
        warn('未检测到 sing-box 可执行文件，保存时将仅执行 JSON 语法校验');
      }
    } catch (err: unknown) {
      error(err instanceof Error ? err.message : '加载 config.json 失败');
    }
  }, [error, warn]);

  useEffect(() => {
    void loadCache();
  }, [loadCache]);

  useEffect(() => {
    if (sub === 'editor' && !sbCfg) {
      void loadSbConfig();
    }
  }, [sub, sbCfg, loadSbConfig]);

  const sb = status?.singbox;

  const formatJson = () => {
    try {
      setJsonText(JSON.stringify(JSON.parse(jsonText), null, 2));
      success('JSON 已格式化');
    } catch (err: unknown) {
      error(`JSON 解析失败：${err instanceof Error ? err.message : '语法错误'}`);
    }
  };

  const handleSaveConfig = async () => {
    setSavingCfg(true);
    try {
      const res = await clientApi.saveSbConfig(jsonText);
      success(res.checked ? 'sing-box check 语义校验通过，配置已保存' : 'JSON 已保存');
      await loadSbConfig();
    } catch (err: unknown) {
      error(`保存失败：${err instanceof Error ? err.message : '未知错误'}`);
    } finally {
      setSavingCfg(false);
    }
  };

  const handleRestoreBackup = async () => {
    if (!selectedBackup) return;
    setSavingCfg(true);
    try {
      await clientApi.restoreSbConfig(selectedBackup);
      success('已恢复所选配置备份');
      setRestoreConfirmOpen(false);
      await loadSbConfig();
    } catch (err: unknown) {
      error(`恢复失败：${err instanceof Error ? err.message : '未知错误'}`);
    } finally {
      setSavingCfg(false);
    }
  };

  const cacheColumns: DataColumn<CacheEntry>[] = [
    {
      key: 'state',
      header: '状态',
      render: (row) => {
        if (row.state === 'ok') return <Badge tone="ok" dot>本地已就绪</Badge>;
        if (row.state === 'snapshot') return <Badge tone="warn">内置快照</Badge>;
        return <Badge tone="danger">缺失</Badge>;
      },
    },
    {
      key: 'tag',
      header: '规则集标识',
      render: (row) => <span className="font-mono font-medium text-primary">{row.tag}</span>,
    },
    {
      key: 'format',
      header: '格式',
      render: (row) => <span className="font-mono text-secondary">{row.format}</span>,
    },
    {
      key: 'updatedAt',
      header: '更新时间',
      render: (row) => <span className="font-mono text-secondary tnum">{row.updatedAt || '-'}</span>,
    },
  ];

  return (
    <div className="space-y-5">
      <PageHeader
        title="sing-box 核心"
        description={sb?.configPath || '/etc/sing-box/config.json'}
        badge={
          <Badge tone={sb?.running ? 'ok' : sb?.installed ? 'neutral' : 'warn'} dot={sb?.running} pulse={sb?.running}>
            {sb?.running ? `运行中 · v${sb.version || '-'}` : sb?.installed ? '已停止' : '未安装'}
          </Badge>
        }
        actions={
          <SegmentedTabs
            value={sub}
            onChange={(k) => setSub(k as SbSubTab)}
            items={[
              { key: 'overview', label: '内核与规则缓存', icon: <Database className="w-3.5 h-3.5" /> },
              { key: 'editor', label: 'config.json 编辑器', icon: <FileCode className="w-3.5 h-3.5" /> },
            ]}
          />
        }
      />

      {sub === 'overview' ? (
        <div className="space-y-5">
          <SectionCard title="核心控制与升级" icon={<Box className="w-4 h-4" />}>
            <div className="flex flex-wrap items-center gap-2.5">
              {sb?.running ? (
                <>
                  <Button variant="primary" disabled={busy} onClick={() => onAction('sb-restart')}>
                    重启内核
                  </Button>
                  <Button
                    variant="danger"
                    disabled={busy}
                    onClick={() => onAction('sb-stop', {}, '确认停止 sing-box？这会中断当前代理连接。')}
                  >
                    停止内核
                  </Button>
                </>
              ) : (
                <Button variant="primary" disabled={busy} onClick={() => onAction('sb-start')}>
                  启动内核
                </Button>
              )}
              <Button disabled={busy} onClick={() => onAction('sb-gen')} icon={<Sparkles className="w-3.5 h-3.5" />}>
                从订阅生成配置
              </Button>
              <Button disabled={busy} onClick={() => onAction(sb?.installed ? 'sb-update' : 'sb-install')}>
                {sb?.installed ? '更新 sing-box' : '安装 sing-box'}
              </Button>
              {sb?.running && (
                <Button variant="ghost" onClick={() => onNavigate('panel')} icon={<ExternalLink className="w-3.5 h-3.5" />}>
                  打开控制面板
                </Button>
              )}
            </div>
          </SectionCard>

          <SectionCard
            title="规则集（.srs）本地缓存"
            icon={<Database className="w-4 h-4" />}
            subtitle={
              cache
                ? `目录: ${cache.cacheDir || '-'} · 内置快照 ${cache.snapshotCount || 0} 个 (${cache.snapshotTime || '-'})`
                : '加载规则缓存状态…'
            }
            noPadding
            actions={
              <>
                <Button size="xs" loading={cacheLoading} onClick={loadCache} icon={<RefreshCw className="w-3 h-3" />}>
                  刷新
                </Button>
                <Button size="xs" variant="primary" disabled={busy} onClick={() => onAction('cache-update')}>
                  拉取更新
                </Button>
                <Button
                  size="xs"
                  variant="danger"
                  disabled={busy}
                  onClick={() => onAction('cache-clear', {}, '确认清空规则集缓存？配置中的本地引用将回退为远程 URL。')}
                >
                  清空缓存
                </Button>
              </>
            }
          >
            <DataTable
              columns={cacheColumns}
              rows={cache?.entries || []}
              rowKey={(r) => r.tag}
              loading={cacheLoading}
              emptyText="暂无本地规则集缓存（生成配置或启动 sing-box 时会自动建立）"
            />
          </SectionCard>
        </div>
      ) : (
        <SectionCard
          title="sing-box config.json"
          icon={<FileCode className="w-4 h-4" />}
          subtitle={sbCfg ? `${sbCfg.path}${sbCfg.exists ? '' : '（尚未生成）'}` : '加载中…'}
          actions={
            <>
              <Button size="xs" onClick={loadSbConfig} icon={<RefreshCw className="w-3 h-3" />}>
                重新加载
              </Button>
              <Button size="xs" onClick={formatJson}>
                格式化 JSON
              </Button>
              <Button size="xs" variant="primary" loading={savingCfg} onClick={handleSaveConfig} icon={<Save className="w-3 h-3" />}>
                校验并保存
              </Button>
            </>
          }
        >
          <div className="space-y-3">
            {sbCfg && sbCfg.backups?.length > 0 && (
              <div className="flex flex-wrap items-center gap-2 p-2.5 rounded-xl bg-surface2 border border-subtle">
                <span className="text-xs text-secondary">历史备份恢复：</span>
                <select
                  value={selectedBackup}
                  onChange={(e) => setSelectedBackup(e.target.value)}
                  className="h-8 px-2.5 rounded-lg bg-surface1 border border-subtle text-xs text-primary font-mono focus:outline-none"
                >
                  <option value="">选择备份时间点…</option>
                  {sbCfg.backups.map((b) => (
                    <option key={b} value={b}>
                      {b.replace(/^.*\.webui-bak-/, '')}
                    </option>
                  ))}
                </select>
                <Button
                  size="xs"
                  disabled={!selectedBackup}
                  onClick={() => setRestoreConfirmOpen(true)}
                  icon={<RotateCcw className="w-3 h-3" />}
                >
                  恢复所选备份
                </Button>
              </div>
            )}

            <textarea
              value={jsonText}
              onChange={(e) => setJsonText(e.target.value)}
              spellCheck={false}
              rows={20}
              className="w-full p-3.5 rounded-xl bg-[var(--console-bg)] text-slate-200 border border-subtle font-mono text-xs leading-relaxed focus:outline-none focus:border-strong"
            />
            <p className="text-xs text-muted">
              保存前自动创建 `.webui-bak-时间戳` 备份，并通过 `sing-box check` 校验语义合法性；保存后如运行中请手动点击「重启内核」应用生效。
            </p>
          </div>
        </SectionCard>
      )}

      <ConfirmDialog
        open={restoreConfirmOpen}
        title="恢复配置备份"
        description={`确认使用备份 "${selectedBackup}" 覆盖当前 sing-box config.json？当前配置会先自动另存为新备份。`}
        confirmText="确认恢复"
        loading={savingCfg}
        onConfirm={handleRestoreBackup}
        onCancel={() => setRestoreConfirmOpen(false)}
      />
    </div>
  );
};

import React, { useState, useEffect, useCallback, useMemo, useRef } from 'react';
import {
  Box,
  RefreshCw,
  FileCode,
  RotateCcw,
  ExternalLink,
  Save,
  Sparkles,
  SlidersHorizontal,
  Search,
  X,
} from 'lucide-react';
import {
  Badge,
  Button,
  ConfirmDialog,
  PageHeader,
  SectionCard,
  SegmentedTabs,
  useToast,
} from '../../ui';
import { clientApi } from '../api';
import {
  ClientRoutingPresetState,
  ClientRoutingReport,
  ClientStatusResponse,
  SbConfigResponse,
} from '../types';

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

  const [routing, setRouting] = useState<ClientRoutingReport | null>(null);
  const [routingLoading, setRoutingLoading] = useState(true);
  const [activeCategory, setActiveCategory] = useState<string>('all');
  const [searchQuery, setSearchQuery] = useState('');
  const [savingId, setSavingId] = useState<string | null>(null);
  const [resetConfirmOpen, setResetConfirmOpen] = useState(false);
  const [resetting, setResetting] = useState(false);

  const [sbCfg, setSbCfg] = useState<SbConfigResponse | null>(null);
  const [jsonText, setJsonText] = useState('');
  const [selectedBackup, setSelectedBackup] = useState('');
  const [savingCfg, setSavingCfg] = useState(false);
  const [restoreConfirmOpen, setRestoreConfirmOpen] = useState(false);

  const loadRouting = useCallback(
    async (silent = false) => {
      if (!silent) setRoutingLoading(true);
      try {
        setRouting(await clientApi.getTrafficRouting());
      } catch (err: unknown) {
        if (!silent) error(err instanceof Error ? err.message : '加载智能分流配置失败');
      } finally {
        if (!silent) setRoutingLoading(false);
      }
    },
    [error],
  );

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
    void loadRouting(false);
  }, [loadRouting]);

  // 执行完生成配置/启动等动作后，自动同步最新策略组与分流状态
  const prevBusyRef = useRef(busy);
  useEffect(() => {
    if (prevBusyRef.current && !busy) {
      void loadRouting(true);
      if (sub === 'editor') void loadSbConfig();
    }
    prevBusyRef.current = busy;
  }, [busy, sub, loadRouting, loadSbConfig]);

  useEffect(() => {
    if (sub === 'editor' && !sbCfg) {
      void loadSbConfig();
    }
  }, [sub, sbCfg, loadSbConfig]);

  const handleUpdatePreset = async (
    item: ClientRoutingPresetState,
    nextEnabled: boolean,
    nextOutbound?: string,
    toastLabel?: string,
  ) => {
    if (savingId || resetting) return;
    const prevReport = routing;
    const chosenGroup = nextOutbound || item.selectedGroup || item.defaultOutbound;
    const nextDest = nextEnabled ? chosenGroup : routing?.directTag || '#DC';

    // 乐观更新当前行展示，消除开关切换迟滞感
    if (routing) {
      const nextItems = routing.items.map((it) =>
        it.id === item.id
          ? {
              ...it,
              enabled: nextEnabled,
              selectedGroup: chosenGroup,
              effectiveDest: nextDest,
            }
          : it,
      );
      setRouting({
        ...routing,
        items: nextItems,
        enabledCount: nextItems.filter((it) => it.enabled).length,
      });
    }

    setSavingId(item.id);
    try {
      const res = await clientApi.updateTrafficRouting({
        presets: {
          [item.id]: {
            enabled: nextEnabled,
            ...(nextOutbound ? { outbound: nextOutbound } : {}),
          },
        },
      });
      if (res.report) setRouting(res.report);
      if (toastLabel) {
        success(toastLabel);
      } else {
        success(
          nextEnabled
            ? `已开启「${item.name}」分流 → ${chosenGroup}（${res.applied ? '已热生效' : '已保存'}）`
            : `已关闭「${item.name}」代理分流 → 直连 ${routing?.directTag || '#DC'}（${res.applied ? '已热生效' : '已保存'}）`,
        );
      }
      if (sub === 'editor' || sbCfg) void loadSbConfig();
    } catch (err: unknown) {
      if (prevReport) setRouting(prevReport);
      error(`切换失败：${err instanceof Error ? err.message : '未知错误'}`);
    } finally {
      setSavingId(null);
    }
  };

  const handleResetDefaults = async () => {
    setResetting(true);
    try {
      const res = await clientApi.updateTrafficRouting({ reset: true });
      if (res.report) setRouting(res.report);
      setResetConfirmOpen(false);
      success(res.message || '已恢复默认推荐分流策略');
      if (sbCfg) void loadSbConfig();
    } catch (err: unknown) {
      error(`恢复默认失败：${err instanceof Error ? err.message : '未知错误'}`);
    } finally {
      setResetting(false);
    }
  };

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
      void loadRouting(true);
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
      void loadRouting(true);
    } catch (err: unknown) {
      error(`恢复失败：${err instanceof Error ? err.message : '未知错误'}`);
    } finally {
      setSavingCfg(false);
    }
  };

  const categoryCounts = useMemo(() => {
    const counts: Record<string, number> = {};
    for (const item of routing?.items || []) {
      counts[item.category] = (counts[item.category] || 0) + 1;
    }
    return counts;
  }, [routing]);

  const filteredItems = useMemo(() => {
    const items = routing?.items || [];
    const q = searchQuery.trim().toLowerCase();
    return items.filter((it) => {
      if (activeCategory !== 'all' && it.category !== activeCategory) return false;
      if (!q) return true;
      return (
        it.name.toLowerCase().includes(q) ||
        it.id.toLowerCase().includes(q) ||
        it.description.toLowerCase().includes(q) ||
        it.domainsSummary.toLowerCase().includes(q) ||
        it.effectiveDest.toLowerCase().includes(q)
      );
    });
  }, [routing, activeCategory, searchQuery]);

  const sb = status?.singbox;

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
              { key: 'overview', label: '内核与分流', icon: <SlidersHorizontal className="w-3.5 h-3.5" /> },
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
            title="智能分流开关中心"
            icon={<SlidersHorizontal className="w-4 h-4" />}
            subtitle={
              routing
                ? `已开启 ${routing.enabledCount}/${routing.totalCount} 项代理分流 · 关闭默认直连 (${routing.directTag}) · 切换后即时热生效`
                : '加载分流规则列表…'
            }
            actions={
              <div className="flex items-center gap-2">
                {routing && routing.customCount > 0 && (
                  <Badge tone="accent">已自定义 {routing.customCount} 项</Badge>
                )}
                <Button
                  size="xs"
                  loading={routingLoading}
                  onClick={() => void loadRouting(false)}
                  icon={<RefreshCw className="w-3 h-3" />}
                >
                  刷新
                </Button>
                <Button
                  size="xs"
                  variant="ghost"
                  disabled={!routing || resetting || !!savingId}
                  onClick={() => setResetConfirmOpen(true)}
                  icon={<RotateCcw className="w-3 h-3" />}
                >
                  恢复推荐默认
                </Button>
              </div>
            }
          >
            <div className="space-y-4">
              {routing && !routing.hasConfig && (
                <div className="rounded-xl border border-amber-500/30 bg-amber-500/10 px-3.5 py-2.5 text-xs text-amber-200">
                  尚未检测到 <code className="font-mono">config.json</code>，当前预设策略将预先保存，点击上方「从订阅生成配置」或启动内核时自动生效。
                </div>
              )}

              <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-3">
                <div className="flex flex-wrap items-center gap-1.5">
                  <button
                    type="button"
                    onClick={() => setActiveCategory('all')}
                    className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-colors cursor-pointer ${
                      activeCategory === 'all'
                        ? 'bg-[var(--accent)] text-white shadow-sm'
                        : 'bg-surface2 text-secondary hover:text-primary border border-subtle'
                    }`}
                  >
                    全部 ({routing?.items.length ?? 0})
                  </button>
                  {(routing?.categories || []).map((cat) => (
                    <button
                      key={cat.id}
                      type="button"
                      onClick={() => setActiveCategory(cat.id)}
                      className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-colors cursor-pointer ${
                        activeCategory === cat.id
                          ? 'bg-[var(--accent)] text-white shadow-sm'
                          : 'bg-surface2 text-secondary hover:text-primary border border-subtle'
                      }`}
                    >
                      {cat.label} ({categoryCounts[cat.id] || 0})
                    </button>
                  ))}
                </div>

                <div className="relative w-full lg:w-64 shrink-0">
                  <Search className="w-3.5 h-3.5 text-muted absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none" />
                  <input
                    type="text"
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                    placeholder="搜索服务或域名…"
                    className="sc-input w-full h-8 pl-8 pr-7 text-xs"
                  />
                  {searchQuery && (
                    <button
                      type="button"
                      onClick={() => setSearchQuery('')}
                      aria-label="清空搜索"
                      className="absolute right-2 top-1/2 -translate-y-1/2 text-muted hover:text-primary cursor-pointer"
                    >
                      <X className="w-3.5 h-3.5" />
                    </button>
                  )}
                </div>
              </div>

              {activeCategory !== 'all' && routing?.categories && (
                <div className="rounded-xl bg-surface2/70 border border-subtle px-3.5 py-2 text-xs text-secondary">
                  {routing.categories.find((c) => c.id === activeCategory)?.description}
                </div>
              )}

              {routingLoading && !routing ? (
                <div className="py-10 text-center text-xs text-muted">正在加载分流规则…</div>
              ) : filteredItems.length === 0 ? (
                <div className="py-10 text-center text-xs text-muted">
                  未找到匹配「{searchQuery}」的分流服务
                </div>
              ) : (
                <div className="divide-y divide-subtle rounded-xl border border-subtle bg-surface1 overflow-hidden">
                  {filteredItems.map((item) => {
                    const isSaving = savingId === item.id;
                    const groupOptions = routing?.groups || [];
                    const hasSelectedInOptions = groupOptions.some((g) => g.tag === item.selectedGroup);

                    return (
                      <div
                        key={item.id}
                        className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 px-4 py-3 hover:bg-surface2/40 transition-colors"
                      >
                        <div className="min-w-0 space-y-1">
                          <div className="flex flex-wrap items-center gap-2">
                            <span className="text-sm font-semibold text-primary">{item.name}</span>
                            {activeCategory === 'all' && (
                              <span className="text-[11px] px-2 py-0.5 rounded-md bg-surface2 text-secondary border border-subtle">
                                {item.categoryLabel}
                              </span>
                            )}
                            {item.enabled ? (
                              <Badge tone={item.effectiveDest === '#VPS' ? 'accent' : 'ok'}>
                                走 {item.effectiveDest}
                              </Badge>
                            ) : (
                              <Badge tone="neutral">直连 {routing?.directTag || '#DC'}</Badge>
                            )}
                            {item.customized && (
                              <span className="text-[10px] font-medium px-1.5 py-0.5 rounded bg-amber-500/15 text-amber-400 border border-amber-500/20">
                                已自定义
                              </span>
                            )}
                          </div>
                          <p className="text-xs text-secondary leading-relaxed">{item.description}</p>
                          <div className="text-[11px] font-mono text-muted truncate">{item.domainsSummary}</div>
                        </div>

                        <div className="flex items-center justify-end gap-3 shrink-0">
                          <div className="flex items-center gap-1.5">
                            <span className="text-[11px] text-muted hidden md:inline">节点组</span>
                            <select
                              aria-label={`${item.name} 目标策略组`}
                              value={item.selectedGroup}
                              disabled={isSaving || resetting || groupOptions.length === 0}
                              onChange={(e) => {
                                const nextGroup = e.target.value;
                                if (!nextGroup) return;
                                const toastText = item.enabled
                                  ? `「${item.name}」分流组已切换至 ${nextGroup}（${routing?.hasConfig ? '已热生效' : '已保存'}）`
                                  : `已开启「${item.name}」并指派至 ${nextGroup}（${routing?.hasConfig ? '已热生效' : '已保存'}）`;
                                void handleUpdatePreset(item, true, nextGroup, toastText);
                              }}
                              title={
                                item.enabled
                                  ? `当前流量路由至 ${item.selectedGroup}，可独立切换其他分组`
                                  : `当前直连 ${routing?.directTag || '#DC'}，选择分组或开启右侧开关后即刻代理`
                              }
                              className={`sc-input h-8 px-2.5 text-xs font-mono min-w-[104px] transition-opacity ${
                                item.enabled ? 'text-primary' : 'text-muted opacity-70'
                              }`}
                            >
                              {!hasSelectedInOptions && item.selectedGroup && (
                                <option value={item.selectedGroup}>{item.selectedGroup}</option>
                              )}
                              {groupOptions.map((g) => (
                                <option key={g.tag} value={g.tag}>
                                  {g.tag}
                                  {g.tag === item.defaultOutbound ? ' (推荐)' : ''}
                                </option>
                              ))}
                            </select>
                          </div>

                          <button
                            type="button"
                            role="switch"
                            aria-checked={item.enabled}
                            aria-label={`切换 ${item.name} 分流开关`}
                            disabled={isSaving || resetting}
                            onClick={() => void handleUpdatePreset(item, !item.enabled)}
                            className={`relative inline-flex h-6 w-11 shrink-0 cursor-pointer items-center rounded-full border transition-colors focus:outline-none disabled:opacity-50 ${
                              item.enabled
                                ? 'bg-[var(--accent)] border-transparent'
                                : 'bg-surface2 border-strong'
                            }`}
                          >
                            <span
                              className={`inline-block h-4 w-4 transform rounded-full bg-white shadow transition-transform ${
                                item.enabled ? 'translate-x-5' : 'translate-x-1'
                              }`}
                            />
                          </button>
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
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

      <ConfirmDialog
        open={resetConfirmOpen}
        title="恢复默认分流策略"
        description="确认将全部 25 项分流开关恢复为系统推荐默认？（AI 大模型默认走 #VPS，流媒体/游戏/社交默认走 Proxy 或 #Auto，Apple 与 Microsoft 默认直连 #DC）"
        confirmText="确认恢复默认"
        loading={resetting}
        onConfirm={() => void handleResetDefaults()}
        onCancel={() => setResetConfirmOpen(false)}
      />
    </div>
  );
};

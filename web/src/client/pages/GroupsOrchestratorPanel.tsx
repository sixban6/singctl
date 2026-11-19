import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  AlertTriangle,
  ArrowRight,
  CheckCircle2,
  ChevronDown,
  ChevronUp,
  Layers,
  RefreshCw,
  RotateCcw,
  Save,
  ShieldCheck,
  Sparkles,
  Wand2,
} from 'lucide-react';
import { Badge, Button, ConfirmDialog, SectionCard, useToast } from '../../ui';
import { clientApi } from '../api';
import {
  ClientGroupsGetResponse,
  ClientRoutingReport,
  GroupMacroInfo,
  GroupsPreviewReport,
  GroupTemplateSnippet,
} from '../types';

export interface GroupsOrchestratorPanelProps {
  busy: boolean;
  onApplied: (nextRouting?: ClientRoutingReport) => void;
  onJumpToRouting: () => void;
  onJumpToGroup: (groupName: string) => void;
}

export const GroupsOrchestratorPanel: React.FC<GroupsOrchestratorPanelProps> = ({
  busy,
  onApplied,
  onJumpToRouting,
  onJumpToGroup,
}) => {
  const { success, error, toast } = useToast();
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [resetting, setResetting] = useState(false);
  const [resetConfirmOpen, setResetConfirmOpen] = useState(false);

  const [filePath, setFilePath] = useState('/etc/singctl/groups.yaml');
  const [fileExists, setFileExists] = useState(false);
  const [hasLiveConfig, setHasLiveConfig] = useState(false);
  const [savedContent, setSavedContent] = useState('');
  const [yamlText, setYamlText] = useState('');
  const [macros, setMacros] = useState<GroupMacroInfo[]>([]);
  const [templates, setTemplates] = useState<GroupTemplateSnippet[]>([]);

  const [preview, setPreview] = useState<GroupsPreviewReport | null>(null);
  const [previewError, setPreviewError] = useState('');
  const [previewing, setPreviewing] = useState(false);
  const [showLeafPool, setShowLeafPool] = useState(false);

  const textareaRef = useRef<HTMLTextAreaElement | null>(null);
  const previewSeqRef = useRef(0);

  const loadInitial = useCallback(async () => {
    setLoading(true);
    try {
      const res: ClientGroupsGetResponse = await clientApi.getGroups();
      setFilePath(res.path || '/etc/singctl/groups.yaml');
      setFileExists(Boolean(res.exists));
      setHasLiveConfig(Boolean(res.hasLiveConfig));
      setSavedContent(res.content || '');
      setYamlText(res.content || '');
      setMacros(res.macros || []);
      setTemplates(res.templates || []);
      setPreview(res.preview || null);
      setPreviewError(res.parseError || '');
    } catch (err: unknown) {
      error(`加载分组编排失败：${err instanceof Error ? err.message : '未知错误'}`);
    } finally {
      setLoading(false);
    }
  }, [error]);

  useEffect(() => {
    void loadInitial();
  }, [loadInitial]);

  const runLivePreview = useCallback(async (content: string) => {
    const seq = ++previewSeqRef.current;
    setPreviewing(true);
    try {
      const res = await clientApi.previewGroups(content);
      if (seq !== previewSeqRef.current) return;
      if (!res.ok) {
        setPreviewError(res.error || 'YAML 校验未通过');
      } else {
        setPreviewError('');
        if (res.preview) {
          setPreview(res.preview);
        }
        if (res.hasLiveConfig !== undefined) {
          setHasLiveConfig(res.hasLiveConfig);
        }
      }
    } catch (err: unknown) {
      if (seq !== previewSeqRef.current) return;
      setPreviewError(err instanceof Error ? err.message : '预览请求失败');
    } finally {
      if (seq === previewSeqRef.current) {
        setPreviewing(false);
      }
    }
  }, []);

  // 输入防抖实时干跑预览（240ms）
  const initialLoadedRef = useRef(false);
  useEffect(() => {
    if (loading) return;
    if (!initialLoadedRef.current) {
      initialLoadedRef.current = true;
      return;
    }
    const timer = window.setTimeout(() => {
      void runLivePreview(yamlText);
    }, 240);
    return () => window.clearTimeout(timer);
  }, [yamlText, loading, runLivePreview]);

  const isDirty = yamlText !== savedContent;

  const handleInsertMacro = (macroId: string) => {
    const el = textareaRef.current;
    if (!el) {
      void navigator.clipboard?.writeText(`"${macroId}"`);
      toast(`已复制语义宏 "${macroId}"`, 'info');
      return;
    }
    const start = el.selectionStart ?? yamlText.length;
    const end = el.selectionEnd ?? yamlText.length;
    // 若光标已在引号内则直接插入 @xx，否则插入 "@xx"
    const beforeChar = start > 0 ? yamlText[start - 1] : '';
    const insertToken = beforeChar === '"' || beforeChar === "'" ? macroId : `"${macroId}"`;
    const next = yamlText.slice(0, start) + insertToken + yamlText.slice(end);
    setYamlText(next);
    window.requestAnimationFrame(() => {
      el.focus();
      const cursor = start + insertToken.length;
      el.setSelectionRange(cursor, cursor);
    });
  };

  const handleApplyTemplate = (tpl: GroupTemplateSnippet) => {
    setYamlText(tpl.content);
    toast(`已载入模板「${tpl.name}」，右侧已实时更新节点命中预览`, 'info');
  };

  const handleEditorKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === 'Tab') {
      e.preventDefault();
      const el = e.currentTarget;
      const start = el.selectionStart;
      const end = el.selectionEnd;
      const next = yamlText.slice(0, start) + '  ' + yamlText.slice(end);
      setYamlText(next);
      window.requestAnimationFrame(() => {
        el.selectionStart = el.selectionEnd = start + 2;
      });
    } else if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 's') {
      e.preventDefault();
      if (!saving && !previewError) {
        void handleSave();
      }
    }
  };

  const handleSave = async () => {
    setSaving(true);
    try {
      const res = await clientApi.saveGroups({ content: yamlText });
      setFileExists(res.exists);
      setSavedContent(res.content);
      setYamlText(res.content);
      if (res.preview) setPreview(res.preview);
      setPreviewError('');
      success(res.message || '分组配置已保存并热重载生效');
      onApplied(res.routingReport);
    } catch (err: unknown) {
      error(`保存失败：${err instanceof Error ? err.message : '未知错误'}`);
    } finally {
      setSaving(false);
    }
  };

  const handleReset = async () => {
    setResetting(true);
    try {
      const res = await clientApi.saveGroups({ reset: true });
      setResetConfirmOpen(false);
      setFileExists(false);
      setSavedContent(res.content);
      setYamlText(res.content);
      if (res.preview) setPreview(res.preview);
      setPreviewError('');
      success(res.message || '已恢复默认内置策略组');
      onApplied(res.routingReport);
    } catch (err: unknown) {
      error(`恢复默认失败：${err instanceof Error ? err.message : '未知错误'}`);
    } finally {
      setResetting(false);
    }
  };

  const groupNameSet = useMemo(() => {
    const s = new Set<string>(['#DC']);
    for (const g of preview?.groups || []) {
      s.add(g.name);
    }
    return s;
  }, [preview]);

  const customGroupCount = useMemo(
    () => (preview?.groups || []).filter((g) => g.customized || !g.builtin).length,
    [preview],
  );

  return (
    <div className="space-y-4">
      <SectionCard
        title="声明式分组编排 (groups.yaml)"
        icon={<Layers className="w-4 h-4" />}
        subtitle={`${filePath} · 零节点隐私凭据 · 订阅变化自动动态归类`}
        actions={
          <div className="flex flex-wrap items-center gap-2">
            <Badge tone={fileExists ? 'ok' : 'neutral'}>
              {fileExists ? `已启用 (${customGroupCount} 项定制)` : '未创建 (当前为默认内置组)'}
            </Badge>
            {isDirty && <Badge tone="warn">有未保存修改</Badge>}
            <Button
              size="xs"
              disabled={loading || saving || busy}
              onClick={() => void loadInitial()}
              icon={<RefreshCw className="w-3 h-3" />}
            >
              重新加载
            </Button>
            {fileExists && (
              <Button
                size="xs"
                variant="secondary"
                disabled={loading || saving || resetting || busy}
                onClick={() => setResetConfirmOpen(true)}
                icon={<RotateCcw className="w-3 h-3" />}
              >
                恢复内置默认
              </Button>
            )}
            <Button
              size="xs"
              variant="primary"
              loading={saving}
              disabled={loading || Boolean(previewError) || busy}
              onClick={() => void handleSave()}
              icon={<Save className="w-3 h-3" />}
            >
              保存并热应用
            </Button>
          </div>
        }
      >
        <div className="space-y-4">
          {/* 快捷模板与语义宏工具栏 */}
          <div className="p-3 rounded-xl bg-surface2 border border-subtle space-y-2.5">
            <div className="flex flex-wrap items-center gap-2">
              <span className="inline-flex items-center gap-1 text-xs font-medium text-secondary">
                <Wand2 className="w-3.5 h-3.5 text-[var(--accent)]" />
                一键载入常用模板：
              </span>
              {templates.map((tpl) => (
                <button
                  key={tpl.id}
                  type="button"
                  title={tpl.description}
                  onClick={() => handleApplyTemplate(tpl)}
                  className="px-2.5 py-1 rounded-lg bg-surface1 hover:bg-[var(--accent)]/15 border border-subtle hover:border-[var(--accent)]/40 text-xs text-primary transition-colors"
                >
                  {tpl.name}
                </button>
              ))}
            </div>

            {macros.length > 0 && (
              <div className="flex flex-wrap items-center gap-1.5 pt-1 border-t border-subtle/60">
                <span className="inline-flex items-center gap-1 text-[11px] text-muted mr-1">
                  <Sparkles className="w-3 h-3 text-[var(--accent)]" />
                  点击插入语义宏：
                </span>
                {macros.map((m) => (
                  <button
                    key={m.id}
                    type="button"
                    title={m.description}
                    onClick={() => handleInsertMacro(m.id)}
                    className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md bg-surface1 hover:bg-surface3 border border-subtle text-[11px] font-mono text-secondary hover:text-primary transition-colors"
                  >
                    <span className="text-[var(--accent)] font-semibold">{m.id}</span>
                    <span className="font-sans text-muted">{m.label}</span>
                  </button>
                ))}
              </div>
            )}
          </div>

          {/* 左右双栏：YAML 编辑器 + 实时干跑节点命中预览 */}
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-4 items-start">
            {/* 左栏：YAML 编辑器 */}
            <div className="lg:col-span-6 space-y-2">
              <div className="flex items-center justify-between text-xs text-secondary px-0.5">
                <span className="font-medium">YAML 规则定义（支持 Ctrl/Cmd + S 快捷保存）</span>
                <span className="text-[11px] text-muted">
                  {previewing ? '正在实时计算命中…' : previewError ? '语法待修正' : '语法校验通过'}
                </span>
              </div>

              <textarea
                ref={textareaRef}
                value={yamlText}
                onChange={(e) => setYamlText(e.target.value)}
                onKeyDown={handleEditorKeyDown}
                spellCheck={false}
                rows={22}
                placeholder="在此编写 groups.yaml 分组规则…"
                className="w-full p-3.5 rounded-xl bg-[var(--console-bg)] text-slate-200 border border-subtle font-mono text-xs leading-relaxed focus:outline-none focus:border-strong"
              />

              {previewError && (
                <div className="flex items-start gap-2 p-3 rounded-xl bg-rose-500/10 border border-rose-500/30 text-xs text-rose-300">
                  <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5 text-rose-400" />
                  <div className="space-y-0.5 break-all">
                    <div className="font-medium text-rose-200">规则校验提示</div>
                    <div>{previewError}</div>
                  </div>
                </div>
              )}

              <p className="text-[11px] text-muted leading-relaxed">
                防断网保障：当任意分组暂时匹配到 0 个节点时，编译器会自动回退至兜底出站（默认{' '}
                <code className="font-mono">#Auto</code> / <code className="font-mono">#DC</code>
                ），确保 <code className="font-mono">sing-box check</code> 始终通过；保存时通过 SIGHUP
                无损热重载，不断开现有连接。
              </p>
            </div>

            {/* 右栏：实时干跑预览 */}
            <div className="lg:col-span-6 space-y-2.5">
              <div className="flex flex-wrap items-center justify-between gap-2 px-0.5">
                <div className="flex items-center gap-2 text-xs">
                  <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                  <span className="font-medium text-secondary">实时节点命中预览</span>
                  {preview && (
                    <span className="text-muted">
                      模式 <code className="font-mono text-primary">{preview.mode}</code> · 共{' '}
                      <strong className="text-primary">{preview.groups?.length || 0}</strong> 个策略组
                    </span>
                  )}
                </div>

                {preview && preview.totalLeafNodes > 0 && (
                  <button
                    type="button"
                    onClick={() => setShowLeafPool((v) => !v)}
                    className="inline-flex items-center gap-1 text-xs text-[var(--accent)] hover:underline"
                  >
                    底层节点池 ({preview.totalLeafNodes})
                    {showLeafPool ? (
                      <ChevronUp className="w-3.5 h-3.5" />
                    ) : (
                      <ChevronDown className="w-3.5 h-3.5" />
                    )}
                  </button>
                )}
              </div>

              {/* 可展开的当前全部底层节点池参考清单 */}
              {showLeafPool && preview && preview.leafNodes?.length > 0 && (
                <div className="p-3 rounded-xl bg-surface2 border border-subtle space-y-2 max-h-44 overflow-y-auto">
                  <div className="text-[11px] text-muted flex flex-wrap items-center justify-between gap-1">
                    <span>当前订阅解析出的全部真实节点（可用于核对关键字 / 协议 / 订阅名）：</span>
                    {preview.subNames && preview.subNames.length > 0 && (
                      <span>
                        订阅源：<code className="font-mono text-primary">{preview.subNames.join(', ')}</code>
                      </span>
                    )}
                  </div>
                  <div className="flex flex-wrap gap-1.5">
                    {preview.leafNodes.map((n) => (
                      <span
                        key={n.tag}
                        className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md bg-surface1 border border-subtle text-[11px] font-mono text-primary"
                      >
                        <span>{n.tag}</span>
                        <span className="text-[10px] text-muted uppercase">{n.type}</span>
                        {n.subs && n.subs.length > 0 && (
                          <span className="text-[10px] text-[var(--accent)]">@{n.subs.join('/')}</span>
                        )}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {/* 编译器告警提示（例如 0 节点自动触发防断网兜底） */}
              {preview?.warnings && preview.warnings.length > 0 && (
                <div className="p-2.5 rounded-xl bg-amber-500/10 border border-amber-500/30 space-y-1 text-xs text-amber-200">
                  {preview.warnings.map((w, idx) => (
                    <div key={idx} className="flex items-start gap-1.5">
                      <AlertTriangle className="w-3.5 h-3.5 shrink-0 mt-0.5 text-amber-400" />
                      <span>{w}</span>
                    </div>
                  ))}
                </div>
              )}

              {!hasLiveConfig ? (
                <div className="p-6 rounded-xl bg-surface2 border border-subtle text-center text-xs text-muted">
                  当前尚未生成本地 <code className="font-mono">config.json</code>。你仍可先编写并保存{' '}
                  <code className="font-mono">groups.yaml</code>，下次启动或更新配置时将自动生效。
                </div>
              ) : (
                <div className="space-y-2 max-h-[540px] overflow-y-auto pr-0.5">
                  {(preview?.groups || []).map((g) => {
                    const isCustom = g.customized || !g.builtin;
                    return (
                      <div
                        key={g.name}
                        className={`p-3 rounded-xl border transition-colors ${
                          isCustom
                            ? 'bg-surface2/90 border-[var(--accent)]/35'
                            : 'bg-surface2/50 border-subtle'
                        }`}
                      >
                        <div className="flex flex-wrap items-center justify-between gap-2">
                          <div className="flex flex-wrap items-center gap-1.5">
                            <span className="font-mono text-sm font-semibold text-primary">
                              {g.name}
                            </span>
                            <Badge tone={g.type === 'urltest' ? 'accent' : 'neutral'}>
                              {g.type === 'urltest' ? '自动测速 urltest' : '手动选择 selector'}
                            </Badge>
                            {!g.builtin ? (
                              <Badge tone="ok">新增分组</Badge>
                            ) : g.customized ? (
                              <Badge tone="accent">内置·已定制</Badge>
                            ) : (
                              <Badge tone="neutral">内置</Badge>
                            )}
                            {g.failover && (
                              <Badge tone="ok">
                                <ShieldCheck className="w-3 h-3 inline mr-0.5" />
                                看门狗容灾
                              </Badge>
                            )}
                            {g.fallbackUsed && (
                              <Badge tone="warn">0节点兜底 → {g.fallbackTag}</Badge>
                            )}
                          </div>

                          <div className="flex items-center gap-2 text-[11px]">
                            <span className="text-muted font-mono">{g.totalCount} 项</span>
                            {!isDirty && (
                              <>
                                <button
                                  type="button"
                                  onClick={() => onJumpToGroup(g.name)}
                                  className="inline-flex items-center gap-0.5 text-secondary hover:text-primary"
                                  title="跳转至节点选择查看该策略组"
                                >
                                  选节点
                                  <ArrowRight className="w-3 h-3" />
                                </button>
                                <button
                                  type="button"
                                  onClick={onJumpToRouting}
                                  className="inline-flex items-center gap-0.5 text-[var(--accent)] hover:underline"
                                  title="前往智能分流开关中心将业务流量绑定到此分组"
                                >
                                  绑分流
                                  <ArrowRight className="w-3 h-3" />
                                </button>
                              </>
                            )}
                          </div>
                        </div>

                        {(g.attachedTo?.length || g.default) && (
                          <div className="mt-1.5 flex flex-wrap items-center gap-3 text-[11px] text-muted">
                            {g.attachedTo && g.attachedTo.length > 0 && (
                              <span>
                                挂载至：<code className="font-mono text-secondary">{g.attachedTo.join(', ')}</code>
                              </span>
                            )}
                            {g.default && (
                              <span>
                                默认首选：<code className="font-mono text-secondary">{g.default}</code>
                              </span>
                            )}
                          </div>
                        )}

                        <div className="mt-2 flex flex-wrap gap-1.5">
                          {g.members.slice(0, 28).map((m) => {
                            const isSubGroup = groupNameSet.has(m);
                            return (
                              <span
                                key={m}
                                className={`px-2 py-0.5 rounded-md text-[11px] font-mono border ${
                                  isSubGroup
                                    ? 'bg-[var(--accent)]/10 border-[var(--accent)]/30 text-[var(--accent)]'
                                    : 'bg-surface1 border-subtle text-secondary'
                                }`}
                              >
                                {m}
                              </span>
                            );
                          })}
                          {g.members.length > 28 && (
                            <span className="px-2 py-0.5 rounded-md text-[11px] text-muted bg-surface1 border border-subtle">
                              +{g.members.length - 28} 更多…
                            </span>
                          )}
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          </div>
        </div>
      </SectionCard>

      <ConfirmDialog
        open={resetConfirmOpen}
        title="恢复默认内置策略组"
        description="确认移除自定义 groups.yaml 配置并恢复为系统内置默认分组（Proxy / AI / #VPS / #Auto / #Nodes）？曾绑定到自定义分组的分流项也将安全回退默认推荐组。"
        confirmText="确认恢复默认"
        loading={resetting}
        onConfirm={() => void handleReset()}
        onCancel={() => setResetConfirmOpen(false)}
      />
    </div>
  );
};

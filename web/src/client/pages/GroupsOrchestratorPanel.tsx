import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  AlertTriangle,
  ArrowRight,
  CheckCircle2,
  ChevronDown,
  ChevronUp,
  Download,
  Layers,
  Plus,
  RefreshCw,
  RotateCcw,
  Save,
  ShieldCheck,
  Sparkles,
  Upload,
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

function parseYAMLErrorLine(errMsg: string): number | null {
  if (!errMsg) return null;
  const m = /\bline\s+(\d+)\b/i.exec(errMsg);
  if (!m) return null;
  const n = Number(m[1]);
  return Number.isFinite(n) && n > 0 ? n : null;
}

function computeNextGroupName(yamlText: string): string {
  if (!yamlText.includes('"#New"') && !yamlText.includes(" '#New'") && !/name:\s*#New\b/.test(yamlText)) {
    return '#New';
  }
  for (let i = 2; i < 100; i++) {
    const cand = `#New${i}`;
    if (!yamlText.includes(cand)) return cand;
  }
  return `#New${Date.now() % 1000}`;
}

function appendGroupSnippetToYAML(text: string): { next: string; groupName: string; focusLine: number } {
  const groupName = computeNextGroupName(text);
  const snippetLines = [
    `  - name: "${groupName}"`,
    `    type: urltest`,
    `    match: ["@hk"]`,
    `    exclude: ["@high_rate"]`,
  ];
  const snippet = snippetLines.join('\n');

  const lines = text.split('\n');
  // 场景 1: 空列表占位 `groups: []` —— 原地展开并保留其后的注释示例
  const emptyListIdx = lines.findIndex((ln) => /^groups:\s*\[\]\s*(#.*)?$/.test(ln));
  if (emptyListIdx >= 0) {
    lines.splice(emptyListIdx, 1, 'groups:', ...snippetLines);
    return {
      next: lines.join('\n'),
      groupName,
      focusLine: emptyListIdx + 2,
    };
  }

  // 场景 2: 已有 `groups:` —— 插入到最后一个有效条目之后（不破坏底部注释示例）
  const groupsHeaderIdx = lines.findIndex((ln) => /^groups:\s*(#.*)?$/.test(ln));
  if (groupsHeaderIdx >= 0) {
    let insertAfter = groupsHeaderIdx;
    for (let i = groupsHeaderIdx + 1; i < lines.length; i++) {
      const ln = lines[i];
      if (/^[a-zA-Z_][a-zA-Z0-9_-]*\s*:/.test(ln)) {
        // 遇到新的顶层 key，结束 groups 区块
        break;
      }
      if (/^\s+\S/.test(ln)) {
        insertAfter = i;
      }
    }
    const toInsert = insertAfter > groupsHeaderIdx ? ['', ...snippetLines] : snippetLines;
    lines.splice(insertAfter + 1, 0, ...toInsert);
    return {
      next: lines.join('\n'),
      groupName,
      focusLine: insertAfter + 1 + (insertAfter > groupsHeaderIdx ? 2 : 1),
    };
  }

  // 场景 3: 文本尚无 `groups:` —— 末尾补充完整块
  const trimmed = text.replace(/\s+$/, '');
  const prefix = trimmed ? `${trimmed}\n\ngroups:\n` : 'version: 1\nmode: merge\n\ngroups:\n';
  const focusLine = prefix.split('\n').length;
  return {
    next: `${prefix}${snippet}\n`,
    groupName,
    focusLine,
  };
}

function hasCustomDraftContent(yamlText: string): boolean {
  const activeLines = yamlText
    .split('\n')
    .map((l) => l.trim())
    .filter((l) => l !== '' && !l.startsWith('#'));
  // 若仅剩 version/mode/groups: [] 三行默认骨架，视为可安全直接套用示例
  if (activeLines.length <= 3 && activeLines.some((l) => /^groups:\s*\[\]/.test(l))) {
    return false;
  }
  return activeLines.length > 0;
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
  const [pendingTemplate, setPendingTemplate] = useState<GroupTemplateSnippet | null>(null);

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
  const [templateSelectVal, setTemplateSelectVal] = useState('');

  const textareaRef = useRef<HTMLTextAreaElement | null>(null);
  const gutterRef = useRef<HTMLDivElement | null>(null);
  const importInputRef = useRef<HTMLInputElement | null>(null);
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
  const lineCount = useMemo(() => Math.max(1, yamlText.split('\n').length), [yamlText]);
  const errorLine = useMemo(() => parseYAMLErrorLine(previewError), [previewError]);

  const syncGutterScroll = () => {
    if (gutterRef.current && textareaRef.current) {
      gutterRef.current.scrollTop = textareaRef.current.scrollTop;
    }
  };

  const jumpToLine = useCallback(
    (lineNum: number) => {
      const el = textareaRef.current;
      if (!el || lineNum < 1) return;
      const lines = yamlText.split('\n');
      const targetIdx = Math.min(lineNum - 1, Math.max(0, lines.length - 1));
      let offset = 0;
      for (let i = 0; i < targetIdx; i++) {
        offset += lines[i].length + 1;
      }
      el.focus();
      el.setSelectionRange(offset, offset + lines[targetIdx].length);
      const lineHeightPx = 20;
      const targetTop = Math.max(0, targetIdx * lineHeightPx - el.clientHeight / 3);
      el.scrollTop = targetTop;
      if (gutterRef.current) {
        gutterRef.current.scrollTop = targetTop;
      }
    },
    [yamlText],
  );

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

  const handleAppendGroup = () => {
    const { next, groupName, focusLine } = appendGroupSnippetToYAML(yamlText);
    setYamlText(next);
    toast(`已追加新分组骨架 "${groupName}"，请按需修改名称与匹配规则`, 'info');
    window.requestAnimationFrame(() => {
      const el = textareaRef.current;
      if (!el) return;
      const lines = next.split('\n');
      const idx = Math.max(0, Math.min(focusLine - 1, lines.length - 1));
      let offset = 0;
      for (let i = 0; i < idx; i++) {
        offset += lines[i].length + 1;
      }
      const quoteStart = lines[idx].indexOf('"');
      const quoteEnd = lines[idx].lastIndexOf('"');
      el.focus();
      if (quoteStart >= 0 && quoteEnd > quoteStart) {
        el.setSelectionRange(offset + quoteStart + 1, offset + quoteEnd);
      } else {
        el.setSelectionRange(offset, offset + lines[idx].length);
      }
      const lineHeightPx = 20;
      const targetTop = Math.max(0, idx * lineHeightPx - el.clientHeight / 3);
      el.scrollTop = targetTop;
      if (gutterRef.current) gutterRef.current.scrollTop = targetTop;
    });
  };

  const applyTemplateContent = (tpl: GroupTemplateSnippet) => {
    setYamlText(tpl.content);
    setPendingTemplate(null);
    setTemplateSelectVal('');
    toast(`已套用示例「${tpl.name}」，右侧已实时更新节点命中预览`, 'info');
  };

  const handleSelectTemplate = (tplId: string) => {
    setTemplateSelectVal('');
    const tpl = templates.find((t) => t.id === tplId);
    if (!tpl) return;
    if (isDirty || hasCustomDraftContent(yamlText)) {
      setPendingTemplate(tpl);
      return;
    }
    applyTemplateContent(tpl);
  };

  const handleExportYAML = () => {
    try {
      const blob = new Blob([yamlText], { type: 'text/yaml;charset=utf-8' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = 'groups.yaml';
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
      toast('已导出 groups.yaml（零节点隐私，可直接用于其他设备）', 'info');
    } catch (err: unknown) {
      error(`导出失败：${err instanceof Error ? err.message : '未知错误'}`);
    }
  };

  const handleImportFile = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    e.target.value = '';
    if (!file) return;
    if (file.size > 512 * 1024) {
      error('文件过大：groups.yaml 不能超过 512 KB');
      return;
    }
    try {
      const text = await file.text();
      setYamlText(text);
      toast(`已导入 ${file.name}，右侧已实时预览；确认无误后请点击「保存并热应用」`, 'info');
    } catch (err: unknown) {
      error(`读取文件失败：${err instanceof Error ? err.message : '未知错误'}`);
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

  const handleEditorKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    const el = e.currentTarget;
    const start = el.selectionStart;
    const end = el.selectionEnd;

    if (e.key === 'Tab') {
      e.preventDefault();
      if (e.shiftKey) {
        // Shift+Tab: 反缩进当前行首最多 2 个空格
        const lineStart = yamlText.lastIndexOf('\n', start - 1) + 1;
        const linePrefix = yamlText.slice(lineStart, lineStart + 2);
        let removeCount = 0;
        if (linePrefix === '  ') removeCount = 2;
        else if (linePrefix.startsWith(' ')) removeCount = 1;
        if (removeCount > 0) {
          const next = yamlText.slice(0, lineStart) + yamlText.slice(lineStart + removeCount);
          setYamlText(next);
          window.requestAnimationFrame(() => {
            const nextStart = Math.max(lineStart, start - removeCount);
            const nextEnd = Math.max(nextStart, end - removeCount);
            el.setSelectionRange(nextStart, nextEnd);
          });
        }
        return;
      }
      const next = yamlText.slice(0, start) + '  ' + yamlText.slice(end);
      setYamlText(next);
      window.requestAnimationFrame(() => {
        el.setSelectionRange(start + 2, start + 2);
      });
      return;
    }

    if (e.key === 'Enter' && start === end) {
      e.preventDefault();
      const lineStart = yamlText.lastIndexOf('\n', start - 1) + 1;
      const lineBeforeCursor = yamlText.slice(lineStart, start);
      const indentMatch = /^(\s*)/.exec(lineBeforeCursor);
      let nextIndent = indentMatch ? indentMatch[1] : '';
      const trimmedBefore = lineBeforeCursor.trim();
      // `groups:` 或 `  - name: "#HK"` 之后自动加 2 空格缩进
      if (trimmedBefore.endsWith(':') || /^-\s+[^#\s][^:]*:/.test(trimmedBefore)) {
        nextIndent += '  ';
      }
      const insertion = `\n${nextIndent}`;
      const next = yamlText.slice(0, start) + insertion + yamlText.slice(end);
      setYamlText(next);
      window.requestAnimationFrame(() => {
        const cursor = start + insertion.length;
        el.setSelectionRange(cursor, cursor);
      });
      return;
    }

    if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 's') {
      e.preventDefault();
      if (!saving && !previewError) {
        void handleSave();
      }
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
        subtitle={`${filePath} · 约定优于配置 · 零节点隐私可跨设备复用`}
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
          {/* 左右双栏：轻量增强 YAML 编辑器 + 实时干跑命中预览 */}
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-4 items-start">
            {/* 左栏：YAML 编辑器 + 紧凑工具栏 + 宏速查条 */}
            <div className="lg:col-span-6 space-y-2">
              <div className="flex flex-wrap items-center justify-between gap-2 px-0.5">
                <div className="flex flex-wrap items-center gap-1.5">
                  <Button
                    size="xs"
                    variant="secondary"
                    disabled={loading}
                    onClick={handleAppendGroup}
                    icon={<Plus className="w-3 h-3" />}
                  >
                    新分组
                  </Button>
                  {templates.length > 0 && (
                    <select
                      aria-label="套用示例模板"
                      value={templateSelectVal}
                      onChange={(e) => handleSelectTemplate(e.target.value)}
                      className="h-7 px-2 rounded-lg bg-surface2 border border-subtle text-xs text-primary focus:outline-none focus:border-strong cursor-pointer"
                    >
                      <option value="">套用示例 ▾</option>
                      {templates.map((tpl) => (
                        <option key={tpl.id} value={tpl.id}>
                          {tpl.name}
                        </option>
                      ))}
                    </select>
                  )}
                  <input
                    ref={importInputRef}
                    type="file"
                    accept=".yaml,.yml,text/yaml,text/plain"
                    className="hidden"
                    onChange={(e) => void handleImportFile(e)}
                  />
                  <Button
                    size="xs"
                    disabled={loading}
                    onClick={() => importInputRef.current?.click()}
                    icon={<Upload className="w-3 h-3" />}
                    title="从本地导入 groups.yaml"
                  >
                    导入
                  </Button>
                  <Button
                    size="xs"
                    disabled={loading || !yamlText.trim()}
                    onClick={handleExportYAML}
                    icon={<Download className="w-3 h-3" />}
                    title="导出当前 groups.yaml 文件"
                  >
                    导出
                  </Button>
                </div>

                <span className="text-[11px] text-muted">
                  {previewing ? '实时校验中…' : previewError ? '待修正' : 'Ctrl/Cmd+S 保存'}
                </span>
              </div>

              {/* 紧凑单行内置语义宏速查与点击插入条 */}
              {macros.length > 0 && (
                <div className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-xl bg-surface2/80 border border-subtle overflow-x-auto">
                  <span className="inline-flex items-center gap-1 text-[11px] text-muted shrink-0">
                    <Sparkles className="w-3 h-3 text-[var(--accent)]" />
                    宏:
                  </span>
                  {macros.map((m) => (
                    <button
                      key={m.id}
                      type="button"
                      title={m.description}
                      onClick={() => handleInsertMacro(m.id)}
                      className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded bg-surface1 hover:bg-[var(--accent)]/15 border border-subtle text-[11px] font-mono text-secondary hover:text-primary shrink-0 transition-colors"
                    >
                      <span className="text-[var(--accent)] font-semibold">{m.id}</span>
                      <span className="font-sans text-muted">{m.label}</span>
                    </button>
                  ))}
                </div>
              )}

              {/* 带行号槽与错行高亮的轻量级 YAML 编辑器 */}
              <div className="flex rounded-xl bg-[var(--console-bg)] border border-subtle focus-within:border-strong overflow-hidden">
                <div
                  ref={gutterRef}
                  aria-hidden="true"
                  className="w-10 shrink-0 py-3 pr-2 bg-black/20 border-r border-white/10 font-mono text-xs leading-[20px] text-right text-slate-500 select-none overflow-hidden h-[464px]"
                >
                  {Array.from({ length: lineCount }, (_, idx) => {
                    const lineNo = idx + 1;
                    const isErr = errorLine === lineNo;
                    return (
                      <div
                        key={lineNo}
                        onClick={isErr ? () => jumpToLine(lineNo) : undefined}
                        title={isErr ? '点击定位到错误行' : undefined}
                        className={`px-1 ${
                          isErr
                            ? 'bg-rose-500/30 text-rose-200 font-semibold cursor-pointer rounded-l'
                            : ''
                        }`}
                      >
                        {lineNo}
                      </div>
                    );
                  })}
                </div>
                <textarea
                  ref={textareaRef}
                  value={yamlText}
                  onChange={(e) => setYamlText(e.target.value)}
                  onScroll={syncGutterScroll}
                  onKeyDown={handleEditorKeyDown}
                  spellCheck={false}
                  wrap="off"
                  placeholder="在此编写 groups.yaml 分组规则…"
                  className="flex-1 h-[464px] py-3 px-3 bg-transparent text-slate-200 font-mono text-xs leading-[20px] whitespace-pre overflow-auto focus:outline-none resize-none"
                />
              </div>

              {previewError && (
                <button
                  type="button"
                  onClick={errorLine ? () => jumpToLine(errorLine) : undefined}
                  className={`w-full text-left flex items-start gap-2 p-3 rounded-xl bg-rose-500/10 border border-rose-500/30 text-xs text-rose-300 ${
                    errorLine ? 'hover:bg-rose-500/15 cursor-pointer' : 'cursor-default'
                  }`}
                >
                  <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5 text-rose-400" />
                  <div className="space-y-0.5 break-all">
                    <div className="font-medium text-rose-200">
                      规则校验提示{errorLine ? `（第 ${errorLine} 行 · 点击定位）` : ''}
                    </div>
                    <div>{previewError}</div>
                  </div>
                </button>
              )}

              <p className="text-[11px] text-muted leading-relaxed">
                防断网保障：匹配 0 节点自动兜底至 <code className="font-mono">#Auto</code> /{' '}
                <code className="font-mono">#DC</code>；<code className="font-mono">replace</code>{' '}
                模式下默认兜底优先匹配 <code className="font-mono">Proxy</code> 否则取第 1 个组，海外 DNS 优先匹配{' '}
                <code className="font-mono">#VPS</code> 否则跟随默认兜底组。
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
                      模式 <code className="font-mono text-primary">{preview.mode}</code> ·{' '}
                      <strong className="text-primary">{preview.groups?.length || 0}</strong> 组
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

              {/* 约定生效状态只读透视条 */}
              {hasLiveConfig && preview && (
                <div className="flex flex-wrap items-center gap-x-4 gap-y-1 px-3 py-1.5 rounded-xl bg-surface2 border border-subtle text-[11px] text-secondary">
                  <span>
                    未匹配规则默认兜底：
                    <code className="font-mono font-semibold text-primary">
                      {preview.defaultOutbound || 'Proxy'}
                    </code>
                  </span>
                  <span>
                    海外 DNS (<code className="font-mono">dns_proxy</code>) 出口：
                    <code className="font-mono font-semibold text-primary">
                      {preview.dnsDetour || '#VPS'}
                    </code>
                  </span>
                </div>
              )}

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

              {/* 编译器告警提示（例如 0 节点自动触发防断网兜底 / replace 自动接管提示） */}
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
                <div className="space-y-2 max-h-[464px] overflow-y-auto pr-0.5">
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
        open={Boolean(pendingTemplate)}
        title="使用示例模板覆盖当前内容"
        description={
          pendingTemplate
            ? `确认用示例模板「${pendingTemplate.name}」替换当前编辑器内容？你当前编写的规则将先被替换，未点保存前暂不影响网关运行。`
            : ''
        }
        confirmText="确认覆盖"
        onConfirm={() => pendingTemplate && applyTemplateContent(pendingTemplate)}
        onCancel={() => setPendingTemplate(null)}
      />

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

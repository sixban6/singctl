import React, { useCallback, useMemo, useRef } from 'react';
import { AlertTriangle, Download, Plus, Sparkles, Upload } from 'lucide-react';
import { Button, useToast } from '../../../ui';
import { copyToClipboard } from '../../../lib/clipboard';
import { GroupMacroInfo, GroupTemplateSnippet } from '../../types';
import { appendGroupSnippetToYAML, parseYAMLErrorLine } from './groupsYamlHelpers';

export interface GroupsYamlEditorPaneProps {
  loading: boolean;
  saving: boolean;
  previewing: boolean;
  previewError: string;
  yamlText: string;
  onYamlTextChange: (next: string) => void;
  macros: GroupMacroInfo[];
  templates: GroupTemplateSnippet[];
  templateSelectVal: string;
  onSelectTemplate: (tplId: string) => void;
  onSaveShortcut: () => void;
}

export const GroupsYamlEditorPane: React.FC<GroupsYamlEditorPaneProps> = ({
  loading,
  saving,
  previewing,
  previewError,
  yamlText,
  onYamlTextChange,
  macros,
  templates,
  templateSelectVal,
  onSelectTemplate,
  onSaveShortcut,
}) => {
  const { error, toast } = useToast();
  const textareaRef = useRef<HTMLTextAreaElement | null>(null);
  const gutterRef = useRef<HTMLDivElement | null>(null);
  const importInputRef = useRef<HTMLInputElement | null>(null);

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
      void copyToClipboard(`"${macroId}"`)
        .then(() => toast(`已复制语义宏 "${macroId}"`, 'info'))
        .catch(() => error('复制失败，请手动复制'));
      return;
    }
    const start = el.selectionStart ?? yamlText.length;
    const end = el.selectionEnd ?? yamlText.length;
    const beforeChar = start > 0 ? yamlText[start - 1] : '';
    const insertToken = beforeChar === '"' || beforeChar === "'" ? macroId : `"${macroId}"`;
    const next = yamlText.slice(0, start) + insertToken + yamlText.slice(end);
    onYamlTextChange(next);
    window.requestAnimationFrame(() => {
      el.focus();
      const cursor = start + insertToken.length;
      el.setSelectionRange(cursor, cursor);
    });
  };

  const handleAppendGroup = () => {
    const { next, groupName, focusLine } = appendGroupSnippetToYAML(yamlText);
    onYamlTextChange(next);
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
      onYamlTextChange(text);
      toast(`已导入 ${file.name}，右侧已实时预览；确认无误后请点击「保存并热应用」`, 'info');
    } catch (err: unknown) {
      error(`读取文件失败：${err instanceof Error ? err.message : '未知错误'}`);
    }
  };

  const handleEditorKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    const el = e.currentTarget;
    const start = el.selectionStart;
    const end = el.selectionEnd;

    if (e.key === 'Tab') {
      e.preventDefault();
      if (e.shiftKey) {
        const lineStart = yamlText.lastIndexOf('\n', start - 1) + 1;
        const linePrefix = yamlText.slice(lineStart, lineStart + 2);
        let removeCount = 0;
        if (linePrefix === '  ') removeCount = 2;
        else if (linePrefix.startsWith(' ')) removeCount = 1;
        if (removeCount > 0) {
          const next = yamlText.slice(0, lineStart) + yamlText.slice(lineStart + removeCount);
          onYamlTextChange(next);
          window.requestAnimationFrame(() => {
            const nextStart = Math.max(lineStart, start - removeCount);
            const nextEnd = Math.max(nextStart, end - removeCount);
            el.setSelectionRange(nextStart, nextEnd);
          });
        }
        return;
      }
      const next = yamlText.slice(0, start) + '  ' + yamlText.slice(end);
      onYamlTextChange(next);
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
      if (trimmedBefore.endsWith(':') || /^-\s+[^#\s][^:]*:/.test(trimmedBefore)) {
        nextIndent += '  ';
      }
      const insertion = `\n${nextIndent}`;
      const next = yamlText.slice(0, start) + insertion + yamlText.slice(end);
      onYamlTextChange(next);
      window.requestAnimationFrame(() => {
        const cursor = start + insertion.length;
        el.setSelectionRange(cursor, cursor);
      });
      return;
    }

    if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 's') {
      e.preventDefault();
      if (!saving && !previewError) {
        onSaveShortcut();
      }
    }
  };

  return (
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
              onChange={(e) => onSelectTemplate(e.target.value)}
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
          onChange={(e) => onYamlTextChange(e.target.value)}
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
  );
};

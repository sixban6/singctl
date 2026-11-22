import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { Layers, RefreshCw, RotateCcw, Save } from 'lucide-react';
import { Badge, Button, ConfirmDialog, SectionCard, useToast } from '../../ui';
import { clientApi } from '../api';
import {
  ClientGroupsGetResponse,
  ClientRoutingReport,
  GroupMacroInfo,
  GroupsPreviewReport,
  GroupTemplateSnippet,
} from '../types';
import { GroupsLivePreviewPane } from './groups/GroupsLivePreviewPane';
import { GroupsYamlEditorPane } from './groups/GroupsYamlEditorPane';
import { hasCustomDraftContent } from './groups/groupsYamlHelpers';

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
  const [templateSelectVal, setTemplateSelectVal] = useState('');

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
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-4 items-start">
          <GroupsYamlEditorPane
            loading={loading}
            saving={saving}
            previewing={previewing}
            previewError={previewError}
            yamlText={yamlText}
            onYamlTextChange={setYamlText}
            macros={macros}
            templates={templates}
            templateSelectVal={templateSelectVal}
            onSelectTemplate={handleSelectTemplate}
            onSaveShortcut={() => void handleSave()}
          />

          <GroupsLivePreviewPane
            preview={preview}
            hasLiveConfig={hasLiveConfig}
            isDirty={isDirty}
            onJumpToGroup={onJumpToGroup}
            onJumpToRouting={onJumpToRouting}
          />
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

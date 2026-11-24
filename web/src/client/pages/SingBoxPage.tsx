import React, { useState, useEffect, useCallback, useRef } from 'react';
import { Cpu, FileCode, Layers, Link2, SlidersHorizontal } from 'lucide-react';
import { Badge, Button, ConfirmDialog, PageHeader, SegmentedTabs, useToast } from '../../ui';
import { clientApi } from '../api';
import { useVisibilityInterval } from '../../hooks';
import {
  ClientRoutingPresetState,
  ClientRoutingReport,
  ClientStatusResponse,
  SbConfigResponse,
  SbProxiesSnapshot,
  SbProxyMode,
  SbTrafficSnapshot,
} from '../types';
import { ProxyNodesPanel } from './singbox/ProxyNodesPanel';
import { GroupsOrchestratorPanel } from './groups/GroupsOrchestratorPanel';
import { SubscriptionsPanel } from './singbox/SubscriptionsPanel';
import { SingBoxConfigEditorSection } from './singbox/SingBoxConfigEditorSection';
import { SingBoxControlBar } from './singbox/SingBoxControlBar';
import { SmartRoutingSection } from './singbox/SmartRoutingSection';

export interface SingBoxPageProps {
  status: ClientStatusResponse | null;
  busy: boolean;
  initialSub?: string;
  onSubChange?: (sub: string) => void;
  onAction: (name: string, params?: Record<string, unknown>, confirmMsg?: string) => void;
  onNavigate: (tab: string, sub?: string) => void;
  onRefreshStatus?: () => void;
}

type SbSubTab = 'routing' | 'nodes' | 'groups' | 'subs' | 'editor';

function normalizeSbSubTab(raw?: string): SbSubTab {
  if (raw === 'nodes') return 'nodes';
  if (raw === 'groups') return 'groups';
  if (raw === 'subs') return 'subs';
  if (raw === 'editor') return 'editor';
  return 'routing';
}

export const SingBoxPage: React.FC<SingBoxPageProps> = ({
  status,
  busy,
  initialSub,
  onSubChange,
  onAction,
  onNavigate,
  onRefreshStatus,
}) => {
  const { success, error, warn, toast } = useToast();
  const [sub, setSub] = useState<SbSubTab>(() => normalizeSbSubTab(initialSub));

  useEffect(() => {
    if (initialSub !== undefined) {
      setSub(normalizeSbSubTab(initialSub));
    }
  }, [initialSub]);

  const selectSubTab = (next: SbSubTab) => {
    setSub(next);
    onSubChange?.(next);
  };

  // 智能分流开关状态
  const [routing, setRouting] = useState<ClientRoutingReport | null>(null);
  const [routingLoading, setRoutingLoading] = useState(true);
  const [savingId, setSavingId] = useState<string | null>(null);
  const [resetConfirmOpen, setResetConfirmOpen] = useState(false);
  const [resetting, setResetting] = useState(false);

  // 原生策略组/节点选择 & 实时状态
  const [proxiesSnap, setProxiesSnap] = useState<SbProxiesSnapshot | null>(null);
  const [proxiesLoading, setProxiesLoading] = useState(false);
  const [traffic, setTraffic] = useState<SbTrafficSnapshot | null>(null);
  const [switchingMode, setSwitchingMode] = useState(false);
  const [focusGroup, setFocusGroup] = useState<string | null>(null);

  // config.json 编辑器状态
  const [sbCfg, setSbCfg] = useState<SbConfigResponse | null>(null);
  const [jsonText, setJsonText] = useState('');
  const [selectedBackup, setSelectedBackup] = useState('');
  const [savingCfg, setSavingCfg] = useState(false);
  const [preserveManual, setPreserveManual] = useState(true);
  const [togglingPreserve, setTogglingPreserve] = useState(false);
  const [restoreConfirmOpen, setRestoreConfirmOpen] = useState(false);

  const sb = status?.singbox;
  const sbRunning = Boolean(sb?.running);

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

  const loadProxies = useCallback(async (silent = false) => {
    if (!silent) setProxiesLoading(true);
    try {
      const data = await clientApi.getSbProxies();
      setProxiesSnap(data);
    } catch {
      // 网络短暂不可达时保留现有状态，避免界面闪烁
    } finally {
      if (!silent) setProxiesLoading(false);
    }
  }, []);

  const loadTraffic = useCallback(async () => {
    try {
      const data = await clientApi.getSbTraffic();
      setTraffic(data);
    } catch {
      // ignore transient telemetry failure
    }
  }, []);

  const loadSbConfig = useCallback(async () => {
    try {
      const d = await clientApi.getSbConfig();
      setSbCfg(d);
      setJsonText(d.content || '');
      setPreserveManual(d.preserveManualConfig !== false);
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

  useEffect(() => {
    if (sbRunning) {
      void loadProxies(false);
      void loadTraffic();
    } else {
      setProxiesSnap(null);
      setTraffic(null);
    }
  }, [sbRunning, loadProxies, loadTraffic]);

  useVisibilityInterval(
    () => {
      void loadTraffic();
    },
    sbRunning && sub !== 'editor' ? 3000 : null,
  );

  const prevBusyRef = useRef(busy);
  useEffect(() => {
    if (prevBusyRef.current && !busy) {
      void loadRouting(true);
      if (sbRunning) void loadProxies(true);
      if (sub === 'editor') void loadSbConfig();
    }
    prevBusyRef.current = busy;
  }, [busy, sub, sbRunning, loadRouting, loadProxies, loadSbConfig]);

  useEffect(() => {
    if (sub === 'editor' && !sbCfg) {
      void loadSbConfig();
    }
  }, [sub, sbCfg, loadSbConfig]);

  const handleModeSwitch = async (nextMode: SbProxyMode) => {
    if (!sbRunning || switchingMode || proxiesSnap?.mode === nextMode) return;
    const prevSnap = proxiesSnap;
    if (proxiesSnap) {
      setProxiesSnap({ ...proxiesSnap, mode: nextMode });
    }
    setSwitchingMode(true);
    try {
      const res = await clientApi.setSbMode(nextMode);
      if (res.snapshot) {
        setProxiesSnap(res.snapshot);
      } else {
        void loadProxies(true);
      }
      if (nextMode === 'global') {
        toast('已切换为「全局代理」模式，可在下方「节点选择」控制 GLOBAL 出口', 'info');
      } else {
        success(res.message || `已切换为 ${nextMode}`);
      }
    } catch (err: unknown) {
      if (prevSnap) setProxiesSnap(prevSnap);
      error(`切换模式失败：${err instanceof Error ? err.message : '未知错误'}`);
    } finally {
      setSwitchingMode(false);
    }
  };

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
      if (sbRunning) void loadProxies(true);
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
      if (sbRunning) void loadProxies(true);
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
      if (sbRunning) void loadProxies(true);
    } catch (err: unknown) {
      error(`保存失败：${err instanceof Error ? err.message : '未知错误'}`);
    } finally {
      setSavingCfg(false);
    }
  };

  const handleTogglePreserve = async (nextVal: boolean) => {
    if (togglingPreserve) return;
    const prevVal = preserveManual;
    setPreserveManual(nextVal);
    setTogglingPreserve(true);
    try {
      const res = await clientApi.setSbConfigPreserve(nextVal);
      const effective = res.preserveManualConfig !== false;
      setPreserveManual(effective);
      success(
        effective
          ? '已开启「保留手动修改」：定时刷新订阅或升级版本时将自动保留 config.json 手改内容'
          : '已关闭「保留手动修改」：下次刷新或生成配置时将按最新订阅与默认模板全新覆盖',
      );
    } catch (err: unknown) {
      setPreserveManual(prevVal);
      error(`切换失败：${err instanceof Error ? err.message : '未知错误'}`);
    } finally {
      setTogglingPreserve(false);
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
      if (sbRunning) void loadProxies(true);
    } catch (err: unknown) {
      error(`恢复失败：${err instanceof Error ? err.message : '未知错误'}`);
    } finally {
      setSavingCfg(false);
    }
  };

  const currentMode: SbProxyMode = proxiesSnap?.mode || 'rule';
  const aiDefaultDest = routing?.categories.find((c) => c.id === 'ai')?.defaultDest || '#VPS';
  const commonDefaultDest =
    routing?.categories.find((c) => c.id === 'streaming')?.defaultDest || 'Proxy';
  const directLabel = routing?.directTag || '#DC';

  return (
    <div className="space-y-4">
      <PageHeader
        title="sing-box"
        description={sb?.configPath || '/etc/sing-box/config.json'}
        badge={
          <Badge tone={sbRunning ? 'ok' : sb?.installed ? 'neutral' : 'warn'} dot={sbRunning} pulse={sbRunning}>
            {sbRunning ? `运行中 · v${sb?.version || '-'}` : sb?.installed ? '已停止' : '未安装'}
          </Badge>
        }
        actions={
          <SegmentedTabs
            value={sub}
            onChange={(k) => selectSubTab(k as SbSubTab)}
            items={[
              { key: 'routing', label: '智能分流', icon: <SlidersHorizontal className="w-3.5 h-3.5" /> },
              { key: 'nodes', label: '节点选择', icon: <Cpu className="w-3.5 h-3.5" /> },
              { key: 'groups', label: '分组编排', icon: <Layers className="w-3.5 h-3.5" /> },
              { key: 'subs', label: '订阅源', icon: <Link2 className="w-3.5 h-3.5" /> },
              { key: 'editor', label: 'config.json', icon: <FileCode className="w-3.5 h-3.5" /> },
            ]}
          />
        }
      />

      {status?.gateway?.effectiveWorkMode === 'basic' && !sbRunning && (
        <div className="console-card rounded-2xl px-4 py-3 border border-subtle flex flex-wrap items-center justify-between gap-2 text-xs text-secondary">
          <span>当前网关处于「基础模式」，sing-box 内核默认不启动；如需启用审计或代理，请在网关模式中切换。</span>
          <Button size="xs" variant="secondary" onClick={() => onNavigate('net', 'gw')}>
            前往网关模式
          </Button>
        </div>
      )}

      <SingBoxControlBar
        sb={sb}
        sbRunning={sbRunning}
        busy={busy}
        traffic={traffic}
        currentMode={currentMode}
        switchingMode={switchingMode}
        hideRoutingModeSwitch={status?.gateway?.effectiveWorkMode === 'audit'}
        onAction={onAction}
        onNavigate={onNavigate}
        onModeSwitch={(nextMode) => void handleModeSwitch(nextMode)}
      />

      {sub === 'routing' && (
        <SmartRoutingSection
          routing={routing}
          routingLoading={routingLoading}
          sbRunning={sbRunning}
          proxiesSnap={proxiesSnap}
          savingId={savingId}
          resetting={resetting}
          onReload={() => void loadRouting(false)}
          onOpenResetConfirm={() => setResetConfirmOpen(true)}
          onUpdatePreset={(item, nextEnabled, nextOutbound, toastLabel) =>
            void handleUpdatePreset(item, nextEnabled, nextOutbound, toastLabel)
          }
          onJumpToGroup={(groupTag) => {
            setFocusGroup(groupTag);
            selectSubTab('nodes');
          }}
        />
      )}

      {sub === 'nodes' && (
        <ProxyNodesPanel
          running={sbRunning}
          busy={busy}
          snapshot={proxiesSnap}
          loading={proxiesLoading}
          focusGroup={focusGroup}
          onClearFocusGroup={() => setFocusGroup(null)}
          onRefresh={() => loadProxies(false)}
          onSnapshotChange={(next) => setProxiesSnap(next)}
          onStartCore={() => onAction('sb-start')}
        />
      )}

      {sub === 'groups' && (
        <GroupsOrchestratorPanel
          busy={busy}
          onApplied={(nextRouting) => {
            if (nextRouting) setRouting(nextRouting);
            else void loadRouting(true);
            if (sbRunning) void loadProxies(true);
            setSbCfg(null);
          }}
          onJumpToRouting={() => selectSubTab('routing')}
          onJumpToGroup={(gName) => {
            setFocusGroup(gName);
            selectSubTab('nodes');
          }}
        />
      )}

      {sub === 'subs' && (
        <SubscriptionsPanel
          busy={busy}
          onAction={onAction}
          onSaved={() => {
            setSbCfg(null);
            onRefreshStatus?.();
          }}
        />
      )}

      {sub === 'editor' && (
        <SingBoxConfigEditorSection
          sbCfg={sbCfg}
          jsonText={jsonText}
          onJsonTextChange={setJsonText}
          selectedBackup={selectedBackup}
          onSelectedBackupChange={setSelectedBackup}
          savingCfg={savingCfg}
          preserveManual={preserveManual}
          togglingPreserve={togglingPreserve}
          onTogglePreserve={(next) => void handleTogglePreserve(next)}
          onReload={() => void loadSbConfig()}
          onFormatJson={formatJson}
          onSaveConfig={() => void handleSaveConfig()}
          onOpenRestoreConfirm={() => setRestoreConfirmOpen(true)}
        />
      )}

      <ConfirmDialog
        open={restoreConfirmOpen}
        title="恢复配置备份"
        description={`确认使用备份 "${selectedBackup}" 覆盖当前 sing-box config.json？当前配置会先自动另存为新备份。`}
        confirmText="确认恢复"
        loading={savingCfg}
        onConfirm={() => void handleRestoreBackup()}
        onCancel={() => setRestoreConfirmOpen(false)}
      />

      <ConfirmDialog
        open={resetConfirmOpen}
        title="恢复默认分流策略"
        description={`确认将全部 ${routing?.totalCount || 25} 项分流开关恢复为系统推荐默认？（AI 大模型默认走 ${aiDefaultDest}，流媒体/游戏/社交默认走 ${commonDefaultDest} 或 #Auto，Apple 与 Microsoft 默认直连 ${directLabel}）`}
        confirmText="确认恢复默认"
        loading={resetting}
        onConfirm={() => void handleResetDefaults()}
        onCancel={() => setResetConfirmOpen(false)}
      />
    </div>
  );
};

import React, { useCallback, useEffect, useState } from 'react';
import { ChevronDown, ChevronRight, RefreshCw, ShieldCheck, Sliders } from 'lucide-react';
import { Badge, Button, SlideDrawer, useToast } from '../../../../ui';
import { clientApi } from '../../../api';
import {
  SafeCommitStatusReport,
  VlanApplyResponse,
  VlanOverview,
  VlanPortMode,
  VlanPreviewResult,
  VlanSaveSegmentRequest,
} from '../../../types';
import { PortSwitchBar } from './PortSwitchBar';
import { ToggleRow, VlanDnsAndPolicyCard, VlanPreviewSummaryCard } from './VlanDnsAndPolicyCard';
import { AppliedWifiCredential, VlanWirelessCard } from './VlanWirelessCard';
import { maskVlanText } from './vlanHelpers';

export interface VlanSegmentDrawerProps {
  open: boolean;
  isEdit: boolean;
  isCallerMgmt: boolean;
  proMode: boolean;
  privacyMask: boolean;
  overview: VlanOverview;
  initialDraft: VlanSaveSegmentRequest | null;
  onClose: () => void;
  onApplied: (res: VlanApplyResponse, newCredential?: AppliedWifiCredential | null) => void;
  onSafeCommitUpdated?: (sc: SafeCommitStatusReport) => void;
}

export const VlanSegmentDrawer: React.FC<VlanSegmentDrawerProps> = ({
  open,
  isEdit,
  isCallerMgmt,
  proMode,
  privacyMask,
  overview,
  initialDraft,
  onClose,
  onApplied,
  onSafeCommitUpdated,
}) => {
  const { success, error, toast } = useToast();
  const [draft, setDraft] = useState<VlanSaveSegmentRequest | null>(initialDraft);
  const [advOpen, setAdvOpen] = useState(proMode);
  const [trustedText, setTrustedText] = useState('');
  const [preview, setPreview] = useState<VlanPreviewResult | null>(null);
  const [previewLoading, setPreviewLoading] = useState(false);
  const [applying, setApplying] = useState(false);
  const [reconnectingHint, setReconnectingHint] = useState(false);
  const [originalPassword, setOriginalPassword] = useState('');
  const [loadingSecret, setLoadingSecret] = useState(false);
  const [sessionSeq, setSessionSeq] = useState(0);

  useEffect(() => {
    if (!open || !initialDraft) {
      setOriginalPassword('');
      setLoadingSecret(false);
      return;
    }
    setDraft(initialDraft);
    setTrustedText((initialDraft.policy.trustedSourceIps ?? []).join(', '));
    setAdvOpen(proMode);
    setPreview(null);
    setReconnectingHint(false);
    setOriginalPassword('');
    setSessionSeq((n) => n + 1);

    if (!isEdit || !initialDraft.wireless?.passwordConfigured) {
      setLoadingSecret(false);
      return;
    }

    let cancelled = false;
    setLoadingSecret(true);
    void clientApi
      .getVlanWifiSecret(initialDraft.id)
      .then((sec) => {
        if (cancelled) return;
        const pwd = sec.password || '';
        setOriginalPassword(pwd);
        if (!pwd) return;
        setDraft((prev) => {
          if (!prev || prev.id !== initialDraft.id) return prev;
          if (prev.wireless?.password) return prev;
          return {
            ...prev,
            wireless: {
              ...(prev.wireless ?? { enabled: true, isolate: false }),
              password: pwd,
              passwordConfigured: true,
            },
          };
        });
      })
      .catch(() => {
        // 读取失败时保持输入框留空，提交时不改动原 UCI key
      })
      .finally(() => {
        if (!cancelled) setLoadingSecret(false);
      });
    return () => {
      cancelled = true;
    };
  }, [open, isEdit, initialDraft, proMode]);

  const buildPayload = useCallback(
    (src: VlanSaveSegmentRequest, trustedRaw: string): VlanSaveSegmentRequest => {
      const trusted = trustedRaw
        .split(/[\s,，]+/)
        .map((s) => s.trim())
        .filter(Boolean);
      return {
        ...src,
        policy: {
          ...src.policy,
          trustedSourceIps: trusted,
        },
      };
    },
    [],
  );

  const runPreview = useCallback(
    async (src: VlanSaveSegmentRequest, trustedRaw: string) => {
      setPreviewLoading(true);
      try {
        const res = await clientApi.previewVlanSave(buildPayload(src, trustedRaw));
        setPreview(res);
      } catch (e: unknown) {
        setPreview({
          valid: false,
          errors: [e instanceof Error ? e.message : '生成变更预览失败'],
        });
      } finally {
        setPreviewLoading(false);
      }
    },
    [buildPayload],
  );

  useEffect(() => {
    if (!open || !draft) return;
    const timer = window.setTimeout(() => {
      void runPreview(draft, trustedText);
    }, 320);
    return () => window.clearTimeout(timer);
  }, [open, draft, trustedText, runPreview]);

  if (!draft) return null;

  const safeRadios = overview.radios ?? [];
  const safePorts = overview.ports ?? [];
  const safeSegments = overview.segments ?? [];
  const hasRadios = safeRadios.length > 0;
  const wifi = draft.wireless ?? { enabled: false, isolate: false };
  const otherSegments = safeSegments.filter((s) => s.id !== draft.id && s.id !== 'lan');

  const updatePortMode = (portName: string, nextMode: VlanPortMode) => {
    setDraft((prev) => {
      if (!prev) return prev;
      const nextPorts = { ...(prev.ports ?? {}) };
      if (nextMode === 'off') {
        delete nextPorts[portName];
      } else {
        nextPorts[portName] = nextMode;
      }
      return { ...prev, ports: nextPorts };
    });
  };

  const handleToggleForwardTo = (targetId: string) => {
    setDraft((prev) => {
      if (!prev) return prev;
      const cur = prev.policy.allowForwardTo ?? [];
      const next = cur.includes(targetId) ? cur.filter((x) => x !== targetId) : [...cur, targetId];
      return { ...prev, policy: { ...prev.policy, allowForwardTo: next } };
    });
  };

  const handleApply = async () => {
    if (!draft) return;
    setApplying(true);
    setReconnectingHint(false);

    const passwordChanged =
      Boolean(draft.wireless?.password) && (!isEdit || draft.wireless?.password !== originalPassword);
    const newCred: AppliedWifiCredential | null =
      draft.wireless?.enabled && draft.wireless.ssid && draft.wireless.password && passwordChanged
        ? {
            segmentName: draft.displayName || draft.id,
            ssid: draft.wireless.ssid,
            password: draft.wireless.password,
            createdAt: Date.now(),
          }
        : null;

    try {
      const res = await clientApi.applyVlanSave(buildPayload(draft, trustedText));
      if (res.safeCommit) {
        onSafeCommitUpdated?.(res.safeCommit);
      }
      success(
        `已应用「${draft.displayName || draft.id}」，防失联保险丝已启动 (${res.safeCommitTtlSec || 180}s 内可确认保留)`,
        6000,
      );
      onApplied(res, newCred);
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : '';
      const isTransientDrop =
        !msg ||
        /network|failed to fetch|load failed|aborted|timeout|超时|连接|网络/i.test(msg);

      if (!isTransientDrop) {
        error(msg || '应用 VLAN 配置失败');
        return;
      }

      // 网络重载瞬间若发生 Wi-Fi 闪断，自动每 2s 探测 /api/safe-commit/status（持续 30s）并恢复展示倒计时条
      setReconnectingHint(true);
      toast('配置已提交，网络正在重载重连，正在同步防失联倒计时…', 'info', 6000);
      for (let attempt = 0; attempt < 15; attempt++) {
        await new Promise((resolve) => window.setTimeout(resolve, 2000));
        try {
          const sc = await clientApi.getSafeCommitStatus();
          onSafeCommitUpdated?.(sc);
          let latestOv: VlanOverview | undefined;
          try {
            latestOv = await clientApi.getVlanOverview();
          } catch {
            // ignore optional overview refresh failure
          }
          success('已重新连上路由器并同步防失联安全回滚倒计时', 5000);
          onApplied(
            {
              ok: true,
              segmentId: draft.id,
              safeCommit: sc,
              safeCommitTtlSec: sc.state?.ttlSec,
              overview: latestOv,
            },
            newCred,
          );
          return;
        } catch {
          // continue retrying until router network/Wi-Fi finishes reconnecting
        }
      }
      error('配置已提交但暂未重新连上路由器；若确认失联，网关将在倒计时归零后自动回滚恢复。');
    } finally {
      setApplying(false);
      setReconnectingHint(false);
    }
  };

  return (
    <SlideDrawer
      open={open}
      onClose={onClose}
      size="lg"
      title={isEdit ? `配置网络：${draft.displayName || draft.id}` : `新建隔离网：${draft.displayName || draft.id}`}
      subtitle={
        proMode
          ? `接口 ${draft.id} · VLAN ${draft.vlanId} · 网关 ${maskVlanText(draft.ipAddr, privacyMask)}`
          : '零术语向导 · 提交前自动开启 180 秒断联自动回滚保护'
      }
      footer={
        <div className="flex flex-wrap items-center justify-between gap-2.5">
          <Button size="sm" variant="secondary" onClick={onClose} disabled={applying}>
            取消
          </Button>
          <div className="flex items-center gap-2">
            <Button
              size="sm"
              variant="secondary"
              loading={previewLoading}
              icon={<RefreshCw className="w-3.5 h-3.5" />}
              onClick={() => void runPreview(draft, trustedText)}
            >
              重新检查
            </Button>
            <Button
              size="sm"
              variant="primary"
              loading={applying}
              disabled={!preview?.valid || previewLoading}
              icon={<ShieldCheck className="w-4 h-4" />}
              onClick={() => void handleApply()}
            >
              安全应用（{draft.ttlSec || 180}s 自动回滚保护）
            </Button>
          </div>
        </div>
      }
    >
      {/* 1. 基础名称 */}
      <div className="rounded-2xl border border-slate-800/90 bg-slate-900/60 p-4 space-y-3">
        <div className="flex items-center justify-between gap-2">
          <h4 className="text-xs font-semibold text-white">1. 网络名称</h4>
          {isCallerMgmt && <Badge tone="warn">当前管理会话所在网段</Badge>}
        </div>

        <div className={`grid gap-3 ${proMode ? 'sm:grid-cols-2' : 'grid-cols-1'}`}>
          <label className="space-y-1">
            <span className="text-[11px] text-slate-400">显示名称（便于日常识别）</span>
            <input
              type="text"
              value={draft.displayName || ''}
              onChange={(e) => setDraft({ ...draft, displayName: e.target.value })}
              placeholder="例如：智能家居隔离网 / 访客 Wi-Fi"
              className="w-full rounded-xl border border-slate-700/90 bg-slate-950/80 px-3 py-2 text-xs text-white focus:border-emerald-500/70 focus:outline-none"
            />
          </label>
          {proMode && (
            <label className="space-y-1">
              <span className="text-[11px] text-slate-400">UCI 接口标识（小写字母/数字）</span>
              <input
                type="text"
                value={draft.id}
                disabled={isEdit}
                onChange={(e) => setDraft({ ...draft, id: e.target.value.toLowerCase() })}
                placeholder="例如：iot / guest / lab_lan"
                className="w-full rounded-xl border border-slate-700/90 bg-slate-950/80 px-3 py-2 text-xs font-mono text-white disabled:opacity-60 focus:border-emerald-500/70 focus:outline-none"
              />
            </label>
          )}
        </div>
      </div>

      {/* 2. 专属 Wi-Fi 与物理网口 */}
      <div className="rounded-2xl border border-slate-800/90 bg-slate-900/60 p-4 space-y-4">
        <h4 className="text-xs font-semibold text-white">2. 哪些设备连入这个网络？</h4>

        {/* Wireless section */}
        <VlanWirelessCard
          hasRadios={hasRadios}
          isEdit={isEdit}
          proMode={proMode}
          radios={safeRadios}
          wifi={wifi}
          originalPassword={originalPassword}
          loadingSecret={loadingSecret}
          onChange={(nextWifi) => setDraft({ ...draft, wireless: nextWifi })}
        />

        {reconnectingHint && (
          <div className="rounded-xl border border-amber-500/40 bg-amber-500/10 px-3 py-2 text-xs text-amber-200 flex items-center gap-2">
            <RefreshCw className="w-3.5 h-3.5 animate-spin text-amber-400 shrink-0" />
            <span>配置已提交，网络正在重载重连，正在自动同步防失联倒计时…</span>
          </div>
        )}

        {/* Physical port assignment */}
        <PortSwitchBar
          ports={safePorts}
          segments={safeSegments}
          mode="select"
          proMode={proMode}
          selectedPorts={draft.ports}
          editingSegmentId={draft.id}
          onChangePortMode={updatePortMode}
        />
      </div>

      {/* 3. 上网方式（透明代理联动）、下发 DNS 与安全隔离 */}
      <VlanDnsAndPolicyCard
        resetKey={`${draft.id}:${sessionSeq}`}
        draft={draft}
        privacyMask={privacyMask}
        onChangeDraft={setDraft}
      />

      {/* 4. 高级网络参数（折叠 / 专家模式自动展开） */}
      <div className="rounded-2xl border border-slate-800/90 bg-slate-900/45 overflow-hidden">
        <button
          type="button"
          onClick={() => setAdvOpen((v) => !v)}
          className="w-full flex items-center justify-between px-4 py-3 text-xs font-semibold text-slate-200 hover:bg-slate-800/40 transition-colors cursor-pointer"
        >
          <span className="flex items-center gap-2">
            <Sliders className="w-3.5 h-3.5 text-emerald-400" />
            高级网络参数（VLAN ID / 自定义网段 / Home Assistant 白名单）
          </span>
          {advOpen ? <ChevronDown className="w-4 h-4 text-slate-400" /> : <ChevronRight className="w-4 h-4 text-slate-400" />}
        </button>

        {advOpen && (
          <div className="p-4 pt-1 border-t border-slate-800/70 space-y-3">
            <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
              <label className="space-y-1">
                <span className="text-[11px] text-slate-400">VLAN ID (2~4094)</span>
                <input
                  type="number"
                  min={2}
                  max={4094}
                  value={draft.vlanId}
                  onChange={(e) => setDraft({ ...draft, vlanId: Number(e.target.value) || 0 })}
                  className="w-full rounded-xl border border-slate-700/90 bg-slate-950/80 px-3 py-2 text-xs font-mono text-white"
                />
              </label>

              <label className="space-y-1">
                <span className="text-[11px] text-slate-400">子网网关 IPv4</span>
                <input
                  type="text"
                  value={draft.ipAddr}
                  onChange={(e) => setDraft({ ...draft, ipAddr: e.target.value })}
                  placeholder="192.168.20.1"
                  className="w-full rounded-xl border border-slate-700/90 bg-slate-950/80 px-3 py-2 text-xs font-mono text-white"
                />
              </label>

              <label className="space-y-1">
                <span className="text-[11px] text-slate-400">IPv6 分配模式</span>
                <select
                  value={draft.ipv6Mode || 'off'}
                  onChange={(e) => setDraft({ ...draft, ipv6Mode: e.target.value })}
                  className="w-full rounded-xl border border-slate-700/90 bg-slate-950/80 px-3 py-2 text-xs text-white"
                >
                  <option value="off">关闭（推荐隔离网）</option>
                  <option value="relay">中继模式 (Relay)</option>
                  <option value="server">独立分配 (Server)</option>
                </select>
              </label>

              <label className="space-y-1">
                <span className="text-[11px] text-slate-400">DHCP 起始 IP</span>
                <input
                  type="number"
                  min={2}
                  max={240}
                  value={draft.dhcpStart ?? 100}
                  onChange={(e) => setDraft({ ...draft, dhcpStart: Number(e.target.value) || 100 })}
                  className="w-full rounded-xl border border-slate-700/90 bg-slate-950/80 px-3 py-2 text-xs font-mono text-white"
                />
              </label>

              <label className="space-y-1">
                <span className="text-[11px] text-slate-400">最大可分配数量</span>
                <input
                  type="number"
                  min={1}
                  max={240}
                  value={draft.dhcpLimit ?? 150}
                  onChange={(e) => setDraft({ ...draft, dhcpLimit: Number(e.target.value) || 150 })}
                  className="w-full rounded-xl border border-slate-700/90 bg-slate-950/80 px-3 py-2 text-xs font-mono text-white"
                />
              </label>

              <label className="space-y-1">
                <span className="text-[11px] text-slate-400">防失联回滚倒计时 (秒)</span>
                <input
                  type="number"
                  min={60}
                  max={600}
                  value={draft.ttlSec ?? 180}
                  onChange={(e) => setDraft({ ...draft, ttlSec: Number(e.target.value) || 180 })}
                  className="w-full rounded-xl border border-slate-700/90 bg-slate-950/80 px-3 py-2 text-xs font-mono text-white"
                />
              </label>
            </div>

            <label className="block space-y-1">
              <span className="text-[11px] text-slate-400">
                允许上级主网受信任 IP 主动访问此子网（例如 Home Assistant IP，多个以逗号分隔）
              </span>
              <input
                type="text"
                value={trustedText}
                onChange={(e) => setTrustedText(e.target.value)}
                placeholder="例如：192.168.1.10 或 192.168.1.0/24"
                className="w-full rounded-xl border border-slate-700/90 bg-slate-950/80 px-3 py-2 text-xs font-mono text-white"
              />
            </label>

            {otherSegments.length > 0 && (
              <div className="space-y-1.5">
                <span className="text-[11px] text-slate-400">允许本网段单向主动访问其他子网</span>
                <div className="flex flex-wrap gap-2">
                  {otherSegments.map((s) => {
                    const active = (draft.policy.allowForwardTo ?? []).includes(s.id);
                    return (
                      <button
                        key={s.id}
                        type="button"
                        onClick={() => handleToggleForwardTo(s.id)}
                        className={`px-2.5 py-1 rounded-lg border text-xs transition-colors cursor-pointer ${
                          active
                            ? 'border-emerald-500/60 bg-emerald-500/15 text-emerald-200'
                            : 'border-slate-700 bg-slate-950/70 text-slate-400 hover:text-white'
                        }`}
                      >
                        {active ? '✓ ' : '+ '}
                        {s.displayName} ({s.id})
                      </button>
                    );
                  })}
                </div>
              </div>
            )}

            {isCallerMgmt && (
              <ToggleRow
                label="我确认修改当前正在使用的管理网段（高风险）"
                desc="仅在确定新配置不会中断你的管理会话时勾选，若失联将在倒计时归零后自动回滚"
                checked={Boolean(draft.allowModifyMgmt)}
                onChange={(v) => setDraft({ ...draft, allowModifyMgmt: v })}
              />
            )}
          </div>
        )}
      </div>

      {/* 5. 生效前变更摘要（人话版 + 专家 UCI 预览） */}
      <VlanPreviewSummaryCard
        proMode={proMode}
        privacyMask={privacyMask}
        preview={preview}
        previewLoading={previewLoading}
      />
    </SlideDrawer>
  );
};

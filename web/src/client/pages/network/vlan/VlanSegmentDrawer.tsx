import React, { useCallback, useEffect, useState } from 'react';
import {
  AlertTriangle,
  Check,
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  Copy,
  Eye,
  EyeOff,
  Globe,
  RefreshCw,
  Shield,
  ShieldCheck,
  Sliders,
  Terminal,
  Wifi,
  Zap,
} from 'lucide-react';
import { Badge, Button, SlideDrawer, useToast } from '../../../../ui';
import { clientApi } from '../../../api';
import { copyPlainText } from '../../../lib/leakProbes';
import {
  VlanApplyResponse,
  VlanOverview,
  VlanPortMode,
  VlanPreviewResult,
  VlanSaveSegmentRequest,
} from '../../../types';
import { PortSwitchBar } from './PortSwitchBar';
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
  onApplied: (res: VlanApplyResponse) => void;
}

interface ToggleRowProps {
  label: string;
  desc: string;
  checked: boolean;
  onChange: (next: boolean) => void;
}

const ToggleRow: React.FC<ToggleRowProps> = ({ label, desc, checked, onChange }) => (
  <label className="flex items-start justify-between gap-3 rounded-xl border border-slate-800/80 bg-slate-950/50 px-3.5 py-2.5 cursor-pointer hover:border-slate-700 transition-colors">
    <div className="min-w-0">
      <div className="text-xs font-medium text-white">{label}</div>
      <div className="text-[11px] text-slate-400 mt-0.5 leading-relaxed">{desc}</div>
    </div>
    <input
      type="checkbox"
      checked={checked}
      onChange={(e) => onChange(e.target.checked)}
      className="mt-1 h-4 w-4 rounded border-slate-600 bg-slate-900 accent-emerald-500 shrink-0 cursor-pointer"
    />
  </label>
);

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
}) => {
  const { success, error } = useToast();
  const [draft, setDraft] = useState<VlanSaveSegmentRequest | null>(initialDraft);
  const [showPass, setShowPass] = useState(false);
  const [advOpen, setAdvOpen] = useState(proMode);
  const [trustedText, setTrustedText] = useState('');
  const [preview, setPreview] = useState<VlanPreviewResult | null>(null);
  const [previewLoading, setPreviewLoading] = useState(false);
  const [applying, setApplying] = useState(false);
  const [copiedRoute, setCopiedRoute] = useState(false);

  useEffect(() => {
    if (!open || !initialDraft) return;
    setDraft(initialDraft);
    setTrustedText((initialDraft.policy.trustedSourceIps ?? []).join(', '));
    setAdvOpen(proMode);
    setPreview(null);
    setShowPass(false);
  }, [open, initialDraft, proMode]);

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

  const hasRadios = overview.radios.length > 0;
  const wifi = draft.wireless ?? { enabled: false, isolate: false };
  const otherSegments = overview.segments.filter((s) => s.id !== draft.id && s.id !== 'lan');

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
    try {
      const res = await clientApi.applyVlanSave(buildPayload(draft, trustedText));
      success(
        `已应用「${draft.displayName || draft.id}」，防失联保险丝已启动 (${res.safeCommitTtlSec || 180}s 内可确认保留)`,
        6000,
      );
      onApplied(res);
    } catch (e: unknown) {
      error(e instanceof Error ? e.message : '应用 VLAN 配置失败');
    } finally {
      setApplying(false);
    }
  };

  const handleCopyRoute = async (cmd: string) => {
    try {
      await copyPlainText(cmd);
      setCopiedRoute(true);
      success('已复制上级主路由回程路由命令');
      window.setTimeout(() => setCopiedRoute(false), 2000);
    } catch {
      error('复制失败，请手动选中复制');
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
        <div className="rounded-xl border border-slate-800/80 bg-slate-950/50 p-3.5 space-y-3">
          <div className="flex items-center justify-between gap-2">
            <div className="flex items-center gap-2">
              <Wifi className="w-4 h-4 text-sky-400" />
              <div>
                <div className="text-xs font-medium text-white">开启专属 Wi-Fi</div>
                <div className="text-[11px] text-slate-400">
                  {hasRadios ? '为该隔离网独立广播一个无线名称' : '当前设备未检测到无线网卡，仅支持有线网口分配'}
                </div>
              </div>
            </div>
            <input
              type="checkbox"
              disabled={!hasRadios}
              checked={Boolean(wifi.enabled) && hasRadios}
              onChange={(e) =>
                setDraft({
                  ...draft,
                  wireless: { ...wifi, enabled: e.target.checked, radio: wifi.radio || overview.radios[0]?.name },
                })
              }
              className="h-4 w-4 rounded border-slate-600 accent-emerald-500 cursor-pointer disabled:opacity-40"
            />
          </div>

          {hasRadios && wifi.enabled && (
            <div className="pt-2 border-t border-slate-800/70 space-y-3">
              <div className="grid sm:grid-cols-2 gap-3">
                <label className="space-y-1">
                  <span className="text-[11px] text-slate-400">Wi-Fi 名称 (SSID)</span>
                  <input
                    type="text"
                    value={wifi.ssid || ''}
                    onChange={(e) => setDraft({ ...draft, wireless: { ...wifi, ssid: e.target.value } })}
                    placeholder="例如：Home-IoT"
                    className="w-full rounded-xl border border-slate-700/90 bg-slate-900/90 px-3 py-2 text-xs text-white focus:border-emerald-500/70 focus:outline-none"
                  />
                </label>

                <label className="space-y-1">
                  <span className="text-[11px] text-slate-400">
                    连接密码{wifi.passwordConfigured ? '（留空保持原密码不变）' : '（至少 8 位）'}
                  </span>
                  <div className="relative">
                    <input
                      type={showPass ? 'text' : 'password'}
                      value={wifi.password || ''}
                      onChange={(e) => setDraft({ ...draft, wireless: { ...wifi, password: e.target.value } })}
                      placeholder={wifi.passwordConfigured ? '已设置密码，留空不修改' : '请输入 8~63 位 Wi-Fi 密码'}
                      className="w-full rounded-xl border border-slate-700/90 bg-slate-900/90 pl-3 pr-9 py-2 text-xs text-white focus:border-emerald-500/70 focus:outline-none"
                    />
                    <button
                      type="button"
                      onClick={() => setShowPass((v) => !v)}
                      className="absolute right-2.5 top-1/2 -translate-y-1/2 text-slate-400 hover:text-white"
                      aria-label="显示或隐藏密码"
                    >
                      {showPass ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
                    </button>
                  </div>
                </label>
              </div>

              <div className="grid sm:grid-cols-2 gap-3">
                <label className="space-y-1">
                  <span className="text-[11px] text-slate-400">无线频段</span>
                  <select
                    value={wifi.radio || overview.radios[0]?.name || ''}
                    onChange={(e) => setDraft({ ...draft, wireless: { ...wifi, radio: e.target.value } })}
                    className="w-full rounded-xl border border-slate-700/90 bg-slate-900/90 px-3 py-2 text-xs text-white focus:border-emerald-500/70 focus:outline-none"
                  >
                    {overview.radios.map((r) => (
                      <option key={r.name} value={r.name}>
                        {r.bandLabel}
                        {r.band === '2g' ? '（推荐老设备/智能家居）' : '（高速低延迟）'}
                        {proMode ? ` · ${r.name}` : ''}
                      </option>
                    ))}
                  </select>
                </label>

                <label className="space-y-1">
                  <span className="text-[11px] text-slate-400">加密兼容模式</span>
                  <select
                    value={wifi.encryption || 'psk2'}
                    onChange={(e) => setDraft({ ...draft, wireless: { ...wifi, encryption: e.target.value } })}
                    className="w-full rounded-xl border border-slate-700/90 bg-slate-900/90 px-3 py-2 text-xs text-white focus:border-emerald-500/70 focus:outline-none"
                  >
                    <option value="psk2">老设备高兼容模式 (WPA2 · 适合智能家居)</option>
                    <option value="sae-mixed">高速安全模式 (WPA2/WPA3 混合)</option>
                  </select>
                </label>
              </div>

              <ToggleRow
                label="同网段无线设备互不可见（防横向传染）"
                desc="开启后，连上同一个 Wi-Fi 的扫地机/访客手机彼此无法互相扫描或通信"
                checked={Boolean(wifi.isolate)}
                onChange={(checked) => setDraft({ ...draft, wireless: { ...wifi, isolate: checked } })}
              />
            </div>
          )}
        </div>

        {/* Physical port assignment */}
        <PortSwitchBar
          ports={overview.ports}
          segments={overview.segments}
          mode="select"
          proMode={proMode}
          selectedPorts={draft.ports}
          editingSegmentId={draft.id}
          onChangePortMode={updatePortMode}
        />
      </div>

      {/* 3. 上网方式（透明代理联动）与安全隔离 */}
      <div className="rounded-2xl border border-slate-800/90 bg-slate-900/60 p-4 space-y-3.5">
        <h4 className="text-xs font-semibold text-white">3. 上网方式与安全隔离</h4>

        <div className="space-y-1.5">
          <div className="text-[11px] text-slate-400">透明代理联动策略</div>
          <div className="grid sm:grid-cols-2 gap-2.5">
            <button
              type="button"
              onClick={() => setDraft({ ...draft, proxyMode: 'follow' })}
              className={`rounded-xl border p-3 text-left transition-all cursor-pointer ${
                draft.proxyMode !== 'direct'
                  ? 'border-emerald-500/65 bg-emerald-500/12'
                  : 'border-slate-800 bg-slate-950/60 hover:border-slate-700'
              }`}
            >
              <div className="flex items-center gap-2 text-xs font-semibold text-white">
                <Globe className="w-3.5 h-3.5 text-emerald-400" />
                跟随网关透明代理
              </div>
              <p className="text-[11px] text-slate-400 mt-1">
                按网关规则自动分流国内外流量，适合主力手机与电脑。
              </p>
            </button>

            <button
              type="button"
              onClick={() => setDraft({ ...draft, proxyMode: 'direct' })}
              className={`rounded-xl border p-3 text-left transition-all cursor-pointer ${
                draft.proxyMode === 'direct'
                  ? 'border-amber-500/65 bg-amber-500/12'
                  : 'border-slate-800 bg-slate-950/60 hover:border-slate-700'
              }`}
            >
              <div className="flex items-center gap-2 text-xs font-semibold text-white">
                <Zap className="w-3.5 h-3.5 text-amber-400" />
                纯直连 · 绕过代理
              </div>
              <p className="text-[11px] text-slate-400 mt-1">
                彻底绕开 sing-box，不消耗节点流量，最适合智能家居与访客。
              </p>
            </button>
          </div>
        </div>

        <div className="space-y-2">
          <ToggleRow
            label="允许访问外网 (Internet)"
            desc="关闭后该网段将成为纯离线内网（适合防摄像头偷传云端）"
            checked={draft.policy.allowWan}
            onChange={(v) => setDraft({ ...draft, policy: { ...draft.policy, allowWan: v } })}
          />
          <ToggleRow
            label="禁止访问路由器管理后台（推荐隔离网开启）"
            desc="拦截该网段访问路由器的网页后台、SSH 与 SingCtl 面板，防止设备被入侵后提权"
            checked={draft.policy.blockRouterMgmt}
            onChange={(v) => setDraft({ ...draft, policy: { ...draft.policy, blockRouterMgmt: v } })}
          />
          <ToggleRow
            label="禁止访问家里主网设备（电脑 / NAS）"
            desc="该网段无法主动探测或访问上级主网与个人电脑，仅保留正常上网能力"
            checked={draft.policy.blockUpstreamLan}
            onChange={(v) => setDraft({ ...draft, policy: { ...draft.policy, blockUpstreamLan: v } })}
          />
          <ToggleRow
            label="允许主网设备单向控制此网"
            desc="允许主网手机/电脑主动访问此网段设备（例如从主力网控制扫地机），但反向被禁止"
            checked={draft.policy.allowFromMainLan}
            onChange={(v) => setDraft({ ...draft, policy: { ...draft.policy, allowFromMainLan: v } })}
          />
          <ToggleRow
            label="支持跨网设备发现 (AirPlay / 米家 / mDNS)"
            desc="放行局域网 UDP 5353 组播发现，方便手机自动找到智能设备"
            checked={draft.policy.allowMdns}
            onChange={(v) => setDraft({ ...draft, policy: { ...draft.policy, allowMdns: v } })}
          />
        </div>
      </div>

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
      <div className="rounded-2xl border border-slate-800/90 bg-slate-950/70 p-4 space-y-3">
        <div className="flex items-center justify-between gap-2">
          <div className="flex items-center gap-2 text-xs font-semibold text-white">
            <Shield className="w-3.5 h-3.5 text-emerald-400" />
            生效前变更核对
          </div>
          {previewLoading ? (
            <Badge tone="neutral">实时校验中…</Badge>
          ) : preview?.valid ? (
            <Badge tone="ok" dot>
              校验通过 · 可安全应用
            </Badge>
          ) : (
            <Badge tone="danger" dot>
              存在冲突待修正
            </Badge>
          )}
        </div>

        {preview?.errors && preview.errors.length > 0 && (
          <div className="rounded-xl border border-rose-500/40 bg-rose-500/10 p-3 space-y-1 text-xs text-rose-200">
            {preview.errors.map((errMsg, idx) => (
              <div key={idx} className="flex items-start gap-2">
                <AlertTriangle className="w-3.5 h-3.5 text-rose-400 shrink-0 mt-0.5" />
                <span>{maskVlanText(errMsg, privacyMask)}</span>
              </div>
            ))}
          </div>
        )}

        {preview?.warnings && preview.warnings.length > 0 && (
          <div className="rounded-xl border border-amber-500/35 bg-amber-500/10 p-3 space-y-1 text-xs text-amber-200">
            {preview.warnings.map((wMsg, idx) => (
              <div key={idx} className="flex items-start gap-2">
                <AlertTriangle className="w-3.5 h-3.5 text-amber-400 shrink-0 mt-0.5" />
                <span>{maskVlanText(wMsg, privacyMask)}</span>
              </div>
            ))}
          </div>
        )}

        {preview?.plainSummary && preview.plainSummary.length > 0 && (
          <ul className="space-y-1.5 text-xs text-slate-200">
            {preview.plainSummary.map((line, idx) => (
              <li key={idx} className="flex items-start gap-2">
                <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0 mt-0.5" />
                <span>{maskVlanText(line, privacyMask)}</span>
              </li>
            ))}
          </ul>
        )}

        {preview?.upstreamRouteHint && (
          <div className="rounded-xl border border-sky-500/30 bg-sky-500/8 p-3 space-y-1.5">
            <div className="flex items-center justify-between gap-2 text-[11px] text-sky-200">
              <span>若上级还有主软路由，需在其上添加回程静态路由：</span>
              <Button
                size="xs"
                variant="secondary"
                icon={copiedRoute ? <Check className="w-3 h-3" /> : <Copy className="w-3 h-3" />}
                onClick={() => void handleCopyRoute(preview.upstreamRouteHint || '')}
              >
                {copiedRoute ? '已复制' : '复制命令'}
              </Button>
            </div>
            <code className="block text-[11px] font-mono text-sky-300 break-all">
              {maskVlanText(preview.upstreamRouteHint, privacyMask)}
            </code>
          </div>
        )}

        {proMode && preview?.uciCommands && preview.uciCommands.length > 0 && (
          <details className="rounded-xl border border-slate-800 bg-slate-950/90 p-3">
            <summary className="text-[11px] font-mono text-slate-300 cursor-pointer flex items-center gap-1.5">
              <Terminal className="w-3.5 h-3.5 text-emerald-400" />
              查看底层 UCI 批量指令 ({preview.uciCommands.length} 条)
            </summary>
            <pre className="mt-2 max-h-48 overflow-auto text-[11px] font-mono text-emerald-300/90 leading-relaxed whitespace-pre-wrap break-all">
              {maskVlanText(preview.uciCommands.join('\n'), privacyMask)}
            </pre>
          </details>
        )}
      </div>
    </SlideDrawer>
  );
};

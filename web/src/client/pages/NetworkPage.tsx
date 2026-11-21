import React, { useState, useEffect, useCallback, useMemo, useRef } from 'react';
import {
  Share2,
  Flame,
  GitFork,
  RefreshCw,
  Save,
  AlertTriangle,
  CheckCircle2,
  Network,
  Smartphone,
  Copy,
  Check,
  ShieldCheck,
  ShieldAlert,
  Zap,
  Download,
  HardDrive,
  Cpu,
  Terminal,
  Play,
  Power,
  KeyRound,
  ChevronDown,
  ChevronUp,
  Eye,
  EyeOff,
  Monitor,
  X,
} from 'lucide-react';
import {
  Badge,
  Button,
  ConfirmDialog,
  PageHeader,
  SectionCard,
  SegmentedTabs,
  SlideDrawer,
  formatBytes,
  useToast,
} from '../../ui';
import { useCachedQuery } from '../../hooks';
import { clientApi } from '../api';
import {
  BROWSER_DOH_EVENT,
  DNSLeakTestCard,
  getCachedBrowserDoH,
  runBrowserDoHCheckFlow,
} from '../components/DNSLeakTestCard';
import { copyPlainText, detectBrowserDoHGuide } from '../lib/leakProbes';
import {
  maskFullIP,
  PRIVACY_MASK_EVENT,
  readPrivacyMaskPref,
  redactInlineSensitive,
  writePrivacyMaskPref,
} from '../lib/privacyMask';
import {
  BrowserDoHCheckResponse,
  ClientGatewayConfigResponse,
  ClientStatusResponse,
  GatewayIPv6Mode,
  GatewayRoleMode,
  TailscaleAccessMode,
  TailscaleConfigResponse,
  TailscaleP2PPeerConfig,
  TailscaleP2PPeerView,
  TailscaleP2PReport,
  TailscaleUpgradePreflight,
} from '../types';
import { FirewallPanel } from './FirewallPanel';

export const GATEWAY_CACHE_KEY = 'client:gateway';
export const TAILSCALE_CFG_CACHE_KEY = 'client:tailscale:config';
export const TAILSCALE_P2P_CACHE_KEY = 'client:tailscale:p2p';

export interface TailscalePageProps {
  status: ClientStatusResponse | null;
  busy: boolean;
  privacyMask?: boolean;
  onAction: (name: string, params?: Record<string, unknown>, confirmMsg?: string) => void;
  onRefreshStatus?: () => void;
}

const TS_MODES = [
  { value: 'client', title: '默认客户端', desc: '仅作为普通节点加入 Tailscale，不广播路由' },
  { value: 'router', title: '子网路由器', desc: '广播本机局域网网段，软路由设备推荐此项' },
  { value: 'exit', title: '出口节点', desc: '将本机设为全网流量出口，供其他设备选为 Exit Node' },
  { value: 'gateway', title: '全能网关', desc: '同时充当子网路由器 + 出口节点' },
];

function normalizeTSMode(raw?: string): string {
  if (raw === 'router' || raw === 'exit' || raw === 'gateway') return raw;
  return 'client';
}

const P2P_ACCESS_MODES: { key: TailscaleAccessMode; label: string }[] = [
  { key: 'outbound_only', label: '单向锁死' },
  { key: 'bidirectional_timed', label: '探亲限时双向' },
  { key: 'bidirectional', label: '长期双向' },
];

interface EditableP2PPeer {
  key: string;
  id: string;
  name: string;
  tailscaleIP: string;
  configured: boolean;
  jitEnabled: boolean;
  accessMode: TailscaleAccessMode;
  bidirectionalUntil: string;
  allowedLanTargetsText: string;
}

function peerEditKey(p: TailscaleP2PPeerView): string {
  return p.id || p.tailscaleIPs?.[0] || p.name || p.shortName;
}

function formatRemainingCountdown(sec: number): string {
  if (sec <= 0) return '已过期（自动锁死）';
  const days = Math.floor(sec / 86400);
  const hours = Math.floor((sec % 86400) / 3600);
  const mins = Math.floor((sec % 3600) / 60);
  if (days > 0) return `剩余 ${days}天${hours}小时`;
  if (hours > 0) return `剩余 ${hours}小时${mins}分`;
  return `剩余 ${Math.max(1, mins)} 分钟`;
}

export const TailscalePage: React.FC<TailscalePageProps> = ({
  status,
  busy,
  privacyMask = false,
  onAction,
  onRefreshStatus,
}) => {
  const { toast, success, error } = useToast();
  const ts = status?.tailscale;
  const [mode, setMode] = useState<string>(() => (ts?.running ? normalizeTSMode(ts.mode) : 'router'));
  const [acceptRoutes, setAcceptRoutes] = useState(() => Boolean(ts?.acceptRoutes));
  const [modeDirty, setModeDirty] = useState(false);

  const {
    data: tsCfg,
    loading: tsCfgLoading,
    setData: setTsCfgData,
  } = useCachedQuery<TailscaleConfigResponse>(TAILSCALE_CFG_CACHE_KEY, () => clientApi.getTailscaleConfig());
  const [tsAuthExpanded, setTsAuthExpanded] = useState(false);
  const [authKeyInput, setAuthKeyInput] = useState('');
  const [clearAuthKey, setClearAuthKey] = useState(false);
  const [subnetsInput, setSubnetsInput] = useState(() => tsCfg?.subnets || '');
  const [subnetsDirty, setSubnetsDirty] = useState(false);
  const [savingTsCfg, setSavingTsCfg] = useState(false);

  const [stopConfirmOpen, setStopConfirmOpen] = useState(false);
  const [reconfigConfirmOpen, setReconfigConfirmOpen] = useState(false);

  const {
    data: p2pReport,
    loading: p2pLoading,
    setData: setP2pReportData,
    refetch: refetchP2P,
  } = useCachedQuery<TailscaleP2PReport>(TAILSCALE_P2P_CACHE_KEY, () => clientApi.getTailscaleP2P());
  const p2pDirtyRef = useRef(false);
  const [p2pSaving, setP2pSaving] = useState(false);
  const [pokingKey, setPokingKey] = useState('');

  const p2pLiveEnabled = Boolean(p2pReport?.config?.enabled);
  const [jitWindowSec, setJitWindowSec] = useState(() =>
    p2pReport?.config?.jit_window_sec && p2pReport.config.jit_window_sec > 0
      ? p2pReport.config.jit_window_sec
      : 5,
  );
  const [cooldownSec, setCooldownSec] = useState(() =>
    p2pReport?.config?.cooldown_sec && p2pReport.config.cooldown_sec > 0 ? p2pReport.config.cooldown_sec : 300,
  );
  const [sandboxUjail, setSandboxUjail] = useState(() =>
    p2pReport?.ujailAvailable
      ? !p2pReport.config?.enabled
        ? true
        : Boolean(p2pReport.config?.sandbox_ujail)
      : false,
  );
  const [peerEdits, setPeerEdits] = useState<Record<string, EditableP2PPeer>>({});

  const [upgradeDrawerOpen, setUpgradeDrawerOpen] = useState(false);
  const [preflight, setPreflight] = useState<TailscaleUpgradePreflight | null>(null);
  const [preflightLoading, setPreflightLoading] = useState(false);
  const [preflightError, setPreflightError] = useState('');
  const [forceReinstall, setForceReinstall] = useState(false);
  const [showSwapLogTail, setShowSwapLogTail] = useState(false);

  const loadUpgradePreflight = useCallback(async () => {
    setPreflightLoading(true);
    setPreflightError('');
    try {
      const rep = await clientApi.getTailscaleUpgradePreflight();
      setPreflight(rep);
    } catch (err) {
      setPreflightError((err as Error)?.message || '读取升级体检信息失败');
    } finally {
      setPreflightLoading(false);
    }
  }, []);

  const openUpgradeDrawer = () => {
    setForceReinstall(false);
    setShowSwapLogTail(false);
    setUpgradeDrawerOpen(true);
    void loadUpgradePreflight();
  };

  useEffect(() => {
    const onDone = () => {
      if (upgradeDrawerOpen) {
        void loadUpgradePreflight();
      }
    };
    window.addEventListener('singctl:ts-upgrade-done', onDone);
    return () => window.removeEventListener('singctl:ts-upgrade-done', onDone);
  }, [upgradeDrawerOpen, loadUpgradePreflight]);

  useEffect(() => {
    if (!tsCfg) return;
    if (!subnetsDirty) {
      setSubnetsInput(tsCfg.subnets || '');
    }
    if (!tsCfg.authKeySet) {
      setTsAuthExpanded(true);
    }
  }, [tsCfg, subnetsDirty]);

  const savedMode = ts?.running ? normalizeTSMode(ts.mode) : mode;
  const savedAcceptRoutes = ts?.running ? Boolean(ts.acceptRoutes) : acceptRoutes;
  const hasModeChanges = Boolean(ts?.running) && (mode !== savedMode || acceptRoutes !== savedAcceptRoutes);

  useEffect(() => {
    if (!ts?.installed || !ts.running) return;
    const liveMode = normalizeTSMode(ts.mode);
    const liveAccept = Boolean(ts.acceptRoutes);
    if (!modeDirty) {
      setMode(liveMode);
      setAcceptRoutes(liveAccept);
    } else if (!busy && mode === liveMode && acceptRoutes === liveAccept) {
      setModeDirty(false);
    }
  }, [ts?.installed, ts?.running, ts?.mode, ts?.acceptRoutes, modeDirty, busy, mode, acceptRoutes]);

  const handleSaveTsConfig = async (e: React.FormEvent) => {
    e.preventDefault();
    if (privacyMask) return;
    setSavingTsCfg(true);
    try {
      const saved = await clientApi.saveTailscaleConfig({
        authKey: authKeyInput.trim(),
        clearAuthKey,
        subnets: subnetsInput.trim(),
      });
      setTsCfgData(saved);
      setAuthKeyInput('');
      setClearAuthKey(false);
      setSubnetsDirty(false);
      setSubnetsInput(saved.subnets || '');
      success('Tailscale 认证密钥与广播子网已保存（0600 权限）');
      onRefreshStatus?.();
    } catch (err) {
      error((err as Error)?.message || '保存 Tailscale 配置失败');
    } finally {
      setSavingTsCfg(false);
    }
  };

  const hydrateP2PReport = useCallback(
    (rep: TailscaleP2PReport, updateCache = true) => {
      if (updateCache) {
        setP2pReportData(rep);
      }
      setJitWindowSec(rep.config?.jit_window_sec && rep.config.jit_window_sec > 0 ? rep.config.jit_window_sec : 5);
      setCooldownSec(rep.config?.cooldown_sec && rep.config.cooldown_sec > 0 ? rep.config.cooldown_sec : 300);
      setSandboxUjail(
        rep.ujailAvailable ? (!rep.config?.enabled ? true : Boolean(rep.config?.sandbox_ujail)) : false,
      );

      const nextEdits: Record<string, EditableP2PPeer> = {};
      for (const p of rep.peers || []) {
        const k = peerEditKey(p);
        const rawMode = (p.accessMode || 'outbound_only') as TailscaleAccessMode;
        const modeVal: TailscaleAccessMode =
          rawMode === 'bidirectional' || rawMode === 'bidirectional_timed' ? rawMode : 'outbound_only';
        nextEdits[k] = {
          key: k,
          id: p.id || '',
          name: p.shortName || p.name || p.hostName || k,
          tailscaleIP: p.tailscaleIPs?.[0] || '',
          configured: Boolean(p.configured),
          jitEnabled: Boolean(p.jitEnabled),
          accessMode: modeVal,
          bidirectionalUntil: p.bidirectionalUntil || '',
          allowedLanTargetsText: (p.allowedLanTargets || []).join(', '),
        };
      }
      setPeerEdits(nextEdits);
    },
    [setP2pReportData],
  );

  useEffect(() => {
    if (!p2pReport) return;
    if (!p2pDirtyRef.current) {
      hydrateP2PReport(p2pReport, false);
    }
  }, [p2pReport, hydrateP2PReport]);

  const loadP2P = useCallback(async () => {
    p2pDirtyRef.current = false;
    try {
      const rep = await refetchP2P(false);
      if (rep) hydrateP2PReport(rep, false);
    } catch (err) {
      toast((err as Error)?.message || '读取 P2P 防线状态失败', 'error');
    }
  }, [hydrateP2PReport, refetchP2P, toast]);

  const updatePeerEdit = (k: string, patch: Partial<EditableP2PPeer>) => {
    p2pDirtyRef.current = true;
    setPeerEdits((prev) => {
      const cur = prev[k];
      if (!cur) return prev;
      return { ...prev, [k]: { ...cur, ...patch } };
    });
  };

  const applyQuickDays = (k: string, days: number) => {
    const until = new Date(Date.now() + days * 86400 * 1000).toISOString().replace(/\.\d{3}Z$/, 'Z');
    updatePeerEdit(k, {
      configured: true,
      accessMode: 'bidirectional_timed',
      bidirectionalUntil: until,
    });
  };

  const handleSaveP2P = async () => {
    setP2pSaving(true);
    try {
      const peersPayload: TailscaleP2PPeerConfig[] = Object.values(peerEdits)
        .filter((e) => e.configured)
        .map((e) => {
          const targets = e.allowedLanTargetsText
            .split(/[,，\n]+/)
            .map((s) => s.trim())
            .filter(Boolean);
          let until = e.bidirectionalUntil.trim();
          if (e.accessMode === 'bidirectional_timed' && !until) {
            until = new Date(Date.now() + 7 * 86400 * 1000).toISOString().replace(/\.\d{3}Z$/, 'Z');
          }
          return {
            id: e.id || undefined,
            name: e.name,
            tailscale_ip: e.tailscaleIP || undefined,
            jit_enabled: e.jitEnabled,
            access_mode: e.accessMode,
            bidirectional_until: e.accessMode === 'bidirectional_timed' ? until : undefined,
            allowed_lan_targets: targets,
          };
        });

      const rep = await clientApi.saveTailscaleP2P({
        enabled: true,
        jit_window_sec: Math.min(10, Math.max(3, Number(jitWindowSec) || 5)),
        cooldown_sec: Math.min(3600, Math.max(30, Number(cooldownSec) || 300)),
        payload_filter: true,
        sandbox_ujail: Boolean(p2pReport?.ujailAvailable && sandboxUjail),
        peers: peersPayload,
      });
      p2pDirtyRef.current = false;
      hydrateP2PReport(rep);
      toast(rep.message || 'P2P 防线配置已生效', 'success');
    } catch (err) {
      toast((err as Error)?.message || '保存 P2P 防线配置失败', 'error');
    } finally {
      setP2pSaving(false);
    }
  };

  const handlePokePeer = async (p: TailscaleP2PPeerView) => {
    const k = peerEditKey(p);
    setPokingKey(k);
    try {
      const res = await clientApi.pokeTailscaleP2P({ id: p.id, name: p.name });
      toast(res.message || '测试完成', res.direct ? 'success' : 'warn');
      if (res.report) {
        hydrateP2PReport(res.report);
      } else {
        await loadP2P();
      }
    } catch (err) {
      toast((err as Error)?.message || '瞬时打洞测试失败', 'error');
    } finally {
      setPokingKey('');
    }
  };

  const activeModeLabel = ts?.running
    ? TS_MODES.find((m) => m.value === normalizeTSMode(ts.mode))?.title || normalizeTSMode(ts.mode)
    : '-';
  const selectedModeLabel = TS_MODES.find((m) => m.value === mode)?.title || mode;

  const renderAuthSubnetsForm = () => (
    <form onSubmit={(e) => void handleSaveTsConfig(e)} className="space-y-3 text-xs">
      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
        <label className="block space-y-1">
          <span className="text-secondary">Tailscale 授权密钥 (`auth_key`)</span>
          <input
            type="password"
            autoComplete="new-password"
            disabled={tsCfgLoading || clearAuthKey}
            value={authKeyInput}
            onChange={(e) => setAuthKeyInput(e.target.value)}
            placeholder={
              tsCfg?.authKeySet
                ? privacyMask
                  ? '已配置 (••••••••)，留空保持不变'
                  : `已配置 (${tsCfg.authKeyHint || '********'})，留空保持不变`
                : 'tskey-auth-...'
            }
            className="w-full h-9 px-3 rounded-xl bg-surface1 border border-subtle text-primary font-mono focus:outline-none focus:border-strong disabled:opacity-60"
          />
        </label>
        <label className="block space-y-1">
          <span className="text-secondary">广播局域网网段 (`subnets`，留空自动探测)</span>
          <input
            type={privacyMask ? 'password' : 'text'}
            readOnly={privacyMask}
            disabled={tsCfgLoading}
            value={subnetsInput}
            onChange={(e) => {
              setSubnetsInput(e.target.value);
              setSubnetsDirty(true);
            }}
            placeholder={privacyMask ? '••••••••' : '例如 192.168.1.0/24（多网段用英文逗号分隔）'}
            className="w-full h-9 px-3 rounded-xl bg-surface1 border border-subtle text-primary font-mono focus:outline-none focus:border-strong"
          />
        </label>
      </div>
      <div className="flex flex-wrap items-center justify-between gap-2 pt-1">
        <div>
          {tsCfg?.authKeySet && (
            <label className="inline-flex items-center gap-1.5 text-[11px] text-rose-300 cursor-pointer select-none">
              <input
                type="checkbox"
                checked={clearAuthKey}
                onChange={(e) => {
                  setClearAuthKey(e.target.checked);
                  if (e.target.checked) setAuthKeyInput('');
                }}
                className="accent-rose-500 w-3.5 h-3.5"
              />
              <span>清空已保存的 Auth Key</span>
            </label>
          )}
        </div>
        <Button
          type="submit"
          size="xs"
          variant="secondary"
          loading={savingTsCfg}
          disabled={tsCfgLoading || busy || privacyMask}
          title={privacyMask ? '隐私完全遮挡开启期间请先关闭遮挡再编辑网段' : undefined}
          icon={<Save className="w-3.5 h-3.5" />}
        >
          保存认证与子网
        </Button>
      </div>
    </form>
  );

  return (
    <div className="space-y-5">
      <PageHeader
        title="Tailscale 组网"
        description={
          !ts
            ? '正在读取 Tailscale 运行状态…'
            : !ts.installed
            ? '尚未安装 Tailscale 二进制'
            : ts.version
            ? `v${ts.version}${ts.subnets ? ` · 子网 ${maskFullIP(ts.subnets, privacyMask)}` : ''}`
            : '已安装'
        }
        badge={
          <Badge
            tone={!ts?.installed ? 'warn' : ts.state === 'Running' ? 'ok' : ts.running ? 'warn' : 'neutral'}
            dot={Boolean(ts?.running)}
            pulse={ts?.state === 'Running'}
          >
            {!ts?.installed ? '未安装' : ts.state === 'Running' ? '已连接' : ts.running ? ts.state : '未运行'}
          </Badge>
        }
      />

      {ts && !ts.installed ? (
        <SectionCard
          title="安装并启用 Tailscale 组网"
          icon={<Share2 className="w-4 h-4" />}
          subtitle="一键拉取架构适配安装包（ARM64 为精简合体版，含官方 SHA256 强校验），先配好 auth_key 再启动更省心"
        >
          <div className="space-y-4">
            <div className="p-3.5 rounded-xl bg-surface2 border border-subtle space-y-3">
              <div className="flex items-center gap-2 text-xs font-semibold text-primary">
                <KeyRound className="w-3.5 h-3.5 text-[var(--accent)]" />
                认证密钥与广播子网 (`tailscale.auth_key` / `subnets`)
              </div>
              {renderAuthSubnetsForm()}
            </div>
            <div className="flex flex-wrap items-center gap-3 pt-1">
              <Button
                variant="primary"
                disabled={busy}
                onClick={() => onAction('ts-install')}
                icon={<Download className="w-4 h-4" />}
              >
                安装 Tailscale
              </Button>
            </div>
          </div>
        </SectionCard>
      ) : (
        <>
          {/* 常驻生命周期控制条（与 sing-box 页规范一致：状态摘要 + 互斥启停与零失联升级） */}
          <div className="console-card rounded-2xl px-4 py-3 flex flex-col lg:flex-row lg:items-center justify-between gap-3">
            <div className="flex flex-wrap items-center gap-2 text-xs">
              <Badge tone={ts?.running ? 'ok' : 'neutral'} dot={Boolean(ts?.running)}>
                {ts?.running ? `运行中 (${ts.state || 'Running'})` : '守护进程已停止'}
              </Badge>
              {ts?.running && (
                <Badge tone="accent">当前模式: {activeModeLabel}</Badge>
              )}
              {ts?.running && ts.acceptRoutes && (
                <Badge tone="neutral">已启用接收对端路由</Badge>
              )}
              <Badge tone={tsCfg?.authKeySet || ts?.authKeySet ? 'ok' : 'warn'}>
                {tsCfg?.authKeySet || ts?.authKeySet ? 'auth_key 已就绪' : 'auth_key 未配置'}
              </Badge>
            </div>
            <div className="flex flex-wrap items-center gap-2">
              {!ts?.running && (
                <Button
                  size="sm"
                  variant="primary"
                  disabled={busy}
                  icon={<Play className="w-3.5 h-3.5" />}
                  onClick={() => onAction('ts-start', { mode, acceptRoutes })}
                >
                  启动 Tailscale
                </Button>
              )}
              <Button
                size="sm"
                variant="secondary"
                disabled={busy}
                icon={<Download className="w-3.5 h-3.5" />}
                onClick={openUpgradeDrawer}
              >
                零失联更新
              </Button>
              {ts?.running && (
                <Button
                  size="sm"
                  variant="danger"
                  disabled={busy}
                  icon={<Power className="w-3.5 h-3.5" />}
                  onClick={() => setStopConfirmOpen(true)}
                >
                  停止服务
                </Button>
              )}
            </div>
          </div>

          <SectionCard
            title="启动模式与路由策略"
            icon={<Share2 className="w-4 h-4" />}
            subtitle={
              ts?.running
                ? '切换模式或路由选项后不会立即改动网络，需点击下方「保存并热切换模式」确认生效'
                : '选择网关在 Tailscale 网络中承担的角色，然后启动服务'
            }
          >
            <div className="space-y-4">
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
                {TS_MODES.map((m) => {
                  const selected = mode === m.value;
                  return (
                    <button
                      key={m.value}
                      type="button"
                      onClick={() => {
                        setMode(m.value);
                        setModeDirty(true);
                      }}
                      style={
                        selected
                          ? {
                              backgroundColor: 'var(--accent-soft)',
                              borderColor: 'var(--accent)',
                            }
                          : undefined
                      }
                      className={`p-3.5 rounded-xl border text-left transition-all cursor-pointer ${
                        selected ? '' : 'bg-surface2 border-subtle hover:border-strong'
                      }`}
                    >
                      <div className="text-xs sm:text-sm font-semibold text-primary">{m.title}</div>
                      <div className="text-[11px] text-secondary mt-1 leading-relaxed">{m.desc}</div>
                    </button>
                  );
                })}
              </div>

              <label className="inline-flex items-center gap-2 text-xs sm:text-sm text-primary cursor-pointer select-none">
                <input
                  type="checkbox"
                  checked={acceptRoutes}
                  onChange={(e) => {
                    setAcceptRoutes(e.target.checked);
                    setModeDirty(true);
                  }}
                  className="accent-[var(--accent)] w-4 h-4"
                />
                <span>接收其他节点广播的路由（`--accept-routes`）</span>
              </label>

              {/* 内联折叠区：Tailscale Auth Key 与通告子网（不再跨页跳转） */}
              <div className="rounded-xl border border-subtle bg-surface2/60 overflow-hidden">
                <button
                  type="button"
                  onClick={() => setTsAuthExpanded((v) => !v)}
                  className="w-full px-3.5 py-2.5 flex items-center justify-between gap-2 text-left hover:bg-surface2 transition-colors cursor-pointer"
                >
                  <div className="flex items-center gap-2 text-xs font-medium text-primary">
                    <KeyRound className="w-3.5 h-3.5 text-[var(--accent)]" />
                    <span>认证密钥与广播子网 (`auth_key` / `subnets`)</span>
                    <Badge tone={tsCfg?.authKeySet || ts?.authKeySet ? 'ok' : 'warn'}>
                      {tsCfg?.authKeySet
                        ? privacyMask
                          ? '•••••••• (已遮挡)'
                          : tsCfg.authKeyHint || '已配置'
                        : '未配置'}
                    </Badge>
                    {tsCfg?.subnets && (
                      <span className="hidden sm:inline text-[11px] font-mono text-secondary">
                        · {maskFullIP(tsCfg.subnets, privacyMask)}
                      </span>
                    )}
                  </div>
                  {tsAuthExpanded ? (
                    <ChevronUp className="w-4 h-4 text-secondary shrink-0" />
                  ) : (
                    <ChevronDown className="w-4 h-4 text-secondary shrink-0" />
                  )}
                </button>
                {tsAuthExpanded && (
                  <div className="px-3.5 pb-3.5 pt-2 border-t border-subtle">
                    {renderAuthSubnetsForm()}
                  </div>
                )}
              </div>

              <div className="flex flex-wrap items-center justify-between gap-3 pt-2 border-t border-subtle">
                {!ts?.running ? (
                  <>
                    <span className="text-[11px] text-secondary">
                      将使用「{selectedModeLabel}」模式（{acceptRoutes ? '接收对端路由' : '不接收对端路由'}）启动 Tailscale
                    </span>
                    <Button
                      variant="primary"
                      disabled={busy}
                      icon={<Play className="w-3.5 h-3.5" />}
                      onClick={() => onAction('ts-start', { mode, acceptRoutes })}
                    >
                      按所选模式启动
                    </Button>
                  </>
                ) : hasModeChanges ? (
                  <>
                    <span className="text-[11px] text-amber-300">
                      检测到待应用变更：{activeModeLabel} → {selectedModeLabel}（--accept-routes={String(acceptRoutes)}），请确认保存并热切换
                    </span>
                    <div className="flex items-center gap-2">
                      <Button
                        size="sm"
                        variant="ghost"
                        disabled={busy}
                        onClick={() => {
                          setMode(savedMode);
                          setAcceptRoutes(savedAcceptRoutes);
                          setModeDirty(false);
                        }}
                      >
                        撤销变更
                      </Button>
                      <Button
                        variant="primary"
                        disabled={busy}
                        icon={<Save className="w-3.5 h-3.5" />}
                        onClick={() => setReconfigConfirmOpen(true)}
                      >
                        保存并热切换模式
                      </Button>
                    </div>
                  </>
                ) : (
                  <span className="text-[11px] text-emerald-300/90 flex items-center gap-1.5">
                    <CheckCircle2 className="w-3.5 h-3.5 shrink-0" />
                    当前正以「{activeModeLabel}」模式运行 · 修改上方选项并点击保存即可在线热生效
                  </span>
                )}
              </div>
            </div>
          </SectionCard>
        </>
      )}

      <SectionCard
        title="P2P 直连防线 · 零常驻暴露 (JIT)"
        icon={<ShieldCheck className="w-4 h-4" />}
        subtitle="闲置与直连期间 WAN 侧 UDP :41641 零暴露；仅在授权节点按需直连时瞬时放行 3~10s 并在连上后毫秒级自动关门"
        actions={
          <div className="flex items-center gap-2">
            {p2pReport && (
              <Badge tone={p2pReport.openPinholes > 0 ? 'warn' : p2pLiveEnabled ? 'ok' : 'neutral'} dot>
                {p2pReport.openPinholes > 0
                  ? `瞬时放行 ${p2pReport.openPinholes} 个 IP`
                  : p2pLiveEnabled
                  ? '0 开放 · 零暴露'
                  : '未开启'}
              </Badge>
            )}
            <Button size="sm" variant="ghost" onClick={loadP2P} disabled={p2pLoading}>
              <RefreshCw className={`w-3.5 h-3.5 ${p2pLoading ? 'animate-spin' : ''}`} />
              刷新
            </Button>
          </div>
        }
      >
        <div className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs">
            <div
              className="flex items-center justify-between gap-3 p-3.5 rounded-xl border border-subtle bg-surface2 cursor-default"
              title="核心防线默认强制开启，确保 UDP :41641 不长期裸露公网"
            >
              <div className="min-w-0">
                <div className="font-semibold text-primary flex items-center gap-1.5 flex-wrap">
                  <span>启用防线守护</span>
                  <span className="text-[10px] px-1.5 py-0.5 rounded bg-[var(--accent)]/15 text-[var(--accent)] font-medium">
                    必选
                  </span>
                </div>
                <div className="text-[11px] text-secondary mt-1 truncate">
                  {p2pReport?.fw4Available
                    ? p2pReport.runtime?.applyMode === 'nft_direct'
                      ? 'OpenWrt nftables 原子注入就绪'
                      : 'OpenWrt fw4 原生热重载就绪'
                    : '未检测到 inet fw4 表'}
                </div>
              </div>
              <input
                type="checkbox"
                checked
                readOnly
                tabIndex={-1}
                aria-label="启用防线守护（必选）"
                className="accent-[var(--accent)] w-4 h-4 shrink-0 pointer-events-none"
              />
            </div>

            <div
              className="flex items-center justify-between gap-3 p-3.5 rounded-xl border border-subtle bg-surface2 cursor-default"
              title="核心安全拦截默认强制开启，仅放行 STUN / DISCO / WireGuard 合法载荷"
            >
              <div className="min-w-0">
                <div className="font-semibold text-primary flex items-center gap-1.5 flex-wrap">
                  <span>Layer 2 载荷魔法头过滤</span>
                  <span className="text-[10px] px-1.5 py-0.5 rounded bg-[var(--accent)]/15 text-[var(--accent)] font-medium">
                    必选
                  </span>
                </div>
                <div className="text-[11px] text-secondary mt-1 truncate">
                  UDP :41641 仅放行 STUN / DISCO / WireGuard
                </div>
              </div>
              <input
                type="checkbox"
                checked
                readOnly
                tabIndex={-1}
                aria-label="Layer 2 载荷魔法头过滤（必选）"
                className="accent-[var(--accent)] w-4 h-4 shrink-0 pointer-events-none"
              />
            </div>

            <label
              className={`flex items-center justify-between gap-3 p-3.5 rounded-xl border border-subtle bg-surface2 ${
                p2pReport?.ujailAvailable ? 'cursor-pointer' : 'opacity-60 cursor-not-allowed'
              }`}
              title={p2pReport?.ujailAvailable ? '重启 tailscaled 进入 OpenWrt ujail 沙盒' : '当前环境无 /sbin/ujail'}
            >
              <div className="min-w-0">
                <div className="font-semibold text-primary flex items-center gap-1.5 flex-wrap">
                  <span>Layer 3 ujail 沙盒隔离</span>
                  <span className="text-[10px] px-1.5 py-0.5 rounded bg-surface1 text-secondary border border-subtle font-medium">
                    {p2pReport?.ujailAvailable ? '默认开启 · 可取消' : '不可用'}
                  </span>
                </div>
                <div className="text-[11px] text-secondary mt-1 truncate">
                  {p2pReport?.ujailAvailable ? '裁剪 Capabilities 并隔离敏感配置目录' : '当前环境无 /sbin/ujail'}
                </div>
              </div>
              <input
                type="checkbox"
                disabled={!p2pReport?.ujailAvailable}
                checked={sandboxUjail}
                onChange={(e) => {
                  p2pDirtyRef.current = true;
                  setSandboxUjail(e.target.checked);
                }}
                aria-label="Layer 3 ujail 沙盒隔离"
                className="accent-[var(--accent)] w-4 h-4 shrink-0"
              />
            </label>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
            <div className="p-3 rounded-xl border border-subtle bg-surface2">
              <label className="block font-semibold text-primary mb-1">JIT 瞬时窗口（秒）</label>
              <input
                type="number"
                min={3}
                max={10}
                value={jitWindowSec}
                onChange={(e) => {
                  p2pDirtyRef.current = true;
                  setJitWindowSec(Number(e.target.value));
                }}
                className="w-full px-2.5 py-1.5 rounded-lg border border-subtle bg-surface1 font-mono text-xs text-primary focus:outline-none focus:border-[var(--accent)]"
              />
            </div>

            <div className="p-3 rounded-xl border border-subtle bg-surface2">
              <label className="block font-semibold text-primary mb-1">失败冷却退避（秒）</label>
              <input
                type="number"
                min={30}
                max={3600}
                value={cooldownSec}
                onChange={(e) => {
                  p2pDirtyRef.current = true;
                  setCooldownSec(Number(e.target.value));
                }}
                className="w-full px-2.5 py-1.5 rounded-lg border border-subtle bg-surface1 font-mono text-xs text-primary focus:outline-none focus:border-[var(--accent)]"
              />
            </div>
          </div>

          <div className="p-3 rounded-xl border border-subtle bg-surface2/60 text-xs text-secondary leading-relaxed">
            未勾选「纳入防线管控」的个人管理员终端（如您的 MacBook、iPhone）保持 24/7 全量放行不受入向子网锁死限制；仅勾选需要隔离或 P2P 协助的异地路由器/节点。
          </div>

          <div className="space-y-3">
            {(p2pReport?.peers || []).length === 0 ? (
              <div className="p-4 rounded-xl border border-subtle bg-surface2 text-xs text-secondary text-center">
                {p2pLoading ? '正在读取 Tailscale 节点拓扑…' : '暂无已发现的 Tailscale 对端节点'}
              </div>
            ) : (
              (p2pReport?.peers || []).map((p, peerIdx) => {
                const k = peerEditKey(p);
                const ed = peerEdits[k];
                if (!ed) return null;
                const isDirect = Boolean(p.curAddr);
                const showLANTargets =
                  ed.configured && (ed.accessMode === 'bidirectional' || ed.accessMode === 'bidirectional_timed');

                return (
                  <div key={k} className="p-3.5 rounded-xl border border-subtle bg-surface2 space-y-3">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <div className="min-w-0">
                        <div className="flex flex-wrap items-center gap-2">
                          <span className="text-xs sm:text-sm font-semibold text-primary">
                            {privacyMask ? `对端节点 #${peerIdx + 1}` : p.shortName || p.name || p.hostName}
                          </span>
                          <Badge tone={p.online ? 'ok' : 'neutral'} dot>
                            {p.online ? '在线' : '离线'}
                          </Badge>
                          {p.online && (
                            <Badge tone={isDirect ? 'ok' : 'warn'}>
                              {isDirect ? 'P2P 直连' : `DERP 中继${!privacyMask && p.relay ? ` (${p.relay})` : ''}`}
                            </Badge>
                          )}
                          {p.pinholeActive && <Badge tone="warn">JIT 窗口放行中</Badge>}
                          {p.cooldownRemainingSec > 0 && (
                            <Badge tone="neutral">退避冷却 {p.cooldownRemainingSec}s</Badge>
                          )}
                        </div>
                        <div className="text-[11px] font-mono text-secondary mt-1 flex flex-wrap gap-x-3 gap-y-0.5">
                          <span>IP: {privacyMask ? '••••••••' : p.tailscaleIPs?.join(', ') || '-'}</span>
                          {p.primaryRoutes && p.primaryRoutes.length > 0 && (
                            <span>广播子网: {privacyMask ? '••••••••' : p.primaryRoutes.join(', ')}</span>
                          )}
                          <span>候选公网端点: {p.candidatePublicCount}</span>
                          {p.lastUpgradeAt && <span>最近直连: {p.lastUpgradeAt}</span>}
                        </div>
                      </div>

                      <div className="flex items-center gap-2">
                        <Button
                          size="sm"
                          disabled={!p2pLiveEnabled || !ed.configured || !ed.jitEnabled || !p.online || pokingKey === k}
                          onClick={() => handlePokePeer(p)}
                        >
                          <Zap className="w-3.5 h-3.5" />
                          {pokingKey === k ? '打洞中…' : '测试瞬时打洞'}
                        </Button>
                      </div>
                    </div>

                    <div className="flex flex-wrap items-center gap-4 pt-2 border-t border-subtle text-xs">
                      <label className="inline-flex items-center gap-2 cursor-pointer text-primary">
                        <input
                          type="checkbox"
                          checked={ed.configured}
                          onChange={(e) => updatePeerEdit(k, { configured: e.target.checked })}
                          className="accent-[var(--accent)] w-4 h-4"
                        />
                        <span>纳入防线管控</span>
                      </label>

                      {ed.configured && (
                        <>
                          <label className="inline-flex items-center gap-2 cursor-pointer text-primary">
                            <input
                              type="checkbox"
                              checked={ed.jitEnabled}
                              onChange={(e) => updatePeerEdit(k, { jitEnabled: e.target.checked })}
                              className="accent-[var(--accent)] w-4 h-4"
                            />
                            <span>允许 JIT 自动瞬时打洞</span>
                          </label>

                          <SegmentedTabs
                            items={P2P_ACCESS_MODES}
                            value={ed.accessMode}
                            onChange={(val) => {
                              const nextMode = val as TailscaleAccessMode;
                              const patch: Partial<EditableP2PPeer> = { accessMode: nextMode };
                              if (nextMode === 'bidirectional_timed' && !ed.bidirectionalUntil) {
                                patch.bidirectionalUntil = new Date(Date.now() + 7 * 86400 * 1000)
                                  .toISOString()
                                  .replace(/\.\d{3}Z$/, 'Z');
                              }
                              updatePeerEdit(k, patch);
                            }}
                          />
                        </>
                      )}
                    </div>

                    {showLANTargets && (
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-3 pt-2 border-t border-subtle text-xs">
                        {ed.accessMode === 'bidirectional_timed' && (
                          <div className="space-y-1.5">
                            <div className="flex items-center justify-between gap-2">
                              <span className="font-medium text-primary">限时双向到期时间 (UTC RFC3339)</span>
                              <span className="text-[11px] font-mono text-secondary">
                                {p.bidirectionalRemainingSec > 0
                                  ? formatRemainingCountdown(p.bidirectionalRemainingSec)
                                  : '保存后按设定倒计时生效'}
                              </span>
                            </div>
                            <input
                              type="text"
                              value={ed.bidirectionalUntil}
                              onChange={(e) => updatePeerEdit(k, { bidirectionalUntil: e.target.value })}
                              placeholder="2026-12-01T00:00:00Z"
                              className="w-full px-2.5 py-1.5 rounded-lg border border-subtle bg-surface1 font-mono text-xs text-primary"
                            />
                            <div className="flex flex-wrap gap-1.5">
                              {[7, 15, 30].map((d) => (
                                <Button key={d} size="sm" onClick={() => applyQuickDays(k, d)}>
                                  +{d}天
                                </Button>
                              ))}
                            </div>
                          </div>
                        )}

                        <div className="space-y-1.5">
                          <span className="block font-medium text-primary">
                            允许对方主动访问的本机 LAN 目标（留空默认{' '}
                            {privacyMask ? '本地 LAN 网段 (已遮挡)' : p2pReport?.defaultLanCidr || '本地 LAN 网段'}）
                          </span>
                          <input
                            type={privacyMask ? 'password' : 'text'}
                            readOnly={privacyMask}
                            value={ed.allowedLanTargetsText}
                            onChange={(e) => updatePeerEdit(k, { allowedLanTargetsText: e.target.value })}
                            placeholder={
                              privacyMask
                                ? '••••••••'
                                : p2pReport?.defaultLanCidr
                                ? `${p2pReport.defaultLanCidr}, 192.168.1.10:445`
                                : '192.168.1.0/24, 192.168.1.10:445'
                            }
                            className="w-full px-2.5 py-1.5 rounded-lg border border-subtle bg-surface1 font-mono text-xs text-primary"
                          />
                        </div>
                      </div>
                    )}
                  </div>
                );
              })
            )}
          </div>

          <div className="flex flex-wrap items-center justify-between gap-3 pt-2 border-t border-subtle">
            <div className="text-[11px] text-secondary font-mono">
              {p2pReport?.runtime?.lastError
                ? `最近状态异常: ${redactInlineSensitive(p2pReport.runtime.lastError, privacyMask)}`
                : p2pReport?.runtime?.updatedAt
                ? `最近守护收敛: ${p2pReport.runtime.updatedAt}`
                : '修改配置并保存后立即下发防火墙与看门狗'}
            </div>
            <Button variant="primary" disabled={p2pSaving || privacyMask} onClick={handleSaveP2P}>
              <Save className="w-3.5 h-3.5" />
              {p2pSaving ? '正在下发规则…' : '保存并应用防线策略'}
            </Button>
          </div>
        </div>
      </SectionCard>

      <ConfirmDialog
        open={stopConfirmOpen}
        title="确认停止 Tailscale 服务"
        description="确认执行 tailscale down 并停止守护进程？若当前正通过 Tailscale 隧道远程管理路由器，停止后将立即断开连接。"
        confirmText="确认停止服务"
        onConfirm={() => {
          setStopConfirmOpen(false);
          onAction('ts-stop');
        }}
        onCancel={() => setStopConfirmOpen(false)}
      />

      <ConfirmDialog
        open={reconfigConfirmOpen}
        title="确认在线热切换 Tailscale 模式"
        description={`确认将运行模式切换为「${selectedModeLabel}」（--accept-routes=${String(acceptRoutes)}）？将通过 tailscale up --reset 在线重配参数而无需重启服务（期间隧道可能短暂重建 1~3 秒）。`}
        confirmText="确认保存并热切换"
        danger={false}
        onConfirm={() => {
          setReconfigConfirmOpen(false);
          onAction('ts-start', { mode, acceptRoutes, reconfigure: true });
        }}
        onCancel={() => setReconfigConfirmOpen(false)}
      />

      <SlideDrawer
        open={upgradeDrawerOpen}
        onClose={() => setUpgradeDrawerOpen(false)}
        title="Tailscale 零失联安全升级 · 升级前体检"
        subtitle="Phase 1 零 /tmp 流式落盘与 SHA256/ELF 兼容预检；Phase 2 脱离父进程原子切换 + 25s 健康门禁自动回滚"
        size="lg"
        headerExtra={
          <Button
            size="xs"
            variant="ghost"
            onClick={() => void loadUpgradePreflight()}
            disabled={preflightLoading}
            icon={<RefreshCw className={`w-3.5 h-3.5 ${preflightLoading ? 'animate-spin' : ''}`} />}
          >
            重新体检
          </Button>
        }
        footer={
          <div className="flex flex-wrap items-center justify-between gap-3">
            <span className="text-[11px] text-slate-400">
              {preflight?.supported
                ? preflight.viaTailscale
                  ? '经 Tailscale 访问已启用 2s 优雅缓冲与自动重连'
                  : '失败时将在 25s 内自动还原旧版本并重启隧道'
                : '当前平台不支持在线升级'}
            </span>
            <div className="flex items-center gap-2">
              <Button variant="secondary" onClick={() => setUpgradeDrawerOpen(false)}>
                取消
              </Button>
              <Button
                variant="primary"
                disabled={
                  busy ||
                  preflightLoading ||
                  !preflight?.supported ||
                  (preflight.upToDate && !forceReinstall ? true : !preflight.canForceProceed)
                }
                icon={<Download className="w-3.5 h-3.5" />}
                onClick={() => {
                  setUpgradeDrawerOpen(false);
                  onAction('ts-update', { force: forceReinstall });
                }}
              >
                {preflight?.upToDate && forceReinstall ? '强制重刷当前版本' : '开始零失联升级'}
              </Button>
            </div>
          </div>
        }
      >
        {preflightLoading && !preflight ? (
          <div className="py-10 text-center text-xs text-slate-400 flex items-center justify-center gap-2">
            <RefreshCw className="w-4 h-4 animate-spin text-sky-400" />
            正在直连 GitHub API 获取版本摘要并检测 Flash / 内存环境…
          </div>
        ) : preflightError ? (
          <div className="p-3.5 rounded-xl border border-rose-500/35 bg-rose-500/10 text-xs text-rose-200 space-y-2">
            <div className="font-semibold flex items-center gap-1.5">
              <AlertTriangle className="w-4 h-4 shrink-0" />
              升级前体检失败
            </div>
            <p className="leading-relaxed">{preflightError}</p>
          </div>
        ) : preflight ? (
          <div className="space-y-4 text-xs">
            {!preflight.supported ? (
              <div className="p-3.5 rounded-xl border border-amber-500/35 bg-amber-500/10 text-amber-200 space-y-1">
                <div className="font-semibold">当前系统不受支持</div>
                <p>{preflight.unsupportedReason || '仅支持 Linux / OpenWrt 设备。'}</p>
              </div>
            ) : (
              <>
                {preflight.viaTailscale && (
                  <div className="p-3 rounded-xl border border-sky-500/30 bg-sky-500/10 text-sky-200 flex items-start gap-2.5 leading-relaxed">
                    <ShieldCheck className="w-4 h-4 shrink-0 mt-0.5 text-sky-300" />
                    <div>
                      <div className="font-semibold text-white">已检测到通过 Tailscale 隧道远程访问控制台</div>
                      <div className="text-[11px] text-sky-200/90 mt-0.5">
                        切换过程将在独立会话（setsid）中运行，并在停止旧隧道前预留 2 秒缓冲；期间 WebUI 将自动进入无感重连等待（不弹过期登录框）。
                      </div>
                    </div>
                  </div>
                )}

                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                  <div className="p-3.5 rounded-xl border border-subtle bg-surface2/70 space-y-2">
                    <div className="flex items-center justify-between gap-2">
                      <span className="font-semibold text-primary">版本与产物元数据</span>
                      <Badge tone={preflight.hasOfficialDigest ? 'ok' : 'warn'}>
                        {preflight.hasOfficialDigest ? 'SHA256 官方强校验' : '大小校验'}
                      </Badge>
                    </div>
                    <div className="space-y-1.5 text-[11px]">
                      <div className="flex justify-between gap-2">
                        <span className="text-secondary">版本变化</span>
                        <span className="font-mono text-primary">
                          {preflight.currentVersion || '未安装'} → {preflight.latestVersion || '-'}
                        </span>
                      </div>
                      <div className="flex justify-between gap-2">
                        <span className="text-secondary">目标架构 / 形态</span>
                        <span className="font-mono text-primary">
                          {preflight.arch || '-'}{' '}
                          {preflight.combinedMinimal ? '· 精简合体版' : '· 标准双二进制'}
                        </span>
                      </div>
                      <div className="flex justify-between gap-2">
                        <span className="text-secondary">服务管理器</span>
                        <span className="font-mono text-primary">
                          {preflight.initSystem === 'procd'
                            ? 'OpenWrt procd'
                            : preflight.initSystem === 'systemd'
                            ? 'Linux systemd'
                            : preflight.initSystem || '未识别'}
                        </span>
                      </div>
                    </div>
                  </div>

                  <div className="p-3.5 rounded-xl border border-subtle bg-surface2/70 space-y-2">
                    <div className="flex items-center justify-between gap-2">
                      <span className="font-semibold text-primary flex items-center gap-1.5">
                        <HardDrive className="w-3.5 h-3.5 text-sky-400" />
                        存储与内存体检
                      </span>
                      <Badge tone={preflight.blockedReasons?.length ? 'danger' : 'ok'}>
                        {preflight.blockedReasons?.length ? '门禁拦截' : '空间充裕'}
                      </Badge>
                    </div>
                    <div className="space-y-1.5 text-[11px]">
                      <div className="flex justify-between gap-2">
                        <span className="text-secondary">Flash 剩余空间</span>
                        <span className="font-mono text-primary">
                          {formatBytes(preflight.flashFreeBytes)}
                        </span>
                      </div>
                      <div className="flex justify-between gap-2">
                        <span className="text-secondary">安全切换所需（含回滚）</span>
                        <span className="font-mono text-primary">
                          {formatBytes(preflight.requiredFreeBytes)}
                        </span>
                      </div>
                      <div className="flex justify-between gap-2">
                        <span className="text-secondary flex items-center gap-1">
                          <Cpu className="w-3 h-3" />
                          可用内存 / Swap
                        </span>
                        <span className="font-mono text-primary">
                          {formatBytes(preflight.memAvailableBytes)}
                          {preflight.swapFreeBytes > 0 ? ` / ${formatBytes(preflight.swapFreeBytes)}` : ''}
                        </span>
                      </div>
                      <div className="text-[10.5px] text-emerald-300/90 pt-0.5">
                        ✓ 流式直写 Flash · 0 MB /tmp 内存占用
                      </div>
                    </div>
                  </div>
                </div>

                {(preflight.blockedReasons?.length ?? 0) > 0 && (
                  <div className="p-3.5 rounded-xl border border-rose-500/35 bg-rose-500/10 text-rose-200 space-y-1.5">
                    <div className="font-semibold flex items-center gap-1.5">
                      <AlertTriangle className="w-4 h-4 shrink-0" />
                      以下安全门禁阻止本次升级：
                    </div>
                    <ul className="list-disc pl-5 space-y-1 text-[11px]">
                      {preflight.blockedReasons?.map((r, i) => (
                        <li key={i}>{r}</li>
                      ))}
                    </ul>
                  </div>
                )}

                {(preflight.warnings?.length ?? 0) > 0 && (
                  <div className="p-3 rounded-xl border border-amber-500/30 bg-amber-500/10 text-amber-200 space-y-1 text-[11px]">
                    {preflight.warnings?.map((w, i) => (
                      <div key={i}>• {w}</div>
                    ))}
                  </div>
                )}

                {preflight.upToDate && (
                  <div className="p-3.5 rounded-xl border border-emerald-500/30 bg-emerald-500/10 space-y-2.5">
                    <div className="flex items-center gap-2 text-emerald-200 font-semibold">
                      <CheckCircle2 className="w-4 h-4 shrink-0" />
                      当前已是最新版本 ({preflight.currentVersion})
                    </div>
                    <label className="flex items-start gap-2 text-[11px] text-slate-200 cursor-pointer select-none">
                      <input
                        type="checkbox"
                        checked={forceReinstall}
                        disabled={!preflight.canForceProceed}
                        onChange={(e) => setForceReinstall(e.target.checked)}
                        className="accent-[var(--accent)] mt-0.5 w-3.5 h-3.5"
                      />
                      <span>
                        强制重刷当前版本（<code className="font-mono">--force</code>）：可用于验证零失联切换流程、切换为精简合体版或修复受损二进制。
                      </span>
                    </label>
                  </div>
                )}

                {preflight.activeSwap && preflight.activeSwap.phase !== 'idle' && (
                  <div className="p-3.5 rounded-xl border border-subtle bg-surface2/60 space-y-2">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <span className="font-semibold text-primary flex items-center gap-1.5">
                        <Terminal className="w-3.5 h-3.5 text-slate-400" />
                        最近一次后台切换记录
                      </span>
                      <Badge
                        tone={
                          preflight.activeSwap.phase === 'succeeded'
                            ? 'ok'
                            : preflight.activeSwap.phase === 'rolled_back' || preflight.activeSwap.phase === 'failed'
                            ? 'warn'
                            : 'accent'
                        }
                      >
                        {preflight.activeSwap.phase}
                      </Badge>
                    </div>
                    {preflight.activeSwap.message && (
                      <div className="text-[11px] text-secondary leading-relaxed">
                        {redactInlineSensitive(preflight.activeSwap.message, privacyMask)}
                      </div>
                    )}
                    {preflight.activeSwap.error && (
                      <div className="text-[11px] text-rose-300 font-mono">
                        {redactInlineSensitive(preflight.activeSwap.error, privacyMask)}
                      </div>
                    )}
                    {preflight.activeSwap.logTail && (
                      <div>
                        <button
                          type="button"
                          onClick={() => setShowSwapLogTail((v) => !v)}
                          className="text-[11px] text-sky-400 hover:text-sky-300 underline cursor-pointer"
                        >
                          {showSwapLogTail ? '收起切换日志' : '展开详细切换日志'}
                        </button>
                        {showSwapLogTail && (
                          <pre className="mt-2 p-2.5 rounded-lg bg-[#070a10] border border-white/10 text-[10.5px] font-mono text-slate-300 max-h-48 overflow-auto whitespace-pre-wrap break-all">
                            {redactInlineSensitive(preflight.activeSwap.logTail, privacyMask)}
                          </pre>
                        )}
                      </div>
                    )}
                  </div>
                )}
              </>
            )}
          </div>
        ) : null}
      </SlideDrawer>
    </div>
  );
};

export interface GatewayModePageProps {
  status?: ClientStatusResponse | null;
  busy: boolean;
  privacyMask?: boolean;
  onSaved?: () => void;
}

const SECONDARY_ROUTER_IPV6_CMD = `cp -a /etc/config/dhcp /etc/config/dhcp.bak && chmod 600 /etc/config/dhcp.bak && \\
uci set dhcp.@dnsmasq[0].dnsforwardmax=1024 && \\
for s in $(uci show dhcp | sed -n 's/^dhcp\\.\\([^.=]*\\)=dhcp$/\\1/p'); do
  [ "$s" = "wan" ] || [ "$s" = "wan6" ] && continue
  uci set "dhcp.$s.ra_dns=0"
  uci set "dhcp.$s.dns_service=0"
done && \\
uci commit dhcp && /etc/init.d/odhcpd reload && /etc/init.d/dnsmasq reload`;

export const GatewayModePage: React.FC<GatewayModePageProps> = ({
  status,
  busy,
  privacyMask = false,
  onSaved,
}) => {
  const { success, error } = useToast();
  const {
    data,
    loading,
    refreshing,
    setData: setGatewayData,
    refetch: refetchGateway,
  } = useCachedQuery<ClientGatewayConfigResponse>(GATEWAY_CACHE_KEY, () => clientApi.getGateway());

  const [saving, setSaving] = useState(false);
  const [ipv6Saving, setIpv6Saving] = useState(false);
  const [copiedSubCmd, setCopiedSubCmd] = useState(false);

  const gwSummary = status?.gateway;

  const [mode, setMode] = useState<GatewayRoleMode | null>(() => {
    if (data?.mode) return data.mode === 'side' ? 'side' : 'main';
    if (gwSummary?.mode) return gwSummary.mode === 'side' ? 'side' : 'main';
    return null;
  });
  const [mainRouterIP, setMainRouterIP] = useState<string>(
    () => data?.mainRouterIP || data?.topology?.suggestedMainRouterIP || gwSummary?.mainRouterIP || '',
  );
  const [ipv6Mode, setIpv6Mode] = useState<GatewayIPv6Mode | null>(
    () => (data?.ipv6Mode as GatewayIPv6Mode | undefined) || (gwSummary?.ipv6Mode as GatewayIPv6Mode | undefined) || null,
  );
  const [modeDirty, setModeDirty] = useState(false);
  const [mainRouterDirty, setMainRouterDirty] = useState(false);
  const [ipv6Dirty, setIpv6Dirty] = useState(false);

  useEffect(() => {
    if (data) {
      if (!modeDirty) {
        setMode(data.mode === 'side' ? 'side' : 'main');
      }
      if (!mainRouterDirty) {
        setMainRouterIP(data.mainRouterIP || data.topology?.suggestedMainRouterIP || '');
      }
      if (!ipv6Dirty) {
        setIpv6Mode((data.ipv6Mode as GatewayIPv6Mode) || 'off');
      }
      return;
    }
    if (gwSummary) {
      if (!modeDirty && mode === null && gwSummary.mode) {
        setMode(gwSummary.mode === 'side' ? 'side' : 'main');
      }
      if (!mainRouterDirty && !mainRouterIP && gwSummary.mainRouterIP) {
        setMainRouterIP(gwSummary.mainRouterIP);
      }
      if (!ipv6Dirty && ipv6Mode === null && gwSummary.ipv6Mode) {
        setIpv6Mode(gwSummary.ipv6Mode);
      }
    }
  }, [data, gwSummary, modeDirty, mainRouterDirty, ipv6Dirty, mode, mainRouterIP, ipv6Mode]);

  const handleCopySubRouterCmd = async () => {
    try {
      await copyPlainText(SECONDARY_ROUTER_IPV6_CMD);
      setCopiedSubCmd(true);
      success('已复制二级路由一键加固命令');
      window.setTimeout(() => setCopiedSubCmd(false), 2000);
    } catch {
      error('复制失败，请手动选中下方命令复制');
    }
  };

  const loadGateway = useCallback(async () => {
    try {
      await refetchGateway(false);
    } catch (e: unknown) {
      error(e instanceof Error ? e.message : '读取网关模式配置失败');
    }
  }, [error, refetchGateway]);

  const topo = data?.topology;
  const v6Status = data?.ipv6Status;
  const trimmedIP = mainRouterIP.trim();
  const isSelfLoop = Boolean(mode === 'side' && topo?.lanIP && trimmedIP === topo.lanIP);
  const activeGatewayMode = data?.mode ?? gwSummary?.mode ?? mode;
  const effectiveDisplayIPv6Mode: GatewayIPv6Mode | null =
    mode === 'side' ? 'off' : ipv6Mode ?? (data?.ipv6Mode as GatewayIPv6Mode | undefined) ?? gwSummary?.ipv6Mode ?? null;

  const handleSelectMode = (nextMode: GatewayRoleMode) => {
    setMode(nextMode);
    setModeDirty(true);
    if (nextMode === 'side') {
      setIpv6Mode('off');
      setIpv6Dirty(true);
      if (!trimmedIP && topo?.suggestedMainRouterIP) {
        setMainRouterIP(topo.suggestedMainRouterIP);
      }
    }
  };

  const handleSave = async (forIPv6 = false) => {
    if (!mode || privacyMask) return;
    if (mode === 'side' && !trimmedIP) {
      error('旁路由模式请填写上级主路由(网关) IP');
      return;
    }
    if (isSelfLoop) {
      error(`上级主路由 IP 不能等于旁路由本机 IP (${topo?.lanIP})`);
      return;
    }
    const effectiveV6: GatewayIPv6Mode = mode === 'side' ? 'off' : ipv6Mode || 'off';
    if (forIPv6) {
      setIpv6Saving(true);
    } else {
      setSaving(true);
    }
    try {
      const res = await clientApi.saveGateway({
        mode,
        mainRouterIP: mode === 'side' ? trimmedIP : '',
        ipv6Mode: effectiveV6,
      });
      setGatewayData(res);
      setMode(res.mode);
      setMainRouterIP(res.mainRouterIP || res.topology?.suggestedMainRouterIP || '');
      setIpv6Mode((res.ipv6Mode as GatewayIPv6Mode) || effectiveV6);
      setModeDirty(false);
      setMainRouterDirty(false);
      setIpv6Dirty(false);
      success(res.message || '网关模式已保存');
      onSaved?.();
    } catch (e: unknown) {
      error(e instanceof Error ? e.message : '保存网关模式失败');
    } finally {
      setSaving(false);
      setIpv6Saving(false);
    }
  };

  const sideLanDisplay = privacyMask ? '••••••••' : topo?.lanIP || '<旁路由IP>';
  const mainGwDisplay = privacyMask ? '••••••••' : trimmedIP || topo?.suggestedMainRouterIP || '<主路由IP>';

  return (
    <div className="space-y-5">
      <PageHeader
        title="网关部署模式"
        description="默认主路由模式；单网口挂在主路由下做旁路由时可在此一键切换"
        badge={
          <Badge
            tone={!activeGatewayMode ? 'neutral' : activeGatewayMode === 'side' ? 'accent' : 'ok'}
            dot={Boolean(activeGatewayMode)}
          >
            {!activeGatewayMode
              ? '读取中…'
              : activeGatewayMode === 'side'
              ? '当前：旁路由模式 (Side)'
              : '当前：主路由模式 (Main)'}
          </Badge>
        }
        actions={
          <Button
            size="xs"
            loading={loading || refreshing}
            onClick={() => void loadGateway()}
            icon={<RefreshCw className="w-3 h-3" />}
          >
            重新探测拓扑
          </Button>
        }
      />

      <SectionCard
        title="选择客户端网关角色"
        icon={<GitFork className="w-4 h-4" />}
        subtitle="主路由模式不加载任何旁路由附加规则；旁路由模式自动挂载独立可逆的内核转发与单臂防丢包规则"
      >
        <div className="space-y-4">
          {topo?.selfLooped && (
            <div className="rounded-xl border border-amber-500/35 bg-amber-500/10 px-3.5 py-2.5 text-xs text-amber-200 flex items-start gap-2">
              <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
              <span>
                检测到当前系统默认网关已误指回本机 ({maskFullIP(topo.lanIP, privacyMask)})！请确认下方上级主路由 IP 并保存，系统将自动修复默认路由避免死循环。
              </span>
            </div>
          )}

          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {[
              {
                key: 'main' as GatewayRoleMode,
                title: '主路由模式 (Main Router)',
                tag: '默认推荐',
                desc: '设备本身直接拨号或连接光猫，作为全屋主网关运行（保持原生 TProxy 规则零变动）。',
              },
              {
                key: 'side' as GatewayRoleMode,
                title: '旁路由模式 (Side Router)',
                tag: '单臂网关',
                desc: '单网口接入主路由 LAN 口，自动开启转发、MSS 钳制与单臂防非对称丢包，同时保留终端真实 IP 审计。',
              },
            ].map((opt) => {
              const active = mode !== null && mode === opt.key;
              return (
                <button
                  key={opt.key}
                  type="button"
                  disabled={mode === null}
                  onClick={() => handleSelectMode(opt.key)}
                  style={
                    active
                      ? {
                          backgroundColor: 'var(--accent-soft)',
                          borderColor: 'var(--accent)',
                        }
                      : undefined
                  }
                  className={`p-4 rounded-xl border text-left transition-all cursor-pointer ${
                    active ? '' : 'bg-surface2 border-subtle hover:border-strong'
                  }`}
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-xs sm:text-sm font-semibold text-primary">{opt.title}</span>
                    <span className="text-[10px] px-1.5 py-0.5 rounded bg-surface1 text-secondary border border-subtle">
                      {opt.tag}
                    </span>
                  </div>
                  <p className="text-xs text-secondary mt-1.5 leading-relaxed">{opt.desc}</p>
                </button>
              );
            })}
          </div>

          {mode === 'side' && (
            <div className="rounded-xl bg-surface2 border border-subtle p-4 space-y-3">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                <div>
                  <label htmlFor="main-router-ip-input" className="text-xs sm:text-sm font-semibold text-primary">
                    上级主路由（网关）IPv4 地址
                  </label>
                  <p className="text-[11px] text-secondary mt-0.5">
                    已自动探测候选网关，确认无误可直接保存；若与实际主路由不符请手动修改。
                  </p>
                </div>
                {topo?.suggestedMainRouterIP && trimmedIP !== topo.suggestedMainRouterIP && !privacyMask && (
                  <Button
                    size="xs"
                    variant="ghost"
                    onClick={() => {
                      setMainRouterIP(topo.suggestedMainRouterIP);
                      setMainRouterDirty(true);
                    }}
                  >
                    填入探测值 ({topo.suggestedMainRouterIP})
                  </Button>
                )}
              </div>

              <input
                id="main-router-ip-input"
                type={privacyMask ? 'password' : 'text'}
                readOnly={privacyMask}
                value={mainRouterIP}
                onChange={(e) => {
                  setMainRouterIP(e.target.value);
                  setMainRouterDirty(true);
                }}
                placeholder={privacyMask ? '••••••••' : topo?.suggestedMainRouterIP || '例如 192.168.1.1'}
                className="sc-input w-full sm:max-w-xs h-9 px-3 text-xs sm:text-sm font-mono"
              />

              {isSelfLoop && (
                <p className="text-xs text-rose-400">
                  上级主路由 IP 不能等于旁路由本机地址 ({maskFullIP(topo?.lanIP, privacyMask)})，否则会引发路由死循环！
                </p>
              )}
            </div>
          )}

          <div className="flex flex-wrap items-center justify-between gap-3 pt-2 border-t border-subtle">
            <div className="text-xs text-secondary font-mono">
              本机地址: <span className="text-primary">{maskFullIP(topo?.lanIP, privacyMask)}</span> · 网卡:{' '}
              <span className="text-primary">{topo?.lanIface || '-'}</span> · 系统当前网关:{' '}
              <span className="text-primary">{maskFullIP(topo?.currentGatewayIP, privacyMask)}</span>
            </div>

            <Button
              variant="primary"
              loading={saving}
              disabled={busy || !mode || isSelfLoop || privacyMask}
              title={privacyMask ? '隐私完全遮挡开启期间已锁定修改，避免误改网络配置' : undefined}
              icon={<Save className="w-3.5 h-3.5" />}
              onClick={() => void handleSave()}
            >
              保存并应用模式
            </Button>
          </div>
        </div>
      </SectionCard>

      {mode === 'side' && (
        <SectionCard
          title="旁路由终端与主路由 DHCP 接入指引"
          icon={<CheckCircle2 className="w-4 h-4" />}
        >
          <div className="space-y-2.5 text-xs sm:text-sm text-secondary leading-relaxed">
            <p>
              1. <strong className="text-primary">单设备测试接入</strong>：将手机或电脑 Wi-Fi / 有线网络的{' '}
              <code className="font-mono text-emerald-300">默认网关</code> 与{' '}
              <code className="font-mono text-emerald-300">DNS 服务器</code> 同时设为旁路由地址{' '}
              <code className="font-mono text-cyan-300">{sideLanDisplay}</code>。
            </p>
            <p>
              2. <strong className="text-primary">全屋自动透明生效</strong>：登录上级主路由（
              <code className="font-mono text-primary">{mainGwDisplay}</code>）后台，在 LAN 口 DHCP 设置中将下发的「默认网关」与「DNS 服务器」填写为{' '}
              <code className="font-mono text-cyan-300">{sideLanDisplay}</code>（切勿修改主路由 WAN 口上游 DNS）。
            </p>
            <p>
              3. <strong className="text-primary">防绕过与防自环提醒</strong>：请为旁路由本机固定静态 IP（或在主路由绑定静态租约），并在主路由关闭 LAN 侧{' '}
              <code className="font-mono text-amber-300">IPv6 RA / DHCPv6</code> 通告，防止手机经主路由 IPv6 直出绕过旁路由。
            </p>
          </div>
        </SectionCard>
      )}

      <SectionCard
        title="IPv6 智能双栈分流 (自动探测与配置)"
        icon={<Network className="w-4 h-4" />}
        subtitle="主路由开启时自动探测 WAN 前缀，一键托管 OpenWrt RA/DHCPv6、dnsmasq 放行与本地防 DNS 泄漏策略"
        actions={
          <Badge
            tone={
              effectiveDisplayIPv6Mode === null
                ? 'neutral'
                : effectiveDisplayIPv6Mode === 'off'
                ? 'neutral'
                : effectiveDisplayIPv6Mode === 'cn_only'
                  ? 'ok'
                  : 'accent'
            }
          >
            {effectiveDisplayIPv6Mode === null
              ? '读取策略中…'
              : effectiveDisplayIPv6Mode === 'cn_only'
              ? '当前：智能双栈 (推荐)'
              : effectiveDisplayIPv6Mode === 'full'
                ? '当前：全量双栈'
                : '当前：纯 IPv4'}
          </Badge>
        }
      >
        <div className="space-y-4">
          {v6Status && (
            <div className="rounded-xl border border-subtle bg-surface2/60 px-3.5 py-2.5 flex flex-wrap items-center gap-x-4 gap-y-1.5 text-xs">
              <div className="flex items-center gap-1.5">
                <span className="text-muted">WAN IPv6:</span>
                <Badge tone={v6Status.wanHasGua ? 'ok' : 'warn'}>
                  {v6Status.wanHasGua
                    ? v6Status.pdPrefix
                      ? `已获公网 + PD ${maskFullIP(v6Status.pdPrefix, privacyMask)}`
                      : '已获公网地址'
                    : '未检测到公网 IPv6'}
                </Badge>
              </div>
              <div className="flex items-center gap-1.5">
                <span className="text-muted">LAN 前缀与 RA:</span>
                <span className="font-mono text-primary">
                  {v6Status.lanPrefixes && v6Status.lanPrefixes.length > 0
                    ? privacyMask
                      ? '•••••••• (已遮挡)'
                      : v6Status.lanPrefixes.join(', ')
                    : '未分配'}
                </span>
                {v6Status.isOpenWrt && (
                  <span className="text-[11px] text-secondary">
                    (RA={v6Status.lanRaMode || 'off'}, DHCPv6={v6Status.lanDhcpv6Mode || 'off'})
                  </span>
                )}
              </div>
              {v6Status.isOpenWrt && (
                <>
                  <div className="flex items-center gap-1.5">
                    <span className="text-muted">dnsmasq AAAA:</span>
                    <span className="font-mono text-primary">
                      {v6Status.dnsmasqFilterAaaa === '1' ? '过滤关闭' : '正常解析'}
                    </span>
                  </div>
                  <div className="flex items-center gap-1.5">
                    <span className="text-muted">IPv6 DNS 通告:</span>
                    <Badge tone={v6Status.raDnsAnnounce ? 'warn' : 'ok'}>
                      {v6Status.raDnsAnnounce ? '仍在通告' : '已关闭(仅 IPv4 DNS)'}
                    </Badge>
                  </div>
                  <div className="flex items-center gap-1.5">
                    <span className="text-muted">并发上限:</span>
                    <span className="font-mono text-primary">
                      {v6Status.dnsmasqForwardMax || '默认(150)'}
                    </span>
                  </div>
                </>
              )}
            </div>
          )}

          {v6Status?.warnings && v6Status.warnings.length > 0 && (
            <div className="rounded-xl border border-amber-500/35 bg-amber-500/10 px-3.5 py-2.5 text-xs text-amber-200 space-y-1">
              {v6Status.warnings.map((w, idx) => (
                <div key={idx} className="flex items-start gap-2">
                  <AlertTriangle className="w-3.5 h-3.5 text-amber-400 shrink-0 mt-0.5" />
                  <span>{redactInlineSensitive(w, privacyMask)}</span>
                </div>
              ))}
            </div>
          )}

          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
            {[
              {
                key: 'off' as GatewayIPv6Mode,
                title: '关闭 (仅 IPv4)',
                tag: '默认兼容',
                desc: '屏蔽并还原 AAAA 解析（ipv4_only），最稳妥但局域网设备不使用宽带 IPv6。',
                disabled: false,
              },
              {
                key: 'cn_only' as GatewayIPv6Mode,
                title: '智能双栈 (国内 IPv6 + 海外 IPv4)',
                tag: '黄金推荐',
                desc: '国内直连与 PT 原生 IPv6+IPv4；海外域名 0ms 静音海外 AAAA/HTTPS、拦截 DoT/国内 DoH 与代理侧 ::/0，彻底免去节点无 IPv6 导致的卡顿/弹盾与泄漏。',
                disabled: mode === 'side',
              },
              {
                key: 'full' as GatewayIPv6Mode,
                title: '全量双栈 (国内外全部 IPv6)',
                tag: '节点需双栈',
                desc: '国内外域名均保留 A+AAAA 双栈解析。仅建议在自建/机场主力节点全部具备优质 IPv6 出站时启用。',
                disabled: mode === 'side',
              },
            ].map((opt) => {
              const selected = effectiveDisplayIPv6Mode !== null && effectiveDisplayIPv6Mode === opt.key;
              return (
                <button
                  key={opt.key}
                  type="button"
                  disabled={opt.disabled || effectiveDisplayIPv6Mode === null}
                  onClick={() => {
                    setIpv6Mode(opt.key);
                    setIpv6Dirty(true);
                  }}
                  style={
                    selected
                      ? {
                          backgroundColor: 'var(--accent-soft)',
                          borderColor: 'var(--accent)',
                        }
                      : undefined
                  }
                  className={`p-3.5 rounded-xl border text-left transition-all ${
                    opt.disabled || effectiveDisplayIPv6Mode === null
                      ? 'opacity-45 cursor-not-allowed bg-surface2 border-subtle'
                      : selected
                        ? 'cursor-pointer'
                        : 'bg-surface2 border-subtle hover:border-strong cursor-pointer'
                  }`}
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-xs sm:text-sm font-semibold text-primary">{opt.title}</span>
                    <span className="text-[10px] px-1.5 py-0.5 rounded bg-surface1 text-secondary border border-subtle shrink-0">
                      {opt.tag}
                    </span>
                  </div>
                  <p className="text-[11px] text-secondary mt-1.5 leading-relaxed">{opt.desc}</p>
                </button>
              );
            })}
          </div>

          {mode !== 'side' && effectiveDisplayIPv6Mode && effectiveDisplayIPv6Mode !== 'off' && (
            <div className="rounded-xl border border-sky-500/35 bg-sky-500/10 px-3.5 py-3 space-y-2 text-xs text-sky-100">
              <div className="flex items-center gap-2 font-semibold text-sky-200">
                <Smartphone className="w-4 h-4 text-sky-400 shrink-0" />
                <span>开启 IPv6 必看：如何彻底关闭手机端 5G 蜂窝兜底泄漏</span>
              </div>
              <p className="text-[11px] text-sky-100/90 leading-relaxed">
                当路由器对海外 AAAA/HTTPS 做静音（或遭遇高并发 DNS 探测）时，手机若开启 Wi-Fi/蜂窝智能切网且同时开着 5G 数据，系统会误判 Wi-Fi 无 IPv6 而直接经 5G 基站发出运营商 IPv6 DNS 查询，绕过家用路由器：
              </p>
              <ul className="space-y-1 text-[11px] text-sky-100/90 list-disc pl-4 leading-relaxed">
                <li>
                  <span className="font-semibold text-white">iPhone (iOS)</span>：打开{' '}
                  <code className="px-1 py-0.5 rounded bg-sky-950/60 border border-sky-400/20">设置 → 无线局域网 (WLAN)</code>{' '}
                  关闭 <span className="font-semibold text-white">「连接助理」</span>（部分系统版本位于{' '}
                  <code className="px-1 py-0.5 rounded bg-sky-950/60 border border-sky-400/20">设置 → 蜂窝网络 → 展开全部应用 → 拉至最底端</code>{' '}
                  关闭 <span className="font-semibold text-white">「无线局域网助理」</span>）。
                </li>
                <li>
                  <span className="font-semibold text-white">华为 / 鸿蒙</span>：打开{' '}
                  <code className="px-1 py-0.5 rounded bg-sky-950/60 border border-sky-400/20">设置 → WLAN → 更多 WLAN 设置</code>{' '}
                  关闭 <span className="font-semibold text-white">「WLAN+」</span> 与{' '}
                  <span className="font-semibold text-white">「网络加速 / 双通道加速」</span>。
                </li>
                <li>
                  <span className="font-semibold text-white">小米 / OPPO / vivo / 三星等安卓</span>：打开{' '}
                  <code className="px-1 py-0.5 rounded bg-sky-950/60 border border-sky-400/20">设置 → WLAN → WLAN 助理 / 智能选网</code>{' '}
                  关闭 <span className="font-semibold text-white">「自动切换移动数据」</span> 与{' '}
                  <span className="font-semibold text-white">「双通道加速」</span>。
                </li>
                <li>
                  <span className="font-semibold text-white">多级路由 &amp; 生效步骤</span>：若前端还接有二级无线路由器，请同步将其{' '}
                  <code className="px-1 py-0.5 rounded bg-sky-950/60 border border-sky-400/20">dnsforwardmax</code> 调至{' '}
                  <code className="px-1 py-0.5 rounded bg-sky-950/60 border border-sky-400/20">1024</code> 并关闭 IPv6 RDNSS（
                  <code className="px-1 py-0.5 rounded bg-sky-950/60 border border-sky-400/20">ra_dns=0</code> /{' '}
                  <code className="px-1 py-0.5 rounded bg-sky-950/60 border border-sky-400/20">dns_service=0</code>）；保存后请
                  <span className="font-semibold text-white">断开并重连一次 Wi-Fi</span> 刷新租约后再复测。
                </li>
              </ul>
              <div className="rounded-lg border border-sky-400/20 bg-slate-950/75 p-2.5 space-y-1.5">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <span className="text-[11px] font-medium text-sky-200/95">
                    二级 OpenWrt / ImmortalWrt 无线路由一键加固命令（SSH 登录二级路由后直接粘贴执行）
                  </span>
                  <button
                    type="button"
                    onClick={() => void handleCopySubRouterCmd()}
                    className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md border border-sky-400/30 bg-sky-500/15 hover:bg-sky-500/25 text-[11px] text-sky-100 transition-colors cursor-pointer"
                  >
                    {copiedSubCmd ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                    <span>{copiedSubCmd ? '已复制' : '复制命令'}</span>
                  </button>
                </div>
                <pre className="overflow-x-auto text-[11px] font-mono text-sky-100/95 leading-relaxed select-all whitespace-pre">
                  {SECONDARY_ROUTER_IPV6_CMD}
                </pre>
              </div>
            </div>
          )}

          <div className="flex flex-wrap items-center justify-between gap-3 pt-2 border-t border-subtle">
            <span className="text-[11px] text-muted">
              {mode === 'side'
                ? '当前选择旁路由模式：为避免主路由 RA 绕过旁路由造成泄漏，IPv6 自动保持关闭。'
                : '保存后自动同步 OpenWrt RA/DHCPv6、dnsmasq 与 sing-box 规则并零断网热重载（切回关闭会自动按备份还原）。'}
            </span>
            <Button
              variant="primary"
              loading={ipv6Saving}
              disabled={busy || !mode || effectiveDisplayIPv6Mode === null || isSelfLoop || privacyMask}
              title={privacyMask ? '隐私完全遮挡开启期间已锁定修改' : undefined}
              icon={<Save className="w-3.5 h-3.5" />}
              onClick={() => void handleSave(true)}
            >
              保存并自动配置 IPv6
            </Button>
          </div>
        </div>
      </SectionCard>

      <DNSLeakTestCard
        privacyMask={privacyMask}
      />
    </div>
  );
};

export type NetSubTab = 'gw' | 'ts' | 'fw';

function normalizeNetSubTab(raw?: string): NetSubTab {
  if (raw === 'fw') return 'fw';
  if (raw === 'ts') return 'ts';
  if (raw === 'gw') return 'gw';
  return 'gw';
}

export interface NetworkHubPageProps {
  status: ClientStatusResponse | null;
  busy: boolean;
  initialSub?: string;
  onSubChange?: (sub: NetSubTab) => void;
  onAction: (name: string, params?: Record<string, unknown>, confirmMsg?: string) => void;
  onNavigate?: (tab: string) => void;
  onRefreshStatus?: () => void;
}

export const NetworkHubPage: React.FC<NetworkHubPageProps> = ({
  status,
  busy,
  initialSub,
  onSubChange,
  onAction,
  onRefreshStatus,
}) => {
  const { success, toast } = useToast();
  const [sub, setSub] = useState<NetSubTab>(() => normalizeNetSubTab(initialSub));
  const [privacyMask, setPrivacyMask] = useState<boolean>(() => readPrivacyMaskPref());
  const [browserDoH, setBrowserDoH] = useState<BrowserDoHCheckResponse | null>(() => getCachedBrowserDoH());
  const [dohChecking, setDohChecking] = useState(false);
  const [dohDismissed, setDohDismissed] = useState(false);
  const [copiedDoHUrl, setCopiedDoHUrl] = useState(false);
  const dohGuide = useMemo(() => detectBrowserDoHGuide(), []);

  useEffect(() => {
    if (initialSub !== undefined) {
      setSub(normalizeNetSubTab(initialSub));
    }
  }, [initialSub]);

  useEffect(() => {
    const onMaskChange = (ev: Event) => {
      const detail = (ev as CustomEvent<boolean>).detail;
      setPrivacyMask(typeof detail === 'boolean' ? detail : readPrivacyMaskPref());
    };
    const onDoHUpdated = (ev: Event) => {
      const detail = (ev as CustomEvent<BrowserDoHCheckResponse>).detail;
      if (detail) {
        setBrowserDoH(detail);
      }
    };
    window.addEventListener(PRIVACY_MASK_EVENT, onMaskChange);
    window.addEventListener(BROWSER_DOH_EVENT, onDoHUpdated);
    return () => {
      window.removeEventListener(PRIVACY_MASK_EVENT, onMaskChange);
      window.removeEventListener(BROWSER_DOH_EVENT, onDoHUpdated);
    };
  }, []);

  useEffect(() => {
    if (getCachedBrowserDoH()) return;
    setDohChecking(true);
    void runBrowserDoHCheckFlow()
      .then((res) => {
        if (res) setBrowserDoH(res);
      })
      .finally(() => setDohChecking(false));
  }, []);

  const handleTogglePrivacyMask = () => {
    const next = !privacyMask;
    setPrivacyMask(next);
    writePrivacyMaskPref(next);
    toast(next ? '已开启隐私完全遮挡（适合截图分享）' : '已解除隐私遮挡', 'info');
  };

  const handleRecheckBrowserDoH = async () => {
    setDohChecking(true);
    setDohDismissed(false);
    try {
      const res = await runBrowserDoHCheckFlow();
      if (res) {
        setBrowserDoH(res);
        if (res.status === 'clean') {
          success('未检测到当前浏览器绕过网关使用安全 DNS');
        }
      }
    } finally {
      setDohChecking(false);
    }
  };

  const handleCopyDoHSettingsUrl = async () => {
    try {
      await copyPlainText(dohGuide.settingsUrl);
      setCopiedDoHUrl(true);
      success(`已复制 ${dohGuide.browserName} 安全 DNS 设置页地址`);
      window.setTimeout(() => setCopiedDoHUrl(false), 2000);
    } catch {
      toast('复制失败，请手动复制设置页地址', 'warn');
    }
  };

  const handleSelect = (next: NetSubTab) => {
    setSub(next);
    onSubChange?.(next);
  };

  const showDoHAlert =
    !dohDismissed && (browserDoH?.status === 'detected' || browserDoH?.status === 'suspected');

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <SegmentedTabs
          value={sub}
          onChange={(k) => handleSelect(k as NetSubTab)}
          items={[
            {
              key: 'gw',
              label: '网关模式 (主/旁路由)',
              icon: <GitFork className="w-3.5 h-3.5" />,
            },
            {
              key: 'ts',
              label: 'Tailscale 异地组网',
              icon: <Share2 className="w-3.5 h-3.5" />,
            },
            {
              key: 'fw',
              label: 'nftables 防火墙加固',
              icon: <Flame className="w-3.5 h-3.5" />,
            },
          ]}
        />

        <Button
          size="sm"
          variant={privacyMask ? 'primary' : 'secondary'}
          icon={privacyMask ? <Eye className="w-3.5 h-3.5" /> : <EyeOff className="w-3.5 h-3.5" />}
          onClick={handleTogglePrivacyMask}
          title="完全遮挡本页与防泄漏面板中的 IP、IPv6 前缀、地理位置、运营商/ASN 及 Tailscale 节点信息"
        >
          {privacyMask ? '已开启完全遮挡' : '隐私完全遮挡'}
        </Button>
      </div>

      {showDoHAlert && browserDoH && (
        <div
          className={`rounded-2xl border p-4 flex flex-col lg:flex-row lg:items-start justify-between gap-3 ${
            browserDoH.status === 'detected'
              ? 'border-rose-500/45 bg-rose-500/12 text-rose-100'
              : 'border-amber-500/40 bg-amber-500/12 text-amber-100'
          }`}
        >
          <div className="flex items-start gap-3 min-w-0">
            <ShieldAlert
              className={`w-5 h-5 shrink-0 mt-0.5 ${
                browserDoH.status === 'detected' ? 'text-rose-400' : 'text-amber-400'
              }`}
            />
            <div className="space-y-1.5 text-xs min-w-0">
              <div className="flex flex-wrap items-center gap-2 font-semibold">
                <span>
                  {browserDoH.status === 'detected'
                    ? '检测到当前浏览器开启了自身安全 DNS (DoH)'
                    : '检测到浏览器与网关 DNS 出口分歧'}
                </span>
                {browserDoH.detectedProvider && (
                  <Badge tone={browserDoH.status === 'detected' ? 'danger' : 'warn'}>
                    {browserDoH.detectedProvider}
                  </Badge>
                )}
              </div>
              <p className="leading-relaxed opacity-95">
                {redactInlineSensitive(browserDoH.summary, privacyMask)}
              </p>
              <div className="text-[11px] opacity-90 flex flex-wrap items-center gap-2">
                <Monitor className="w-3.5 h-3.5 shrink-0" />
                <span>
                  <strong className="text-white">{dohGuide.browserName} 关闭指引：</strong>
                  {dohGuide.steps}（
                  <code className="font-mono text-sky-300">{dohGuide.settingsUrl}</code>）
                </span>
              </div>
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-2 shrink-0">
            <Button
              size="xs"
              variant="primary"
              icon={copiedDoHUrl ? <Check className="w-3 h-3" /> : <Copy className="w-3 h-3" />}
              onClick={() => void handleCopyDoHSettingsUrl()}
            >
              {copiedDoHUrl ? '已复制设置地址' : '复制关闭设置地址'}
            </Button>
            <Button
              size="xs"
              variant="secondary"
              loading={dohChecking}
              icon={<RefreshCw className="w-3 h-3" />}
              onClick={() => void handleRecheckBrowserDoH()}
            >
              重新检测
            </Button>
            <button
              type="button"
              onClick={() => setDohDismissed(true)}
              title="本次会话暂不提醒"
              className="p-1.5 rounded-lg hover:bg-white/10 text-secondary hover:text-primary transition-colors cursor-pointer"
            >
              <X className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>
      )}

      {sub === 'gw' && (
        <GatewayModePage status={status} busy={busy} privacyMask={privacyMask} onSaved={onRefreshStatus} />
      )}
      {sub === 'ts' && (
        <TailscalePage
          status={status}
          busy={busy}
          privacyMask={privacyMask}
          onAction={onAction}
          onRefreshStatus={onRefreshStatus}
        />
      )}
      {sub === 'fw' && (
        <FirewallPanel
          status={status}
          busy={busy}
          privacyMask={privacyMask}
          onRefreshStatus={onRefreshStatus}
        />
      )}
    </div>
  );
};

import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  AlertTriangle,
  Download,
  Info,
  KeyRound,
  Lock,
  RotateCcw,
  Save,
  Share2,
} from 'lucide-react';
import { Badge, Button, ConfirmDialog, PageHeader, SectionCard, useToast } from '../../../ui';
import { useCachedQuery } from '../../../hooks';
import { clientApi } from '../../api';
import { TAILSCALE_MESH_CACHE_KEY } from '../../cacheKeys';
import { maskFullIP } from '../../../lib/privacyMask';
import {
  ClientStatusResponse,
  TailscaleLocalSubnetRuleDTO,
  TailscaleMeshTopologyResponse,
  TailscaleP2PPeerConfig,
  TailscaleP2PPeerView,
  TailscaleSubnetScope,
} from '../../types';
import { LocalSubnetDraft } from './TailscaleLocalScopeCard';
import { PeerPolicyDraft, TailscaleMeshMap, meshPeerKey } from './TailscaleMeshMap';
import { TailscaleAdvancedDrawer } from './TailscaleAdvancedDrawer';
import { TailscaleRoleAuthCard, normalizeTSMode } from './TailscaleRoleAuthCard';
import { TailscaleUpgradeDrawer } from './TailscaleUpgradeDrawer';

export interface TailscalePageProps {
  status: ClientStatusResponse | null;
  busy: boolean;
  privacyMask?: boolean;
  onAction: (name: string, params?: Record<string, unknown>, confirmMsg?: string) => void;
  onRefreshStatus?: () => void;
}

function buildDraftFromMesh(mesh: TailscaleMeshTopologyResponse) {
  const subnetDrafts: Record<string, LocalSubnetDraft> = {};
  const custom: string[] = [];
  for (const n of mesh.localNetworks || []) {
    subnetDrafts[n.cidr] = {
      cidr: n.cidr,
      selected: Boolean(n.selected),
      scope: (n.scope as TailscaleSubnetScope) || 'all',
      devices: new Set(n.selectedDevices || []),
    };
    if (n.kind === 'custom') custom.push(n.cidr);
  }
  const peers: Record<string, PeerPolicyDraft> = {};
  for (const p of mesh.gatewayPeers || []) {
    const k = meshPeerKey(p);
    const isBidir =
      p.effectiveAccessMode === 'bidirectional' ||
      p.effectiveAccessMode === 'bidirectional_timed' ||
      p.accessMode === 'bidirectional';
    peers[k] = {
      id: p.id || '',
      name: p.shortName || p.name || p.hostName || k,
      tailscaleIP: p.tailscaleIPs?.[0] || '',
      jitEnabled: p.configured ? Boolean(p.jitEnabled) : true,
      accessMode: isBidir ? 'bidirectional' : 'outbound_only',
      allowedLanTargetsText: (p.allowedLanTargets || []).join(', '),
    };
  }
  const p2pCfg = mesh.p2p?.config;
  const preferredRole = mesh.roleMode || mesh.tailscaleStatus?.mode || '';
  return {
    mode: normalizeTSMode(preferredRole || (mesh.tailscaleStatus?.running ? 'client' : 'router')),
    subnetDrafts,
    custom,
    peers,
    jitWindowSec: p2pCfg?.jit_window_sec && p2pCfg.jit_window_sec > 0 ? p2pCfg.jit_window_sec : 5,
    cooldownSec: p2pCfg?.cooldown_sec && p2pCfg.cooldown_sec > 0 ? p2pCfg.cooldown_sec : 300,
    sandboxUjail: mesh.p2p?.ujailAvailable
      ? !p2pCfg?.enabled
        ? true
        : Boolean(p2pCfg?.sandbox_ujail)
      : false,
    downstreamAssist: p2pCfg?.downstream_assist === undefined ? true : Boolean(p2pCfg.downstream_assist),
  };
}

export const TailscalePage: React.FC<TailscalePageProps> = ({
  status,
  busy,
  privacyMask = false,
  onAction,
  onRefreshStatus,
}) => {
  const { success, error, toast } = useToast();
  const {
    data: mesh,
    loading: meshLoading,
    setData: setMeshData,
    refetch: refetchMesh,
  } = useCachedQuery<TailscaleMeshTopologyResponse>(TAILSCALE_MESH_CACHE_KEY, () =>
    clientApi.getTailscaleMesh(),
  );

  const ts = mesh?.tailscaleStatus || status?.tailscale;
  const tsCfg = mesh?.config;
  const gatewayRole = mesh?.gatewayRole || status?.gateway?.mode || 'main';

  const dirtyRef = useRef(false);
  const [hasDraftChanges, setHasDraftChanges] = useState(false);
  const [savingMesh, setSavingMesh] = useState(false);
  const [pokingKey, setPokingKey] = useState('');

  const [mode, setMode] = useState<string>(() => normalizeTSMode(mesh?.roleMode || ts?.mode || 'router'));
  const [subnetDrafts, setSubnetDrafts] = useState<Record<string, LocalSubnetDraft>>({});
  const [customSubnets, setCustomSubnets] = useState<string[]>([]);
  const [peerDrafts, setPeerDrafts] = useState<Record<string, PeerPolicyDraft>>({});
  const [jitWindowSec, setJitWindowSec] = useState(5);
  const [cooldownSec, setCooldownSec] = useState(300);
  const [sandboxUjail, setSandboxUjail] = useState(false);
  const [downstreamAssist, setDownstreamAssist] = useState(true);

  const [authExpanded, setAuthExpanded] = useState<boolean | null>(null);
  const [authKeyInput, setAuthKeyInput] = useState('');
  const [clearAuthKey, setClearAuthKey] = useState(false);
  const [savingAuthKey, setSavingAuthKey] = useState(false);
  const [stopConfirmOpen, setStopConfirmOpen] = useState(false);
  const [upgradeDrawerOpen, setUpgradeDrawerOpen] = useState(false);

  const [newWebPassword, setNewWebPassword] = useState('');
  const [savingWebPassword, setSavingWebPassword] = useState(false);

  const applyMeshHydration = useCallback((m: TailscaleMeshTopologyResponse) => {
    const d = buildDraftFromMesh(m);
    setMode(d.mode);
    setSubnetDrafts(d.subnetDrafts);
    setCustomSubnets(d.custom);
    setPeerDrafts(d.peers);
    setJitWindowSec(d.jitWindowSec);
    setCooldownSec(d.cooldownSec);
    setSandboxUjail(d.sandboxUjail);
    setDownstreamAssist(d.downstreamAssist);
    dirtyRef.current = false;
    setHasDraftChanges(false);
  }, []);

  useEffect(() => {
    if (!mesh || dirtyRef.current) return;
    applyMeshHydration(mesh);
  }, [mesh, applyMeshHydration]);

  const markDirty = () => {
    dirtyRef.current = true;
    setHasDraftChanges(true);
  };

  const handleRefreshAll = async () => {
    dirtyRef.current = false;
    try {
      const fresh = await refetchMesh(false);
      if (fresh) applyMeshHydration(fresh);
      onRefreshStatus?.();
    } catch (err) {
      error((err as Error)?.message || '刷新组网拓扑失败');
    }
  };

  const handleSelectRole = (nextRole: string) => {
    markDirty();
    setMode(nextRole);
    if (nextRole === 'router' || nextRole === 'gateway') {
      setSubnetDrafts((prev) => {
        const anySelected = Object.values(prev).some((s) => s.selected);
        if (anySelected) return prev;
        const firstCIDR = mesh?.localNetworks?.[0]?.cidr || customSubnets[0];
        if (!firstCIDR) return prev;
        const cur = prev[firstCIDR] || {
          cidr: firstCIDR,
          selected: true,
          scope: 'all' as TailscaleSubnetScope,
          devices: new Set<string>(),
        };
        return { ...prev, [firstCIDR]: { ...cur, selected: true } };
      });
    }
  };

  const handleToggleSubnet = (cidr: string) => {
    markDirty();
    setSubnetDrafts((prev) => {
      const cur = prev[cidr] || { cidr, selected: false, scope: 'all' as TailscaleSubnetScope, devices: new Set<string>() };
      const nextSelected = !cur.selected;
      const next = { ...prev, [cidr]: { ...cur, selected: nextSelected } };
      const countSelected = Object.values(next).filter((s) => s.selected).length;
      if (nextSelected && (mode === 'client' || mode === 'exit')) {
        setMode(mode === 'exit' ? 'gateway' : 'router');
      } else if (!nextSelected && countSelected === 0 && (mode === 'router' || mode === 'gateway')) {
        setMode(mode === 'gateway' ? 'exit' : 'client');
      }
      return next;
    });
  };

  const handleAddCustomSubnet = (cidr: string) => {
    markDirty();
    setCustomSubnets((prev) => (prev.includes(cidr) ? prev : [...prev, cidr]));
    setSubnetDrafts((prev) => ({
      ...prev,
      [cidr]: { cidr, selected: true, scope: 'all', devices: new Set<string>() },
    }));
    if (mode === 'client' || mode === 'exit') {
      setMode(mode === 'exit' ? 'gateway' : 'router');
    }
  };

  const handleRemoveCustomSubnet = (cidr: string) => {
    markDirty();
    setCustomSubnets((prev) => prev.filter((c) => c !== cidr));
    setSubnetDrafts((prev) => {
      const copy = { ...prev };
      delete copy[cidr];
      return copy;
    });
  };

  const handleChangeScope = (cidr: string, scope: TailscaleSubnetScope) => {
    markDirty();
    setSubnetDrafts((prev) => {
      const cur = prev[cidr] || { cidr, selected: true, scope: 'all' as TailscaleSubnetScope, devices: new Set<string>() };
      return { ...prev, [cidr]: { ...cur, scope } };
    });
  };

  const handleToggleDevice = (cidr: string, deviceIP: string) => {
    markDirty();
    setSubnetDrafts((prev) => {
      const cur = prev[cidr] || { cidr, selected: true, scope: 'allowlist' as TailscaleSubnetScope, devices: new Set<string>() };
      const nextSet = new Set(cur.devices);
      if (nextSet.has(deviceIP)) nextSet.delete(deviceIP);
      else nextSet.add(deviceIP);
      return { ...prev, [cidr]: { ...cur, devices: nextSet } };
    });
  };

  const handleAddManualDevice = (cidr: string, deviceIP: string) => {
    markDirty();
    setSubnetDrafts((prev) => {
      const cur = prev[cidr] || { cidr, selected: true, scope: 'allowlist' as TailscaleSubnetScope, devices: new Set<string>() };
      const nextSet = new Set(cur.devices);
      nextSet.add(deviceIP);
      return { ...prev, [cidr]: { ...cur, devices: nextSet } };
    });
  };

  const handleUpdatePeerPolicy = (k: string, patch: Partial<PeerPolicyDraft>) => {
    markDirty();
    setPeerDrafts((prev) => {
      const cur = prev[k];
      if (!cur) return prev;
      return { ...prev, [k]: { ...cur, ...patch } };
    });
  };

  const collectSavePayload = () => {
    const isSubnetRole = mode === 'router' || mode === 'gateway';
    const orderedSubnets: string[] = [];
    const localRules: TailscaleLocalSubnetRuleDTO[] = [];
    if (isSubnetRole) {
      const seen = new Set<string>();
      const pushCIDR = (cidr: string) => {
        if (seen.has(cidr)) return;
        const d = subnetDrafts[cidr];
        if (!d?.selected) return;
        seen.add(cidr);
        orderedSubnets.push(cidr);
        localRules.push({
          cidr,
          scope: d.scope,
          devices: Array.from(d.devices),
        });
      };
      for (const n of mesh?.localNetworks || []) pushCIDR(n.cidr);
      for (const c of customSubnets) pushCIDR(c);
    }

    const peersPayload: TailscaleP2PPeerConfig[] = Object.values(peerDrafts).map((d) => ({
      id: d.id || undefined,
      name: d.name,
      tailscale_ip: d.tailscaleIP || undefined,
      jit_enabled: d.jitEnabled,
      access_mode: d.accessMode,
      allowed_lan_targets: d.allowedLanTargetsText
        .split(/[,，\n]+/)
        .map((s) => s.trim())
        .filter(Boolean),
    }));

    return {
      mode,
      subnets: orderedSubnets,
      local_rules: localRules,
      peers: peersPayload,
      jit_window_sec: Math.min(10, Math.max(3, Number(jitWindowSec) || 5)),
      cooldown_sec: Math.min(3600, Math.max(30, Number(cooldownSec) || 300)),
      sandbox_ujail: Boolean(mesh?.p2p?.ujailAvailable && sandboxUjail),
      downstream_assist: downstreamAssist,
    };
  };

  const handleSaveMesh = async () => {
    if (privacyMask) return;
    setSavingMesh(true);
    try {
      const res = await clientApi.saveTailscaleMesh(collectSavePayload());
      if (res.mesh) {
        setMeshData(res.mesh);
        applyMeshHydration(res.mesh);
      }
      success(res.message || '组网角色、设备范围与防线策略已保存并生效');
      onRefreshStatus?.();
    } catch (err) {
      error((err as Error)?.message || '保存组网配置失败');
    } finally {
      setSavingMesh(false);
    }
  };

  const handleSaveAuthKey = async (e?: React.FormEvent) => {
    e?.preventDefault();
    if (privacyMask) return;
    setSavingAuthKey(true);
    try {
      const payload = collectSavePayload();
      await clientApi.saveTailscaleConfig({
        authKey: authKeyInput.trim(),
        clearAuthKey,
        subnets: payload.subnets.join(','),
      });
      setAuthKeyInput('');
      setClearAuthKey(false);
      success('Tailscale 授权密钥已安全保存（0600 权限）');
      await handleRefreshAll();
    } catch (err) {
      error((err as Error)?.message || '保存授权密钥失败');
    } finally {
      setSavingAuthKey(false);
    }
  };

  const handleStartWithAutoSave = async () => {
    if (privacyMask) {
      onAction('ts-start', { mode, acceptRoutes: true });
      return;
    }
    try {
      const payload = collectSavePayload();
      if (authKeyInput.trim() || clearAuthKey) {
        await clientApi.saveTailscaleConfig({
          authKey: authKeyInput.trim(),
          clearAuthKey,
          subnets: payload.subnets.join(','),
        });
        setAuthKeyInput('');
        setClearAuthKey(false);
      }
      if (hasDraftChanges || authKeyInput.trim()) {
        await clientApi.saveTailscaleMesh(payload);
      }
    } catch (err) {
      error((err as Error)?.message || '启动前保存配置失败');
      return;
    }
    onAction('ts-start', { mode, acceptRoutes: true });
  };

  const handlePokePeer = async (peer: TailscaleP2PPeerView) => {
    const k = meshPeerKey(peer);
    setPokingKey(k);
    try {
      const res = await clientApi.pokeTailscaleP2P({ id: peer.id, name: peer.name });
      toast(res.message || '打洞探测完成', res.direct ? 'success' : 'warn');
      await handleRefreshAll();
    } catch (err) {
      error((err as Error)?.message || '瞬时打洞探测失败');
    } finally {
      setPokingKey('');
    }
  };

  const handleEnableWebPassword = async (e: React.FormEvent) => {
    e.preventDefault();
    if (newWebPassword.length < 6) {
      error('WebUI 访问口令至少需要 6 位字符');
      return;
    }
    setSavingWebPassword(true);
    try {
      await clientApi.updatePassword({ password: newWebPassword });
      setNewWebPassword('');
      success('已开启 WebUI 口令保护（已自动维持 30 天免重登）');
      await handleRefreshAll();
    } catch (err) {
      error((err as Error)?.message || '开启 WebUI 口令失败');
    } finally {
      setSavingWebPassword(false);
    }
  };

  const isAuthOpen = authExpanded ?? (!tsCfg?.authKeySet || !ts?.running || Boolean(ts?.needsLogin));
  const hasAnyBidirectionalPeer = useMemo(
    () => Object.values(peerDrafts).some((d) => d.accessMode === 'bidirectional'),
    [peerDrafts],
  );
  const showPasswordGuardBanner = hasAnyBidirectionalPeer && mesh && !mesh.webPasswordConfigured;

  return (
    <div className="space-y-4">
      <PageHeader
        title="Tailscale 异地组网"
        description={
          !ts
            ? '正在读取 Tailscale 状态…'
            : !ts.installed
              ? '尚未安装 Tailscale 二进制'
              : `v${ts.version || '-'}${ts.selfIp ? ` · ${maskFullIP(ts.selfIp, privacyMask)}` : ''}`
        }
        badge={
          <Badge
            tone={!ts?.installed ? 'warn' : ts.state === 'Running' ? 'ok' : ts.running ? 'warn' : 'neutral'}
            dot={Boolean(ts?.running)}
            pulse={ts?.state === 'Running'}
          >
            {!ts?.installed ? '未安装' : ts.state === 'Running' ? '组网已连接' : ts.running ? ts.state : '未运行'}
          </Badge>
        }
      />

      {ts && !ts.installed ? (
        <SectionCard
          title="安装并启用 Tailscale 组网"
          icon={<Share2 className="w-4 h-4" />}
          subtitle="一键拉取架构适配安装包（含官方 SHA256 强校验），先填好授权密钥启动即连"
        >
          <div className="space-y-4">
            <form onSubmit={(e) => void handleSaveAuthKey(e)} className="flex flex-col sm:flex-row sm:items-center gap-2 text-xs">
              <div className="flex items-center gap-2 flex-1">
                <KeyRound className="w-4 h-4 text-[var(--accent)] shrink-0" />
                <input
                  type="password"
                  value={authKeyInput}
                  onChange={(e) => setAuthKeyInput(e.target.value)}
                  placeholder={tsCfg?.authKeySet ? '已保存 Auth Key（留空不变）' : '可选：粘贴 tskey-auth-...'}
                  className="flex-1 h-10 sm:h-9 px-3 rounded-xl bg-surface1 border border-subtle text-base sm:text-xs text-primary font-mono"
                />
              </div>
              <Button type="submit" size="sm" variant="secondary" loading={savingAuthKey}>
                保存密钥
              </Button>
            </form>
            <Button
              variant="primary"
              disabled={busy}
              onClick={() => onAction('ts-install')}
              icon={<Download className="w-4 h-4" />}
            >
              一键安装 Tailscale
            </Button>
          </div>
        </SectionCard>
      ) : (
        <>
          <TailscaleRoleAuthCard
            ts={ts}
            tsCfg={tsCfg}
            p2p={mesh?.p2p}
            lanShieldActive={mesh?.lanShieldActive}
            mode={mode}
            busy={busy}
            meshLoading={meshLoading}
            privacyMask={privacyMask}
            isAuthOpen={isAuthOpen}
            authKeyInput={authKeyInput}
            clearAuthKey={clearAuthKey}
            savingAuthKey={savingAuthKey}
            onSelectRole={handleSelectRole}
            onToggleAuthOpen={() => setAuthExpanded(!isAuthOpen)}
            onAuthKeyInputChange={setAuthKeyInput}
            onClearAuthKeyChange={(checked) => {
              setClearAuthKey(checked);
              if (checked) setAuthKeyInput('');
            }}
            onSaveAuthKey={(e) => void handleSaveAuthKey(e)}
            onStartWithAutoSave={() => void handleStartWithAutoSave()}
            onRefreshAll={() => void handleRefreshAll()}
            onOpenUpgrade={() => setUpgradeDrawerOpen(true)}
            onRequestStop={() => setStopConfirmOpen(true)}
            onFixTun={() => onAction('ts-fix-tun')}
          />

          {gatewayRole === 'side' && (
            <div className="p-3.5 rounded-2xl border border-sky-500/30 bg-sky-500/10 text-xs text-sky-100 flex items-start gap-2.5 leading-relaxed">
              <Info className="w-4 h-4 text-sky-300 shrink-0 mt-0.5" />
              <div>
                <div className="font-semibold text-white">旁路由无需重复开启 Tailscale</div>
                <div className="text-sky-200/90 mt-0.5">
                  主路由开启即可覆盖全屋局域网；若仍需在本机启动，SingCtl 内核双通护盾（5260/5265）会自动防止局域网访问失联。
                </div>
              </div>
            </div>
          )}

          {showPasswordGuardBanner && (
            <form
              onSubmit={(e) => void handleEnableWebPassword(e)}
              className="p-3.5 rounded-2xl border border-amber-500/35 bg-amber-500/10 text-xs text-amber-100 flex flex-col lg:flex-row lg:items-center justify-between gap-3"
            >
              <div className="flex items-start gap-2.5">
                <AlertTriangle className="w-4 h-4 text-amber-300 shrink-0 mt-0.5" />
                <div>
                  <div className="font-semibold text-white">安全提醒：建议为 WebUI 启用访问口令</div>
                  <div className="text-amber-200/90 mt-0.5 leading-relaxed">
                    已开启「互通（家庭网络）」，设置 6 位以上口令可避免对端设备免密误改路由器配置。
                  </div>
                </div>
              </div>
              <div className="flex items-center gap-2 shrink-0">
                <input
                  type="password"
                  autoComplete="new-password"
                  value={newWebPassword}
                  onChange={(e) => setNewWebPassword(e.target.value)}
                  placeholder="输入 6 位以上口令"
                  className="flex-1 sm:w-48 h-10 sm:h-8 px-3 rounded-lg bg-surface1 border border-amber-400/40 text-base sm:text-xs text-primary"
                />
                <Button
                  type="submit"
                  size="sm"
                  variant="primary"
                  loading={savingWebPassword}
                  icon={<Lock className="w-3.5 h-3.5" />}
                >
                  启用口令
                </Button>
              </div>
            </form>
          )}

          <TailscaleMeshMap
            mode={mode}
            localNetworks={mesh?.localNetworks || []}
            customSubnets={customSubnets}
            subnetDrafts={subnetDrafts}
            gatewayPeers={mesh?.gatewayPeers || []}
            personalDevices={mesh?.personalDevices || []}
            peerDrafts={peerDrafts}
            tsStatus={ts}
            p2pLiveEnabled={Boolean(mesh?.p2p?.config?.enabled)}
            pokingKey={pokingKey}
            privacyMask={privacyMask}
            onToggleSubnet={handleToggleSubnet}
            onAddCustomSubnet={handleAddCustomSubnet}
            onRemoveCustomSubnet={handleRemoveCustomSubnet}
            onChangeScope={handleChangeScope}
            onToggleDevice={handleToggleDevice}
            onAddManualDevice={handleAddManualDevice}
            onUpdatePeerPolicy={handleUpdatePeerPolicy}
            onPokePeer={(p) => void handlePokePeer(p)}
          />

          <TailscaleAdvancedDrawer
            p2pReport={mesh?.p2p}
            privacyMask={privacyMask}
            jitWindowSec={jitWindowSec}
            cooldownSec={cooldownSec}
            sandboxUjail={sandboxUjail}
            downstreamAssist={downstreamAssist}
            onJitWindowChange={(sec) => {
              markDirty();
              setJitWindowSec(sec);
            }}
            onCooldownChange={(sec) => {
              markDirty();
              setCooldownSec(sec);
            }}
            onSandboxUjailChange={(enabled) => {
              markDirty();
              setSandboxUjail(enabled);
            }}
            onDownstreamAssistChange={(enabled) => {
              markDirty();
              setDownstreamAssist(enabled);
            }}
          />

          {/* 拇指区智能悬浮保存条：有待保存修改时固定在手机底部导航正上方，平时不遮挡滚动视野 */}
          <div
            className={`console-card rounded-2xl px-3.5 sm:px-4 py-3 flex flex-wrap items-center justify-between gap-2.5 transition-all ${
              hasDraftChanges
                ? 'sticky bottom-[calc(4.5rem+env(safe-area-inset-bottom,0px))] md:bottom-4 z-30 shadow-2xl border-[var(--accent)]/70 backdrop-blur-xl'
                : ''
            }`}
          >
            <div className="text-xs text-secondary flex flex-wrap items-center gap-2 min-w-0">
              {hasDraftChanges ? (
                <Badge tone="warn" dot>
                  有未生效的组网修改
                </Badge>
              ) : (
                <Badge tone="ok" dot>
                  配置与实时防线已同步
                </Badge>
              )}
              <span className="hidden sm:inline">
                保存将同步写入 0600 配置、更新进出双向设备防火墙并无断流生效。
              </span>
            </div>
            <div className="flex items-center gap-2 w-full sm:w-auto justify-end">
              {hasDraftChanges && mesh && (
                <Button
                  type="button"
                  size="sm"
                  variant="ghost"
                  disabled={savingMesh}
                  onClick={() => applyMeshHydration(mesh)}
                  icon={<RotateCcw className="w-3.5 h-3.5" />}
                >
                  撤销
                </Button>
              )}
              <Button
                type="button"
                size="sm"
                variant="primary"
                loading={savingMesh}
                disabled={savingMesh || privacyMask}
                title={privacyMask ? '请先关闭隐私遮挡再保存修改' : undefined}
                onClick={() => void handleSaveMesh()}
                icon={<Save className="w-3.5 h-3.5" />}
              >
                {savingMesh ? '正在生效…' : '保存并立即生效'}
              </Button>
            </div>
          </div>
        </>
      )}

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

      <TailscaleUpgradeDrawer
        open={upgradeDrawerOpen}
        busy={busy}
        privacyMask={privacyMask}
        onClose={() => setUpgradeDrawerOpen(false)}
        onStartUpgrade={(force) => onAction('ts-update', { force })}
      />
    </div>
  );
};

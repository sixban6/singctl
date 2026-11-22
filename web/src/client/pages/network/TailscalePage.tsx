import React, { useEffect, useState } from 'react';
import {
  CheckCircle2,
  ChevronDown,
  ChevronUp,
  Download,
  KeyRound,
  Play,
  Power,
  Save,
  Share2,
} from 'lucide-react';
import { Badge, Button, ConfirmDialog, PageHeader, SectionCard, useToast } from '../../../ui';
import { useCachedQuery } from '../../../hooks';
import { clientApi } from '../../api';
import { TAILSCALE_CFG_CACHE_KEY } from '../../cacheKeys';
import { maskFullIP } from '../../../lib/privacyMask';
import { ClientStatusResponse, TailscaleConfigResponse } from '../../types';
import { TailscaleP2PSection } from './TailscaleP2PSection';
import { TailscaleUpgradeDrawer } from './TailscaleUpgradeDrawer';

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

export const TailscalePage: React.FC<TailscalePageProps> = ({
  status,
  busy,
  privacyMask = false,
  onAction,
  onRefreshStatus,
}) => {
  const { success, error } = useToast();
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
  const [upgradeDrawerOpen, setUpgradeDrawerOpen] = useState(false);

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
          subtitle="一键拉取架构适配安装包（AMD64/ARM64 均为精简合体无加壳版，含官方 SHA256 强校验），先配好 auth_key 再启动更省心"
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
          <div className="console-card rounded-2xl px-4 py-3 flex flex-col lg:flex-row lg:items-center justify-between gap-3">
            <div className="flex flex-wrap items-center gap-2 text-xs">
              <Badge tone={ts?.running ? 'ok' : 'neutral'} dot={Boolean(ts?.running)}>
                {ts?.running ? `运行中 (${ts.state || 'Running'})` : '守护进程已停止'}
              </Badge>
              {ts?.running && <Badge tone="accent">当前模式: {activeModeLabel}</Badge>}
              {ts?.running && ts.acceptRoutes && <Badge tone="neutral">已启用接收对端路由</Badge>}
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
                onClick={() => setUpgradeDrawerOpen(true)}
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

      <TailscaleP2PSection privacyMask={privacyMask} />

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

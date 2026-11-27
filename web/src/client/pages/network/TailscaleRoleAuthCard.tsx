import React from 'react';
import {
  AlertTriangle,
  ChevronDown,
  ChevronUp,
  Download,
  ExternalLink,
  KeyRound,
  Play,
  Power,
  RefreshCw,
  Save,
  Share2,
  Wrench,
} from 'lucide-react';
import { Badge, Button, SectionCard } from '../../../ui';
import { maskFullIP } from '../../../lib/privacyMask';
import { ClientTailscaleStatus, TailscaleConfigResponse, TailscaleP2PReport } from '../../types';

export const TS_MODES = [
  { value: 'client', title: '默认客户端', desc: '仅加入组网，不广播本地路由' },
  { value: 'router', title: '子网路由器', desc: '开放所选内网，软路由首选' },
  { value: 'exit', title: '出口节点', desc: '将本机设为全网流量出口' },
  { value: 'gateway', title: '全能网关', desc: '同时开放内网 + 流量出口' },
];

export function normalizeTSMode(raw?: string): string {
  if (raw === 'client' || raw === 'router' || raw === 'exit' || raw === 'gateway') return raw;
  return 'router';
}

export interface TailscaleRoleAuthCardProps {
  ts?: ClientTailscaleStatus;
  tsCfg?: TailscaleConfigResponse;
  p2p?: TailscaleP2PReport;
  lanShieldActive?: boolean;
  mode: string;
  busy: boolean;
  meshLoading: boolean;
  privacyMask: boolean;
  isAuthOpen: boolean;
  authKeyInput: string;
  clearAuthKey: boolean;
  savingAuthKey: boolean;
  onSelectRole: (role: string) => void;
  onToggleAuthOpen: () => void;
  onAuthKeyInputChange: (val: string) => void;
  onClearAuthKeyChange: (checked: boolean) => void;
  onSaveAuthKey: (e?: React.FormEvent) => void;
  onStartWithAutoSave: () => void;
  onRefreshAll: () => void;
  onOpenUpgrade: () => void;
  onRequestStop: () => void;
  onFixTun: () => void;
}

export const TailscaleRoleAuthCard: React.FC<TailscaleRoleAuthCardProps> = ({
  ts,
  tsCfg,
  p2p,
  lanShieldActive,
  mode,
  busy,
  meshLoading,
  privacyMask,
  isAuthOpen,
  authKeyInput,
  clearAuthKey,
  savingAuthKey,
  onSelectRole,
  onToggleAuthOpen,
  onAuthKeyInputChange,
  onClearAuthKeyChange,
  onSaveAuthKey,
  onStartWithAutoSave,
  onRefreshAll,
  onOpenUpgrade,
  onRequestStop,
  onFixTun,
}) => {
  const activeModeLabel = TS_MODES.find((m) => m.value === normalizeTSMode(ts?.mode || mode))?.title || mode;
  const openPinholes = p2p?.openPinholes ?? 0;

  return (
    <>
      {/* 顶栏状态与全生命周期控制按钮（桌/手自适应，停止按钮靠右防误触） */}
      <div className="console-card rounded-2xl px-3.5 sm:px-4 py-3 flex flex-col lg:flex-row lg:items-center justify-between gap-3">
        <div className="flex flex-wrap items-center gap-1.5 sm:gap-2 text-xs">
          <Badge tone={ts?.running ? 'ok' : 'neutral'} dot={Boolean(ts?.running)}>
            {ts?.running ? `运行中 (${ts.state || 'Running'})` : '服务未启动'}
          </Badge>
          {ts?.running && <Badge tone="accent">{activeModeLabel}</Badge>}
          {ts?.selfIp && <Badge tone="neutral">{maskFullIP(ts.selfIp, privacyMask)}</Badge>}
          {p2p && (
            <Badge tone={openPinholes > 0 ? 'warn' : 'ok'}>
              {openPinholes > 0 ? `瞬时放行 ${openPinholes} IP` : '0 暴露 · JIT'}
            </Badge>
          )}
          {lanShieldActive && <Badge tone="ok">防锁死护盾</Badge>}
          {ts?.installed && ts.userspaceMode && <Badge tone="danger">纯用户态 · 缺 TUN</Badge>}
        </div>

        <div className="flex flex-wrap items-center gap-2 w-full lg:w-auto">
          {!ts?.running && (
            <Button
              size="sm"
              variant="primary"
              disabled={busy}
              icon={<Play className="w-3.5 h-3.5" />}
              onClick={onStartWithAutoSave}
            >
              启动 Tailscale
            </Button>
          )}
          <Button
            size="sm"
            variant="ghost"
            disabled={meshLoading}
            onClick={onRefreshAll}
            icon={<RefreshCw className={`w-3.5 h-3.5 ${meshLoading ? 'animate-spin' : ''}`} />}
          >
            刷新
          </Button>
          <Button
            size="sm"
            variant="secondary"
            disabled={busy}
            icon={<Download className="w-3.5 h-3.5" />}
            onClick={onOpenUpgrade}
          >
            零失联更新
          </Button>
          {ts?.running && (
            <Button
              size="sm"
              variant="danger"
              disabled={busy}
              className="ml-auto sm:ml-0"
              icon={<Power className="w-3.5 h-3.5" />}
              onClick={onRequestStop}
            >
              停止服务
            </Button>
          )}
        </div>
      </div>

      {ts?.installed && ts.userspaceMode && (
        <div className="p-3.5 sm:p-4 rounded-2xl border border-rose-500/40 bg-rose-500/10 text-xs text-rose-100 flex flex-col lg:flex-row lg:items-center justify-between gap-3">
          <div className="flex items-start gap-2.5 min-w-0">
            <AlertTriangle className="w-4 h-4 text-rose-300 shrink-0 mt-0.5" />
            <div className="min-w-0">
              <div className="font-semibold text-white">
                {ts.canSwitchToKernel
                  ? '内核 TUN 驱动已就绪，但 Tailscale 仍运行在纯用户态模式'
                  : '缺少内核 TUN 驱动（/dev/net/tun），局域网设备无法透明访问远端内网'}
              </div>
              <div className="text-rose-100/90 mt-1 leading-relaxed">
                {ts.tunReason ||
                  '当前处于 --tun=userspace-networking 模式（无 tailscale0 网卡），仅路由器本机 tailscale ping 可达，手机/电脑无法直连远端局域网。'}
              </div>
            </div>
          </div>
          <Button
            size="sm"
            variant="primary"
            disabled={busy}
            className="shrink-0 w-full lg:w-auto"
            icon={<Wrench className="w-3.5 h-3.5" />}
            onClick={onFixTun}
          >
            {ts.canSwitchToKernel ? '一键切换至内核模式' : '一键安装 kmod-tun 并修复'}
          </Button>
        </div>
      )}

      {ts?.needsLogin && ts.authUrl && (
        <div className="p-3.5 rounded-2xl border border-[var(--accent)]/40 bg-[var(--accent-soft)] text-xs flex flex-wrap items-center justify-between gap-3">
          <div>
            <div className="font-semibold text-primary">等待 Tailscale 网页授权登录</div>
            <div className="text-secondary mt-0.5">点击右侧按钮完成账号登录授权后，组网将立即上线。</div>
          </div>
          <a
            href={ts.authUrl}
            target="_blank"
            rel="noreferrer"
            className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-xl bg-[var(--accent)] text-white font-medium"
          >
            <span>去官网授权登录</span>
            <ExternalLink className="w-3.5 h-3.5" />
          </a>
        </div>
      )}

      {/* 首屏：运行角色选择（手机 2×2 / 桌面 1×4）+ 智能 AuthKey 接入区 */}
      <SectionCard
        title="运行角色与认证接入"
        icon={<Share2 className="w-4 h-4" />}
        subtitle="选定本机在组网中承担的角色，并配置自动登录所需的授权密钥（auth_key）"
      >
        <div className="space-y-3.5">
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-2 sm:gap-3">
            {TS_MODES.map((m) => {
              const selected = mode === m.value;
              return (
                <button
                  key={m.value}
                  type="button"
                  onClick={() => onSelectRole(m.value)}
                  style={
                    selected
                      ? { backgroundColor: 'var(--accent-soft)', borderColor: 'var(--accent)' }
                      : undefined
                  }
                  className={`p-2.5 sm:p-3.5 rounded-xl border text-left transition-all cursor-pointer active:scale-[0.99] ${
                    selected ? '' : 'bg-surface2 border-subtle hover:border-strong'
                  }`}
                >
                  <div className="text-xs sm:text-sm font-semibold text-primary">{m.title}</div>
                  <div className="text-[11px] text-secondary mt-1 leading-snug">{m.desc}</div>
                </button>
              );
            })}
          </div>

          <div className="rounded-xl border border-subtle bg-surface2/70 overflow-hidden">
            <button
              type="button"
              onClick={onToggleAuthOpen}
              className="w-full min-h-[44px] px-3.5 py-2.5 flex items-center justify-between gap-2 text-left hover:bg-surface2 transition-colors cursor-pointer"
            >
              <div className="flex flex-wrap items-center gap-2 text-xs font-medium text-primary">
                <KeyRound className="w-3.5 h-3.5 text-[var(--accent)] shrink-0" />
                <span>Tailscale 授权密钥 (`auth_key`)</span>
                <Badge tone={tsCfg?.authKeySet || ts?.authKeySet ? 'ok' : 'warn'}>
                  {tsCfg?.authKeySet
                    ? privacyMask
                      ? '••••••••'
                      : tsCfg.authKeyHint || '已配置'
                    : '未配置（可直接网页扫码登录或填入密钥）'}
                </Badge>
              </div>
              {isAuthOpen ? (
                <ChevronUp className="w-4 h-4 text-secondary shrink-0" />
              ) : (
                <ChevronDown className="w-4 h-4 text-secondary shrink-0" />
              )}
            </button>

            {isAuthOpen && (
              <form
                onSubmit={onSaveAuthKey}
                className="px-3.5 pb-3.5 pt-2.5 border-t border-subtle space-y-2.5 text-xs"
              >
                <div className="flex flex-col sm:flex-row sm:items-center gap-2">
                  <input
                    type="password"
                    autoComplete="new-password"
                    disabled={clearAuthKey}
                    value={authKeyInput}
                    onChange={(e) => onAuthKeyInputChange(e.target.value)}
                    placeholder={
                      tsCfg?.authKeySet
                        ? `已配置 (${privacyMask ? '••••••••' : tsCfg.authKeyHint || '********'})，留空不变`
                        : '粘贴 tskey-auth-...（也可留空直接点启动，通过网页链接登录）'
                    }
                    className="flex-1 h-10 sm:h-9 px-3 rounded-xl bg-surface1 border border-subtle text-base sm:text-xs text-primary font-mono focus:outline-none focus:border-strong"
                  />
                  <Button
                    type="submit"
                    size="sm"
                    variant="secondary"
                    loading={savingAuthKey}
                    disabled={busy || privacyMask}
                    icon={<Save className="w-3.5 h-3.5" />}
                  >
                    保存密钥
                  </Button>
                </div>
                {tsCfg?.authKeySet && (
                  <label className="inline-flex items-center gap-2 text-[11px] text-rose-300 cursor-pointer select-none py-1">
                    <input
                      type="checkbox"
                      checked={clearAuthKey}
                      onChange={(e) => onClearAuthKeyChange(e.target.checked)}
                      className="accent-rose-500 w-4 h-4"
                    />
                    <span>清空已保存的 Auth Key</span>
                  </label>
                )}
              </form>
            )}
          </div>

          {!ts?.running && (
            <div className="flex flex-wrap items-center justify-between gap-2 pt-2 border-t border-subtle text-xs">
              <span className="text-secondary">
                选好上方角色、填写密钥（或网页登录）并勾好下方网段后，点击启动即可一键接入。
              </span>
              <Button
                size="sm"
                variant="primary"
                disabled={busy}
                icon={<Play className="w-3.5 h-3.5" />}
                onClick={onStartWithAutoSave}
              >
                按所选角色启动
              </Button>
            </div>
          )}
        </div>
      </SectionCard>
    </>
  );
};

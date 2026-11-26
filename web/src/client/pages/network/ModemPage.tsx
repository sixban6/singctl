import React, { useCallback, useEffect, useRef, useState } from 'react';
import {
  AlertTriangle,
  ArrowRight,
  Cable,
  CheckCircle2,
  Globe,
  RefreshCw,
  RotateCcw,
  Router,
  Save,
  ShieldAlert,
} from 'lucide-react';
import { Badge, Button, PageHeader, SectionCard, useToast } from '../../../ui';
import { useCachedQuery } from '../../../hooks';
import { maskFullIP } from '../../../lib/privacyMask';
import { clientApi } from '../../api';
import { MODEM_STATUS_CACHE_KEY } from '../../cacheKeys';
import { HomeDomainOverviewResponse, ModemCredentialsSummary, ModemStatusResponse } from '../../types';
import { ModemConsoleCard } from './ModemConsoleCard';
import { ModemCredentialsCard } from './ModemCredentialsCard';

export interface ModemPageProps {
  busy: boolean;
  privacyMask?: boolean;
}

interface PendingAutofillPayload {
  nonce: string;
  username: string;
  password: string;
}

function formatAccessModeMeta(
  mode?: string,
  natLayers?: number,
): { label: string; tone: 'ok' | 'warn' | 'accent' | 'neutral' } {
  switch (mode) {
    case 'router_nat':
      return {
        label: natLayers && natLayers >= 3 ? `光猫路由模式 · ${natLayers}层 NAT` : '光猫路由模式 · 双层 NAT',
        tone: 'warn',
      };
    case 'pppoe_bridge':
      return { label: '光猫桥接 + 路由拨号 · 单层 NAT', tone: 'ok' };
    case 'side_via_main':
      return { label: '旁路由视角 · 经主路由可达', tone: 'accent' };
    default:
      return { label: '待确认接入形态', tone: 'neutral' };
  }
}

function formatWANExitLabel(exitType?: string): { label: string; tone: 'ok' | 'warn' | 'neutral' } {
  switch (exitType) {
    case 'public':
      return { label: '公网 IPv4', tone: 'ok' };
    case 'cgnat':
      return { label: '运营商内网 CGNAT (100.64/10)', tone: 'warn' };
    case 'private':
      return { label: '上游光猫私网 NAT', tone: 'warn' };
    default:
      return { label: '未知 / 旁路由未直接拨号', tone: 'neutral' };
  }
}

function buildModemProxyURL(port: number, ticket?: string): string {
  const host = typeof window !== 'undefined' && window.location.hostname ? window.location.hostname : '127.0.0.1';
  const hostForUrl = host.includes(':') && !host.startsWith('[') ? `[${host}]` : host;
  const base = `http://${hostForUrl}:${port}/`;
  return ticket ? `${base}?_sc_modem_ticket=${encodeURIComponent(ticket)}` : base;
}

function parsePortFromTarget(target?: string): number | null {
  if (!target) return null;
  try {
    const u = new URL(target);
    if (u.port) return Number(u.port);
    return u.protocol === 'https:' ? 443 : 80;
  } catch {
    return null;
  }
}

export const ModemPage: React.FC<ModemPageProps> = ({ busy, privacyMask = false }) => {
  const { success, error, toast } = useToast();
  const {
    data: status,
    loading,
    refreshing,
    setData: setStatus,
    refetch: refetchStatus,
  } = useCachedQuery<ModemStatusResponse>(MODEM_STATUS_CACHE_KEY, () => clientApi.getModemStatus());

  const [ipInput, setIPInput] = useState('');
  const [ipDirty, setIPDirty] = useState(false);
  const [savingIP, setSavingIP] = useState(false);
  const [bridgeBusy, setBridgeBusy] = useState(false);

  const [homeDomain, setHomeDomain] = useState<HomeDomainOverviewResponse | null>(null);
  const [bindingHome, setBindingHome] = useState(false);

  const [consoleOpening, setConsoleOpening] = useState(false);
  const [consoleClosing, setConsoleClosing] = useState(false);
  const [iframeSrc, setIframeSrc] = useState<string | null>(null);
  const [iframeKey, setIframeKey] = useState(0);
  const [fullscreen, setFullscreen] = useState(false);
  const [activeProxyPort, setActiveProxyPort] = useState<number | null>(null);
  const [autofillNonce, setAutofillNonce] = useState('');
  const [loginBusySlot, setLoginBusySlot] = useState<'super' | 'user' | null>(null);

  const iframeRef = useRef<HTMLIFrameElement | null>(null);
  const pendingAutofillRef = useRef<PendingAutofillPayload | null>(null);

  useEffect(() => {
    if (status && !ipDirty) {
      setIPInput(status.configuredModemIp || status.effectiveModemIp || '');
    }
    if (status?.console?.running) {
      const parsed = parsePortFromTarget(status.console.target);
      if (parsed) setActiveProxyPort(parsed);
    }
  }, [status, ipDirty]);

  const loadHomeDomain = useCallback(async () => {
    try {
      const res = await clientApi.getHomeDomain();
      setHomeDomain(res);
    } catch {
      // keep silent when home domain service unavailable
    }
  }, []);

  useEffect(() => {
    void loadHomeDomain();
  }, [loadHomeDomain]);

  useEffect(() => {
    if (!fullscreen) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') setFullscreen(false);
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [fullscreen]);

  useEffect(() => {
    const onMessage = (ev: MessageEvent) => {
      const data = ev.data as { type?: string; nonce?: string; status?: string } | null;
      if (!data || data.type !== 'sc_modem_autofill_ack') return;
      if (!autofillNonce || data.nonce !== autofillNonce) return;

      pendingAutofillRef.current = null;
      setLoginBusySlot(null);

      switch (data.status) {
        case 'submitted':
          success('已自动填入凭据并提交光猫登录');
          break;
        case 'filled':
          success('已自动填入凭据，请在光猫页面点击登录');
          break;
        case 'captcha_required':
          toast('已填入账号密码（检测到图形验证码，请手动输入验证码后登录）', 'warn');
          break;
        case 'not_found':
          toast('当前画面未检测到登录输入框（可能已登录或请使用复制账密手动填入）', 'warn');
          break;
      }
    };
    window.addEventListener('message', onMessage);
    return () => window.removeEventListener('message', onMessage);
  }, [autofillNonce, success, toast]);

  const handleRefresh = async () => {
    try {
      await refetchStatus(false);
      success('已刷新上游光猫与 WAN 接入状态');
    } catch (e: unknown) {
      error(e instanceof Error ? e.message : '探测上游光猫状态失败');
    }
  };

  const savedConfiguredIP = (status?.configuredModemIp || '').trim();
  const effectiveModemIP = (status?.effectiveModemIp || '').trim();
  const trimmedInput = ipInput.trim();
  const hasIPChange = Boolean(
    status &&
      ((trimmedInput !== '' && trimmedInput !== (savedConfiguredIP || effectiveModemIP)) ||
        (trimmedInput === '' && savedConfiguredIP !== '')),
  );

  const handleSaveModemIP = async (overrideIP?: string) => {
    if (privacyMask) return;
    const nextIP = overrideIP !== undefined ? overrideIP : trimmedInput;
    setSavingIP(true);
    try {
      const res = await clientApi.saveModemConfig({ modemIP: nextIP });
      setStatus(res.status);
      setIPInput(res.status.configuredModemIp || res.status.effectiveModemIp || '');
      setIPDirty(false);
      success(res.message);
    } catch (e: unknown) {
      error(e instanceof Error ? e.message : '保存光猫地址失败');
    } finally {
      setSavingIP(false);
    }
  };

  const handleToggleBridgeHelper = async (enable: boolean) => {
    if (privacyMask) return;
    setBridgeBusy(true);
    try {
      const target = trimmedInput || effectiveModemIP;
      const res = await clientApi.saveModemBridge({ enabled: enable, modemIP: enable ? target : '' });
      setStatus(res.status);
      setIPDirty(false);
      success(res.message);
    } catch (e: unknown) {
      error(e instanceof Error ? e.message : '操作桥接访问接口失败');
    } finally {
      setBridgeBusy(false);
    }
  };

  const openConsoleOnPort = async (desiredPort: number, newWindow = false) => {
    if (privacyMask) {
      toast('隐私完全遮挡开启期间已隐藏内嵌控制台，请先关闭遮挡', 'warn');
      return null;
    }
    const targetIP = trimmedInput || effectiveModemIP;
    if (!targetIP) {
      error('未探测到上游光猫地址，请先手动填写光猫 IP 并保存');
      return null;
    }
    setConsoleOpening(true);
    try {
      const scheme = desiredPort === 8080 ? 'http' : desiredPort === 443 ? 'https' : status?.scheme || 'http';
      const res = await clientApi.openModemConsole({ scheme, ip: targetIP, port: desiredPort });
      const nextUrl = buildModemProxyURL(res.session.port, res.session.ticket);
      const nonce = res.session.autofillNonce || '';
      setAutofillNonce(nonce);
      setActiveProxyPort(desiredPort);
      setStatus((prev) => (prev ? { ...prev, console: res.console } : prev));
      if (newWindow) {
        window.open(nextUrl, '_blank', 'noopener,noreferrer');
      } else {
        setIframeSrc(nextUrl);
        setIframeKey((k) => k + 1);
      }
      return res.session;
    } catch (e: unknown) {
      error(e instanceof Error ? e.message : '打开光猫内嵌控制台失败');
      return null;
    } finally {
      setConsoleOpening(false);
    }
  };

  const handleCloseConsole = async () => {
    setConsoleClosing(true);
    try {
      const res = await clientApi.closeModemConsole();
      pendingAutofillRef.current = null;
      setLoginBusySlot(null);
      setIframeSrc(null);
      setActiveProxyPort(null);
      setAutofillNonce('');
      setFullscreen(false);
      setStatus((prev) => (prev ? { ...prev, console: res.console } : prev));
      success('已休眠关闭光猫代理端口，释放后台资源');
    } catch (e: unknown) {
      error(e instanceof Error ? e.message : '关闭光猫控制台失败');
    } finally {
      setConsoleClosing(false);
    }
  };

  const handleIframeLoad = () => {
    const pending = pendingAutofillRef.current;
    const win = iframeRef.current?.contentWindow;
    if (!pending || !win) return;
    win.postMessage(
      {
        type: 'sc_modem_autofill',
        nonce: pending.nonce,
        username: pending.username,
        password: pending.password,
        autoSubmit: true,
      },
      '*',
    );
  };

  const handleOneClickLogin = async (slot: 'super' | 'user') => {
    if (privacyMask) {
      toast('隐私完全遮挡开启期间已禁用一键登录', 'warn');
      return;
    }
    const desiredPort = slot === 'super' && status?.adminPort ? status.adminPort : status?.port || 80;
    setLoginBusySlot(slot);
    try {
      const cred = await clientApi.useModemCredential({ slot });
      const alreadyLoadedSamePort = Boolean(iframeSrc && autofillNonce && activeProxyPort === desiredPort);
      if (alreadyLoadedSamePort && iframeRef.current?.contentWindow) {
        const payload = { nonce: autofillNonce, username: cred.username, password: cred.password };
        pendingAutofillRef.current = payload;
        iframeRef.current.contentWindow.postMessage(
          { type: 'sc_modem_autofill', ...payload, autoSubmit: true },
          '*',
        );
        window.setTimeout(() => setLoginBusySlot(null), 3200);
        return;
      }

      const sess = await openConsoleOnPort(desiredPort, false);
      if (!sess || !sess.autofillNonce) {
        setLoginBusySlot(null);
        return;
      }
      pendingAutofillRef.current = {
        nonce: sess.autofillNonce,
        username: cred.username,
        password: cred.password,
      };
      window.setTimeout(() => setLoginBusySlot(null), 5000);
    } catch (e: unknown) {
      setLoginBusySlot(null);
      error(e instanceof Error ? e.message : '一键登录准备失败');
    }
  };

  const modemHomeBound = Boolean(
    homeDomain?.devices?.some((d) => d.alias === 'modem' && (!effectiveModemIP || d.ip === effectiveModemIP)),
  );
  const homeSuffix = homeDomain?.suffix || 'home';

  const handleBindModemHome = async () => {
    if (!effectiveModemIP || privacyMask) return;
    setBindingHome(true);
    try {
      const next = await clientApi.upsertHomeDomainDevice({
        alias: 'modem',
        displayName: '上游光猫',
        ip: effectiveModemIP,
        source: 'manual',
        services: [
          {
            label: '光猫控制台',
            scheme: status?.scheme === 'https' ? 'https' : 'http',
            port: status?.port || 80,
          },
        ],
      });
      setHomeDomain(next);
      success(`已绑定 http://modem.${next.suffix || homeSuffix} → ${effectiveModemIP}（支持局域网与 Tailscale 直达）`);
    } catch (e: unknown) {
      error(e instanceof Error ? e.message : '绑定本地域名失败');
    } finally {
      setBindingHome(false);
    }
  };

  const handleCredentialsChange = (nextCreds: ModemCredentialsSummary) => {
    setStatus((prev) => (prev ? { ...prev, credentials: nextCreds } : prev));
  };

  const modeMeta = formatAccessModeMeta(status?.accessMode, status?.natLayers);
  const exitMeta = formatWANExitLabel(status?.wanExitType);
  const consoleRunning = Boolean(iframeSrc || status?.console?.running);
  const normalPort = status?.port || 80;
  const currentTargetPort = activeProxyPort || parsePortFromTarget(status?.console?.target) || normalPort;

  return (
    <div className="space-y-5">
      <PageHeader
        title="上游光猫与宽带接入"
        description="按需探测多跳上游路由链、真光猫指纹与公网 / CGNAT 属性，并提供带 0600 凭据保险箱与一键登录的内嵌控制台"
        badge={
          <Badge tone={modeMeta.tone} dot={Boolean(status)}>
            {status ? modeMeta.label : '探测中…'}
          </Badge>
        }
        actions={
          <Button
            size="xs"
            loading={loading || refreshing}
            onClick={() => void handleRefresh()}
            icon={<RefreshCw className="w-3 h-3" />}
          >
            重新探测光猫
          </Button>
        }
      />

      <SectionCard
        title="光猫连通性与 WAN 多跳拓扑摘要"
        icon={<Router className="w-4 h-4" />}
        subtitle="不运行常驻后台轮询，零小内存负担；自动追踪公网前所有私网跳数并区分真光猫与中间家用路由器"
        actions={
          <Badge tone={status?.online ? 'ok' : 'warn'} dot>
            {status?.online
              ? `在线 · ${status.scheme?.toUpperCase() || 'HTTP'}:${normalPort}${status.adminPort ? ` / :${status.adminPort}` : ''} (${status.latencyMs || 1}ms)`
              : status
                ? '暂不可达 / 未绑定'
                : '探测中…'}
          </Badge>
        }
      >
        <div className="space-y-4">
          {status && (
            <div className="rounded-xl border border-subtle bg-surface2/60 px-3.5 py-2.5 flex flex-wrap items-center gap-x-4 gap-y-2 text-xs">
              <div className="flex items-center gap-1.5">
                <span className="text-muted">WAN 协议:</span>
                <span className="font-mono text-primary">
                  {status.wanProto ? `${status.wanProto.toUpperCase()} (${status.wanIface || '-'})` : '经主路由上联'}
                </span>
              </div>
              <div className="flex items-center gap-1.5">
                <span className="text-muted">出口属性:</span>
                <Badge tone={exitMeta.tone}>{exitMeta.label}</Badge>
              </div>
              {status.wanIp && (
                <div className="flex items-center gap-1.5">
                  <span className="text-muted">WAN IP:</span>
                  <span className="font-mono text-primary">{maskFullIP(status.wanIp, privacyMask)}</span>
                </div>
              )}
              {status.vendorHint && (
                <div className="flex items-center gap-1.5">
                  <span className="text-muted">当前锁定:</span>
                  <span className={status.deviceKind === 'router' ? 'text-amber-300 font-medium' : 'text-emerald-300 font-medium'}>
                    {status.vendorHint}
                  </span>
                  {status.deviceKind === 'modem' && <Badge tone="ok">真光猫</Badge>}
                  {status.deviceKind === 'router' && <Badge tone="warn">上级路由器</Badge>}
                </div>
              )}
            </div>
          )}

          {status?.upstreamHops && status.upstreamHops.length > 0 && (
            <div className="rounded-xl border border-subtle bg-surface2/40 px-3.5 py-2.5 flex flex-wrap items-center gap-2 text-xs">
              <span className="text-muted shrink-0">实测上联链路:</span>
              <span className="px-2 py-0.5 rounded-md bg-surface3/60 text-primary font-medium">本机网关</span>
              {status.upstreamHops.map((h) => {
                const isSelected = h.ip === effectiveModemIP;
                return (
                  <React.Fragment key={h.ip}>
                    <ArrowRight className="w-3.5 h-3.5 text-muted shrink-0" />
                    <div
                      className={`px-2.5 py-1 rounded-lg border flex items-center gap-1.5 ${
                        isSelected
                          ? 'border-emerald-500/45 bg-emerald-500/10 text-emerald-200'
                          : 'border-subtle bg-surface3/40 text-secondary'
                      }`}
                    >
                      <span className="font-mono">{maskFullIP(h.ip, privacyMask)}</span>
                      <span>
                        · {h.deviceKind === 'modem' ? '真光猫' : h.deviceKind === 'router' ? '路由器' : '网关'}
                      </span>
                      {h.vendorHint && <span className="text-[11px] opacity-80">({h.vendorHint})</span>}
                    </div>
                  </React.Fragment>
                );
              })}
              <ArrowRight className="w-3.5 h-3.5 text-muted shrink-0" />
              <span className="px-2 py-0.5 rounded-md bg-surface3/60 text-muted">运营商公网</span>
            </div>
          )}

          {status?.doubleNatHint && (
            <div className="rounded-xl border border-amber-500/35 bg-amber-500/10 px-3.5 py-2.5 text-xs text-amber-200 flex items-start gap-2">
              <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
              <span>{status.doubleNatHint}</span>
            </div>
          )}

          {status?.subnetConflict && (
            <div className="rounded-xl border border-rose-500/35 bg-rose-500/10 px-3.5 py-2.5 text-xs text-rose-200 flex items-start gap-2">
              <ShieldAlert className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
              <span>{status.subnetConflict}</span>
            </div>
          )}

          {status?.bridgeHelperCapable && (
            <div className="rounded-xl border border-subtle bg-surface2 p-3.5 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
              <div className="flex items-start gap-2.5 text-xs">
                <Cable className="w-4 h-4 text-sky-400 shrink-0 mt-0.5" />
                <div>
                  <div className="font-semibold text-primary">
                    PPPoE 桥接光猫免插线访问（物理口 {status.wanPhysDevice}）
                  </div>
                  <p className="text-secondary mt-0.5">
                    {status.bridgeHelperEnabled
                      ? `已安全挂载独立旁路接口 (${maskFullIP(status.bridgeHelperIp, privacyMask)}，defaultroute=0 不影响宽带拨号)。`
                      : '光猫改桥接由本机 PPPoE 拨号后，开启此项即可免插网线直接打开光猫后台。'}
                  </p>
                </div>
              </div>
              <Button
                size="sm"
                variant={status.bridgeHelperEnabled ? 'secondary' : 'primary'}
                loading={bridgeBusy}
                disabled={busy || privacyMask || (!status.bridgeHelperEnabled && Boolean(status.subnetConflict))}
                onClick={() => void handleToggleBridgeHelper(!status.bridgeHelperEnabled)}
              >
                {status.bridgeHelperEnabled ? '移除桥接直通口' : '一键打通桥接光猫访问'}
              </Button>
            </div>
          )}

          <div className="flex flex-col sm:flex-row sm:items-end justify-between gap-3 pt-1">
            <div className="space-y-1.5 flex-1 max-w-md">
              <label htmlFor="modem-ip-input" className="text-xs font-semibold text-primary block">
                上游光猫管理 IPv4 地址（留空点击恢复即自动探测）
              </label>
              <div className="flex items-center gap-2 flex-wrap">
                <input
                  id="modem-ip-input"
                  type={privacyMask ? 'password' : 'text'}
                  readOnly={privacyMask}
                  value={ipInput}
                  onChange={(e) => {
                    setIPInput(e.target.value);
                    setIPDirty(true);
                  }}
                  placeholder={privacyMask ? '••••••••' : '例如 192.168.1.1 或 192.168.100.1'}
                  className="sc-input h-9 px-3 text-xs sm:text-sm font-mono w-48 sm:w-56"
                />
                <Button
                  size="sm"
                  variant={hasIPChange ? 'primary' : 'secondary'}
                  loading={savingIP}
                  disabled={busy || privacyMask || !hasIPChange}
                  icon={hasIPChange ? <Save className="w-3.5 h-3.5" /> : <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />}
                  onClick={() => void handleSaveModemIP()}
                >
                  {hasIPChange ? '保存地址' : '已匹配生效'}
                </Button>
                {savedConfiguredIP && (
                  <Button
                    size="sm"
                    variant="ghost"
                    disabled={busy || privacyMask || savingIP}
                    icon={<RotateCcw className="w-3.5 h-3.5" />}
                    onClick={() => void handleSaveModemIP('')}
                  >
                    恢复自动探测
                  </Button>
                )}
              </div>
            </div>

            <div className="flex items-center gap-2 flex-wrap">
              <Button
                size="sm"
                variant={modemHomeBound ? 'secondary' : 'ghost'}
                loading={bindingHome}
                disabled={busy || privacyMask || !effectiveModemIP}
                icon={modemHomeBound ? <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" /> : <Globe className="w-3.5 h-3.5" />}
                onClick={() => void handleBindModemHome()}
              >
                {modemHomeBound ? `已绑定 modem.${homeSuffix}` : `一键绑定 modem.${homeSuffix}`}
              </Button>
            </div>
          </div>
        </div>
      </SectionCard>

      <ModemCredentialsCard
        credentials={status?.credentials}
        busy={busy}
        privacyMask={privacyMask}
        canAutoLogin={Boolean(trimmedInput || effectiveModemIP)}
        adminPort={status?.adminPort}
        loginBusySlot={loginBusySlot}
        onCredentialsChange={handleCredentialsChange}
        onOneClickLogin={(slot) => void handleOneClickLogin(slot)}
      />

      <ModemConsoleCard
        status={status}
        busy={busy}
        privacyMask={privacyMask}
        effectiveModemIP={effectiveModemIP}
        consoleRunning={consoleRunning}
        consoleOpening={consoleOpening}
        consoleClosing={consoleClosing}
        iframeSrc={iframeSrc}
        iframeKey={iframeKey}
        fullscreen={fullscreen}
        normalPort={normalPort}
        currentTargetPort={currentTargetPort}
        hasSuperCred={Boolean(status?.credentials?.super?.saved)}
        hasUserCred={Boolean(status?.credentials?.user?.saved)}
        loginBusySlot={loginBusySlot}
        iframeRef={iframeRef}
        onIframeLoad={handleIframeLoad}
        onRefreshFrame={() => {
          if (iframeSrc) {
            setIframeKey((k) => k + 1);
          } else {
            void openConsoleOnPort(currentTargetPort, false);
          }
        }}
        onToggleFullscreen={() => setFullscreen((v) => !v)}
        onOpenPort={(port, nw) => void openConsoleOnPort(port, nw)}
        onOneClickLogin={(slot) => void handleOneClickLogin(slot)}
        onCloseConsole={() => void handleCloseConsole()}
      />
    </div>
  );
};

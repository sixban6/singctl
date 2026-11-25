import React, { useEffect, useMemo, useState } from 'react';
import {
  Check,
  Copy,
  Eye,
  EyeOff,
  Flame,
  GitFork,
  Globe,
  Monitor,
  Network,
  RefreshCw,
  Share2,
  ShieldAlert,
  X,
} from 'lucide-react';
import { Badge, Button, SegmentedTabs, useToast } from '../../ui';
import {
  BROWSER_DOH_EVENT,
  getCachedBrowserDoH,
  runBrowserDoHCheckFlow,
} from '../components/DNSLeakTestCard';
import { copyPlainText, detectBrowserDoHGuide } from '../lib/leakProbes';
import {
  PRIVACY_MASK_EVENT,
  readPrivacyMaskPref,
  redactInlineSensitive,
  writePrivacyMaskPref,
} from '../../lib/privacyMask';
import { BrowserDoHCheckResponse, ClientStatusResponse, SafeCommitStatusReport } from '../types';
import { FirewallPanel } from './firewall/FirewallPanel';
import { GatewayModePage, GatewayModePageProps } from './network/GatewayModePage';
import { HomeDomainSection } from './network/homedomain/HomeDomainSection';
import { TailscalePage, TailscalePageProps } from './network/TailscalePage';
import { VlanManagerSection } from './network/vlan/VlanManagerSection';

export { GatewayModePage, TailscalePage };
export type { GatewayModePageProps, TailscalePageProps };

export type NetSubTab = 'gw' | 'ts' | 'home' | 'fw' | 'vlan';

function normalizeNetSubTab(raw?: string): NetSubTab {
  if (raw === 'fw') return 'fw';
  if (raw === 'ts') return 'ts';
  if (raw === 'home') return 'home';
  if (raw === 'vlan') return 'vlan';
  if (raw === 'gw') return 'gw';
  return 'gw';
}

export interface NetworkHubPageProps {
  status: ClientStatusResponse | null;
  busy: boolean;
  initialSub?: string;
  onSubChange?: (sub: NetSubTab) => void;
  onAction: (name: string, params?: Record<string, unknown>, confirmMsg?: string) => void;
  onNavigate?: (tab: string, sub?: string) => void;
  onRefreshStatus?: () => void;
  onSafeCommitUpdated?: (sc: SafeCommitStatusReport) => void;
}

export const NetworkHubPage: React.FC<NetworkHubPageProps> = ({
  status,
  busy,
  initialSub,
  onSubChange,
  onAction,
  onNavigate,
  onRefreshStatus,
  onSafeCommitUpdated,
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
              key: 'home',
              label: '本地域名 (.home)',
              icon: <Globe className="w-3.5 h-3.5" />,
            },
            {
              key: 'fw',
              label: 'nftables 防火墙加固',
              icon: <Flame className="w-3.5 h-3.5" />,
            },
            {
              key: 'vlan',
              label: '子网隔离 (VLAN)',
              icon: <Network className="w-3.5 h-3.5" />,
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
        <GatewayModePage
          status={status}
          busy={busy}
          privacyMask={privacyMask}
          onNavigate={onNavigate}
          onSaved={onRefreshStatus}
        />
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
      {sub === 'home' && (
        <HomeDomainSection
          busy={busy}
          privacyMask={privacyMask}
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
      {sub === 'vlan' && (
        <VlanManagerSection
          busy={busy}
          privacyMask={privacyMask}
          safeCommit={status?.safeCommit}
          onRefreshStatus={onRefreshStatus}
          onSafeCommitUpdated={onSafeCommitUpdated}
        />
      )}
    </div>
  );
};

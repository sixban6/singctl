import React, { useEffect, useMemo, useState } from 'react';
import {
  Check,
  Copy,
  Eye,
  EyeOff,
  Flame,
  GitFork,
  Monitor,
  Network,
  RefreshCw,
  Router,
  Share2,
  ShieldAlert,
  Wifi,
  X,
} from 'lucide-react';
import { Badge, Button, SegmentedTabItem, SegmentedTabs, useToast } from '../../ui';
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
import { MeshAndDomainSection, MeshDomainView } from './network/MeshAndDomainSection';
import { ModemPage } from './network/ModemPage';
import { TailscalePage, TailscalePageProps } from './network/TailscalePage';
import { VlanManagerSection } from './network/vlan/VlanManagerSection';
import { WifiOptSection } from './network/wifi/WifiOptSection';

export { GatewayModePage, TailscalePage };
export type { GatewayModePageProps, TailscalePageProps };

export type NetSubTab = 'gw' | 'ts' | 'home' | 'fw' | 'vlan' | 'wifi' | 'modem';
type EffectiveNetSubTab = 'gw' | 'ts' | 'fw' | 'vlan' | 'wifi' | 'modem';

function normalizeNetSubTab(raw?: string): EffectiveNetSubTab {
  if (raw === 'fw') return 'fw';
  if (raw === 'ts' || raw === 'home') return 'ts';
  if (raw === 'vlan') return 'vlan';
  if (raw === 'wifi') return 'wifi';
  if (raw === 'modem') return 'modem';
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
  const [sub, setSub] = useState<EffectiveNetSubTab>(() => normalizeNetSubTab(initialSub));
  const [meshView, setMeshView] = useState<MeshDomainView>(() => (initialSub === 'home' ? 'home' : 'ts'));
  const [privacyMask, setPrivacyMask] = useState<boolean>(() => readPrivacyMaskPref());
  const [browserDoH, setBrowserDoH] = useState<BrowserDoHCheckResponse | null>(() => getCachedBrowserDoH());
  const [dohChecking, setDohChecking] = useState(false);
  const [dohDismissed, setDohDismissed] = useState(false);
  const [copiedDoHUrl, setCopiedDoHUrl] = useState(false);
  const dohGuide = useMemo(() => detectBrowserDoHGuide(), []);

  useEffect(() => {
    if (initialSub !== undefined) {
      setSub(normalizeNetSubTab(initialSub));
      if (initialSub === 'home') {
        setMeshView('home');
      } else if (initialSub === 'ts') {
        setMeshView('ts');
      }
    }
  }, [initialSub]);

  const caps = status?.host?.capabilities;
  const showFirewall = caps ? caps.firewall : Boolean(status?.firewall?.supported);
  const showVlan = Boolean(caps?.vlan);
  const showWifi = Boolean(caps?.wifi);

  const tabItems = useMemo<SegmentedTabItem<EffectiveNetSubTab>[]>(() => {
    const items: SegmentedTabItem<EffectiveNetSubTab>[] = [
      {
        key: 'gw',
        label: '网关模式 (主/旁路由)',
        icon: <GitFork className="w-3.5 h-3.5" />,
      },
      {
        key: 'ts',
        label: '异地组网与域名',
        icon: <Share2 className="w-3.5 h-3.5" />,
      },
    ];
    if (showFirewall) {
      items.push({
        key: 'fw',
        label: 'nftables 防火墙加固',
        icon: <Flame className="w-3.5 h-3.5" />,
      });
    }
    if (showVlan) {
      items.push({
        key: 'vlan',
        label: '子网隔离 (VLAN)',
        icon: <Network className="w-3.5 h-3.5" />,
      });
    }
    if (showWifi) {
      items.push({
        key: 'wifi',
        label: 'Wi-Fi 调优',
        icon: <Wifi className="w-3.5 h-3.5" />,
      });
    }
    items.push({
      key: 'modem',
      label: '上游光猫',
      icon: <Router className="w-3.5 h-3.5" />,
    });
    return items;
  }, [showFirewall, showVlan, showWifi]);

  // 仅当设备能力探针已就绪且当前页签不可用时回退，避免冷启动直达链接闪烁跳转
  useEffect(() => {
    if (!caps) return;
    if (!tabItems.some((item) => item.key === sub)) {
      setSub('gw');
      onSubChange?.('gw');
    }
  }, [caps, onSubChange, sub, tabItems]);

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

  const handleSelect = (next: EffectiveNetSubTab) => {
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
          onChange={(k) => handleSelect(k as EffectiveNetSubTab)}
          items={tabItems}
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
          onAction={onAction}
          onNavigate={onNavigate}
          onSaved={onRefreshStatus}
        />
      )}
      {sub === 'ts' && (
        <MeshAndDomainSection
          status={status}
          busy={busy}
          privacyMask={privacyMask}
          initialView={meshView}
          onViewChange={setMeshView}
          onAction={onAction}
          onRefreshStatus={onRefreshStatus}
        />
      )}
      {sub === 'fw' && showFirewall && (
        <FirewallPanel
          status={status}
          busy={busy}
          privacyMask={privacyMask}
          onRefreshStatus={onRefreshStatus}
        />
      )}
      {sub === 'vlan' && showVlan && (
        <VlanManagerSection
          busy={busy}
          privacyMask={privacyMask}
          safeCommit={status?.safeCommit}
          onRefreshStatus={onRefreshStatus}
          onSafeCommitUpdated={onSafeCommitUpdated}
        />
      )}
      {sub === 'wifi' && showWifi && (
        <WifiOptSection
          busy={busy}
          privacyMask={privacyMask}
          onRefreshStatus={onRefreshStatus}
          onSafeCommitUpdated={onSafeCommitUpdated}
        />
      )}
      {sub === 'modem' && <ModemPage busy={busy} privacyMask={privacyMask} />}
    </div>
  );
};

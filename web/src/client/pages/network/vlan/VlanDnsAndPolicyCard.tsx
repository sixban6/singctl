import React, { useEffect, useState } from 'react';
import {
  AlertTriangle,
  Check,
  CheckCircle2,
  Copy,
  Globe,
  Server,
  Share2,
  Shield,
  Terminal,
  Zap,
} from 'lucide-react';
import { Badge, Button, useToast } from '../../../../ui';
import { copyPlainText } from '../../../lib/leakProbes';
import { VlanPreviewResult, VlanSaveSegmentRequest, VlanSecurityPolicy } from '../../../types';
import { maskVlanText, parseDnsInput } from './vlanHelpers';

export interface ToggleRowProps {
  label: string;
  desc: string;
  checked: boolean;
  onChange: (next: boolean) => void;
}

export const ToggleRow: React.FC<ToggleRowProps> = ({ label, desc, checked, onChange }) => (
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

export interface VlanDnsAndPolicyCardProps {
  resetKey: string;
  draft: VlanSaveSegmentRequest;
  sideRouterIp?: string;
  privacyMask: boolean;
  onChangeDraft: (next: VlanSaveSegmentRequest) => void;
}

export const VlanDnsAndPolicyCard: React.FC<VlanDnsAndPolicyCardProps> = ({
  resetKey,
  draft,
  sideRouterIp = '',
  privacyMask,
  onChangeDraft,
}) => {
  const savedDns = draft.dhcpDns ?? [];
  const [customDnsMode, setCustomDnsMode] = useState<boolean>(savedDns.length > 0);
  const [dnsText, setDnsText] = useState<string>(savedDns.join(', '));

  useEffect(() => {
    const initial = draft.dhcpDns ?? [];
    setCustomDnsMode(initial.length > 0);
    setDnsText(initial.join(', '));
    // Re-hydrate only when drawer switches target segment or reopens
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [resetKey]);

  const setPolicy = (patch: Partial<VlanSecurityPolicy>) => {
    onChangeDraft({ ...draft, policy: { ...draft.policy, ...patch } });
  };

  const handleSelectGatewayDns = () => {
    setCustomDnsMode(false);
    setDnsText('');
    onChangeDraft({ ...draft, dhcpDns: [] });
  };

  const handleSelectCustomDns = () => {
    setCustomDnsMode(true);
    if (!dnsText.trim() && (draft.dhcpDns?.length ?? 0) === 0) {
      setDnsText('');
    }
  };

  const handleDnsInputChange = (val: string) => {
    setDnsText(val);
    onChangeDraft({ ...draft, dhcpDns: parseDnsInput(val) });
  };

  const applyDnsPreset = (presetVal: string) => {
    setCustomDnsMode(true);
    setDnsText(presetVal);
    onChangeDraft({ ...draft, dhcpDns: parseDnsInput(presetVal) });
  };

  return (
    <div className="rounded-2xl border border-slate-800/90 bg-slate-900/60 p-4 space-y-4">
      <h4 className="text-xs font-semibold text-white">3. 上网方式、DNS 下发与安全隔离</h4>

      {/* Proxy mode selector */}
      <div className="space-y-1.5">
        <div className="text-[11px] text-slate-400">分流与透明代理联动策略</div>
        <div className="grid sm:grid-cols-3 gap-2.5">
          <button
            type="button"
            onClick={() => onChangeDraft({ ...draft, proxyMode: 'follow' })}
            className={`rounded-xl border p-3 text-left transition-all cursor-pointer ${
              draft.proxyMode !== 'direct' && draft.proxyMode !== 'side_router'
                ? 'border-emerald-500/65 bg-emerald-500/12'
                : 'border-slate-800 bg-slate-950/60 hover:border-slate-700'
            }`}
          >
            <div className="flex items-center gap-2 text-xs font-semibold text-white">
              <Globe className="w-3.5 h-3.5 text-emerald-400" />
              跟随本机网关
            </div>
            <p className="text-[11px] text-slate-400 mt-1">
              遵循主路由当前运行模式转发或审计。
            </p>
          </button>

          <button
            type="button"
            disabled={!sideRouterIp && draft.proxyMode !== 'side_router'}
            onClick={() => onChangeDraft({ ...draft, proxyMode: 'side_router' })}
            className={`rounded-xl border p-3 text-left transition-all ${
              !sideRouterIp && draft.proxyMode !== 'side_router'
                ? 'border-slate-800/70 bg-slate-950/40 opacity-55 cursor-not-allowed'
                : draft.proxyMode === 'side_router'
                  ? 'border-cyan-500/70 bg-cyan-500/15 cursor-pointer'
                  : 'border-slate-800 bg-slate-950/60 hover:border-slate-700 cursor-pointer'
            }`}
          >
            <div className="flex items-center gap-2 text-xs font-semibold text-white">
              <Share2 className="w-3.5 h-3.5 text-cyan-400" />
              交由旁路由分流
            </div>
            <p className="text-[11px] text-slate-400 mt-1">
              {sideRouterIp
                ? `策略路由直转 ${maskVlanText(sideRouterIp, privacyMask)} 科学分流，并保持主网严格隔离。`
                : '需先在「网关模式」填写旁路由 IP。'}
            </p>
          </button>

          <button
            type="button"
            onClick={() => onChangeDraft({ ...draft, proxyMode: 'direct' })}
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
              彻底不走代理与旁路由，直出 WAN，适合智能家居与访客。
            </p>
          </button>
        </div>
      </div>

      {/* Custom DHCP Option 6 DNS server selector */}
      <div className="rounded-xl border border-slate-800/80 bg-slate-950/50 p-3.5 space-y-2.5">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <Server className="w-3.5 h-3.5 text-sky-400 shrink-0" />
            <span className="text-xs font-medium text-white">Wi-Fi / 子网下发 DNS 服务器</span>
          </div>
          <span className="text-[11px] text-slate-400">DHCP Option 6 唯一指定</span>
        </div>

        <div className="grid sm:grid-cols-2 gap-2">
          <button
            type="button"
            onClick={handleSelectGatewayDns}
            className={`rounded-xl border px-3 py-2 text-left text-xs transition-all cursor-pointer ${
              !customDnsMode
                ? 'border-emerald-500/65 bg-emerald-500/12 text-white'
                : 'border-slate-800 bg-slate-900/60 text-slate-400 hover:border-slate-700 hover:text-slate-200'
            }`}
          >
            <div className="font-semibold">
              {draft.proxyMode === 'side_router' && sideRouterIp
                ? '自动下发旁路由 DNS（推荐协同）'
                : '跟随本子网网关（默认推荐）'}
            </div>
            <div className="text-[11px] opacity-80 mt-0.5">
              {draft.proxyMode === 'side_router' && sideRouterIp
                ? `保存时自动下发旁路由 ${maskVlanText(sideRouterIp, privacyMask)} 并放行 53 端口`
                : `下发 ${maskVlanText(draft.ipAddr || '子网网关', privacyMask)}，由本机就近解析`}
            </div>
          </button>

          <button
            type="button"
            onClick={handleSelectCustomDns}
            className={`rounded-xl border px-3 py-2 text-left text-xs transition-all cursor-pointer ${
              customDnsMode
                ? 'border-sky-500/65 bg-sky-500/12 text-white'
                : 'border-slate-800 bg-slate-900/60 text-slate-400 hover:border-slate-700 hover:text-slate-200'
            }`}
          >
            <div className="font-semibold">自定义指定 DNS IP</div>
            <div className="text-[11px] opacity-80 mt-0.5">
              独立指定旁路由 AdGuard Home 或公共 DNS
            </div>
          </button>
        </div>

        {customDnsMode && (
          <div className="space-y-2 pt-1">
            <input
              type="text"
              value={dnsText}
              onChange={(e) => handleDnsInputChange(e.target.value)}
              placeholder="例如：192.168.1.2 或 223.5.5.5, 119.29.29.29（最多 4 个 IPv4）"
              className="w-full rounded-xl border border-slate-700/90 bg-slate-900/90 px-3 py-2 text-xs font-mono text-white focus:border-sky-500/70 focus:outline-none"
            />
            <div className="flex flex-wrap items-center gap-1.5 text-[11px]">
              <span className="text-slate-400">快捷填入：</span>
              <button
                type="button"
                onClick={() => applyDnsPreset('223.5.5.5, 119.29.29.29')}
                className="px-2 py-0.5 rounded-lg border border-slate-700 bg-slate-900 text-slate-300 hover:border-sky-500/50 hover:text-white transition-colors cursor-pointer"
              >
                阿里 + 腾讯公共 DNS
              </button>
              <button
                type="button"
                onClick={() => applyDnsPreset('223.5.5.5')}
                className="px-2 py-0.5 rounded-lg border border-slate-700 bg-slate-900 text-slate-300 hover:border-sky-500/50 hover:text-white transition-colors cursor-pointer"
              >
                仅阿里 DNS (223.5.5.5)
              </button>
            </div>
            <p className="text-[11px] text-sky-300/85 leading-relaxed">
              保存时会自动同步放行该子网去往指定 DNS 的跨网 53 端口，并豁免本机 dns_redirect / 透明代理 DNS 截胡，确保连上此 Wi-Fi 的设备 100% 唯一命中你指定的 DNS。
            </p>
          </div>
        )}
      </div>

      {/* Isolation toggles */}
      <div className="space-y-2">
        <ToggleRow
          label="允许访问外网 (Internet)"
          desc="关闭后该网段将成为纯离线内网（适合防摄像头偷传云端）"
          checked={draft.policy.allowWan}
          onChange={(v) => setPolicy({ allowWan: v })}
        />
        <ToggleRow
          label="禁止访问路由器管理后台（推荐隔离网开启）"
          desc="拦截该网段访问路由器的网页后台、SSH 与 SingCtl 面板，防止设备被入侵后提权"
          checked={draft.policy.blockRouterMgmt}
          onChange={(v) => setPolicy({ blockRouterMgmt: v })}
        />
        <ToggleRow
          label="禁止访问家里主网设备（电脑 / NAS）"
          desc="该网段无法主动探测或访问上级主网与个人电脑，仅保留正常上网能力"
          checked={draft.policy.blockUpstreamLan}
          onChange={(v) => setPolicy({ blockUpstreamLan: v })}
        />
        <ToggleRow
          label="允许主网设备单向控制此网"
          desc="允许主网手机/电脑主动访问此网段设备（例如从主力网控制扫地机），但反向被禁止"
          checked={draft.policy.allowFromMainLan}
          onChange={(v) => setPolicy({ allowFromMainLan: v })}
        />
        <ToggleRow
          label="支持跨网设备发现 (AirPlay / 米家 / mDNS)"
          desc="放行局域网 UDP 5353 组播发现，方便手机自动找到智能设备"
          checked={draft.policy.allowMdns}
          onChange={(v) => setPolicy({ allowMdns: v })}
        />
      </div>
    </div>
  );
};

export interface VlanPreviewSummaryCardProps {
  proMode: boolean;
  privacyMask: boolean;
  preview: VlanPreviewResult | null;
  previewLoading: boolean;
}

export const VlanPreviewSummaryCard: React.FC<VlanPreviewSummaryCardProps> = ({
  proMode,
  privacyMask,
  preview,
  previewLoading,
}) => {
  const { success, error } = useToast();
  const [copiedRoute, setCopiedRoute] = useState(false);

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
  );
};

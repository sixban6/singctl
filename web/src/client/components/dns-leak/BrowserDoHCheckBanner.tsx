import React, { useMemo, useState } from 'react';
import { Check, Copy, Monitor, RefreshCw } from 'lucide-react';
import { Badge, Button, useToast } from '../../../ui';
import { copyPlainText, detectBrowserDoHGuide } from '../../lib/leakProbes';
import { maskFullIP, redactInlineSensitive } from '../../../lib/privacyMask';
import { BrowserDoHCheckResponse } from '../../types';

export interface BrowserDoHCheckBannerProps {
  browserDoH: BrowserDoHCheckResponse | null;
  checkingDoH: boolean;
  running: boolean;
  hideIP: boolean;
  onRecheck: () => void;
}

export const BrowserDoHCheckBanner: React.FC<BrowserDoHCheckBannerProps> = ({
  browserDoH,
  checkingDoH,
  running,
  hideIP,
  onRecheck,
}) => {
  const { success, toast } = useToast();
  const [copiedGuideUrl, setCopiedGuideUrl] = useState(false);
  const dohGuide = useMemo(() => detectBrowserDoHGuide(), []);

  const handleCopyDoHGuideUrl = async () => {
    try {
      await copyPlainText(dohGuide.settingsUrl);
      setCopiedGuideUrl(true);
      success(`已复制 ${dohGuide.browserName} 安全 DNS 设置地址`);
      window.setTimeout(() => setCopiedGuideUrl(false), 2000);
    } catch {
      toast('复制失败，请手动复制设置页地址', 'warn');
    }
  };

  const dohRisk = browserDoH?.status === 'detected' || browserDoH?.status === 'suspected';
  const dohTone: 'ok' | 'warn' | 'danger' | 'neutral' =
    browserDoH?.status === 'detected'
      ? 'danger'
      : browserDoH?.status === 'suspected'
        ? 'warn'
        : browserDoH?.status === 'clean'
          ? 'ok'
          : 'neutral';
  const dohBadgeLabel = !browserDoH
    ? checkingDoH
      ? '检测中…'
      : '待检测'
    : browserDoH.status === 'detected'
      ? '检测到安全 DNS 绕过'
      : browserDoH.status === 'suspected'
        ? '疑似启用外部安全 DNS'
        : browserDoH.status === 'clean'
          ? '正常 · 走网关统一解析'
          : browserDoH.status === 'skipped_remote'
            ? browserDoH.viaTailscale
              ? '远程隧道访问已跳过'
              : '非局域网直连已跳过'
            : '暂不可用';

  return (
    <div
      className={`rounded-xl border px-3.5 py-2.5 text-xs space-y-2 ${
        browserDoH?.status === 'detected'
          ? 'border-rose-500/40 bg-rose-500/10 text-rose-100'
          : browserDoH?.status === 'suspected'
            ? 'border-amber-500/35 bg-amber-500/10 text-amber-100'
            : 'border-subtle bg-surface2/55 text-secondary'
      }`}
    >
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex flex-wrap items-center gap-2">
          <Monitor className="w-3.5 h-3.5 text-sky-400 shrink-0" />
          <span className="font-semibold text-primary">浏览器安全 DNS (DoH) 绕过检测</span>
          <Badge tone={dohTone}>{dohBadgeLabel}</Badge>
          {browserDoH?.detectedProvider && dohRisk && (
            <Badge tone="danger">{browserDoH.detectedProvider}</Badge>
          )}
        </div>
        <Button
          size="xs"
          variant="ghost"
          loading={checkingDoH}
          disabled={running}
          icon={<RefreshCw className="w-3 h-3" />}
          onClick={onRecheck}
        >
          {browserDoH ? '重新检测 DoH' : '检测浏览器 DoH'}
        </Button>
      </div>

      {browserDoH && (
        <div className="space-y-1.5 text-[11px] leading-relaxed">
          <div className="text-primary/90">{redactInlineSensitive(browserDoH.summary, hideIP)}</div>
          <div className="flex flex-wrap gap-x-4 gap-y-0.5 text-muted font-mono">
            {browserDoH.clientIp && <span>本机终端: {maskFullIP(browserDoH.clientIp, hideIP)}</span>}
            {browserDoH.gatewayResolver && (
              <span>
                网关解析:{' '}
                {hideIP
                  ? '•••••••• (已遮挡)'
                  : `${browserDoH.gatewayResolver.isp || '-'} (${browserDoH.gatewayResolver.ip || '-'})`}
              </span>
            )}
            {browserDoH.browserResolvers && browserDoH.browserResolvers.length > 0 && (
              <span>
                浏览器解析:{' '}
                {hideIP
                  ? '•••••••• (已遮挡)'
                  : browserDoH.browserResolvers
                      .map((r) => `${r.isp || '-'}${r.dnsIp ? ` (${r.dnsIp})` : ''}`)
                      .join(', ')}
              </span>
            )}
          </div>
          {browserDoH.signals && browserDoH.signals.length > 0 && (
            <ul className="list-disc pl-4 space-y-0.5 text-amber-200/90">
              {browserDoH.signals.map((sig, idx) => (
                <li key={idx}>{redactInlineSensitive(sig, hideIP)}</li>
              ))}
            </ul>
          )}
          {dohRisk && (
            <div className="rounded-lg border border-amber-400/30 bg-slate-950/60 px-3 py-2 flex flex-col sm:flex-row sm:items-center justify-between gap-2">
              <div className="space-y-0.5">
                <div className="font-semibold text-amber-200">
                  建议关闭 {dohGuide.browserName} 的安全 DNS (DoH)
                </div>
                <div className="text-slate-300">
                  {dohGuide.steps}（设置页：<code className="font-mono text-sky-300">{dohGuide.settingsUrl}</code>）
                </div>
              </div>
              <Button
                size="xs"
                variant="secondary"
                className="shrink-0"
                icon={copiedGuideUrl ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                onClick={() => void handleCopyDoHGuideUrl()}
              >
                {copiedGuideUrl ? '已复制地址' : '复制设置地址'}
              </Button>
            </div>
          )}
        </div>
      )}
    </div>
  );
};

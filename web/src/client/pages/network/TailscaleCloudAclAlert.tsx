import React, { useEffect, useRef, useState } from 'react';
import { Check, Copy, ExternalLink, ShieldAlert } from 'lucide-react';
import { Button } from '../../../ui';
import { copyToClipboard } from '../../../lib/clipboard';
import { maskFullIP } from '../../../lib/privacyMask';

export interface TailscaleCloudAclAlertProps {
  blockedCidrs: string[];
  privacyMask: boolean;
}

export const TailscaleCloudAclAlert: React.FC<TailscaleCloudAclAlertProps> = ({
  blockedCidrs,
  privacyMask,
}) => {
  const [copied, setCopied] = useState(false);
  const [copyErr, setCopyErr] = useState('');
  const timerRef = useRef<number | null>(null);

  useEffect(() => {
    return () => {
      if (timerRef.current !== null) {
        window.clearTimeout(timerRef.current);
      }
    };
  }, []);

  if (blockedCidrs.length === 0) {
    return null;
  }

  const rawSnippet = blockedCidrs.map((cidr) => `"${cidr}:*"`).join(',\n');
  const displaySnippet = privacyMask
    ? blockedCidrs.map(() => '"•••.•••.•••.•••/••:*"').join(',\n')
    : rawSnippet;

  const handleCopy = async () => {
    if (privacyMask) return;
    try {
      await copyToClipboard(rawSnippet);
      setCopyErr('');
      setCopied(true);
      if (timerRef.current !== null) {
        window.clearTimeout(timerRef.current);
      }
      timerRef.current = window.setTimeout(() => setCopied(false), 2000);
    } catch {
      setCopyErr('复制失败，请手动选中下方片段');
    }
  };

  return (
    <div
      role="alert"
      className="p-3 rounded-xl border border-rose-500/40 bg-rose-500/10 text-[11px] text-rose-100 space-y-2 leading-relaxed"
    >
      <div className="flex items-start gap-2">
        <ShieldAlert className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
        <div className="min-w-0 space-y-1">
          <div className="font-semibold text-rose-200">
            云端 ACL 未放行已启用网段（远端访问将被拦截）
          </div>
          <p className="text-rose-200/85">
            以下网段已通告并获批（
            <span className="font-mono text-rose-100">
              {blockedCidrs.map((c) => maskFullIP(c, privacyMask)).join('、')}
            </span>
            ），但 Tailscale 云端 Access Controls (ACL) 策略的{' '}
            <code className="px-1 py-0.5 rounded bg-black/30 font-mono text-[10.5px]">dst</code>{' '}
            中未包含它们，远端设备访问将被 tailscaled 直接丢弃 (no rules matched)。
          </p>
        </div>
      </div>

      <div className="pl-6 space-y-1.5">
        <div className="flex items-center justify-between gap-2 flex-wrap">
          <span className="text-[10.5px] text-rose-200/80">
            可复制下方规则添加到 ACL 策略的{' '}
            <code className="font-mono text-rose-100">dst</code> 数组：
          </span>
          <Button
            type="button"
            size="xs"
            variant="secondary"
            disabled={privacyMask}
            onClick={() => void handleCopy()}
            title={privacyMask ? '请先关闭隐私遮挡再复制' : '复制 ACL dst 放行片段'}
            icon={copied ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
          >
            {copied ? '已复制' : '一键复制'}
          </Button>
        </div>

        <pre className="p-2 rounded-lg bg-black/35 border border-rose-500/25 font-mono text-[11px] text-rose-100 overflow-x-auto select-all">
          {displaySnippet}
        </pre>

        {copyErr && <div className="text-[10.5px] text-amber-300">{copyErr}</div>}

        <div className="flex flex-wrap items-center gap-x-2 gap-y-1 text-[10.5px] text-rose-200/80">
          <span>
            前往 Tailscale Admin → Access Controls 加入对应规则的 dst 列表并 Save，随后点击本页「刷新」即可消除告警。
          </span>
          <a
            href="https://login.tailscale.com/admin/acls"
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-1 text-rose-200 hover:text-white underline underline-offset-2 font-medium"
          >
            <span>打开 Access Controls</span>
            <ExternalLink className="w-3 h-3" />
          </a>
        </div>
      </div>
    </div>
  );
};

import React from 'react';
import {
  AlertTriangle,
  CheckCircle2,
  Copy,
  ExternalLink,
  RefreshCw,
  ShieldCheck,
  XCircle,
} from 'lucide-react';
import { Badge, Button, SlideDrawer, useToast } from '../../../../ui';
import { maskFullIP } from '../../../../lib/privacyMask';
import { copyPlainText } from '../../../lib/leakProbes';
import { HomeDomainOverviewResponse, HomeDomainVerifyReport } from '../../../types';

export interface SplitDNSGuideDrawerProps {
  open: boolean;
  data: HomeDomainOverviewResponse | null;
  privacyMask: boolean;
  verifying: boolean;
  verifyReport: HomeDomainVerifyReport | null;
  onClose: () => void;
  onRunVerify: () => void;
}

export const SplitDNSGuideDrawer: React.FC<SplitDNSGuideDrawerProps> = ({
  open,
  data,
  privacyMask,
  verifying,
  verifyReport,
  onClose,
  onRunVerify,
}) => {
  const { success, toast } = useToast();
  const guide = data?.splitDnsGuide;
  const nsIP = guide?.nameserverIp || '';
  const suffix = guide?.domain || data?.suffix || 'home';

  const handleCopy = async (label: string, val: string) => {
    if (!val) return;
    try {
      await copyPlainText(val);
      success(`已复制 ${label}`);
    } catch {
      toast('复制失败，请手动选中复制', 'warn');
    }
  };

  return (
    <SlideDrawer
      open={open}
      onClose={onClose}
      size="lg"
      title="Tailscale Split-DNS 15 秒接入向导"
      subtitle="在 Tailscale 网页后台配置 1 次即可终身有效：后续在 SingCtl 任意增删设备，手机/电脑在外地全部自动生效"
      footer={
        <div className="flex flex-wrap items-center justify-between gap-2 w-full">
          <Button
            size="sm"
            variant="secondary"
            loading={verifying}
            icon={<RefreshCw className="w-3.5 h-3.5" />}
            onClick={onRunVerify}
          >
            立即执行四项端到端自检
          </Button>
          <Button size="sm" variant="primary" onClick={onClose}>
            我明白了
          </Button>
        </div>
      }
    >
      <div className="space-y-4 text-xs">
        <div className="rounded-xl border border-emerald-500/25 bg-emerald-500/10 p-3.5 space-y-1.5 text-emerald-100">
          <div className="font-semibold flex items-center gap-1.5">
            <ShieldCheck className="w-4 h-4 text-emerald-400" />
            <span>原理简述：为什么外网咖啡馆也能解析 .{suffix}？</span>
          </div>
          <p className="leading-relaxed opacity-90">
            你在外面使用 5G 或咖啡馆 Wi-Fi 时，手机默认向运营商 DNS 查询。设置 Split-DNS 后，Tailscale 只会把{' '}
            <code className="font-mono text-emerald-300">*.{suffix}</code> 查询通过加密隧道发给家里这台路由器（
            <code className="font-mono text-emerald-300">{nsIP ? `${maskFullIP(nsIP, privacyMask)}:53` : 'Tailscale IP:53'}</code>
            ），其余所有公网访问保持原样不受影响；SingCtl 内置应答器仅放行 Tailscale 虚拟网段且零公网递归，无任何暴露风险。
          </p>
        </div>

        <div className="rounded-xl border border-subtle bg-surface2/50 p-4 space-y-3">
          <div className="flex items-center justify-between gap-2">
            <span className="font-semibold text-sm text-primary">一次性配置步骤（约 15 秒）</span>
            <a
              href={guide?.adminDnsUrl || 'https://login.tailscale.com/admin/dns'}
              target="_blank"
              rel="noreferrer"
              className="inline-flex items-center gap-1 text-sky-400 hover:text-sky-300 font-medium"
            >
              <span>打开 Tailscale DNS 后台</span>
              <ExternalLink className="w-3.5 h-3.5" />
            </a>
          </div>

          <ol className="space-y-2.5 text-secondary list-decimal list-inside leading-relaxed">
            <li>
              登录 <strong className="text-primary">Tailscale Admin Console → DNS → Nameservers</strong>，点击{' '}
              <code className="font-mono text-primary">Add nameserver → Custom...</code>
            </li>
            <li>
              在 <strong className="text-primary">Nameserver</strong> 输入框填入本路由器的 Tailscale 专属 IP：
              <div className="mt-1.5 flex items-center gap-2 pl-4">
                <code className="flex-1 px-3 py-1.5 rounded-lg bg-surface1 border border-subtle font-mono text-sky-300">
                  {nsIP ? maskFullIP(nsIP, privacyMask) : '（未检测到 Tailscale IP，请先启动 Tailscale 组网）'}
                </code>
                {nsIP && !privacyMask && (
                  <Button
                    size="xs"
                    variant="secondary"
                    icon={<Copy className="w-3 h-3" />}
                    onClick={() => void handleCopy('Tailscale Nameserver IP', nsIP)}
                  >
                    复制 IP
                  </Button>
                )}
              </div>
            </li>
            <li>
              打开下方的 <strong className="text-primary">Restrict to domain (Split DNS)</strong> 开关，并在{' '}
              <strong className="text-primary">Domain</strong> 框填入：
              <div className="mt-1.5 flex items-center gap-2 pl-4">
                <code className="flex-1 px-3 py-1.5 rounded-lg bg-surface1 border border-subtle font-mono text-emerald-300">
                  {suffix}
                </code>
                <Button
                  size="xs"
                  variant="secondary"
                  icon={<Copy className="w-3 h-3" />}
                  onClick={() => void handleCopy('Split-DNS 后缀', suffix)}
                >
                  复制后缀
                </Button>
              </div>
            </li>
            <li>
              点击 <strong className="text-primary">Save</strong> 保存即可！无需保存高权限 API Key、永不过期。
            </li>
          </ol>
        </div>

        <div className="rounded-xl border border-subtle bg-surface2/40 p-4 space-y-3">
          <div className="flex items-center justify-between gap-2">
            <div className="font-semibold text-sm text-primary">四项端到端实测体检</div>
            {verifyReport && (
              <Badge tone={verifyReport.overallOk ? 'ok' : 'warn'}>
                {verifyReport.overallOk ? '核心链路全部正常' : '发现待处理项'}
              </Badge>
            )}
          </div>

          {!verifyReport ? (
            <div className="text-muted py-3 text-center">
              点击左下角「立即执行四项端到端自检」，同步实测本地防劫持 DNS、OpenWrt Rebind 放行、Tailscale :53 应答器与外网可达性
            </div>
          ) : (
            <div className="space-y-2">
              {verifyReport.checks.map((c) => {
                const Icon =
                  c.status === 'pass'
                    ? CheckCircle2
                    : c.status === 'warn'
                      ? AlertTriangle
                      : XCircle;
                const toneClass =
                  c.status === 'pass'
                    ? 'text-emerald-400 border-emerald-500/25 bg-emerald-500/10'
                    : c.status === 'warn'
                      ? 'text-amber-300 border-amber-500/25 bg-amber-500/10'
                      : 'text-rose-300 border-rose-500/30 bg-rose-500/10';
                return (
                  <div key={c.id} className={`rounded-xl border p-3 space-y-1 ${toneClass}`}>
                    <div className="flex items-center justify-between gap-2">
                      <div className="font-semibold flex items-center gap-1.5">
                        <Icon className="w-4 h-4 shrink-0" />
                        <span>{c.title}</span>
                      </div>
                      {typeof c.rttMs === 'number' && c.rttMs >= 0 && c.status === 'pass' && (
                        <span className="font-mono text-[11px] opacity-85">{c.rttMs} ms</span>
                      )}
                    </div>
                    <div className="text-[11px] opacity-90 font-mono break-all">
                      {privacyMask ? c.detail.replace(/\b\d{1,3}(?:\.\d{1,3}){3}\b/g, '•••.•••.•••.•••') : c.detail}
                    </div>
                    {c.fixHint && (
                      <div className="text-[11px] opacity-85 pt-0.5">建议：{c.fixHint}</div>
                    )}
                  </div>
                );
              })}
            </div>
          )}
        </div>
      </div>
    </SlideDrawer>
  );
};

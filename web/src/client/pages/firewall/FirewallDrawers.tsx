import React, { useState } from 'react';
import { Check, Copy, RefreshCw } from 'lucide-react';
import { Badge, Button, SlideDrawer, useToast } from '../../../ui';
import { copyPlainText } from '../../lib/leakProbes';
import { FirewallLogEvent, FirewallOverviewResponse } from '../../types';
import { maskDisplayIP } from './firewallHelpers';

export const FirewallLogsDrawer: React.FC<{
  open: boolean;
  logs: FirewallLogEvent[];
  logsLoading: boolean;
  privacyMask: boolean;
  onClose: () => void;
  onReload: () => void;
}> = ({ open, logs, logsLoading, privacyMask, onClose, onReload }) => (
  <SlideDrawer
    open={open}
    onClose={onClose}
    size="md"
    title="实时防火墙拦截日志 ([NFT])"
    subtitle="已自动剥离本机公网入口 IP（DST），仅展示攻击来源、入站接口与目标端口"
    footer={
      <div className="flex items-center justify-between gap-2">
        <span className="text-[11px] text-muted">最近最多展示 50 条内核拦截记录</span>
        <Button
          size="sm"
          variant="secondary"
          loading={logsLoading}
          icon={<RefreshCw className="w-3.5 h-3.5" />}
          onClick={onReload}
        >
          刷新日志
        </Button>
      </div>
    }
  >
    {logsLoading ? (
      <div className="py-12 text-center text-xs text-muted">正在读取内核日志…</div>
    ) : logs.length === 0 ? (
      <div className="py-12 text-center text-xs text-muted">
        近期系统日志缓冲区暂无 <code className="font-mono">[NFT]</code> 拦截事件。
      </div>
    ) : (
      <div className="space-y-2">
        {logs.map((ev, idx) => (
          <div
            key={`${ev.time}-${ev.srcIp}-${idx}`}
            className="rounded-xl border border-subtle bg-surface2/60 p-3 text-xs space-y-1.5"
          >
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div className="flex items-center gap-2">
                <Badge tone={ev.category.includes('永久') ? 'danger' : ev.category.includes('诱捕') ? 'warn' : 'accent'}>
                  {ev.category}
                </Badge>
                <span className="font-mono font-semibold text-primary">
                  {maskDisplayIP(ev.srcIp, privacyMask)}
                </span>
              </div>
              <span className="font-mono text-[10.5px] text-muted">{ev.time || '—'}</span>
            </div>
            <div className="flex flex-wrap items-center gap-3 text-[11px] font-mono text-secondary">
              {ev.iface && <span>接口: {ev.iface}</span>}
              {ev.proto && <span>协议: {ev.proto}</span>}
              {ev.dstPort ? <span>探测端口: :{ev.dstPort}</span> : null}
            </div>
          </div>
        ))}
      </div>
    )}
  </SlideDrawer>
);

export const FirewallRulesDrawer: React.FC<{
  open: boolean;
  overview: FirewallOverviewResponse | null;
  onClose: () => void;
}> = ({ open, overview, onClose }) => {
  const { toast, error } = useToast();
  const [copiedRules, setCopiedRules] = useState(false);

  return (
    <SlideDrawer
      open={open}
      onClose={onClose}
      size="lg"
      title="内核 nftables 规则透视 (table inet security)"
      subtitle="长动态集合已自动折叠摘要，避免浏览器渲染卡顿"
      footer={
        <div className="flex items-center justify-between gap-2">
          <span className="text-[11px] text-muted">
            共存内核表：{overview?.preflight?.coexistingTables?.join(' · ') || 'inet security'}
          </span>
          <Button
            size="sm"
            variant="secondary"
            icon={copiedRules ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
            onClick={async () => {
              if (!overview?.compactRuleText) return;
              try {
                await copyPlainText(overview.compactRuleText);
                setCopiedRules(true);
                toast('已复制规则骨架文本', 'success');
                window.setTimeout(() => setCopiedRules(false), 1800);
              } catch {
                error('当前浏览器不支持自动复制');
              }
            }}
          >
            {copiedRules ? '已复制' : '复制规则骨架'}
          </Button>
        </div>
      }
    >
      <div className="space-y-4">
        <div className="rounded-xl border border-subtle bg-surface2/60 p-3.5 text-xs text-secondary leading-relaxed space-y-1.5">
          <div className="font-semibold text-primary">多表隔离协作架构（零冲突、卸载零残留）</div>
          <p>
            • <code className="font-mono text-primary">inet fw4</code>：OpenWrt 基础区域转发与 LAN/WAN 路由控制；
          </p>
          <p>
            • <code className="font-mono text-primary">inet sing-box</code>：透明代理分流（TProxy 劫持）；
          </p>
          <p>
            • <code className="font-mono text-primary">inet singctl_audit_throttle</code>：特定 IoT/流目标的不断网速率封顶；
          </p>
          <p>
            • <code className="font-mono text-emerald-300">inet security</code>：本页面托管的公网入口防扫描护盾，停用时整表销毁，不影响上述任何业务表。
          </p>
        </div>

        <pre className="p-3.5 rounded-xl bg-[#070a10] border border-subtle text-[11px] font-mono text-slate-300 overflow-x-auto max-h-[55vh] whitespace-pre-wrap break-all leading-relaxed">
          {overview?.compactRuleText || '当前内核未加载 table inet security'}
        </pre>
      </div>
    </SlideDrawer>
  );
};

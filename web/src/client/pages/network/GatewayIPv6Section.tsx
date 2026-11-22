import React, { useState } from 'react';
import { AlertTriangle, Check, Copy, Network, Save, Smartphone } from 'lucide-react';
import { Badge, Button, SectionCard, useToast } from '../../../ui';
import { copyPlainText } from '../../lib/leakProbes';
import { maskFullIP, redactInlineSensitive } from '../../lib/privacyMask';
import { GatewayIPv6Mode, GatewayRoleMode, IPv6StatusInfo } from '../../types';

const SECONDARY_ROUTER_IPV6_CMD = `cp -a /etc/config/dhcp /etc/config/dhcp.bak && chmod 600 /etc/config/dhcp.bak && \\
uci set dhcp.@dnsmasq[0].dnsforwardmax=1024 && \\
for s in $(uci show dhcp | sed -n 's/^dhcp\\.\\([^.=]*\\)=dhcp$/\\1/p'); do
  [ "$s" = "wan" ] || [ "$s" = "wan6" ] && continue
  uci set "dhcp.$s.ra_dns=0"
  uci set "dhcp.$s.dns_service=0"
done && \\
uci commit dhcp && /etc/init.d/odhcpd reload && /etc/init.d/dnsmasq reload`;

export interface GatewayIPv6SectionProps {
  mode: GatewayRoleMode | null;
  v6Status?: IPv6StatusInfo;
  effectiveDisplayIPv6Mode: GatewayIPv6Mode | null;
  ipv6Saving: boolean;
  busy: boolean;
  isSelfLoop: boolean;
  privacyMask: boolean;
  onSelectIPv6Mode: (next: GatewayIPv6Mode) => void;
  onSaveIPv6: () => void;
}

export const GatewayIPv6Section: React.FC<GatewayIPv6SectionProps> = ({
  mode,
  v6Status,
  effectiveDisplayIPv6Mode,
  ipv6Saving,
  busy,
  isSelfLoop,
  privacyMask,
  onSelectIPv6Mode,
  onSaveIPv6,
}) => {
  const { success, error } = useToast();
  const [copiedSubCmd, setCopiedSubCmd] = useState(false);

  const handleCopySubRouterCmd = async () => {
    try {
      await copyPlainText(SECONDARY_ROUTER_IPV6_CMD);
      setCopiedSubCmd(true);
      success('已复制二级路由一键加固命令');
      window.setTimeout(() => setCopiedSubCmd(false), 2000);
    } catch {
      error('复制失败，请手动选中下方命令复制');
    }
  };

  return (
    <SectionCard
      title="IPv6 智能双栈分流 (自动探测与配置)"
      icon={<Network className="w-4 h-4" />}
      subtitle="主路由开启时自动探测 WAN 前缀，一键托管 OpenWrt RA/DHCPv6、dnsmasq 放行与本地防 DNS 泄漏策略"
      actions={
        <Badge
          tone={
            effectiveDisplayIPv6Mode === null
              ? 'neutral'
              : effectiveDisplayIPv6Mode === 'off'
                ? 'neutral'
                : effectiveDisplayIPv6Mode === 'cn_only'
                  ? 'ok'
                  : 'accent'
          }
        >
          {effectiveDisplayIPv6Mode === null
            ? '读取策略中…'
            : effectiveDisplayIPv6Mode === 'cn_only'
              ? '当前：智能双栈 (推荐)'
              : effectiveDisplayIPv6Mode === 'full'
                ? '当前：全量双栈'
                : '当前：纯 IPv4'}
        </Badge>
      }
    >
      <div className="space-y-4">
        {v6Status && (
          <div className="rounded-xl border border-subtle bg-surface2/60 px-3.5 py-2.5 flex flex-wrap items-center gap-x-4 gap-y-1.5 text-xs">
            <div className="flex items-center gap-1.5">
              <span className="text-muted">WAN IPv6:</span>
              <Badge tone={v6Status.wanHasGua ? 'ok' : 'warn'}>
                {v6Status.wanHasGua
                  ? v6Status.pdPrefix
                    ? `已获公网 + PD ${maskFullIP(v6Status.pdPrefix, privacyMask)}`
                    : '已获公网地址'
                  : '未检测到公网 IPv6'}
              </Badge>
            </div>
            <div className="flex items-center gap-1.5">
              <span className="text-muted">LAN 前缀与 RA:</span>
              <span className="font-mono text-primary">
                {v6Status.lanPrefixes && v6Status.lanPrefixes.length > 0
                  ? privacyMask
                    ? '•••••••• (已遮挡)'
                    : v6Status.lanPrefixes.join(', ')
                  : '未分配'}
              </span>
              {v6Status.isOpenWrt && (
                <span className="text-[11px] text-secondary">
                  (RA={v6Status.lanRaMode || 'off'}, DHCPv6={v6Status.lanDhcpv6Mode || 'off'})
                </span>
              )}
            </div>
            {v6Status.isOpenWrt && (
              <>
                <div className="flex items-center gap-1.5">
                  <span className="text-muted">dnsmasq AAAA:</span>
                  <span className="font-mono text-primary">
                    {v6Status.dnsmasqFilterAaaa === '1' ? '过滤关闭' : '正常解析'}
                  </span>
                </div>
                <div className="flex items-center gap-1.5">
                  <span className="text-muted">IPv6 DNS 通告:</span>
                  <Badge tone={v6Status.raDnsAnnounce ? 'warn' : 'ok'}>
                    {v6Status.raDnsAnnounce ? '仍在通告' : '已关闭(仅 IPv4 DNS)'}
                  </Badge>
                </div>
                <div className="flex items-center gap-1.5">
                  <span className="text-muted">并发上限:</span>
                  <span className="font-mono text-primary">
                    {v6Status.dnsmasqForwardMax || '默认(150)'}
                  </span>
                </div>
              </>
            )}
          </div>
        )}

        {v6Status?.warnings && v6Status.warnings.length > 0 && (
          <div className="rounded-xl border border-amber-500/35 bg-amber-500/10 px-3.5 py-2.5 text-xs text-amber-200 space-y-1">
            {v6Status.warnings.map((w, idx) => (
              <div key={idx} className="flex items-start gap-2">
                <AlertTriangle className="w-3.5 h-3.5 text-amber-400 shrink-0 mt-0.5" />
                <span>{redactInlineSensitive(w, privacyMask)}</span>
              </div>
            ))}
          </div>
        )}

        <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
          {[
            {
              key: 'off' as GatewayIPv6Mode,
              title: '关闭 (仅 IPv4)',
              tag: '默认兼容',
              desc: '屏蔽并还原 AAAA 解析（ipv4_only），最稳妥但局域网设备不使用宽带 IPv6。',
              disabled: false,
            },
            {
              key: 'cn_only' as GatewayIPv6Mode,
              title: '智能双栈 (国内 IPv6 + 海外 IPv4)',
              tag: '黄金推荐',
              desc: '国内直连与 PT 原生 IPv6+IPv4；海外域名 0ms 静音海外 AAAA/HTTPS、拦截 DoT/国内 DoH 与代理侧 ::/0，彻底免去节点无 IPv6 导致的卡顿/弹盾与泄漏。',
              disabled: mode === 'side',
            },
            {
              key: 'full' as GatewayIPv6Mode,
              title: '全量双栈 (国内外全部 IPv6)',
              tag: '节点需双栈',
              desc: '国内外域名均保留 A+AAAA 双栈解析。仅建议在自建/机场主力节点全部具备优质 IPv6 出站时启用。',
              disabled: mode === 'side',
            },
          ].map((opt) => {
            const selected = effectiveDisplayIPv6Mode !== null && effectiveDisplayIPv6Mode === opt.key;
            return (
              <button
                key={opt.key}
                type="button"
                disabled={opt.disabled || effectiveDisplayIPv6Mode === null}
                onClick={() => onSelectIPv6Mode(opt.key)}
                style={
                  selected
                    ? {
                        backgroundColor: 'var(--accent-soft)',
                        borderColor: 'var(--accent)',
                      }
                    : undefined
                }
                className={`p-3.5 rounded-xl border text-left transition-all ${
                  opt.disabled || effectiveDisplayIPv6Mode === null
                    ? 'opacity-45 cursor-not-allowed bg-surface2 border-subtle'
                    : selected
                      ? 'cursor-pointer'
                      : 'bg-surface2 border-subtle hover:border-strong cursor-pointer'
                }`}
              >
                <div className="flex items-center justify-between gap-2">
                  <span className="text-xs sm:text-sm font-semibold text-primary">{opt.title}</span>
                  <span className="text-[10px] px-1.5 py-0.5 rounded bg-surface1 text-secondary border border-subtle shrink-0">
                    {opt.tag}
                  </span>
                </div>
                <p className="text-[11px] text-secondary mt-1.5 leading-relaxed">{opt.desc}</p>
              </button>
            );
          })}
        </div>

        {mode !== 'side' && effectiveDisplayIPv6Mode && effectiveDisplayIPv6Mode !== 'off' && (
          <div className="rounded-xl border border-sky-500/35 bg-sky-500/10 px-3.5 py-3 space-y-2 text-xs text-sky-100">
            <div className="flex items-center gap-2 font-semibold text-sky-200">
              <Smartphone className="w-4 h-4 text-sky-400 shrink-0" />
              <span>开启 IPv6 必看：如何彻底关闭手机端 5G 蜂窝兜底泄漏</span>
            </div>
            <p className="text-[11px] text-sky-100/90 leading-relaxed">
              当路由器对海外 AAAA/HTTPS 做静音（或遭遇高并发 DNS 探测）时，手机若开启 Wi-Fi/蜂窝智能切网且同时开着 5G 数据，系统会误判 Wi-Fi 无 IPv6 而直接经 5G 基站发出运营商 IPv6 DNS 查询，绕过家用路由器：
            </p>
            <ul className="space-y-1 text-[11px] text-sky-100/90 list-disc pl-4 leading-relaxed">
              <li>
                <span className="font-semibold text-white">iPhone (iOS)</span>：打开{' '}
                <code className="px-1 py-0.5 rounded bg-sky-950/60 border border-sky-400/20">设置 → 无线局域网 (WLAN)</code>{' '}
                关闭 <span className="font-semibold text-white">「连接助理」</span>（部分系统版本位于{' '}
                <code className="px-1 py-0.5 rounded bg-sky-950/60 border border-sky-400/20">设置 → 蜂窝网络 → 展开全部应用 → 拉至最底端</code>{' '}
                关闭 <span className="font-semibold text-white">「无线局域网助理」</span>）。
              </li>
              <li>
                <span className="font-semibold text-white">华为 / 鸿蒙</span>：打开{' '}
                <code className="px-1 py-0.5 rounded bg-sky-950/60 border border-sky-400/20">设置 → WLAN → 更多 WLAN 设置</code>{' '}
                关闭 <span className="font-semibold text-white">「WLAN+」</span> 与{' '}
                <span className="font-semibold text-white">「网络加速 / 双通道加速」</span>。
              </li>
              <li>
                <span className="font-semibold text-white">小米 / OPPO / vivo / 三星等安卓</span>：打开{' '}
                <code className="px-1 py-0.5 rounded bg-sky-950/60 border border-sky-400/20">设置 → WLAN → WLAN 助理 / 智能选网</code>{' '}
                关闭 <span className="font-semibold text-white">「自动切换移动数据」</span> 与{' '}
                <span className="font-semibold text-white">「双通道加速」</span>。
              </li>
              <li>
                <span className="font-semibold text-white">多级路由 &amp; 生效步骤</span>：若前端还接有二级无线路由器，请同步将其{' '}
                <code className="px-1 py-0.5 rounded bg-sky-950/60 border border-sky-400/20">dnsforwardmax</code> 调至{' '}
                <code className="px-1 py-0.5 rounded bg-sky-950/60 border border-sky-400/20">1024</code> 并关闭 IPv6 RDNSS（
                <code className="px-1 py-0.5 rounded bg-sky-950/60 border border-sky-400/20">ra_dns=0</code> /{' '}
                <code className="px-1 py-0.5 rounded bg-sky-950/60 border border-sky-400/20">dns_service=0</code>）；保存后请
                <span className="font-semibold text-white">断开并重连一次 Wi-Fi</span> 刷新租约后再复测。
              </li>
            </ul>
            <div className="rounded-lg border border-sky-400/20 bg-slate-950/75 p-2.5 space-y-1.5">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <span className="text-[11px] font-medium text-sky-200/95">
                  二级 OpenWrt / ImmortalWrt 无线路由一键加固命令（SSH 登录二级路由后直接粘贴执行）
                </span>
                <button
                  type="button"
                  onClick={() => void handleCopySubRouterCmd()}
                  className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md border border-sky-400/30 bg-sky-500/15 hover:bg-sky-500/25 text-[11px] text-sky-100 transition-colors cursor-pointer"
                >
                  {copiedSubCmd ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                  <span>{copiedSubCmd ? '已复制' : '复制命令'}</span>
                </button>
              </div>
              <pre className="overflow-x-auto text-[11px] font-mono text-sky-100/95 leading-relaxed select-all whitespace-pre">
                {SECONDARY_ROUTER_IPV6_CMD}
              </pre>
            </div>
          </div>
        )}

        <div className="flex flex-wrap items-center justify-between gap-3 pt-2 border-t border-subtle">
          <span className="text-[11px] text-muted">
            {mode === 'side'
              ? '当前选择旁路由模式：为避免主路由 RA 绕过旁路由造成泄漏，IPv6 自动保持关闭。'
              : '保存后自动同步 OpenWrt RA/DHCPv6、dnsmasq 与 sing-box 规则并零断网热重载（切回关闭会自动按备份还原）。'}
          </span>
          <Button
            variant="primary"
            loading={ipv6Saving}
            disabled={busy || !mode || effectiveDisplayIPv6Mode === null || isSelfLoop || privacyMask}
            title={privacyMask ? '隐私完全遮挡开启期间已锁定修改' : undefined}
            icon={<Save className="w-3.5 h-3.5" />}
            onClick={onSaveIPv6}
          >
            保存并自动配置 IPv6
          </Button>
        </div>
      </div>
    </SectionCard>
  );
};

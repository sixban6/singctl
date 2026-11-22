import React from 'react';
import { AlertTriangle, Download, ShieldCheck } from 'lucide-react';
import { Button, PageHeader, SectionCard } from '../../../ui';

export interface AdGuardUninstalledViewProps {
  supported: boolean;
  busy: boolean;
  headerBadge: React.ReactNode;
  lowMemoryBlocked?: boolean;
  lowMemoryWarning?: string;
  onInstall: () => void;
  onForceInstall?: () => void;
}

export const AdGuardUninstalledView: React.FC<AdGuardUninstalledViewProps> = ({
  supported,
  busy,
  headerBadge,
  lowMemoryBlocked,
  lowMemoryWarning,
  onInstall,
  onForceInstall,
}) => (
  <div className="space-y-5">
    <PageHeader
      title="防劫持 DNS (AdGuard Home)"
      description="本地 127.0.0.1:5353 回环托管 + 纯 IP 加密 DoH 上游，彻底根除宽带运营商明文 DNS 抢答劫持"
      badge={headerBadge}
    />

    {lowMemoryBlocked && lowMemoryWarning && (
      <div
        className="console-card rounded-2xl p-4 flex flex-col gap-3 border animate-sc-in"
        style={{
          borderColor: 'var(--status-warn)',
          backgroundColor: 'var(--status-warn-soft)',
        }}
      >
        <div className="flex items-start gap-2.5 min-w-0">
          <AlertTriangle
            className="w-5 h-5 shrink-0 mt-0.5"
            style={{ color: 'var(--status-warn)' }}
          />
          <div className="text-xs sm:text-sm space-y-1">
            <div className="font-semibold text-primary">
              小内存路由器防 OOM 保护已启用（推荐零额外内存内置加密 DNS）
            </div>
            <div className="text-secondary leading-relaxed">{lowMemoryWarning}</div>
          </div>
        </div>
        {onForceInstall && (
          <div className="flex justify-end">
            <Button
              size="xs"
              variant="ghost"
              disabled={busy || !supported}
              onClick={onForceInstall}
            >
              已知晓 OOM 风险，仍强制安装
            </Button>
          </div>
        )}
      </div>
    )}

    <SectionCard
      title="为什么建议在网关客户端启用本地 AdGuard Home？"
      icon={<ShieldCheck className="w-4 h-4" />}
      subtitle="安装过程全自动免向导，先验证解析就绪再热切换 sing-box，全程零断网"
    >
      <div className="space-y-5">
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
          {[
            {
              title: '纯 IP 加密 DoH 防运营商抢答',
              desc: '接管 sing-box 国内分流与代理节点引导解析，并发查询阿里/腾讯纯 IP DoH/DoT，杜绝 UDP 53 污染。',
            },
            {
              title: '回环隔离不抢 53 端口',
              desc: '仅绑定 127.0.0.1:5353 供本机内核调用，不与 OpenWrt dnsmasq 或系统 DHCP 主机名解析冲突。',
            },
            {
              title: '控制台一体化免记密码',
              desc: '直接在当前页面一键临时暂停去广告、放行误拦域名、配置内网 NAS 域名映射，免登第二套后台。',
            },
            {
              title: '软路由闪存保护 + 永不断网联动',
              desc: 'OpenWrt 自动关闭查询日志落盘保护闪存；启停、卸载或异常时自动原子回退内置加密 DNS，全屋不断网。',
            },
          ].map((item) => (
            <div
              key={item.title}
              className="p-3.5 rounded-xl bg-surface2 border border-subtle space-y-1"
            >
              <div className="text-xs sm:text-sm font-semibold text-primary">{item.title}</div>
              <div className="text-[11px] sm:text-xs text-secondary leading-relaxed">
                {item.desc}
              </div>
            </div>
          ))}
        </div>

        <div className="flex flex-wrap items-center gap-3 pt-2 border-t border-subtle">
          <Button
            variant="primary"
            disabled={busy || !supported || Boolean(lowMemoryBlocked)}
            icon={<Download className="w-4 h-4" />}
            onClick={onInstall}
          >
            {lowMemoryBlocked ? '已启用内置 DoH + geosite-ad1 保护' : '一键安装并无感接管 DNS'}
          </Button>
          {!supported && (
            <span className="text-xs text-muted">
              当前操作系统暂不支持托管，请在 Linux / OpenWrt 客户端网关上使用。
            </span>
          )}
        </div>
      </div>
    </SectionCard>
  </div>
);

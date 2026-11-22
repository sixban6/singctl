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
      title="防劫持 DNS"
      description="支持 sing-box 加强版 / SmartDNS / AdGuard Home 三引擎纯 IP 加密 DoH 防运营商明文抢答劫持"
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
              小内存路由器防 OOM 保护已启用（推荐零额外内存 sing-box 加强版内置加密 DNS）
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
      title="三引擎防劫持 DNS 工作台"
      icon={<ShieldCheck className="w-4 h-4" />}
      subtitle="安装与切换过程全自动免向导，先验证加密解析就绪再热切换 sing-box，全程零断网"
    >
      <div className="space-y-5">
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
          {[
            {
              title: '纯 IP 加密 DoH / DoT 防运营商抢答',
              desc: '接管 sing-box 国内分流与代理节点引导解析，并发查询阿里/腾讯纯 IP 加密上游，杜绝 UDP 53 污染。',
            },
            {
              title: '按硬件自动选型 · 三引擎无缝热切换',
              desc: '大内存可选 AdGuard Home，中小闪存推荐 SmartDNS，极限小内存零开销运行 sing-box 加强版。',
            },
            {
              title: '控制台一体化管理',
              desc: '直接在当前页面一键临时暂停去广告、屏蔽 AAAA、放行误拦域名、配置内网 NAS 域名映射。',
            },
            {
              title: '软路由闪存保护 + 永不断网联动',
              desc: 'OpenWrt 全程零查询日志落盘保护闪存；启停、卸载或异常时自动原子回退内置加密 DNS，全屋不断网。',
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
            {lowMemoryBlocked ? '已启用内置加密 DoH 保护' : '一键安装推荐防劫持引擎'}
          </Button>
          {!supported && (
            <span className="text-xs text-muted">
              当前操作系统暂不支持外部引擎托管，请在 Linux / OpenWrt 客户端网关上使用。
            </span>
          )}
        </div>
      </div>
    </SectionCard>
  </div>
);

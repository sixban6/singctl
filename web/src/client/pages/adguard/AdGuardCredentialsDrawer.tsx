import React, { useState } from 'react';
import { Copy, Download, ExternalLink, Eye, EyeOff, Power, RotateCw } from 'lucide-react';
import { Button, SectionCard, SlideDrawer, useToast } from '../../../ui';
import { AdGuardCredentialsResponse, AdGuardOverviewSnapshot } from '../../types';

export const AdGuardLifecycleSection: React.FC<{
  dnsHealthy: boolean;
  busy: boolean;
  onAction: (name: string, params?: Record<string, unknown>, confirmMsg?: string) => void;
}> = ({ dnsHealthy, busy, onAction }) => (
  <SectionCard
    title="服务生命周期与安全切换"
    subtitle="停用或卸载时会自动先将 sing-box dns_local 平滑切回内置纯 IP 加密 DoH，确保全屋网关零断网"
  >
    <div className="flex flex-wrap items-center gap-2.5">
      {dnsHealthy ? (
        <>
          <Button
            size="sm"
            variant="secondary"
            disabled={busy}
            icon={<RotateCw className="w-3.5 h-3.5" />}
            onClick={() => onAction('dns-restart')}
          >
            重启服务
          </Button>
          <Button
            size="sm"
            variant="secondary"
            disabled={busy}
            onClick={() =>
              onAction(
                'dns-stop',
                {},
                '确认停用本地 AdGuard Home 接管？系统将自动先把 sing-box 切回内置纯 IP 加密 DoH，不会中断当前网络。',
              )
            }
          >
            安全停用接管
          </Button>
        </>
      ) : (
        <Button
          size="sm"
          variant="primary"
          disabled={busy}
          icon={<Power className="w-3.5 h-3.5" />}
          onClick={() => onAction('dns-start')}
        >
          启动并接管 DNS
        </Button>
      )}

      <Button
        size="sm"
        variant="secondary"
        disabled={busy}
        icon={<Download className="w-3.5 h-3.5" />}
        onClick={() => onAction('dns-update')}
      >
        更新核心版本
      </Button>

      <Button
        size="sm"
        variant="danger"
        disabled={busy}
        onClick={() =>
          onAction(
            'dns-uninstall',
            { purge: false },
            '确认卸载 AdGuard Home？（将自动先切回 sing-box 内置加密 DNS 保证不断网，并保留 /etc/AdGuardHome 自定义规则目录以备重装恢复）',
          )
        }
      >
        安全卸载
      </Button>
    </div>
  </SectionCard>
);

export interface AdGuardCredentialsDrawerProps {
  open: boolean;
  snap: AdGuardOverviewSnapshot | null;
  credData: AdGuardCredentialsResponse | null;
  credLoading: boolean;
  resettingPwd: boolean;
  onClose: () => void;
  onResetPassword: () => Promise<boolean>;
}

export const AdGuardCredentialsDrawer: React.FC<AdGuardCredentialsDrawerProps> = ({
  open,
  snap,
  credData,
  credLoading,
  resettingPwd,
  onClose,
  onResetPassword,
}) => {
  const { success, error } = useToast();
  const [showPwd, setShowPwd] = useState(false);

  const copyText = async (text: string, msg: string) => {
    try {
      await navigator.clipboard.writeText(text);
      success(msg);
    } catch {
      error('复制失败，请手动复制');
    }
  };

  return (
    <SlideDrawer
      open={open}
      onClose={onClose}
      title="原生 AdGuard Home 面板与凭据"
      subtitle="仅供需要查看完整查询明细或高阶调优时使用（仅绑定局域网私网 IP，绝不暴露公网）"
    >
      <div className="space-y-4 py-1 text-xs sm:text-sm">
        {credLoading ? (
          <div className="py-8 text-center text-muted">正在读取凭据…</div>
        ) : (
          <>
            <div className="p-3.5 rounded-xl bg-surface2 border border-subtle space-y-2.5">
              <div className="flex items-center justify-between gap-2">
                <span className="text-secondary">局域网访问地址</span>
                <div className="flex items-center gap-1.5">
                  <Button
                    size="xs"
                    variant="ghost"
                    onClick={() =>
                      void copyText(credData?.webUrl || snap?.webUrl || '', '已复制面板地址')
                    }
                    icon={<Copy className="w-3 h-3" />}
                  >
                    复制
                  </Button>
                  {(credData?.webUrl || snap?.webUrl) && (
                    <a
                      href={credData?.webUrl || snap?.webUrl}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="inline-flex items-center gap-1 px-2.5 py-1 rounded-lg text-xs font-semibold bg-[var(--accent)] text-white"
                    >
                      <span>打开面板</span>
                      <ExternalLink className="w-3 h-3" />
                    </a>
                  )}
                </div>
              </div>
              <div className="font-mono text-primary break-all">
                {credData?.webUrl || snap?.webUrl || '-'}
              </div>
            </div>

            <div className="p-3.5 rounded-xl bg-surface2 border border-subtle space-y-3">
              <div className="flex items-center justify-between gap-2">
                <span className="text-secondary">管理员账号</span>
                <div className="flex items-center gap-2">
                  <span className="font-mono font-semibold text-primary">
                    {credData?.username || snap?.username || 'root'}
                  </span>
                  <Button
                    size="xs"
                    variant="ghost"
                    onClick={() =>
                      void copyText(credData?.username || snap?.username || 'root', '已复制管理员账号')
                    }
                    icon={<Copy className="w-3 h-3" />}
                  />
                </div>
              </div>

              <div className="flex items-center justify-between gap-2 pt-2 border-t border-subtle">
                <span className="text-secondary">管理员密码</span>
                {credData?.password ? (
                  <div className="flex items-center gap-1.5">
                    <span className="font-mono text-primary">
                      {showPwd ? credData.password : '••••••••••••••••'}
                    </span>
                    <Button
                      size="xs"
                      variant="ghost"
                      onClick={() => setShowPwd((v) => !v)}
                      icon={
                        showPwd ? (
                          <EyeOff className="w-3.5 h-3.5" />
                        ) : (
                          <Eye className="w-3.5 h-3.5" />
                        )
                      }
                    />
                    <Button
                      size="xs"
                      variant="secondary"
                      onClick={() => void copyText(credData.password, '已复制管理员密码')}
                      icon={<Copy className="w-3 h-3" />}
                    >
                      复制密码
                    </Button>
                  </div>
                ) : (
                  <span className="text-muted text-xs">密码已哈希落盘，点击下方可一键重置</span>
                )}
              </div>
            </div>

            <div className="pt-2 flex items-center justify-between gap-2">
              <span className="text-[11px] text-muted">
                重置不会影响已添加的去广告规则库与内网重写映射
              </span>
              <Button
                size="sm"
                variant="secondary"
                loading={resettingPwd}
                onClick={async () => {
                  const ok = await onResetPassword();
                  if (ok) setShowPwd(true);
                }}
              >
                生成新随机密码
              </Button>
            </div>
          </>
        )}
      </div>
    </SlideDrawer>
  );
};

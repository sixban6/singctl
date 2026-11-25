import React, { useState } from 'react';
import {
  Copy,
  Download,
  ExternalLink,
  Eye,
  EyeOff,
  FileCode2,
  Power,
  RefreshCw,
  RotateCw,
  Trash2,
} from 'lucide-react';
import { Badge, Button, SectionCard, SlideDrawer, useToast } from '../../../ui';
import { copyToClipboard } from '../../../lib/clipboard';
import {
  AdGuardCredentialsResponse,
  DNSCapabilities,
  DNSConfigPreviewResponse,
  DNSOverviewSnapshot,
} from '../../types';
import { getEngineDisplayName, resolveActiveEngine } from './adguardHelpers';

export const AdGuardLifecycleSection: React.FC<{
  snap: DNSOverviewSnapshot | null;
  capabilities: DNSCapabilities;
  busy: boolean;
  onAction: (name: string, params?: Record<string, unknown>, confirmMsg?: string) => void;
}> = ({ snap, capabilities, busy, onAction }) => {
  const activeEngine = resolveActiveEngine(snap);
  const engineLabel = getEngineDisplayName(activeEngine, snap?.activeEngineLabel);
  const dnsHealthy = Boolean(snap?.dnsHealthy);

  return (
    <SectionCard
      title={`服务生命周期与安全切换 · ${engineLabel}`}
      subtitle={`停用或卸载 ${engineLabel} 时会自动先将 sing-box dns_local 平滑回退至内置纯 IP 加密 DoH 兜底，确保全屋网关零断网`}
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
                  `确认停用本地 ${engineLabel} 接管？系统将自动先把 sing-box 切回内置纯 IP 加密 DoH，不会中断当前网络。`,
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
          onClick={() =>
            onAction(
              'dns-install',
              { engine: activeEngine },
              `确认重新安装 / 刷新 ${engineLabel}？期间将保持加密 DoH 兜底不断网，既有配置自动保留。`,
            )
          }
        >
          重装引擎
        </Button>

        {activeEngine === 'adguard' && (
          <Button
            size="sm"
            variant="secondary"
            disabled={busy}
            icon={<RefreshCw className="w-3.5 h-3.5" />}
            onClick={() => onAction('dns-update')}
          >
            更新核心版本
          </Button>
        )}

        {capabilities.canUninstall && (
          <Button
            size="sm"
            variant="danger"
            disabled={busy}
            icon={<Trash2 className="w-3.5 h-3.5" />}
            onClick={() =>
              onAction(
                'dns-uninstall',
                { engine: activeEngine, purge: false },
                `确认卸载 ${engineLabel}？（将自动先把 sing-box 切回内置纯 IP 加密 DoH 兜底保证不断网，并保留自定义配置文件以备重装恢复）`,
              )
            }
          >
            安全卸载
          </Button>
        )}
      </div>
    </SectionCard>
  );
};

export interface AdGuardCredentialsDrawerProps {
  open: boolean;
  snap: DNSOverviewSnapshot | null;
  capabilities: DNSCapabilities;
  credData: AdGuardCredentialsResponse | null;
  credLoading: boolean;
  resettingPwd: boolean;
  configPreview: DNSConfigPreviewResponse | null;
  configPreviewLoading: boolean;
  configPreviewError: string | null;
  onClose: () => void;
  onResetPassword: () => Promise<boolean>;
  onRefreshConfigPreview: () => Promise<void>;
}

export const AdGuardCredentialsDrawer: React.FC<AdGuardCredentialsDrawerProps> = ({
  open,
  snap,
  capabilities,
  credData,
  credLoading,
  resettingPwd,
  configPreview,
  configPreviewLoading,
  configPreviewError,
  onClose,
  onResetPassword,
  onRefreshConfigPreview,
}) => {
  const { success, error } = useToast();
  const [showPwd, setShowPwd] = useState(false);

  const activeEngine = resolveActiveEngine(snap);
  const engineLabel = getEngineDisplayName(activeEngine, snap?.activeEngineLabel);

  const copyText = async (text: string, msg: string) => {
    if (!text) return;
    try {
      await copyToClipboard(text);
      success(msg);
    } catch {
      error('复制失败，请手动复制');
    }
  };

  const drawerTitle = capabilities.hasNativeWebPanel
    ? `原生 ${engineLabel} 面板与配置`
    : `${engineLabel} 生效配置与诊断`;

  const drawerSubtitle = capabilities.hasNativeWebPanel
    ? '局域网管理凭据与实时生效配置摘要（仅绑定私网/回环，绝不暴露公网）'
    : '查看当前防劫持 DNS 引擎实时生效的配置内容、落盘路径与运行摘要';

  return (
    <SlideDrawer
      open={open}
      onClose={onClose}
      size="lg"
      title={drawerTitle}
      subtitle={drawerSubtitle}
    >
      <div className="space-y-5 py-1 text-xs sm:text-sm">
        {capabilities.hasNativeWebPanel && (
          <div className="space-y-3">
            <div className="flex items-center justify-between gap-2">
              <span className="text-xs font-semibold text-primary">原生 Web 管理面板与凭据</span>
              <Badge tone="neutral">仅限局域网访问</Badge>
            </div>

            {credLoading ? (
              <div className="py-6 text-center text-muted">正在读取管理凭据…</div>
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
                          void copyText(
                            credData?.username || snap?.username || 'root',
                            '已复制管理员账号',
                          )
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
                      <span className="text-muted text-xs">
                        密码已哈希落盘，点击下方可一键重置
                      </span>
                    )}
                  </div>
                </div>

                <div className="flex items-center justify-between gap-2">
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
        )}

        {capabilities.hasConfigPreview && (
          <div className="space-y-3 pt-1">
            <div className="flex items-center justify-between gap-2">
              <div className="flex items-center gap-1.5 text-xs font-semibold text-primary">
                <FileCode2 className="w-4 h-4 text-sky-400" />
                <span>{configPreview?.title || `${engineLabel} 实时生效配置`}</span>
              </div>
              <div className="flex items-center gap-1.5">
                <Button
                  size="xs"
                  variant="ghost"
                  loading={configPreviewLoading}
                  onClick={() => void onRefreshConfigPreview()}
                  icon={<RefreshCw className="w-3 h-3" />}
                >
                  刷新
                </Button>
                <Button
                  size="xs"
                  variant="secondary"
                  disabled={!configPreview?.content}
                  onClick={() => void copyText(configPreview?.content || '', '已复制实时生效配置')}
                  icon={<Copy className="w-3 h-3" />}
                >
                  复制配置
                </Button>
              </div>
            </div>

            {configPreviewLoading && !configPreview ? (
              <div className="py-8 text-center text-muted">正在读取实时生效配置预览…</div>
            ) : configPreviewError ? (
              <div className="p-3.5 rounded-xl bg-rose-500/10 border border-rose-500/25 text-xs text-rose-300 space-y-2">
                <div>读取配置预览失败：{configPreviewError}</div>
                <Button
                  size="xs"
                  variant="secondary"
                  onClick={() => void onRefreshConfigPreview()}
                >
                  重新读取
                </Button>
              </div>
            ) : configPreview ? (
              <div className="space-y-2.5">
                {configPreview.runtimeSummary && (
                  <div className="p-3 rounded-xl bg-surface2 border border-subtle text-xs text-secondary leading-relaxed">
                    <div className="text-[11px] font-semibold text-primary mb-1">运行摘要</div>
                    <div>{configPreview.runtimeSummary}</div>
                  </div>
                )}

                {configPreview.path && (
                  <div className="flex items-center justify-between gap-2 px-3 py-2 rounded-xl bg-surface2 border border-subtle text-xs">
                    <span className="font-mono text-secondary truncate" title={configPreview.path}>
                      {configPreview.path}
                    </span>
                    <Button
                      size="xs"
                      variant="ghost"
                      onClick={() => void copyText(configPreview.path, '已复制配置文件路径')}
                      icon={<Copy className="w-3 h-3" />}
                    >
                      复制路径
                    </Button>
                  </div>
                )}

                <pre className="p-3.5 rounded-xl bg-slate-950/90 border border-slate-800 text-[11px] sm:text-xs font-mono text-slate-200 overflow-x-auto max-h-[52vh] overflow-y-auto whitespace-pre leading-relaxed">
                  {configPreview.content || '# 当前配置内容为空'}
                </pre>
              </div>
            ) : (
              <div className="py-6 text-center text-muted">暂无可预览的生效配置</div>
            )}
          </div>
        )}
      </div>
    </SlideDrawer>
  );
};

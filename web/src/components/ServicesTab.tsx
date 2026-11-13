import React, { useState } from 'react';
import { ServerStatusResponse } from '../types';
import { api } from '../api';
import { Badge, Button, PageHeader, SectionCard, SlideDrawer, useToast } from '../ui';
import { TabKey } from '../App';
import {
  Play,
  Square,
  RotateCw,
  FileText,
  Save,
  Edit3,
  ShieldCheck,
  Zap,
  RefreshCw,
  Sparkles,
  Globe,
  ArrowUpCircle,
  Split,
  CheckCircle2,
  X,
} from 'lucide-react';

interface ServicesTabProps {
  status: ServerStatusResponse | null;
  onRefresh: () => void;
  onOpenLogs: (service: string) => void;
  onNavigate?: (tab: TabKey) => void;
}

export const ServicesTab: React.FC<ServicesTabProps> = ({
  status,
  onRefresh,
  onOpenLogs,
  onNavigate,
}) => {
  const { success, error } = useToast();
  const [loading, setLoading] = useState<string | null>(null);
  const [viewingConfig, setViewingConfig] = useState<{
    service: string;
    path: string;
    content: string;
  } | null>(null);
  const [editedConfig, setEditedConfig] = useState<string>('');
  const [savingConfig, setSavingConfig] = useState(false);

  const [enablingBBR, setEnablingBBR] = useState(false);
  const [editingSNI, setEditingSNI] = useState(false);
  const [sniInput, setSniInput] = useState('');
  const [updatingSNI, setUpdatingSNI] = useState(false);
  const [showSyncNotice, setShowSyncNotice] = useState(false);

  const [updateStates, setUpdateStates] = useState<
    Record<
      string,
      { checked: boolean; hasUpdate: boolean; latestVersion: string; message?: string }
    >
  >({});

  const handleCheckUpdate = async (service: string) => {
    const key = `${service}-check`;
    setLoading(key);
    try {
      const res = await api.checkServiceUpdate(service);
      setUpdateStates((prev) => ({
        ...prev,
        [service]: {
          checked: true,
          hasUpdate: res.hasUpdate,
          latestVersion: res.latestVersion,
          message: res.message,
        },
      }));
      if (res.hasUpdate) {
        success(`发现新版本 (v${res.latestVersion})，可点击立即升级`);
      } else {
        success(res.message || `${service} 已是最新稳定版本，无需更新`);
      }
    } catch (err: unknown) {
      error(err instanceof Error ? err.message : `${service} 检查更新失败`);
    } finally {
      setLoading(null);
    }
  };

  const handleExecuteUpgrade = async (service: string) => {
    const key = `${service}-upgrade`;
    setLoading(key);
    try {
      const res = await api.upgradeService(service);
      success(res.message || `${service} 平滑升级成功`);
      setUpdateStates((prev) => {
        const next = { ...prev };
        delete next[service];
        return next;
      });
      window.setTimeout(onRefresh, res.willRestartUI ? 2800 : 1500);
    } catch (err: unknown) {
      error(err instanceof Error ? err.message : `${service} 升级失败`);
    } finally {
      setLoading(null);
    }
  };

  const renderUpgradeAction = (service: string) => {
    const info = updateStates[service];
    const isChecking = loading === `${service}-check`;
    const isUpgrading = loading === `${service}-upgrade`;

    if (info?.hasUpdate) {
      return (
        <Button
          size="xs"
          variant="primary"
          loading={isUpgrading}
          icon={<ArrowUpCircle className="w-3.5 h-3.5" />}
          onClick={() => handleExecuteUpgrade(service)}
          title={`检测到远端新版本 (v${info.latestVersion})，点击平滑升级`}
        >
          {isUpgrading ? '平滑升级中…' : `升级至 v${info.latestVersion}`}
        </Button>
      );
    }

    if (info?.checked && !info.hasUpdate) {
      return (
        <Button
          size="xs"
          variant="secondary"
          loading={isChecking}
          icon={<CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />}
          onClick={() => handleCheckUpdate(service)}
          title="当前核心已是最新稳定版本 (点击可重新探查)"
        >
          {isChecking ? '探查中…' : '已是最新'}
        </Button>
      );
    }

    return (
      <Button
        size="xs"
        variant="secondary"
        loading={isChecking}
        icon={<RefreshCw className="w-3.5 h-3.5" />}
        onClick={() => handleCheckUpdate(service)}
        title="在线检查远端版本更新"
      >
        {isChecking ? '检查中…' : '检查更新'}
      </Button>
    );
  };

  const handleEnableBBR = async () => {
    setEnablingBBR(true);
    try {
      const res = await api.enableBBR();
      success(res.message);
      window.setTimeout(onRefresh, 1000);
    } catch (err: unknown) {
      error(err instanceof Error ? err.message : '启用 BBR 失败');
    } finally {
      setEnablingBBR(false);
    }
  };

  const handleRegenerateMaskSite = async () => {
    setLoading('caddy-mask');
    try {
      const res = await api.regenerateMaskSite();
      success(res.message);
    } catch (err: unknown) {
      error(err instanceof Error ? err.message : '重新生成伪装站失败');
    } finally {
      setLoading(null);
    }
  };

  const handleSaveSNI = async () => {
    if (!sniInput.trim()) return;
    setUpdatingSNI(true);
    try {
      const res = await api.updateSNI(sniInput.trim());
      success(res.message);
      setEditingSNI(false);
      setShowSyncNotice(true);
      window.setTimeout(onRefresh, 1500);
    } catch (err: unknown) {
      error(err instanceof Error ? err.message : '更新 SNI 失败');
    } finally {
      setUpdatingSNI(false);
    }
  };

  const handleAction = async (service: string, action: 'start' | 'stop' | 'restart' | 'reload') => {
    const key = `${service}-${action}`;
    setLoading(key);
    try {
      const res = await api.serviceAction(service, action);
      success(res.message);
      window.setTimeout(onRefresh, 1000);
    } catch (err: unknown) {
      error(err instanceof Error ? err.message : '操作执行失败');
    } finally {
      setLoading(null);
    }
  };

  const handleViewConfig = async (service: string) => {
    try {
      const res = await api.getServiceConfig(service);
      setViewingConfig(res);
      setEditedConfig(res.content);
    } catch (err: unknown) {
      error(err instanceof Error ? err.message : '无法获取配置文件');
    }
  };

  const handleSaveConfig = async () => {
    if (!viewingConfig) return;
    setSavingConfig(true);
    try {
      const res = await api.updateServiceConfig(viewingConfig.service, editedConfig);
      success(res.message);
      setViewingConfig(null);
      setShowSyncNotice(true);
      window.setTimeout(onRefresh, 1200);
    } catch (err: unknown) {
      error(err instanceof Error ? err.message : '保存配置失败');
    } finally {
      setSavingConfig(false);
    }
  };

  const singbox = status?.services?.singbox;
  const caddy = status?.services?.caddy;
  const subhub = status?.services?.subhub;
  const warp = status?.services?.warp;

  return (
    <div className="space-y-5">
      <PageHeader
        title="四核服务运维控制台"
        description="支持对 SingCtl 主程序与四大核心服务进行版本巡检、平滑升级、实时日志调取与配置在线编辑"
        badge={
          status?.version ? (
            <Badge tone="accent">
              SingCtl {status.version.startsWith('v') ? status.version : `v${status.version}`}
            </Badge>
          ) : null
        }
        actions={renderUpgradeAction('singctl')}
      />

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
        {/* sing-box */}
        <SectionCard
          title="sing-box 代理核心"
          subtitle="VLESS Reality & Hysteria2 协议承载"
          badge={
            <div className="flex items-center gap-1.5">
              {singbox?.version && <Badge tone="neutral">{singbox.version}</Badge>}
              <Badge tone={singbox?.running ? 'ok' : 'danger'} dot pulse={singbox?.running}>
                {singbox?.running ? '运行中' : '已停止'}
              </Badge>
            </div>
          }
        >
          <div className="space-y-4">
            <div className="grid grid-cols-2 gap-2.5 text-xs font-mono">
              <div className="p-2.5 rounded-xl bg-surface2/60 border border-subtle">
                <div className="text-muted text-[11px]">当前版本</div>
                <div className="text-primary font-semibold mt-0.5">{singbox?.version || '检测中…'}</div>
              </div>
              <div className="p-2.5 rounded-xl bg-surface2/60 border border-subtle">
                <div className="text-muted text-[11px]">持续运行</div>
                <div className="text-primary mt-0.5">{singbox?.uptime || '-'}</div>
              </div>
              <div className="p-2.5 rounded-xl bg-surface2/60 border border-subtle">
                <div className="text-muted text-[11px]">监听端口</div>
                <div className="text-primary mt-0.5">8443 (Reality) / 2080 (SS)</div>
              </div>
              <div className="p-2.5 rounded-xl bg-surface2/60 border border-subtle">
                <div className="text-muted text-[11px]">SNI 伪装</div>
                <div className="text-primary mt-0.5 truncate">{status?.config?.sni || 'swdist.apple.com'}</div>
              </div>
              <div className="p-2.5 rounded-xl bg-surface2/60 border border-subtle">
                <div className="text-muted text-[11px]">主进程 PID</div>
                <div className="text-primary tnum mt-0.5">{singbox?.pid || '-'}</div>
              </div>
              <div className="p-2.5 rounded-xl bg-surface2/60 border border-subtle">
                <div className="text-muted text-[11px]">进程守护</div>
                <div className="text-primary mt-0.5">systemd (sing-box)</div>
              </div>
            </div>

            <div className="pt-3 border-t border-subtle flex flex-wrap gap-2">
              {renderUpgradeAction('singbox')}
              <Button
                size="xs"
                variant="secondary"
                loading={loading === 'singbox-restart'}
                icon={<RotateCw className="w-3.5 h-3.5" />}
                onClick={() => handleAction('singbox', 'restart')}
              >
                重启
              </Button>
              <Button
                size="xs"
                variant="secondary"
                loading={loading === 'singbox-start' || loading === 'singbox-stop'}
                icon={
                  singbox?.running ? (
                    <Square className="w-3.5 h-3.5 text-rose-400" />
                  ) : (
                    <Play className="w-3.5 h-3.5 text-emerald-400" />
                  )
                }
                onClick={() => handleAction('singbox', singbox?.running ? 'stop' : 'start')}
              >
                {singbox?.running ? '停止' : '启动'}
              </Button>
              <Button
                size="xs"
                variant="secondary"
                icon={<FileText className="w-3.5 h-3.5" />}
                onClick={() => onOpenLogs('singbox')}
              >
                实时日志
              </Button>
              <Button
                size="xs"
                variant="secondary"
                icon={<Edit3 className="w-3.5 h-3.5" />}
                onClick={() => handleViewConfig('singbox')}
              >
                配置编辑
              </Button>
            </div>
          </div>
        </SectionCard>

        {/* Caddy */}
        <SectionCard
          title="Caddy 网关"
          subtitle="Cloudflare DNS 自动化 TLS 与隐蔽路径反代"
          badge={
            <div className="flex items-center gap-1.5">
              {caddy?.version && <Badge tone="neutral">{caddy.version}</Badge>}
              <Badge tone={caddy?.running ? 'ok' : 'danger'} dot pulse={caddy?.running}>
                {caddy?.running ? '运行中' : '已停止'}
              </Badge>
            </div>
          }
        >
          <div className="space-y-4">
            <div className="grid grid-cols-2 gap-2.5 text-xs font-mono">
              <div className="p-2.5 rounded-xl bg-surface2/60 border border-subtle">
                <div className="text-muted text-[11px]">当前版本</div>
                <div className="text-primary font-semibold mt-0.5">{caddy?.version || '检测中…'}</div>
              </div>
              <div className="p-2.5 rounded-xl bg-surface2/60 border border-subtle">
                <div className="text-muted text-[11px]">持续运行</div>
                <div className="text-primary mt-0.5">{caddy?.uptime || '-'}</div>
              </div>
              <div className="p-2.5 rounded-xl bg-surface2/60 border border-subtle">
                <div className="text-muted text-[11px]">主绑定域名</div>
                <div className="text-primary mt-0.5 truncate">{status?.config?.nodeDomain || '-'}</div>
              </div>
              <div className="p-2.5 rounded-xl bg-surface2/60 border border-subtle">
                <div className="text-muted text-[11px]">Sub-Store 域名</div>
                <div className="text-primary mt-0.5 truncate">{status?.config?.substoreDomain || '-'}</div>
              </div>
              <div className="p-2.5 rounded-xl bg-surface2/60 border border-subtle">
                <div className="text-muted text-[11px]">主进程 PID</div>
                <div className="text-primary tnum mt-0.5">{caddy?.pid || '-'}</div>
              </div>
              <div className="p-2.5 rounded-xl bg-surface2/60 border border-subtle">
                <div className="text-muted text-[11px]">扩展模块</div>
                <div className="text-primary mt-0.5">CF DNS + Layer4</div>
              </div>
            </div>

            <div className="pt-3 border-t border-subtle flex flex-wrap gap-2">
              {renderUpgradeAction('caddy')}
              <Button
                size="xs"
                variant="secondary"
                loading={loading === 'caddy-reload'}
                icon={<RotateCw className="w-3.5 h-3.5" />}
                onClick={() => handleAction('caddy', 'reload')}
              >
                热重载
              </Button>
              <Button
                size="xs"
                variant="secondary"
                loading={loading === 'caddy-restart'}
                icon={<RotateCw className="w-3.5 h-3.5" />}
                onClick={() => handleAction('caddy', 'restart')}
              >
                重启
              </Button>
              <Button
                size="xs"
                variant="secondary"
                icon={<FileText className="w-3.5 h-3.5" />}
                onClick={() => onOpenLogs('caddy')}
              >
                日志
              </Button>
              <Button
                size="xs"
                variant="secondary"
                icon={<Edit3 className="w-3.5 h-3.5" />}
                onClick={() => handleViewConfig('caddy')}
              >
                Caddyfile
              </Button>
              <Button
                size="xs"
                variant="secondary"
                loading={loading === 'caddy-mask'}
                icon={<Sparkles className="w-3.5 h-3.5" />}
                onClick={handleRegenerateMaskSite}
                title="随机生成全新主题、作者与文章的高熵伪装博客"
              >
                换一批伪装站
              </Button>
              {status?.config?.nodeDomain && (
                <a
                  href={`https://${status.config.nodeDomain}`}
                  target="_blank"
                  rel="noreferrer"
                  className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-surface2 border border-subtle text-xs font-medium text-secondary hover:text-primary transition-colors"
                >
                  <Globe className="w-3.5 h-3.5 text-accent" />
                  <span>访问回落页</span>
                </a>
              )}
            </div>
          </div>
        </SectionCard>

        {/* SubHub */}
        <SectionCard
          title="SubHub 订阅中枢"
          subtitle="Go 原生内置多协议聚合与配置转换引擎"
          badge={
            <div className="flex items-center gap-1.5">
              {subhub?.version && <Badge tone="neutral">{subhub.version}</Badge>}
              <Badge tone={subhub?.running ? 'ok' : 'danger'} dot pulse={subhub?.running}>
                {subhub?.running ? '运行中' : '已停止'}
              </Badge>
            </div>
          }
        >
          <div className="space-y-4">
            <div className="grid grid-cols-2 gap-2.5 text-xs font-mono">
              <div className="p-2.5 rounded-xl bg-surface2/60 border border-subtle">
                <div className="text-muted text-[11px]">当前版本</div>
                <div className="text-primary font-semibold mt-0.5">{subhub?.version || '检测中…'}</div>
              </div>
              <div className="p-2.5 rounded-xl bg-surface2/60 border border-subtle">
                <div className="text-muted text-[11px]">持续运行</div>
                <div className="text-primary mt-0.5">{subhub?.uptime || '-'}</div>
              </div>
              <div className="p-2.5 rounded-xl bg-surface2/60 border border-subtle">
                <div className="text-muted text-[11px]">内网监听</div>
                <div className="text-primary mt-0.5">127.0.0.1:3001</div>
              </div>
              <div className="p-2.5 rounded-xl bg-surface2/60 border border-subtle">
                <div className="text-muted text-[11px]">主进程 PID</div>
                <div className="text-primary tnum mt-0.5">{subhub?.pid || '-'}</div>
              </div>
              <div className="p-2.5 rounded-xl bg-surface2/60 border border-subtle">
                <div className="text-muted text-[11px]">进程守护</div>
                <div className="text-primary mt-0.5">systemd (singctl-sub)</div>
              </div>
              <div className="p-2.5 rounded-xl bg-surface2/60 border border-subtle">
                <div className="text-muted text-[11px]">运行架构</div>
                <div className="text-emerald-400 mt-0.5">Go 原生零容器依赖</div>
              </div>
            </div>

            <div className="pt-3 border-t border-subtle flex flex-wrap gap-2">
              {renderUpgradeAction('singctl')}
              <Button
                size="xs"
                variant="secondary"
                loading={loading === 'subhub-restart'}
                icon={<RotateCw className="w-3.5 h-3.5" />}
                onClick={() => handleAction('subhub', 'restart')}
              >
                重启服务
              </Button>
              <Button
                size="xs"
                variant="secondary"
                loading={loading === 'subhub-start' || loading === 'subhub-stop'}
                icon={
                  subhub?.running ? (
                    <Square className="w-3.5 h-3.5 text-rose-400" />
                  ) : (
                    <Play className="w-3.5 h-3.5 text-emerald-400" />
                  )
                }
                onClick={() => handleAction('subhub', subhub?.running ? 'stop' : 'start')}
              >
                {subhub?.running ? '停止' : '启动'}
              </Button>
              <Button
                size="xs"
                variant="secondary"
                icon={<FileText className="w-3.5 h-3.5" />}
                onClick={() => onOpenLogs('subhub')}
              >
                实时日志
              </Button>
            </div>
          </div>
        </SectionCard>

        {/* WARP */}
        <SectionCard
          title="Cloudflare WARP 出口"
          subtitle="wireproxy 专属出口 SOCKS5 代理"
          badge={
            <div className="flex items-center gap-1.5">
              {warp?.version && <Badge tone="neutral">{warp.version}</Badge>}
              <Badge tone={warp?.running ? 'ok' : 'danger'} dot pulse={warp?.running}>
                {warp?.running ? '运行中' : '已停止'}
              </Badge>
            </div>
          }
        >
          <div className="space-y-4">
            <div className="grid grid-cols-2 gap-2.5 text-xs font-mono">
              <div className="p-2.5 rounded-xl bg-surface2/60 border border-subtle">
                <div className="text-muted text-[11px]">当前版本</div>
                <div className="text-primary font-semibold mt-0.5">{warp?.version || '检测中…'}</div>
              </div>
              <div className="p-2.5 rounded-xl bg-surface2/60 border border-subtle">
                <div className="text-muted text-[11px]">SOCKS5 代理</div>
                <div className="text-primary mt-0.5">127.0.0.1:40000</div>
              </div>
              <div className="p-2.5 rounded-xl bg-surface2/60 border border-subtle">
                <div className="text-muted text-[11px]">主进程 PID</div>
                <div className="text-primary tnum mt-0.5">{warp?.pid || '-'}</div>
              </div>
              <div className="p-2.5 rounded-xl bg-surface2/60 border border-subtle">
                <div className="text-muted text-[11px]">进程守护</div>
                <div className="text-primary mt-0.5">systemd (singctl-warp)</div>
              </div>
            </div>

            <div className="pt-3 border-t border-subtle flex flex-wrap gap-2">
              {renderUpgradeAction('warp')}
              <Button
                size="xs"
                variant="secondary"
                loading={loading === 'warp-restart'}
                icon={<RotateCw className="w-3.5 h-3.5" />}
                onClick={() => handleAction('warp', 'restart')}
              >
                重启 WARP
              </Button>
              <Button
                size="xs"
                variant="secondary"
                icon={<FileText className="w-3.5 h-3.5" />}
                onClick={() => onOpenLogs('warp')}
              >
                实时日志
              </Button>
              {onNavigate && (
                <Button
                  size="xs"
                  variant="primary"
                  className="ml-auto"
                  icon={<Split className="w-3.5 h-3.5" />}
                  onClick={() => onNavigate('warp')}
                >
                  配置分流规则
                </Button>
              )}
            </div>
          </div>
        </SectionCard>
      </div>

      {/* BBR & Reality SNI */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
        <SectionCard
          title="Google BBR 拥塞控制"
          subtitle="内核层 TCP 加速与抗丢包算法"
          icon={<ShieldCheck className="w-4 h-4" />}
          badge={
            <Badge tone={status?.system?.bbr ? 'ok' : 'warn'} dot>
              {status?.system?.bbr ? 'BBR 已开启' : '未开启'}
            </Badge>
          }
        >
          <p className="text-xs text-secondary leading-relaxed">
            {status?.system?.bbr
              ? '内核已启用 Google BBR 拥塞控制算法，大幅优化跨国高延迟与弱网长距离丢包，跑满服务器峰值带宽。'
              : '检测到内核尚未启用 BBR 算法，建议一键开启以提升海外连接速度与抗丢包能力。'}
          </p>
          <div className="mt-4 pt-3 border-t border-subtle flex items-center justify-between">
            <span className="text-xs text-muted font-mono">
              状态: {status?.system?.bbr ? '运行中 (fq + bbr)' : '默认算法 (cubic)'}
            </span>
            <Button
              size="sm"
              variant={status?.system?.bbr ? 'secondary' : 'primary'}
              loading={enablingBBR}
              disabled={Boolean(status?.system?.bbr)}
              icon={<Zap className="w-3.5 h-3.5" />}
              onClick={handleEnableBBR}
            >
              {status?.system?.bbr ? 'BBR 已就绪' : '一键开启 BBR'}
            </Button>
          </div>
        </SectionCard>

        <SectionCard
          title="Reality 目标伪装与探测防御"
          subtitle="TLS 1.3 握手伪装域名 (SNI)"
          icon={<Zap className="w-4 h-4" />}
          badge={<Badge tone="accent">TLS 1.3 拟态</Badge>}
        >
          <p className="text-xs text-secondary leading-relaxed">
            伪装 TLS 握手域名，使 TLS 握手特征与官方分发站点的正常访问保持一致。
          </p>
          {editingSNI ? (
            <div className="mt-3 space-y-2">
              <input
                type="text"
                value={sniInput}
                onChange={(e) => setSniInput(e.target.value)}
                placeholder="例如: swdist.apple.com"
                className="sc-input w-full px-3 py-2 text-xs font-mono"
              />
              <div className="flex flex-wrap gap-1.5">
                {['swdist.apple.com', 'gateway.icloud.com', 'itunes.apple.com'].map((s) => (
                  <Button key={s} size="xs" variant="secondary" onClick={() => setSniInput(s)}>
                    {s}
                  </Button>
                ))}
              </div>
            </div>
          ) : (
            <div className="mt-3 text-xs font-mono bg-surface2/70 px-3 py-2.5 rounded-xl border border-subtle">
              <span className="text-muted">当前伪装域名: </span>
              <span className="text-primary font-semibold">
                {status?.config?.sni || 'swdist.apple.com'}
              </span>
            </div>
          )}

          <div className="mt-4 pt-3 border-t border-subtle flex items-center justify-between gap-2">
            <span className="text-[11px] text-muted">修改后自动重载网关并同步订阅</span>
            {editingSNI ? (
              <div className="flex items-center gap-2">
                <Button size="xs" variant="ghost" onClick={() => setEditingSNI(false)}>
                  取消
                </Button>
                <Button
                  size="xs"
                  variant="primary"
                  loading={updatingSNI}
                  disabled={!sniInput.trim()}
                  onClick={handleSaveSNI}
                >
                  保存并应用
                </Button>
              </div>
            ) : (
              <Button
                size="xs"
                variant="secondary"
                onClick={() => {
                  setSniInput(status?.config?.sni || 'swdist.apple.com');
                  setEditingSNI(true);
                }}
              >
                修改伪装域名
              </Button>
            )}
          </div>
        </SectionCard>
      </div>

      {/* Config Editor SlideDrawer */}
      <SlideDrawer
        open={Boolean(viewingConfig)}
        onClose={() => setViewingConfig(null)}
        size="xl"
        title={`在线配置编辑 · ${viewingConfig?.service || ''}`}
        subtitle={viewingConfig?.path || ''}
        footer={
          <div className="flex items-center justify-between w-full">
            <span className="text-xs text-muted font-mono tnum">
              {editedConfig.split('\n').length} 行 · {new Blob([editedConfig]).size} 字节
            </span>
            <div className="flex items-center gap-2">
              <Button variant="secondary" onClick={() => setViewingConfig(null)}>
                取消
              </Button>
              <Button
                variant="primary"
                loading={savingConfig}
                icon={<Save className="w-3.5 h-3.5" />}
                onClick={handleSaveConfig}
              >
                {savingConfig ? '正在校验并重载…' : '保存并重载服务'}
              </Button>
            </div>
          </div>
        }
      >
        <div className="space-y-3 h-full flex flex-col">
          <p className="text-xs text-muted font-mono">
            保存时将自动执行语法校验并重载服务；原配置文件会自动备份为 .bak 文件。
          </p>
          <textarea
            value={editedConfig}
            onChange={(e) => setEditedConfig(e.target.value)}
            spellCheck={false}
            rows={24}
            className="w-full flex-1 bg-[#070a10] text-emerald-300 border border-subtle rounded-xl p-4 font-mono text-xs leading-relaxed focus:outline-none focus:border-accent"
          />
        </div>
      </SlideDrawer>

      {/* Client Sync Notice Dialog */}
      {showSyncNotice && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/65 backdrop-blur-sm">
          <div className="w-full max-w-md console-card rounded-2xl p-6 text-center space-y-4 shadow-2xl animate-sc-in relative">
            <button
              type="button"
              onClick={() => setShowSyncNotice(false)}
              className="absolute right-4 top-4 p-1 rounded-lg text-muted hover:text-primary cursor-pointer"
            >
              <X className="w-4 h-4" />
            </button>
            <div className="w-12 h-12 rounded-2xl bg-emerald-500/12 border border-emerald-500/25 text-emerald-400 flex items-center justify-center mx-auto">
              <CheckCircle2 className="w-6 h-6" />
            </div>
            <div>
              <h4 className="text-base font-bold text-primary">服务端核心配置已生效</h4>
              <p className="text-xs text-secondary mt-2 leading-relaxed">
                核心服务配置已在 VPS 完成热重载并同步至订阅中枢。
              </p>
              <div className="mt-3 p-3 rounded-xl bg-amber-500/10 border border-amber-500/25 text-left text-xs text-secondary leading-relaxed">
                <strong className="text-amber-400">重要提醒：</strong>
                请在客户端（Shadowrocket、Clash Verge、sing-box 等）中点击「更新订阅」，以拉取最新节点参数。
              </div>
            </div>
            <Button variant="primary" className="w-full" onClick={() => setShowSyncNotice(false)}>
              我知道了
            </Button>
          </div>
        </div>
      )}
    </div>
  );
};

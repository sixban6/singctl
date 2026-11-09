import React, { useState } from 'react';
import { ServerStatusResponse } from '../types';
import { api } from '../api';
import { useToast } from './Toast';
import { Play, Square, RotateCw, FileText, Code2, ExternalLink, CheckCircle2, XCircle, X, Save, Edit3, ShieldCheck, Zap, RefreshCw, Sparkles, Globe, ArrowUpCircle } from 'lucide-react';

interface ServicesTabProps {
  status: ServerStatusResponse | null;
  onRefresh: () => void;
  onOpenLogs: (service: string) => void;
}

export const ServicesTab: React.FC<ServicesTabProps> = ({ status, onRefresh, onOpenLogs }) => {
  const { success, error } = useToast();
  const [loading, setLoading] = useState<string | null>(null);
  const [viewingConfig, setViewingConfig] = useState<{ service: string; path: string; content: string } | null>(null);
  const [editedConfig, setEditedConfig] = useState<string>('');
  const [savingConfig, setSavingConfig] = useState(false);

  const [enablingBBR, setEnablingBBR] = useState(false);
  const [editingSNI, setEditingSNI] = useState(false);
  const [sniInput, setSniInput] = useState('');
  const [updatingSNI, setUpdatingSNI] = useState(false);
  const [showSyncNotice, setShowSyncNotice] = useState(false);

  // 状态字典: service -> { checked, hasUpdate, latestVersion, message }
  const [updateStates, setUpdateStates] = useState<Record<string, { checked: boolean; hasUpdate: boolean; latestVersion: string; message?: string }>>({});

  const handleCheckUpdate = async (service: string) => {
    const key = `${service}-check`;
    setLoading(key);
    try {
      const res = await api.checkServiceUpdate(service);
      setUpdateStates(prev => ({
        ...prev,
        [service]: {
          checked: true,
          hasUpdate: res.hasUpdate,
          latestVersion: res.latestVersion,
          message: res.message,
        },
      }));
      if (res.hasUpdate) {
        success(`发现新版本 (v${res.latestVersion})，可点击升级按钮`);
      } else {
        success(res.message || `${service} 已是最新稳定版本，无需更新`);
      }
    } catch (err: any) {
      error(err.message || `${service} 检查更新失败`);
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
      // 重置该组件检查状态
      setUpdateStates(prev => {
        const next = { ...prev };
        delete next[service];
        return next;
      });
      setTimeout(onRefresh, 1500);
    } catch (err: any) {
      error(err.message || `${service} 升级失败`);
    } finally {
      setLoading(null);
    }
  };

  const renderUpgradeAction = (service: string, color: 'emerald' | 'blue' | 'purple' | 'amber') => {
    const info = updateStates[service];
    const isChecking = loading === `${service}-check`;
    const isUpgrading = loading === `${service}-upgrade`;

    // 1. 若检测到新版本: 渲染高亮醒目的立即升级按钮
    if (info?.hasUpdate) {
      const gradients = {
        emerald: 'from-emerald-500 to-teal-600 hover:from-emerald-400 hover:to-teal-500 shadow-emerald-500/20',
        blue: 'from-blue-500 to-indigo-600 hover:from-blue-400 hover:to-indigo-500 shadow-blue-500/20',
        purple: 'from-purple-500 to-pink-600 hover:from-purple-400 hover:to-pink-500 shadow-purple-500/20',
        amber: 'from-amber-500 to-orange-600 hover:from-amber-400 hover:to-orange-500 shadow-amber-500/20',
      };

      return (
        <button
          onClick={() => handleExecuteUpgrade(service)}
          disabled={isUpgrading}
          className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-gradient-to-r ${gradients[color]} text-white shadow-lg text-xs font-bold transition-all`}
          title={`检测到远端新版本 (v${info.latestVersion})，点击立即下载并平滑重启`}
        >
          <ArrowUpCircle className={`w-3.5 h-3.5 ${isUpgrading ? 'animate-spin' : ''}`} />
          <span>{isUpgrading ? '正在平滑升级...' : `立即升级至 v${info.latestVersion}`}</span>
        </button>
      );
    }

    // 2. 若已检查且已是最新版本: 渲染已是最新状态
    if (info?.checked && !info.hasUpdate) {
      return (
        <button
          onClick={() => handleCheckUpdate(service)}
          disabled={isChecking}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-emerald-500/10 hover:bg-emerald-500/20 border border-emerald-500/30 text-xs font-semibold text-emerald-400 transition-colors"
          title="当前核心已是最新稳定版本 (点击可重新探查)"
        >
          <CheckCircle2 className={`w-3.5 h-3.5 ${isChecking ? 'animate-spin' : 'text-emerald-400'}`} />
          <span>{isChecking ? '探查中...' : '已是最新'}</span>
        </button>
      );
    }

    // 3. 默认初始状态: 检查更新
    const themeBorders = {
      emerald: 'bg-emerald-500/10 hover:bg-emerald-500/20 border-emerald-500/30 text-emerald-300',
      blue: 'bg-blue-500/10 hover:bg-blue-500/20 border-blue-500/30 text-blue-300',
      purple: 'bg-purple-500/10 hover:bg-purple-500/20 border-purple-500/30 text-purple-300',
      amber: 'bg-amber-500/10 hover:bg-amber-500/20 border-amber-500/30 text-amber-300',
    };

    return (
      <button
        onClick={() => handleCheckUpdate(service)}
        disabled={isChecking}
        className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg border text-xs font-semibold transition-colors ${themeBorders[color]}`}
        title="在线检查远端版本更新"
      >
        <RefreshCw className={`w-3.5 h-3.5 ${isChecking ? 'animate-spin' : ''}`} />
        <span>{isChecking ? '检查中...' : '检查更新'}</span>
      </button>
    );
  };

  const handleEnableBBR = async () => {
    setEnablingBBR(true);
    try {
      const res = await api.enableBBR();
      success(res.message);
      setTimeout(onRefresh, 1000);
    } catch (err: any) {
      error(err.message || '启用 BBR 失败');
    } finally {
      setEnablingBBR(false);
    }
  };

  const handleRegenerateMaskSite = async () => {
    setLoading('caddy-mask');
    try {
      const res = await api.regenerateMaskSite();
      success(res.message);
    } catch (err: any) {
      error(err.message || '重新生成伪装站失败');
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
      setTimeout(onRefresh, 1500);
    } catch (err: any) {
      error(err.message || '更新 SNI 失败');
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
      setTimeout(onRefresh, 1000);
    } catch (err: any) {
      error(err.message || '操作执行失败');
    } finally {
      setLoading(null);
    }
  };

  const handleViewConfig = async (service: string) => {
    try {
      const res = await api.getServiceConfig(service);
      setViewingConfig(res);
      setEditedConfig(res.content);
    } catch (err: any) {
      error(err.message || '无法获取配置文件');
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
      setTimeout(onRefresh, 1200);
    } catch (err: any) {
      error(err.message || '保存配置失败');
    } finally {
      setSavingConfig(false);
    }
  };

  const singbox = status?.services?.singbox;
  const caddy = status?.services?.caddy;
  const subhub = status?.services?.subhub;
  const warp = status?.services?.warp;

  return (
    <div className="space-y-6">
      <div className="p-5 rounded-2xl glass-card">
        <h2 className="text-lg font-semibold text-white tracking-tight">四核服务运维控制台</h2>
        <p className="text-xs text-slate-400 mt-1">
          支持对每个核心服务进行独立进程管理、实时日志调取以及在线编辑配置
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
        {/* sing-box Card */}
        <div className="p-5 rounded-2xl glass-card flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between pb-3 border-b border-slate-800">
              <div className="flex items-center gap-2.5">
                <div className="w-8 h-8 rounded-xl bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center text-emerald-400 font-bold font-mono text-sm">
                  SB
                </div>
                <div>
                  <h3 className="font-semibold text-white text-base">sing-box 代理核心</h3>
                  <p className="text-xs text-slate-400">VLESS Reality & Shadowsocks 协议承载</p>
                </div>
              </div>
              <div className="flex items-center gap-2">
                {singbox?.version && (
                  <span className="px-2 py-0.5 rounded-md bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 text-xs font-mono font-medium">
                    {singbox.version}
                  </span>
                )}
                {updateStates.singbox?.hasUpdate && (
                  <span className="px-2 py-0.5 rounded-md bg-amber-500/20 text-amber-300 border border-amber-500/30 text-xs font-mono font-medium animate-pulse">
                    新版 v{updateStates.singbox.latestVersion}
                  </span>
                )}
                <div
                  className={`flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium border ${
                    singbox?.running
                      ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20'
                      : 'bg-rose-500/10 text-rose-400 border-rose-500/20'
                  }`}
                >
                  {singbox?.running ? <CheckCircle2 className="w-3.5 h-3.5" /> : <XCircle className="w-3.5 h-3.5" />}
                  <span>{singbox?.running ? 'active (运行中)' : 'inactive'}</span>
                </div>
              </div>
            </div>

            <div className="mt-4 grid grid-cols-2 gap-2 text-xs font-mono">
              <div className="p-2.5 rounded-xl bg-slate-900/60 border border-slate-800">
                <div className="text-slate-500">当前版本</div>
                <div className="text-emerald-400 font-semibold mt-0.5">{singbox?.version || '检测中...'}</div>
              </div>
              <div className="p-2.5 rounded-xl bg-slate-900/60 border border-slate-800">
                <div className="text-slate-500">持续运行</div>
                <div className="text-slate-200 mt-0.5">{singbox?.uptime || '-'}</div>
              </div>
              <div className="p-2.5 rounded-xl bg-slate-900/60 border border-slate-800">
                <div className="text-slate-500">监听端口</div>
                <div className="text-slate-200 mt-0.5">8443 (Reality) / 2080 (SS)</div>
              </div>
              <div className="p-2.5 rounded-xl bg-slate-900/60 border border-slate-800">
                <div className="text-slate-500">SNI 伪装</div>
                <div className="text-slate-200 mt-0.5">{status?.config?.sni || 'swdist.apple.com'}</div>
              </div>
              <div className="p-2.5 rounded-xl bg-slate-900/60 border border-slate-800">
                <div className="text-slate-500">主进程 PID</div>
                <div className="text-slate-200 mt-0.5">{singbox?.pid || '-'}</div>
              </div>
              <div className="p-2.5 rounded-xl bg-slate-900/60 border border-slate-800">
                <div className="text-slate-500">进程守护</div>
                <div className="text-slate-200 mt-0.5">systemd (sing-box)</div>
              </div>
            </div>
          </div>

          <div className="mt-5 pt-4 border-t border-slate-800 flex flex-wrap gap-2">
            {renderUpgradeAction('singbox', 'emerald')}
            <button
              onClick={() => handleAction('singbox', 'restart')}
              disabled={loading === 'singbox-restart'}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-700/60 text-xs font-medium text-slate-200 transition-colors"
            >
              <RotateCw className={`w-3.5 h-3.5 ${loading === 'singbox-restart' ? 'animate-spin text-emerald-400' : ''}`} />
              <span>重启</span>
            </button>
            <button
              onClick={() => handleAction('singbox', singbox?.running ? 'stop' : 'start')}
              disabled={loading === 'singbox-start' || loading === 'singbox-stop'}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-700/60 text-xs font-medium text-slate-200 transition-colors"
            >
              {singbox?.running ? <Square className="w-3.5 h-3.5 text-rose-400" /> : <Play className="w-3.5 h-3.5 text-emerald-400" />}
              <span>{singbox?.running ? '停止' : '启动'}</span>
            </button>
            <button
              onClick={() => onOpenLogs('singbox')}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-700/60 text-xs font-medium text-slate-200 transition-colors"
            >
              <FileText className="w-3.5 h-3.5 text-blue-400" />
              <span>实时日志</span>
            </button>
            <button
              onClick={() => handleViewConfig('singbox')}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-700/60 text-xs font-medium text-slate-200 transition-colors"
            >
              <Edit3 className="w-3.5 h-3.5 text-purple-400" />
              <span>配置编辑</span>
            </button>
          </div>
        </div>

        {/* Caddy Card */}
        <div className="p-5 rounded-2xl glass-card flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between pb-3 border-b border-slate-800">
              <div className="flex items-center gap-2.5">
                <div className="w-8 h-8 rounded-xl bg-blue-500/10 border border-blue-500/20 flex items-center justify-center text-blue-400 font-bold font-mono text-sm">
                  CA
                </div>
                <div>
                  <h3 className="font-semibold text-white text-base">Caddy 网关</h3>
                  <p className="text-xs text-slate-400">Cloudflare DNS 自动化 TLS 与隐蔽路径反代</p>
                </div>
              </div>
              <div className="flex items-center gap-2">
                {caddy?.version && (
                  <span className="px-2 py-0.5 rounded-md bg-blue-500/10 text-blue-400 border border-blue-500/20 text-xs font-mono font-medium">
                    {caddy.version}
                  </span>
                )}
                {updateStates.caddy?.hasUpdate && (
                  <span className="px-2 py-0.5 rounded-md bg-amber-500/20 text-amber-300 border border-amber-500/30 text-xs font-mono font-medium animate-pulse">
                    新版 v{updateStates.caddy.latestVersion}
                  </span>
                )}
                <div
                  className={`flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium border ${
                    caddy?.running
                      ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20'
                      : 'bg-rose-500/10 text-rose-400 border-rose-500/20'
                  }`}
                >
                  {caddy?.running ? <CheckCircle2 className="w-3.5 h-3.5" /> : <XCircle className="w-3.5 h-3.5" />}
                  <span>{caddy?.running ? 'active (运行中)' : 'inactive'}</span>
                </div>
              </div>
            </div>

            <div className="mt-4 grid grid-cols-2 gap-2 text-xs font-mono">
              <div className="p-2.5 rounded-xl bg-slate-900/60 border border-slate-800">
                <div className="text-slate-500">当前版本</div>
                <div className="text-blue-400 font-semibold mt-0.5">{caddy?.version || '检测中...'}</div>
              </div>
              <div className="p-2.5 rounded-xl bg-slate-900/60 border border-slate-800">
                <div className="text-slate-500">持续运行</div>
                <div className="text-slate-200 mt-0.5">{caddy?.uptime || '-'}</div>
              </div>
              <div className="p-2.5 rounded-xl bg-slate-900/60 border border-slate-800">
                <div className="text-slate-500">主绑定域名</div>
                <div className="text-slate-200 mt-0.5 truncate">{status?.config?.nodeDomain || '-'}</div>
              </div>
              <div className="p-2.5 rounded-xl bg-slate-900/60 border border-slate-800">
                <div className="text-slate-500">Sub-Store 域名</div>
                <div className="text-slate-200 mt-0.5 truncate">{status?.config?.substoreDomain || '-'}</div>
              </div>
              <div className="p-2.5 rounded-xl bg-slate-900/60 border border-slate-800">
                <div className="text-slate-500">主进程 PID</div>
                <div className="text-slate-200 mt-0.5">{caddy?.pid || '-'}</div>
              </div>
              <div className="p-2.5 rounded-xl bg-slate-900/60 border border-slate-800">
                <div className="text-slate-500">扩展模块</div>
                <div className="text-slate-200 mt-0.5">CF DNS + Layer4</div>
              </div>
            </div>
          </div>

          <div className="mt-5 pt-4 border-t border-slate-800 flex flex-wrap gap-2">
            {renderUpgradeAction('caddy', 'blue')}
            <button
              onClick={() => handleAction('caddy', 'reload')}
              disabled={loading === 'caddy-reload'}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-emerald-500/10 hover:bg-emerald-500/20 border border-emerald-500/30 text-xs font-semibold text-emerald-300 transition-colors"
            >
              <RotateCw className={`w-3.5 h-3.5 ${loading === 'caddy-reload' ? 'animate-spin' : ''}`} />
              <span>热重载 (Reload)</span>
            </button>
            <button
              onClick={() => handleAction('caddy', 'restart')}
              disabled={loading === 'caddy-restart'}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-700/60 text-xs font-medium text-slate-200 transition-colors"
            >
              <RotateCw className="w-3.5 h-3.5" />
              <span>重启</span>
            </button>
            <button
              onClick={() => onOpenLogs('caddy')}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-700/60 text-xs font-medium text-slate-200 transition-colors"
            >
              <FileText className="w-3.5 h-3.5 text-blue-400" />
              <span>实时日志</span>
            </button>
            <button
              onClick={() => handleViewConfig('caddy')}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-700/60 text-xs font-medium text-slate-200 transition-colors"
            >
              <Edit3 className="w-3.5 h-3.5 text-purple-400" />
              <span>Caddyfile 编辑</span>
            </button>
            <button
              onClick={handleRegenerateMaskSite}
              disabled={loading === 'caddy-mask'}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-indigo-500/10 hover:bg-indigo-500/20 border border-indigo-500/30 text-xs font-semibold text-indigo-300 transition-colors"
              title="随机生成全新主题、作者和文章的高熵伪装博客，防御空间测绘与流量指纹"
            >
              <Sparkles className={`w-3.5 h-3.5 ${loading === 'caddy-mask' ? 'animate-spin' : ''}`} />
              <span>换一批伪装站</span>
            </button>
            {status?.config?.nodeDomain && (
              <a
                href={`https://${status.config.nodeDomain}`}
                target="_blank"
                rel="noreferrer"
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-700/60 text-xs font-medium text-slate-300 transition-colors"
                title="在浏览器中直接打开当前 443 伪装回落网站"
              >
                <Globe className="w-3.5 h-3.5 text-cyan-400" />
                <span>访问回落页</span>
              </a>
            )}
          </div>
        </div>

        {/* SubHub Native Subscription Engine Card */}
        <div className="p-5 rounded-2xl glass-card flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between pb-3 border-b border-slate-800">
              <div className="flex items-center gap-2.5">
                <div className="w-8 h-8 rounded-xl bg-purple-500/10 border border-purple-500/20 flex items-center justify-center text-purple-400 font-bold font-mono text-sm">
                  SH
                </div>
                <div>
                  <h3 className="font-semibold text-white text-base">SubHub 订阅中枢</h3>
                  <p className="text-xs text-slate-400">Go 原生内置多协议聚合与配置转换引擎</p>
                </div>
              </div>
              <div className="flex items-center gap-2">
                {subhub?.version && (
                  <span className="px-2 py-0.5 rounded-md bg-purple-500/10 text-purple-400 border border-purple-500/20 text-xs font-mono font-medium">
                    {subhub.version}
                  </span>
                )}
                <div
                  className={`flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium border ${
                    subhub?.running
                      ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20'
                      : 'bg-rose-500/10 text-rose-400 border-rose-500/20'
                  }`}
                >
                  {subhub?.running ? <CheckCircle2 className="w-3.5 h-3.5" /> : <XCircle className="w-3.5 h-3.5" />}
                  <span>{subhub?.running ? 'active (运行中)' : 'inactive'}</span>
                </div>
              </div>
            </div>

            <div className="mt-4 grid grid-cols-2 gap-2 text-xs font-mono">
              <div className="p-2.5 rounded-xl bg-slate-900/60 border border-slate-800">
                <div className="text-slate-500">当前版本</div>
                <div className="text-purple-400 font-semibold mt-0.5">{subhub?.version || '检测中...'}</div>
              </div>
              <div className="p-2.5 rounded-xl bg-slate-900/60 border border-slate-800">
                <div className="text-slate-500">持续运行</div>
                <div className="text-slate-200 mt-0.5">{subhub?.uptime || '-'}</div>
              </div>
              <div className="p-2.5 rounded-xl bg-slate-900/60 border border-slate-800">
                <div className="text-slate-500">内网监听</div>
                <div className="text-slate-200 mt-0.5">127.0.0.1:3001</div>
              </div>
              <div className="p-2.5 rounded-xl bg-slate-900/60 border border-slate-800">
                <div className="text-slate-500">主进程 PID</div>
                <div className="text-slate-200 mt-0.5">{subhub?.pid || '-'}</div>
              </div>
              <div className="p-2.5 rounded-xl bg-slate-900/60 border border-slate-800">
                <div className="text-slate-500">进程守护</div>
                <div className="text-slate-200 mt-0.5">systemd (singctl-sub)</div>
              </div>
              <div className="p-2.5 rounded-xl bg-slate-900/60 border border-slate-800">
                <div className="text-slate-500">运行架构</div>
                <div className="text-emerald-400 mt-0.5">Go 原生零容器依赖</div>
              </div>
            </div>
          </div>

          <div className="mt-5 pt-4 border-t border-slate-800 flex flex-wrap gap-2">
            <button
              onClick={() => handleAction('subhub', 'restart')}
              disabled={loading === 'subhub-restart'}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-700/60 text-xs font-medium text-slate-200 transition-colors"
            >
              <RotateCw className={`w-3.5 h-3.5 ${loading === 'subhub-restart' ? 'animate-spin' : ''}`} />
              <span>重启服务</span>
            </button>
            <button
              onClick={() => handleAction('subhub', subhub?.running ? 'stop' : 'start')}
              disabled={loading === 'subhub-start' || loading === 'subhub-stop'}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-700/60 text-xs font-medium text-slate-200 transition-colors"
            >
              {subhub?.running ? <Square className="w-3.5 h-3.5 text-rose-400" /> : <Play className="w-3.5 h-3.5 text-emerald-400" />}
              <span>{subhub?.running ? '停止' : '启动'}</span>
            </button>
            <button
              onClick={() => onOpenLogs('subhub')}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-700/60 text-xs font-medium text-slate-200 transition-colors"
            >
              <FileText className="w-3.5 h-3.5 text-blue-400" />
              <span>实时日志</span>
            </button>
          </div>
        </div>

        {/* Cloudflare WARP Card */}
        <div className="p-5 rounded-2xl glass-card flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between pb-3 border-b border-slate-800">
              <div className="flex items-center gap-2.5">
                <div className="w-8 h-8 rounded-xl bg-amber-500/10 border border-amber-500/20 flex items-center justify-center text-amber-400 font-bold font-mono text-sm">
                  WP
                </div>
                <div>
                  <h3 className="font-semibold text-white text-base">Cloudflare WARP 出口</h3>
                  <p className="text-xs text-slate-400">wireproxy 专属出口 SOCKS5 代理</p>
                </div>
              </div>
              <div className="flex items-center gap-2">
                {warp?.version && (
                  <span className="px-2 py-0.5 rounded-md bg-amber-500/10 text-amber-400 border border-amber-500/20 text-xs font-mono font-medium">
                    {warp.version}
                  </span>
                )}
                {updateStates.warp?.hasUpdate && (
                  <span className="px-2 py-0.5 rounded-md bg-amber-500/20 text-amber-300 border border-amber-500/30 text-xs font-mono font-medium animate-pulse">
                    新版 v{updateStates.warp.latestVersion}
                  </span>
                )}
                <div
                  className={`flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium border ${
                    warp?.running
                      ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20'
                      : 'bg-rose-500/10 text-rose-400 border-rose-500/20'
                  }`}
                >
                  {warp?.running ? <CheckCircle2 className="w-3.5 h-3.5" /> : <XCircle className="w-3.5 h-3.5" />}
                  <span>{warp?.running ? 'active (运行中)' : 'inactive'}</span>
                </div>
              </div>
            </div>

            <div className="mt-4 grid grid-cols-2 gap-2 text-xs font-mono">
              <div className="p-2.5 rounded-xl bg-slate-900/60 border border-slate-800">
                <div className="text-slate-500">当前版本</div>
                <div className="text-amber-400 font-semibold mt-0.5">{warp?.version || '检测中...'}</div>
              </div>
              <div className="p-2.5 rounded-xl bg-slate-900/60 border border-slate-800">
                <div className="text-slate-500">SOCKS5 代理</div>
                <div className="text-slate-200 mt-0.5">127.0.0.1:40000</div>
              </div>
              <div className="p-2.5 rounded-xl bg-slate-900/60 border border-slate-800">
                <div className="text-slate-500">主进程 PID</div>
                <div className="text-slate-200 mt-0.5">{warp?.pid || '-'}</div>
              </div>
              <div className="p-2.5 rounded-xl bg-slate-900/60 border border-slate-800">
                <div className="text-slate-500">进程守护</div>
                <div className="text-slate-200 mt-0.5">systemd (singctl-warp)</div>
              </div>
            </div>
          </div>

          <div className="mt-5 pt-4 border-t border-slate-800 flex flex-wrap gap-2">
            {renderUpgradeAction('warp', 'amber')}
            <button
              onClick={() => handleAction('warp', 'restart')}
              disabled={loading === 'warp-restart'}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-700/60 text-xs font-medium text-slate-200 transition-colors"
            >
              <RotateCw className={`w-3.5 h-3.5 ${loading === 'warp-restart' ? 'animate-spin' : ''}`} />
              <span>重启 WARP</span>
            </button>
            <button
              onClick={() => onOpenLogs('warp')}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-700/60 text-xs font-medium text-slate-200 transition-colors"
            >
              <FileText className="w-3.5 h-3.5 text-blue-400" />
              <span>实时日志</span>
            </button>
          </div>
        </div>
      </div>

      {/* 系统网络优化与传输安全伪装 (BBR 与 Reality SNI) */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
        {/* BBR Card */}
        <div className="p-5 rounded-2xl glass-card flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between pb-3 border-b border-slate-800">
              <div className="flex items-center gap-2.5">
                <div className="p-2 rounded-xl bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                  <ShieldCheck className="w-5 h-5" />
                </div>
                <div>
                  <h3 className="font-semibold text-white text-base">Google BBR 拥塞控制</h3>
                  <p className="text-xs text-slate-400">内核层 TCP 加速与抗丢包算法</p>
                </div>
              </div>
              <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-mono font-medium border ${
                status?.system?.bbr
                  ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20'
                  : 'bg-amber-500/10 text-amber-400 border-amber-500/20'
              }`}>
                <span className={`w-1.5 h-1.5 rounded-full ${status?.system?.bbr ? 'bg-emerald-400' : 'bg-amber-400'}`}></span>
                <span>{status?.system?.bbr ? 'BBR 已开启' : '未开启'}</span>
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-3 leading-relaxed">
              {status?.system?.bbr
                ? '内核已启用 Google BBR 拥塞控制算法，大幅优化跨国高延迟与弱网长距离丢包，跑满服务器峰值带宽。'
                : '检测到内核尚未启用 BBR 算法，建议一键开启以大幅提升海外连接速度与抗丢包能力。'}
            </p>
          </div>
          <div className="mt-4 pt-3 border-t border-slate-800/80 flex items-center justify-between">
            <span className="text-xs text-slate-500 font-mono">
              状态: {status?.system?.bbr ? '运行中 (fq + bbr)' : '默认算法 (cubic)'}
            </span>
            <button
              onClick={handleEnableBBR}
              disabled={enablingBBR || status?.system?.bbr}
              className={`flex items-center gap-1.5 px-3.5 py-2 rounded-xl text-xs font-semibold transition-all ${
                status?.system?.bbr
                  ? 'bg-slate-800/60 text-emerald-400 border border-emerald-500/20 cursor-default'
                  : 'bg-emerald-500 hover:bg-emerald-600 text-slate-950 shadow-md shadow-emerald-500/20'
              }`}
            >
              {enablingBBR ? (
                <>
                  <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                  <span>正在配置 BBR...</span>
                </>
              ) : status?.system?.bbr ? (
                <>
                  <CheckCircle2 className="w-3.5 h-3.5" />
                  <span>BBR 加速已就绪</span>
                </>
              ) : (
                <>
                  <Zap className="w-3.5 h-3.5" />
                  <span>一键开启 BBR</span>
                </>
              )}
            </button>
          </div>
        </div>

        {/* Reality SNI Card */}
        <div className="p-5 rounded-2xl glass-card flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between pb-3 border-b border-slate-800">
              <div className="flex items-center gap-2.5">
                <div className="p-2 rounded-xl bg-purple-500/10 text-purple-400 border border-purple-500/20">
                  <Zap className="w-5 h-5" />
                </div>
                <div>
                  <h3 className="font-semibold text-white text-base">Reality 目标伪装与探测防御</h3>
                  <p className="text-xs text-slate-400">TLS 握手伪装域名 (SNI)</p>
                </div>
              </div>
              <span className="px-2.5 py-1 rounded-full text-xs font-mono font-medium bg-purple-500/10 text-purple-400 border border-purple-500/20">
                TLS 1.3 拟态
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-3 leading-relaxed">
              伪装 TLS 握手域名，使 TLS 握手特征与官方分发站点的正常访问保持高度一致。
            </p>
            {editingSNI ? (
              <div className="mt-3 space-y-2">
                <input
                  type="text"
                  value={sniInput}
                  onChange={(e) => setSniInput(e.target.value)}
                  placeholder="例如: swdist.apple.com"
                  className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-xs font-mono text-emerald-400 focus:outline-none focus:border-purple-500"
                />
                <div className="flex flex-wrap gap-1.5">
                  {['swdist.apple.com', 'gateway.icloud.com', 'itunes.apple.com'].map((s) => (
                    <button
                      key={s}
                      type="button"
                      onClick={() => setSniInput(s)}
                      className="px-2 py-0.5 rounded text-[10px] font-mono bg-slate-800 text-slate-300 hover:text-white hover:bg-slate-700"
                    >
                      {s}
                    </button>
                  ))}
                </div>
              </div>
            ) : (
              <div className="mt-3 text-xs font-mono text-slate-300 bg-slate-950/60 px-3 py-2 rounded-xl border border-slate-800 flex items-center justify-between">
                <div>
                  <span className="text-slate-500">当前伪装域名: </span>
                  <span className="text-emerald-400 font-semibold">{status?.config?.sni || 'swdist.apple.com'}</span>
                </div>
              </div>
            )}
          </div>
          <div className="mt-4 pt-3 border-t border-slate-800/80 flex items-center justify-between">
            <span className="text-[11px] text-slate-500">修改后将自动重载网关、节点核心并同步更新订阅</span>
            {editingSNI ? (
              <div className="flex items-center gap-2">
                <button
                  onClick={() => setEditingSNI(false)}
                  className="px-3 py-1.5 rounded-xl text-xs text-slate-400 hover:text-white hover:bg-slate-800"
                >
                  取消
                </button>
                <button
                  onClick={handleSaveSNI}
                  disabled={updatingSNI || !sniInput.trim()}
                  className="flex items-center gap-1.5 px-3.5 py-1.5 rounded-xl bg-purple-500 hover:bg-purple-600 text-white font-semibold text-xs shadow-md shadow-purple-500/20 disabled:opacity-50"
                >
                  {updatingSNI && <RefreshCw className="w-3 h-3 animate-spin" />}
                  <span>保存并应用</span>
                </button>
              </div>
            ) : (
              <button
                onClick={() => {
                  setSniInput(status?.config?.sni || 'swdist.apple.com');
                  setEditingSNI(true);
                }}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-200 font-medium text-xs transition-colors"
              >
                <span>修改伪装域名</span>
              </button>
            )}
          </div>
        </div>
      </div>

      {/* Editable Config Modal */}
      {viewingConfig && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/85 backdrop-blur-md">
          <div className="bg-slate-900 border border-slate-800 rounded-3xl w-full max-w-4xl max-h-[90vh] flex flex-col shadow-2xl overflow-hidden">
            <div className="flex items-center justify-between p-4 sm:px-6 border-b border-slate-800">
              <div className="flex items-center gap-2.5">
                <div className="p-2 rounded-xl bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                  <Edit3 className="w-4 h-4" />
                </div>
                <div>
                  <h3 className="font-semibold text-sm text-white flex items-center gap-2">
                    <span>在线配置编辑</span>
                    <span className="text-xs px-2 py-0.5 rounded-md bg-slate-800 text-slate-400 font-mono">
                      {viewingConfig.service}
                    </span>
                  </h3>
                  <p className="text-xs text-slate-500 font-mono mt-0.5">{viewingConfig.path}</p>
                </div>
              </div>
              <button
                onClick={() => setViewingConfig(null)}
                className="p-1.5 hover:bg-slate-800 rounded-xl text-slate-400 hover:text-white transition-colors"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="p-4 sm:px-6 flex-1 flex flex-col overflow-hidden bg-slate-950/70">
              <p className="text-[11px] text-slate-500 mb-2 font-mono">
                💡 保存时将自动进行语法校验并重载服务；原配置会自动备份为 .bak 文件
              </p>
              <textarea
                value={editedConfig}
                onChange={(e) => setEditedConfig(e.target.value)}
                spellCheck={false}
                className="w-full flex-1 bg-slate-950 border border-slate-800/80 rounded-2xl p-4 font-mono text-xs text-emerald-300/90 leading-relaxed focus:outline-none focus:border-emerald-500/50 resize-none selection:bg-emerald-500/30"
                rows={20}
              />
            </div>

            <div className="p-4 sm:px-6 border-t border-slate-800 flex items-center justify-between bg-slate-900">
              <span className="text-xs text-slate-500 font-mono">
                {editedConfig.split('\n').length} 行 · {new Blob([editedConfig]).size} 字节
              </span>
              <div className="flex items-center gap-2.5">
                <button
                  onClick={() => setViewingConfig(null)}
                  className="px-4 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-medium transition-colors"
                >
                  取消
                </button>
                <button
                  onClick={handleSaveConfig}
                  disabled={savingConfig}
                  className="flex items-center gap-1.5 px-5 py-2 rounded-xl bg-emerald-500 hover:bg-emerald-600 text-slate-950 text-xs font-semibold shadow-lg shadow-emerald-500/20 transition-all disabled:opacity-50"
                >
                  <Save className={`w-3.5 h-3.5 ${savingConfig ? 'animate-spin' : ''}`} />
                  <span>{savingConfig ? '正在校验并重载...' : '保存并重载服务'}</span>
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
      {/* Client Sync Notice Modal */}
      {showSyncNotice && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm animate-fade-in">
          <div className="w-full max-w-md bg-slate-900 border border-slate-800 rounded-2xl shadow-2xl p-6 text-center space-y-4">
            <div className="w-12 h-12 rounded-2xl bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 flex items-center justify-center mx-auto">
              <CheckCircle2 className="w-6 h-6" />
            </div>
            <div>
              <h4 className="text-base font-bold text-white">服务端核心配置已生效</h4>
              <p className="text-xs text-slate-300 mt-2 leading-relaxed">
                Reality 伪装 SNI / 核心服务配置已在 VPS 完成热重载并同步至 Sub-Store。
              </p>
              <div className="mt-3 p-3 rounded-xl bg-slate-950 border border-slate-800 text-left text-xs text-amber-300 flex items-start gap-2">
                <span className="text-base leading-none">📱</span>
                <span>
                  <strong>重要提醒</strong>：请在您的手机/电脑客户端（如 Shadowrocket、Clash Verge、Sing-box 等）中点击<strong>【更新订阅】</strong>，以拉取最新节点连接参数！
                </span>
              </div>
            </div>
            <button
              onClick={() => setShowSyncNotice(false)}
              className="w-full py-2.5 rounded-xl bg-emerald-500 hover:bg-emerald-600 text-slate-950 font-semibold text-xs transition-colors shadow-lg shadow-emerald-500/20"
            >
              我知道了，已了解
            </button>
          </div>
        </div>
      )}
    </div>
  );
};

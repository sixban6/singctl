import React from 'react';
import { ServerStatusResponse } from '../../types';
import { TabKey } from '../Navigation';
import { CheckCircle2, Edit3, FileText, Globe, Play, RotateCw, Sparkles, Split, Square, XCircle } from 'lucide-react';
import { UpdateStateMap, UpgradeActionButton } from './UpgradeActionButton';

interface CoreServiceGridProps {
  status: ServerStatusResponse | null;
  loading: string | null;
  updateStates: UpdateStateMap;
  onCheckUpdate: (service: string) => void;
  onExecuteUpgrade: (service: string) => void;
  onServiceAction: (service: string, action: 'start' | 'stop' | 'restart' | 'reload') => void;
  onOpenLogs: (service: string) => void;
  onViewConfig: (service: string) => void;
  onRegenerateMaskSite: () => void;
  onNavigate?: (tab: TabKey) => void;
}

export const CoreServiceGrid: React.FC<CoreServiceGridProps> = ({
  status,
  loading,
  updateStates,
  onCheckUpdate,
  onExecuteUpgrade,
  onServiceAction,
  onOpenLogs,
  onViewConfig,
  onRegenerateMaskSite,
  onNavigate,
}) => {
  const singbox = status?.services?.singbox;
  const caddy = status?.services?.caddy;
  const subhub = status?.services?.subhub;
  const warp = status?.services?.warp;

  const renderUpgrade = (service: string, color: 'emerald' | 'blue' | 'purple' | 'amber') => (
    <UpgradeActionButton
      service={service}
      color={color}
      updateStates={updateStates}
      loading={loading}
      onCheckUpdate={onCheckUpdate}
      onExecuteUpgrade={onExecuteUpgrade}
    />
  );

  return (
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
          {renderUpgrade('singbox', 'emerald')}
          <button
            onClick={() => onServiceAction('singbox', 'restart')}
            disabled={loading === 'singbox-restart'}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-700/60 text-xs font-medium text-slate-200 transition-colors"
          >
            <RotateCw className={`w-3.5 h-3.5 ${loading === 'singbox-restart' ? 'animate-spin text-emerald-400' : ''}`} />
            <span>重启</span>
          </button>
          <button
            onClick={() => onServiceAction('singbox', singbox?.running ? 'stop' : 'start')}
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
            onClick={() => onViewConfig('singbox')}
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
          {renderUpgrade('caddy', 'blue')}
          <button
            onClick={() => onServiceAction('caddy', 'reload')}
            disabled={loading === 'caddy-reload'}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-emerald-500/10 hover:bg-emerald-500/20 border border-emerald-500/30 text-xs font-semibold text-emerald-300 transition-colors"
          >
            <RotateCw className={`w-3.5 h-3.5 ${loading === 'caddy-reload' ? 'animate-spin' : ''}`} />
            <span>热重载 (Reload)</span>
          </button>
          <button
            onClick={() => onServiceAction('caddy', 'restart')}
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
            onClick={() => onViewConfig('caddy')}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-700/60 text-xs font-medium text-slate-200 transition-colors"
          >
            <Edit3 className="w-3.5 h-3.5 text-purple-400" />
            <span>Caddyfile 编辑</span>
          </button>
          <button
            onClick={onRegenerateMaskSite}
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
          {renderUpgrade('singctl', 'purple')}
          <button
            onClick={() => onServiceAction('subhub', 'restart')}
            disabled={loading === 'subhub-restart'}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-700/60 text-xs font-medium text-slate-200 transition-colors"
          >
            <RotateCw className={`w-3.5 h-3.5 ${loading === 'subhub-restart' ? 'animate-spin' : ''}`} />
            <span>重启服务</span>
          </button>
          <button
            onClick={() => onServiceAction('subhub', subhub?.running ? 'stop' : 'start')}
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
          {renderUpgrade('warp', 'amber')}
          <button
            onClick={() => onServiceAction('warp', 'restart')}
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
          {onNavigate && (
            <button
              type="button"
              onClick={() => onNavigate('warp')}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-amber-500/15 hover:bg-amber-500/25 border border-amber-500/35 text-xs font-semibold text-amber-300 transition-colors ml-auto"
            >
              <Split className="w-3.5 h-3.5" />
              <span>配置分流规则 →</span>
            </button>
          )}
        </div>
      </div>
    </div>
  );
};

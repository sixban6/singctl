import React, { useState } from 'react';
import { ServerStatusResponse } from '../types';
import { api } from '../api';
import { useToast } from './Toast';
import { Play, Square, RotateCw, FileText, Code2, ExternalLink, CheckCircle2, XCircle, X, Save, Edit3, ShieldCheck, Zap, RefreshCw } from 'lucide-react';

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

  const handleSaveSNI = async () => {
    if (!sniInput.trim()) return;
    setUpdatingSNI(true);
    try {
      const res = await api.updateSNI(sniInput.trim());
      success(res.message);
      setEditingSNI(false);
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
      setTimeout(onRefresh, 1200);
    } catch (err: any) {
      error(err.message || '保存配置失败');
    } finally {
      setSavingConfig(false);
    }
  };

  const singbox = status?.services?.singbox;
  const caddy = status?.services?.caddy;
  const substore = status?.services?.substore;
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

            <div className="mt-4 grid grid-cols-2 gap-2 text-xs font-mono">
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
                <div className="text-slate-500">持续运行</div>
                <div className="text-slate-200 mt-0.5">{singbox?.uptime || '-'}</div>
              </div>
            </div>
          </div>

          <div className="mt-5 pt-4 border-t border-slate-800 flex flex-wrap gap-2">
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

            <div className="mt-4 grid grid-cols-2 gap-2 text-xs font-mono">
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
                <div className="text-slate-500">持续运行</div>
                <div className="text-slate-200 mt-0.5">{caddy?.uptime || '-'}</div>
              </div>
            </div>
          </div>

          <div className="mt-5 pt-4 border-t border-slate-800 flex flex-wrap gap-2">
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
          </div>
        </div>

        {/* Sub-Store Card */}
        <div className="p-5 rounded-2xl glass-card flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between pb-3 border-b border-slate-800">
              <div className="flex items-center gap-2.5">
                <div className="w-8 h-8 rounded-xl bg-purple-500/10 border border-purple-500/20 flex items-center justify-center text-purple-400 font-bold font-mono text-sm">
                  SS
                </div>
                <div>
                  <h3 className="font-semibold text-white text-base">Sub-Store 订阅中枢</h3>
                  <p className="text-xs text-slate-400">Docker 容器化订阅解析与节点下发</p>
                </div>
              </div>
              <div
                className={`flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium border ${
                  substore?.running
                    ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20'
                    : 'bg-rose-500/10 text-rose-400 border-rose-500/20'
                }`}
              >
                {substore?.running ? <CheckCircle2 className="w-3.5 h-3.5" /> : <XCircle className="w-3.5 h-3.5" />}
                <span>{substore?.running ? 'active (运行中)' : 'inactive'}</span>
              </div>
            </div>

            <div className="mt-4 grid grid-cols-2 gap-2 text-xs font-mono">
              <div className="p-2.5 rounded-xl bg-slate-900/60 border border-slate-800">
                <div className="text-slate-500">容器 ID</div>
                <div className="text-slate-200 mt-0.5">{substore?.id || 'sub-store'}</div>
              </div>
              <div className="p-2.5 rounded-xl bg-slate-900/60 border border-slate-800">
                <div className="text-slate-500">内网端口</div>
                <div className="text-slate-200 mt-0.5">3001 (反代保护)</div>
              </div>
            </div>
          </div>

          <div className="mt-5 pt-4 border-t border-slate-800 flex flex-wrap gap-2">
            <button
              onClick={() => handleAction('substore', 'restart')}
              disabled={loading === 'substore-restart'}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-700/60 text-xs font-medium text-slate-200 transition-colors"
            >
              <RotateCw className={`w-3.5 h-3.5 ${loading === 'substore-restart' ? 'animate-spin' : ''}`} />
              <span>重启容器</span>
            </button>
            <button
              onClick={() => onOpenLogs('substore')}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-700/60 text-xs font-medium text-slate-200 transition-colors"
            >
              <FileText className="w-3.5 h-3.5 text-blue-400" />
              <span>容器日志</span>
            </button>
            <a
              href={`https://${status?.config?.substoreDomain || status?.config?.nodeDomain}`}
              target="_blank"
              rel="noreferrer"
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-700/60 text-xs font-medium text-slate-200 transition-colors"
            >
              <ExternalLink className="w-3.5 h-3.5 text-purple-400" />
              <span>打开 Sub-Store</span>
            </a>
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

            <div className="mt-4 grid grid-cols-2 gap-2 text-xs font-mono">
              <div className="p-2.5 rounded-xl bg-slate-900/60 border border-slate-800">
                <div className="text-slate-500">SOCKS5 代理</div>
                <div className="text-slate-200 mt-0.5">127.0.0.1:40000</div>
              </div>
              <div className="p-2.5 rounded-xl bg-slate-900/60 border border-slate-800">
                <div className="text-slate-500">主进程 PID</div>
                <div className="text-slate-200 mt-0.5">{warp?.pid || '-'}</div>
              </div>
            </div>
          </div>

          <div className="mt-5 pt-4 border-t border-slate-800 flex flex-wrap gap-2">
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
                  <h3 className="font-semibold text-white text-base">Reality 伪装与传输安全</h3>
                  <p className="text-xs text-slate-400">TLS 握手伪装域名 (SNI)</p>
                </div>
              </div>
              <span className="px-2.5 py-1 rounded-full text-xs font-mono font-medium bg-purple-500/10 text-purple-400 border border-purple-500/20">
                TLS 1.3 拟态
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-3 leading-relaxed">
              伪装 TLS 握手域名，使节点流量穿透审查时表现为对官方分发站点的正常合法访问。
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
    </div>
  );
};

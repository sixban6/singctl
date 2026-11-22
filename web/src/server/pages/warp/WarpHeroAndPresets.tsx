import React, { useMemo } from 'react';
import {
  WarpDaemonStatus,
  WarpPresetItem,
  WarpRoutingConfig,
  WarpRoutingMode,
} from '../../types';
import {
  AlertTriangle,
  Bot,
  Film,
  PauseCircle,
  RefreshCw,
  RotateCcw,
  Shield,
  ShieldCheck,
  Split,
  Users,
  Wrench,
} from 'lucide-react';

export const WarpHeroAndPresets: React.FC<{
  daemon?: WarpDaemonStatus;
  routing: WarpRoutingConfig;
  presets: WarpPresetItem[];
  dcConnCount: number;
  warpConnCount: number;
  selectedNode: string;
  hasCluster: boolean;
  syncCluster: boolean;
  currentScopeLabel: string;
  saving: boolean;
  acting: 'rekey' | 'ensure' | 'enable_telemetry' | null;
  onModeChange: (mode: WarpRoutingMode) => void;
  onTogglePreset: (presetId: string) => void;
  onWarpAction: (action: 'rekey' | 'ensure') => void;
  onRefreshRouting: () => void;
}> = ({
  daemon,
  routing,
  presets,
  dcConnCount,
  warpConnCount,
  selectedNode,
  hasCluster,
  syncCluster,
  currentScopeLabel,
  saving,
  acting,
  onModeChange,
  onTogglePreset,
  onWarpAction,
  onRefreshRouting,
}) => {
  const groupedPresets = useMemo(() => {
    const groups: { key: string; label: string; icon: React.ReactNode; items: WarpPresetItem[] }[] = [
      { key: 'ai', label: 'AI 大模型', icon: <Bot className="w-4 h-4 text-emerald-400" />, items: [] },
      { key: 'streaming', label: '流媒体与成人内容', icon: <Film className="w-4 h-4 text-amber-400" />, items: [] },
      { key: 'social', label: '社交与防风控', icon: <Users className="w-4 h-4 text-sky-400" />, items: [] },
    ];
    for (const p of presets) {
      const g = groups.find((x) => x.key === p.group);
      if (g) g.items.push(p);
      else groups[2].items.push(p);
    }
    return groups.filter((g) => g.items.length > 0);
  }, [presets]);

  return (
    <>
      {/* 1. 隧道 offline/未安装 防黑洞引导横幅 */}
      {daemon && !daemon.tunnelHealthy && selectedNode !== 'all' && (
        <div className="p-4 sm:p-5 rounded-2xl border border-amber-500/40 bg-amber-950/25 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div className="flex items-start gap-3">
            <div className="p-2 rounded-xl bg-amber-500/15 text-amber-400 border border-amber-500/30 shrink-0">
              <AlertTriangle className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-sm font-bold text-amber-200">
                [{currentScopeLabel}] WARP 隧道 (127.0.0.1:40000) 当前未就绪
              </h3>
              <p className="text-xs text-amber-200/80 mt-1">
                {daemon.error || 'wireproxy 尚未安装或已停止运行'}
                。为防止流量切换后断网，系统已自动开启防黑洞保护，请先一键部署或拉起 WARP 服务。
              </p>
            </div>
          </div>
          <button
            type="button"
            onClick={() => onWarpAction('ensure')}
            disabled={acting === 'ensure'}
            className="flex items-center justify-center gap-1.5 px-4 py-2.5 rounded-xl bg-amber-500 hover:bg-amber-400 text-slate-950 font-semibold text-xs transition-all shrink-0 disabled:opacity-50"
          >
            <Wrench className={`w-3.5 h-3.5 ${acting === 'ensure' ? 'animate-spin' : ''}`} />
            <span>{acting === 'ensure' ? '正在部署修复...' : '一键部署 / 修复该节点 WARP'}</span>
          </button>
        </div>
      )}

      {/* 1.5 后台巡检自动熔断降级保护横幅 */}
      {daemon?.degradedFallback && (
        <div className="p-4 sm:p-5 rounded-2xl border border-sky-500/40 bg-sky-950/25 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div className="flex items-start gap-3">
            <div className="p-2 rounded-xl bg-sky-500/15 text-sky-400 border border-sky-500/30 shrink-0">
              <ShieldCheck className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-sm font-bold text-sky-200 flex items-center gap-2 flex-wrap">
                <span>自动熔断保护生效中：已临时切回原生直出 (DC)</span>
                {daemon.lastHealedAt && (
                  <span className="px-2 py-0.5 rounded bg-sky-500/10 border border-sky-500/30 text-[10px] font-mono text-sky-300">
                    {daemon.lastHealedAt}
                  </span>
                )}
              </h3>
              <p className="text-xs text-sky-200/80 mt-1">
                {daemon.autoHealStatus ||
                  'WARP 出口异常且多节点自动重连未恢复，系统已临时降级至 DC 直出保障 x.com/AI 不断网，原有配置已安全保留，后台探测恢复后将自动回切。'}
              </p>
            </div>
          </div>
          <button
            type="button"
            onClick={() => onWarpAction('rekey')}
            disabled={acting !== null}
            className="flex items-center justify-center gap-1.5 px-4 py-2.5 rounded-xl bg-sky-500 hover:bg-sky-400 text-slate-950 font-semibold text-xs transition-all shrink-0 disabled:opacity-50"
          >
            <RotateCcw className={`w-3.5 h-3.5 ${acting === 'rekey' ? 'animate-spin' : ''}`} />
            <span>{acting === 'rekey' ? '正在重试换 IP...' : '立即更换 WARP IP 尝试恢复'}</span>
          </button>
        </div>
      )}

      {/* 2. 顶部双出口态势与全局分流模式 Hero Bar */}
      <div className="p-5 rounded-2xl glass-card space-y-5">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          {/* 左侧：WARP 隧道信息与换 IP 操作 */}
          <div className="space-y-2.5">
            <div className="flex flex-wrap items-center gap-2.5">
              <div className="p-2 rounded-xl bg-amber-500/10 text-amber-400 border border-amber-500/20">
                <Split className="w-5 h-5" />
              </div>
              <div>
                <h2 className="text-lg font-semibold text-white tracking-tight flex items-center gap-2 flex-wrap">
                  <span>WARP 智能分流中心</span>
                  {hasCluster && (
                    <span className="px-2.5 py-0.5 rounded-full text-[11px] font-mono bg-amber-500/10 text-amber-200 border border-amber-500/30">
                      {selectedNode === 'all'
                        ? '🌐 全集群统一编排'
                        : syncCluster
                        ? `🎯 ${currentScopeLabel} + 全集群同步`
                        : `🖥 当前控制: ${currentScopeLabel}`}
                    </span>
                  )}
                  <span
                    className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-[11px] font-mono border ${
                      daemon?.tunnelHealthy
                        ? 'bg-emerald-500/10 text-emerald-300 border-emerald-500/25'
                        : 'bg-rose-500/10 text-rose-300 border-rose-500/25'
                    }`}
                  >
                    <span
                      className={`w-1.5 h-1.5 rounded-full ${
                        daemon?.tunnelHealthy ? 'bg-emerald-400 animate-pulse' : 'bg-rose-400'
                      }`}
                    />
                    {selectedNode === 'all'
                      ? daemon?.warpIp || '集群探测中'
                      : daemon?.tunnelHealthy
                      ? '127.0.0.1:40000 就绪'
                      : '隧道未连通'}
                  </span>
                  {saving && (
                    <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[11px] font-mono bg-sky-500/10 text-sky-300 border border-sky-500/25">
                      <RefreshCw className="w-3 h-3 animate-spin" />
                      正在热更新...
                    </span>
                  )}
                </h2>
                <p className="text-xs text-slate-400 mt-0.5">
                  {selectedNode === 'all' || syncCluster
                    ? '当前更改将并发下发至主控与全部就绪子节点，每台节点自动保护各自域名并执行零断流热重载'
                    : '采用 SIGHUP 零断流热重载 + 逐流精准切换，修改域名/预设后毫秒级生效且不影响其它活跃连接'}
                </p>
              </div>
            </div>

            <div className="flex flex-wrap items-center gap-2 text-xs font-mono">
              <span className="px-2.5 py-1 rounded-lg bg-slate-950/70 border border-slate-800 text-amber-300 break-all sm:break-normal">
                WARP 出口: {daemon?.warpIp ? `${daemon.warpIp}${daemon.warpLoc ? ` (${daemon.warpLoc})` : ''}` : '待探测'}
              </span>
              <span className="px-2.5 py-1 rounded-lg bg-slate-950/70 border border-slate-800 text-sky-300">
                直出 DC: {dcConnCount} 连
              </span>
              <span className="px-2.5 py-1 rounded-lg bg-slate-950/70 border border-slate-800 text-amber-300">
                WARP 分流: {warpConnCount} 连
              </span>
              <button
                type="button"
                onClick={() => onWarpAction('rekey')}
                disabled={acting !== null || !daemon?.installed}
                className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-700/70 text-slate-200 transition-colors disabled:opacity-40"
                title="重新注册 WireGuard 身份以更换全新 Cloudflare WARP 出口 IP（失败自动回滚）"
              >
                <RotateCcw className={`w-3 h-3 text-amber-400 ${acting === 'rekey' ? 'animate-spin' : ''}`} />
                <span>
                  {acting === 'rekey' ? '正在换 IP...' : selectedNode === 'all' ? '全集群换 IP' : '更换 WARP IP'}
                </span>
              </button>
              <button
                type="button"
                onClick={onRefreshRouting}
                className="inline-flex items-center gap-1 px-2.5 py-1 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-700/70 text-slate-300 transition-colors"
              >
                <RefreshCw className="w-3 h-3" />
                <span>刷新</span>
              </button>
              {!daemon?.degradedFallback && daemon?.autoHealStatus && (
                <span
                  className="inline-flex items-center gap-1 px-2.5 py-1 rounded-lg bg-emerald-500/10 border border-emerald-500/25 text-emerald-300 text-[11px]"
                  title={daemon.lastHealedAt ? `时间: ${daemon.lastHealedAt}` : undefined}
                >
                  <ShieldCheck className="w-3 h-3 shrink-0" />
                  <span>{daemon.autoHealStatus}</span>
                </span>
              )}
            </div>
          </div>

          {/* 右侧：三段式全局分流模式切换器 */}
          <div className="flex flex-col items-stretch sm:items-end gap-2 shrink-0">
            <div className="inline-flex flex-wrap sm:flex-nowrap p-1 rounded-xl bg-slate-950/90 border border-slate-800 gap-1">
              <button
                type="button"
                onClick={() => onModeChange('split')}
                className={`flex items-center justify-center gap-1.5 px-3 py-2 rounded-lg text-xs font-semibold transition-all ${
                  routing.mode === 'split'
                    ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/35 shadow-sm'
                    : 'text-slate-400 hover:text-slate-200 border border-transparent'
                }`}
              >
                <Split className="w-3.5 h-3.5" />
                <span>原生优先 · 按需分流</span>
              </button>
              <button
                type="button"
                onClick={() => onModeChange('global_warp')}
                className={`flex items-center justify-center gap-1.5 px-3 py-2 rounded-lg text-xs font-semibold transition-all ${
                  routing.mode === 'global_warp'
                    ? 'bg-amber-500/20 text-amber-300 border border-amber-500/35 shadow-sm'
                    : 'text-slate-400 hover:text-slate-200 border border-transparent'
                }`}
              >
                <Shield className="w-3.5 h-3.5" />
                <span>全局 WARP 接管</span>
              </button>
              <button
                type="button"
                onClick={() => onModeChange('bypass')}
                className={`flex items-center justify-center gap-1.5 px-3 py-2 rounded-lg text-xs font-semibold transition-all ${
                  routing.mode === 'bypass'
                    ? 'bg-rose-500/20 text-rose-300 border border-rose-500/35 shadow-sm'
                    : 'text-slate-400 hover:text-slate-200 border border-transparent'
                }`}
              >
                <PauseCircle className="w-3.5 h-3.5" />
                <span>紧急全直出旁路</span>
              </button>
            </div>
            <p className="text-[11px] text-slate-400 text-left sm:text-right">
              {routing.mode === 'split' && '未命中 WARP 规则的流量默认走 VPS 原生直出，兼顾速度与关键服务解锁'}
              {routing.mode === 'global_warp' && '除右下方「强制直出白名单」外，全站出站流量默认经 WARP 隐匿源站 IP'}
              {routing.mode === 'bypass' && '紧急旁路中：所有 WARP 分流规则已临时挂起（配置安全保留，可随时一键恢复）'}
            </p>
          </div>
        </div>
      </div>

      {/* 3. 15 项场景化预设矩阵 */}
      <div className="space-y-4">
        {groupedPresets.map((group) => (
          <div key={group.key} className="p-5 rounded-2xl glass-card space-y-3.5">
            <div className="flex items-center justify-between pb-2.5 border-b border-slate-800/80">
              <div className="flex items-center gap-2">
                {group.icon}
                <h3 className="text-sm font-semibold text-white">{group.label}</h3>
                <span className="px-2 py-0.5 rounded-md bg-slate-900 border border-slate-800 text-[10px] font-mono text-slate-400">
                  {group.items.filter((i) => i.enabled).length} / {group.items.length} 走 WARP
                </span>
              </div>
              {routing.mode === 'bypass' && (
                <span className="text-[11px] font-mono text-rose-300">旁路模式生效中</span>
              )}
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-3">
              {group.items.map((preset) => {
                const isMissAV = preset.id === 'missav';
                const active = preset.enabled;
                return (
                  <div
                    key={preset.id}
                    className={`p-3.5 rounded-xl border transition-all flex flex-col justify-between gap-3 ${
                      active
                        ? 'bg-amber-500/8 border-amber-500/35 shadow-sm shadow-amber-500/5'
                        : 'bg-slate-950/55 border-slate-800/80 hover:border-slate-700'
                    }`}
                  >
                    <div className="space-y-1.5">
                      <div className="flex items-start justify-between gap-2">
                        <div>
                          <div className="flex items-center gap-1.5 flex-wrap">
                            <span className="text-sm font-semibold text-white">{preset.name}</span>
                            {isMissAV && (
                              <span className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-amber-500/15 text-amber-300 border border-amber-500/30">
                                6 域全覆盖
                              </span>
                            )}
                          </div>
                          <p className="text-[11px] text-slate-400 mt-0.5 leading-relaxed">{preset.description}</p>
                        </div>

                        <button
                          type="button"
                          role="switch"
                          aria-checked={active}
                          onClick={() => onTogglePreset(preset.id)}
                          className={`relative inline-flex h-6 w-11 shrink-0 cursor-pointer rounded-full border transition-colors duration-200 focus:outline-none ${
                            active ? 'bg-amber-500 border-amber-400' : 'bg-slate-800 border-slate-700'
                          }`}
                          title={active ? '点击切换回原生直出' : '点击切走 WARP 出口'}
                        >
                          <span
                            className={`pointer-events-none inline-block h-5 w-5 transform rounded-full bg-white shadow transition duration-200 ${
                              active ? 'translate-x-5' : 'translate-x-0'
                            }`}
                          />
                        </button>
                      </div>
                    </div>

                    <div className="flex items-center justify-between gap-2 pt-2 border-t border-slate-800/60 text-[10px] font-mono">
                      <span className="text-slate-500 truncate" title={preset.domainsSummary}>
                        {preset.domainsSummary}
                      </span>
                      <span
                        className={`px-1.5 py-0.5 rounded shrink-0 border ${
                          routing.mode === 'bypass'
                            ? 'bg-slate-900 text-slate-500 border-slate-800'
                            : active
                            ? 'bg-amber-500/15 text-amber-300 border-amber-500/30'
                            : 'bg-sky-500/10 text-sky-300 border-sky-500/25'
                        }`}
                      >
                        {routing.mode === 'bypass' ? '已旁路' : active ? '⚡ WARP' : '原生直出'}
                      </span>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        ))}
      </div>
    </>
  );
};

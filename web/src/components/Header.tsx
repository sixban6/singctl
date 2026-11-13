import React from 'react';
import { Activity, LogOut, ShieldCheck, User } from 'lucide-react';
import { ServerStatusResponse } from '../types';

interface HeaderProps {
  status: ServerStatusResponse | null;
  onLogout: () => void;
  lastOk?: Date | null;
  linkDown?: boolean;
}

export const Header: React.FC<HeaderProps> = ({ status, onLogout, lastOk, linkDown }) => {
  const nodeDomain = status?.config?.nodeDomain || status?.config?.substoreDomain || 'Node Fleet';
  const username = status?.admin?.username || 'singctl';
  const memPercent = status?.system?.memUsagePercent || '0%';
  const loadAvg = status?.system?.loadAvg ? status.system.loadAvg.split(',')[0] : '0.00';

  return (
    <header className="sticky top-0 z-40 w-full border-b border-slate-800/80 bg-slate-950/80 backdrop-blur-xl">
      <div className="max-w-[1440px] mx-auto px-3.5 sm:px-6 lg:px-8 h-14 sm:h-16 flex items-center justify-between gap-2">
        {/* Brand */}
        <div className="flex items-center gap-2.5 sm:gap-3 min-w-0">
          <div className="w-8 h-8 sm:w-9 sm:h-9 rounded-xl bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center shrink-0 glow-green">
            <Activity className="w-4 h-4 sm:w-5 sm:h-5 text-emerald-400" />
          </div>
          <div className="min-w-0">
            <div className="flex items-center gap-1.5 sm:gap-2">
              <span className="font-bold text-sm sm:text-base tracking-tight text-white truncate">服务端控制台</span>
              <span className="text-[10px] sm:text-xs px-1.5 sm:px-2 py-0.5 rounded-full bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 font-mono font-medium shrink-0">
                v{status?.version || '1.0.0'}
              </span>
            </div>
            <p className="text-[11px] text-slate-400 font-mono truncate max-w-[160px] sm:max-w-xs">{nodeDomain}</p>
          </div>
        </div>

        {/* Right Badges & Controls */}
        <div className="flex items-center gap-2 sm:gap-3 shrink-0">
          {/* Quick Metrics: compact on tablet (md), full on desktop (xl) */}
          <div className="hidden md:flex items-center gap-2 text-xs font-mono text-slate-400">
            <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-slate-900 border border-slate-800">
              <span className="text-slate-400">负载</span>
              <span className="text-slate-200 font-semibold">{loadAvg}</span>
            </div>
            <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-slate-900 border border-slate-800">
              <span className="text-slate-400">内存</span>
              <span className="text-slate-200 font-semibold">{memPercent}</span>
            </div>
            <div className="hidden xl:flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-slate-900 border border-slate-800">
              <span className="text-slate-400">{linkDown ? '上次刷新' : '刷新'}</span>
              <span className="text-slate-200 font-semibold">{lastOk ? lastOk.toLocaleTimeString() : '--'}</span>
            </div>
            {status?.system?.bbr && (
              <div className="flex items-center gap-1 px-2 py-1 rounded-lg bg-emerald-950/40 border border-emerald-500/20 text-emerald-400 font-medium">
                <ShieldCheck className="w-3.5 h-3.5" />
                <span>BBR</span>
              </div>
            )}
          </div>

          {/* Mobile quick load/mem pill */}
          <div className="flex md:hidden items-center gap-1 px-2 py-1 rounded-lg bg-slate-900/90 border border-slate-800 text-[10px] font-mono text-slate-300">
            <span>{memPercent}</span>
          </div>

          {/* User Badge + Logout */}
          <div className="flex items-center gap-1.5 sm:gap-2 pl-2 border-l border-slate-800">
            <div className="hidden sm:flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-slate-900 border border-slate-800 text-xs font-mono text-slate-300">
              <User className="w-3.5 h-3.5 text-emerald-400" />
              <span className="font-semibold">{username}</span>
            </div>

            <button
              onClick={onLogout}
              title="退出登录 (关闭浏览器亦自动登出)"
              className="flex items-center gap-1.5 px-2.5 sm:px-3 py-1.5 rounded-lg bg-rose-500/10 hover:bg-rose-500/20 border border-rose-500/20 text-rose-300 text-xs font-medium transition-all"
            >
              <LogOut className="w-3.5 h-3.5" />
              <span className="hidden sm:inline">退出</span>
            </button>
          </div>
        </div>
      </div>
    </header>
  );
};

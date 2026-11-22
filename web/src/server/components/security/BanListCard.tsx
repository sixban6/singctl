import React, { useMemo, useState } from 'react';
import { BannedIP } from '../../types';
import { AlertOctagon, RefreshCw, ShieldCheck, Unlock } from 'lucide-react';

export const BanListCard: React.FC<{
  bans: BannedIP[];
  loadingBans: boolean;
  unbanningIP: string | null;
  onRefreshBans: () => void;
  onUnban: (ip: string) => void;
}> = ({ bans, loadingBans, unbanningIP, onRefreshBans, onUnban }) => {
  const [banSourceFilter, setBanSourceFilter] = useState<'all' | 'login_fail' | 'manual_sniff'>('all');

  const loginBanCount = useMemo(
    () => bans.filter((b) => (b.source || 'login_fail') !== 'manual_sniff').length,
    [bans],
  );
  const manualBanCount = useMemo(() => bans.filter((b) => b.source === 'manual_sniff').length, [bans]);
  const filteredBans = useMemo(() => {
    if (banSourceFilter === 'all') return bans;
    if (banSourceFilter === 'manual_sniff') return bans.filter((b) => b.source === 'manual_sniff');
    return bans.filter((b) => (b.source || 'login_fail') !== 'manual_sniff');
  }, [bans, banSourceFilter]);

  return (
    <div className="p-4 sm:p-6 rounded-2xl glass-card">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-4 border-b border-slate-800">
        <div>
          <div className="flex items-center gap-2 text-rose-400 text-xs font-semibold uppercase tracking-wider mb-1">
            <AlertOctagon className="w-3.5 h-3.5" />
            <span>智能防御与封禁池明细</span>
          </div>
          <h3 className="text-lg sm:text-xl font-bold text-white tracking-tight flex flex-wrap items-center gap-2">
            <span>安全封禁与防爆破看板</span>
            {bans.length > 0 ? (
              <>
                <span className="px-2.5 py-0.5 rounded-full bg-rose-500/20 text-rose-300 border border-rose-500/30 text-xs font-semibold">
                  密码试错拦截: {loginBanCount}
                </span>
                <span className="px-2.5 py-0.5 rounded-full bg-amber-500/15 text-amber-300 border border-amber-500/30 text-xs font-semibold">
                  嗅探手动拉黑: {manualBanCount}
                </span>
              </>
            ) : (
              <span className="px-2.5 py-0.5 rounded-full bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 text-xs font-semibold">
                全绿无拦截
              </span>
            )}
          </h3>
          <p className="text-xs text-slate-400 mt-0.5">
            清晰区分「后台输错密码 3 次自动封锁 15 分钟」与「嗅探雷达手动拉黑 7 天」；点击解封将全链路清理内核防火墙与限流表。
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2 self-start sm:self-auto">
          {bans.length > 0 && (
            <div className="inline-flex rounded-xl bg-slate-950 border border-slate-800 p-0.5 text-xs">
              {[
                { id: 'all', label: `全部 (${bans.length})` },
                { id: 'login_fail', label: `密码试错 (${loginBanCount})` },
                { id: 'manual_sniff', label: `嗅探手动 (${manualBanCount})` },
              ].map((tab) => (
                <button
                  key={tab.id}
                  type="button"
                  onClick={() => setBanSourceFilter(tab.id as any)}
                  className={`px-2.5 py-1 rounded-lg transition-colors ${
                    banSourceFilter === tab.id ? 'bg-slate-800 text-white font-semibold' : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  {tab.label}
                </button>
              ))}
            </div>
          )}
          <button
            onClick={onRefreshBans}
            disabled={loadingBans}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-xl bg-slate-900 hover:bg-slate-800 border border-slate-800 text-xs text-slate-300 transition-all disabled:opacity-50"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loadingBans ? 'animate-spin' : ''}`} />
            <span>刷新列表</span>
          </button>
          {bans.length > 0 && (
            <button
              onClick={() => onUnban('all')}
              disabled={unbanningIP === 'all'}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-xl bg-rose-500/20 hover:bg-rose-500/30 border border-rose-500/30 text-xs text-rose-200 font-semibold transition-all disabled:opacity-50"
            >
              <Unlock className="w-3.5 h-3.5" />
              <span>全链路解封全部</span>
            </button>
          )}
        </div>
      </div>

      <div className="mt-4">
        {filteredBans.length === 0 ? (
          <div className="py-8 text-center rounded-xl bg-slate-950/40 border border-slate-800/80">
            <ShieldCheck className="w-9 h-9 text-emerald-400 mx-auto mb-2 opacity-80" />
            <div className="text-sm font-semibold text-slate-200">
              {bans.length === 0 ? '当前系统安全，无活跃封禁 IP' : '当前筛选分类下暂无记录'}
            </div>
            <p className="text-xs text-slate-500 mt-1 max-w-md mx-auto px-3">
              实时守护运行中。无论是后台密码爆破拦截还是嗅探雷达手动拉黑，均在此处透明区分来源并支持全链路解封。
            </p>
          </div>
        ) : (
          <>
            {/* Mobile Stacked Cards (< 768px) */}
            <div className="md:hidden space-y-2.5">
              {filteredBans.map((b) => {
                const isManual = b.source === 'manual_sniff';
                return (
                  <div
                    key={b.ip}
                    className="p-3.5 rounded-xl bg-slate-950/70 border border-slate-800 space-y-2 text-xs font-mono"
                  >
                    <div className="flex items-center justify-between gap-2">
                      <span className="text-white font-semibold break-all">{b.ip}</span>
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-sans font-semibold shrink-0 border ${
                          isManual
                            ? 'bg-amber-500/15 text-amber-300 border-amber-500/30'
                            : 'bg-rose-500/20 text-rose-300 border-rose-500/30'
                        }`}
                      >
                        {b.sourceLabel || (isManual ? '嗅探手动封禁' : '密码试错拦截')}
                      </span>
                    </div>
                    {(b.flag || b.geo || b.isp) && (
                      <div className="text-[11px] text-slate-400 font-sans">
                        {b.flag} {b.geo} {b.isp ? `· ${b.isp}` : ''}
                      </div>
                    )}
                    {b.reason && <div className="text-[11px] text-slate-400 font-sans">原因: {b.reason}</div>}
                    <div className="flex items-center justify-between pt-1">
                      <span className="text-amber-300 text-[11px]">
                        剩余 {b.remainingText || `约 ${b.remainingMinutes} 分钟`}
                      </span>
                      <button
                        onClick={() => onUnban(b.ip)}
                        disabled={unbanningIP === b.ip}
                        className="px-3 py-1.5 rounded-lg bg-emerald-500/20 border border-emerald-500/30 text-emerald-300 text-xs font-sans font-medium"
                      >
                        {unbanningIP === b.ip ? '解封中...' : '全链路解封'}
                      </button>
                    </div>
                  </div>
                );
              })}
            </div>

            {/* Desktop Table (>= 768px) */}
            <div className="hidden md:block overflow-x-auto">
              <table className="w-full text-left text-xs font-mono">
                <thead>
                  <tr className="border-b border-slate-800 text-slate-400">
                    <th className="py-2.5 px-3">受限源 IP</th>
                    <th className="py-2.5 px-3">封禁来源与原因</th>
                    <th className="py-2.5 px-3">剩余时长 / 解封时间</th>
                    <th className="py-2.5 px-3 text-right">运维操作</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60">
                  {filteredBans.map((b) => {
                    const isManual = b.source === 'manual_sniff';
                    return (
                      <tr key={b.ip} className="hover:bg-slate-900/40 transition-colors">
                        <td className="py-3 px-3 text-white font-semibold">
                          <div className="flex items-center gap-2 flex-wrap">
                            <span
                              className={`w-2 h-2 rounded-full shrink-0 ${
                                isManual ? 'bg-amber-400' : 'bg-rose-500 animate-pulse'
                              }`}
                            ></span>
                            <span>{b.ip}</span>
                            {(b.flag || b.geo || b.isp) && (
                              <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md bg-slate-800/90 border border-slate-700/60 text-[10px] text-slate-300 font-sans font-normal">
                                {b.flag && <span>{b.flag}</span>}
                                {b.geo && <span>{b.geo}</span>}
                                {b.isp && <span className="text-slate-500">· {b.isp}</span>}
                              </span>
                            )}
                          </div>
                        </td>
                        <td className="py-3 px-3 font-sans">
                          <div className="flex items-center gap-2 flex-wrap">
                            <span
                              className={`px-2 py-0.5 rounded-md text-[11px] font-semibold border ${
                                isManual
                                  ? 'bg-amber-500/15 text-amber-300 border-amber-500/30'
                                  : 'bg-rose-500/20 text-rose-300 border-rose-500/30'
                              }`}
                            >
                              {b.sourceLabel || (isManual ? '嗅探手动封禁' : '密码试错拦截')}
                            </span>
                            <span className="text-slate-400 text-xs">
                              {b.reason || (isManual ? '嗅探雷达手动拉黑 (nftables + 429)' : '后台登录密码连续输错')}
                            </span>
                          </div>
                        </td>
                        <td className="py-3 px-3">
                          <div className="text-amber-300 font-medium">
                            {b.remainingText || `约 ${b.remainingMinutes} 分钟`}
                          </div>
                          {b.bannedUntil && <div className="text-[11px] text-slate-500">至 {b.bannedUntil}</div>}
                        </td>
                        <td className="py-3 px-3 text-right">
                          <button
                            onClick={() => onUnban(b.ip)}
                            disabled={unbanningIP === b.ip}
                            className="px-3 py-1.5 rounded-lg bg-emerald-500/20 hover:bg-emerald-500/30 border border-emerald-500/30 text-emerald-300 text-xs font-sans font-medium transition-all disabled:opacity-50"
                          >
                            {unbanningIP === b.ip ? '正在解封...' : '全链路解封'}
                          </button>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </>
        )}
      </div>
    </div>
  );
};

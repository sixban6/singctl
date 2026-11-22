import React from 'react';
import { SubscriptionAccessLogItem, SubscriptionRiskSummary } from '../../types';
import { Ban, KeyRound, RefreshCw, ShieldAlert, ShieldCheck, Trash2 } from 'lucide-react';

export const AccessAuditCard: React.FC<{
  auditLogs: SubscriptionAccessLogItem[];
  riskSummary: SubscriptionRiskSummary | null;
  bannedIps: Set<string>;
  blockingIP: string | null;
  loadingAudit: boolean;
  clearingAudit: boolean;
  rotatingKey: boolean;
  onRefreshAudit: () => void;
  onClearAudit: () => void;
  onRotateKey: () => void;
  onBlockIP: (ip: string) => void;
}> = ({
  auditLogs,
  riskSummary,
  bannedIps,
  blockingIP,
  loadingAudit,
  clearingAudit,
  rotatingKey,
  onRefreshAudit,
  onClearAudit,
  onRotateKey,
  onBlockIP,
}) => {
  return (
    <div className="p-5 rounded-2xl glass-card space-y-4">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-slate-800">
        <div>
          <h3 className="text-sm font-semibold text-white flex items-center gap-2">
            <ShieldCheck className="w-4 h-4 text-emerald-400" />
            <span>订阅拉取防盗刷审计 (Access Audit)</span>
            {auditLogs.some((item) => item.status === 'denied') && (
              <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-mono bg-rose-500/15 text-rose-300 border border-rose-500/30">
                <ShieldAlert className="w-3 h-3" />
                检测到异常探测
              </span>
            )}
          </h3>
          <p className="text-xs text-slate-400 mt-0.5">
            自动记录每次客户端订阅拉取与错误密钥试探（保留最近 100 条）。如发现陌生海外 IP 盗刷，点击顶部「轮换密钥」即可一键熔断旧链接
          </p>
        </div>

        <div className="flex items-center gap-2 shrink-0">
          <button
            type="button"
            onClick={onRefreshAudit}
            disabled={loadingAudit}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-xl bg-slate-900 hover:bg-slate-800 border border-slate-700/70 text-xs text-slate-200 transition-colors"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loadingAudit ? 'animate-spin' : ''}`} />
            <span>刷新审计</span>
          </button>
          {auditLogs.length > 0 && (
            <button
              type="button"
              onClick={onClearAudit}
              disabled={clearingAudit}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-xl bg-rose-500/10 hover:bg-rose-500/20 border border-rose-500/25 text-xs text-rose-300 transition-colors disabled:opacity-50"
            >
              <Trash2 className="w-3.5 h-3.5" />
              <span>清空记录</span>
            </button>
          )}
        </div>
      </div>

      {riskSummary && riskSummary.level !== 'safe' && (
        <div
          className={`p-3.5 rounded-xl border flex flex-col sm:flex-row sm:items-center justify-between gap-3 ${
            riskSummary.level === 'high'
              ? 'bg-rose-500/10 border-rose-500/35 text-rose-200'
              : 'bg-amber-500/10 border-amber-500/30 text-amber-200'
          }`}
        >
          <div className="space-y-1">
            <div className="flex items-center gap-2 text-xs font-bold">
              <ShieldAlert className="w-4 h-4 shrink-0" />
              <span>
                {riskSummary.level === 'high'
                  ? '高危防盗刷告警：检测到疑似订阅泄露或爬虫批量拉取'
                  : '订阅访问风险提示：检测到多地域或非标客户端拉取'}
              </span>
              <span className="px-2 py-0.5 rounded-full bg-slate-950/60 text-[10px] font-mono">
                24h 独立 IP: {riskSummary.uniqueIps24h} · 国家/地区: {riskSummary.uniqueCountries24h}
              </span>
            </div>
            <ul className="text-[11px] opacity-90 list-disc list-inside space-y-0.5">
              {riskSummary.reasons.map((r, i) => (
                <li key={i}>{r}</li>
              ))}
            </ul>
          </div>
          <button
            type="button"
            onClick={onRotateKey}
            disabled={rotatingKey}
            className="inline-flex items-center justify-center gap-1.5 px-3.5 py-2 rounded-xl bg-rose-500 hover:bg-rose-600 text-white text-xs font-bold shrink-0 transition-colors disabled:opacity-50"
          >
            <KeyRound className="w-3.5 h-3.5" />
            <span>{rotatingKey ? '正在轮换...' : '立即轮换密钥熔断'}</span>
          </button>
        </div>
      )}

      {auditLogs.length === 0 ? (
        <div className="p-6 text-center text-xs text-slate-500 bg-slate-950/40 rounded-xl border border-slate-800/70 font-mono">
          暂无客户端订阅拉取记录。当手机或桌面客户端更新订阅时，此处将实时记录设备软件类型与来源地区
        </div>
      ) : (
        <>
          {/* Mobile Stacked Audit Cards (< 768px) */}
          <div className="md:hidden space-y-2">
            {auditLogs.slice(0, 25).map((log, idx) => {
              const formattedTime = (() => {
                const d = new Date(log.timestamp);
                return Number.isNaN(d.getTime()) ? log.timestamp : d.toLocaleString();
              })();
              const isDenied = log.status === 'denied';
              return (
                <div
                  key={`m-${log.timestamp}-${idx}`}
                  className="p-3 rounded-xl bg-slate-950/60 border border-slate-800/80 space-y-1.5 text-xs font-mono"
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="px-2 py-0.5 rounded bg-slate-900 border border-slate-700/80 text-slate-200 text-[11px] truncate">
                      {log.clientApp || 'Unknown'} · {log.target}
                    </span>
                    {isDenied ? (
                      <span className="px-2 py-0.5 rounded text-[10px] bg-rose-500/15 text-rose-300 border border-rose-500/30 shrink-0">
                        密钥拦截
                      </span>
                    ) : (
                      <span className="px-2 py-0.5 rounded text-[10px] bg-emerald-500/10 text-emerald-400 border border-emerald-500/25 shrink-0">
                        正常下发
                      </span>
                    )}
                  </div>
                  <div className="flex flex-wrap items-center justify-between gap-1 text-[11px] text-slate-400">
                    <span>
                      {log.flag || '🌐'} {log.ip || '-'} {log.geo ? `(${log.geo})` : ''}
                    </span>
                    <div className="flex items-center gap-2">
                      <span>{formattedTime}</span>
                      {log.ip &&
                        (bannedIps.has(log.ip) ? (
                          <span className="px-1.5 py-0.5 rounded bg-rose-500/20 text-rose-300 text-[10px] font-sans">
                            已拉黑
                          </span>
                        ) : (
                          <button
                            type="button"
                            onClick={() => onBlockIP(log.ip)}
                            disabled={blockingIP === log.ip}
                            className="px-2 py-0.5 rounded bg-rose-500/15 border border-rose-500/30 text-rose-300 text-[10px] font-sans"
                          >
                            {blockingIP === log.ip ? '拉黑中...' : '拉黑'}
                          </button>
                        ))}
                    </div>
                  </div>
                </div>
              );
            })}
          </div>

          {/* Desktop Table (>= 768px) */}
          <div className="hidden md:block overflow-x-auto">
            <table className="w-full text-left border-collapse text-xs">
              <thead>
                <tr className="border-b border-slate-800/80 text-[11px] text-slate-400 font-mono">
                  <th className="py-2.5 pr-3">拉取时间</th>
                  <th className="py-2.5 px-3">客户端软件</th>
                  <th className="py-2.5 px-3">来源 IP / 地区</th>
                  <th className="py-2.5 px-3">转换目标</th>
                  <th className="py-2.5 pl-3 text-right">状态</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/50 font-mono">
                {auditLogs.slice(0, 25).map((log, idx) => {
                  const formattedTime = (() => {
                    const d = new Date(log.timestamp);
                    return Number.isNaN(d.getTime()) ? log.timestamp : d.toLocaleString();
                  })();
                  const isDenied = log.status === 'denied';
                  return (
                    <tr key={`${log.timestamp}-${idx}`} className="hover:bg-slate-900/40 transition-colors">
                      <td className="py-2.5 pr-3 text-slate-400 whitespace-nowrap">{formattedTime}</td>
                      <td className="py-2.5 px-3 whitespace-nowrap">
                        <span
                          className="px-2 py-0.5 rounded-md bg-slate-900 border border-slate-700/80 text-slate-200 text-[11px]"
                          title={log.userAgent || ''}
                        >
                          {log.clientApp || 'Unknown'}
                        </span>
                      </td>
                      <td className="py-2.5 px-3 whitespace-nowrap text-slate-200">
                        <span className="mr-1.5">{log.flag || '🌐'}</span>
                        <span>{log.ip || '-'}</span>
                        {log.geo && <span className="text-slate-500 ml-1.5">({log.geo})</span>}
                      </td>
                      <td className="py-2.5 px-3 whitespace-nowrap text-slate-300">
                        <span>{log.target}</span>
                        {!isDenied && log.nodeCount > 0 && (
                          <span className="text-slate-500 ml-1.5">· {log.nodeCount} 节点</span>
                        )}
                      </td>
                      <td className="py-2.5 pl-3 text-right whitespace-nowrap">
                        <div className="inline-flex items-center justify-end gap-1.5">
                          {isDenied ? (
                            <span className="px-2 py-0.5 rounded-md text-[10px] bg-rose-500/15 text-rose-300 border border-rose-500/30">
                              密钥拦截
                            </span>
                          ) : (
                            <span className="px-2 py-0.5 rounded-md text-[10px] bg-emerald-500/10 text-emerald-400 border border-emerald-500/25">
                              正常下发
                            </span>
                          )}
                          {log.ip &&
                            (bannedIps.has(log.ip) ? (
                              <span className="px-2 py-0.5 rounded-md text-[10px] bg-slate-800 text-slate-400 border border-slate-700 font-sans">
                                已拉黑
                              </span>
                            ) : (
                              <button
                                type="button"
                                onClick={() => onBlockIP(log.ip)}
                                disabled={blockingIP === log.ip}
                                className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md text-[10px] bg-rose-500/15 hover:bg-rose-500/25 text-rose-300 border border-rose-500/30 font-sans transition-colors disabled:opacity-50"
                                title="将该 IP 加入全集群防火墙黑名单"
                              >
                                <Ban className="w-2.5 h-2.5" />
                                <span>{blockingIP === log.ip ? '拉黑中...' : '拉黑 IP'}</span>
                              </button>
                            ))}
                        </div>
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
  );
};

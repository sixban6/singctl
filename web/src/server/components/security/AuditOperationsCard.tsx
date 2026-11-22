import React, { useMemo, useState } from 'react';
import { AuditLogItem } from '../../types';
import { ClipboardList, RefreshCw, ShieldAlert } from 'lucide-react';
import { inferAuditCategory } from './helpers';

export const AuditOperationsCard: React.FC<{
  auditLogs: AuditLogItem[];
  loadingAudit: boolean;
  onRefreshAuditLogs: () => void;
}> = ({ auditLogs, loadingAudit, onRefreshAuditLogs }) => {
  const [auditCategoryFilter, setAuditCategoryFilter] = useState<string>('all');

  const filteredAuditLogs = useMemo(() => {
    if (auditCategoryFilter === 'all') return auditLogs;
    return auditLogs.filter((l) => inferAuditCategory(l) === auditCategoryFilter);
  }, [auditLogs, auditCategoryFilter]);

  return (
    <>
      <div className="p-4 sm:p-6 rounded-2xl glass-card">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-4 border-b border-slate-800">
          <div>
            <div className="flex items-center gap-2 text-indigo-400 text-xs font-semibold uppercase tracking-wider mb-1">
              <ClipboardList className="w-3.5 h-3.5" />
              <span>操作审计与合规追溯</span>
            </div>
            <h3 className="text-lg sm:text-xl font-bold text-white tracking-tight flex items-center gap-2">
              <span>最近管理操作</span>
              <span className="px-2.5 py-0.5 rounded-full bg-indigo-500/10 text-indigo-300 border border-indigo-500/20 text-xs font-semibold">
                {auditCategoryFilter === 'all'
                  ? `共 ${auditLogs.length} 条记录`
                  : `筛选 ${filteredAuditLogs.length} / ${auditLogs.length} 条`}
              </span>
            </h3>
            <p className="text-xs text-slate-400 mt-0.5">
              保留最近 200 条关键管理操作的时间、动作与来源 IP，绝不记录任何明文密码或会话秘钥。
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2 self-start sm:self-auto">
            <div className="flex flex-wrap gap-1 bg-slate-950 border border-slate-800 rounded-xl p-0.5 text-xs">
              {[
                { id: 'all', label: '全部' },
                { id: 'login', label: '登录认证' },
                { id: 'security', label: '安全封禁' },
                { id: 'fleet', label: '舰队编排' },
                { id: 'subscription', label: '订阅管理' },
                { id: 'service', label: '服务运维' },
              ].map((cat) => (
                <button
                  key={cat.id}
                  type="button"
                  onClick={() => setAuditCategoryFilter(cat.id)}
                  className={`px-2 py-1 rounded-lg transition-colors ${
                    auditCategoryFilter === cat.id
                      ? 'bg-indigo-500/25 text-indigo-200 font-semibold'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  {cat.label}
                </button>
              ))}
            </div>
            <button
              onClick={onRefreshAuditLogs}
              disabled={loadingAudit}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-xl bg-slate-900 hover:bg-slate-800 border border-slate-800 text-xs text-slate-300 transition-all disabled:opacity-50"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${loadingAudit ? 'animate-spin' : ''}`} />
              <span>刷新记录</span>
            </button>
          </div>
        </div>

        <div className="mt-4">
          {filteredAuditLogs.length === 0 ? (
            <div className="py-8 text-center rounded-xl bg-slate-950/40 border border-slate-800/80">
              <ClipboardList className="w-9 h-9 text-slate-600 mx-auto mb-2 opacity-80" />
              <div className="text-sm font-semibold text-slate-400">暂无匹配的管理操作记录</div>
            </div>
          ) : (
            <>
              {/* Mobile Stacked Audit Cards (< 768px) */}
              <div className="md:hidden space-y-2 max-h-80 overflow-y-auto pr-1">
                {filteredAuditLogs.map((log, idx) => (
                  <div
                    key={`${log.time}-${idx}`}
                    className="p-3 rounded-xl bg-slate-950/60 border border-slate-800/80 space-y-1 text-xs"
                  >
                    <div className="font-medium text-slate-100 break-words">{log.action}</div>
                    <div className="flex flex-wrap items-center justify-between gap-1 text-[11px] font-mono text-slate-400">
                      <span>{log.time}</span>
                      <span className="text-emerald-400">
                        {log.flag ? `${log.flag} ` : ''}
                        {log.ip}
                      </span>
                    </div>
                  </div>
                ))}
              </div>

              {/* Desktop Audit Table (>= 768px) */}
              <div className="hidden md:block overflow-x-auto max-h-96 overflow-y-auto">
                <table className="w-full text-left text-xs font-mono">
                  <thead className="sticky top-0 bg-slate-900/90 backdrop-blur-md z-10">
                    <tr className="border-b border-slate-800 text-slate-400">
                      <th className="py-2.5 px-3">操作时间</th>
                      <th className="py-2.5 px-3">管理动作</th>
                      <th className="py-2.5 px-3 text-right">来源客户端 IP</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60">
                    {filteredAuditLogs.map((log, idx) => (
                      <tr key={`${log.time}-${idx}`} className="hover:bg-slate-900/40 transition-colors">
                        <td className="py-3 px-3 text-slate-400 whitespace-nowrap">{log.time}</td>
                        <td className="py-3 px-3 text-slate-200">
                          <span className="font-sans font-medium text-slate-200">{log.action}</span>
                        </td>
                        <td className="py-3 px-3 text-right whitespace-nowrap">
                          <div className="flex items-center justify-end gap-1.5 flex-wrap">
                            <span className="text-emerald-400 font-semibold">{log.ip}</span>
                            {(log.flag || log.geo || log.isp) && (
                              <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md bg-slate-800/90 border border-slate-700/60 text-[10px] text-slate-300 font-sans font-normal">
                                {log.flag && <span>{log.flag}</span>}
                                {log.geo && <span>{log.geo}</span>}
                                {log.isp && <span className="text-slate-500">· {log.isp}</span>}
                              </span>
                            )}
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </>
          )}
        </div>
      </div>

      {/* Session Security Policy Card */}
      <div className="p-4 sm:p-5 rounded-2xl glass-card flex items-start gap-3.5 border-emerald-500/20 bg-emerald-950/10">
        <div className="p-2.5 rounded-xl bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 shrink-0">
          <ShieldAlert className="w-5 h-5" />
        </div>
        <div>
          <h4 className="font-semibold text-sm text-white">会话安全策略 (纯会话，无长期免密)</h4>
          <p className="text-xs text-slate-300 mt-1 leading-relaxed">
            管理面板采用严苛的 <strong>Session Cookie</strong> 认证。无论在手机 Safari 还是桌面浏览器中，关闭标签页或杀掉后台凭据即失效，并具备{' '}
            <strong>2 小时空闲超时</strong> 自动登出保护。
          </p>
        </div>
      </div>
    </>
  );
};

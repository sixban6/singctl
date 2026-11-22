import React, { useMemo, useState } from 'react';
import { SniffSummary } from '../../types';
import { Ban, RefreshCw, Search, Server, ShieldAlert, ShieldCheck } from 'lucide-react';

export const SniffingDefenseCard: React.FC<{
  sniffSummary: SniffSummary | null;
  loadingSniff: boolean;
  selectedSniffNode: string;
  syncBlockCluster: boolean;
  setSyncBlockCluster: (v: boolean) => void;
  blockingTarget: string | null;
  unbanningIP: string | null;
  onSelectSniffNode: (nodeId: string) => void;
  onRefreshSniffers: () => void;
  onBlockSniffer: (target: string, onClearInput?: () => void) => void;
  onUnban: (ipOrCidr: string) => void;
}> = ({
  sniffSummary,
  loadingSniff,
  selectedSniffNode,
  syncBlockCluster,
  setSyncBlockCluster,
  blockingTarget,
  unbanningIP,
  onSelectSniffNode,
  onRefreshSniffers,
  onBlockSniffer,
  onUnban,
}) => {
  const [sniffTab, setSniffTab] = useState<'ip' | 'subnet' | 'country'>('ip');
  const [sniffSearch, setSniffSearch] = useState('');
  const [sniffStatusFilter, setSniffStatusFilter] = useState<'all' | 'banned' | 'masqueraded' | 'observing'>('all');
  const [sniffSortBy, setSniffSortBy] = useState<'hits' | 'lastSeen' | 'firstSeen'>('lastSeen');
  const [sniffPageSize, setSniffPageSize] = useState<number>(20);
  const [sniffPage, setSniffPage] = useState<number>(1);
  const [manualBlockInput, setManualBlockInput] = useState('');

  const sniffNodeOptions =
    sniffSummary?.nodes && sniffSummary.nodes.length > 0
      ? sniffSummary.nodes
      : [
          {
            id: 'all',
            name: '全集群汇总',
            online: true,
            totalSniffIPs: sniffSummary?.totalSniffIPs || 0,
            totalSubnets: sniffSummary?.totalSubnets || 0,
            totalBanned: sniffSummary?.totalBannedIPs || 0,
          },
          {
            id: 'local',
            name: '本机网关',
            online: true,
            totalSniffIPs: sniffSummary?.totalSniffIPs || 0,
            totalSubnets: sniffSummary?.totalSubnets || 0,
            totalBanned: sniffSummary?.totalBannedIPs || 0,
          },
        ];

  const filteredSniffIPs = useMemo(() => {
    const raw = sniffSummary?.topIPs || [];
    const q = sniffSearch.trim().toLowerCase();
    const filtered = raw.filter((item) => {
      if (sniffStatusFilter !== 'all' && item.status !== sniffStatusFilter) {
        return false;
      }
      if (!q) return true;
      const nodeNames = (item.nodes || []).map((n) => `${n.name} ${n.id} ${n.host || ''}`).join(' ');
      const hay = `${item.ip} ${item.subnet} ${item.vector} ${item.scannerTag || ''} ${item.country || ''} ${
        item.geo || ''
      } ${item.isp || ''} ${nodeNames}`.toLowerCase();
      return hay.includes(q);
    });

    return [...filtered].sort((a, b) => {
      if (sniffSortBy === 'lastSeen') {
        const cmpLast = (b.lastSeen || '').localeCompare(a.lastSeen || '');
        if (cmpLast !== 0) return cmpLast;
      } else if (sniffSortBy === 'firstSeen') {
        const cmpFirst = (b.firstSeen || '').localeCompare(a.firstSeen || '');
        if (cmpFirst !== 0) return cmpFirst;
      }
      if (b.hits !== a.hits) return b.hits - a.hits;
      return (b.lastSeen || '').localeCompare(a.lastSeen || '');
    });
  }, [sniffSummary?.topIPs, sniffSearch, sniffStatusFilter, sniffSortBy]);

  const filteredSniffSubnets = useMemo(() => {
    const raw = sniffSummary?.topSubnets || [];
    const q = sniffSearch.trim().toLowerCase();
    const filtered = raw.filter((sub) => {
      if (sniffStatusFilter === 'banned' && sub.status !== 'banned') return false;
      if (sniffStatusFilter === 'masqueraded' && sub.status === 'banned') return false;
      if (!q) return true;
      const nodeNames = (sub.nodes || []).map((n) => `${n.name} ${n.id}`).join(' ');
      const hay = `${sub.cidr} ${sub.country || ''} ${sub.isp || ''} ${sub.scannerTag || ''} ${(
        sub.sampleIPs || []
      ).join(' ')} ${nodeNames}`.toLowerCase();
      return hay.includes(q);
    });

    return [...filtered].sort((a, b) => {
      if (sniffSortBy === 'lastSeen') {
        const cmpLast = (b.lastSeen || '').localeCompare(a.lastSeen || '');
        if (cmpLast !== 0) return cmpLast;
      } else if (sniffSortBy === 'firstSeen') {
        const cmpFirst = (b.firstSeen || '').localeCompare(a.firstSeen || '');
        if (cmpFirst !== 0) return cmpFirst;
      }
      if (b.uniqueIPs !== a.uniqueIPs) return b.uniqueIPs - a.uniqueIPs;
      return b.totalHits - a.totalHits;
    });
  }, [sniffSummary?.topSubnets, sniffSearch, sniffStatusFilter, sniffSortBy]);

  const totalIPPages = sniffPageSize > 0 ? Math.max(1, Math.ceil(filteredSniffIPs.length / sniffPageSize)) : 1;
  const safeIPPage = Math.min(sniffPage, totalIPPages);
  const pagedSniffIPs =
    sniffPageSize > 0
      ? filteredSniffIPs.slice((safeIPPage - 1) * sniffPageSize, safeIPPage * sniffPageSize)
      : filteredSniffIPs;

  const totalSubnetPages =
    sniffPageSize > 0 ? Math.max(1, Math.ceil(filteredSniffSubnets.length / sniffPageSize)) : 1;
  const safeSubnetPage = Math.min(sniffPage, totalSubnetPages);
  const pagedSniffSubnets =
    sniffPageSize > 0
      ? filteredSniffSubnets.slice((safeSubnetPage - 1) * sniffPageSize, safeSubnetPage * sniffPageSize)
      : filteredSniffSubnets;

  return (
    <div className="p-4 sm:p-6 rounded-2xl glass-card">
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-3 pb-4 border-b border-slate-800">
        <div>
          <div className="flex items-center gap-2 text-amber-400 text-xs font-semibold uppercase tracking-wider mb-1">
            <ShieldAlert className="w-3.5 h-3.5" />
            <span>集群主动探测与嗅探态势感知</span>
          </div>
          <h3 className="text-lg sm:text-xl font-bold text-white tracking-tight flex flex-wrap items-center gap-2">
            <span>集群活跃嗅探追踪与网段防御</span>
            <span className="px-2.5 py-0.5 rounded-full bg-amber-500/15 text-amber-300 border border-amber-500/30 text-xs font-semibold font-mono">
              {sniffSummary?.totalSniffIPs || 0} 嗅探 IP · {sniffSummary?.totalSubnets || 0} 个 /24 段 ·{' '}
              {sniffSummary?.totalCountries || 0} 个国家
            </span>
          </h3>
          <p className="text-xs text-slate-400 mt-0.5">
            支持按全集群或单台主机分视角查看全部嗅探源、首次开始时间与最近活跃时间；自动剔除合法代理客户端，支持一键拉黑单点 IP 或整个{' '}
            <code className="text-amber-300 font-mono">/24</code> 扫描段。
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2 self-start lg:self-auto">
          <div className="inline-flex rounded-xl bg-slate-950/80 p-1 border border-slate-800 text-xs">
            <button
              type="button"
              onClick={() => {
                setSniffTab('ip');
                setSniffPage(1);
              }}
              className={`px-3 py-1 rounded-lg font-medium transition-all ${
                sniffTab === 'ip'
                  ? 'bg-rose-500/20 text-rose-300 border border-rose-500/30'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              活跃嗅探 IP ({sniffSummary?.topIPs?.length || 0})
            </button>
            <button
              type="button"
              onClick={() => {
                setSniffTab('subnet');
                setSniffPage(1);
              }}
              className={`px-3 py-1 rounded-lg font-medium transition-all ${
                sniffTab === 'subnet'
                  ? 'bg-amber-500/20 text-amber-300 border border-amber-500/30'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              活跃嗅探 IP段 ({sniffSummary?.topSubnets?.length || 0})
            </button>
            <button
              type="button"
              onClick={() => setSniffTab('country')}
              className={`px-3 py-1 rounded-lg font-medium transition-all ${
                sniffTab === 'country'
                  ? 'bg-indigo-500/20 text-indigo-300 border border-indigo-500/30'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              活跃嗅探国 ({sniffSummary?.topCountries?.length || 0})
            </button>
          </div>

          <button
            type="button"
            onClick={onRefreshSniffers}
            disabled={loadingSniff}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-xl bg-slate-900 hover:bg-slate-800 border border-slate-800 text-xs text-slate-300 transition-all disabled:opacity-50"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loadingSniff ? 'animate-spin' : ''}`} />
            <span>刷新态势</span>
          </button>
        </div>
      </div>

      {/* Cluster Host Selector Bar */}
      <div className="mt-4 flex flex-wrap items-center gap-2 bg-slate-950/60 p-2.5 rounded-xl border border-slate-800/80">
        <div className="flex items-center gap-1.5 text-xs font-semibold text-slate-400 px-2 shrink-0">
          <Server className="w-3.5 h-3.5 text-emerald-400" />
          <span>查看主机视角:</span>
        </div>
        <div className="flex flex-wrap items-center gap-1.5">
          {sniffNodeOptions.map((node) => {
            const active = selectedSniffNode === node.id;
            return (
              <button
                key={node.id}
                type="button"
                onClick={() => {
                  setSniffPage(1);
                  onSelectSniffNode(node.id);
                }}
                className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition-all ${
                  active
                    ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40 shadow-sm'
                    : 'bg-slate-900/90 hover:bg-slate-800 text-slate-300 border border-slate-800'
                }`}
              >
                <span className={`w-1.5 h-1.5 rounded-full ${node.online !== false ? 'bg-emerald-400' : 'bg-slate-500'}`} />
                <span>{node.name}</span>
                <span className="px-1.5 py-0.2 rounded bg-slate-950/70 text-[10px] font-mono text-slate-300">
                  {node.totalSniffIPs} IP
                </span>
              </button>
            );
          })}
        </div>
      </div>

      {/* Manual Block Input & Filter Toolbar */}
      <div className="mt-3 grid grid-cols-1 xl:grid-cols-12 gap-2.5">
        <div className="xl:col-span-6 flex flex-col sm:flex-row items-stretch sm:items-center gap-2 bg-slate-950/50 p-2.5 rounded-xl border border-slate-800/80">
          <input
            type="text"
            value={manualBlockInput}
            onChange={(e) => setManualBlockInput(e.target.value)}
            placeholder="输入异常嗅探 IP 或 /24 网段 (如 198.51.100.42 或 198.51.100.0/24)"
            className="flex-1 bg-slate-900/90 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-slate-200 placeholder:text-slate-500 focus:outline-none focus:border-rose-500 font-mono"
          />
          <label className="inline-flex items-center gap-1.5 text-[11px] text-slate-300 cursor-pointer select-none px-1 shrink-0">
            <input
              type="checkbox"
              checked={syncBlockCluster}
              onChange={(e) => setSyncBlockCluster(e.target.checked)}
              className="rounded border-slate-700 bg-slate-900 text-rose-500"
            />
            <span>全集群同步拉黑</span>
          </label>
          <button
            type="button"
            onClick={() => onBlockSniffer(manualBlockInput, () => setManualBlockInput(''))}
            disabled={!manualBlockInput.trim() || blockingTarget !== null}
            className="inline-flex items-center justify-center gap-1.5 px-3.5 py-1.5 rounded-lg bg-rose-500/20 hover:bg-rose-500/30 border border-rose-500/30 text-rose-200 text-xs font-semibold transition-all disabled:opacity-50 shrink-0"
          >
            <Ban className="w-3.5 h-3.5" />
            <span>{blockingTarget === manualBlockInput.trim() ? '正在拉黑...' : '一键拉黑'}</span>
          </button>
        </div>

        <div className="xl:col-span-6 flex flex-wrap items-center gap-2 bg-slate-950/50 p-2.5 rounded-xl border border-slate-800/80">
          <div className="relative flex-1 min-w-[160px]">
            <Search className="w-3.5 h-3.5 text-slate-500 absolute left-2.5 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={sniffSearch}
              onChange={(e) => {
                setSniffSearch(e.target.value);
                setSniffPage(1);
              }}
              placeholder="筛选 IP / 网段 / 国家 / 指纹 / 主机..."
              className="w-full bg-slate-900/90 border border-slate-800 rounded-lg pl-8 pr-2.5 py-1.5 text-xs text-slate-200 placeholder:text-slate-500 focus:outline-none focus:border-emerald-500 font-mono"
            />
          </div>

          <select
            value={sniffStatusFilter}
            onChange={(e) => {
              setSniffStatusFilter(e.target.value as any);
              setSniffPage(1);
            }}
            className="bg-slate-900 border border-slate-800 rounded-lg px-2.5 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-emerald-500"
          >
            <option value="all">全部状态</option>
            <option value="banned">已拉黑拦截</option>
            <option value="masqueraded">已回落伪装</option>
            <option value="observing">观察中</option>
          </select>

          <select
            value={sniffSortBy}
            onChange={(e) => {
              setSniffSortBy(e.target.value as any);
              setSniffPage(1);
            }}
            className="bg-slate-900 border border-slate-800 rounded-lg px-2.5 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-emerald-500"
          >
            <option value="lastSeen">按最近时间排序</option>
            <option value="firstSeen">按开始时间排序</option>
            <option value="hits">按命中次数排序</option>
          </select>

          <select
            value={sniffPageSize}
            onChange={(e) => {
              setSniffPageSize(Number(e.target.value));
              setSniffPage(1);
            }}
            className="bg-slate-900 border border-slate-800 rounded-lg px-2.5 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-emerald-500"
          >
            <option value={20}>每页 20 条</option>
            <option value={50}>每页 50 条</option>
            <option value={100}>每页 100 条</option>
            <option value={0}>显示全部</option>
          </select>
        </div>
      </div>

      <div className="mt-4">
        {sniffTab === 'ip' && (
          <>
            {filteredSniffIPs.length === 0 ? (
              <div className="py-8 text-center rounded-xl bg-slate-950/40 border border-slate-800/80">
                <ShieldCheck className="w-9 h-9 text-emerald-400 mx-auto mb-2 opacity-80" />
                <div className="text-sm font-semibold text-slate-200">
                  {sniffSearch || sniffStatusFilter !== 'all'
                    ? '未找到匹配筛选条件的嗅探 IP'
                    : '当前视角未捕获到外部活跃嗅探 IP'}
                </div>
                <p className="text-xs text-slate-500 mt-1 max-w-md mx-auto px-3">
                  当外部扫描器试探高危端口、回落伪装站或爆破密码时，将在此处实时汇总每个 IP 的开始时间、最近时间与受探主机。
                </p>
              </div>
            ) : (
              <>
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-xs font-mono">
                    <thead>
                      <tr className="border-b border-slate-800 text-slate-400">
                        <th className="py-2.5 px-3">活跃嗅探源 IP</th>
                        <th className="py-2.5 px-3">受探主机</th>
                        <th className="py-2.5 px-3">所属 /24 网段</th>
                        <th className="py-2.5 px-3">探测特征与指纹</th>
                        <th className="py-2.5 px-3">命中数</th>
                        <th className="py-2.5 px-3">开始时间 (首次)</th>
                        <th className="py-2.5 px-3">最近时间 (最后)</th>
                        <th className="py-2.5 px-3">当前状态</th>
                        <th className="py-2.5 px-3 text-right">主动防御操作</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800/60">
                      {pagedSniffIPs.map((item) => (
                        <tr key={item.ip} className="hover:bg-slate-900/40 transition-colors">
                          <td className="py-3 px-3 text-white font-semibold">
                            <div className="flex items-center gap-2 flex-wrap">
                              <span>{item.ip}</span>
                              {(item.flag || item.geo || item.isp) && (
                                <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md bg-slate-800/90 border border-slate-700/60 text-[10px] text-slate-300 font-sans font-normal">
                                  {item.flag && <span>{item.flag}</span>}
                                  {item.geo && <span>{item.geo}</span>}
                                  {item.isp && <span className="text-slate-400">· {item.isp}</span>}
                                </span>
                              )}
                            </div>
                          </td>
                          <td className="py-3 px-3 font-sans">
                            <div className="flex flex-wrap gap-1">
                              {(item.nodes && item.nodes.length > 0
                                ? item.nodes
                                : [{ id: 'local', name: '本机网关' }]
                              ).map((n) => (
                                <span
                                  key={n.id}
                                  className="px-2 py-0.5 rounded bg-sky-500/15 text-sky-300 border border-sky-500/30 text-[10px] font-medium whitespace-nowrap"
                                >
                                  {n.name}
                                </span>
                              ))}
                            </div>
                          </td>
                          <td className="py-3 px-3 text-amber-300 whitespace-nowrap">{item.subnet}</td>
                          <td className="py-3 px-3 font-sans">
                            <div className="flex items-center gap-1.5 flex-wrap">
                              {item.scannerTag && (
                                <span className="px-2 py-0.5 rounded bg-purple-500/20 text-purple-300 border border-purple-500/30 text-[10px] font-semibold">
                                  {item.scannerTag}
                                </span>
                              )}
                              <span className="text-slate-300">{item.vector}</span>
                            </div>
                          </td>
                          <td className="py-3 px-3 text-slate-200 whitespace-nowrap">{item.hits} 次</td>
                          <td className="py-3 px-3 text-slate-400 whitespace-nowrap">
                            {item.firstSeen || item.lastSeen || '--'}
                          </td>
                          <td className="py-3 px-3 text-emerald-300 whitespace-nowrap">{item.lastSeen || '--'}</td>
                          <td className="py-3 px-3 whitespace-nowrap">
                            {item.status === 'banned' ? (
                              <span className="px-2 py-0.5 rounded-md bg-rose-500/20 text-rose-300 border border-rose-500/30 text-[11px]">
                                已拉黑拦截
                              </span>
                            ) : item.status === 'masqueraded' ? (
                              <span className="px-2 py-0.5 rounded-md bg-amber-500/15 text-amber-300 border border-amber-500/25 text-[11px]">
                                已回落伪装
                              </span>
                            ) : (
                              <span className="px-2 py-0.5 rounded-md bg-slate-800 text-slate-300 border border-slate-700 text-[11px]">
                                观察中
                              </span>
                            )}
                          </td>
                          <td className="py-3 px-3 text-right whitespace-nowrap">
                            <div className="inline-flex items-center justify-end gap-1.5 flex-wrap">
                              {item.status === 'banned' ? (
                                <button
                                  type="button"
                                  onClick={() => onUnban(item.ip)}
                                  disabled={unbanningIP === item.ip}
                                  className="px-2.5 py-1 rounded-lg bg-emerald-500/20 hover:bg-emerald-500/30 border border-emerald-500/30 text-emerald-300 text-[11px] font-sans font-medium transition-all disabled:opacity-50"
                                >
                                  {unbanningIP === item.ip ? '解封中...' : '解除封禁'}
                                </button>
                              ) : (
                                <button
                                  type="button"
                                  onClick={() => onBlockSniffer(item.ip)}
                                  disabled={blockingTarget === item.ip}
                                  className="px-2.5 py-1 rounded-lg bg-rose-500/20 hover:bg-rose-500/30 border border-rose-500/30 text-rose-300 text-[11px] font-sans font-medium transition-all disabled:opacity-50"
                                >
                                  {blockingTarget === item.ip ? '拉黑中...' : '一键拉黑 IP'}
                                </button>
                              )}
                              {item.subnet && (
                                <button
                                  type="button"
                                  onClick={() => onBlockSniffer(item.subnet)}
                                  disabled={blockingTarget === item.subnet}
                                  className="px-2.5 py-1 rounded-lg bg-amber-500/15 hover:bg-amber-500/25 border border-amber-500/30 text-amber-300 text-[11px] font-sans font-medium transition-all disabled:opacity-50"
                                >
                                  {blockingTarget === item.subnet ? '封网段中...' : '一键拉黑 /24 段'}
                                </button>
                              )}
                            </div>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>

                <div className="mt-3 pt-3 border-t border-slate-800/80 flex flex-col sm:flex-row items-center justify-between gap-2 text-xs text-slate-400">
                  <div>
                    共筛选出 <span className="text-white font-mono font-semibold">{filteredSniffIPs.length}</span> 个嗅探 IP
                    {sniffPageSize > 0 && `（当前第 ${safeIPPage} / ${totalIPPages} 页）`}
                  </div>
                  {sniffPageSize > 0 && totalIPPages > 1 && (
                    <div className="flex items-center gap-1.5">
                      <button
                        type="button"
                        disabled={safeIPPage <= 1}
                        onClick={() => setSniffPage((p) => Math.max(1, p - 1))}
                        className="px-2.5 py-1 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-800 text-slate-300 disabled:opacity-40"
                      >
                        上一页
                      </button>
                      <button
                        type="button"
                        disabled={safeIPPage >= totalIPPages}
                        onClick={() => setSniffPage((p) => Math.min(totalIPPages, p + 1))}
                        className="px-2.5 py-1 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-800 text-slate-300 disabled:opacity-40"
                      >
                        下一页
                      </button>
                    </div>
                  )}
                </div>
              </>
            )}
          </>
        )}

        {sniffTab === 'subnet' && (
          <>
            {filteredSniffSubnets.length === 0 ? (
              <div className="py-8 text-center rounded-xl bg-slate-950/40 border border-slate-800/80 text-xs text-slate-400">
                当前视角暂无活跃 /24 嗅探网段记录
              </div>
            ) : (
              <>
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-xs font-mono">
                    <thead>
                      <tr className="border-b border-slate-800 text-slate-400">
                        <th className="py-2.5 px-3">活跃嗅探 IP 段 (/24)</th>
                        <th className="py-2.5 px-3">受探主机</th>
                        <th className="py-2.5 px-3">段内独立 IP 数</th>
                        <th className="py-2.5 px-3">累计探测次数</th>
                        <th className="py-2.5 px-3">归属国家与组织指纹</th>
                        <th className="py-2.5 px-3">开始时间 (首次)</th>
                        <th className="py-2.5 px-3">最近时间 (最后)</th>
                        <th className="py-2.5 px-3">状态</th>
                        <th className="py-2.5 px-3 text-right">网段级封禁操作</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800/60">
                      {pagedSniffSubnets.map((sub) => (
                        <tr key={sub.cidr} className="hover:bg-slate-900/40 transition-colors">
                          <td className="py-3 px-3 text-amber-300 font-semibold whitespace-nowrap">{sub.cidr}</td>
                          <td className="py-3 px-3 font-sans">
                            <div className="flex flex-wrap gap-1">
                              {(sub.nodes && sub.nodes.length > 0
                                ? sub.nodes
                                : [{ id: 'local', name: '本机网关' }]
                              ).map((n) => (
                                <span
                                  key={n.id}
                                  className="px-2 py-0.5 rounded bg-sky-500/15 text-sky-300 border border-sky-500/30 text-[10px] font-medium whitespace-nowrap"
                                >
                                  {n.name}
                                </span>
                              ))}
                            </div>
                          </td>
                          <td className="py-3 px-3 text-white whitespace-nowrap">{sub.uniqueIPs} 个 IP</td>
                          <td className="py-3 px-3 text-slate-300 whitespace-nowrap">{sub.totalHits} 次</td>
                          <td className="py-3 px-3 font-sans">
                            <div className="flex items-center gap-1.5 flex-wrap">
                              {sub.flag && <span>{sub.flag}</span>}
                              {sub.country && <span className="text-slate-200">{sub.country}</span>}
                              {sub.scannerTag && (
                                <span className="px-2 py-0.5 rounded bg-purple-500/20 text-purple-300 border border-purple-500/30 text-[10px] font-semibold">
                                  {sub.scannerTag}
                                </span>
                              )}
                              {sub.isp && <span className="text-slate-400 text-[11px]">· {sub.isp}</span>}
                            </div>
                          </td>
                          <td className="py-3 px-3 text-slate-400 whitespace-nowrap">
                            {sub.firstSeen || sub.lastSeen || '--'}
                          </td>
                          <td className="py-3 px-3 text-emerald-300 whitespace-nowrap">{sub.lastSeen || '--'}</td>
                          <td className="py-3 px-3 whitespace-nowrap">
                            {sub.status === 'banned' ? (
                              <span className="px-2 py-0.5 rounded-md bg-rose-500/20 text-rose-300 border border-rose-500/30 text-[11px]">
                                全段已封禁
                              </span>
                            ) : sub.status === 'partial' ? (
                              <span className="px-2 py-0.5 rounded-md bg-amber-500/15 text-amber-300 border border-amber-500/25 text-[11px]">
                                部分已封 ({sub.bannedCount}/{sub.uniqueIPs})
                              </span>
                            ) : (
                              <span className="px-2 py-0.5 rounded-md bg-amber-500/15 text-amber-300 border border-amber-500/25 text-[11px]">
                                活跃扫描段
                              </span>
                            )}
                          </td>
                          <td className="py-3 px-3 text-right whitespace-nowrap">
                            {sub.status === 'banned' ? (
                              <button
                                type="button"
                                onClick={() => onUnban(sub.cidr)}
                                disabled={unbanningIP === sub.cidr}
                                className="px-3 py-1.5 rounded-lg bg-emerald-500/20 hover:bg-emerald-500/30 border border-emerald-500/30 text-emerald-300 text-xs font-sans font-medium transition-all disabled:opacity-50"
                              >
                                {unbanningIP === sub.cidr ? '正在解封网段...' : `解除网段封禁`}
                              </button>
                            ) : (
                              <button
                                type="button"
                                onClick={() => onBlockSniffer(sub.cidr)}
                                disabled={blockingTarget === sub.cidr}
                                className="px-3 py-1.5 rounded-lg bg-rose-500/20 hover:bg-rose-500/30 border border-rose-500/30 text-rose-300 text-xs font-sans font-medium transition-all disabled:opacity-50"
                              >
                                {blockingTarget === sub.cidr ? '正在封禁网段...' : `一键拉黑 ${sub.cidr}`}
                              </button>
                            )}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>

                <div className="mt-3 pt-3 border-t border-slate-800/80 flex flex-col sm:flex-row items-center justify-between gap-2 text-xs text-slate-400">
                  <div>
                    共筛选出 <span className="text-white font-mono font-semibold">{filteredSniffSubnets.length}</span> 个 /24 嗅探网段
                    {sniffPageSize > 0 && `（当前第 ${safeSubnetPage} / ${totalSubnetPages} 页）`}
                  </div>
                  {sniffPageSize > 0 && totalSubnetPages > 1 && (
                    <div className="flex items-center gap-1.5">
                      <button
                        type="button"
                        disabled={safeSubnetPage <= 1}
                        onClick={() => setSniffPage((p) => Math.max(1, p - 1))}
                        className="px-2.5 py-1 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-800 text-slate-300 disabled:opacity-40"
                      >
                        上一页
                      </button>
                      <button
                        type="button"
                        disabled={safeSubnetPage >= totalSubnetPages}
                        onClick={() => setSniffPage((p) => Math.min(totalSubnetPages, p + 1))}
                        className="px-2.5 py-1 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-800 text-slate-300 disabled:opacity-40"
                      >
                        下一页
                      </button>
                    </div>
                  )}
                </div>
              </>
            )}
          </>
        )}

        {sniffTab === 'country' && (
          <>
            {!sniffSummary?.topCountries || sniffSummary.topCountries.length === 0 ? (
              <div className="py-8 text-center rounded-xl bg-slate-950/40 border border-slate-800/80 text-xs text-slate-400">
                当前暂无活跃嗅探国统计数据
              </div>
            ) : (
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
                {sniffSummary.topCountries.map((c) => (
                  <div key={c.countryCode} className="p-3.5 rounded-xl bg-slate-950/60 border border-slate-800 space-y-2">
                    <div className="flex items-center justify-between">
                      <span className="text-sm font-semibold text-white">
                        {c.flag ? `${c.flag} ` : ''}
                        {c.country}
                      </span>
                      <span className="text-xs font-mono text-indigo-300 font-bold">{c.ratioPercent}%</span>
                    </div>
                    <div className="w-full h-2 bg-slate-900 rounded-full overflow-hidden">
                      <div
                        className="bg-indigo-500 h-full rounded-full"
                        style={{ width: `${Math.min(100, Math.max(5, c.ratioPercent))}%` }}
                      />
                    </div>
                    <div className="flex items-center justify-between text-[11px] font-mono text-slate-400">
                      <span>独立 IP: {c.uniqueIPs}</span>
                      <span>涉及 /24 段: {c.uniqueSubnets}</span>
                      <span>命中: {c.totalHits}</span>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
};

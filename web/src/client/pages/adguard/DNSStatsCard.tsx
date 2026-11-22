import React, { useMemo } from 'react';
import { BarChart3, ShieldBan, TrendingUp } from 'lucide-react';
import { Badge, Button, SectionCard } from '../../../ui';
import {
  DNSDomainStat,
  DNSOverviewSnapshot,
  UpstreamProbeReport,
} from '../../types';
import { formatNumber, resolveActiveEngine } from './adguardHelpers';

export interface DNSStatsCardProps {
  snap: DNSOverviewSnapshot | null;
  probe: UpstreamProbeReport | null;
  probing: boolean;
  mutating: boolean;
  canMutate: boolean;
  onWhitelist: (action: 'add' | 'remove', domain: string) => Promise<boolean>;
}

function getDefaultStatsSourceLabel(snap: DNSOverviewSnapshot | null): string {
  if (snap?.statsSourceLabel) return snap.statsSourceLabel;
  const engine = resolveActiveEngine(snap);
  if (engine === 'adguard') return 'AdGuard Home 逐包 DNS 统计';
  if (engine === 'smartdns') return 'SmartDNS 内存盘逐包审计';
  return 'sing-box 连接与拦截实时遥测';
}

function getStatsSourceBadge(statsSource?: string, engine?: string): string {
  switch (statsSource) {
    case 'adguard_api':
      return 'AdGuard API';
    case 'smartdns_audit':
      return '内存盘审计';
    case 'singbox_telemetry':
      return '内核遥测';
    default:
      if (engine === 'adguard') return 'AdGuard API';
      if (engine === 'smartdns') return '内存盘审计';
      return '内核遥测';
  }
}

export const DNSStatsCard: React.FC<DNSStatsCardProps> = ({
  snap,
  probe,
  probing,
  mutating,
  canMutate,
  onWhitelist,
}) => {
  const activeEngine = resolveActiveEngine(snap);
  const stats = snap?.stats;
  const sourceLabel = getDefaultStatsSourceLabel(snap);
  const sourceBadge = getStatsSourceBadge(snap?.statsSource, activeEngine);

  const topQueried: DNSDomainStat[] = stats?.topQueriedDomains || [];
  const topBlocked: DNSDomainStat[] = stats?.topBlockedDomains || [];

  const maxQueried = useMemo(
    () => topQueried.reduce((acc, item) => Math.max(acc, item.count), 1),
    [topQueried],
  );
  const maxBlocked = useMemo(
    () => topBlocked.reduce((acc, item) => Math.max(acc, item.count), 1),
    [topBlocked],
  );

  const whitelistSet = useMemo(
    () => new Set((snap?.whitelistedDomains || []).map((d) => d.toLowerCase())),
    [snap?.whitelistedDomains],
  );

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3.5">
        <div className="console-card rounded-2xl p-4 space-y-1">
          <div className="text-xs text-secondary">
            {activeEngine === 'singbox' ? '24h 域名访问总量' : '24h DNS 查询总量'}
          </div>
          <div className="text-xl sm:text-2xl font-bold text-primary font-mono tnum">
            {formatNumber(stats?.numDnsQueries || 0)}
          </div>
          <div className="text-[11px] text-muted truncate" title={sourceLabel}>
            {activeEngine === 'singbox'
              ? 'sing-box 加强版内置接管中'
              : snap?.singboxLinked
                ? 'sing-box dns_local 实时接管中'
                : '等待内核接管'}
          </div>
        </div>

        <div className="console-card rounded-2xl p-4 space-y-1">
          <div className="text-xs text-secondary">已拦截广告与追踪</div>
          <div
            className="text-xl sm:text-2xl font-bold font-mono tnum"
            style={{ color: 'var(--status-ok)' }}
          >
            {formatNumber(stats?.numBlockedFiltering || 0)}
          </div>
          <div className="text-[11px] text-muted tnum">
            拦截占比 {stats?.blockedPercent ?? 0}%
            {(snap?.totalRulesCount || 0) > 0
              ? ` · 生效规则 ${formatNumber(snap?.totalRulesCount || 0)} 条`
              : ''}
          </div>
        </div>

        <div className="console-card rounded-2xl p-4 space-y-1">
          <div className="text-xs text-secondary">平均解析耗时</div>
          <div className="text-xl sm:text-2xl font-bold text-primary font-mono tnum">
            {stats?.avgProcessingMs ?? 0} <span className="text-xs font-normal">ms</span>
          </div>
          <div className="text-[11px] text-muted">
            {activeEngine === 'singbox'
              ? '加密 DoH 实测与乐观缓存参考'
              : '含本地缓存与并发竞速加速'}
          </div>
        </div>

        <div className="console-card rounded-2xl p-4 space-y-1">
          <div className="text-xs text-secondary">加密上游竞速实测</div>
          <div className="text-xl sm:text-2xl font-bold text-primary font-mono tnum">
            {probing ? (
              <span className="text-sm text-secondary">并发测速中…</span>
            ) : probe?.fastestLatencyMs ? (
              <>
                {probe.fastestLatencyMs} <span className="text-xs font-normal">ms</span>
              </>
            ) : probe?.healthy ? (
              <>
                {probe.latencyMs} <span className="text-xs font-normal">ms</span>
              </>
            ) : (
              <span className="text-sm text-secondary">--</span>
            )}
          </div>
          <div className="text-[11px] text-muted truncate" title={probe?.fastestUpstream || ''}>
            {probe?.fastestName
              ? `最快：${probe.fastestName}`
              : probe?.healthy
                ? `${probe.domain} → ${probe.resolved}`
                : probe?.error || '点击「实测上游」对比各节点速度'}
          </div>
        </div>
      </div>

      <SectionCard
        title="24h 域名统计与拦截排行"
        icon={<BarChart3 className="w-4 h-4" />}
        subtitle={`统计来源：${sourceLabel}（内存环形窗口，零闪存损耗）`}
        actions={<Badge tone="accent">{sourceBadge}</Badge>}
      >
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          {/* Top Queried Domains */}
          <div className="rounded-xl border border-subtle bg-surface2/50 p-3.5 space-y-3">
            <div className="flex items-center justify-between gap-2">
              <div className="flex items-center gap-1.5 text-xs font-semibold text-primary">
                <TrendingUp className="w-3.5 h-3.5 text-sky-400" />
                <span>{activeEngine === 'singbox' ? 'Top 访问域名排行' : 'Top 查询域名排行'}</span>
              </div>
              <span className="text-[11px] text-muted tnum">
                {topQueried.length > 0 ? `前 ${topQueried.length} 项` : '实时采集'}
              </span>
            </div>

            {topQueried.length === 0 ? (
              <div className="py-8 text-center text-xs text-muted">
                暂无 24h 域名查询统计，设备产生解析流量后自动汇聚展示
              </div>
            ) : (
              <div className="space-y-2 max-h-72 overflow-y-auto pr-1">
                {topQueried.map((item, idx) => {
                  const pct = Math.max(4, Math.round((item.count / maxQueried) * 100));
                  return (
                    <div key={`${item.domain}-${idx}`} className="space-y-1">
                      <div className="flex items-center justify-between gap-2 text-xs">
                        <div className="flex items-center gap-2 min-w-0">
                          <span className="w-5 text-[11px] font-mono text-muted tnum shrink-0">
                            #{idx + 1}
                          </span>
                          <span className="font-mono text-primary truncate" title={item.domain}>
                            {item.domain}
                          </span>
                        </div>
                        <span className="font-mono text-[11px] text-secondary tnum shrink-0">
                          {formatNumber(item.count)} 次
                        </span>
                      </div>
                      <div className="h-1.5 rounded-full bg-surface1 overflow-hidden">
                        <div
                          className="h-full rounded-full transition-all"
                          style={{
                            width: `${pct}%`,
                            backgroundColor: 'var(--accent)',
                            opacity: 0.75,
                          }}
                        />
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </div>

          {/* Top Blocked Domains */}
          <div className="rounded-xl border border-subtle bg-surface2/50 p-3.5 space-y-3">
            <div className="flex items-center justify-between gap-2">
              <div className="flex items-center gap-1.5 text-xs font-semibold text-primary">
                <ShieldBan className="w-3.5 h-3.5 text-emerald-400" />
                <span>Top 拦截域名排行</span>
              </div>
              <span className="text-[11px] text-muted">误拦可一键放行至白名单</span>
            </div>

            {topBlocked.length === 0 ? (
              <div className="py-8 text-center text-xs text-muted">
                暂无 24h 被拦截域名记录
              </div>
            ) : (
              <div className="space-y-2 max-h-72 overflow-y-auto pr-1">
                {topBlocked.map((item, idx) => {
                  const pct = Math.max(4, Math.round((item.count / maxBlocked) * 100));
                  const allowed = whitelistSet.has(item.domain.toLowerCase());
                  return (
                    <div key={`${item.domain}-${idx}`} className="space-y-1">
                      <div className="flex items-center justify-between gap-2 text-xs">
                        <div className="flex items-center gap-2 min-w-0 flex-1">
                          <span className="w-5 text-[11px] font-mono text-muted tnum shrink-0">
                            #{idx + 1}
                          </span>
                          <span className="font-mono text-primary truncate" title={item.domain}>
                            {item.domain}
                          </span>
                        </div>
                        <div className="flex items-center gap-2 shrink-0">
                          <span className="font-mono text-[11px] text-secondary tnum">
                            {formatNumber(item.count)} 次
                          </span>
                          {allowed ? (
                            <Badge tone="ok">已放行</Badge>
                          ) : (
                            <Button
                              size="xs"
                              variant="ghost"
                              disabled={mutating || !canMutate}
                              onClick={() => void onWhitelist('add', item.domain)}
                            >
                              放行
                            </Button>
                          )}
                        </div>
                      </div>
                      <div className="h-1.5 rounded-full bg-surface1 overflow-hidden">
                        <div
                          className="h-full rounded-full transition-all"
                          style={{
                            width: `${pct}%`,
                            backgroundColor: 'var(--status-ok)',
                            opacity: 0.75,
                          }}
                        />
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        </div>
      </SectionCard>
    </div>
  );
};

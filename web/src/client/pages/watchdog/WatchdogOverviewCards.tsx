import React from 'react';
import { Clock, Dog, RefreshCw, ShieldCheck } from 'lucide-react';
import { Badge, Button, SectionCard } from '../../../ui';
import { CacheResponse, WatchdogEventItem, WatchdogReport } from '../../types';
import { DEFAULT_FO_GROUPS, fmtKB } from './watchdogHelpers';

export interface WatchdogTopCardsProps {
  report: WatchdogReport | null;
  cacheSummary: CacheResponse | null;
  busy: boolean;
  onAction: (name: string, params?: Record<string, unknown>, confirmMsg?: string) => void;
}

export const WatchdogTopCards: React.FC<WatchdogTopCardsProps> = ({
  report,
  cacheSummary,
  busy,
  onAction,
}) => {
  const dm = report?.daemon;
  const cfg = report?.config;
  const rt = report?.runtime;
  const agh = report?.adguard;
  const activeFO = rt?.activeFailovers || [];

  return (
    <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
      <SectionCard
        title="守护进程控制台"
        icon={<Dog className="w-4 h-4" />}
        actions={
          <div className="flex items-center gap-2">
            {dm?.running ? (
              <>
                <Button size="xs" disabled={busy} onClick={() => onAction('dm-restart')}>
                  平滑重启
                </Button>
                <Button
                  size="xs"
                  variant="danger"
                  disabled={busy}
                  onClick={() => onAction('dm-stop', {}, '确认停止看门狗守护进程？')}
                >
                  停止
                </Button>
              </>
            ) : (
              <Button size="xs" variant="primary" disabled={busy} onClick={() => onAction('dm-start')}>
                启动守护
              </Button>
            )}
          </div>
        }
      >
        <div className="divide-y divide-[var(--border-subtle)] text-xs sm:text-sm">
          <div className="flex items-center justify-between py-2.5 gap-3">
            <span className="text-secondary">进程状态</span>
            <span className="font-mono text-primary tnum">
              {dm?.running
                ? `运行中 (PID ${dm.pid || '-'}${dm.daemonVersion ? ` · v${dm.daemonVersion.replace(/^v/, '')}` : ''})`
                : '未运行'}
            </span>
          </div>
          <div className="flex items-center justify-between py-2.5 gap-3">
            <span className="text-secondary">上次健康巡检</span>
            <span className="font-mono text-primary tnum text-right">
              {rt?.lastHealthAt
                ? `${rt.lastHealthOK ? '✓ 正常' : '✗ 异常'}${rt.lastHealthDelayMs ? ` (${rt.lastHealthDelayMs}ms)` : ''} · ${rt.lastHealthAt}`
                : '等待首轮巡检'}
            </span>
          </div>
          <div className="flex items-center justify-between py-2.5 gap-3">
            <span className="text-secondary">熔断与重启统计</span>
            <span className="font-mono text-primary tnum">
              1h: {dm?.restarts || 0}/{dm?.maxRestarts || 3} · 累计: {dm?.totalRestarts || 0} 次
            </span>
          </div>
          <div className="flex items-center justify-between py-2.5 gap-3">
            <span className="text-secondary">守护日志占用</span>
            <span className="font-mono text-muted truncate max-w-[260px] tnum" title={dm?.logPath}>
              {fmtKB(dm?.logSizeBytes || 0)} / {fmtKB(dm?.logMaxBytes || 524288)}
            </span>
          </div>
        </div>
      </SectionCard>

      <SectionCard title="五大自愈防线" icon={<ShieldCheck className="w-4 h-4" />} subtitle="7×24 全自动无人值守保护">
        <div className="space-y-2.5">
          {[
            {
              title: '① 进程与内部 DNS 自愈',
              desc: `每 ${cfg?.interval || 180}s 检测进程与解析，异常 ${cfg?.confirm_wait || 30}s 复核拉起`,
              badge: dm?.running ? <Badge tone="ok">守护中</Badge> : <Badge>未运行</Badge>,
            },
            {
              title: '② 策略组自动故障切换',
              desc: cfg?.failover.enabled
                ? `每 ${cfg.failover.patrol_interval || 300}s 巡检 ${(cfg.failover.groups || DEFAULT_FO_GROUPS).length} 组 · 复测 ${cfg.failover.confirm_retries ?? 1} 次`
                : '已手动关闭策略组节点容灾切换',
              badge: !cfg?.failover.enabled ? (
                <Badge>已关闭</Badge>
              ) : activeFO.length > 0 ? (
                <Badge tone="warn">{activeFO.length} 组容灾中</Badge>
              ) : (
                <Badge tone={dm?.running ? 'ok' : 'neutral'}>{dm?.running ? '巡检中' : '待启动'}</Badge>
              ),
            },
            {
              title: '③ 订阅节点无感热同步',
              desc: cfg?.sub_sync_enabled
                ? `每 ${Math.round((cfg.sub_sync_interval || 600) / 60)} 分钟静默比对订阅并 SIGHUP 重载`
                : '已关闭后台订阅自动同步',
              badge: !cfg?.sub_sync_enabled ? (
                <Badge>已关闭</Badge>
              ) : (
                <Badge tone={dm?.running ? 'ok' : 'neutral'}>{dm?.running ? '已启用' : '待启动'}</Badge>
              ),
            },
            {
              title: '④ 规则集 (.srs) 静默刷新',
              desc: (() => {
                const entries = cacheSummary?.entries || [];
                const total = entries.length;
                const ready = entries.filter((e) => e.state === 'ok' || e.state === 'snapshot').length;
                const local = entries.filter((e) => e.state === 'ok').length;
                const parts = ['每 24 小时自动校准'];
                if (total > 0) parts.push(`就绪 ${ready}/${total} (本地 ${local})`);
                else if (cacheSummary?.snapshotCount) parts.push(`内置兜底 ${cacheSummary.snapshotCount} 项`);
                if (rt?.lastRuleSetAt) parts.push(`上次: ${rt.lastRuleSetAt}`);
                return parts.join(' · ');
              })(),
              badge: (() => {
                const entries = cacheSummary?.entries || [];
                const total = entries.length;
                const ready = entries.filter((e) => e.state === 'ok' || e.state === 'snapshot').length;
                const missing = entries.filter((e) => e.state === 'missing').length;
                if (missing > 0) return <Badge tone="warn">缺 {missing} 项</Badge>;
                if (total > 0) return <Badge tone="ok">{ready}/{total} 就绪</Badge>;
                return <Badge tone={dm?.running ? 'ok' : 'neutral'}>{dm?.running ? '定时守护' : '待启动'}</Badge>;
              })(),
              action: (
                <Button
                  size="xs"
                  disabled={busy}
                  onClick={() => onAction('cache-update')}
                  icon={<RefreshCw className="w-3 h-3" />}
                >
                  立即更新
                </Button>
              ),
            },
            {
              title: '⑤ 本地防劫持 DNS 保活',
              desc: agh?.supported ? '联动巡检本地加密 DNS 引擎与上游活性，异常自动热切自愈' : '当前非 Linux 网关，自动跳过',
              badge: !agh?.supported ? (
                <Badge>仅 Linux</Badge>
              ) : !agh.enabled ? (
                <Badge>已禁用</Badge>
              ) : agh.healthy ? (
                <Badge tone="ok">健康</Badge>
              ) : (
                <Badge tone="warn">待自愈</Badge>
              ),
            },
          ].map((item) => (
            <div
              key={item.title}
              className="flex items-center justify-between gap-3 px-3 py-2 rounded-xl bg-surface2"
            >
              <div className="min-w-0">
                <div className="text-xs font-semibold text-primary">{item.title}</div>
                <div className="text-[11px] text-secondary truncate">{item.desc}</div>
              </div>
              <div className="flex items-center gap-2 shrink-0">
                {item.action}
                {item.badge}
              </div>
            </div>
          ))}
        </div>
      </SectionCard>
    </div>
  );
};

export const WatchdogEventsTimelineCard: React.FC<{
  events: WatchdogEventItem[];
  onOpenEventsLog: () => void;
}> = ({ events, onOpenEventsLog }) => (
  <SectionCard
    title="最近看门狗与容灾事件"
    icon={<Clock className="w-4 h-4" />}
    actions={
      <Button size="xs" onClick={onOpenEventsLog}>
        查看完整日志
      </Button>
    }
  >
    {events.length === 0 ? (
      <div className="py-6 text-center text-xs text-muted">近期运行平稳，暂无故障切备或异常自愈事件</div>
    ) : (
      <div className="divide-y divide-[var(--border-subtle)] text-xs">
        {events.map((ev, i) => {
          const tone =
            ev.action === 'GROUP_FAILOVER' || !ev.healthy
              ? 'warn'
              : ev.action === 'CHECK_FAIL' ||
                  ev.action === 'RESTART_FAIL' ||
                  ev.action === 'CIRCUIT_BREAK' ||
                  ev.action === 'SKIP_RESTART'
                ? 'danger'
                : ev.action === 'SUB_SYNC' || ev.action === 'RULESET' || ev.action === 'RULESET_REFRESH'
                  ? 'accent'
                  : 'ok';
          return (
            <div key={i} className="flex flex-wrap items-center gap-2.5 py-2.5">
              <span className="font-mono text-muted tnum shrink-0">{ev.time || '-'}</span>
              <Badge tone={tone}>{ev.action || '事件'}</Badge>
              <span className="text-primary break-words">{ev.summary}</span>
            </div>
          );
        })}
      </div>
    )}
  </SectionCard>
);

import React from 'react';
import { Globe, Monitor, Radar, Router, Wifi } from 'lucide-react';
import { Badge } from '../../../ui';
import { countryFlag } from '../../lib/leakProbes';
import { maskFullIP, redactInlineSensitive } from '../../lib/privacyMask';
import { DNSLeakReport } from '../../types';
import { PanoramicAnalysis } from './analyzePanoramicSuite';
import { formatGeoLine, MergedDNSRow, PanoramicSuiteState } from './browserDoHFlow';

interface EgressTileProps {
  label: string;
  icon: React.ReactNode;
  badge: { tone: 'ok' | 'warn' | 'danger' | 'neutral'; text: string };
  ipText: string;
  geoText?: string;
  ispText?: string;
  hideTooltip?: boolean;
  latencyMs?: number;
  danger?: boolean;
}

const EgressTile: React.FC<EgressTileProps> = ({
  label,
  icon,
  badge,
  ipText,
  geoText,
  ispText,
  hideTooltip,
  latencyMs,
  danger,
}) => (
  <div
    className={`rounded-xl border px-3.5 py-3 space-y-1.5 ${
      danger ? 'border-rose-500/45 bg-rose-500/10' : 'border-subtle bg-surface2/45'
    }`}
  >
    <div className="flex items-center justify-between gap-2">
      <span className="inline-flex items-center gap-1.5 text-xs font-medium text-secondary">
        {icon}
        <span>{label}</span>
      </span>
      <div className="flex items-center gap-1.5">
        {latencyMs ? (
          <span className="font-mono tnum text-[10.5px] text-muted">{latencyMs}ms</span>
        ) : null}
        <Badge tone={badge.tone}>{badge.text}</Badge>
      </div>
    </div>
    <div className="font-mono text-sm font-semibold text-primary break-all">{ipText}</div>
    {geoText && <div className="text-[11px] text-secondary">{geoText}</div>}
    {ispText && (
      <div className="text-[11px] text-muted truncate" title={hideTooltip ? undefined : ispText}>
        {ispText}
      </div>
    )}
  </div>
);

export const EgressMatrixGrid: React.FC<{
  analysis: PanoramicAnalysis;
  suite: PanoramicSuiteState | null;
  running: boolean;
  hideIP: boolean;
}> = ({ analysis, suite, running, hideIP }) => (
  <div className="space-y-2">
    <div className="flex items-center justify-between text-xs font-semibold text-primary">
      <span className="inline-flex items-center gap-1.5">
        <Globe className="w-3.5 h-3.5 text-sky-400" />
        四路出口 IP 与双栈分流全景
      </span>
      <span className="text-[11px] font-normal text-muted">对比国内直连与海外代理落地真实表现</span>
    </div>
    <div className="grid grid-cols-1 md:grid-cols-2 gap-2.5">
      <EgressTile
        label="国内直连 IPv4"
        icon={<Wifi className="w-3.5 h-3.5 text-emerald-400" />}
        badge={
          analysis.domV4?.reachable
            ? { tone: 'ok', text: '直连正常' }
            : { tone: 'warn', text: running ? '探测中' : '未检出' }
        }
        ipText={analysis.domV4?.reachable ? maskFullIP(analysis.domV4.ip, hideIP) : '未获取到'}
        geoText={
          hideIP
            ? analysis.domV4?.reachable
              ? '位置已遮挡'
              : ''
            : formatGeoLine(analysis.domV4)
        }
        ispText={
          hideIP
            ? analysis.domV4?.reachable
              ? '运营商 / ASN 已遮挡'
              : ''
            : analysis.domV4?.isp || analysis.domV4?.asn || analysis.domV4?.error || ''
        }
        hideTooltip={hideIP}
        latencyMs={analysis.domV4?.latencyMs}
      />

      <EgressTile
        label="国内直连 IPv6"
        icon={<Wifi className="w-3.5 h-3.5 text-sky-400" />}
        badge={
          analysis.ipv6Mode === 'off'
            ? { tone: 'neutral', text: '策略已关闭' }
            : analysis.domV6?.reachable
              ? { tone: 'ok', text: '原生双栈生效' }
              : { tone: 'warn', text: running ? '探测中' : '暂无 IPv6' }
        }
        ipText={
          analysis.domV6?.reachable
            ? maskFullIP(analysis.domV6.ip, hideIP)
            : analysis.ipv6Mode === 'off'
              ? '未启用 (纯 IPv4)'
              : '未获取到'
        }
        geoText={
          hideIP
            ? analysis.domV6?.reachable
              ? '位置已遮挡'
              : ''
            : formatGeoLine(analysis.domV6)
        }
        ispText={
          analysis.domV6?.reachable
            ? hideIP
              ? `运营商已遮挡${suite?.browserDom?.usedIPv6 ? ' · 浏览器优先直连 IPv6 命中' : ''}`
              : `${analysis.domV6.isp || '原生 IPv6'}${suite?.browserDom?.usedIPv6 ? ' · 浏览器优先直连 IPv6 命中' : ''}`
            : analysis.domV6?.error || ''
        }
        hideTooltip={hideIP}
        latencyMs={analysis.domV6?.latencyMs}
      />

      <EgressTile
        label="海外代理 IPv4"
        icon={<Globe className="w-3.5 h-3.5 text-indigo-400" />}
        badge={
          analysis.ov4Leaked
            ? { tone: 'danger', text: '异常 · 落回国内' }
            : analysis.ov4?.reachable
              ? { tone: 'ok', text: '代理生效' }
              : { tone: 'warn', text: running ? '探测中' : '不可达' }
        }
        ipText={analysis.ov4?.reachable ? maskFullIP(analysis.ov4.ip, hideIP) : '未响应'}
        geoText={
          analysis.ov4?.reachable
            ? hideIP
              ? '地区已遮挡'
              : `${countryFlag(analysis.ov4.countryCode)} ${formatGeoLine(analysis.ov4)}`
            : ''
        }
        ispText={
          hideIP
            ? analysis.ov4?.reachable
              ? '运营商 / ASN 已遮挡'
              : ''
            : analysis.ov4?.asn || analysis.ov4?.isp || analysis.ov4?.error || ''
        }
        hideTooltip={hideIP}
        latencyMs={analysis.ov4?.latencyMs}
        danger={analysis.ov4Leaked}
      />

      <EgressTile
        label="海外代理 IPv6"
        icon={<Globe className="w-3.5 h-3.5 text-purple-400" />}
        badge={
          analysis.ov6Leaked
            ? { tone: 'danger', text: '严重泄漏原生 IPv6' }
            : analysis.ipv6Mode === 'full'
              ? analysis.ov6Target?.reachable
                ? { tone: 'ok', text: '全双栈出站' }
                : { tone: 'warn', text: running ? '探测中' : '节点暂不支持 IPv6' }
              : !analysis.ov6Target?.reachable
                ? analysis.ipv6Mode === 'cn_only' && analysis.clientIPv6Disabled
                  ? { tone: 'warn', text: '本机未启用 IPv6' }
                  : { tone: 'ok', text: '已静音拦截 · 零泄漏' }
                : { tone: 'ok', text: '海外代理 IPv6 出站' }
        }
        ipText={
          analysis.ov6Target?.reachable
            ? maskFullIP(analysis.ov6Target.ip, hideIP)
            : analysis.ipv6Mode === 'full'
              ? '当前节点无 IPv6 出站'
              : analysis.ipv6Mode === 'cn_only' && analysis.clientIPv6Disabled
                ? '仅网关侧已静音拦截'
                : '已 0ms 拦截 AAAA/HTTPS 及 ::/0'
        }
        geoText={
          analysis.ov6Target?.reachable
            ? hideIP
              ? '地区已遮挡'
              : `${countryFlag(analysis.ov6Target.countryCode)} ${formatGeoLine(analysis.ov6Target)}`
            : ''
        }
        ispText={
          analysis.ov6Leaked
            ? '海外探测直接露出家庭宽带 IPv6，请检查 AAAA 屏蔽或透明代理规则'
            : analysis.ov6Target?.reachable
              ? hideIP
                ? '运营商 / ASN 已遮挡'
                : analysis.ov6Target.asn || analysis.ov6Target.isp || ''
              : analysis.ipv6Mode === 'full'
                ? analysis.ov6Target?.error || '建议切换为「智能双栈」获得零延迟体验'
                : analysis.ipv6Mode === 'cn_only' && analysis.clientIPv6Disabled
                  ? '当前浏览器所在终端未获取到 IPv6（国内 IPv6 未通），无法验证终端双栈回退；请在系统开启 IPv6 后复测'
                  : '海外域名不返回 AAAA/HTTPS 且路由层秒拒 ::/0，浏览器直走代理 IPv4'
        }
        hideTooltip={hideIP}
        latencyMs={analysis.ov6Target?.latencyMs}
        danger={analysis.ov6Leaked}
      />
    </div>
  </div>
);

export const DNSResolversTable: React.FC<{
  rows: MergedDNSRow[];
  totalSweepTarget: number;
  running: boolean;
  hideIP: boolean;
}> = ({ rows, totalSweepTarget, running, hideIP }) => (
  <div className="space-y-2">
    <div className="flex flex-wrap items-center justify-between gap-2 text-xs font-semibold text-primary">
      <span className="inline-flex items-center gap-1.5">
        <Radar className="w-3.5 h-3.5 text-emerald-400" />
        DNS 解析器防缓存多轮扫描列表
        <Badge tone="neutral">{rows.length} 个唯一解析器</Badge>
      </span>
      <span className="text-[11px] font-normal text-muted">
        并发请求唯一随机子域，杜绝缓存伪装并揪出多上游混用泄漏
      </span>
    </div>

    {rows.length === 0 ? (
      <div className="rounded-xl border border-subtle bg-surface2/45 px-3.5 py-3 text-xs text-muted">
        {running ? '正在汇总浏览器与网关出口解析器…' : '暂无捕获到的海外递归 DNS 出口记录'}
      </div>
    ) : (
      <div className="overflow-x-auto rounded-xl border border-subtle bg-surface2/45">
        <table className="w-full text-left border-collapse text-xs">
          <thead>
            <tr className="border-b border-[var(--border-subtle)] text-[11px] text-muted bg-surface2/70">
              <th className="py-2 px-3 font-medium">出口 DNS IP</th>
              <th className="py-2 px-3 font-medium">国家 / 地区</th>
              <th className="py-2 px-3 font-medium">运营商 / 组织</th>
              <th className="py-2 px-3 font-medium">ECS 子网</th>
              <th className="py-2 px-3 font-medium">发现视角</th>
              <th className="py-2 px-3 font-medium">命中轮次</th>
              <th className="py-2 px-3 font-medium text-right">判定</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-[var(--border-subtle)]">
            {rows.map((row) => {
              const totalHits = row.gwHits + row.brHits;
              const maxHits = Math.max(1, totalSweepTarget);
              const barPct = Math.min(100, Math.round((totalHits / maxHits) * 100));
              return (
                <tr
                  key={row.ip}
                  className={row.leaked ? 'bg-rose-500/10' : 'hover:bg-white/[0.02]'}
                >
                  <td className="py-2 px-3 font-mono font-semibold text-primary whitespace-nowrap">
                    {maskFullIP(row.ip, hideIP)}
                    {row.leaked && row.leakReason && (
                      <div className="text-[10.5px] font-sans font-normal text-rose-300 mt-0.5">
                        {redactInlineSensitive(row.leakReason, hideIP)}
                      </div>
                    )}
                  </td>
                  <td className="py-2 px-3 whitespace-nowrap text-secondary">
                    {hideIP ? (
                      '已遮挡'
                    ) : (
                      <>
                        <span className="mr-1.5">{countryFlag(row.countryCode)}</span>
                        <span>{row.country || row.countryCode || '-'}</span>
                      </>
                    )}
                  </td>
                  <td
                    className="py-2 px-3 text-secondary max-w-[220px] truncate"
                    title={hideIP ? undefined : row.isp}
                  >
                    {hideIP ? '已遮挡' : row.isp || '-'}
                  </td>
                  <td className="py-2 px-3 font-mono text-[11px] text-muted whitespace-nowrap">
                    {row.ecs
                      ? hideIP
                        ? '已遮挡'
                        : `${row.ecs}${row.ecsCountryCode ? ` (${row.ecsCountryCode})` : ''}`
                      : '未携带'}
                  </td>
                  <td className="py-2 px-3 whitespace-nowrap">
                    {row.fromBrowser && row.fromGateway ? (
                      <Badge tone="accent">双端命中</Badge>
                    ) : row.fromBrowser ? (
                      <Badge tone="neutral">浏览器</Badge>
                    ) : (
                      <Badge tone="neutral">网关</Badge>
                    )}
                  </td>
                  <td className="py-2 px-3 whitespace-nowrap">
                    <div className="flex items-center gap-2">
                      <span className="font-mono tnum text-secondary">{totalHits}</span>
                      <div className="w-12 h-1.5 rounded-full bg-slate-800 overflow-hidden">
                        <div
                          className={`h-full ${row.leaked ? 'bg-rose-400' : 'bg-emerald-400'}`}
                          style={{ width: `${Math.max(12, barPct)}%` }}
                        />
                      </div>
                    </div>
                  </td>
                  <td className="py-2 px-3 text-right whitespace-nowrap">
                    {row.leaked ? (
                      <Badge tone="danger">存在泄漏</Badge>
                    ) : (
                      <Badge tone="ok">安全</Badge>
                    )}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    )}
  </div>
);

export const WebRTCLeakSection: React.FC<{
  analysis: PanoramicAnalysis;
  running: boolean;
  hideIP: boolean;
}> = ({ analysis, running, hideIP }) => (
  <div className="rounded-xl border border-subtle bg-surface2/45 px-3.5 py-3 space-y-2">
    <div className="flex flex-wrap items-center justify-between gap-2">
      <div className="flex items-center gap-2 text-xs font-semibold text-primary">
        <Monitor className="w-3.5 h-3.5 text-sky-400" />
        <span>浏览器 WebRTC 真实 IP 泄漏检测</span>
        {analysis.rtc && (
          <Badge
            tone={
              analysis.webrtcStatus === 'safe'
                ? 'ok'
                : analysis.webrtcStatus === 'leaked'
                  ? 'danger'
                  : 'warn'
            }
          >
            {analysis.webrtcStatus === 'safe'
              ? '无泄漏'
              : analysis.webrtcStatus === 'leaked'
                ? '泄漏真实宽带 IP'
                : '暴露代理公网 IP'}
          </Badge>
        )}
      </div>
      {analysis.rtc && (
        <span className="font-mono tnum text-[10.5px] text-muted">
          耗时 {analysis.rtc.durationMs}ms
        </span>
      )}
    </div>

    {!analysis.rtc ? (
      <div className="text-xs text-muted">{running ? '正在收集 WebRTC ICE / STUN 候选地址…' : '等待探测'}</div>
    ) : (
      <div className="space-y-1.5 text-xs">
        <div className="text-secondary">{analysis.webrtcHeadline}</div>
        <div className="flex flex-wrap gap-2 text-[11px] font-mono">
          <span className="px-2 py-0.5 rounded bg-slate-900/60 border border-subtle text-muted">
            mDNS 匿名保护地址: {analysis.rtc.mdnsCount} 个
          </span>
          <span className="px-2 py-0.5 rounded bg-slate-900/60 border border-subtle text-muted">
            局域网候选:{' '}
            {analysis.rtc.localIPs.length > 0
              ? analysis.rtc.localIPs.map((ip) => maskFullIP(ip, hideIP)).join(', ')
              : '无'}
          </span>
          <span
            className={`px-2 py-0.5 rounded border ${
              analysis.webrtcStatus === 'leaked'
                ? 'bg-rose-500/15 border-rose-500/40 text-rose-200'
                : 'bg-slate-900/60 border-subtle text-secondary'
            }`}
          >
            反射公网 IPv4:{' '}
            {analysis.rtc.publicIPv4s.length > 0
              ? analysis.rtc.publicIPv4s.map((ip) => maskFullIP(ip, hideIP)).join(', ')
              : '无'}
          </span>
          <span
            className={`px-2 py-0.5 rounded border ${
              analysis.webrtcStatus === 'leaked'
                ? 'bg-rose-500/15 border-rose-500/40 text-rose-200'
                : 'bg-slate-900/60 border-subtle text-secondary'
            }`}
          >
            反射公网 IPv6:{' '}
            {analysis.rtc.publicIPv6s.length > 0
              ? analysis.rtc.publicIPv6s.map((ip) => maskFullIP(ip, hideIP)).join(', ')
              : '无'}
          </span>
        </div>
      </div>
    )}
  </div>
);

export const GatewayChecksSection: React.FC<{
  gatewayReport: DNSLeakReport;
  hideIP: boolean;
}> = ({ gatewayReport, hideIP }) => {
  if (!gatewayReport.checks || gatewayReport.checks.length === 0) return null;
  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between text-xs font-semibold text-primary">
        <span className="inline-flex items-center gap-1.5">
          <Router className="w-3.5 h-3.5 text-amber-400" />
          网关底层防线审计（:53 劫持 / 防投毒 / AAAA 规则 / RA 基线）
        </span>
        <span className="font-mono tnum text-[11px] font-normal text-muted">
          网关侧耗时 {gatewayReport.durationMs}ms
        </span>
      </div>
      <div className="divide-y divide-[var(--border-subtle)] rounded-xl border border-subtle bg-surface2/45">
        {gatewayReport.checks.map((c) => {
          const tone: 'ok' | 'warn' | 'danger' =
            c.status === 'pass' ? 'ok' : c.status === 'fail' ? 'danger' : 'warn';
          const label = c.status === 'pass' ? '通过' : c.status === 'fail' ? '泄漏/异常' : '提示';
          return (
            <div
              key={c.id}
              className="px-3.5 py-2.5 flex flex-col sm:flex-row sm:items-start justify-between gap-2 text-xs"
            >
              <div className="space-y-0.5 min-w-0">
                <div className="flex flex-wrap items-center gap-2">
                  <Badge tone={tone}>{label}</Badge>
                  <span className="font-semibold text-primary">{c.title}</span>
                  {c.latencyMs ? (
                    <span className="font-mono tnum text-[10.5px] text-muted">{c.latencyMs}ms</span>
                  ) : null}
                </div>
                <div className="text-secondary leading-relaxed">
                  {redactInlineSensitive(c.summary, hideIP)}
                </div>
                {c.detail && (
                  <div className="text-[11px] text-muted font-mono break-all">
                    {redactInlineSensitive(c.detail, hideIP)}
                  </div>
                )}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};

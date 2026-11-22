import React from 'react';
import {
  AlertTriangle,
  Ban,
  Bot,
  Gauge,
  Search,
  ShieldCheck,
  Unplug,
} from 'lucide-react';
import {
  Badge,
  Button,
  SlideDrawer,
  formatBytes as fmtBytes,
} from '../../../ui';
import { AuditAIReview, AuditFlowRecord } from '../../types';
import {
  fmtBps,
  fmtDurationSpan,
  formatDeviceRoleLabel,
  formatOutboundMeta,
  isProtectedBootstrapTarget,
  NONLINEAR_FACTOR_LABELS,
  SubnetBlockConfirmState,
} from './auditHelpers';

export interface AuditFlowDetailDrawerProps {
  detailFlow: AuditFlowRecord | null;
  throttleBusy: boolean;
  getCachedReview: (f: AuditFlowRecord) => AuditAIReview | null;
  onClose: () => void;
  onReviewSingleFlow: (f: AuditFlowRecord, force: boolean) => void;
  onCloseFlowConnections: (f: AuditFlowRecord) => void;
  onWhitelistAdd: (target: string) => void;
  onBlockFlow: (f: AuditFlowRecord, deviceOnly: boolean) => void;
  onSetThrottle: (f: AuditFlowRecord, rateKbps: number) => void;
  onFilterBySubnet: (cidr: string) => void;
  onRequestSubnetBlock: (state: SubnetBlockConfirmState) => void;
}

export const AuditFlowDetailDrawer: React.FC<AuditFlowDetailDrawerProps> = ({
  detailFlow,
  throttleBusy,
  getCachedReview,
  onClose,
  onReviewSingleFlow,
  onCloseFlowConnections,
  onWhitelistAdd,
  onBlockFlow,
  onSetThrottle,
  onFilterBySubnet,
  onRequestSubnetBlock,
}) => (
  <SlideDrawer
    open={Boolean(detailFlow)}
    onClose={onClose}
    size="md"
    title={detailFlow?.target || '连接行为详情'}
    subtitle={
      detailFlow
        ? `${detailFlow.deviceName || detailFlow.deviceIp} (${detailFlow.deviceIp}) · ${detailFlow.network.toUpperCase()}${
            detailFlow.destPort ? `:${detailFlow.destPort}` : ''
          }`
        : ''
    }
    footer={
      detailFlow ? (
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div className="flex flex-wrap gap-2">
            <Button
              size="sm"
              variant="secondary"
              icon={<Bot className="w-3.5 h-3.5" />}
              onClick={() => onReviewSingleFlow(detailFlow, true)}
            >
              重新 AI 研判
            </Button>
            {(detailFlow.activeConns || 0) > 0 && (
              <Button
                size="sm"
                variant="secondary"
                icon={<Unplug className="w-3.5 h-3.5" />}
                onClick={() => onCloseFlowConnections(detailFlow)}
              >
                断开活跃 ({detailFlow.activeConns})
              </Button>
            )}
          </div>
          <div className="flex flex-wrap gap-2">
            <Button
              size="sm"
              variant="secondary"
              icon={<ShieldCheck className="w-3.5 h-3.5" />}
              onClick={() => onWhitelistAdd(detailFlow.target)}
            >
              加入白名单
            </Button>
            {!isProtectedBootstrapTarget(detailFlow.target) &&
              detailFlow.deviceIp &&
              detailFlow.deviceIp !== '127.0.0.1' && (
                <Button
                  size="sm"
                  variant="secondary"
                  className="border-rose-500/35 text-rose-300 hover:bg-rose-500/15"
                  icon={<Ban className="w-3.5 h-3.5" />}
                  onClick={() => onBlockFlow(detailFlow, true)}
                >
                  仅阻断此设备
                </Button>
              )}
            {!isProtectedBootstrapTarget(detailFlow.target) && (
              <Button
                size="sm"
                variant="danger"
                icon={<Ban className="w-3.5 h-3.5" />}
                onClick={() => onBlockFlow(detailFlow, false)}
              >
                全局拉黑
              </Button>
            )}
          </div>
        </div>
      ) : null
    }
  >
    {detailFlow && (
      <div className="space-y-4">
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-2.5">
          <div className="rounded-xl border border-subtle bg-surface2/60 p-3">
            <div className="text-[11px] text-muted">累计上传 ↑</div>
            <div className="mt-1 font-mono tnum text-sm font-bold text-primary">
              {fmtBytes(detailFlow.uploadBytes)}
            </div>
            {(detailFlow.avgUploadBps || 0) > 0 && (
              <div className="text-[10.5px] font-mono text-muted mt-0.5 truncate">
                均速 {fmtBps(detailFlow.avgUploadBps)} · 观测 {fmtDurationSpan(detailFlow.activeSpanSec)}
              </div>
            )}
          </div>
          <div className="rounded-xl border border-subtle bg-surface2/60 p-3">
            <div className="text-[11px] text-muted">累计下载 ↓</div>
            <div className="mt-1 font-mono tnum text-sm font-bold text-primary">
              {fmtBytes(detailFlow.downloadBytes)}
            </div>
            <div className="text-[10.5px] font-mono text-muted mt-0.5">
              上/下比 {Number(detailFlow.uploadRatio || 0).toFixed(2)}x
            </div>
          </div>
          <div className="rounded-xl border border-subtle bg-surface2/60 p-3">
            <div className="text-[11px] text-muted">安全 / 隐私轴</div>
            <div className="mt-1 font-mono tnum text-sm font-bold text-primary">
              {detailFlow.securityScore || 0} / {detailFlow.privacyScore || 0}
            </div>
            <div className="text-[10.5px] text-muted mt-0.5">
              {detailFlow.dominantAxis === 'security'
                ? '安全风险主导'
                : detailFlow.dominantAxis === 'privacy'
                  ? '隐私追踪主导'
                  : detailFlow.dominantAxis === 'both'
                    ? '双轴并发风险'
                    : '基线平稳'}
            </div>
          </div>
          <div className="rounded-xl border border-subtle bg-surface2/60 p-3">
            <div className="text-[11px] text-muted">综合风险分</div>
            <div className="mt-1 font-mono tnum text-sm font-bold text-primary">
              {detailFlow.riskScore || 0} 分
            </div>
            <div className="text-[10.5px] text-muted mt-0.5">
              {detailFlow.threatLabel || '正常'}
            </div>
          </div>
        </div>

        <div className="rounded-xl border border-subtle bg-surface2/50 p-3.5 space-y-2.5">
          <div className="text-xs font-semibold text-primary">网络分流链路与终端画像</div>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-x-4 gap-y-2 text-xs">
            <div className="flex items-center justify-between gap-2 border-b border-subtle/60 pb-1.5">
              <span className="text-muted">来源终端</span>
              <span className="font-medium text-primary truncate">
                {detailFlow.deviceName || detailFlow.deviceIp}
              </span>
            </div>
            <div className="flex items-center justify-between gap-2 border-b border-subtle/60 pb-1.5">
              <span className="text-muted">终端类型 / MAC</span>
              <span className="font-mono text-[11px] text-secondary truncate">
                {formatDeviceRoleLabel(detailFlow.deviceRole)}
                {detailFlow.deviceMac ? ` · ${detailFlow.deviceMac}` : ''}
              </span>
            </div>
            <div className="flex items-center justify-between gap-2 border-b border-subtle/60 pb-1.5">
              <span className="text-muted">目的地址</span>
              <span className="font-mono text-[11px] text-primary truncate">
                {detailFlow.destIp || detailFlow.target}
                {detailFlow.destPort ? `:${detailFlow.destPort}` : ''} ({detailFlow.network.toUpperCase()})
              </span>
            </div>
            <div className="flex items-center justify-between gap-2 border-b border-subtle/60 pb-1.5">
              <span className="text-muted">访问方式</span>
              <span>
                {detailFlow.isDirectIp ? (
                  <Badge tone="warn">绕过 DNS 纯 IP 直连</Badge>
                ) : (
                  <Badge tone="ok">标准域名解析{detailFlow.appName ? ` · ${detailFlow.appName}` : ''}</Badge>
                )}
              </span>
            </div>
            <div className="flex items-start justify-between gap-2 sm:col-span-2">
              <span className="text-muted shrink-0 pt-0.5">完整分流链 (Chains)</span>
              <div className="flex flex-wrap items-center justify-end gap-1">
                {detailFlow.chains && detailFlow.chains.length > 0 ? (
                  detailFlow.chains.map((hop, idx) => (
                    <React.Fragment key={`${hop}-${idx}`}>
                      {idx > 0 && <span className="text-muted text-[10px]">→</span>}
                      <Badge
                        tone={
                          idx === detailFlow.chains!.length - 1
                            ? formatOutboundMeta(hop).tone
                            : 'neutral'
                        }
                      >
                        {hop}
                      </Badge>
                    </React.Fragment>
                  ))
                ) : (
                  <Badge tone={formatOutboundMeta(detailFlow.outbound).tone}>
                    {formatOutboundMeta(detailFlow.outbound).label}
                  </Badge>
                )}
              </div>
            </div>
            <div className="flex items-center justify-between gap-2 sm:col-span-2">
              <span className="text-muted">命中规则 (Rule)</span>
              <span className="font-mono text-[11px] text-secondary truncate max-w-[320px]" title={detailFlow.rule || 'final / 默认路由'}>
                {detailFlow.rule || 'final / 默认路由'}
              </span>
            </div>
          </div>
        </div>

        {!isProtectedBootstrapTarget(detailFlow.target) && (
          <div className="rounded-xl border border-subtle bg-surface2/50 p-3.5 space-y-2.5">
            <div className="flex items-center justify-between gap-2">
              <div className="flex items-center gap-1.5 text-xs font-semibold text-primary">
                <Gauge className="w-3.5 h-3.5 text-accent" />
                <span>限速防爆（不断网）</span>
              </div>
              {(detailFlow.throttledRateKbps || 0) > 0 ? (
                <Badge tone="accent">已限速 {detailFlow.throttledRateKbps} KB/s</Badge>
              ) : (
                <Badge tone="neutral">未限速</Badge>
              )}
            </div>
            <p className="text-[11px] text-muted leading-relaxed">
              锁定{' '}
              <span className="font-mono text-secondary">
                {detailFlow.target}
                {detailFlow.destPort ? `:${detailFlow.destPort}` : ''}
              </span>{' '}
              的网关上行封顶速率但不切断长连接，既防止后台突发跑满宽带，又不影响智能设备在线控制。
            </p>
            <div className="flex flex-wrap items-center gap-2">
              {[
                { rate: 5, label: '5 KB/s (IoT 心跳)' },
                { rate: 20, label: '20 KB/s' },
                { rate: 100, label: '100 KB/s' },
              ].map((preset) => {
                const active = detailFlow.throttledRateKbps === preset.rate;
                return (
                  <Button
                    key={preset.rate}
                    size="xs"
                    variant={active ? 'primary' : 'secondary'}
                    disabled={throttleBusy}
                    onClick={() => onSetThrottle(detailFlow, preset.rate)}
                  >
                    {preset.label}
                  </Button>
                );
              })}
              {(detailFlow.throttledRateKbps || 0) > 0 && (
                <Button
                  size="xs"
                  variant="ghost"
                  disabled={throttleBusy}
                  onClick={() => onSetThrottle(detailFlow, 0)}
                >
                  解除限速
                </Button>
              )}
            </div>
          </div>
        )}

        {detailFlow.isDirectIp && detailFlow.subnetCluster && (
          <div className="rounded-xl border border-subtle bg-surface2/50 p-3.5 space-y-2.5">
            <div className="flex items-center justify-between gap-2">
              <span className="text-xs font-semibold text-primary">目的网段聚集分析 (CIDR)</span>
              {detailFlow.subnetCluster.suspicious ? (
                <Badge tone="warn">聚集告警 · {detailFlow.subnetCluster.uniqueIps} IP</Badge>
              ) : detailFlow.subnetCluster.uniqueIps > 1 ? (
                <Badge tone="neutral">同段多 IP · {detailFlow.subnetCluster.uniqueIps} IP</Badge>
              ) : (
                <Badge tone="neutral">单 IP 直连</Badge>
              )}
            </div>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-x-4 gap-y-2 text-xs">
              <div className="flex items-center justify-between gap-2 border-b border-subtle/60 pb-1.5">
                <span className="text-muted">归属网段</span>
                <span className="font-mono text-[11px] font-semibold text-primary">
                  {detailFlow.subnetCluster.cidr}
                </span>
              </div>
              <div className="flex items-center justify-between gap-2 border-b border-subtle/60 pb-1.5">
                <span className="text-muted">网段累计与活跃</span>
                <span className="font-mono tnum text-[11px] text-secondary">
                  ↑ {fmtBytes(detailFlow.subnetCluster.uploadBytes)} / ↓{' '}
                  {fmtBytes(detailFlow.subnetCluster.downloadBytes)} ·{' '}
                  {detailFlow.subnetCluster.flowCount} 流 ({detailFlow.subnetCluster.activeConns} 活跃)
                </span>
              </div>
            </div>
            {detailFlow.subnetCluster.sampleIps && detailFlow.subnetCluster.sampleIps.length > 0 && (
              <div className="space-y-1">
                <div className="text-[11px] text-muted">同网段命中 IP 样本</div>
                <div className="flex flex-wrap gap-1.5">
                  {detailFlow.subnetCluster.sampleIps.map((ip) => (
                    <span
                      key={ip}
                      className="px-1.5 py-0.5 rounded bg-surface2 border border-subtle font-mono text-[10.5px] text-secondary"
                    >
                      {ip}
                    </span>
                  ))}
                </div>
              </div>
            )}
            <div className="flex flex-wrap items-center gap-2 pt-1">
              <Button
                size="sm"
                variant="secondary"
                icon={<Search className="w-3.5 h-3.5" />}
                onClick={() => onFilterBySubnet(detailFlow.subnetCluster!.cidr)}
              >
                筛选同网段
              </Button>
              {detailFlow.deviceIp &&
                detailFlow.deviceIp !== '127.0.0.1' &&
                !isProtectedBootstrapTarget(detailFlow.target) && (
                  <Button
                    size="sm"
                    variant="secondary"
                    className="border-amber-500/35 text-amber-300 hover:bg-amber-500/15"
                    icon={<Ban className="w-3.5 h-3.5" />}
                    onClick={() =>
                      onRequestSubnetBlock({
                        cidr: detailFlow.subnetCluster!.cidr,
                        sourceIp: detailFlow.deviceIp,
                        deviceLabel: detailFlow.deviceName || detailFlow.deviceIp,
                        uniqueIps: detailFlow.subnetCluster!.uniqueIps,
                        reason: detailFlow.subnetCluster!.suspicious
                          ? `同网段裸IP聚集封禁 (${detailFlow.subnetCluster!.cidr}, ${detailFlow.subnetCluster!.uniqueIps} IP)`
                          : `行为审计按设备封禁网段 (${detailFlow.subnetCluster!.cidr})`,
                      })
                    }
                  >
                    仅针对此设备封禁 {detailFlow.subnetCluster.cidr}
                  </Button>
                )}
            </div>
          </div>
        )}

        <div className="rounded-xl border border-subtle bg-surface2/50 p-3.5 space-y-2.5">
          <div className="text-xs font-semibold text-primary">时间跨度与连接节律特征</div>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-x-4 gap-y-2 text-xs">
            <div className="flex items-center justify-between gap-2 border-b border-subtle/60 pb-1.5">
              <span className="text-muted">连接活跃态</span>
              <span className="font-mono tnum text-primary">
                <strong className={(detailFlow.activeConns || 0) > 0 ? 'text-emerald-400' : 'text-secondary'}>
                  {detailFlow.activeConns || 0} 活跃
                </strong>{' '}
                / 累计 {detailFlow.connCount || 1} 次
              </span>
            </div>
            <div className="flex items-center justify-between gap-2 border-b border-subtle/60 pb-1.5">
              <span className="text-muted">凌晨暗夜活跃</span>
              <span className="font-mono tnum">
                {(detailFlow.nightHits || 0) > 0 ? (
                  <span className="text-amber-400 font-semibold">01:00–05:59 捕获 {detailFlow.nightHits} 次</span>
                ) : (
                  <span className="text-muted">0 次 (无夜间异动)</span>
                )}
              </span>
            </div>
            <div className="flex items-center justify-between gap-2 border-b border-subtle/60 pb-1.5">
              <span className="text-muted">首次观测</span>
              <span className="font-mono text-[11px] text-secondary">{detailFlow.firstSeen || '—'}</span>
            </div>
            <div className="flex items-center justify-between gap-2 border-b border-subtle/60 pb-1.5">
              <span className="text-muted">最近活跃</span>
              <span className="font-mono text-[11px] text-secondary">{detailFlow.lastSeen || '—'}</span>
            </div>
            <div className="flex items-center justify-between gap-2">
              <span className="text-muted">心跳变异系数 (CV)</span>
              <span className="font-mono text-[11px] text-secondary">
                {typeof detailFlow.intervalCv === 'number' && detailFlow.intervalCv > 0
                  ? `${detailFlow.intervalCv.toFixed(2)} (${detailFlow.intervalCv < 0.35 ? '疑似定时脚本心跳' : '自然离散'})`
                  : '样本不足'}
              </span>
            </div>
            <div className="flex items-center justify-between gap-2">
              <span className="text-muted">域名信息熵</span>
              <span className="font-mono text-[11px] text-secondary">
                {detailFlow.isDirectIp
                  ? '纯 IP (无域名)'
                  : `${Number(detailFlow.domainEntropy || 0).toFixed(2)} bits${
                      (detailFlow.domainEntropy || 0) >= 3.65 ? ' (偏高随机性)' : ''
                    }`}
              </span>
            </div>
          </div>
        </div>

        {(() => {
          const rawFactors = detailFlow.nonlinearFactors || {};
          const activeFactors = Object.entries(NONLINEAR_FACTOR_LABELS)
            .map(([k, label]) => ({ key: k, label, score: Number(rawFactors[k] || 0) }))
            .filter((item) => item.score > 0)
            .sort((a, b) => b.score - a.score);
          if (activeFactors.length === 0) return null;
          return (
            <div className="rounded-xl border border-subtle bg-surface2/50 p-3.5 space-y-2.5">
              <div className="text-xs font-semibold text-primary">非线性风险算子分量拆解</div>
              <div className="space-y-2">
                {activeFactors.map((item) => {
                  const pct = Math.min(100, Math.max(6, Math.round((item.score / 50) * 100)));
                  return (
                    <div key={item.key} className="space-y-1">
                      <div className="flex items-center justify-between text-[11px]">
                        <span className="text-secondary">{item.label}</span>
                        <span className="font-mono tnum text-primary">+{item.score.toFixed(1)}</span>
                      </div>
                      <div className="h-1.5 rounded-full bg-slate-800 overflow-hidden">
                        <div
                          className="h-full rounded-full bg-gradient-to-r from-amber-500/80 to-rose-500"
                          style={{ width: `${pct}%` }}
                        />
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          );
        })()}

        {(() => {
          const rev = getCachedReview(detailFlow);
          if (!rev) return null;
          return (
            <div className="rounded-xl border border-subtle bg-surface2/60 p-3.5 space-y-1.5">
              <div className="flex items-center justify-between">
                <span className="text-xs font-semibold text-primary">AI 深度研判结论</span>
                <Badge
                  tone={
                    rev.verdict === 'safe_to_block'
                      ? 'danger'
                      : rev.verdict === 'caution'
                        ? 'warn'
                        : 'accent'
                  }
                >
                  {rev.verdictText} · {rev.category}
                </Badge>
              </div>
              <p className="text-xs text-secondary leading-relaxed">{rev.impact}</p>
              {rev.source && (
                <div className="text-[11px] font-mono text-muted">来源: {rev.source}</div>
              )}
            </div>
          );
        })()}

        <div className="space-y-2">
          <div className="text-xs font-semibold text-primary flex items-center gap-1.5">
            <AlertTriangle className="w-3.5 h-3.5 text-amber-400" />
            启发式风险依据
          </div>
          {detailFlow.reasons && detailFlow.reasons.length > 0 ? (
            <ul className="space-y-1.5 text-xs text-secondary">
              {detailFlow.reasons.map((r, i) => (
                <li key={i} className="rounded-lg bg-surface2/70 border border-subtle px-3 py-2">
                  {r}
                </li>
              ))}
            </ul>
          ) : (
            <div className="text-xs text-muted">未触发异常启发式特征</div>
          )}
        </div>
      </div>
    )}
  </SlideDrawer>
);

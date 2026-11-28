import React, { useEffect, useRef, useState } from 'react';
import {
  AlertTriangle,
  ArrowRightLeft,
  Ban,
  Bot,
  ChevronDown,
  ChevronLeft,
  ChevronRight,
  Copy,
  Gauge,
  Search,
  ShieldCheck,
  ShieldOff,
  Unplug,
} from 'lucide-react';
import {
  Badge,
  Button,
  SlideDrawer,
  formatBytes as fmtBytes,
} from '../../../ui';
import {
  AuditAIReview,
  AuditFlowRecord,
  AuditRouteRuleDeleteRequest,
  AuditRouteRuleUpsertRequest,
  ClientRoutingReport,
} from '../../types';
import {
  fmtBps,
  fmtDurationSpan,
  formatDeviceRoleLabel,
  formatOutboundMeta,
  getFlowCacheKey,
  isProtectedBootstrapTarget,
  NONLINEAR_FACTOR_LABELS,
  SubnetBlockConfirmState,
} from './auditHelpers';
import { AuditRouteRulePopover, findMatchingCustomRule } from './AuditRouteRulePopover';
import { AuditSubConnsCard } from './AuditSubConnsCard';

export interface AuditFlowDetailDrawerProps {
  detailFlow: AuditFlowRecord | null;
  detailIndex: number;
  totalCount: number;
  throttleBusy: boolean;
  isAuditOnlyMode?: boolean;
  routeBusy?: boolean;
  routingReport?: ClientRoutingReport | null;
  getCachedReview: (f: AuditFlowRecord) => AuditAIReview | null;
  onClose: () => void;
  onNavigatePrev: () => void;
  onNavigateNext: () => void;
  onCopyText: (text: string, label?: string) => void;
  onReviewSingleFlow: (f: AuditFlowRecord, force: boolean) => void;
  onCloseFlowConnections: (f: AuditFlowRecord) => void;
  onCloseSingleSubConn: (connId: string, label?: string) => Promise<void> | void;
  onWhitelistAction: (action: 'add' | 'remove', target: string) => void;
  onBlockFlow: (f: AuditFlowRecord, deviceOnly: boolean) => void;
  onSetThrottle: (f: AuditFlowRecord, rateKbps: number) => void;
  onUpsertRouteRule?: (req: AuditRouteRuleUpsertRequest) => void;
  onDeleteRouteRule?: (req: AuditRouteRuleDeleteRequest) => void;
  onFilterByDevice: (f: AuditFlowRecord) => void;
  onFilterByChain: (chain: string) => void;
  onFilterBySubnet: (cidr: string) => void;
  onRequestSubnetBlock: (state: SubnetBlockConfirmState) => void;
}

export const AuditFlowDetailDrawer: React.FC<AuditFlowDetailDrawerProps> = ({
  detailFlow,
  detailIndex,
  totalCount,
  throttleBusy,
  isAuditOnlyMode = false,
  routeBusy = false,
  routingReport = null,
  getCachedReview,
  onClose,
  onNavigatePrev,
  onNavigateNext,
  onCopyText,
  onReviewSingleFlow,
  onCloseFlowConnections,
  onCloseSingleSubConn,
  onWhitelistAction,
  onBlockFlow,
  onSetThrottle,
  onUpsertRouteRule,
  onDeleteRouteRule,
  onFilterByDevice,
  onFilterByChain,
  onFilterBySubnet,
  onRequestSubnetBlock,
}) => {
  const flowKey = detailFlow ? getFlowCacheKey(detailFlow) : '';
  const isRisky = detailFlow?.threat === 'high_risk' || detailFlow?.threat === 'suspicious';
  const [techOpen, setTechOpen] = useState(Boolean(isRisky));
  const [routeOpen, setRouteOpen] = useState(false);
  const routeBtnRef = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    setTechOpen(Boolean(isRisky));
    setRouteOpen(false);
  }, [flowKey, isRisky]);

  useEffect(() => {
    if (!detailFlow) return;
    const onKeyDown = (e: KeyboardEvent) => {
      const tag = (document.activeElement?.tagName || '').toLowerCase();
      if (tag === 'input' || tag === 'textarea' || tag === 'select') return;
      if (e.key === 'ArrowUp' && detailIndex > 0) {
        e.preventDefault();
        onNavigatePrev();
      } else if (e.key === 'ArrowDown' && detailIndex >= 0 && detailIndex < totalCount - 1) {
        e.preventDefault();
        onNavigateNext();
      }
    };
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, [detailFlow, detailIndex, totalCount, onNavigatePrev, onNavigateNext]);

  const rev = detailFlow ? getCachedReview(detailFlow) : null;
  const isWhitelisted = detailFlow?.state === 'whitelisted';
  const protectedTarget = detailFlow ? isProtectedBootstrapTarget(detailFlow.target) : false;

  return (
    <SlideDrawer
      open={Boolean(detailFlow)}
      onClose={onClose}
      size="lg"
      title={
        detailFlow ? (
          <div className="flex items-center gap-2 min-w-0">
            <span className="font-mono truncate">{detailFlow.target}</span>
            <button
              type="button"
              onClick={() => onCopyText(detailFlow.target, '目标')}
              className="p-1 rounded-md text-slate-400 hover:text-white hover:bg-slate-800/70 transition-colors shrink-0 cursor-pointer"
              title="复制目标域名/IP"
            >
              <Copy className="w-3.5 h-3.5" />
            </button>
          </div>
        ) : (
          '连接行为详情'
        )
      }
      subtitle={
        detailFlow
          ? `${detailFlow.deviceName || detailFlow.deviceIp} (${detailFlow.deviceIp}) · ${detailFlow.network.toUpperCase()}${
              detailFlow.destPort ? `:${detailFlow.destPort}` : ''
            }`
          : ''
      }
      headerExtra={
        detailFlow && totalCount > 1 && detailIndex >= 0 ? (
          <div className="inline-flex items-center rounded-lg border border-slate-700/80 bg-slate-800/70 text-[11px] font-mono tnum">
            <button
              type="button"
              disabled={detailIndex <= 0}
              onClick={onNavigatePrev}
              className="p-1 text-slate-300 hover:text-white disabled:opacity-35 cursor-pointer"
              title="上一条 (键盘 ↑)"
            >
              <ChevronLeft className="w-3.5 h-3.5" />
            </button>
            <span className="px-1.5 text-slate-300">
              {detailIndex + 1}/{totalCount}
            </span>
            <button
              type="button"
              disabled={detailIndex >= totalCount - 1}
              onClick={onNavigateNext}
              className="p-1 text-slate-300 hover:text-white disabled:opacity-35 cursor-pointer"
              title="下一条 (键盘 ↓)"
            >
              <ChevronRight className="w-3.5 h-3.5" />
            </button>
          </div>
        ) : null
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
              {!isAuditOnlyMode && !protectedTarget && onUpsertRouteRule && (
                <button
                  ref={routeBtnRef}
                  type="button"
                  disabled={routeBusy}
                  onClick={() => setRouteOpen((v) => !v)}
                  className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium border transition-colors cursor-pointer disabled:opacity-50 ${
                    findMatchingCustomRule(detailFlow, routingReport?.customRules)
                      ? 'bg-accent/18 border-accent/45 text-accent hover:bg-accent/25'
                      : 'bg-surface2 border-subtle text-primary hover:bg-surfaceHover'
                  }`}
                >
                  <ArrowRightLeft className="w-3.5 h-3.5" />
                  <span>切换出口</span>
                </button>
              )}
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
              {isWhitelisted ? (
                <Button
                  size="sm"
                  variant="secondary"
                  icon={<ShieldOff className="w-3.5 h-3.5" />}
                  onClick={() => onWhitelistAction('remove', detailFlow.target)}
                >
                  移出白名单
                </Button>
              ) : (
                <Button
                  size="sm"
                  variant="secondary"
                  icon={<ShieldCheck className="w-3.5 h-3.5" />}
                  onClick={() => onWhitelistAction('add', detailFlow.target)}
                >
                  加入白名单
                </Button>
              )}
              {!protectedTarget && detailFlow.deviceIp && detailFlow.deviceIp !== '127.0.0.1' && (
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
              {!protectedTarget && (
                <Button
                  size="sm"
                  variant="danger"
                  icon={<Ban className="w-3.5 h-3.5" />}
                  onClick={() => onBlockFlow(detailFlow, false)}
                >
                  全屋拉黑
                </Button>
              )}
            </div>
          </div>
        ) : null
      }
    >
      {detailFlow && (
        <div className="space-y-4">
          {/* 1. Core live metrics */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-2.5">
            <div className="rounded-xl border border-subtle bg-surface2/60 p-3">
              <div className="text-[11px] text-muted">累计上传 ↑</div>
              <div className="mt-1 font-mono tnum text-sm font-bold text-primary">
                {fmtBytes(detailFlow.uploadBytes)}
              </div>
              <div className="text-[10.5px] font-mono text-muted mt-0.5 truncate">
                {(detailFlow.activeConns || 0) > 0 && (detailFlow.currentUploadBps || 0) > 0 ? (
                  <span className="text-emerald-400">实时 {fmtBps(detailFlow.currentUploadBps)}</span>
                ) : (detailFlow.activeConns || 0) > 0 ? (
                  <span>当前无实时上传</span>
                ) : (
                  <span>观测 {fmtDurationSpan(detailFlow.activeSpanSec)}</span>
                )}
              </div>
            </div>
            <div className="rounded-xl border border-subtle bg-surface2/60 p-3">
              <div className="text-[11px] text-muted">累计下载 ↓</div>
              <div className="mt-1 font-mono tnum text-sm font-bold text-primary">
                {fmtBytes(detailFlow.downloadBytes)}
              </div>
              <div className="text-[10.5px] font-mono text-muted mt-0.5 truncate">
                {(detailFlow.activeConns || 0) > 0 && (detailFlow.currentDownloadBps || 0) > 0 ? (
                  <>
                    <span className="text-sky-400">实时 {fmtBps(detailFlow.currentDownloadBps)}</span> ·{' '}
                  </>
                ) : null}
                比值 {Number(detailFlow.uploadRatio || 0).toFixed(2)}x
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
                {isWhitelisted ? '已放行' : detailFlow.threatLabel || '正常'}
              </div>
            </div>
          </div>

          {/* 2. Decision Bench: AI Verdict + Heuristic Reasons upfront */}
          {rev && (
            <div className="rounded-xl border border-subtle bg-surface2/60 p-3.5 space-y-1.5">
              <div className="flex items-center justify-between gap-2">
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
          )}

          {detailFlow.reasons && detailFlow.reasons.length > 0 && (
            <div className="space-y-2">
              <div className="text-xs font-semibold text-primary flex items-center gap-1.5">
                <AlertTriangle className="w-3.5 h-3.5 text-amber-400" />
                研判与风险依据
              </div>
              <ul className="space-y-1.5 text-xs text-secondary">
                {detailFlow.reasons.map((r, i) => (
                  <li key={i} className="rounded-lg bg-surface2/70 border border-subtle px-3 py-2">
                    {r}
                  </li>
                ))}
              </ul>
            </div>
          )}

          {/* 3. Clash-style Active Sub-Connections Microscope */}
          <AuditSubConnsCard
            activeConns={detailFlow.activeConns || 0}
            details={detailFlow.activeConnDetails}
            onCloseSingleSubConn={onCloseSingleSubConn}
          />

          {/* 4. Routing & Device Profile */}
          <div className="rounded-xl border border-subtle bg-surface2/50 p-3.5 space-y-2.5">
            <div className="text-xs font-semibold text-primary">网络分流链路与终端画像</div>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-x-4 gap-y-2 text-xs">
              <div className="flex items-center justify-between gap-2 border-b border-subtle/60 pb-1.5">
                <span className="text-muted">来源终端</span>
                <button
                  type="button"
                  onClick={() => {
                    onFilterByDevice(detailFlow);
                    onClose();
                  }}
                  className="font-medium text-accent hover:underline truncate cursor-pointer"
                  title="点击按此设备筛选列表"
                >
                  {detailFlow.deviceName || detailFlow.deviceIp}
                </button>
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
                <button
                  type="button"
                  onClick={() => onCopyText(detailFlow.destIp || detailFlow.target, '目的 IP')}
                  className="inline-flex items-center gap-1 font-mono text-[11px] text-primary hover:text-accent truncate cursor-pointer"
                  title="点击复制目的地址"
                >
                  <span className="truncate">
                    {detailFlow.destIp || detailFlow.target}
                    {detailFlow.destPort ? `:${detailFlow.destPort}` : ''} ({detailFlow.network.toUpperCase()})
                  </span>
                  <Copy className="w-3 h-3 shrink-0 opacity-70" />
                </button>
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
                <span className="text-muted shrink-0 pt-0.5">完整分流链</span>
                <div className="flex flex-wrap items-center justify-end gap-1">
                  {detailFlow.chains && detailFlow.chains.length > 0 ? (
                    detailFlow.chains.map((hop, idx) => (
                      <React.Fragment key={`${hop}-${idx}`}>
                        {idx > 0 && <span className="text-muted text-[10px]">→</span>}
                        <button
                          type="button"
                          onClick={() => {
                            onFilterByChain(hop);
                            onClose();
                          }}
                          className="cursor-pointer"
                          title={`点击按链路 ${hop} 筛选`}
                        >
                          <Badge
                            tone={
                              idx === detailFlow.chains!.length - 1
                                ? formatOutboundMeta(hop).tone
                                : 'neutral'
                            }
                          >
                            {hop}
                          </Badge>
                        </button>
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
                <span className="text-muted">命中规则</span>
                <span
                  className="font-mono text-[11px] text-secondary truncate max-w-[360px]"
                  title={detailFlow.rule || 'final / 默认路由'}
                >
                  {detailFlow.rule || 'final / 默认路由'}
                </span>
              </div>
            </div>
          </div>

          {/* 5. Throttle Control */}
          {!protectedTarget && (
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
              <div className="flex flex-wrap items-center gap-2">
                {[
                  { rate: 5, label: '5 KB/s (IoT 心跳)' },
                  { rate: 20, label: '20 KB/s' },
                  { rate: 100, label: '100 KB/s' },
                ].map((preset) => (
                  <Button
                    key={preset.rate}
                    size="xs"
                    variant={detailFlow.throttledRateKbps === preset.rate ? 'primary' : 'secondary'}
                    disabled={throttleBusy}
                    onClick={() => onSetThrottle(detailFlow, preset.rate)}
                  >
                    {preset.label}
                  </Button>
                ))}
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

          {/* 6. Direct-IP CIDR Cluster */}
          {detailFlow.isDirectIp && detailFlow.subnetCluster && (
            <div className="rounded-xl border border-subtle bg-surface2/50 p-3.5 space-y-2.5">
              <div className="flex items-center justify-between gap-2">
                <span className="text-xs font-semibold text-primary">目的网段聚集分析 (CIDR)</span>
                <Badge tone={detailFlow.subnetCluster.suspicious ? 'warn' : 'neutral'}>
                  {detailFlow.subnetCluster.cidr} · {detailFlow.subnetCluster.uniqueIps} IP
                </Badge>
              </div>
              {detailFlow.subnetCluster.sampleIps && detailFlow.subnetCluster.sampleIps.length > 0 && (
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
              )}
              <div className="flex flex-wrap items-center gap-2">
                <Button
                  size="xs"
                  variant="secondary"
                  icon={<Search className="w-3 h-3" />}
                  onClick={() => onFilterBySubnet(detailFlow.subnetCluster!.cidr)}
                >
                  筛选同网段
                </Button>
                {detailFlow.deviceIp && detailFlow.deviceIp !== '127.0.0.1' && !protectedTarget && (
                  <Button
                    size="xs"
                    variant="secondary"
                    className="border-amber-500/35 text-amber-300 hover:bg-amber-500/15"
                    icon={<Ban className="w-3 h-3" />}
                    onClick={() =>
                      onRequestSubnetBlock({
                        cidr: detailFlow.subnetCluster!.cidr,
                        sourceIp: detailFlow.deviceIp,
                        deviceLabel: detailFlow.deviceName || detailFlow.deviceIp,
                        uniqueIps: detailFlow.subnetCluster!.uniqueIps,
                        reason: `同网段裸IP聚集封禁 (${detailFlow.subnetCluster!.cidr}, ${detailFlow.subnetCluster!.uniqueIps} IP)`,
                      })
                    }
                  >
                    仅针对此设备封禁 {detailFlow.subnetCluster.cidr}
                  </Button>
                )}
              </div>
            </div>
          )}

          {/* 7. Collapsible Advanced Technical Diagnostics */}
          <div className="rounded-xl border border-subtle bg-surface2/40 overflow-hidden">
            <button
              type="button"
              onClick={() => setTechOpen((v) => !v)}
              className="w-full px-3.5 py-2.5 flex items-center justify-between gap-2 text-xs font-semibold text-secondary hover:text-primary transition-colors cursor-pointer"
            >
              <span>高级技术诊断（心跳 CV、域名熵与非线性算子）</span>
              {techOpen ? <ChevronDown className="w-4 h-4" /> : <ChevronRight className="w-4 h-4" />}
            </button>
            {techOpen && (
              <div className="px-3.5 pb-3.5 pt-1 border-t border-subtle/60 space-y-3 text-xs">
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-x-4 gap-y-2">
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-muted">首次观测</span>
                    <span className="font-mono text-[11px] text-secondary">{detailFlow.firstSeen || '—'}</span>
                  </div>
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-muted">最近活跃</span>
                    <span className="font-mono text-[11px] text-secondary">{detailFlow.lastSeen || '—'}</span>
                  </div>
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-muted">凌晨暗夜活跃</span>
                    <span className="font-mono tnum text-[11px]">
                      {(detailFlow.nightHits || 0) > 0 ? (
                        <span className="text-amber-400">01:00–05:59 × {detailFlow.nightHits}</span>
                      ) : (
                        <span className="text-muted">0 次</span>
                      )}
                    </span>
                  </div>
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-muted">心跳变异系数 (CV)</span>
                    <span className="font-mono text-[11px] text-secondary">
                      {typeof detailFlow.intervalCv === 'number' && detailFlow.intervalCv > 0
                        ? `${detailFlow.intervalCv.toFixed(2)} (${detailFlow.intervalCv < 0.35 ? '规律心跳' : '自然离散'})`
                        : '样本不足'}
                    </span>
                  </div>
                  <div className="flex items-center justify-between gap-2 sm:col-span-2">
                    <span className="text-muted">域名信息熵</span>
                    <span className="font-mono text-[11px] text-secondary">
                      {detailFlow.isDirectIp
                        ? '纯 IP (无域名)'
                        : `${Number(detailFlow.domainEntropy || 0).toFixed(2)} bits`}
                    </span>
                  </div>
                </div>

                {(() => {
                  const rawFactors = detailFlow.nonlinearFactors || {};
                  const activeFactors = Object.entries(NONLINEAR_FACTOR_LABELS)
                    .map(([k, label]) => ({ key: k, label, score: Number(rawFactors[k] || 0) }))
                    .filter((item) => item.score > 0)
                    .sort((a, b) => b.score - a.score);
                  if (!activeFactors.length) return null;
                  return (
                    <div className="space-y-2 pt-2 border-t border-subtle/60">
                      <div className="text-[11px] font-semibold text-primary">非线性风险算子拆解</div>
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
                  );
                })()}
              </div>
            )}
          </div>
        </div>
      )}
      {detailFlow && !isAuditOnlyMode && !protectedTarget && onUpsertRouteRule && onDeleteRouteRule && (
        <AuditRouteRulePopover
          open={routeOpen}
          anchorEl={routeBtnRef.current}
          flow={detailFlow}
          routingReport={routingReport ?? null}
          busy={routeBusy}
          onSelectOutbound={onUpsertRouteRule}
          onDeleteRule={onDeleteRouteRule}
          onClose={() => setRouteOpen(false)}
        />
      )}
    </SlideDrawer>
  );
};

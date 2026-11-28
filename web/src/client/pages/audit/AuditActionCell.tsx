import React, { useEffect, useRef, useState } from 'react';
import { createPortal } from 'react-dom';
import {
  ArrowRightLeft,
  Ban,
  ChevronDown,
  Copy,
  Filter,
  Gauge,
  Globe,
  Laptop,
  MoreHorizontal,
  ShieldCheck,
  ShieldOff,
  Unplug,
} from 'lucide-react';
import { Badge, Button } from '../../../ui';
import {
  AuditFlowRecord,
  AuditRouteRuleDeleteRequest,
  AuditRouteRuleUpsertRequest,
  ClientRoutingReport,
} from '../../types';
import { isProtectedBootstrapTarget } from './auditHelpers';
import { AuditRouteRulePopover, findMatchingCustomRule } from './AuditRouteRulePopover';

export interface AuditActionCellProps {
  flow: AuditFlowRecord;
  isBusy: boolean;
  isDualAlert: boolean;
  disabled: boolean;
  isAuditOnlyMode?: boolean;
  routingReport?: ClientRoutingReport | null;
  onMarkPointerInteraction: () => void;
  onBlockFlow: (f: AuditFlowRecord, deviceOnly: boolean) => void;
  onWhitelistAction: (action: 'add' | 'remove', target: string) => void;
  onCloseFlowConnections: (f: AuditFlowRecord) => void;
  onSetThrottle: (f: AuditFlowRecord, rateKbps: number) => void;
  onUpsertRouteRule?: (req: AuditRouteRuleUpsertRequest) => void;
  onDeleteRouteRule?: (req: AuditRouteRuleDeleteRequest) => void;
  onFilterByDevice: (f: AuditFlowRecord) => void;
  onFilterBySubnet: (cidr: string) => void;
  onCopyTarget: (target: string) => void;
}

interface MenuCoords {
  top: number;
  left: number;
}

function calcMenuCoords(rect: DOMRect, menuW: number, menuH: number): MenuCoords {
  const vw = window.innerWidth || 1280;
  const vh = window.innerHeight || 800;
  let left = rect.right - menuW;
  if (left < 8) left = 8;
  if (left + menuW > vw - 8) left = vw - menuW - 8;
  const spaceBelow = vh - rect.bottom;
  const top = spaceBelow >= menuH + 10 ? rect.bottom + 6 : Math.max(8, rect.top - menuH - 6);
  return { top, left };
}

export const AuditActionCell: React.FC<AuditActionCellProps> = ({
  flow,
  isBusy,
  isDualAlert,
  disabled,
  isAuditOnlyMode = false,
  routingReport = null,
  onMarkPointerInteraction,
  onBlockFlow,
  onWhitelistAction,
  onCloseFlowConnections,
  onSetThrottle,
  onUpsertRouteRule,
  onDeleteRouteRule,
  onFilterByDevice,
  onFilterBySubnet,
  onCopyTarget,
}) => {
  const [openMenu, setOpenMenu] = useState<'block' | 'more' | null>(null);
  const [routeOpen, setRouteOpen] = useState(false);
  const [coords, setCoords] = useState<MenuCoords>({ top: 0, left: 0 });
  const blockBtnRef = useRef<HTMLButtonElement>(null);
  const routeBtnRef = useRef<HTMLButtonElement>(null);
  const moreBtnRef = useRef<HTMLButtonElement>(null);
  const menuRef = useRef<HTMLDivElement>(null);
  const matchedRule = findMatchingCustomRule(flow, routingReport?.customRules);

  useEffect(() => {
    if (!openMenu) return;
    const onDown = (ev: MouseEvent) => {
      const target = ev.target as Node;
      if (
        menuRef.current?.contains(target) ||
        blockBtnRef.current?.contains(target) ||
        moreBtnRef.current?.contains(target)
      ) {
        return;
      }
      setOpenMenu(null);
    };
    const onKey = (ev: KeyboardEvent) => {
      if (ev.key === 'Escape') setOpenMenu(null);
    };
    const onScroll = () => setOpenMenu(null);
    window.addEventListener('mousedown', onDown);
    window.addEventListener('keydown', onKey);
    window.addEventListener('scroll', onScroll, true);
    return () => {
      window.removeEventListener('mousedown', onDown);
      window.removeEventListener('keydown', onKey);
      window.removeEventListener('scroll', onScroll, true);
    };
  }, [openMenu]);

  const protectedTarget = isProtectedBootstrapTarget(flow.target);
  const hasActive = (flow.activeConns || 0) > 0;
  const isWhitelisted = flow.state === 'whitelisted';
  const canScopeDevice = Boolean(flow.deviceIp && flow.deviceIp !== '127.0.0.1');

  const toggleMenu = (kind: 'block' | 'more', e: React.MouseEvent) => {
    e.stopPropagation();
    onMarkPointerInteraction();
    setRouteOpen(false);
    if (openMenu === kind) {
      setOpenMenu(null);
      return;
    }
    const el = kind === 'block' ? blockBtnRef.current : moreBtnRef.current;
    if (!el) return;
    const rect = el.getBoundingClientRect();
    setCoords(calcMenuCoords(rect, kind === 'block' ? 248 : 210, kind === 'block' ? 142 : 270));
    setOpenMenu(kind);
  };

  if (protectedTarget) {
    return (
      <div
        className="flex justify-end items-center gap-1.5 whitespace-nowrap"
        onPointerDown={onMarkPointerInteraction}
        onClick={(e) => e.stopPropagation()}
      >
        {hasActive && (
          <Button
            size="xs"
            variant="secondary"
            loading={isBusy}
            disabled={disabled}
            onClick={() => onCloseFlowConnections(flow)}
            title="仅断开活跃连接强制重连，不影响访问"
          >
            断开
          </Button>
        )}
        <Badge tone="neutral">核心保护</Badge>
      </div>
    );
  }

  return (
    <div
      className="flex justify-end items-center gap-1.5 whitespace-nowrap"
      onPointerDown={onMarkPointerInteraction}
      onClick={(e) => e.stopPropagation()}
    >
      <button
        ref={blockBtnRef}
        type="button"
        disabled={isBusy || disabled}
        onClick={(e) => toggleMenu('block', e)}
        className={`inline-flex items-center gap-1 px-2.5 py-1 rounded-lg text-xs font-medium border transition-colors cursor-pointer disabled:opacity-50 ${
          isDualAlert
            ? 'bg-rose-500/22 border-rose-500/50 text-rose-200 hover:bg-rose-500/30 animate-pulse'
            : 'bg-rose-500/14 border-rose-500/35 text-rose-300 hover:bg-rose-500/24'
        }`}
        title="选择「仅阻断此设备」或「全屋拉黑」（防误杀）"
      >
        <Ban className="w-3 h-3" />
        <span>{isDualAlert ? '立即拉黑' : '拉黑'}</span>
        <ChevronDown className="w-3 h-3 opacity-80" />
      </button>

      {isWhitelisted ? (
        <Button
          size="xs"
          variant="ghost"
          disabled={isBusy || disabled}
          icon={<ShieldOff className="w-3 h-3" />}
          onClick={() => onWhitelistAction('remove', flow.target)}
          title="移出白名单"
        >
          移出
        </Button>
      ) : (
        <Button
          size="xs"
          variant="secondary"
          disabled={isBusy || disabled}
          icon={<ShieldCheck className="w-3 h-3" />}
          onClick={() => onWhitelistAction('add', flow.target)}
          title="加入白名单放行（6 秒内可撤销）"
        >
          放行
        </Button>
      )}

      {!isAuditOnlyMode && onUpsertRouteRule && (
        <button
          ref={routeBtnRef}
          type="button"
          disabled={isBusy || disabled}
          onClick={(e) => {
            e.stopPropagation();
            onMarkPointerInteraction();
            setOpenMenu(null);
            setRouteOpen((v) => !v);
          }}
          className={`inline-flex items-center gap-1 px-2 py-1 rounded-lg text-xs font-medium border transition-colors cursor-pointer disabled:opacity-50 ${
            matchedRule
              ? 'bg-accent/16 border-accent/45 text-accent hover:bg-accent/25'
              : 'bg-surface2/75 border-subtle text-secondary hover:text-primary hover:bg-surfaceHover'
          }`}
          title={
            matchedRule
              ? `已固定出口 → ${matchedRule.outbound}，点击修改或恢复默认分流`
              : '一键切换该目标的出站节点组或直连，并自动加入永久分流/DNS 规则'
          }
        >
          <ArrowRightLeft className="w-3 h-3" />
          <span>改出口</span>
        </button>
      )}

      <button
        ref={moreBtnRef}
        type="button"
        disabled={isBusy || disabled}
        onClick={(e) => toggleMenu('more', e)}
        className="p-1.5 rounded-lg border border-subtle bg-surface2/70 text-secondary hover:text-primary hover:bg-surfaceHover transition-colors cursor-pointer disabled:opacity-50"
        title="更多操作：限速、断开活跃、筛选设备/网段、复制"
        aria-label="更多操作"
      >
        <MoreHorizontal className="w-3.5 h-3.5" />
      </button>

      {openMenu === 'block' &&
        createPortal(
          <div
            ref={menuRef}
            style={{ top: coords.top, left: coords.left, width: 248 }}
            onClick={(e) => e.stopPropagation()}
            className="fixed z-[80] rounded-xl border border-strong bg-slate-900/98 backdrop-blur-xl shadow-2xl p-1.5 space-y-1 animate-sc-in"
          >
            <div className="px-2 py-1 text-[10.5px] text-muted border-b border-subtle/70">
              选择封禁范围 · 6 秒内可撤销
            </div>
            {canScopeDevice && (
              <button
                type="button"
                onClick={() => {
                  setOpenMenu(null);
                  onBlockFlow(flow, true);
                }}
                className="w-full text-left px-2.5 py-2 rounded-lg hover:bg-rose-500/15 transition-colors cursor-pointer group"
              >
                <div className="flex items-center justify-between gap-2">
                  <span className="inline-flex items-center gap-1.5 text-xs font-semibold text-rose-300">
                    <Laptop className="w-3.5 h-3.5" />
                    仅阻断此设备
                  </span>
                  <span className="text-[10px] px-1.5 py-0.5 rounded bg-emerald-500/18 text-emerald-300">
                    推荐
                  </span>
                </div>
                <div className="text-[11px] text-muted mt-0.5 truncate">
                  仅限 {flow.deviceName || flow.deviceIp} ({flow.deviceIp})，不影响其他终端
                </div>
              </button>
            )}
            <button
              type="button"
              onClick={() => {
                setOpenMenu(null);
                onBlockFlow(flow, false);
              }}
              className="w-full text-left px-2.5 py-2 rounded-lg hover:bg-rose-500/15 transition-colors cursor-pointer"
            >
              <div className="inline-flex items-center gap-1.5 text-xs font-semibold text-primary">
                <Globe className="w-3.5 h-3.5 text-rose-400" />
                全屋拉黑
              </div>
              <div className="text-[11px] text-muted mt-0.5 truncate">
                拦截局域网全部设备访问 {flow.target}
              </div>
            </button>
          </div>,
          document.body,
        )}

      {openMenu === 'more' &&
        createPortal(
          <div
            ref={menuRef}
            style={{ top: coords.top, left: coords.left, width: 210 }}
            onClick={(e) => e.stopPropagation()}
            className="fixed z-[80] rounded-xl border border-strong bg-slate-900/98 backdrop-blur-xl shadow-2xl p-1.5 space-y-0.5 text-xs animate-sc-in"
          >
            {hasActive && (
              <button
                type="button"
                onClick={() => {
                  setOpenMenu(null);
                  onCloseFlowConnections(flow);
                }}
                className="w-full flex items-center gap-2 px-2.5 py-1.5 rounded-lg text-amber-300 hover:bg-amber-500/12 transition-colors cursor-pointer"
              >
                <Unplug className="w-3.5 h-3.5 shrink-0" />
                <span>断开活跃连接 ({flow.activeConns})</span>
              </button>
            )}
            <div className="px-2.5 pt-1.5 pb-0.5 text-[10.5px] text-muted flex items-center gap-1">
              <Gauge className="w-3 h-3" />
              <span>限速防爆（不断网）</span>
            </div>
            <div className="grid grid-cols-3 gap-1 px-1.5 pb-1">
              {[5, 20, 100].map((rate) => {
                const act = flow.throttledRateKbps === rate;
                return (
                  <button
                    key={rate}
                    type="button"
                    onClick={() => {
                      setOpenMenu(null);
                      onSetThrottle(flow, rate);
                    }}
                    className={`px-1.5 py-1 rounded-md font-mono text-[11px] border transition-colors cursor-pointer ${
                      act
                        ? 'border-accent/50 bg-accent/20 text-accent font-semibold'
                        : 'border-subtle bg-surface2/70 text-secondary hover:text-primary'
                    }`}
                  >
                    {rate}K
                  </button>
                );
              })}
            </div>
            {(flow.throttledRateKbps || 0) > 0 && (
              <button
                type="button"
                onClick={() => {
                  setOpenMenu(null);
                  onSetThrottle(flow, 0);
                }}
                className="w-full flex items-center gap-2 px-2.5 py-1.5 rounded-lg text-secondary hover:text-primary hover:bg-surfaceHover transition-colors cursor-pointer"
              >
                <Gauge className="w-3.5 h-3.5 shrink-0 text-muted" />
                <span>解除当前限速</span>
              </button>
            )}
            <div className="my-1 border-t border-subtle/70" />
            {canScopeDevice && (
              <button
                type="button"
                onClick={() => {
                  setOpenMenu(null);
                  onFilterByDevice(flow);
                }}
                className="w-full flex items-center gap-2 px-2.5 py-1.5 rounded-lg text-secondary hover:text-primary hover:bg-surfaceHover transition-colors cursor-pointer"
              >
                <Laptop className="w-3.5 h-3.5 shrink-0" />
                <span className="truncate">只看 {flow.deviceName || flow.deviceIp}</span>
              </button>
            )}
            {flow.isDirectIp && flow.subnetCluster?.cidr && (
              <button
                type="button"
                onClick={() => {
                  setOpenMenu(null);
                  onFilterBySubnet(flow.subnetCluster!.cidr);
                }}
                className="w-full flex items-center gap-2 px-2.5 py-1.5 rounded-lg text-secondary hover:text-primary hover:bg-surfaceHover transition-colors cursor-pointer"
              >
                <Filter className="w-3.5 h-3.5 shrink-0" />
                <span className="truncate">筛选同段 {flow.subnetCluster.cidr}</span>
              </button>
            )}
            <button
              type="button"
              onClick={() => {
                setOpenMenu(null);
                onCopyTarget(flow.target);
              }}
              className="w-full flex items-center gap-2 px-2.5 py-1.5 rounded-lg text-secondary hover:text-primary hover:bg-surfaceHover transition-colors cursor-pointer"
            >
              <Copy className="w-3.5 h-3.5 shrink-0" />
              <span>复制目标地址</span>
            </button>
          </div>,
          document.body,
        )}

      {!isAuditOnlyMode && onUpsertRouteRule && onDeleteRouteRule && (
        <AuditRouteRulePopover
          open={routeOpen}
          anchorEl={routeBtnRef.current}
          flow={flow}
          routingReport={routingReport ?? null}
          busy={isBusy || disabled}
          onSelectOutbound={onUpsertRouteRule}
          onDeleteRule={onDeleteRouteRule}
          onClose={() => setRouteOpen(false)}
        />
      )}
    </div>
  );
};

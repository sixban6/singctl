import React, { useEffect, useRef, useState } from 'react';
import { createPortal } from 'react-dom';
import { ArrowRightLeft, Check, Globe, Laptop, RotateCcw } from 'lucide-react';
import { Badge } from '../../../ui';
import {
  AuditFlowRecord,
  AuditRouteRuleDeleteRequest,
  AuditRouteRuleUpsertRequest,
  ClientRoutingReport,
  TrafficCustomRule,
  TrafficMatchType,
} from '../../types';

const MULTI_PART_SUFFIXES = new Set([
  'com.cn',
  'net.cn',
  'org.cn',
  'gov.cn',
  'edu.cn',
  'ac.cn',
  'co.uk',
  'org.uk',
  'gov.uk',
  'co.jp',
  'ne.jp',
  'or.jp',
  'com.hk',
  'com.tw',
  'com.au',
  'com.sg',
]);

function isIPLiteral(raw: string): boolean {
  const s = raw.trim().replace(/^\[|\]$/g, '');
  if (/^\d{1,3}(\.\d{1,3}){3}(\/\d{1,2})?$/.test(s)) return true;
  return s.includes(':') && /^[0-9a-fA-F:]+(\/\d{1,3})?$/.test(s);
}

export function extractSuggestedRootDomain(host: string): string {
  const clean = String(host || '')
    .trim()
    .toLowerCase()
    .replace(/^\*\./, '')
    .replace(/\.$/, '');
  if (!clean || isIPLiteral(clean)) return clean;
  const parts = clean.split('.').filter(Boolean);
  if (parts.length <= 2) return clean;
  const tail2 = `${parts[parts.length - 2]}.${parts[parts.length - 1]}`;
  if (MULTI_PART_SUFFIXES.has(tail2) && parts.length >= 3) {
    return `${parts[parts.length - 3]}.${tail2}`;
  }
  return tail2;
}

export function findMatchingCustomRule(
  flow: AuditFlowRecord,
  rules?: TrafficCustomRule[],
): TrafficCustomRule | null {
  if (!rules || rules.length === 0) return null;
  const raw = String(flow.target || '').trim().toLowerCase().replace(/\.$/, '');
  const devIP = String(flow.deviceIp || '').trim();
  const candidates: TrafficCustomRule[] = [];

  for (const r of rules) {
    const rt = String(r.target || '').trim().toLowerCase().replace(/\.$/, '');
    if (!rt) continue;
    if (r.sourceIp && r.sourceIp !== devIP) continue;
    if (r.matchType === 'ip_cidr') {
      const bareRule = rt.replace(/\/(32|128)$/, '');
      if (raw === rt || raw === bareRule) {
        candidates.push(r);
      }
      continue;
    }
    if (r.matchType === 'domain') {
      if (raw === rt) candidates.push(r);
      continue;
    }
    if (raw === rt || raw.endsWith(`.${rt}`)) {
      candidates.push(r);
    }
  }
  if (candidates.length === 0) return null;
  // 设备精准绑定 > 全屋精确域名 > 全屋后缀域名
  candidates.sort((a, b) => {
    const aDev = a.sourceIp ? 0 : 1;
    const bDev = b.sourceIp ? 0 : 1;
    if (aDev !== bDev) return aDev - bDev;
    const aExact = a.matchType === 'domain' ? 0 : 1;
    const bExact = b.matchType === 'domain' ? 0 : 1;
    return aExact - bExact;
  });
  return candidates[0];
}

export interface AuditRouteRulePopoverProps {
  open: boolean;
  anchorEl: HTMLElement | null;
  flow: AuditFlowRecord;
  routingReport: ClientRoutingReport | null;
  busy?: boolean;
  onSelectOutbound: (req: AuditRouteRuleUpsertRequest) => void;
  onDeleteRule: (req: AuditRouteRuleDeleteRequest) => void;
  onClose: () => void;
}

export const AuditRouteRulePopover: React.FC<AuditRouteRulePopoverProps> = ({
  open,
  anchorEl,
  flow,
  routingReport,
  busy = false,
  onSelectOutbound,
  onDeleteRule,
  onClose,
}) => {
  const menuRef = useRef<HTMLDivElement>(null);
  const cleanHost = String(flow.target || '').trim().toLowerCase().replace(/\.$/, '');
  const isIP = Boolean(flow.isDirectIp || isIPLiteral(cleanHost));
  const rootDomain = isIP ? cleanHost : extractSuggestedRootDomain(cleanHost);
  const canScopeDevice = Boolean(flow.deviceIp && flow.deviceIp !== '127.0.0.1');
  const matchedRule = findMatchingCustomRule(flow, routingReport?.customRules);

  const [matchType, setMatchType] = useState<TrafficMatchType>(
    isIP ? 'ip_cidr' : matchedRule?.matchType === 'domain' ? 'domain' : 'domain_suffix',
  );
  const [scopeDevice, setScopeDevice] = useState(Boolean(matchedRule?.sourceIp));

  useEffect(() => {
    if (!open) return;
    setMatchType(isIP ? 'ip_cidr' : matchedRule?.matchType === 'domain' ? 'domain' : 'domain_suffix');
    setScopeDevice(Boolean(matchedRule?.sourceIp));
  }, [open, cleanHost, isIP, matchedRule?.matchType, matchedRule?.sourceIp]);

  useEffect(() => {
    if (!open) return;
    const onDown = (ev: MouseEvent) => {
      const target = ev.target as Node;
      if (menuRef.current?.contains(target) || anchorEl?.contains(target)) return;
      onClose();
    };
    const onKey = (ev: KeyboardEvent) => {
      if (ev.key === 'Escape') onClose();
    };
    const onScroll = () => onClose();
    window.addEventListener('mousedown', onDown);
    window.addEventListener('keydown', onKey);
    window.addEventListener('scroll', onScroll, true);
    return () => {
      window.removeEventListener('mousedown', onDown);
      window.removeEventListener('keydown', onKey);
      window.removeEventListener('scroll', onScroll, true);
    };
  }, [open, anchorEl, onClose]);

  if (!open || !anchorEl) return null;

  const rect = anchorEl.getBoundingClientRect();
  const menuW = 286;
  const estH = 340;
  const vw = window.innerWidth || 1280;
  const vh = window.innerHeight || 800;
  let left = rect.right - menuW;
  if (left < 8) left = 8;
  if (left + menuW > vw - 8) left = vw - menuW - 8;
  const spaceBelow = vh - rect.bottom;
  const top = spaceBelow >= estH ? rect.bottom + 6 : Math.max(8, rect.top - estH - 6);

  const directTag = routingReport?.directTag || '#DC';
  const effectiveTarget = isIP
    ? cleanHost
    : matchType === 'domain_suffix'
      ? rootDomain || cleanHost
      : cleanHost;
  const groups = routingReport?.groups || [
    { tag: 'Proxy', type: 'selector', count: 0 },
    { tag: '#VPS', type: 'selector', count: 0 },
    { tag: '#Auto', type: 'urltest', count: 0 },
  ];

  const curOutbound = String(flow.outbound || '').trim();
  const isCurrentDirect =
    curOutbound === directTag || curOutbound.toUpperCase() === 'DIRECT' || curOutbound === 'direct';

  const submitOutbound = (outbound: string) => {
    onClose();
    onSelectOutbound({
      target: effectiveTarget,
      matchType,
      outbound,
      sourceIp: scopeDevice && canScopeDevice ? flow.deviceIp : undefined,
      connTarget: cleanHost,
      closeConnections: true,
    });
  };

  return createPortal(
    <div
      ref={menuRef}
      style={{ top, left, width: menuW }}
      onClick={(e) => e.stopPropagation()}
      className="fixed z-[90] rounded-xl border border-strong bg-slate-900/98 backdrop-blur-xl shadow-2xl p-2.5 space-y-2.5 text-xs animate-sc-in"
    >
      <div className="flex items-center justify-between gap-2 pb-1.5 border-b border-subtle/70">
        <div className="min-w-0">
          <div className="font-semibold text-primary flex items-center gap-1.5">
            <ArrowRightLeft className="w-3.5 h-3.5 text-accent shrink-0" />
            <span>切换出口并固定分流</span>
          </div>
          <div className="text-[10.5px] font-mono text-muted truncate mt-0.5">{effectiveTarget}</div>
        </div>
        {matchedRule && <Badge tone="accent">已固定</Badge>}
      </div>

      {!isIP && (
        <div className="space-y-1">
          <div className="text-[10.5px] text-muted">匹配范围（同步写入路由与 DNS）</div>
          <div className="grid grid-cols-2 gap-1">
            <button
              type="button"
              onClick={() => setMatchType('domain_suffix')}
              className={`px-2 py-1.5 rounded-lg border text-[11px] truncate cursor-pointer transition-colors ${
                matchType === 'domain_suffix'
                  ? 'border-accent/60 bg-accent/18 text-primary font-medium'
                  : 'border-subtle bg-surface2/60 text-secondary hover:text-primary'
              }`}
              title={`主域名后缀: *.${rootDomain}`}
            >
              主域 *.{rootDomain}
            </button>
            <button
              type="button"
              onClick={() => setMatchType('domain')}
              className={`px-2 py-1.5 rounded-lg border text-[11px] truncate cursor-pointer transition-colors ${
                matchType === 'domain'
                  ? 'border-accent/60 bg-accent/18 text-primary font-medium'
                  : 'border-subtle bg-surface2/60 text-secondary hover:text-primary'
              }`}
              title={`仅精确匹配 ${cleanHost}`}
            >
              精确 {cleanHost === rootDomain ? '仅当前域名' : cleanHost}
            </button>
          </div>
        </div>
      )}

      {canScopeDevice && (
        <div className="grid grid-cols-2 gap-1">
          <button
            type="button"
            onClick={() => setScopeDevice(false)}
            className={`inline-flex items-center justify-center gap-1 px-2 py-1 rounded-lg border text-[11px] cursor-pointer transition-colors ${
              !scopeDevice
                ? 'border-accent/60 bg-accent/18 text-primary font-medium'
                : 'border-subtle bg-surface2/60 text-secondary hover:text-primary'
            }`}
          >
            <Globe className="w-3 h-3" />
            <span>全局设备</span>
          </button>
          <button
            type="button"
            onClick={() => setScopeDevice(true)}
            className={`inline-flex items-center justify-center gap-1 px-2 py-1 rounded-lg border text-[11px] truncate cursor-pointer transition-colors ${
              scopeDevice
                ? 'border-accent/60 bg-accent/18 text-primary font-medium'
                : 'border-subtle bg-surface2/60 text-secondary hover:text-primary'
            }`}
            title={`仅限定 ${flow.deviceName || flow.deviceIp}`}
          >
            <Laptop className="w-3 h-3 shrink-0" />
            <span className="truncate">仅 {flow.deviceName || flow.deviceIp}</span>
          </button>
        </div>
      )}

      <div className="space-y-1 max-h-48 overflow-y-auto pr-0.5">
        <button
          type="button"
          disabled={busy}
          onClick={() => submitOutbound('direct')}
          className="w-full flex items-center justify-between gap-2 px-2.5 py-1.5 rounded-lg bg-surface2/55 hover:bg-emerald-500/15 border border-subtle/80 hover:border-emerald-500/40 text-left transition-colors cursor-pointer"
        >
          <div className="min-w-0">
            <div className="font-mono font-semibold text-emerald-300 text-xs">
              直连 {directTag}
            </div>
            <div className="text-[10px] text-muted">绕过代理，同步走本地 DNS</div>
          </div>
          <div className="flex items-center gap-1 shrink-0">
            {isCurrentDirect && <Badge tone="neutral">当前</Badge>}
            {matchedRule?.outbound === 'direct' && <Check className="w-3.5 h-3.5 text-emerald-400" />}
          </div>
        </button>

        {groups.map((g) => {
          const isCur = curOutbound === g.tag;
          const isFixed = matchedRule?.outbound === g.tag;
          return (
            <button
              key={g.tag}
              type="button"
              disabled={busy}
              onClick={() => submitOutbound(g.tag)}
              className="w-full flex items-center justify-between gap-2 px-2.5 py-1.5 rounded-lg bg-surface2/55 hover:bg-accent/15 border border-subtle/80 hover:border-accent/40 text-left transition-colors cursor-pointer"
            >
              <div className="min-w-0">
                <div className="font-mono font-semibold text-primary text-xs truncate">{g.tag}</div>
                <div className="text-[10px] text-muted truncate">
                  {g.default ? `${g.type} · 当前 ${g.default}` : g.type}
                </div>
              </div>
              <div className="flex items-center gap-1 shrink-0">
                {isCur && <Badge tone="neutral">当前</Badge>}
                {isFixed && <Check className="w-3.5 h-3.5 text-accent" />}
              </div>
            </button>
          );
        })}
      </div>

      {matchedRule && (
        <div className="pt-1.5 border-t border-subtle/70">
          <button
            type="button"
            disabled={busy}
            onClick={() => {
              onClose();
              onDeleteRule({
                target: matchedRule.target,
                matchType: matchedRule.matchType,
                sourceIp: matchedRule.sourceIp,
                closeConnections: true,
              });
            }}
            className="w-full flex items-center justify-center gap-1.5 px-2.5 py-1.5 rounded-lg border border-amber-500/35 bg-amber-500/10 text-amber-300 hover:bg-amber-500/20 transition-colors cursor-pointer text-[11px]"
          >
            <RotateCcw className="w-3 h-3" />
            <span>恢复默认分流（移除固定规则）</span>
          </button>
        </div>
      )}
    </div>,
    document.body,
  );
};

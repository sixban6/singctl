import React, { useCallback, useEffect, useState } from 'react';
import { emitClientInvalidate } from '../../../hooks';
import { useToast } from '../../../ui';
import { clientApi } from '../../api';
import {
  AuditRouteRuleDeleteRequest,
  AuditRouteRuleUpsertRequest,
  ClientRoutingReport,
} from '../../types';

export interface UseAuditRouteRulesParams {
  active: boolean;
  isAuditOnlyMode: boolean;
  actionInFlightRef: React.MutableRefObject<number>;
  loadAudit: (silent?: boolean) => Promise<void>;
}

export function useAuditRouteRules({
  active,
  isAuditOnlyMode,
  actionInFlightRef,
  loadAudit,
}: UseAuditRouteRulesParams) {
  const { success, error } = useToast();
  const [routingReport, setRoutingReport] = useState<ClientRoutingReport | null>(null);
  const [routeBusy, setRouteBusy] = useState(false);

  const refreshRoutingReport = useCallback(async () => {
    if (isAuditOnlyMode) return;
    try {
      const rep = await clientApi.getTrafficRouting();
      setRoutingReport(rep);
    } catch {
      // ignore transient routing report load error on audit page
    }
  }, [isAuditOnlyMode]);

  useEffect(() => {
    if (active && !isAuditOnlyMode) {
      void refreshRoutingReport();
    }
  }, [active, isAuditOnlyMode, refreshRoutingReport]);

  const handleUpsertRouteRule = async (req: AuditRouteRuleUpsertRequest) => {
    const prevMatched = (routingReport?.customRules || []).find(
      (r) =>
        r.target === req.target &&
        (r.matchType || 'domain_suffix') === (req.matchType || 'domain_suffix') &&
        (r.sourceIp || '') === (req.sourceIp || ''),
    );

    setRouteBusy(true);
    actionInFlightRef.current++;
    try {
      const res = await clientApi.upsertAuditRouteRule(req);
      if (res.report) {
        setRoutingReport(res.report);
      } else {
        await refreshRoutingReport();
      }
      const saved = res.rule;
      const closedNote = res.closedConnections > 0 ? `（已踢断 ${res.closedConnections} 条旧连接）` : '';
      success(
        `${res.message || '已切换并固定出口规则'}${closedNote}`,
        6000,
        saved
          ? {
              label: '撤销',
              onClick: async () => {
                actionInFlightRef.current++;
                try {
                  if (prevMatched) {
                    const undoRes = await clientApi.upsertAuditRouteRule({
                      target: prevMatched.target,
                      matchType: prevMatched.matchType,
                      outbound: prevMatched.outbound,
                      sourceIp: prevMatched.sourceIp,
                      closeConnections: true,
                    });
                    if (undoRes.report) setRoutingReport(undoRes.report);
                  } else {
                    const undoRes = await clientApi.deleteAuditRouteRule({
                      target: saved.target,
                      matchType: saved.matchType,
                      sourceIp: saved.sourceIp,
                      closeConnections: true,
                    });
                    if (undoRes.report) setRoutingReport(undoRes.report);
                  }
                  success(`已撤销对 ${saved.target} 的出口修改`, 3000);
                  emitClientInvalidate('all');
                  await loadAudit(false);
                } catch (ue) {
                  error((ue as Error)?.message || '撤销出口规则失败');
                } finally {
                  actionInFlightRef.current = Math.max(0, actionInFlightRef.current - 1);
                }
              },
            }
          : undefined,
      );
      emitClientInvalidate('all');
      await loadAudit(false);
    } catch (e) {
      error((e as Error)?.message || '切换出口失败');
    } finally {
      setRouteBusy(false);
      actionInFlightRef.current = Math.max(0, actionInFlightRef.current - 1);
    }
  };

  const handleDeleteRouteRule = async (req: AuditRouteRuleDeleteRequest) => {
    setRouteBusy(true);
    actionInFlightRef.current++;
    try {
      const res = await clientApi.deleteAuditRouteRule(req);
      if (res.report) {
        setRoutingReport(res.report);
      } else {
        await refreshRoutingReport();
      }
      success(res.message || `已恢复 ${req.target} 默认分流`);
      emitClientInvalidate('all');
      await loadAudit(false);
    } catch (e) {
      error((e as Error)?.message || '移除自定义出口规则失败');
    } finally {
      setRouteBusy(false);
      actionInFlightRef.current = Math.max(0, actionInFlightRef.current - 1);
    }
  };

  return {
    routingReport,
    routeBusy,
    refreshRoutingReport,
    handleUpsertRouteRule,
    handleDeleteRouteRule,
  };
}

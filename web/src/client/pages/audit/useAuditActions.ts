import React, { useState } from 'react';
import { emitClientInvalidate } from '../../../hooks';
import { useToast } from '../../../ui';
import { clientApi } from '../../api';
import { AuditBlockRule, AuditFlowRecord, AuditReport } from '../../types';
import {
  AuditSortKey,
  getFlowCacheKey,
  isProtectedBootstrapTarget,
  SubnetBlockConfirmState,
} from './auditHelpers';

export interface UseAuditActionsParams {
  report: AuditReport | null;
  deviceFilter: string;
  onlySuspect: boolean;
  sortBy: AuditSortKey;
  sortDir: 'asc' | 'desc';
  detailFlowKey: string | null;
  setDetailFlowKey: (next: string | null) => void;
  setPcdnBannerDismissed: (next: boolean) => void;
  actionInFlightRef: React.MutableRefObject<number>;
  loadAudit: (silent?: boolean) => Promise<void>;
}

export function useAuditActions({
  report,
  deviceFilter,
  onlySuspect,
  sortBy,
  sortDir,
  detailFlowKey,
  setDetailFlowKey,
  setPcdnBannerDismissed,
  actionInFlightRef,
  loadAudit,
}: UseAuditActionsParams) {
  const { success, error, toast } = useToast();

  const [blockBusy, setBlockBusy] = useState(false);
  const [pcdnToggleBusy, setPcdnToggleBusy] = useState(false);
  const [throttleBusy, setThrottleBusy] = useState(false);
  const [busyFlowKeys, setBusyFlowKeys] = useState<Set<string>>(() => new Set());
  const [closingAll, setClosingAll] = useState(false);
  const [closeAllConfirmOpen, setCloseAllConfirmOpen] = useState(false);
  const [subnetBlockConfirm, setSubnetBlockConfirm] = useState<SubnetBlockConfirmState | null>(null);
  const [subnetBlocking, setSubnetBlocking] = useState(false);

  const handleBlockFlow = async (f: AuditFlowRecord, deviceOnly = false) => {
    if (isProtectedBootstrapTarget(f.target)) {
      toast('受核心防断网基础设施保护，禁止拉黑此目标', 'info');
      return;
    }
    const fk = getFlowCacheKey(f);
    const scopedSource =
      deviceOnly && f.deviceIp && f.deviceIp !== '127.0.0.1' ? f.deviceIp : '';
    actionInFlightRef.current++;
    setBusyFlowKeys((prev) => new Set(prev).add(fk));
    try {
      const reason = (f.reasons && f.reasons[0]) || 'WebUI 安全审计拉黑';
      const res = await clientApi.blockAuditTarget(f.target, scopedSource, reason);
      success(
        res.message ||
          (scopedSource ? `已仅针对 ${scopedSource} 阻断 ${f.target}` : `已全局拉黑 ${f.target}`),
      );
      if (detailFlowKey === fk) {
        setDetailFlowKey(null);
      }
      emitClientInvalidate('adguard');
      await loadAudit(false);
    } catch (e) {
      error((e as Error).message || '拉黑失败');
    } finally {
      actionInFlightRef.current = Math.max(0, actionInFlightRef.current - 1);
      setBusyFlowKeys((prev) => {
        const next = new Set(prev);
        next.delete(fk);
        return next;
      });
    }
  };

  const handleManualBlock = async (
    rawTarget: string,
    rawDevice: string,
    overrideReason?: string,
  ): Promise<boolean> => {
    const target = rawTarget.trim();
    if (!target) {
      toast('请输入域名、IP 或 .srs/.json 规则集 URL', 'info');
      return false;
    }
    if (isProtectedBootstrapTarget(target)) {
      toast('受核心防断网基础设施保护，禁止拉黑此目标', 'info');
      return false;
    }
    setBlockBusy(true);
    actionInFlightRef.current++;
    try {
      const isRuleset =
        /^ruleset:/i.test(target) || /^https?:\/\//i.test(target) || /\.(srs|json)(\?|#|$)/i.test(target);
      const reason = overrideReason || (isRuleset ? 'WebUI 规则集整包导入' : 'WebUI 手动拉黑');
      const res = await clientApi.blockAuditTarget(target, rawDevice.trim(), reason);
      success(res.message || '已添加封禁规则');
      emitClientInvalidate('adguard');
      await loadAudit(false);
      return true;
    } catch (e) {
      error((e as Error).message || '添加拉黑规则失败');
      return false;
    } finally {
      setBlockBusy(false);
      actionInFlightRef.current = Math.max(0, actionInFlightRef.current - 1);
    }
  };

  const handleConfirmSubnetBlock = async () => {
    if (!subnetBlockConfirm) return;
    const target = subnetBlockConfirm;
    setSubnetBlocking(true);
    actionInFlightRef.current++;
    try {
      const res = await clientApi.blockAuditTarget(target.cidr, target.sourceIp, target.reason);
      success(res.message || `已仅针对 ${target.sourceIp} 封禁网段 ${target.cidr}`);
      setSubnetBlockConfirm(null);
      setDetailFlowKey(null);
      emitClientInvalidate('adguard');
      await loadAudit(false);
    } catch (e) {
      error((e as Error).message || '按设备封禁网段失败');
    } finally {
      setSubnetBlocking(false);
      actionInFlightRef.current = Math.max(0, actionInFlightRef.current - 1);
    }
  };

  const handleUnblock = async (r: AuditBlockRule) => {
    actionInFlightRef.current++;
    try {
      const res = await clientApi.unblockAuditTarget(r.target, r.source_ip || '');
      success(res.message || `已解封 ${r.target}`);
      emitClientInvalidate('adguard');
      await loadAudit(false);
    } catch (e) {
      error((e as Error).message || '解封失败');
    } finally {
      actionInFlightRef.current = Math.max(0, actionInFlightRef.current - 1);
    }
  };

  const handleWhitelist = async (action: 'add' | 'remove', rawTarget: string): Promise<boolean> => {
    const target = rawTarget.trim();
    if (!target) {
      toast('请输入要加入白名单的域名或 IP', 'info');
      return false;
    }
    actionInFlightRef.current++;
    try {
      const res = await clientApi.whitelistAuditTarget(action, target);
      success(res.message || (action === 'add' ? '已加入白名单' : '已移出白名单'));
      emitClientInvalidate('adguard');
      await loadAudit(false);
      return true;
    } catch (e) {
      error((e as Error).message || '白名单操作失败');
      return false;
    } finally {
      actionInFlightRef.current = Math.max(0, actionInFlightRef.current - 1);
    }
  };

  const handleTogglePCDNBlock = async (nextEnabled: boolean) => {
    setPcdnToggleBusy(true);
    actionInFlightRef.current++;
    try {
      const res = await clientApi.togglePCDNBlock(nextEnabled);
      success(res.message || (nextEnabled ? '已开启内置防 PCDN 拦截' : '已关闭内置防 PCDN 拦截'));
      if (nextEnabled) {
        setPcdnBannerDismissed(false);
      }
      await loadAudit(false);
    } catch (e) {
      error((e as Error).message || '切换内置防 PCDN 拦截失败');
    } finally {
      setPcdnToggleBusy(false);
      actionInFlightRef.current = Math.max(0, actionInFlightRef.current - 1);
    }
  };

  const handleSetThrottle = async (f: AuditFlowRecord, rateKbps: number) => {
    setThrottleBusy(true);
    actionInFlightRef.current++;
    try {
      const res = await clientApi.setAuditThrottle({
        target: f.target,
        port: f.destPort || 0,
        rateKbps,
        comment: rateKbps > 0 ? `审计限速 ${rateKbps} KB/s (${f.appName || f.deviceName || f.target})` : '',
      });
      success(
        res.message ||
          (rateKbps > 0
            ? `已将 ${f.target} 上行限速为 ${rateKbps} KB/s`
            : `已解除 ${f.target} 上行限速`),
      );
      await loadAudit(false);
    } catch (e) {
      error((e as Error).message || '配置目标限速失败');
    } finally {
      setThrottleBusy(false);
      actionInFlightRef.current = Math.max(0, actionInFlightRef.current - 1);
    }
  };

  const handleCloseFlowConnections = async (f: AuditFlowRecord) => {
    const fk = getFlowCacheKey(f);
    actionInFlightRef.current++;
    setBusyFlowKeys((prev) => new Set(prev).add(fk));
    try {
      const res = await clientApi.closeAuditConnections({
        connIds: f.activeConnIds,
        deviceIp: f.deviceIp,
        target: f.target,
        network: f.network,
      });
      success(res.message || `已断开 ${f.target} 活跃连接`);
      await loadAudit(false);
    } catch (e) {
      error((e as Error).message || '断开连接失败');
    } finally {
      actionInFlightRef.current = Math.max(0, actionInFlightRef.current - 1);
      setBusyFlowKeys((prev) => {
        const next = new Set(prev);
        next.delete(fk);
        return next;
      });
    }
  };

  const handleCloseAllConnections = async () => {
    setClosingAll(true);
    actionInFlightRef.current++;
    try {
      const res = await clientApi.closeAuditConnections({ all: true });
      setCloseAllConfirmOpen(false);
      success(res.message || '已断开所有活跃连接');
      await loadAudit(false);
    } catch (e) {
      error((e as Error).message || '断开全部活跃连接失败');
    } finally {
      setClosingAll(false);
      actionInFlightRef.current = Math.max(0, actionInFlightRef.current - 1);
    }
  };

  const handleExportCSV = async () => {
    try {
      const qs = new URLSearchParams();
      const q = deviceFilter.trim();
      const isKnownDevice = Boolean(
        q &&
          (report?.devices || []).some(
            (d) =>
              d.deviceIp.toLowerCase() === q.toLowerCase() ||
              (d.deviceName || '').toLowerCase() === q.toLowerCase(),
          ),
      );
      if (isKnownDevice) qs.set('device', q);
      if (onlySuspect) qs.set('suspicious', '1');
      if (sortBy) qs.set('sort', sortBy);
      if (sortDir) qs.set('dir', sortDir);
      qs.set('format', 'csv');
      const csv = await clientApi.downloadAuditCSV(qs);
      const blob = new Blob([csv], { type: 'text/csv;charset=utf-8' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `singctl-audit-${new Date().toISOString().slice(0, 19).replace(/[:T]/g, '-')}.csv`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
      success('CSV 导出已触发下载');
    } catch (e) {
      error((e as Error).message || '导出 CSV 失败');
    }
  };

  return {
    blockBusy,
    pcdnToggleBusy,
    throttleBusy,
    busyFlowKeys,
    closingAll,
    closeAllConfirmOpen,
    setCloseAllConfirmOpen,
    subnetBlockConfirm,
    setSubnetBlockConfirm,
    subnetBlocking,
    handleBlockFlow,
    handleManualBlock,
    handleConfirmSubnetBlock,
    handleUnblock,
    handleWhitelist,
    handleTogglePCDNBlock,
    handleSetThrottle,
    handleCloseFlowConnections,
    handleCloseAllConnections,
    handleExportCSV,
  };
}

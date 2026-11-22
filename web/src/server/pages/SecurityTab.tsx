import React, { useEffect, useState } from 'react';
import {
  ServerStatusResponse,
  BannedIP,
  AuditLogItem,
  HealStatusReport,
  FleetHealReport,
  SniffSummary,
  CertHealthItem,
} from '../types';
import { api } from '../api';
import { BANS_CACHE_KEY, HEAL_CACHE_KEY, SNIFF_CACHE_KEY } from '../prefetch';
import { peekCachedQuery, writeCachedQuery } from '../../hooks';
import { useToast } from '../../ui';
import { SelfHealingCenterCard } from './security/SelfHealingCenterCard';
import { AccessAndCredentialsCards } from './security/AccessAndCredentialsCards';
import { SniffingDefenseCard } from './security/SniffingDefenseCard';
import { BanListCard } from './security/BanListCard';
import { CertAndBackupGrid } from './security/CertAndBackupGrid';
import { AuditOperationsCard } from './security/AuditOperationsCard';

export interface SecurityTabProps {
  active?: boolean;
  status: ServerStatusResponse | null;
  onRefresh: () => void;
}

export const SecurityTab: React.FC<SecurityTabProps> = ({ active = true, status, onRefresh }) => {
  const { success, error } = useToast();

  // 3-Layer Security Self-Healing State
  const [healStatus, setHealStatus] = useState<HealStatusReport | null>(
    () => peekCachedQuery<HealStatusReport>(HEAL_CACHE_KEY) ?? null,
  );
  const [loadingHeal, setLoadingHeal] = useState(() => !peekCachedQuery(HEAL_CACHE_KEY));
  const [runningHealScope, setRunningHealScope] = useState<'local' | 'fleet' | null>(null);
  const [savingPolicy, setSavingPolicy] = useState(false);
  const [syncPolicyToFleet, setSyncPolicyToFleet] = useState(true);
  const [lastFleetHeal, setLastFleetHeal] = useState<FleetHealReport | null>(null);

  // 防爆破封禁 IP 列表状态
  const [bans, setBans] = useState<BannedIP[]>(
    () => peekCachedQuery<{ bans: BannedIP[] }>(BANS_CACHE_KEY)?.bans || [],
  );
  const [loadingBans, setLoadingBans] = useState(false);
  const [unbanningIP, setUnbanningIP] = useState<string | null>(null);

  // TLS 证书巡检状态
  const [certs, setCerts] = useState<CertHealthItem[]>(status?.certs || []);
  const [loadingCerts, setLoadingCerts] = useState(false);

  // 外部活跃嗅探与探测追踪状态
  const [sniffSummary, setSniffSummary] = useState<SniffSummary | null>(
    () => peekCachedQuery<SniffSummary>(SNIFF_CACHE_KEY) ?? null,
  );
  const [loadingSniff, setLoadingSniff] = useState(false);
  const [selectedSniffNode, setSelectedSniffNode] = useState<string>('all');
  const [syncBlockCluster, setSyncBlockCluster] = useState<boolean>(true);
  const [blockingTarget, setBlockingTarget] = useState<string | null>(null);

  // 最近管理操作审计状态
  const [auditLogs, setAuditLogs] = useState<AuditLogItem[]>(status?.auditLogs || []);
  const [loadingAudit, setLoadingAudit] = useState(false);

  const fetchHealStatus = async (silent = false, forceRefresh = false) => {
    if (!silent && !peekCachedQuery(HEAL_CACHE_KEY)) setLoadingHeal(true);
    try {
      const rep = await api.getHealStatus(forceRefresh);
      setHealStatus(rep);
      writeCachedQuery(HEAL_CACHE_KEY, rep);
    } catch {
      // non-fatal
    } finally {
      setLoadingHeal(false);
    }
  };

  const fetchBans = async (silent?: boolean | React.SyntheticEvent) => {
    const isSilent = silent === true;
    if (!isSilent && !peekCachedQuery(BANS_CACHE_KEY)) setLoadingBans(true);
    try {
      const res = await api.getBans();
      setBans(res.bans || []);
      writeCachedQuery(BANS_CACHE_KEY, res);
    } catch {
      // silent
    } finally {
      setLoadingBans(false);
    }
  };

  const fetchSniffers = async (nodeScope = selectedSniffNode, forceRefresh = false, silent = false) => {
    if (!silent && !sniffSummary) setLoadingSniff(true);
    try {
      const res = await api.getSniffers(nodeScope, forceRefresh);
      setSniffSummary(res);
      if (nodeScope === 'all') {
        writeCachedQuery(SNIFF_CACHE_KEY, res);
      }
    } catch {
      // silent
    } finally {
      setLoadingSniff(false);
    }
  };

  const handleSelectSniffNode = (nodeId: string) => {
    setSelectedSniffNode(nodeId);
    void fetchSniffers(nodeId, false, false);
  };

  const fetchAuditLogs = async (silent?: boolean | React.SyntheticEvent) => {
    const isSilent = silent === true;
    if (!isSilent) setLoadingAudit(true);
    try {
      const res = await api.getAuditLogs();
      setAuditLogs(res.logs || []);
    } catch {
      // silent
    } finally {
      setLoadingAudit(false);
    }
  };

  useEffect(() => {
    if (!active) return;
    void fetchHealStatus(Boolean(peekCachedQuery(HEAL_CACHE_KEY)));
    void fetchBans(Boolean(peekCachedQuery(BANS_CACHE_KEY)));
    void fetchSniffers(selectedSniffNode, false, Boolean(sniffSummary));
    if (!status?.auditLogs?.length) {
      void fetchAuditLogs(true);
    }
  }, [active]);

  useEffect(() => {
    if (status?.auditLogs) {
      setAuditLogs(status.auditLogs);
    }
  }, [status?.auditLogs]);

  useEffect(() => {
    if (status?.certs) {
      setCerts(status.certs);
    }
  }, [status?.certs]);

  const fetchCerts = async (force = true) => {
    setLoadingCerts(true);
    try {
      const res = await api.getCerts(force);
      setCerts(res.certs || []);
    } catch (err: any) {
      error(err.message || '读取证书状态失败');
    } finally {
      setLoadingCerts(false);
    }
  };

  const handleRunHeal = async (scope: 'local' | 'fleet') => {
    if (scope === 'fleet') {
      if (
        !window.confirm(
          '确定对全舰队与本机执行「三层自动化安全自愈」吗？\n\n• 核心组件与系统安全补丁将在后台并发无感热修复（失败秒级回滚）\n• 需加载新内核的子节点将按【单台串行滚动重启 + 异常熔断】方式执行，保障全网永不断流。',
        )
      ) {
        return;
      }
    }
    setRunningHealScope(scope);
    try {
      const res = await api.runHeal({
        scope,
        allowReboot: scope === 'fleet',
      });
      success(res.message);
      setHealStatus(res.status);
      if (res.fleetReport) {
        setLastFleetHeal(res.fleetReport);
      }
      onRefresh();
      await fetchAuditLogs();
    } catch (err: any) {
      error(err.message || '执行安全自愈失败');
    } finally {
      setRunningHealScope(null);
    }
  };

  const handleTogglePolicy = async (nextEnabled: boolean, nextAutoReboot: boolean) => {
    setSavingPolicy(true);
    try {
      const res = await api.updateHealPolicy({
        autoHealEnabled: nextEnabled,
        schedule: healStatus?.policy?.schedule || '*-*-* 04:00:00',
        autoReboot: nextAutoReboot,
        applyToFleet: syncPolicyToFleet,
      });
      success(res.message);
      setHealStatus(res.status);
      await fetchAuditLogs();
    } catch (err: any) {
      error(err.message || '保存自动自愈策略失败');
    } finally {
      setSavingPolicy(false);
    }
  };

  const handleUnban = async (ip: string) => {
    if (ip === 'all' && !window.confirm('确定要全链路解封所有当前拦截 IP 及手动封禁网段吗？')) {
      return;
    }
    setUnbanningIP(ip);
    try {
      const unbanScope = syncBlockCluster ? 'all' : selectedSniffNode;
      const res = await api.unban(ip, unbanScope, selectedSniffNode);
      success(res.message || `已成功解除 ${ip} 的封锁`);
      if (res.summary) {
        setSniffSummary(res.summary);
      } else {
        await fetchSniffers(selectedSniffNode, false);
      }
      await fetchBans();
      await fetchAuditLogs();
    } catch (err: any) {
      error(err.message || '解封失败');
    } finally {
      setUnbanningIP(null);
    }
  };

  const handleBlockSniffer = async (target: string, onClearInput?: () => void) => {
    const trimmed = target.trim();
    if (!trimmed) {
      error('请输入要封禁的 IP 地址或 /24 网段');
      return;
    }
    const blockScope = syncBlockCluster ? 'all' : selectedSniffNode;
    setBlockingTarget(trimmed);
    try {
      const res = await api.blockSniffer(trimmed, blockScope, selectedSniffNode);
      success(res.message || `已封禁 ${trimmed}`);
      setSniffSummary(res.summary);
      onClearInput?.();
      await fetchBans();
      await fetchAuditLogs();
    } catch (err: any) {
      error(err.message || '封禁失败');
    } finally {
      setBlockingTarget(null);
    }
  };

  return (
    <div className="space-y-5 sm:space-y-6">
      <SelfHealingCenterCard
        healStatus={healStatus}
        loadingHeal={loadingHeal}
        runningHealScope={runningHealScope}
        savingPolicy={savingPolicy}
        syncPolicyToFleet={syncPolicyToFleet}
        setSyncPolicyToFleet={setSyncPolicyToFleet}
        lastFleetHeal={lastFleetHeal}
        onClearFleetHeal={() => setLastFleetHeal(null)}
        onRunHeal={handleRunHeal}
        onRescan={() => void fetchHealStatus(false, true)}
        onTogglePolicy={handleTogglePolicy}
      />

      <AccessAndCredentialsCards status={status} onRefresh={onRefresh} />

      <SniffingDefenseCard
        sniffSummary={sniffSummary}
        loadingSniff={loadingSniff}
        selectedSniffNode={selectedSniffNode}
        syncBlockCluster={syncBlockCluster}
        setSyncBlockCluster={setSyncBlockCluster}
        blockingTarget={blockingTarget}
        unbanningIP={unbanningIP}
        onSelectSniffNode={handleSelectSniffNode}
        onRefreshSniffers={() => void fetchSniffers(selectedSniffNode, true)}
        onBlockSniffer={handleBlockSniffer}
        onUnban={handleUnban}
      />

      <BanListCard
        bans={bans}
        loadingBans={loadingBans}
        unbanningIP={unbanningIP}
        onRefreshBans={() => void fetchBans()}
        onUnban={handleUnban}
      />

      <CertAndBackupGrid
        certs={certs}
        loadingCerts={loadingCerts}
        onRefreshCerts={() => void fetchCerts(true)}
        onRefreshParent={onRefresh}
        onRefreshAuditLogs={() => void fetchAuditLogs()}
      />

      <AuditOperationsCard
        auditLogs={auditLogs}
        loadingAudit={loadingAudit}
        onRefreshAuditLogs={() => void fetchAuditLogs()}
      />
    </div>
  );
};

import { useCallback, useEffect, useRef, useState } from 'react';
import {
  CLIENT_INVALIDATE_EVENT,
  ClientInvalidateScope,
  peekCachedQuery,
  prefetchCachedQuery,
  useVisibilityInterval,
  writeCachedQuery,
} from '../../../hooks';
import { useToast } from '../../../ui';
import { clientApi } from '../../api';
import { ADGUARD_OVERVIEW_CACHE_KEY, ADGUARD_PROBE_CACHE_KEY } from '../../cacheKeys';
import {
  AdGuardCredentialsResponse,
  AdGuardOverviewSnapshot,
  AdGuardProbeResult,
  AdGuardUpstreamMode,
  ClientStatusResponse,
} from '../../types';

export function useAdGuardController(
  active: boolean,
  status: ClientStatusResponse | null,
  onRefreshStatus: () => void,
) {
  const { success, error } = useToast();
  const [snap, setSnap] = useState<AdGuardOverviewSnapshot | null>(
    () => peekCachedQuery<AdGuardOverviewSnapshot>(ADGUARD_OVERVIEW_CACHE_KEY) ?? null,
  );
  const [loading, setLoading] = useState<boolean>(
    () => !peekCachedQuery<AdGuardOverviewSnapshot>(ADGUARD_OVERVIEW_CACHE_KEY),
  );
  const [mutating, setMutating] = useState(false);

  const [probe, setProbe] = useState<AdGuardProbeResult | null>(
    () => peekCachedQuery<AdGuardProbeResult>(ADGUARD_PROBE_CACHE_KEY) ?? null,
  );
  const [probing, setProbing] = useState(false);

  const pauseDeadlineRef = useRef<number>(0);
  const [pauseRemainSec, setPauseRemainSec] = useState<number>(() => {
    const cached = peekCachedQuery<AdGuardOverviewSnapshot>(ADGUARD_OVERVIEW_CACHE_KEY);
    if (
      cached &&
      !cached.protectionEnabled &&
      cached.protectionDisabledDurationMs &&
      cached.protectionDisabledDurationMs > 0
    ) {
      return Math.ceil(cached.protectionDisabledDurationMs / 1000);
    }
    return 0;
  });

  const [savingUpstreams, setSavingUpstreams] = useState(false);
  const [credOpen, setCredOpen] = useState(false);
  const [credData, setCredData] = useState<AdGuardCredentialsResponse | null>(null);
  const [credLoading, setCredLoading] = useState(false);
  const [resettingPwd, setResettingPwd] = useState(false);

  const loadOverview = useCallback(
    async (silent = false) => {
      if (!silent && !peekCachedQuery(ADGUARD_OVERVIEW_CACHE_KEY)) {
        setLoading(true);
      }
      try {
        const res = silent
          ? await clientApi.getAdGuardOverview()
          : (await prefetchCachedQuery(ADGUARD_OVERVIEW_CACHE_KEY, () => clientApi.getAdGuardOverview())) ??
            (await clientApi.getAdGuardOverview());
        writeCachedQuery(ADGUARD_OVERVIEW_CACHE_KEY, res);
        setSnap(res);
        if (!res.protectionEnabled && res.protectionDisabledDurationMs && res.protectionDisabledDurationMs > 0) {
          pauseDeadlineRef.current = Date.now() + res.protectionDisabledDurationMs;
          setPauseRemainSec(Math.ceil(res.protectionDisabledDurationMs / 1000));
        } else {
          pauseDeadlineRef.current = 0;
          setPauseRemainSec(0);
        }
      } catch (e) {
        if (!silent) error((e as Error).message || '加载防劫持 DNS 状态失败');
      } finally {
        setLoading(false);
      }
    },
    [error],
  );

  useEffect(() => {
    void loadOverview(Boolean(snap));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [status?.adguard?.installed, status?.adguard?.running, status?.adguard?.singboxLinked]);

  const prevActiveRef = useRef<boolean>(active);
  useEffect(() => {
    const becameActive = !prevActiveRef.current && active;
    prevActiveRef.current = active;
    if (!becameActive) return;

    if (pauseDeadlineRef.current > 0) {
      const rem = Math.max(0, Math.ceil((pauseDeadlineRef.current - Date.now()) / 1000));
      setPauseRemainSec(rem);
    }
    void loadOverview(true);
  }, [active, loadOverview]);

  useEffect(() => {
    const onInvalidate = (ev: Event) => {
      const scope = (ev as CustomEvent<ClientInvalidateScope>).detail;
      if (!scope || scope === 'all' || scope === 'adguard') {
        void loadOverview(true);
      }
    };
    window.addEventListener(CLIENT_INVALIDATE_EVENT, onInvalidate);
    return () => window.removeEventListener(CLIENT_INVALIDATE_EVENT, onInvalidate);
  }, [loadOverview]);

  useVisibilityInterval(
    () => {
      void loadOverview(true);
    },
    active && snap?.installed ? 15000 : null,
  );

  useEffect(() => {
    if (!active || pauseRemainSec <= 0) return;
    if (pauseDeadlineRef.current <= 0) {
      pauseDeadlineRef.current = Date.now() + pauseRemainSec * 1000;
    }
    const t = window.setInterval(() => {
      const rem = Math.max(0, Math.ceil((pauseDeadlineRef.current - Date.now()) / 1000));
      setPauseRemainSec(rem);
      if (rem <= 0) {
        pauseDeadlineRef.current = 0;
        window.setTimeout(() => void loadOverview(true), 500);
      }
    }, 1000);
    return () => window.clearInterval(t);
  }, [active, pauseRemainSec, loadOverview]);

  const runProbe = useCallback(
    async (silent = false) => {
      setProbing(true);
      try {
        const res = await clientApi.probeAdGuardUpstream();
        writeCachedQuery(ADGUARD_PROBE_CACHE_KEY, res);
        setProbe(res);
        if (!silent) {
          if (res.healthy && res.fastestUpstream) {
            success(
              `实测完成：当前最快为 ${res.fastestName || res.fastestUpstream} (${res.fastestLatencyMs}ms) · 本地端到端 ${res.latencyMs}ms`,
            );
          } else if (res.healthy) {
            success(`加密上游解析正常：${res.domain} → ${res.resolved} (${res.latencyMs}ms)`);
          } else {
            error(res.error || '上游解析探测异常');
          }
        }
      } catch (e) {
        if (!silent) error((e as Error).message || '探测失败');
      } finally {
        setProbing(false);
      }
    },
    [success, error],
  );

  useEffect(() => {
    if (active && snap?.installed && snap.dnsHealthy && !probe && !probing) {
      void runProbe(true);
    }
  }, [active, snap?.installed, snap?.dnsHealthy, probe, probing, runProbe]);

  const handleProtection = async (enabled: boolean, durationMinutes = 0) => {
    setMutating(true);
    try {
      await clientApi.setAdGuardProtection(enabled, durationMinutes);
      if (enabled) {
        success('已恢复去广告与隐私追踪过滤保护');
      } else if (durationMinutes > 0) {
        success(`已临时暂停广告过滤 ${durationMinutes} 分钟（防劫持 DoH 解析保持运行，不断网）`);
      } else {
        success('已暂停广告过滤规则');
      }
      await loadOverview(true);
    } catch (e) {
      error((e as Error).message || '切换过滤状态失败');
    } finally {
      setMutating(false);
    }
  };

  const handleClearCache = async () => {
    setMutating(true);
    try {
      await clientApi.clearAdGuardCache();
      success('已清空本地 DNS 缓存');
      void runProbe(true);
    } catch (e) {
      error((e as Error).message || '清空缓存失败');
    } finally {
      setMutating(false);
    }
  };

  const handleWhitelist = async (action: 'add' | 'remove', rawDomain: string): Promise<boolean> => {
    const d = rawDomain.trim();
    if (!d) return false;
    setMutating(true);
    try {
      await clientApi.setAdGuardWhitelist(action, d);
      success(action === 'add' ? `已放行域名 ${d}` : `已移出白名单 ${d}`);
      await loadOverview(true);
      return true;
    } catch (e) {
      error((e as Error).message || '更新白名单失败');
      return false;
    } finally {
      setMutating(false);
    }
  };

  const handleAddRewrite = async (domainRaw: string, answerRaw: string): Promise<boolean> => {
    const domain = domainRaw.trim();
    const answer = answerRaw.trim();
    if (!domain || !answer) {
      error('请填写内网域名与目标 IP / 域名');
      return false;
    }
    setMutating(true);
    try {
      await clientApi.manageAdGuardRewrite('add', domain, answer);
      success(`已添加域名映射：${domain} → ${answer}`);
      await loadOverview(true);
      return true;
    } catch (err) {
      error((err as Error).message || '添加重写失败');
      return false;
    } finally {
      setMutating(false);
    }
  };

  const handleDeleteRewrite = async (domain: string, answer: string) => {
    setMutating(true);
    try {
      await clientApi.manageAdGuardRewrite('delete', domain, answer);
      success(`已移除映射 ${domain}`);
      await loadOverview(true);
    } catch (err) {
      error((err as Error).message || '删除映射失败');
    } finally {
      setMutating(false);
    }
  };

  const handleFilterToggle = async (url: string, name: string, enabled: boolean) => {
    setMutating(true);
    try {
      await clientApi.manageAdGuardFilter({ action: 'toggle', url, name, enabled });
      success(enabled ? `已启用规则库：${name}` : `已停用规则库：${name}`);
      await loadOverview(true);
    } catch (err) {
      error((err as Error).message || '切换规则库失败');
    } finally {
      setMutating(false);
    }
  };

  const handleAddCustomFilter = async (nameRaw: string, urlRaw: string): Promise<boolean> => {
    const url = urlRaw.trim();
    if (!url) {
      error('请输入有效的 http:// 或 https:// 规则订阅链接');
      return false;
    }
    setMutating(true);
    try {
      await clientApi.manageAdGuardFilter({
        action: 'add',
        url,
        name: nameRaw.trim(),
        enabled: true,
      });
      success('已添加并启用自定义过滤规则库');
      await loadOverview(true);
      return true;
    } catch (err) {
      error((err as Error).message || '添加自定义规则库失败');
      return false;
    } finally {
      setMutating(false);
    }
  };

  const handleRemoveCustomFilter = async (url: string, name: string) => {
    setMutating(true);
    try {
      await clientApi.manageAdGuardFilter({ action: 'remove', url });
      success(`已移除规则库：${name}`);
      await loadOverview(true);
    } catch (err) {
      error((err as Error).message || '移除规则库失败');
    } finally {
      setMutating(false);
    }
  };

  const handleRefreshFilters = async () => {
    setMutating(true);
    try {
      await clientApi.manageAdGuardFilter({ action: 'refresh' });
      success('已在线同步更新全部规则库');
      await loadOverview(true);
    } catch (err) {
      error((err as Error).message || '更新规则库失败');
    } finally {
      setMutating(false);
    }
  };

  const openCredentialsDrawer = async () => {
    setCredOpen(true);
    setCredLoading(true);
    try {
      const res = await clientApi.getAdGuardCredentials();
      setCredData(res);
    } catch (err) {
      error((err as Error).message || '读取凭据失败');
    } finally {
      setCredLoading(false);
    }
  };

  const handleResetPassword = async (): Promise<boolean> => {
    setResettingPwd(true);
    try {
      const res = await clientApi.resetAdGuardCredentials();
      setCredData(res);
      success('已生成新的 16 位随机管理密码并热同步生效');
      onRefreshStatus();
      return true;
    } catch (err) {
      error((err as Error).message || '重置密码失败');
      return false;
    } finally {
      setResettingPwd(false);
    }
  };

  const handleUpdateUpstreams = async (
    nextList: string[],
    nextMode?: AdGuardUpstreamMode,
    resetDefault = false,
  ): Promise<boolean> => {
    setSavingUpstreams(true);
    try {
      const res = await clientApi.saveAdGuardUpstreams({
        upstreams: resetDefault ? undefined : nextList,
        upstreamMode: nextMode || snap?.upstreamMode || 'parallel',
        resetDefault,
      });
      if (snap) {
        setSnap({
          ...snap,
          upstreams: res.upstreams,
          upstreamMode: res.upstreamMode,
          upstreamModeLabel: res.upstreamModeLabel,
        });
      }
      if (resetDefault) {
        success('已恢复默认推荐的阿里 / 腾讯纯 IP 加密上游并热生效');
      } else if (res.notes && res.notes.length > 0) {
        success(`上游已热生效（${res.notes.join('；')}）`);
      } else {
        success('加密上游 DNS 配置已热生效');
      }
      await loadOverview(true);
      void runProbe(true);
      return true;
    } catch (e) {
      error((e as Error).message || '保存上游 DNS 配置失败');
      return false;
    } finally {
      setSavingUpstreams(false);
    }
  };

  const handleToggleUpstreamPreset = (presetAddr: string) => {
    if (!snap) return;
    const current = snap.upstreams.map((u) => u.address);
    const exists = current.some((a) => a.toLowerCase() === presetAddr.toLowerCase());
    if (exists) {
      if (current.length <= 1) {
        error('至少需保留 1 条加密上游 DNS 服务器');
        return;
      }
      void handleUpdateUpstreams(
        current.filter((a) => a.toLowerCase() !== presetAddr.toLowerCase()),
      );
    } else {
      void handleUpdateUpstreams([...current, presetAddr]);
    }
  };

  const handleRemoveUpstream = (addr: string) => {
    if (!snap) return;
    const current = snap.upstreams.map((u) => u.address);
    if (current.length <= 1) {
      error('至少需保留 1 条加密上游 DNS 服务器');
      return;
    }
    void handleUpdateUpstreams(current.filter((a) => a !== addr));
  };

  return {
    snap,
    loading,
    mutating,
    probe,
    probing,
    pauseRemainSec,
    savingUpstreams,
    credOpen,
    setCredOpen,
    credData,
    credLoading,
    resettingPwd,
    runProbe,
    handleProtection,
    handleClearCache,
    handleWhitelist,
    handleAddRewrite,
    handleDeleteRewrite,
    handleFilterToggle,
    handleAddCustomFilter,
    handleRemoveCustomFilter,
    handleRefreshFilters,
    openCredentialsDrawer,
    handleResetPassword,
    handleUpdateUpstreams,
    handleToggleUpstreamPreset,
    handleRemoveUpstream,
  };
}

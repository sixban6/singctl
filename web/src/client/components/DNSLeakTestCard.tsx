import React, { useEffect, useMemo, useRef, useState } from 'react';
import {
  Activity,
  AlertTriangle,
  Eye,
  EyeOff,
  Monitor,
  Radar,
  ShieldAlert,
  ShieldCheck,
} from 'lucide-react';
import { Badge, Button, SectionCard, useToast } from '../../ui';
import { clientApi } from '../api';
import {
  BrowserEDNSSample,
  BrowserWebRTCReport,
  probeBrowserDomesticIP,
  probeBrowserOverseasIP,
  runBrowserEDNSSweep,
  runBrowserWebRTCProbe,
  sameIPv6Prefix48,
} from '../lib/leakProbes';
import {
  maskFullIP,
  PRIVACY_MASK_EVENT,
  readPrivacyMaskPref,
  redactInlineSensitive,
  writePrivacyMaskPref,
} from '../../lib/privacyMask';
import { BrowserDoHCheckResponse, DNSLeakReport, EgressEndpoint } from '../types';
import { analyzePanoramicSuite } from './dns-leak/analyzePanoramicSuite';
import { BrowserDoHCheckBanner } from './dns-leak/BrowserDoHCheckBanner';
import {
  BROWSER_DOH_EVENT,
  getCachedBrowserDoH,
  getCachedSuiteState,
  PanoramicSuiteState,
  runBrowserDoHCheckFlow,
  setCachedSuiteState,
  SweepMode,
  VERDICT_META,
} from './dns-leak/browserDoHFlow';
import {
  DNSResolversTable,
  EgressMatrixGrid,
  GatewayChecksSection,
  WebRTCLeakSection,
} from './dns-leak/DNSLeakResultSections';

export { BROWSER_DOH_EVENT, getCachedBrowserDoH, runBrowserDoHCheckFlow };

export interface DNSLeakTestCardProps {
  title?: string;
  subtitle?: string;
  report?: DNSLeakReport | null;
  onReportChange?: (rep: DNSLeakReport) => void;
  privacyMask?: boolean;
  onPrivacyMaskChange?: (next: boolean) => void;
}

export const DNSLeakTestCard: React.FC<DNSLeakTestCardProps> = ({
  title = '全景隐私与 DNS 防泄漏体检中心',
  subtitle = '同步从「当前浏览器视角」与「路由器网关视角」执行多轮随机子域 EDNS 扫探、四路双栈出口核验及 WebRTC 检测（类 ipleak.net）',
  report: controlledReport,
  onReportChange,
  privacyMask,
  onPrivacyMaskChange,
}) => {
  const { success, error, toast } = useToast();
  const [suite, setSuite] = useState<PanoramicSuiteState | null>(() => getCachedSuiteState());
  const [running, setRunning] = useState(false);
  const [localMask, setLocalMask] = useState<boolean>(() => readPrivacyMaskPref());
  const [browserDoH, setBrowserDoH] = useState<BrowserDoHCheckResponse | null>(() => getCachedBrowserDoH());
  const [checkingDoH, setCheckingDoH] = useState(false);
  const abortRef = useRef<AbortController | null>(null);
  const runIdRef = useRef(0);

  const isControlledMask = privacyMask !== undefined;
  const hideIP = isControlledMask ? Boolean(privacyMask) : localMask;

  useEffect(() => {
    if (isControlledMask) return;
    const onMaskChange = (ev: Event) => {
      const detail = (ev as CustomEvent<boolean>).detail;
      setLocalMask(typeof detail === 'boolean' ? detail : readPrivacyMaskPref());
    };
    window.addEventListener(PRIVACY_MASK_EVENT, onMaskChange);
    return () => window.removeEventListener(PRIVACY_MASK_EVENT, onMaskChange);
  }, [isControlledMask]);

  useEffect(() => {
    const onDoHUpdated = (ev: Event) => {
      const detail = (ev as CustomEvent<BrowserDoHCheckResponse>).detail;
      if (detail) setBrowserDoH(detail);
    };
    window.addEventListener(BROWSER_DOH_EVENT, onDoHUpdated);
    return () => window.removeEventListener(BROWSER_DOH_EVENT, onDoHUpdated);
  }, []);

  useEffect(() => {
    return () => {
      abortRef.current?.abort();
    };
  }, []);

  const toggleMask = () => {
    const next = !hideIP;
    if (onPrivacyMaskChange) {
      onPrivacyMaskChange(next);
    } else {
      setLocalMask(next);
      writePrivacyMaskPref(next);
    }
  };

  const handleCheckBrowserDoH = async () => {
    setCheckingDoH(true);
    try {
      const res = await runBrowserDoHCheckFlow();
      if (res) {
        setBrowserDoH(res);
        if (res.status === 'detected') {
          toast(`检测到浏览器安全 DNS（${res.detectedProvider || 'DoH'}）`, 'warn');
        } else if (res.status === 'suspected') {
          toast('检测到浏览器与网关 DNS 出口存在分歧', 'warn');
        } else if (res.status === 'clean') {
          success('未检测到当前浏览器绕过网关使用安全 DNS');
        }
      }
    } finally {
      setCheckingDoH(false);
    }
  };

  const effectiveGatewayReport =
    controlledReport !== undefined ? controlledReport : suite?.gatewayReport ?? null;

  const updateSuite = (updater: (prev: PanoramicSuiteState | null) => PanoramicSuiteState | null) => {
    setSuite((prev) => {
      const next = updater(prev);
      setCachedSuiteState(next);
      return next;
    });
  };

  const handleRun = async (mode: SweepMode) => {
    abortRef.current?.abort();
    const ctrl = new AbortController();
    abortRef.current = ctrl;
    const myRunId = ++runIdRef.current;

    const browserRounds = mode === 'deep' ? 128 : 47;
    const t0 = performance.now();

    setRunning(true);
    const initial: PanoramicSuiteState = {
      mode,
      checkedAt: new Date().toISOString(),
      totalDurationMs: 0,
      gatewayReport: null,
      gatewayError: '',
      browserSamples: [],
      browserRoundsTarget: browserRounds,
      browserRoundsDone: 0,
      browserDom: null,
      browserOv4: null,
      browserOv6: null,
      webrtc: null,
    };
    updateSuite(() => initial);

    let localGwReport: DNSLeakReport | null = null;
    let localBrowserSamples: BrowserEDNSSample[] = [];
    let localBrowserDom: { endpoint: EgressEndpoint; usedIPv6: boolean } | null = null;
    let localBrowserOv4: EgressEndpoint | null = null;
    let localBrowserOv6: EgressEndpoint | null = null;
    let localWebRTC: BrowserWebRTCReport | null = null;

    const dohBegin = await clientApi.checkBrowserDoH({ phase: 'begin' }).catch(() => null);

    await Promise.allSettled([
      clientApi
        .runDNSLeakTest(mode)
        .then((res) => {
          if (runIdRef.current !== myRunId) return;
          localGwReport = res;
          onReportChange?.(res);
          updateSuite((prev) => (prev ? { ...prev, gatewayReport: res } : prev));
        })
        .catch((err: unknown) => {
          if (runIdRef.current !== myRunId) return;
          const msg = err instanceof Error ? err.message : '网关探测请求失败';
          updateSuite((prev) => (prev ? { ...prev, gatewayError: msg } : prev));
        }),

      runBrowserEDNSSweep(
        browserRounds,
        (done, total, sample) => {
          if (runIdRef.current !== myRunId) return;
          if (sample) {
            localBrowserSamples = [...localBrowserSamples, sample];
          }
          updateSuite((prev) =>
            prev
              ? {
                  ...prev,
                  browserRoundsTarget: total,
                  browserRoundsDone: done,
                  browserSamples: sample ? [...prev.browserSamples, sample] : prev.browserSamples,
                }
              : prev,
          );
        },
        ctrl.signal,
      ),

      probeBrowserDomesticIP(ctrl.signal).then((res) => {
        if (runIdRef.current !== myRunId) return;
        localBrowserDom = res;
        updateSuite((prev) => (prev ? { ...prev, browserDom: res } : prev));
      }),

      probeBrowserOverseasIP('v4', ctrl.signal).then((ep) => {
        if (runIdRef.current !== myRunId) return;
        localBrowserOv4 = ep;
        updateSuite((prev) => (prev ? { ...prev, browserOv4: ep } : prev));
      }),

      probeBrowserOverseasIP('v6', ctrl.signal).then((ep) => {
        if (runIdRef.current !== myRunId) return;
        localBrowserOv6 = ep;
        updateSuite((prev) => (prev ? { ...prev, browserOv6: ep } : prev));
      }),

      runBrowserWebRTCProbe(ctrl.signal).then((rep) => {
        if (runIdRef.current !== myRunId) return;
        localWebRTC = rep;
        updateSuite((prev) => (prev ? { ...prev, webrtc: rep } : prev));
      }),
    ]);

    if (runIdRef.current !== myRunId) return;
    const totalMs = Math.max(1, Math.round(performance.now() - t0));
    updateSuite((prev) => (prev ? { ...prev, totalDurationMs: totalMs } : prev));
    setRunning(false);

    void runBrowserDoHCheckFlow(
      localBrowserSamples,
      browserRounds,
      Math.max(0, browserRounds - localBrowserSamples.length),
      dohBegin?.probeId,
    ).then((res) => {
      if (res && runIdRef.current === myRunId) {
        setBrowserDoH(res);
      }
    });

    const gwSnap = localGwReport as DNSLeakReport | null;
    const homeV4 = gwSnap?.egress?.domesticIpv4?.ip || gwSnap?.homePublicIp || '';
    const domSnap = localBrowserDom as { endpoint: EgressEndpoint; usedIPv6: boolean } | null;
    const homeV6 = gwSnap?.egress?.domesticIpv6?.ip || (domSnap?.usedIPv6 ? domSnap.endpoint.ip || '' : '');
    const ov4Snap = localBrowserOv4 as EgressEndpoint | null;
    const ov6Snap = localBrowserOv6 as EgressEndpoint | null;
    const rtcSnap = localWebRTC as BrowserWebRTCReport | null;
    const modeV6 = gwSnap?.ipv6Mode || 'off';

    const hasLeakedSample =
      gwSnap?.verdict === 'leaked' ||
      localBrowserSamples.some(
        (s) =>
          s.countryCode === 'CN' ||
          s.ednsCountryCode === 'CN' ||
          (homeV4 && s.dnsIp === homeV4) ||
          (homeV6 && (s.dnsIp === homeV6 || sameIPv6Prefix48(s.dnsIp, homeV6))),
      ) ||
      Boolean(ov4Snap?.reachable && (ov4Snap.countryCode === 'CN' || (homeV4 && ov4Snap.ip === homeV4))) ||
      Boolean(
        ov6Snap?.reachable &&
          modeV6 !== 'full' &&
          (ov6Snap.countryCode === 'CN' || (homeV6 && sameIPv6Prefix48(ov6Snap.ip, homeV6))),
      ) ||
      Boolean(homeV4 && rtcSnap?.publicIPv4s.includes(homeV4)) ||
      Boolean(
        homeV6 &&
          rtcSnap?.publicIPv6s.some((ip) => ip === homeV6 || sameIPv6Prefix48(ip, homeV6)),
      );

    if (hasLeakedSample) {
      error('检测到 DNS、IPv6 或 WebRTC 泄漏风险，请查看下方告警明细');
    } else if (gwSnap?.verdict === 'warning') {
      toast('全景防泄漏体检完成（存在提示项，请留意详情）', 'info');
    } else {
      success(`双端全景防泄漏体检通过 (${totalMs}ms)`);
    }
  };

  const analysis = useMemo(
    () => analyzePanoramicSuite(effectiveGatewayReport, suite),
    [effectiveGatewayReport, suite],
  );

  const hasResult = Boolean(effectiveGatewayReport || suite);
  const verdictMeta = VERDICT_META[analysis.verdict] || VERDICT_META.warning;
  const totalSweepTarget =
    (suite?.browserRoundsTarget || 0) +
    (effectiveGatewayReport?.gatewayRounds || (suite?.mode === 'deep' ? 16 : 8));
  const totalSweepDone =
    (suite?.browserRoundsDone || 0) +
    (effectiveGatewayReport ? effectiveGatewayReport.gatewayRounds || 0 : 0);
  const progressPct =
    totalSweepTarget > 0 ? Math.min(100, Math.round((totalSweepDone / totalSweepTarget) * 100)) : 0;

  return (
    <SectionCard
      title={title}
      icon={<ShieldCheck className="w-4 h-4" />}
      subtitle={subtitle}
      actions={
        <div className="flex flex-wrap items-center gap-2">
          {!isControlledMask && (hasResult || Boolean(browserDoH)) && (
            <Button
              size="sm"
              variant={hideIP ? 'primary' : 'ghost'}
              icon={hideIP ? <Eye className="w-3.5 h-3.5" /> : <EyeOff className="w-3.5 h-3.5" />}
              onClick={toggleMask}
            >
              {hideIP ? '已完全遮挡' : '隐私完全遮挡'}
            </Button>
          )}
          <Button
            size="sm"
            variant={hasResult ? 'secondary' : 'primary'}
            loading={running && suite?.mode === 'standard'}
            disabled={running}
            icon={<Activity className="w-3.5 h-3.5" />}
            onClick={() => void handleRun('standard')}
          >
            标准体检 (55 轮)
          </Button>
          <Button
            size="sm"
            variant="secondary"
            loading={running && suite?.mode === 'deep'}
            disabled={running}
            icon={<Radar className="w-3.5 h-3.5" />}
            onClick={() => void handleRun('deep')}
          >
            深度扫描 (144 轮)
          </Button>
        </div>
      }
    >
      <div className="space-y-4">
        <BrowserDoHCheckBanner
          browserDoH={browserDoH}
          checkingDoH={checkingDoH}
          running={running}
          hideIP={hideIP}
          onRecheck={() => void handleCheckBrowserDoH()}
        />

        {!hasResult ? (
          <div className="rounded-xl border border-dashed border-subtle bg-surface2/40 px-4 py-5 text-xs text-secondary flex flex-col sm:flex-row sm:items-center justify-between gap-4">
            <div className="space-y-1.5">
              <div className="font-medium text-primary">
                双端全景防泄漏核验（浏览器终端 + 路由器网关同步发包）
              </div>
              <p className="text-[11px] text-muted leading-relaxed">
                同时测出「国内/海外 × IPv4/IPv6」四路出口归属、并发多轮唯一随机子域防缓存扫描（揪出隐蔽多上游轮询泄漏）、浏览器 WebRTC
                STUN 探测以及明文 :53 透明劫持和 OpenWrt RA 基线。
              </p>
            </div>
            <div className="flex items-center gap-2 shrink-0">
              <Button
                size="sm"
                variant="primary"
                loading={running}
                icon={<Activity className="w-3.5 h-3.5" />}
                onClick={() => void handleRun('standard')}
              >
                立即开始全景体检
              </Button>
            </div>
          </div>
        ) : (
          <div className="space-y-4">
            {running && (
              <div className="rounded-xl border border-sky-500/30 bg-sky-500/10 px-3.5 py-2.5 space-y-1.5">
                <div className="flex items-center justify-between text-[11px] text-sky-200 font-medium">
                  <span>
                    正在执行双端防缓存扫探（浏览器 {suite?.browserRoundsDone || 0}/{suite?.browserRoundsTarget || 0} 轮 · 网关{' '}
                    {effectiveGatewayReport ? `已完成 ${effectiveGatewayReport.gatewayRounds || 0} 轮` : '探测中'}）
                  </span>
                  <span className="font-mono tnum">{progressPct}%</span>
                </div>
                <div className="h-1.5 w-full rounded-full bg-slate-900/60 overflow-hidden">
                  <div
                    className="h-full bg-sky-400 transition-all duration-200"
                    style={{ width: `${Math.max(8, progressPct)}%` }}
                  />
                </div>
              </div>
            )}

            {!running && (
              <div
                className={`rounded-xl border px-3.5 py-3 flex flex-col sm:flex-row sm:items-center justify-between gap-2 ${verdictMeta.boxClass}`}
              >
                <div className="flex items-start gap-2.5">
                  {analysis.verdict === 'safe' ? (
                    <ShieldCheck className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
                  ) : analysis.verdict === 'leaked' ? (
                    <ShieldAlert className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
                  ) : (
                    <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
                  )}
                  <div className="space-y-0.5">
                    <div className="flex flex-wrap items-center gap-2 text-xs font-semibold">
                      <Badge tone={verdictMeta.tone}>{verdictMeta.badge}</Badge>
                      <span>{verdictMeta.headline}</span>
                    </div>
                    <div className="text-[11px] opacity-85 font-mono">
                      IPv6 策略: {analysis.ipv6Mode}
                      {suite?.totalDurationMs ? ` · 全景耗时 ${suite.totalDurationMs}ms` : ''}
                      {analysis.homeIPv4 ? ` · 宽带基准 ${maskFullIP(analysis.homeIPv4, hideIP)}` : ''}
                      {analysis.mergedDNSServers.length > 0
                        ? ` · 捕获 ${analysis.mergedDNSServers.length} 个出口 DNS 节点`
                        : ''}
                    </div>
                  </div>
                </div>
              </div>
            )}

            {analysis.browserOnlyLeak && (
              <div className="rounded-xl border border-rose-500/40 bg-rose-500/12 px-3.5 py-2.5 text-xs text-rose-200 flex items-start gap-2.5">
                <Monitor className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
                <div className="space-y-0.5">
                  <div className="font-semibold">双端归因：路由器网关零泄漏，异常来自你当前的终端或浏览器</div>
                  <p className="text-[11px] opacity-90 leading-relaxed">
                    请检查浏览器设置中的「使用安全 DNS（DoH）」（例如 Brave / Chrome 内置或指向国内公共 DNS），或本机系统网卡是否手动固定了非路由器 IP 的 DNS。若在手机上检测：请关闭 iPhone「设置 → 无线局域网 → 连接助理」（或「蜂窝网络」最底部的「无线局域网助理」），以及华为「WLAN+」/ 安卓「自动切换移动数据」。
                  </p>
                </div>
              </div>
            )}

            {suite?.gatewayError && (
              <div className="rounded-xl border border-amber-500/35 bg-amber-500/10 px-3.5 py-2.5 text-xs text-amber-200">
                网关后端深度体检返回异常：{redactInlineSensitive(suite.gatewayError, hideIP)}
              </div>
            )}

            <EgressMatrixGrid analysis={analysis} suite={suite} running={running} hideIP={hideIP} />

            <DNSResolversTable
              rows={analysis.mergedDNSServers}
              totalSweepTarget={totalSweepTarget}
              running={running}
              hideIP={hideIP}
            />

            <WebRTCLeakSection analysis={analysis} running={running} hideIP={hideIP} />

            {effectiveGatewayReport && (
              <GatewayChecksSection gatewayReport={effectiveGatewayReport} hideIP={hideIP} />
            )}
          </div>
        )}
      </div>
    </SectionCard>
  );
};

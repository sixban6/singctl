import React, { useEffect, useMemo, useRef, useState } from 'react';
import {
  Activity,
  AlertTriangle,
  Check,
  Copy,
  Eye,
  EyeOff,
  Globe,
  Monitor,
  Radar,
  RefreshCw,
  Router,
  ShieldAlert,
  ShieldCheck,
  Wifi,
} from 'lucide-react';
import { Badge, Button, SectionCard, useToast } from '../../ui';
import { clientApi } from '../api';
import {
  BrowserEDNSSample,
  BrowserWebRTCReport,
  copyPlainText,
  countryFlag,
  detectBrowserDoHGuide,
  isLikelyTailscaleHost,
  probeBrowserDomesticIP,
  probeBrowserOverseasIP,
  runBrowserEDNSSweep,
  runBrowserWebRTCProbe,
  runQuickBrowserEDNSProbe,
  sameIPv6Prefix48,
} from '../lib/leakProbes';
import {
  maskFullIP,
  PRIVACY_MASK_EVENT,
  readPrivacyMaskPref,
  redactInlineSensitive,
  writePrivacyMaskPref,
} from '../lib/privacyMask';
import { BrowserDoHCheckResponse, DNSLeakReport, EgressEndpoint } from '../types';

export interface DNSLeakTestCardProps {
  title?: string;
  subtitle?: string;
  report?: DNSLeakReport | null;
  onReportChange?: (rep: DNSLeakReport) => void;
  privacyMask?: boolean;
  onPrivacyMaskChange?: (next: boolean) => void;
}

type SweepMode = 'standard' | 'deep';

interface PanoramicSuiteState {
  mode: SweepMode;
  checkedAt: string;
  totalDurationMs: number;
  gatewayReport: DNSLeakReport | null;
  gatewayError: string;
  browserSamples: BrowserEDNSSample[];
  browserRoundsTarget: number;
  browserRoundsDone: number;
  browserDom: { endpoint: EgressEndpoint; usedIPv6: boolean } | null;
  browserOv4: EgressEndpoint | null;
  browserOv6: EgressEndpoint | null;
  webrtc: BrowserWebRTCReport | null;
}

interface MergedDNSRow {
  ip: string;
  country: string;
  countryCode: string;
  isp: string;
  ecs: string;
  ecsCountryCode: string;
  gwHits: number;
  brHits: number;
  fromGateway: boolean;
  fromBrowser: boolean;
  leaked: boolean;
  leakReason: string;
}

// Keep last completed scan across route/tab switches between NetworkPage and AdGuardPage.
let cachedSuiteState: PanoramicSuiteState | null = null;

export const BROWSER_DOH_EVENT = 'singctl:browser-doh-updated';
let cachedBrowserDoH: BrowserDoHCheckResponse | null = null;
let browserDoHInFlight: Promise<BrowserDoHCheckResponse | null> | null = null;

export function getCachedBrowserDoH(): BrowserDoHCheckResponse | null {
  return cachedBrowserDoH;
}

export async function runBrowserDoHCheckFlow(
  existingSamples?: BrowserEDNSSample[],
  attempted?: number,
  failed?: number,
  presetProbeId?: string,
): Promise<BrowserDoHCheckResponse | null> {
  const hasExplicit = existingSamples !== undefined;
  if (!hasExplicit && browserDoHInFlight) {
    return browserDoHInFlight;
  }

  const task = (async (): Promise<BrowserDoHCheckResponse | null> => {
    try {
      let samples: BrowserEDNSSample[] = [];
      let probeAttempted = attempted ?? 0;
      let probeFailed = failed ?? 0;
      let probeId = presetProbeId;

      if (hasExplicit) {
        samples = existingSamples ?? [];
      } else if (typeof window !== 'undefined' && isLikelyTailscaleHost(window.location.hostname)) {
        probeAttempted = 0;
        probeFailed = 0;
      } else {
        const begin = await clientApi.checkBrowserDoH({ phase: 'begin' }).catch(() => null);
        if (begin?.status === 'skipped_remote') {
          cachedBrowserDoH = begin;
          if (typeof window !== 'undefined') {
            window.dispatchEvent(new CustomEvent<BrowserDoHCheckResponse>(BROWSER_DOH_EVENT, { detail: begin }));
          }
          return begin;
        }
        if (begin?.probeId) {
          probeId = begin.probeId;
        }
        const quick = await runQuickBrowserEDNSProbe(3);
        samples = quick.samples;
        probeAttempted = quick.attempted;
        probeFailed = quick.failed;
      }

      const compactMap = new Map<string, BrowserEDNSSample>();
      for (const s of samples) {
        if (s.dnsIp && !compactMap.has(s.dnsIp)) {
          compactMap.set(s.dnsIp, {
            dnsIp: s.dnsIp,
            country: s.country,
            countryCode: s.countryCode,
            isp: s.isp,
          });
        }
      }

      const res = await clientApi.checkBrowserDoH({
        phase: 'finish',
        probeId,
        browserSamples: Array.from(compactMap.values()),
        browserProbeAttempted: probeAttempted,
        browserProbeFailed: probeFailed,
      });
      cachedBrowserDoH = res;
      if (typeof window !== 'undefined') {
        window.dispatchEvent(new CustomEvent<BrowserDoHCheckResponse>(BROWSER_DOH_EVENT, { detail: res }));
      }
      return res;
    } catch {
      return null;
    }
  })();

  if (!hasExplicit) {
    browserDoHInFlight = task.finally(() => {
      browserDoHInFlight = null;
    });
    return browserDoHInFlight;
  }
  return task;
}

const VERDICT_META: Record<
  string,
  {
    tone: 'ok' | 'warn' | 'danger';
    badge: string;
    headline: string;
    boxClass: string;
  }
> = {
  safe: {
    tone: 'ok',
    badge: '零 DNS / WebRTC 泄漏',
    headline: '浏览器端与网关端多轮防缓存实测均通过，无国内外混淆或真实宽带暴露',
    boxClass: 'border-emerald-500/30 bg-emerald-500/10 text-emerald-200',
  },
  warning: {
    tone: 'warn',
    badge: '存在提示项',
    headline: '核心代理链路无国内 DNS 泄漏，但部分双栈 / WebRTC / 宿主配置项值得留意',
    boxClass: 'border-amber-500/35 bg-amber-500/10 text-amber-200',
  },
  leaked: {
    tone: 'danger',
    badge: '检测到泄漏风险',
    headline: '检测到 DNS 解析、IPv6 分流或 WebRTC 存在真实宽带暴露风险，请立即查看下方红标项',
    boxClass: 'border-rose-500/40 bg-rose-500/10 text-rose-200',
  },
};

function formatGeoLine(ep?: EgressEndpoint | null): string {
  if (!ep) return '';
  const parts = [ep.country, ep.region, ep.city].filter((p, idx, arr) => p && arr.indexOf(p) === idx);
  return parts.join(' · ');
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
  const [suite, setSuite] = useState<PanoramicSuiteState | null>(() => cachedSuiteState);
  const [running, setRunning] = useState(false);
  const [localMask, setLocalMask] = useState<boolean>(() => readPrivacyMaskPref());
  const [browserDoH, setBrowserDoH] = useState<BrowserDoHCheckResponse | null>(() => getCachedBrowserDoH());
  const [checkingDoH, setCheckingDoH] = useState(false);
  const [copiedGuideUrl, setCopiedGuideUrl] = useState(false);
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

  useEffect(() => {
    return () => {
      abortRef.current?.abort();
    };
  }, []);

  // Support optional controlled gateway report injection if a parent passes one.
  const effectiveGatewayReport =
    controlledReport !== undefined ? controlledReport : suite?.gatewayReport ?? null;

  const updateSuite = (updater: (prev: PanoramicSuiteState | null) => PanoramicSuiteState | null) => {
    setSuite((prev) => {
      const next = updater(prev);
      cachedSuiteState = next;
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
      // 1. 网关后端：4 路双栈出口 + 多轮随机子域 EDNS + 5 项底层防线审计
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

      // 2. 浏览器视角：并发多轮唯一随机子域防缓存扫描
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

      // 3. 浏览器视角：国内分流出口 (myip.ipip.net)
      probeBrowserDomesticIP(ctrl.signal).then((res) => {
        if (runIdRef.current !== myRunId) return;
        localBrowserDom = res;
        updateSuite((prev) => (prev ? { ...prev, browserDom: res } : prev));
      }),

      // 4. 浏览器视角：海外 IPv4 出口 (ipv4.geojs.io)
      probeBrowserOverseasIP('v4', ctrl.signal).then((ep) => {
        if (runIdRef.current !== myRunId) return;
        localBrowserOv4 = ep;
        updateSuite((prev) => (prev ? { ...prev, browserOv4: ep } : prev));
      }),

      // 5. 浏览器视角：海外 IPv6 出口 (ipv6.geojs.io)
      probeBrowserOverseasIP('v6', ctrl.signal).then((ep) => {
        if (runIdRef.current !== myRunId) return;
        localBrowserOv6 = ep;
        updateSuite((prev) => (prev ? { ...prev, browserOv6: ep } : prev));
      }),

      // 6. 浏览器视角：WebRTC ICE/STUN 真实 IP 泄漏检测
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
    } else if (localGwReport?.verdict === 'warning') {
      toast('全景防泄漏体检完成（存在提示项，请留意详情）', 'info');
    } else {
      success(`双端全景防泄漏体检通过 (${totalMs}ms)`);
    }
  };

  const analysis = useMemo(() => {
    const gw = effectiveGatewayReport;
    const ipv6Mode = gw?.ipv6Mode || 'off';
    const homeIPv4 = gw?.egress?.domesticIpv4?.ip || gw?.homePublicIp || '';
    const homeIPv6 =
      gw?.egress?.domesticIpv6?.ip ||
      (suite?.browserDom?.usedIPv6 ? suite.browserDom.endpoint.ip : '') ||
      '';

    // Aggregate Browser + Gateway DNS observations
    const rowMap = new Map<string, MergedDNSRow>();
    const getOrCreate = (ip: string): MergedDNSRow => {
      const existing = rowMap.get(ip);
      if (existing) return existing;
      const created: MergedDNSRow = {
        ip,
        country: '',
        countryCode: '',
        isp: '',
        ecs: '',
        ecsCountryCode: '',
        gwHits: 0,
        brHits: 0,
        fromGateway: false,
        fromBrowser: false,
        leaked: false,
        leakReason: '',
      };
      rowMap.set(ip, created);
      return created;
    };

    for (const s of gw?.dnsServers || []) {
      const row = getOrCreate(s.ip);
      row.country = row.country || s.country || '';
      row.countryCode = row.countryCode || s.countryCode || '';
      row.isp = row.isp || s.isp || '';
      row.ecs = row.ecs || s.ecs || '';
      row.ecsCountryCode = row.ecsCountryCode || s.ecsCountryCode || '';
      row.gwHits += s.hits || 1;
      row.fromGateway = true;
      if (s.leaked) {
        row.leaked = true;
        row.leakReason = s.leakReason || '网关探测发现国内或本地解析器出口';
      }
    }

    for (const s of suite?.browserSamples || []) {
      const row = getOrCreate(s.dnsIp);
      row.country = row.country || s.country || '';
      row.countryCode = row.countryCode || s.countryCode || '';
      row.isp = row.isp || s.isp || '';
      row.ecs = row.ecs || s.ednsIp || '';
      row.ecsCountryCode = row.ecsCountryCode || s.ednsCountryCode || '';
      row.brHits += 1;
      row.fromBrowser = true;
    }

    // Re-evaluate browser-observed leaks against home IPv4 & home IPv6 /48
    for (const row of rowMap.values()) {
      const reasons: string[] = [];
      if (row.leakReason) reasons.push(row.leakReason);
      if (row.countryCode === 'CN') {
        reasons.push(`解析器位于中国大陆 (${row.isp || 'CN'})`);
      }
      if (homeIPv4 && row.ip === homeIPv4) {
        reasons.push('解析器 IP 与家庭宽带公网 IPv4 一致');
      }
      if (homeIPv6 && (row.ip === homeIPv6 || sameIPv6Prefix48(row.ip, homeIPv6))) {
        reasons.push('解析器 IP 命中家庭原生 IPv6 前缀');
      }
      if (row.ecsCountryCode === 'CN') {
        reasons.push(`ECS 子网 (${row.ecs}) 归属中国大陆`);
      }
      if (reasons.length > 0) {
        row.leaked = true;
        row.leakReason = Array.from(new Set(reasons)).join('；');
      }
    }

    const mergedDNSServers = Array.from(rowMap.values()).sort((a, b) => {
      if (a.leaked !== b.leaked) return a.leaked ? -1 : 1;
      const totA = a.gwHits + a.brHits;
      const totB = b.gwHits + b.brHits;
      if (totA !== totB) return totB - totA;
      return a.ip.localeCompare(b.ip);
    });

    const gatewayDNSLeaked =
      gw?.verdict === 'leaked' ||
      mergedDNSServers.some((r) => r.fromGateway && r.leaked);
    const browserDNSLeaked = mergedDNSServers.some((r) => r.fromBrowser && r.leaked);

    // Evaluate 4 egress endpoints
    const domV4: EgressEndpoint | null =
      gw?.egress?.domesticIpv4 ||
      (homeIPv4 ? { ip: homeIPv4, isp: gw?.homeIsp, country: '中国', countryCode: 'CN', reachable: true } : null);

    const domV6: EgressEndpoint | null =
      gw?.egress?.domesticIpv6?.reachable
        ? gw.egress.domesticIpv6
        : suite?.browserDom?.usedIPv6 && suite.browserDom.endpoint.reachable
          ? suite.browserDom.endpoint
          : gw?.egress?.domesticIpv6 || null;

    const ov4: EgressEndpoint | null =
      suite?.browserOv4?.reachable ? suite.browserOv4 : gw?.egress?.overseasIpv4 || suite?.browserOv4 || null;
    const ov4Leaked = Boolean(
      ov4?.reachable && (ov4.countryCode === 'CN' || (homeIPv4 && ov4.ip === homeIPv4)),
    );

    const ov6Target =
      suite?.browserOv6?.reachable ? suite.browserOv6 : gw?.egress?.overseasIpv6 || suite?.browserOv6 || null;
    const ov6IsHomeOrCN = Boolean(
      ov6Target?.reachable &&
        (ov6Target.countryCode === 'CN' || (homeIPv6 && sameIPv6Prefix48(ov6Target.ip, homeIPv6))),
    );
    const ov6Leaked = ipv6Mode !== 'full' && ov6IsHomeOrCN;
    const browserHasIPv6 = Boolean(suite?.browserDom?.usedIPv6 || suite?.browserOv6?.reachable);
    const clientIPv6Disabled = Boolean(
      ipv6Mode !== 'off' &&
        suite?.browserDom &&
        !browserHasIPv6 &&
        gw?.egress?.domesticIpv6?.reachable,
    );

    // Evaluate WebRTC
    const rtc = suite?.webrtc || null;
    let webrtcStatus: 'none' | 'safe' | 'warn' | 'leaked' = 'none';
    let webrtcHeadline = '';
    if (rtc) {
      const rtcLeakedV4 = Boolean(homeIPv4 && rtc.publicIPv4s.includes(homeIPv4));
      const rtcLeakedV6 = Boolean(
        homeIPv6 && rtc.publicIPv6s.some((ip) => ip === homeIPv6 || sameIPv6Prefix48(ip, homeIPv6)),
      );
      if (rtcLeakedV4 || rtcLeakedV6) {
        webrtcStatus = 'leaked';
        webrtcHeadline = 'WebRTC 穿透代理暴露了真实家庭宽带公网 IP！';
      } else if (rtc.blocked || (rtc.publicIPv4s.length === 0 && rtc.publicIPv6s.length === 0)) {
        webrtcStatus = 'safe';
        webrtcHeadline = rtc.blocked
          ? '浏览器策略已彻底屏蔽 WebRTC STUN 探测'
          : '零公网 IP 反射（mDNS 隐私保护或本地屏蔽生效）';
      } else {
        webrtcStatus = 'warn';
        webrtcHeadline = 'WebRTC 反射出代理落地公网 IP（未暴露家庭 IP；极客模式可在 Brave 开启“禁用非代理 UDP”）';
      }
    }

    let verdict: 'safe' | 'warning' | 'leaked' = 'safe';
    if (gatewayDNSLeaked || browserDNSLeaked || ov4Leaked || ov6Leaked || webrtcStatus === 'leaked') {
      verdict = 'leaked';
    } else if (gw?.verdict === 'warning' || webrtcStatus === 'warn' || (!gw && Boolean(suite?.gatewayError))) {
      verdict = 'warning';
    }

    const browserOnlyLeak = !gatewayDNSLeaked && browserDNSLeaked;

    return {
      gw,
      ipv6Mode,
      homeIPv4,
      homeIPv6,
      mergedDNSServers,
      domV4,
      domV6,
      ov4,
      ov4Leaked,
      ov6Target,
      ov6Leaked,
      ov6IsHomeOrCN,
      clientIPv6Disabled,
      rtc,
      webrtcStatus,
      webrtcHeadline,
      verdict,
      browserOnlyLeak,
    };
  }, [effectiveGatewayReport, suite]);

  const hasResult = Boolean(effectiveGatewayReport || suite);
  const verdictMeta = VERDICT_META[analysis.verdict] || VERDICT_META.warning;
  const totalSweepTarget = (suite?.browserRoundsTarget || 0) + (effectiveGatewayReport?.gatewayRounds || (suite?.mode === 'deep' ? 16 : 8));
  const totalSweepDone =
    (suite?.browserRoundsDone || 0) +
    (effectiveGatewayReport ? effectiveGatewayReport.gatewayRounds || 0 : 0);
  const progressPct = totalSweepTarget > 0 ? Math.min(100, Math.round((totalSweepDone / totalSweepTarget) * 100)) : 0;

  const dohGuide = useMemo(() => detectBrowserDoHGuide(), []);

  const handleCopyDoHGuideUrl = async () => {
    try {
      await copyPlainText(dohGuide.settingsUrl);
      setCopiedGuideUrl(true);
      success(`已复制 ${dohGuide.browserName} 安全 DNS 设置地址`);
      window.setTimeout(() => setCopiedGuideUrl(false), 2000);
    } catch {
      toast('复制失败，请手动复制设置页地址', 'warn');
    }
  };

  const renderBrowserDoHCard = () => {
    const dohRisk = browserDoH?.status === 'detected' || browserDoH?.status === 'suspected';
    const dohTone: 'ok' | 'warn' | 'danger' | 'neutral' =
      browserDoH?.status === 'detected'
        ? 'danger'
        : browserDoH?.status === 'suspected'
        ? 'warn'
        : browserDoH?.status === 'clean'
        ? 'ok'
        : 'neutral';
    const dohBadgeLabel = !browserDoH
      ? checkingDoH
        ? '检测中…'
        : '待检测'
      : browserDoH.status === 'detected'
      ? '检测到安全 DNS 绕过'
      : browserDoH.status === 'suspected'
      ? '疑似启用外部安全 DNS'
      : browserDoH.status === 'clean'
      ? '正常 · 走网关统一解析'
      : browserDoH.status === 'skipped_remote'
      ? browserDoH.viaTailscale
        ? '远程隧道访问已跳过'
        : '非局域网直连已跳过'
      : '暂不可用';

    return (
      <div
        className={`rounded-xl border px-3.5 py-2.5 text-xs space-y-2 ${
          browserDoH?.status === 'detected'
            ? 'border-rose-500/40 bg-rose-500/10 text-rose-100'
            : browserDoH?.status === 'suspected'
            ? 'border-amber-500/35 bg-amber-500/10 text-amber-100'
            : 'border-subtle bg-surface2/55 text-secondary'
        }`}
      >
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div className="flex flex-wrap items-center gap-2">
            <Monitor className="w-3.5 h-3.5 text-sky-400 shrink-0" />
            <span className="font-semibold text-primary">浏览器安全 DNS (DoH) 绕过检测</span>
            <Badge tone={dohTone}>{dohBadgeLabel}</Badge>
            {browserDoH?.detectedProvider && dohRisk && (
              <Badge tone="danger">{browserDoH.detectedProvider}</Badge>
            )}
          </div>
          <Button
            size="xs"
            variant="ghost"
            loading={checkingDoH}
            disabled={running}
            icon={<RefreshCw className="w-3 h-3" />}
            onClick={() => void handleCheckBrowserDoH()}
          >
            {browserDoH ? '重新检测 DoH' : '检测浏览器 DoH'}
          </Button>
        </div>

        {browserDoH && (
          <div className="space-y-1.5 text-[11px] leading-relaxed">
            <div className="text-primary/90">{redactInlineSensitive(browserDoH.summary, hideIP)}</div>
            <div className="flex flex-wrap gap-x-4 gap-y-0.5 text-muted font-mono">
              {browserDoH.clientIp && <span>本机终端: {maskFullIP(browserDoH.clientIp, hideIP)}</span>}
              {browserDoH.gatewayResolver && (
                <span>
                  网关解析:{' '}
                  {hideIP
                    ? '•••••••• (已遮挡)'
                    : `${browserDoH.gatewayResolver.isp || '-'} (${browserDoH.gatewayResolver.ip || '-'})`}
                </span>
              )}
              {browserDoH.browserResolvers && browserDoH.browserResolvers.length > 0 && (
                <span>
                  浏览器解析:{' '}
                  {hideIP
                    ? '•••••••• (已遮挡)'
                    : browserDoH.browserResolvers
                        .map((r) => `${r.isp || '-'}${r.dnsIp ? ` (${r.dnsIp})` : ''}`)
                        .join(', ')}
                </span>
              )}
            </div>
            {browserDoH.signals && browserDoH.signals.length > 0 && (
              <ul className="list-disc pl-4 space-y-0.5 text-amber-200/90">
                {browserDoH.signals.map((sig, idx) => (
                  <li key={idx}>{redactInlineSensitive(sig, hideIP)}</li>
                ))}
              </ul>
            )}
            {dohRisk && (
              <div className="rounded-lg border border-amber-400/30 bg-slate-950/60 px-3 py-2 flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                <div className="space-y-0.5">
                  <div className="font-semibold text-amber-200">
                    建议关闭 {dohGuide.browserName} 的安全 DNS (DoH)
                  </div>
                  <div className="text-slate-300">
                    {dohGuide.steps}（设置页：<code className="font-mono text-sky-300">{dohGuide.settingsUrl}</code>）
                  </div>
                </div>
                <Button
                  size="xs"
                  variant="secondary"
                  className="shrink-0"
                  icon={copiedGuideUrl ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                  onClick={() => void handleCopyDoHGuideUrl()}
                >
                  {copiedGuideUrl ? '已复制地址' : '复制设置地址'}
                </Button>
              </div>
            )}
          </div>
        )}
      </div>
    );
  };

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
        {renderBrowserDoHCard()}

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
          {/* 实时扫描进度条（扫描进行中显示） */}
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

          {/* 总评 Banner */}
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

          {/* 独家双端智能归因警告 */}
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

          {/* 模块 1：四路出口 IP 与分流全景矩阵 */}
          <div className="space-y-2">
            <div className="flex items-center justify-between text-xs font-semibold text-primary">
              <span className="inline-flex items-center gap-1.5">
                <Globe className="w-3.5 h-3.5 text-sky-400" />
                四路出口 IP 与双栈分流全景
              </span>
              <span className="text-[11px] font-normal text-muted">对比国内直连与海外代理落地真实表现</span>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-2.5">
              {/* 国内直连 IPv4 */}
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

              {/* 国内直连 IPv6 */}
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

              {/* 海外代理 IPv4 */}
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

              {/* 海外代理 IPv6 */}
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

          {/* 模块 2：多轮防缓存 DNS 出口解析器清单（ipleak.net 核心视图） */}
          <div className="space-y-2">
            <div className="flex flex-wrap items-center justify-between gap-2 text-xs font-semibold text-primary">
              <span className="inline-flex items-center gap-1.5">
                <Radar className="w-3.5 h-3.5 text-emerald-400" />
                DNS 解析器防缓存多轮扫描列表
                <Badge tone="neutral">{analysis.mergedDNSServers.length} 个唯一解析器</Badge>
              </span>
              <span className="text-[11px] font-normal text-muted">
                并发请求唯一随机子域，杜绝缓存伪装并揪出多上游混用泄漏
              </span>
            </div>

            {analysis.mergedDNSServers.length === 0 ? (
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
                    {analysis.mergedDNSServers.map((row) => {
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

          {/* 模块 3：浏览器 WebRTC 泄漏检测 */}
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

          {/* 模块 4：网关内核与 OpenWrt 基线审计（5 项核心核验） */}
          {effectiveGatewayReport && effectiveGatewayReport.checks.length > 0 && (
            <div className="space-y-2">
              <div className="flex items-center justify-between text-xs font-semibold text-primary">
                <span className="inline-flex items-center gap-1.5">
                  <Router className="w-3.5 h-3.5 text-amber-400" />
                  网关底层防线审计（:53 劫持 / 防投毒 / AAAA 规则 / RA 基线）
                </span>
                <span className="font-mono tnum text-[11px] font-normal text-muted">
                  网关侧耗时 {effectiveGatewayReport.durationMs}ms
                </span>
              </div>
              <div className="divide-y divide-[var(--border-subtle)] rounded-xl border border-subtle bg-surface2/45">
                {effectiveGatewayReport.checks.map((c) => {
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
          )}
        </div>
      )}
      </div>
    </SectionCard>
  );
};

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

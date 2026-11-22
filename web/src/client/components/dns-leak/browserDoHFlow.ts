import { clientApi } from '../../api';
import {
  BrowserEDNSSample,
  BrowserWebRTCReport,
  isLikelyTailscaleHost,
  runQuickBrowserEDNSProbe,
} from '../../lib/leakProbes';
import { BrowserDoHCheckResponse, DNSLeakReport, EgressEndpoint } from '../../types';

export type SweepMode = 'standard' | 'deep';

export interface PanoramicSuiteState {
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

export interface MergedDNSRow {
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

export function getCachedSuiteState(): PanoramicSuiteState | null {
  return cachedSuiteState;
}

export function setCachedSuiteState(next: PanoramicSuiteState | null): void {
  cachedSuiteState = next;
}

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

export const VERDICT_META: Record<
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

export function formatGeoLine(ep?: EgressEndpoint | null): string {
  if (!ep) return '';
  const parts = [ep.country, ep.region, ep.city].filter((p, idx, arr) => p && arr.indexOf(p) === idx);
  return parts.join(' · ');
}

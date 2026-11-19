import { EgressEndpoint } from '../types';

export interface BrowserEDNSSample {
  dnsIp: string;
  country: string;
  countryCode: string;
  isp: string;
  ednsIp?: string;
  ednsCountryCode?: string;
}

export interface BrowserWebRTCReport {
  supported: boolean;
  blocked: boolean;
  durationMs: number;
  mdnsCount: number;
  localIPs: string[];
  publicIPv4s: string[];
  publicIPv6s: string[];
  error?: string;
}

const COUNTRY_NAME_TO_ISO2: Record<string, string> = {
  china: 'CN',
  "people's republic of china": 'CN',
  'united states': 'US',
  'united states of america': 'US',
  usa: 'US',
  japan: 'JP',
  'hong kong': 'HK',
  taiwan: 'TW',
  macao: 'MO',
  macau: 'MO',
  singapore: 'SG',
  'united kingdom': 'GB',
  'great britain': 'GB',
  germany: 'DE',
  'south korea': 'KR',
  korea: 'KR',
  'republic of korea': 'KR',
  netherlands: 'NL',
  'the netherlands': 'NL',
  canada: 'CA',
  australia: 'AU',
  france: 'FR',
  russia: 'RU',
  'russian federation': 'RU',
  india: 'IN',
  switzerland: 'CH',
  sweden: 'SE',
  finland: 'FI',
  ireland: 'IE',
  brazil: 'BR',
  indonesia: 'ID',
  malaysia: 'MY',
  thailand: 'TH',
  vietnam: 'VN',
  philippines: 'PH',
  turkey: 'TR',
  'türkiye': 'TR',
  'united arab emirates': 'AE',
  italy: 'IT',
  spain: 'ES',
  poland: 'PL',
  ukraine: 'UA',
  norway: 'NO',
  denmark: 'DK',
  austria: 'AT',
  belgium: 'BE',
  'new zealand': 'NZ',
  mexico: 'MX',
  argentina: 'AR',
  'south africa': 'ZA',
  israel: 'IL',
};

/**
 * Generates 32 random hex chars using crypto.getRandomValues so it also works
 * on plain HTTP LAN origins (e.g. http://192.168.31.1:8090) where randomUUID is unavailable.
 */
export function randomHex32(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

export function countryFlag(code?: string): string {
  const cc = (code || '').trim().toUpperCase();
  if (!/^[A-Z]{2}$/.test(cc)) return '🌐';
  const base = 0x1f1e6 - 65;
  return String.fromCodePoint(base + cc.charCodeAt(0), base + cc.charCodeAt(1));
}

export function parseEdnsGeo(geo?: string): { country: string; countryCode: string; isp: string } {
  const trimmed = (geo || '').trim();
  if (!trimmed) return { country: '', countryCode: '', isp: '' };
  const sepIdx = trimmed.indexOf(' - ');
  const country = (sepIdx >= 0 ? trimmed.slice(0, sepIdx) : trimmed).trim();
  const isp = (sepIdx >= 0 ? trimmed.slice(sepIdx + 3) : '').trim();
  const mapped = COUNTRY_NAME_TO_ISO2[country.toLowerCase()];
  if (mapped) return { country, countryCode: mapped, isp };
  if (/^[A-Za-z]{2}$/.test(country)) return { country, countryCode: country.toUpperCase(), isp };
  if (country === '中国') return { country, countryCode: 'CN', isp };
  return { country, countryCode: '', isp };
}

export function expandIPv6Hextets(rawIP?: string): string[] | null {
  if (!rawIP) return null;
  let ip = rawIP.trim().replace(/^\[|\]$/g, '').split('%')[0];
  if (!ip.includes(':')) return null;

  // Handle IPv4-mapped suffix like ::ffff:192.0.2.1
  if (ip.includes('.')) {
    const lastColon = ip.lastIndexOf(':');
    const v4Part = ip.slice(lastColon + 1);
    const octets = v4Part.split('.').map((n) => Number(n));
    if (octets.length !== 4 || octets.some((o) => !Number.isInteger(o) || o < 0 || o > 255)) {
      return null;
    }
    const hi = ((octets[0] << 8) | octets[1]).toString(16);
    const lo = ((octets[2] << 8) | octets[3]).toString(16);
    ip = `${ip.slice(0, lastColon)}:${hi}:${lo}`;
  }

  const dblIdx = ip.indexOf('::');
  if (dblIdx >= 0) {
    if (ip.indexOf('::', dblIdx + 2) >= 0) return null; // invalid multiple ::
    const left = ip.slice(0, dblIdx).split(':').filter(Boolean);
    const right = ip.slice(dblIdx + 2).split(':').filter(Boolean);
    const fill = 8 - (left.length + right.length);
    if (fill < 1) return null;
    const all = [...left, ...Array(fill).fill('0'), ...right];
    return all.map((h) => h.padStart(4, '0').toLowerCase());
  }

  const parts = ip.split(':');
  if (parts.length !== 8) return null;
  return parts.map((h) => h.padStart(4, '0').toLowerCase());
}

export function sameIPv6Prefix48(a?: string, b?: string): boolean {
  const ha = expandIPv6Hextets(a);
  const hb = expandIPv6Hextets(b);
  if (!ha || !hb) return false;
  return ha[0] === hb[0] && ha[1] === hb[1] && ha[2] === hb[2];
}

export function maskIP(ip?: string, masked?: boolean): string {
  if (!ip) return '-';
  if (!masked) return ip;
  const clean = ip.trim();
  if (clean.includes(':')) {
    const parts = clean.split(':');
    if (parts.length <= 2) return '****::****';
    return `${parts.slice(0, 2).join(':')}:****:****`;
  }
  const octets = clean.split('.');
  if (octets.length === 4) {
    return `${octets[0]}.${octets[1]}.*.*`;
  }
  return clean;
}

function combinedAbortSignal(ms: number, parent?: AbortSignal): { signal: AbortSignal; cleanup: () => void } {
  const ctrl = new AbortController();
  const timer = window.setTimeout(() => ctrl.abort(), ms);
  const onParentAbort = () => ctrl.abort();
  if (parent) {
    if (parent.aborted) {
      ctrl.abort();
    } else {
      parent.addEventListener('abort', onParentAbort, { once: true });
    }
  }
  return {
    signal: ctrl.signal,
    cleanup: () => {
      window.clearTimeout(timer);
      parent?.removeEventListener('abort', onParentAbort);
    },
  };
}

export async function probeBrowserOverseasIP(
  family: 'v4' | 'v6',
  parentSignal?: AbortSignal,
): Promise<EgressEndpoint> {
  const url =
    family === 'v6' ? 'https://ipv6.geojs.io/v1/ip/geo.json' : 'https://ipv4.geojs.io/v1/ip/geo.json';
  const timeoutMs = family === 'v6' ? 3200 : 4500;
  const t0 = performance.now();
  const { signal, cleanup } = combinedAbortSignal(timeoutMs, parentSignal);
  try {
    const resp = await fetch(url, { cache: 'no-store', signal });
    const latencyMs = Math.max(1, Math.round(performance.now() - t0));
    if (!resp.ok) {
      return { reachable: false, latencyMs, error: `HTTP ${resp.status}` };
    }
    const g = (await resp.json()) as {
      ip?: string;
      country?: string;
      country_code?: string;
      region?: string;
      city?: string;
      organization_name?: string;
      organization?: string;
      asn?: number;
    };
    const ip = (g.ip || '').trim();
    if (!ip) {
      return { reachable: false, latencyMs, error: '空响应' };
    }
    const isp = (g.organization_name || g.organization || '').trim();
    const asn = g.asn ? `AS${g.asn}${isp ? ` ${isp}` : ''}` : '';
    return {
      ip,
      country: (g.country || '').trim(),
      countryCode: (g.country_code || '').trim().toUpperCase(),
      region: (g.region || '').trim(),
      city: (g.city || '').trim(),
      isp,
      asn,
      latencyMs,
      reachable: true,
    };
  } catch (err) {
    const latencyMs = Math.max(1, Math.round(performance.now() - t0));
    return {
      reachable: false,
      latencyMs,
      error: err instanceof Error ? err.message : 'unreachable',
    };
  } finally {
    cleanup();
  }
}

export async function probeBrowserDomesticIP(
  parentSignal?: AbortSignal,
): Promise<{ endpoint: EgressEndpoint; usedIPv6: boolean }> {
  const t0 = performance.now();
  const { signal, cleanup } = combinedAbortSignal(4000, parentSignal);
  try {
    const resp = await fetch('https://myip.ipip.net/json', { cache: 'no-store', signal });
    const latencyMs = Math.max(1, Math.round(performance.now() - t0));
    if (!resp.ok) {
      return { endpoint: { reachable: false, latencyMs, error: `HTTP ${resp.status}` }, usedIPv6: false };
    }
    const parsed = (await resp.json()) as {
      ret?: string;
      data?: { ip?: string; location?: string[] };
    };
    const ip = (parsed?.data?.ip || '').trim();
    if (!ip) {
      return { endpoint: { reachable: false, latencyMs, error: '返回为空' }, usedIPv6: false };
    }
    const loc = Array.isArray(parsed?.data?.location) ? parsed.data.location : [];
    const country = (loc[0] || '').trim();
    const countryCode = country === '中国' || country.toLowerCase() === 'china' ? 'CN' : '';
    const region = (loc[1] || '').trim();
    const city = (loc[2] || '').trim();
    const isp = (loc[4] || loc[3] || '').trim();
    return {
      usedIPv6: ip.includes(':'),
      endpoint: {
        ip,
        country,
        countryCode,
        region,
        city,
        isp,
        latencyMs,
        reachable: true,
      },
    };
  } catch (err) {
    const latencyMs = Math.max(1, Math.round(performance.now() - t0));
    return {
      usedIPv6: false,
      endpoint: {
        reachable: false,
        latencyMs,
        error: err instanceof Error ? err.message : 'unreachable',
      },
    };
  } finally {
    cleanup();
  }
}

export async function runBrowserEDNSSweep(
  rounds: number,
  onProgress: (done: number, total: number, sample: BrowserEDNSSample | null) => void,
  parentSignal?: AbortSignal,
): Promise<BrowserEDNSSample[]> {
  const total = Math.max(1, Math.min(200, rounds));
  const samples: BrowserEDNSSample[] = [];
  let completed = 0;
  let nextIdx = 0;

  const fetchOne = async (): Promise<BrowserEDNSSample | null> => {
    const sub = randomHex32();
    const { signal, cleanup } = combinedAbortSignal(4500, parentSignal);
    try {
      const resp = await fetch(`https://${sub}.edns.ip-api.com/json`, {
        cache: 'no-store',
        signal,
      });
      if (!resp.ok) return null;
      const body = (await resp.json()) as {
        dns?: { ip?: string; geo?: string };
        edns?: { ip?: string; geo?: string };
      };
      const dnsIp = (body?.dns?.ip || '').trim();
      if (!dnsIp) return null;
      const parsedDns = parseEdnsGeo(body?.dns?.geo);
      const ednsIp = (body?.edns?.ip || '').trim();
      const parsedEdns = ednsIp ? parseEdnsGeo(body?.edns?.geo) : null;
      return {
        dnsIp,
        country: parsedDns.country,
        countryCode: parsedDns.countryCode,
        isp: parsedDns.isp,
        ednsIp: ednsIp || undefined,
        ednsCountryCode: parsedEdns?.countryCode || undefined,
      };
    } catch {
      return null;
    } finally {
      cleanup();
    }
  };

  const worker = async () => {
    while (nextIdx < total && !parentSignal?.aborted) {
      nextIdx++;
      const sample = await fetchOne();
      if (parentSignal?.aborted) break;
      completed++;
      if (sample) samples.push(sample);
      onProgress(completed, total, sample);
    }
  };

  const workers = Array.from({ length: Math.min(8, total) }, () => worker());
  await Promise.all(workers);
  return samples;
}

function classifyCandidateIP(ip: string): 'mdns' | 'local' | 'v4' | 'v6' {
  const trimmed = ip.trim();
  if (!trimmed || trimmed.endsWith('.local')) return 'mdns';
  if (trimmed.includes(':')) {
    const lower = trimmed.toLowerCase();
    if (lower === '::1' || lower.startsWith('fe80:') || lower.startsWith('fc') || lower.startsWith('fd')) {
      return 'local';
    }
    return 'v6';
  }
  const parts = trimmed.split('.').map((n) => Number(n));
  if (parts.length !== 4 || parts.some((p) => !Number.isInteger(p) || p < 0 || p > 255)) {
    return 'local';
  }
  const [a, b] = parts;
  if (
    a === 10 ||
    a === 127 ||
    a === 0 ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) ||
    (a === 198 && (b === 18 || b === 19)) ||
    (a === 100 && b >= 64 && b <= 127)
  ) {
    return 'local';
  }
  return 'v4';
}

export async function runBrowserWebRTCProbe(parentSignal?: AbortSignal): Promise<BrowserWebRTCReport> {
  const t0 = performance.now();
  if (typeof window === 'undefined' || typeof RTCPeerConnection === 'undefined') {
    return {
      supported: false,
      blocked: true,
      durationMs: 1,
      mdnsCount: 0,
      localIPs: [],
      publicIPv4s: [],
      publicIPv6s: [],
      error: '当前浏览器未开放 WebRTC API',
    };
  }

  let pc: RTCPeerConnection | null = null;
  let mdnsCount = 0;
  const seenMdns = new Set<string>();
  const localSet = new Set<string>();
  const v4Set = new Set<string>();
  const v6Set = new Set<string>();

  try {
    pc = new RTCPeerConnection({
      iceServers: [
        { urls: 'stun:stun.l.google.com:19302' },
        { urls: 'stun:stun.cloudflare.com:3478' },
      ],
    });
    pc.createDataChannel('singctl-probe');

    await new Promise<void>((resolve) => {
      if (!pc) {
        resolve();
        return;
      }
      let settled = false;
      const done = () => {
        if (settled) return;
        settled = true;
        window.clearTimeout(timer);
        parentSignal?.removeEventListener('abort', done);
        resolve();
      };
      const timer = window.setTimeout(done, 2600);
      parentSignal?.addEventListener('abort', done, { once: true });

      pc.onicegatheringstatechange = () => {
        if (pc?.iceGatheringState === 'complete') {
          done();
        }
      };

      pc.onicecandidate = (ev) => {
        const cand = ev.candidate;
        if (!cand) {
          done();
          return;
        }
        const raw = cand.candidate || '';
        const addr =
          (cand as RTCIceCandidate & { address?: string | null }).address ||
          raw.split(' ')[4] ||
          '';
        if (!addr) return;

        const typMatch = raw.match(/\btyp\s+(\S+)/i);
        const candType = ((cand as RTCIceCandidate & { type?: string | null }).type || typMatch?.[1] || '').toLowerCase();

        if (addr.endsWith('.local')) {
          if (!seenMdns.has(addr)) {
            seenMdns.add(addr);
            mdnsCount++;
          }
          return;
        }

        const kind = classifyCandidateIP(addr);
        if (kind === 'local' || candType === 'host') {
          if (kind === 'v4' || kind === 'v6') {
            // Host candidate that happens to carry a global/public IP directly
            if (kind === 'v4') v4Set.add(addr);
            else v6Set.add(addr);
          } else {
            localSet.add(addr);
          }
        } else if (kind === 'v4') {
          v4Set.add(addr);
        } else if (kind === 'v6') {
          v6Set.add(addr);
        }
      };

      void pc
        .createOffer()
        .then((offer) => pc?.setLocalDescription(offer))
        .catch(() => done());
    });

    const durationMs = Math.max(1, Math.round(performance.now() - t0));
    const localIPs = Array.from(localSet);
    const publicIPv4s = Array.from(v4Set);
    const publicIPv6s = Array.from(v6Set);
    const blocked =
      mdnsCount === 0 && localIPs.length === 0 && publicIPv4s.length === 0 && publicIPv6s.length === 0;

    return {
      supported: true,
      blocked,
      durationMs,
      mdnsCount,
      localIPs,
      publicIPv4s,
      publicIPv6s,
    };
  } catch (err) {
    return {
      supported: true,
      blocked: true,
      durationMs: Math.max(1, Math.round(performance.now() - t0)),
      mdnsCount: 0,
      localIPs: [],
      publicIPv4s: [],
      publicIPv6s: [],
      error: err instanceof Error ? err.message : 'WebRTC probe blocked',
    };
  } finally {
    try {
      pc?.close();
    } catch {
      // ignore
    }
  }
}

import { BrowserWebRTCReport, sameIPv6Prefix48 } from '../../lib/leakProbes';
import { DNSLeakReport, EgressEndpoint } from '../../types';
import { MergedDNSRow, PanoramicSuiteState } from './browserDoHFlow';

export interface PanoramicAnalysis {
  gw: DNSLeakReport | null;
  ipv6Mode: string;
  homeIPv4: string;
  homeIPv6: string;
  mergedDNSServers: MergedDNSRow[];
  domV4: EgressEndpoint | null;
  domV6: EgressEndpoint | null;
  ov4: EgressEndpoint | null;
  ov4Leaked: boolean;
  ov6Target: EgressEndpoint | null;
  ov6Leaked: boolean;
  ov6IsHomeOrCN: boolean;
  clientIPv6Disabled: boolean;
  rtc: BrowserWebRTCReport | null;
  webrtcStatus: 'none' | 'safe' | 'warn' | 'leaked';
  webrtcHeadline: string;
  verdict: 'safe' | 'warning' | 'leaked';
  browserOnlyLeak: boolean;
}

export function analyzePanoramicSuite(
  effectiveGatewayReport: DNSLeakReport | null,
  suite: PanoramicSuiteState | null,
): PanoramicAnalysis {
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
    gw?.verdict === 'leaked' || mergedDNSServers.some((r) => r.fromGateway && r.leaked);
  const browserDNSLeaked = mergedDNSServers.some((r) => r.fromBrowser && r.leaked);

  // Evaluate 4 egress endpoints
  const domV4: EgressEndpoint | null =
    gw?.egress?.domesticIpv4 ||
    (homeIPv4
      ? { ip: homeIPv4, isp: gw?.homeIsp, country: '中国', countryCode: 'CN', reachable: true }
      : null);

  const domV6: EgressEndpoint | null = gw?.egress?.domesticIpv6?.reachable
    ? gw.egress.domesticIpv6
    : suite?.browserDom?.usedIPv6 && suite.browserDom.endpoint.reachable
      ? suite.browserDom.endpoint
      : gw?.egress?.domesticIpv6 || null;

  const ov4: EgressEndpoint | null = suite?.browserOv4?.reachable
    ? suite.browserOv4
    : gw?.egress?.overseasIpv4 || suite?.browserOv4 || null;
  const ov4Leaked = Boolean(
    ov4?.reachable && (ov4.countryCode === 'CN' || (homeIPv4 && ov4.ip === homeIPv4)),
  );

  const ov6Target = suite?.browserOv6?.reachable
    ? suite.browserOv6
    : gw?.egress?.overseasIpv6 || suite?.browserOv6 || null;
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
      webrtcHeadline =
        'WebRTC 反射出代理落地公网 IP（未暴露家庭 IP；极客模式可在 Brave 开启“禁用非代理 UDP”）';
    }
  }

  let verdict: 'safe' | 'warning' | 'leaked' = 'safe';
  if (
    gatewayDNSLeaked ||
    browserDNSLeaked ||
    ov4Leaked ||
    ov6Leaked ||
    webrtcStatus === 'leaked'
  ) {
    verdict = 'leaked';
  } else if (
    gw?.verdict === 'warning' ||
    webrtcStatus === 'warn' ||
    (!gw && Boolean(suite?.gatewayError))
  ) {
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
}

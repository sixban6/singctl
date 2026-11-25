export interface HomeDomainService {
  label?: string;
  scheme?: 'http' | 'https' | 'ssh' | string;
  port?: number;
}

export interface HomeDomainDevice {
  alias: string;
  displayName?: string;
  ip: string;
  mac?: string;
  source?: 'self' | 'lan' | 'tailscale' | 'manual' | string;
  wildcard?: boolean;
  services?: HomeDomainService[];
  note?: string;
}

export interface HomeDomainReachability {
  status: 'tailscale' | 'subnet' | 'lan_only' | string;
  label: string;
  hint?: string;
  suggestedTailscaleIp?: string;
}

export interface HomeDomainDeviceView extends HomeDomainDevice {
  fqdn: string;
  online: boolean;
  reachability: HomeDomainReachability;
}

export interface HomeDomainSelfInfo {
  hostname: string;
  suggestedAlias: string;
  lanIp?: string;
  tailscaleIp?: string;
  tailscaleOnline: boolean;
  advertisedSubnets?: string[];
}

export interface HomeDomainDiscoveredLAN {
  ip: string;
  mac?: string;
  hostname?: string;
  suggestedAlias?: string;
  online: boolean;
  interface?: string;
}

export interface HomeDomainDiscoveredTailscale {
  hostname: string;
  dnsName?: string;
  suggestedAlias?: string;
  tailscaleIp: string;
  online: boolean;
  os?: string;
  subnets?: string[];
}

export interface HomeDomainResponderStatus {
  running: boolean;
  listenAddr?: string;
  suffix?: string;
  recordCount: number;
  queryCount: number;
  lastError?: string;
}

export interface HomeDomainSplitDNSGuide {
  nameserverIp?: string;
  domain: string;
  adminDnsUrl: string;
  tailscaleReady: boolean;
}

export interface HomeDomainOverviewResponse {
  enabled: boolean;
  suffix: string;
  tailscaleDns: boolean;
  followDhcp: boolean;
  self: HomeDomainSelfInfo;
  devices: HomeDomainDeviceView[];
  discoveredLan: HomeDomainDiscoveredLAN[];
  discoveredTailscale: HomeDomainDiscoveredTailscale[];
  dnsEngine: string;
  dnsEngineLabel: string;
  dnsHealthy: boolean;
  responder: HomeDomainResponderStatus;
  splitDnsGuide: HomeDomainSplitDNSGuide;
  warnings?: string[];
}

export interface HomeDomainSettingsPayload {
  enabled?: boolean;
  suffix: string;
  tailscaleDns?: boolean;
  followDhcp?: boolean;
}

export interface HomeDomainDeviceUpsertPayload extends HomeDomainDevice {
  originalAlias?: string;
}

export interface HomeDomainVerifyCheck {
  id: string;
  title: string;
  status: 'pass' | 'warn' | 'fail' | string;
  detail: string;
  rttMs?: number;
  fixHint?: string;
}

export interface HomeDomainVerifyReport {
  sampleDomain?: string;
  expectedIp?: string;
  overallOk: boolean;
  checks: HomeDomainVerifyCheck[];
}

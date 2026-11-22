export interface ClientAdGuardStatusSummary {
  supported: boolean;
  installed: boolean;
  enabled: boolean;
  running: boolean;
  dnsHealthy: boolean;
  webHealthy: boolean;
  singboxLinked: boolean;
  lowMemoryBlocked?: boolean;
  lowMemoryWarning?: string;
  version: string;
  dnsAddr: string;
  webUrl: string;
}

export interface AdGuardDomainStat {
  domain: string;
  count: number;
}

export interface AdGuardFilterItem {
  id: number;
  enabled: boolean;
  name: string;
  url: string;
  rulesCount: number;
  lastUpdated?: string;
}

export interface AdGuardPresetStatus {
  id: string;
  name: string;
  desc: string;
  url: string;
  recommended: boolean;
  installed: boolean;
  enabled: boolean;
  rulesCount: number;
}

export interface AdGuardRewriteEntry {
  domain: string;
  answer: string;
}

export type AdGuardUpstreamMode = 'parallel' | 'fastest_addr' | 'load_balance' | string;

export interface AdGuardUpstreamPreset {
  address: string;
  name: string;
  protocol: string;
  recommended: boolean;
}

export interface AdGuardUpstreamServerInfo {
  address: string;
  name: string;
  protocol: string;
}

export interface AdGuardUpstreamProbeItem {
  address: string;
  name: string;
  protocol: string;
  healthy: boolean;
  latencyMs: number;
  resolved?: string;
  fastest?: boolean;
  error?: string;
}

export interface AdGuardOverviewSnapshot {
  supported: boolean;
  installed: boolean;
  enabled: boolean;
  running: boolean;
  dnsHealthy: boolean;
  webHealthy: boolean;
  singboxLinked: boolean;
  isOpenWrt: boolean;
  lowMemoryBlocked?: boolean;
  lowMemoryWarning?: string;
  version: string;
  dnsAddr: string;
  webAddr: string;
  webUrl: string;
  username: string;
  hasPassword: boolean;
  protectionEnabled: boolean;
  protectionDisabledDurationMs?: number;
  protectionDisabledUntil?: string;
  upstreamLatencyMs?: number;
  upstreamMode: AdGuardUpstreamMode;
  upstreamModeLabel: string;
  upstreams: AdGuardUpstreamServerInfo[];
  upstreamPresets: AdGuardUpstreamPreset[];
  stats: {
    numDnsQueries: number;
    numBlockedFiltering: number;
    blockedPercent: number;
    avgProcessingMs: number;
    topBlockedDomains: AdGuardDomainStat[];
    topQueriedDomains: AdGuardDomainStat[];
  };
  filters: AdGuardFilterItem[];
  totalRulesCount: number;
  presets: AdGuardPresetStatus[];
  whitelistedDomains: string[];
  autoWhitelistedSubs: string[];
  auditManagedCount: number;
  rewrites: AdGuardRewriteEntry[];
}

export interface AdGuardProbeResult {
  healthy: boolean;
  dnsAddr: string;
  domain?: string;
  resolved?: string;
  latencyMs?: number;
  upstreamMode?: AdGuardUpstreamMode;
  upstreamModeLabel?: string;
  fastestUpstream?: string;
  fastestName?: string;
  fastestLatencyMs?: number;
  upstreams?: AdGuardUpstreamProbeItem[];
  error?: string;
}

export interface AdGuardCredentialsResponse {
  webUrl: string;
  username: string;
  password: string;
}

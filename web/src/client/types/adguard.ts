export type DNSEngineID = 'smartdns' | 'adguard';
export type DNSEnginePreference = 'auto' | DNSEngineID;

export interface DNSCapabilities {
  hasNativeWebPanel: boolean;
  hasConfigPreview: boolean;
  hasQueryStats: boolean;
  hasFilterLists: boolean;
  hasCustomFilterURL: boolean;
  hasPauseProtection: boolean;
  canClearCache: boolean;
  canUninstall: boolean;
}

export interface DNSEngineOption {
  id: DNSEngineID;
  name: string;
  tagline: string;
  installed: boolean;
  active: boolean;
  recommended: boolean;
  eligible: boolean;
  blockedReason?: string;
  diskHint: string;
  ramHint: string;
  version?: string;
}

export interface ClientDNSStatusSummary {
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
  configuredEngine?: DNSEnginePreference;
  activeEngine?: DNSEngineID;
  activeEngineLabel?: string;
  recommendedEngine?: DNSEngineID;
  fallbackDoHActive?: boolean;
}

export type ClientAdGuardStatusSummary = ClientDNSStatusSummary;

export interface AdGuardDomainStat {
  domain: string;
  count: number;
}
export type DNSDomainStat = AdGuardDomainStat;

export interface AdGuardFilterItem {
  id: number;
  enabled: boolean;
  name: string;
  url: string;
  rulesCount: number;
  lastUpdated?: string;
}
export type DNSFilterItem = AdGuardFilterItem;

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
export type DNSPresetStatus = AdGuardPresetStatus;

export interface AdGuardRewriteEntry {
  domain: string;
  answer: string;
}
export type DNSRewriteEntry = AdGuardRewriteEntry;

export type DNSUpstreamMode =
  | 'fastest_ip'
  | 'parallel'
  | 'fastest_addr'
  | 'load_balance'
  | string;
export type AdGuardUpstreamMode = DNSUpstreamMode;

export interface AdGuardUpstreamPreset {
  address: string;
  name: string;
  protocol: string;
  recommended: boolean;
}
export type DNSUpstreamPreset = AdGuardUpstreamPreset;

export interface AdGuardUpstreamServerInfo {
  address: string;
  name: string;
  protocol: string;
}
export type DNSUpstreamServerInfo = AdGuardUpstreamServerInfo;

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
export type DNSUpstreamProbeItem = AdGuardUpstreamProbeItem;

export interface DNSOverviewSnapshot {
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
  upstreamMode: DNSUpstreamMode;
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
  configuredEngine: DNSEnginePreference;
  activeEngine: DNSEngineID;
  activeEngineLabel: string;
  recommendedEngine: DNSEngineID;
  recommendedReason: string;
  fallbackDoHActive?: boolean;
  statsSource: 'adguard_api' | 'smartdns_audit';
  statsSourceLabel: string;
  capabilities: DNSCapabilities;
  engines: DNSEngineOption[];
}

export type AdGuardOverviewSnapshot = DNSOverviewSnapshot;

export interface UpstreamProbeReport {
  healthy: boolean;
  dnsAddr: string;
  domain?: string;
  resolved?: string;
  latencyMs?: number;
  upstreamMode?: DNSUpstreamMode;
  upstreamModeLabel?: string;
  fastestUpstream?: string;
  fastestName?: string;
  fastestLatencyMs?: number;
  upstreams?: AdGuardUpstreamProbeItem[];
  error?: string;
}
export type AdGuardProbeResult = UpstreamProbeReport;

export interface AdGuardCredentialsResponse {
  webUrl: string;
  username: string;
  password: string;
}
export type DNSCredentialsResponse = AdGuardCredentialsResponse;

export interface DNSConfigPreviewResponse {
  engine: string;
  title: string;
  path: string;
  content: string;
  runtimeSummary: string;
}

export interface DNSSwitchEngineRequest {
  engine: DNSEnginePreference;
  forceLowMemory?: boolean;
}

export interface DNSSwitchEngineResponse {
  ok: boolean;
  configuredEngine: string;
  activeEngine: string;
  switched: boolean;
  migratedItems?: string[];
  warnings?: string[];
  overview?: DNSOverviewSnapshot;
}

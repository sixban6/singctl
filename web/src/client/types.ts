export interface ClientHostInfo {
  hostname: string;
  os: string;
  arch: string;
  openwrt: boolean;
  lanIP: string;
}

export interface ClientSingBoxStatus {
  running: boolean;
  installed: boolean;
  version: string;
  configExists: boolean;
  configPath: string;
}

export type SbProxyMode = 'rule' | 'global' | 'direct' | string;

export interface SbProxyNodeMeta {
  name: string;
  type: string;
  delay: number;
  tested?: boolean;
  udp?: boolean;
}

export interface SbProxyGroup {
  name: string;
  type: 'Selector' | 'URLTest' | 'Fallback' | 'LoadBalance' | string;
  canSelect: boolean;
  now?: string;
  resolvedChain?: string[];
  resolvedNode?: string;
  resolvedDelay?: number;
  all: string[];
  usedBy?: string[];
  usedByCount?: number;
  failedOver?: boolean;
  failoverFrom?: string;
  failoverSince?: string;
}

export interface SbProxiesSnapshot {
  running: boolean;
  mode: SbProxyMode;
  primaryGroup?: string;
  primaryNode?: string;
  primaryDelay?: number;
  groups: SbProxyGroup[];
  nodes: Record<string, SbProxyNodeMeta>;
  error?: string;
}

export interface SbTrafficSnapshot {
  running: boolean;
  up: number;
  down: number;
  uploadTotal: number;
  downloadTotal: number;
  connections: number;
  memory: number;
  error?: string;
}

export interface ClientDaemonStatus {
  running: boolean;
  restarts: number;
  maxRestarts: number;
  totalRestarts: number;
  logPath: string;
  daemonVersion?: string;
  staleBinary?: boolean;
  versionMismatch?: boolean;
  lastHealthAt?: string;
  lastHealthOK?: boolean;
  failoverEnabled?: boolean;
  activeFailoverCount?: number;
}

export interface ClientTailscaleStatus {
  installed: boolean;
  running: boolean;
  state: string;
  mode: '' | 'router' | 'exit' | 'gateway' | 'client' | string;
  acceptRoutes?: boolean;
  subnets?: string;
  version: string;
  authKeySet: boolean;
}

export interface TailscaleConfigResponse {
  authKeySet: boolean;
  authKeyHint?: string;
  subnets: string;
  useBuild: boolean;
}

export interface ClientFirewallStatus {
  supported: boolean;
  enabled: boolean;
  kernelActive?: boolean;
  autostartEnabled?: boolean;
  drifted?: boolean;
  mode?: 'standard' | 'minimal' | string;
  nftAvailable?: boolean;
  isOpenWrt?: boolean;
}

export interface FirewallCounterStat {
  packets: number;
  bytes: number;
}

export interface FirewallSecurityStats {
  totalBlockedPackets: number;
  totalBlockedBytes: number;
  foreverBlocked: FirewallCounterStat;
  dynamicV4Blocked: FirewallCounterStat;
  dynamicV6Blocked: FirewallCounterStat;
  honeypotTcpV4: FirewallCounterStat;
  honeypotUdpV4: FirewallCounterStat;
  honeypotTcpV6: FirewallCounterStat;
  honeypotUdpV6: FirewallCounterStat;
  dynamicV4Count: number;
  dynamicV6Count: number;
  foreverCount: number;
  protectedPortCount: number;
  whitelistCount: number;
}

export interface FirewallPreflightInfo {
  callerIp?: string;
  detectedSSHPorts: number[];
  protectedTunnels: string[];
  protectedLanRanges: string[];
  exemptServicePorts: number[];
  coexistingTables?: string[];
}

export interface FirewallEffectiveConfig {
  mode: 'standard' | 'minimal' | string;
  banTimeoutDays: number;
  pingLimitPerSec: number;
  protectedPorts: number[];
  whitelist: string[];
  extraForeverBan: string[];
}

export interface FirewallBanItem {
  target: string;
  scope: 'dynamic_v4' | 'dynamic_v6' | 'forever' | string;
  expiresSec?: number;
  builtin?: boolean;
}

export interface FirewallWhitelistView {
  builtin: string[];
  custom: string[];
  liveExtra?: string[];
}

export interface FirewallPortCatalogItem {
  port: number;
  label: string;
}

export interface FirewallOverviewResponse {
  status: ClientFirewallStatus;
  stats: FirewallSecurityStats;
  preflight: FirewallPreflightInfo;
  config: FirewallEffectiveConfig;
  bans: {
    items: FirewallBanItem[];
    total: number;
    page: number;
    pageSize: number;
  };
  whitelist: FirewallWhitelistView;
  protectedPortsLive?: number[];
  portCatalog: FirewallPortCatalogItem[];
  compactRuleText?: string;
}

export interface FirewallLogEvent {
  time: string;
  category: string;
  prefix: string;
  iface?: string;
  srcIp: string;
  proto?: string;
  dstPort?: number;
}

export interface FirewallApplyPayload {
  mode?: 'standard' | 'minimal' | string;
  banTimeoutDays?: number;
  pingLimitPerSec?: number;
  protectedPorts?: number[];
  resetDefaults?: boolean;
}

export type GatewayRoleMode = 'main' | 'side';
export type GatewayIPv6Mode = 'off' | 'cn_only' | 'full';

export interface IPv6StatusInfo {
  supported: boolean;
  isOpenWrt: boolean;
  kernelEnabled: boolean;
  forwardingEnabled: boolean;
  wanHasGua: boolean;
  wanHasDefaultV6: boolean;
  pdPrefix?: string;
  lanGua?: string;
  lanPrefixes?: string[];
  lanRaMode?: string;
  lanDhcpv6Mode?: string;
  dnsmasqFilterAaaa?: string;
  dnsmasqForwardMax?: string;
  raDnsAnnounce: boolean;
  autoConfigurable: boolean;
  warnings?: string[];
}

export interface ClientGatewayTopology {
  lanIP: string;
  lanCIDR: string;
  hostPrefix?: string;
  lanIface: string;
  currentGatewayIP: string;
  suggestedMainRouterIP: string;
  selfLooped: boolean;
}

export interface ClientGatewayStatusSummary {
  supported: boolean;
  mode: GatewayRoleMode;
  mainRouterIP: string;
  ipv6Mode?: GatewayIPv6Mode;
}

export interface ClientGatewayConfigResponse {
  supported: boolean;
  mode: GatewayRoleMode;
  mainRouterIP: string;
  lanIface?: string;
  ipv6Mode?: GatewayIPv6Mode;
  ipv6Status?: IPv6StatusInfo;
  ipv6Actions?: string[];
  topology: ClientGatewayTopology;
}

export interface DNSLeakCheckItem {
  id: string;
  title: string;
  status: 'pass' | 'warn' | 'fail' | string;
  latencyMs?: number;
  summary: string;
  detail?: string;
}

export interface DNSResolverProfile {
  ip?: string;
  country?: string;
  countryCode?: string;
  isp?: string;
  ecs?: string;
  ecsCountryCode?: string;
}

export interface EgressEndpoint {
  ip?: string;
  country?: string;
  countryCode?: string;
  region?: string;
  city?: string;
  isp?: string;
  asn?: string;
  latencyMs?: number;
  reachable: boolean;
  error?: string;
}

export interface EgressMatrix {
  domesticIpv4?: EgressEndpoint;
  domesticIpv6?: EgressEndpoint;
  overseasIpv4?: EgressEndpoint;
  overseasIpv6?: EgressEndpoint;
}

export interface DNSServerObservation {
  ip: string;
  country?: string;
  countryCode?: string;
  isp?: string;
  ecs?: string;
  ecsCountryCode?: string;
  hits: number;
  source: 'gateway' | 'port53_hijack' | string;
  leaked: boolean;
  leakReason?: string;
}

export interface DNSLeakReport {
  verdict: 'safe' | 'warning' | 'leaked' | string;
  ipv6Mode: GatewayIPv6Mode | string;
  checkedAt: string;
  durationMs: number;
  homePublicIp?: string;
  homeIsp?: string;
  overseasResolver?: DNSResolverProfile | null;
  egress?: EgressMatrix | null;
  dnsServers?: DNSServerObservation[];
  gatewayRounds?: number;
  checks: DNSLeakCheckItem[];
}

export interface BrowserDoHEDNSSample {
  dnsIp: string;
  country?: string;
  countryCode?: string;
  isp?: string;
}

export interface BrowserDoHCheckRequest {
  phase?: 'begin' | 'finish';
  probeId?: string;
  browserSamples?: BrowserDoHEDNSSample[];
  browserProbeAttempted?: number;
  browserProbeFailed?: number;
}

export interface BrowserDoHMatchedEndpoint {
  provider: string;
  host?: string;
  destIp?: string;
  destPort?: string;
  sourceIp?: string;
  network?: string;
  rule?: string;
}

export interface BrowserDoHCheckResponse {
  status: 'clean' | 'detected' | 'suspected' | 'skipped_remote' | 'unavailable' | 'pending' | string;
  confidence: 'high' | 'medium' | 'none' | string;
  probeId?: string;
  idleLeftoverCount?: number;
  clientIp?: string;
  isLanClient: boolean;
  viaTailscale: boolean;
  detectedProvider?: string;
  matchedEndpoints?: BrowserDoHMatchedEndpoint[];
  gatewayResolver?: DNSResolverProfile | null;
  browserResolvers?: BrowserDoHEDNSSample[];
  signals?: string[];
  summary: string;
  recommendation?: string;
  checkedAt: string;
}

export interface ClientAdGuardStatusSummary {
  supported: boolean;
  installed: boolean;
  enabled: boolean;
  running: boolean;
  dnsHealthy: boolean;
  webHealthy: boolean;
  singboxLinked: boolean;
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

export interface ClientConfigSubSummary {
  name: string;
  urlHint: string;
}

export interface ClientStatusResponse {
  singctlVersion: string;
  authEnabled: boolean;
  sessionToken?: string;
  host: ClientHostInfo;
  singbox: ClientSingBoxStatus;
  daemon: ClientDaemonStatus;
  adguard?: ClientAdGuardStatusSummary;
  tailscale: ClientTailscaleStatus;
  firewall: ClientFirewallStatus;
  gateway?: ClientGatewayStatusSummary;
  config: {
    path: string;
    exists: boolean;
    subs: ClientConfigSubSummary[];
    error?: string;
  };
}

export interface ClientHealthResponse {
  healthy: boolean;
  dnsOK: boolean;
  failedReason?: string;
  details: string;
  checkTime: string;
}

export interface ClientConfigSubDTO {
  name: string;
  url: string;
  skip_tls_verify: boolean;
  remove_emoji: boolean;
  include?: string;
  exclude?: string;
  rename?: unknown[];
}

export interface ClientConfigDTO {
  subs: ClientConfigSubDTO[];
  github: { mirror_url: string };
  hy2: { up: number; down: number };
  tailscale: { auth_key: string; use_build: boolean; subnets: string };
  server: { sb_domain: string; cf_dns_key: string; sni: string };
}

export interface SbConfigResponse {
  path: string;
  exists: boolean;
  content: string;
  backups: string[];
  checkable: boolean;
  preserveManualConfig?: boolean;
}

export interface CacheEntry {
  tag: string;
  format: string;
  updatedAt: string;
  fileOK: boolean;
  inSnapshot: boolean;
  state: 'ok' | 'snapshot' | 'missing' | string;
}

export interface CacheResponse {
  cacheDir: string;
  snapshotCount: number;
  snapshotTime: string;
  entries: CacheEntry[];
}

export interface ClientLogsResponse {
  name: string;
  path: string;
  tail: number;
  content: string;
}

export interface WatchdogActiveFailover {
  group: string;
  origin: string;
  current: string;
  lastDelayMs?: number;
  since?: string;
}

export interface WatchdogEventItem {
  time: string;
  action: string;
  summary: string;
  healthy?: boolean;
}

export interface WatchdogFailoverConfig {
  enabled: boolean;
  groups: string[];
  is_default_groups: boolean;
  default_groups: string[];
  patrol_interval: number;
  probe_timeout_ms: number;
  confirm_retries: number;
  auto_failback: boolean;
  failback_cooldown: number;
  max_failback_delay_ms: number;
  probe_urls: string[];
  is_default_probe_urls: boolean;
}

export interface WatchdogConfigDTO {
  interval: number;
  confirm_wait: number;
  max_restarts: number;
  sub_sync_enabled: boolean;
  sub_sync_interval: number;
  failover: WatchdogFailoverConfig;
}

export interface WatchdogSelectorGroup {
  name: string;
  now: string;
  failedOver?: boolean;
}

export interface WatchdogReport {
  daemon: {
    running: boolean;
    pid: number;
    daemonVersion: string;
    singctlVersion: string;
    staleBinary: boolean;
    versionMismatch: boolean;
    startedAt: string;
    restarts: number;
    maxRestarts: number;
    totalRestarts: number;
    logPath: string;
    logSizeBytes: number;
    logMaxBytes: number;
  };
  config: WatchdogConfigDTO;
  runtime: {
    lastHealthAt?: string;
    lastHealthOK?: boolean;
    lastHealthDetail?: string;
    lastHealthDelayMs?: number;
    lastSubSyncAt?: string;
    lastRuleSetAt?: string;
    activeFailovers?: WatchdogActiveFailover[];
    recentEvents?: WatchdogEventItem[];
  };
  selectorGroups: WatchdogSelectorGroup[];
  adguard: {
    supported: boolean;
    enabled: boolean;
    installed: boolean;
    healthy: boolean;
  };
  ok?: boolean;
  daemonReloaded?: boolean;
}

export interface AuditAIReview {
  verdict: 'safe_to_block' | 'caution' | 'do_not_block' | string;
  verdictText: string;
  category: string;
  impact: string;
  source?: string;
}

export interface AuditDeviceSummary {
  deviceIp: string;
  deviceName?: string;
  deviceMac?: string;
  deviceRole?: string;
  flowCount: number;
  activeConns?: number;
  uploadBytes: number;
  downloadBytes: number;
  uploadRatio: number;
  suspiciousCount: number;
  highRiskCount: number;
  maxRiskScore: number;
  maxSecurityScore: number;
  maxPrivacyScore: number;
}

export interface AuditDirectIPSubnetCluster {
  cidr: string;
  uniqueIps: number;
  flowCount: number;
  activeConns: number;
  uploadBytes: number;
  downloadBytes: number;
  sampleIps?: string[];
  suspicious: boolean;
}

export interface AuditPCDNSwarmSummary {
  uniqueSlash16: number;
  uniqueIps: number;
  flowCount: number;
  uploadBytes: number;
  downloadBytes: number;
  uploadRatio: number;
  suspicious: boolean;
}

export interface AuditFlowRecord {
  key?: string;
  id?: string;
  deviceIp: string;
  deviceName?: string;
  deviceMac?: string;
  deviceRole?: string;
  target: string;
  rawHost?: string;
  destIp?: string;
  destPort?: number;
  isDirectIp?: boolean;
  subnetCluster?: AuditDirectIPSubnetCluster | null;
  pcdnKind?: 'upload' | 'download' | 'swarm' | string;
  pcdnSwarm?: AuditPCDNSwarmSummary | null;
  network: string;
  outbound?: string;
  chains?: string[];
  rule?: string;
  uploadBytes: number;
  downloadBytes: number;
  uploadRatio: number;
  avgUploadBps?: number;
  throttledRateKbps?: number;
  connCount?: number;
  activeConns?: number;
  activeConnIds?: string[];
  firstSeen?: string;
  lastSeen?: string;
  activeSpanSec?: number;
  nightHits?: number;
  intervalCv?: number;
  domainEntropy?: number;
  riskScore: number;
  securityScore: number;
  privacyScore: number;
  dominantAxis?: 'security' | 'privacy' | 'both' | string;
  threat: 'high_risk' | 'suspicious' | 'notice' | 'normal' | string;
  threatLabel?: string;
  state?: 'observed' | 'blocked' | 'whitelisted' | string;
  appName?: string;
  reasons?: string[];
  nonlinearFactors?: Record<string, number>;
  aiReview?: AuditAIReview | null;
}

export interface AuditBlockRule {
  target: string;
  source_ip?: string;
  reason?: string;
  ruleset_url?: string;
  rule_count?: number;
  preview?: string;
}

export interface AuditThrottleRule {
  target: string;
  port?: number;
  rateKbps: number;
  comment?: string;
  createdAt?: string;
}

export interface AuditReport {
  totalFlows: number;
  suspiciousFlows: number;
  blockedCount: number;
  whitelistCount: number;
  whitelist?: string[];
  throttles?: AuditThrottleRule[];
  pcdnBlockEnabled?: boolean;
  pcdnRuleCount?: number;
  pcdnDetectedFlows?: number;
  devices: AuditDeviceSummary[];
  flows: AuditFlowRecord[];
  blockRules: AuditBlockRule[];
  message?: string;
}

export interface AuditAIConfig {
  baseUrl: string;
  apiKey: string;
  model: string;
  suggestedLanUrl?: string;
}

export interface AuditAIModelsResponse {
  ok: boolean;
  models: string[];
  resolvedUrl?: string;
  error?: string;
}

export interface ClientRoutingGroupInfo {
  tag: string;
  type: string;
  default?: string;
  count: number;
}

export interface TrafficCategoryInfo {
  id: string;
  label: string;
  description: string;
  defaultDest: string;
}

export interface ClientRoutingPresetState {
  id: string;
  name: string;
  category: string;
  categoryLabel: string;
  description: string;
  domainsSummary: string;
  defaultOn: boolean;
  defaultOutbound: string;
  enabled: boolean;
  selectedGroup: string;
  effectiveDest: string;
  customized: boolean;
}

export interface ClientRoutingReport {
  groups: ClientRoutingGroupInfo[];
  directTag: string;
  categories: TrafficCategoryInfo[];
  items: ClientRoutingPresetState[];
  enabledCount: number;
  customCount: number;
  totalCount: number;
  hasConfig: boolean;
  lastError?: string;
}

export interface GroupMacroInfo {
  id: string;
  label: string;
  description: string;
  pattern: string;
}

export interface GroupTemplateSnippet {
  id: string;
  name: string;
  description: string;
  content: string;
}

export interface LeafOutboundInfo {
  tag: string;
  type: string;
  subs?: string[];
}

export interface CompiledGroupPreview {
  name: string;
  type: 'selector' | 'urltest' | string;
  builtin: boolean;
  customized: boolean;
  fallbackUsed?: boolean;
  fallbackTag?: string;
  default?: string;
  attachedTo?: string[];
  failover?: boolean;
  members: string[];
  leafMatchCount: number;
  totalCount: number;
}

export interface GroupsPreviewReport {
  mode: 'merge' | 'replace' | string;
  defaultOutbound?: string;
  dnsDetour?: string;
  totalLeafNodes: number;
  leafNodes: LeafOutboundInfo[];
  subNames?: string[];
  groups: CompiledGroupPreview[];
  warnings?: string[];
}

export interface ClientGroupsGetResponse {
  path: string;
  exists: boolean;
  content: string;
  hasLiveConfig: boolean;
  macros: GroupMacroInfo[];
  templates: GroupTemplateSnippet[];
  preview?: GroupsPreviewReport;
  parseError?: string;
}

export interface ClientGroupsPreviewResponse {
  ok: boolean;
  hasLiveConfig?: boolean;
  preview?: GroupsPreviewReport;
  error?: string;
}

export interface ClientGroupsPutResponse {
  ok: boolean;
  exists: boolean;
  applied: boolean;
  content: string;
  message: string;
  preview?: GroupsPreviewReport;
  routingReport?: ClientRoutingReport;
}

export interface ClientBackupSummary {
  hasSingctlCfg: boolean;
  hasGroups: boolean;
  hasAdGuard: boolean;
  hasSingBox: boolean;
}

export interface ClientBackupExportResponse {
  ok: boolean;
  message: string;
  filename: string;
  data: string;
  summary: ClientBackupSummary;
}

export interface ClientBackupRestoreResponse {
  ok: boolean;
  message: string;
  restoredItems: string[];
}

export interface ActionStreamEvent {
  t: 'start' | 'out' | 'exit';
  title?: string;
  cmd?: string;
  line?: string;
  code?: number;
  restarting?: boolean;
  tailscaleSwapping?: boolean;
}

export type TailscaleAccessMode = 'outbound_only' | 'bidirectional_timed' | 'bidirectional';

export interface TailscaleP2PPeerConfig {
  id?: string;
  name: string;
  tailscale_ip?: string;
  jit_enabled: boolean;
  access_mode?: TailscaleAccessMode | string;
  bidirectional_until?: string;
  allowed_lan_targets?: string[];
}

export interface TailscaleP2PAssistConfig {
  enabled: boolean;
  jit_window_sec?: number;
  cooldown_sec?: number;
  payload_filter?: boolean;
  sandbox_ujail?: boolean;
  listen_port?: number;
  peers?: TailscaleP2PPeerConfig[];
}

export interface TailscaleP2PPeerView {
  id: string;
  name: string;
  shortName: string;
  dnsName?: string;
  hostName?: string;
  tailscaleIPs?: string[];
  primaryRoutes?: string[];
  online: boolean;
  active: boolean;
  direct: boolean;
  curAddr?: string;
  relay?: string;
  candidatePublicCount: number;
  configured: boolean;
  jitEnabled: boolean;
  accessMode: TailscaleAccessMode | string;
  effectiveAccessMode: TailscaleAccessMode | string;
  bidirectionalUntil?: string;
  bidirectionalRemainingSec: number;
  allowedLanTargets?: string[];
  pinholeActive: boolean;
  cooldownRemainingSec: number;
  lastUpgradeAt?: string;
  lastResult?: string;
}

export interface TailscaleP2PRuntimeSnapshot {
  enabled: boolean;
  applyMode?: string;
  openPinholes: number;
  openPinholeIPs?: string[];
  updatedAt?: string;
  lastError?: string;
}

export interface TailscaleP2PReport {
  supported: boolean;
  isOpenWrt: boolean;
  fw4Available: boolean;
  ujailAvailable: boolean;
  daemonRunning: boolean;
  tailscaleRunning: boolean;
  defaultLanCidr?: string;
  openPinholes: number;
  openPinholeIPs?: string[];
  config: TailscaleP2PAssistConfig;
  runtime: TailscaleP2PRuntimeSnapshot;
  peers?: TailscaleP2PPeerView[];
  ok?: boolean;
  appliedLive?: boolean;
  applyMode?: string;
  message?: string;
}

export interface TailscaleP2PPokeResult {
  ok: boolean;
  direct: boolean;
  curAddr?: string;
  relay?: string;
  latencyMs: number;
  pinholeMs: number;
  candidateCount: number;
  message: string;
  report?: TailscaleP2PReport;
}

export type TailscaleUpgradePhase =
  | 'idle'
  | 'staging'
  | 'swapping'
  | 'verifying'
  | 'succeeded'
  | 'rolled_back'
  | 'failed'
  | string;

export interface TailscaleUpgradeState {
  phase: TailscaleUpgradePhase;
  fromVersion?: string;
  toVersion?: string;
  arch?: string;
  combined: boolean;
  force: boolean;
  startedAt?: string;
  updatedAt?: string;
  finishedAt?: string;
  flashFreeBeforeBytes?: number;
  flashFreeAfterBytes?: number;
  message?: string;
  error?: string;
  rolledBack: boolean;
  logTail?: string;
  swapperPid?: number;
}

export interface TailscaleUpgradePreflight {
  supported: boolean;
  unsupportedReason?: string;
  arch?: string;
  isOpenWrt: boolean;
  initSystem?: string;
  currentVersion?: string;
  latestVersion?: string;
  upToDate: boolean;
  assetName?: string;
  assetSizeBytes?: number;
  estimatedInstallBytes?: number;
  requiredFreeBytes?: number;
  combinedMinimal: boolean;
  hasOfficialDigest: boolean;
  flashFreeBytes: number;
  memAvailableBytes: number;
  swapFreeBytes: number;
  tailscaleRunning: boolean;
  backendState?: string;
  canProceed: boolean;
  canForceProceed: boolean;
  blockedReasons?: string[];
  warnings?: string[];
  viaTailscale: boolean;
  activeSwap?: TailscaleUpgradeState;
}

export interface TailscaleUpgradeStatusResponse {
  state: TailscaleUpgradeState;
  tailscale?: ClientStatusResponse['tailscale'];
}

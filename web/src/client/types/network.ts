export type GatewayRoleMode = 'main' | 'side';
export type GatewayWorkMode = 'auto' | 'basic' | 'audit' | 'proxy';
export type EffectiveGatewayWorkMode = 'basic' | 'audit' | 'proxy';
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
  workMode?: GatewayWorkMode;
  effectiveWorkMode?: EffectiveGatewayWorkMode;
  hasSubs?: boolean;
  mainRouterIP: string;
  ipv6Mode?: GatewayIPv6Mode;
}

export interface ClientGatewayConfigResponse {
  supported: boolean;
  mode: GatewayRoleMode;
  workMode?: GatewayWorkMode;
  effectiveWorkMode?: EffectiveGatewayWorkMode;
  hasSubs?: boolean;
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
  tailscale?: ClientTailscaleStatus;
}

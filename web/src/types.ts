export interface SystemMetrics {
  bbr: boolean;
  uptime?: string;
  memTotalMB?: number;
  memUsedMB?: number;
  memUsagePercent?: string;
  loadAvg?: string;
  load1?: string;
  load5?: string;
  load15?: string;
  diskUsed?: string;
  diskTotal?: string;
  diskPercent?: string;
}

export interface ServiceDetail {
  running: boolean;
  version?: string;
  pid?: string;
  uptime?: string;
  id?: string;
  engine?: string;
  socksPort?: number;
}

export interface ServerStatusResponse {
  version: string;
  authEnabled: boolean;
  system: SystemMetrics;
  admin: {
    username: string;
    path: string;
    httpsUrl: string;
    port: number;
  };
  initialCredentials?: {
    pending: boolean;
    username: string;
    password: string;
  };
  services: {
    caddy: ServiceDetail;
    singbox: ServiceDetail;
    substore: ServiceDetail;
    warp: ServiceDetail;
  };
  config: {
    nodeDomain: string;
    substoreDomain: string;
    substoreAdminUrl?: string;
    nodeTag: string;
    sni: string;
    hasCFToken: boolean;
  };
  auditLogs?: AuditLogItem[];
}

export interface AuditLogItem {
  time: string;
  action: string;
  ip: string;
  geo?: string;
  isp?: string;
  country?: string;
  countryCode?: string;
  flag?: string;
}

export interface SubscriptionSourceItem {
  name: string;
  displayName: string;
  source: 'local' | 'remote';
  url: string;
  content: string;
  remark: string;
  enabled: boolean;
  autoManaged: boolean;
  nodeCount: number;
}

export interface SourceUpsertInput {
  name?: string;
  displayName: string;
  source: 'local' | 'remote';
  url?: string;
  content?: string;
  remark?: string;
  enabled?: boolean;
}

export interface SubscriptionPreviewResponse {
  target: string;
  filename: string;
  contentType: string;
  nodeCount: number;
  content: string;
}

export interface SubscriptionsResponse {
  engine?: string;
  substoreKey?: string;
  substoreAdminUrl: string;
  substoreVercelUrl: string;
  subscriptionUrl: string;
  sources?: SubscriptionSourceItem[];
  importLinks: {
    shadowrocket: string;
    clash: string;
    singbox: string;
    surge: string;
    loon: string;
  };
  nodes: {
    hy2: {
      link: string;
      domain: string;
      port: number;
    };
    vless: {
      link: string;
      sni: string;
      port: number;
    };
  };
}

export interface WarpDiagnoseResponse {
  connected: boolean;
  ip?: string;
  loc?: string;
  warp?: string;
  latencyMs?: number;
  error?: string;
}

export interface ReturnHopResult {
  carrier: string | number;
  name: string;
  target_ip?: string;
  targetIp?: string;
  city: string;
  avg_rtt?: number;
  avgRtt?: number;
  loss_rate?: number;
  lossRate?: number;
  route_name?: string;
  routeName?: string;
  route_type?: string;
  routeType?: string;
  key_hops?: string[];
  keyHops?: string[];
}

export interface ReturnSummary {
  scan_time?: string;
  scanTime?: string;
  server_ip?: string;
  serverIp?: string;
  results: ReturnHopResult[];
  best_for_isp?: any[];
  bestForIsp?: any[];
  summary: string;
}

export interface BannedIP {
  ip: string;
  remainingSeconds: number;
  remainingMinutes: number;
  geo?: string;
  isp?: string;
  country?: string;
  countryCode?: string;
  flag?: string;
}

export interface DoctorCheckItem {
  name: string;
  category: string;
  status: 'ok' | 'warn' | 'fail';
  summary: string;
  detail?: string;
}

export interface DoctorReport {
  score: number;
  checkedAt: string;
  items: DoctorCheckItem[];
  summary: string;
}

export interface ServiceUnlockStatus {
  status: 'unlocked' | 'partially_unlocked' | 'locked' | 'warn' | 'error';
  region?: string;
  details?: string;
}

export interface ExitProfile {
  name: string;
  available: boolean;
  exitIP?: string;
  exitLoc?: string;
  openai: ServiceUnlockStatus;
  netflix: ServiceUnlockStatus;
  youtube: ServiceUnlockStatus;
  disney: ServiceUnlockStatus;
  google: ServiceUnlockStatus;
  errorReason?: string;
}

export interface MediaUnlockReport {
  direct: ExitProfile;
  warp: ExitProfile;
  testedAt: string;
}

export interface CheckUpdateResponse {
  component: string;
  displayName: string;
  currentVersion: string;
  latestVersion: string;
  hasUpdate: boolean;
  message: string;
}

export interface TelemetryRatePoint {
  time: string;
  upBps: number;
  downBps: number;
}

export interface TelemetryProtocolBreakdown {
  hy2Connections: number;
  hy2Bytes: number;
  realityConnections: number;
  realityBytes: number;
  otherConnections: number;
  otherBytes: number;
}

export interface TelemetryOutboundBreakdown {
  directConnections: number;
  directBytes: number;
  warpConnections: number;
  warpBytes: number;
  otherConnections: number;
  otherBytes: number;
}

export interface TelemetryDomainStat {
  domain: string;
  protocol: string;
  outbound: string;
  rule?: string;
  connections: number;
  bytes: number;
}

export interface TelemetrySnapshot {
  enabled: boolean;
  reachable: boolean;
  controllerAddr?: string;
  timestamp: string;
  upBps: number;
  downBps: number;
  uploadTotal: number;
  downloadTotal: number;
  memoryBytes?: number;
  activeConnections: number;
  protocols: TelemetryProtocolBreakdown;
  outbounds: TelemetryOutboundBreakdown;
  topDomains: TelemetryDomainStat[];
  history: TelemetryRatePoint[];
  message?: string;
}

export interface SubscriptionAccessLogItem {
  timestamp: string;
  ip: string;
  countryCode?: string;
  geo?: string;
  flag?: string;
  clientApp: string;
  userAgent?: string;
  target: string;
  collection?: string;
  nodeCount: number;
  status: 'ok' | 'denied';
}

export type FleetAuthType = 'inline_key' | 'key_file' | 'ssh_alias' | 'password';

export interface FleetNode {
  id: string;
  name: string;
  host: string;
  domain?: string;
  dnsAutoManaged?: boolean;
  port: number;
  user: string;
  authType: FleetAuthType;
  sshAlias?: string;
  keyPath?: string;
  hasCredential: boolean;
  enabled: boolean;
  addedAt?: string;
  lastSyncAt?: string;
  lastProbeAt?: string;
  probeStatus?: string;
  certDaysLeft?: number;
  online: boolean;
  lastError?: string;
  latencyMs: number;
  singctlVersion?: string;
  doctorScore: number;
  doctorSummary?: string;
  cpuLoad?: string;
  memPercent: number;
  bbrEnabled: boolean;
  syncedNodes: number;
  protocols?: string[];
}

export interface FleetSummary {
  total: number;
  online: number;
  totalSyncedEndpoints: number;
  avgDoctorScore: number;
  lastProbeAt?: string;
  patrolIntervalSec?: number;
}

export interface FleetListResponse {
  nodes: FleetNode[];
  summary: FleetSummary;
}

export interface FleetUpsertInput {
  id: string;
  name: string;
  host: string;
  port?: number;
  user?: string;
  authType: FleetAuthType;
  sshAlias?: string;
  keyPath?: string;
  privateKey?: string;
  password?: string;
  enabled?: boolean;
  autoSync?: boolean;
}

export interface FleetBootstrapInput {
  id?: string;
  name?: string;
  host: string;
  port?: number;
  user?: string;
  authType?: FleetAuthType;
  sshAlias?: string;
  keyPath?: string;
  privateKey?: string;
  password?: string;
  enabled?: boolean;
  autoSync?: boolean;
  nodeDomain?: string;
  substoreDomain?: string;
  cfDnsKey?: string;
  nodeTag?: string;
  sni?: string;
  skipDns?: boolean;
  hardenSsh?: boolean;
  targetSshPort?: number;
  extraAuthorizedKeys?: string;
}

export interface FleetBootstrapDefaults {
  hasMasterCfToken: boolean;
  masterNodeDomain?: string;
  suggestedRootZone?: string;
  defaultSni: string;
  defaultTargetSshPort: number;
  hy2Up: number;
  hy2Down: number;
}

export interface FleetBootstrapPlan {
  id: string;
  name: string;
  host: string;
  domain: string;
  domainAutoDerive: boolean;
  inheritCfToken: boolean;
  masterDomain?: string;
  sni: string;
  hy2Up: number;
  hy2Down: number;
  nodeTag: string;
  targetSshPort: number;
}

export interface FleetActionResult {
  id: string;
  name: string;
  success: boolean;
  latencyMs: number;
  singctlVersion?: string;
  doctorScore?: number;
  syncedNodes?: number;
  message: string;
  output?: string;
  protocols?: string[];
}

export interface HealComponentCheck {
  name: string;
  displayName: string;
  currentVersion: string;
  latestVersion: string;
  installed: boolean;
  hasUpdate: boolean;
}

export interface HealLayerAction {
  layer: string;
  target: string;
  success: boolean;
  updated: boolean;
  rolledBack?: boolean;
  message: string;
}

export interface HealHistoryItem {
  timestamp: string;
  trigger: string;
  success: boolean;
  durationMs: number;
  summary: string;
  actions?: HealLayerAction[];
  rebootRequired: boolean;
}

export interface HealPolicy {
  autoHealEnabled: boolean;
  schedule: string;
  autoReboot: boolean;
}

export interface HealStatusReport {
  checkedAt: string;
  posture: 'healthy' | 'updates_pending' | 'reboot_required' | string;
  postureLabel: string;
  core: {
    components: HealComponentCheck[];
    pendingCount: number;
    healthy: boolean;
  };
  os: {
    distro: string;
    packageManager: string;
    openwrtProtected?: boolean;
    securityUpdates: string[];
    securityCount: number;
    staleServices: string[];
    healthy: boolean;
  };
  kernel: {
    runningKernel: string;
    installedKernel?: string;
    rebootRequired: boolean;
    rebootReason?: string;
    affectedPkgs?: string[];
    healthy: boolean;
  };
  timer: {
    supported: boolean;
    enabled: boolean;
    active: boolean;
    schedule: string;
    nextRun?: string;
    lastRun?: string;
  };
  policy: HealPolicy;
  history: HealHistoryItem[];
}

export interface FleetHealNodeResult {
  id: string;
  name: string;
  success: boolean;
  posture: string;
  summary: string;
  rebootRequired: boolean;
  rebooted?: boolean;
  doctorScoreAfterReboot?: number;
  circuitBroken?: boolean;
  skippedByCircuitBreaker?: boolean;
  actions?: HealLayerAction[];
}

export interface FleetHealReport {
  checkedAt: string;
  totalNodes: number;
  healthyNodes: number;
  rebootedNodes: number;
  circuitBreakerHit: boolean;
  circuitBreakerNote?: string;
  results: FleetHealNodeResult[];
}

export interface HealRunResponse {
  message: string;
  scope: 'local' | 'fleet';
  execution: HealHistoryItem;
  status: HealStatusReport;
  fleetReport?: FleetHealReport;
}

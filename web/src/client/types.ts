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
  panelURL: string;
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
  version: string;
  authKeySet: boolean;
}

export interface ClientFirewallStatus {
  supported: boolean;
  enabled: boolean;
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
  tailscale: ClientTailscaleStatus;
  firewall: ClientFirewallStatus;
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
  uploadBytes: number;
  downloadBytes: number;
  uploadRatio: number;
  suspiciousCount: number;
  highRiskCount: number;
  maxRiskScore: number;
  maxSecurityScore: number;
  maxPrivacyScore: number;
}

export interface AuditFlowRecord {
  key?: string;
  id?: string;
  deviceIp: string;
  deviceName?: string;
  target: string;
  destPort?: number;
  isDirectIp?: boolean;
  network: string;
  uploadBytes: number;
  downloadBytes: number;
  uploadRatio: number;
  riskScore: number;
  securityScore: number;
  privacyScore: number;
  dominantAxis?: 'security' | 'privacy' | 'both' | string;
  threat: 'high_risk' | 'suspicious' | 'notice' | 'normal' | string;
  threatLabel?: string;
  state?: 'observed' | 'blocked' | 'whitelisted' | string;
  appName?: string;
  reasons?: string[];
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

export interface AuditReport {
  totalFlows: number;
  suspiciousFlows: number;
  blockedCount: number;
  whitelistCount: number;
  whitelist?: string[];
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

export interface ActionStreamEvent {
  t: 'start' | 'out' | 'exit';
  title?: string;
  cmd?: string;
  line?: string;
  code?: number;
  restarting?: boolean;
}

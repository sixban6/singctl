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
  allowOverseas?: boolean;
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

export interface AuditActiveConnDetail {
  id: string;
  sourcePort?: string;
  destIp?: string;
  destPort?: string;
  inboundType?: string;
  rule?: string;
  chains?: string[];
  upload: number;
  download: number;
  uploadBps?: number;
  downloadBps?: number;
  start?: string;
  durationSec?: number;
}

export interface AuditBlockBatchItem {
  target: string;
  sourceIp?: string;
  reason?: string;
}

export interface AuditBlockBatchResult {
  ok: boolean;
  added: number;
  skipped: number;
  failed: number;
  configSaved?: boolean;
  singboxSynced?: boolean;
  dnsBlocked?: boolean;
  killedConnections: number;
  applied?: AuditBlockBatchItem[];
  errors?: string[];
  message: string;
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
  currentUploadBps?: number;
  currentDownloadBps?: number;
  throttledRateKbps?: number;
  connCount?: number;
  activeConns?: number;
  activeConnIds?: string[];
  activeConnDetails?: AuditActiveConnDetail[];
  firstSeen?: string;
  lastSeen?: string;
  lastSeenUnix?: number;
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
  directDevices?: string[];
  message?: string;
}

export interface AuditDeviceAccessResult {
  ok: boolean;
  deviceIp: string;
  allowOverseas: boolean;
  directDevices: string[];
  configSaved?: boolean;
  singboxSynced?: boolean;
  killedConnections: number;
  message: string;
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

export type AuditAppCategory =
  | 'video'
  | 'social'
  | 'ai_dev'
  | 'shopping'
  | 'gaming_music'
  | 'system'
  | 'other';

export type AuditDeviceProfileRange = '24h' | '7d';

export interface AuditDeviceAppStat {
  appName: string;
  category: AuditAppCategory | string;
  categoryLabel: string;
  isInfra: boolean;
  foregroundMinutes: number;
  backgroundMinutes: number;
  sessions: number;
  avgSessionMin: number;
  longestSessionMin: number;
  uploadBytes: number;
  downloadBytes: number;
  peakPeriod: string;
  lastSeen?: string;
  sampleTargets?: string[];
}

export interface AuditDeviceCategoryStat {
  category: AuditAppCategory | string;
  label: string;
  minutes: number;
  sharePct: number;
  bytes: number;
}

export interface AuditDeviceHourStat {
  hour: number;
  foregroundMinutes: number;
  bytes: number;
}

export interface AuditDeviceDayStat {
  date: string;
  foregroundMinutes: number;
  uploadBytes: number;
  downloadBytes: number;
  topApp?: string;
  topAppMinutes?: number;
}

export interface AuditDevicePersonaTag {
  id: string;
  label: string;
  tone: 'accent' | 'ok' | 'warn' | 'neutral' | string;
  detail: string;
}

export interface AuditDeviceProfileStorage {
  retentionDays: number;
  historyDays: number;
  historyBytes: number;
  maxHistoryBytes: number;
  autoCleanup: boolean;
}

export interface AuditDeviceProfile {
  deviceIp: string;
  deviceName: string;
  deviceMac?: string;
  deviceRole: string;
  range: AuditDeviceProfileRange;
  generatedAt: string;
  totalForegroundMinutes: number;
  totalBackgroundMinutes: number;
  activeAppCount: number;
  uploadBytes: number;
  downloadBytes: number;
  proxySharePct: number;
  isNatSubRouter: boolean;
  peakHourLabel: string;
  personaTags: AuditDevicePersonaTag[];
  categories: AuditDeviceCategoryStat[];
  topApps: AuditDeviceAppStat[];
  systemApps: AuditDeviceAppStat[];
  hourlyTimeline: AuditDeviceHourStat[];
  dailyTrend: AuditDeviceDayStat[];
  storage: AuditDeviceProfileStorage;
}

export interface AuditDeviceProfileAISummary {
  ok: boolean;
  source: string;
  summary: string;
  generatedAt: string;
}

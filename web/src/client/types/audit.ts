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
  currentUploadBps?: number;
  currentDownloadBps?: number;
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

import type { AuditLogItem } from './security';

export interface ServerSocketTuneStatus {
  supported: boolean;
  profile: string;
  totalMemMb: number;
  rmemMax: number;
  wmemMax: number;
  rmemDefault: number;
  wmemDefault: number;
  recommendedRmemMax: number;
  recommendedWmemMax: number;
  recommendedRmemDefault: number;
  recommendedWmemDefault: number;
  defaultQdisc: string;
  recommendedQdisc: string;
  tcpCongestion: string;
  bbrAvailable: boolean;
  bbrEnabled: boolean;
  udpRcvbufErrors: number;
  udpSndbufErrors: number;
  maxBufferOptimal: boolean;
  defaultBufferOptimal: boolean;
  excessiveDefault: boolean;
  defaultBottleneck: boolean;
  qdiscOptimal: boolean;
  optimal: boolean;
  summary: string;
}

export interface ServerSocketTuneApplyResponse {
  ok: boolean;
  message: string;
  actions: string[];
  warnings?: string[];
  defaultBufferChanged: boolean;
  restartRecommended: boolean;
  asyncCaddyRestart: boolean;
  status: ServerSocketTuneStatus;
}

export interface SystemMetrics {
  bbr: boolean;
  socketTune?: ServerSocketTuneStatus;
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

export interface CertHealthItem {
  domain: string;
  role: string;
  status: 'healthy' | 'expiring' | 'expired' | 'missing' | string;
  issuer?: string;
  notAfter?: string;
  daysRemaining: number;
  source?: string;
  message?: string;
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
    subhub: ServiceDetail;
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
  certs?: CertHealthItem[];
  auditLogs?: AuditLogItem[];
}

export interface CheckUpdateResponse {
  component: string;
  displayName: string;
  currentVersion: string;
  latestVersion: string;
  hasUpdate: boolean;
  message: string;
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

export interface CamouflagePreset {
  id: string;
  name: string;
  ip: string;
  domain: string;
  sni: string;
}

export interface CamouflageDefaultsResponse {
  ip: string;
  domain: string;
  sni: string;
  ports: string;
  presets: CamouflagePreset[];
}

export interface CamouflageCheckItem {
  name: string;
  description: string;
  score: number;
  max_score: number;
  passed: boolean;
  details: string;
  mitigation: string;
}

export interface CamouflageCategory {
  name: string;
  score: number;
  max_score: number;
  items: CamouflageCheckItem[];
}

export interface CamouflageReport {
  target_ip: string;
  target_sni?: string;
  target_domain?: string;
  scan_time: string;
  total_score: number;
  risk_level: string;
  categories: CamouflageCategory[];
  findings: string[];
  recommendations: string[];
}

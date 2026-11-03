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

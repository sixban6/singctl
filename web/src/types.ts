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
  socksPort?: number;
}

export interface ServerStatusResponse {
  version: string;
  authEnabled: boolean;
  sessionToken: string;
  system: SystemMetrics;
  admin: {
    username: string;
    path: string;
    httpsUrl: string;
    port: number;
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
}

export interface SubscriptionsResponse {
  substoreKey?: string;
  substoreAdminUrl: string;
  substoreVercelUrl: string;
  subscriptionUrl: string;
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

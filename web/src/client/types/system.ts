import type { ClientAdGuardStatusSummary, ClientDNSStatusSummary } from './adguard';
import type { ClientFirewallStatus } from './firewall';
import type { ClientGatewayStatusSummary, ClientTailscaleStatus } from './network';
import type { SafeCommitStatusReport } from './p0';
import type { ClientSingBoxStatus } from './singbox';
import type { ClientDaemonStatus } from './watchdog';

export interface HostMemTelemetry {
  totalBytes: number;
  usedBytes: number;
  availBytes: number;
  swapTotalBytes: number;
  swapUsedBytes: number;
  usedPercent: number;
  lowMemory: boolean;
}

export interface HostDiskTelemetry {
  mountPath: string;
  label: string;
  totalBytes: number;
  usedBytes: number;
  availBytes: number;
  usedPercent: number;
}

export interface HostTelemetry {
  uptimeSec: number;
  cpuCores: number;
  cpuPercent: number;
  cpuReady: boolean;
  loadAvg: [number, number, number];
  mem: HostMemTelemetry;
  disk: HostDiskTelemetry;
  tmpDisk?: HostDiskTelemetry;
  isOpenWrt: boolean;
  collectedAt: number;
}

export interface ClientHostInfo {
  hostname: string;
  os: string;
  arch: string;
  openwrt: boolean;
  lanIP: string;
  telemetry?: HostTelemetry;
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
  dns?: ClientDNSStatusSummary;
  adguard?: ClientAdGuardStatusSummary;
  tailscale: ClientTailscaleStatus;
  firewall: ClientFirewallStatus;
  gateway?: ClientGatewayStatusSummary;
  safeCommit?: SafeCommitStatusReport;
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

export interface ClientBackupSummary {
  hasSingctlCfg: boolean;
  hasGroups: boolean;
  hasAdGuard: boolean;
  hasSingBox: boolean;
  hasSingBoxBase?: boolean;
  ruleSetCount?: number;
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
  ruleSetCount?: number;
  adaptations?: string[];
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

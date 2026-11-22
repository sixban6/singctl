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

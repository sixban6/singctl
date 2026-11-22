export interface WarpDiagnoseResponse {
  connected: boolean;
  ip?: string;
  loc?: string;
  warp?: string;
  latencyMs?: number;
  error?: string;
}

export type WarpRoutingMode = 'split' | 'global_warp' | 'bypass';

export interface WarpDaemonStatus {
  installed: boolean;
  running: boolean;
  tunnelHealthy: boolean;
  socksPort: number;
  warpIp?: string;
  warpLoc?: string;
  error?: string;
  degradedFallback?: boolean;
  autoHealStatus?: string;
  lastHealedAt?: string;
}

export interface WarpRoutingConfig {
  mode: WarpRoutingMode;
  presets?: Record<string, boolean>;
  warpDomains: string[];
  warpCidrs: string[];
  directDomains: string[];
  directCidrs: string[];
}

export interface WarpPresetItem {
  id: string;
  name: string;
  group: 'ai' | 'streaming' | 'social' | string;
  groupLabel: string;
  description: string;
  domainsSummary: string;
  defaultEnabled: boolean;
  enabled: boolean;
  ruleSets?: string[];
  domainSuffixes?: string[];
}

export interface WarpNodeSummary {
  id: string;
  name: string;
  host?: string;
  isLocal: boolean;
  online: boolean;
  mode: WarpRoutingMode | string;
  daemon: WarpDaemonStatus;
  dcConnCount: number;
  warpConnCount: number;
  updatedAt?: string;
  error?: string;
}

export interface WarpClusterOpItem {
  id: string;
  name: string;
  success: boolean;
  skipped?: boolean;
  message: string;
}

export interface WarpRoutingStatusResponse {
  selectedNode?: string;
  nodes?: WarpNodeSummary[];
  daemon: WarpDaemonStatus;
  routing: WarpRoutingConfig;
  presets: WarpPresetItem[];
  dcConnCount: number;
  warpConnCount: number;
}

export interface WarpRoutingUpdateResponse extends WarpRoutingStatusResponse {
  message: string;
  evictedConnections: number;
  results?: WarpClusterOpItem[];
}

export interface WarpQuickSwitchResponse extends WarpRoutingStatusResponse {
  message: string;
  target: string;
  outbound: 'WARP' | 'DC';
  matchedPreset?: string;
  evictedConnections: number;
  results?: WarpClusterOpItem[];
}

export interface ActiveDestinationGroup {
  target: string;
  rootDomain: string;
  isIP: boolean;
  protocol: string;
  outbound: 'WARP' | 'Direct' | string;
  rule?: string;
  connections: number;
  uploadBytes: number;
  downloadBytes: number;
  totalBytes: number;
}

export interface WarpConnectionsResponse {
  enabled: boolean;
  destinations: ActiveDestinationGroup[];
  total: number;
  message?: string;
}

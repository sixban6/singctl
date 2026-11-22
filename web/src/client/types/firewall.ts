export interface ClientFirewallStatus {
  supported: boolean;
  enabled: boolean;
  kernelActive?: boolean;
  autostartEnabled?: boolean;
  drifted?: boolean;
  mode?: 'standard' | 'minimal' | string;
  nftAvailable?: boolean;
  isOpenWrt?: boolean;
}

export interface FirewallCounterStat {
  packets: number;
  bytes: number;
}

export interface FirewallSecurityStats {
  totalBlockedPackets: number;
  totalBlockedBytes: number;
  foreverBlocked: FirewallCounterStat;
  dynamicV4Blocked: FirewallCounterStat;
  dynamicV6Blocked: FirewallCounterStat;
  honeypotTcpV4: FirewallCounterStat;
  honeypotUdpV4: FirewallCounterStat;
  honeypotTcpV6: FirewallCounterStat;
  honeypotUdpV6: FirewallCounterStat;
  dynamicV4Count: number;
  dynamicV6Count: number;
  foreverCount: number;
  protectedPortCount: number;
  whitelistCount: number;
}

export interface FirewallPreflightInfo {
  callerIp?: string;
  detectedSSHPorts: number[];
  protectedTunnels: string[];
  protectedLanRanges: string[];
  exemptServicePorts: number[];
  coexistingTables?: string[];
}

export interface FirewallEffectiveConfig {
  mode: 'standard' | 'minimal' | string;
  banTimeoutDays: number;
  pingLimitPerSec: number;
  protectedPorts: number[];
  whitelist: string[];
  extraForeverBan: string[];
}

export interface FirewallBanItem {
  target: string;
  scope: 'dynamic_v4' | 'dynamic_v6' | 'forever' | string;
  expiresSec?: number;
  builtin?: boolean;
}

export interface FirewallWhitelistView {
  builtin: string[];
  custom: string[];
  liveExtra?: string[];
}

export interface FirewallPortCatalogItem {
  port: number;
  label: string;
}

export interface FirewallOverviewResponse {
  status: ClientFirewallStatus;
  stats: FirewallSecurityStats;
  preflight: FirewallPreflightInfo;
  config: FirewallEffectiveConfig;
  bans: {
    items: FirewallBanItem[];
    total: number;
    page: number;
    pageSize: number;
  };
  whitelist: FirewallWhitelistView;
  protectedPortsLive?: number[];
  portCatalog: FirewallPortCatalogItem[];
  compactRuleText?: string;
}

export interface FirewallLogEvent {
  time: string;
  category: string;
  prefix: string;
  iface?: string;
  srcIp: string;
  proto?: string;
  dstPort?: number;
}

export interface FirewallApplyPayload {
  mode?: 'standard' | 'minimal' | string;
  banTimeoutDays?: number;
  pingLimitPerSec?: number;
  protectedPorts?: number[];
  resetDefaults?: boolean;
}

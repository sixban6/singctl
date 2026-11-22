export interface TelemetryRatePoint {
  time: string;
  upBps: number;
  downBps: number;
}

export interface TelemetryProtocolBreakdown {
  hy2Connections: number;
  hy2Bytes: number;
  realityConnections: number;
  realityBytes: number;
  otherConnections: number;
  otherBytes: number;
}

export interface TelemetryOutboundBreakdown {
  directConnections: number;
  directBytes: number;
  warpConnections: number;
  warpBytes: number;
  otherConnections: number;
  otherBytes: number;
}

export interface TelemetryDomainStat {
  domain: string;
  protocol: string;
  outbound: string;
  rule?: string;
  connections: number;
  bytes: number;
}

export interface SniffNodeRef {
  id: string;
  name: string;
  host?: string;
}

export interface SniffNodeSummary {
  id: string;
  name: string;
  host?: string;
  online: boolean;
  totalSniffIPs: number;
  totalSubnets: number;
  totalBanned: number;
  lastHarvestAt?: string;
  error?: string;
}

export interface SniffIPStat {
  ip: string;
  subnet: string;
  hits: number;
  vector: string;
  status: 'banned' | 'masqueraded' | 'observing' | string;
  country?: string;
  countryCode?: string;
  flag?: string;
  geo?: string;
  isp?: string;
  scannerTag?: string;
  firstSeen: string;
  lastSeen: string;
  nodes?: SniffNodeRef[];
}

export interface SniffSubnetStat {
  cidr: string;
  uniqueIPs: number;
  totalHits: number;
  bannedCount: number;
  status: 'banned' | 'partial' | 'active' | string;
  country?: string;
  countryCode?: string;
  flag?: string;
  isp?: string;
  scannerTag?: string;
  sampleIPs?: string[];
  firstSeen?: string;
  lastSeen?: string;
  nodes?: SniffNodeRef[];
}

export interface SniffCountryStat {
  countryCode: string;
  country: string;
  flag?: string;
  uniqueIPs: number;
  uniqueSubnets: number;
  totalHits: number;
  ratioPercent: number;
}

export interface SniffSummary {
  updatedAt: string;
  selectedNode?: string;
  nodes?: SniffNodeSummary[];
  totalSniffIPs: number;
  totalSubnets: number;
  totalCountries: number;
  totalBannedIPs: number;
  topIPs: SniffIPStat[];
  topSubnets: SniffSubnetStat[];
  topCountries: SniffCountryStat[];
}

export interface TelemetrySnapshot {
  enabled: boolean;
  reachable: boolean;
  controllerAddr?: string;
  timestamp: string;
  upBps: number;
  downBps: number;
  uploadTotal: number;
  downloadTotal: number;
  memoryBytes?: number;
  activeConnections: number;
  protocols: TelemetryProtocolBreakdown;
  outbounds: TelemetryOutboundBreakdown;
  topDomains: TelemetryDomainStat[];
  history: TelemetryRatePoint[];
  sniffing?: SniffSummary;
  message?: string;
}

export interface AuditLogItem {
  time: string;
  action: string;
  ip: string;
  category?: 'login' | 'security' | 'fleet' | 'subscription' | 'service' | string;
  geo?: string;
  isp?: string;
  country?: string;
  countryCode?: string;
  flag?: string;
}

export interface BannedIP {
  ip: string;
  remainingSeconds: number;
  remainingMinutes: number;
  remainingText?: string;
  bannedUntil?: string;
  failCount?: number;
  source?: 'login_fail' | 'manual_sniff' | string;
  sourceLabel?: string;
  reason?: string;
  geo?: string;
  isp?: string;
  country?: string;
  countryCode?: string;
  flag?: string;
}

export interface BackupExportResponse {
  message: string;
  filename: string;
  data: string;
  hasSingctlCfg: boolean;
  hasFleet: boolean;
  fleetKeyCount: number;
  hasSubStore: boolean;
}

export interface HealComponentCheck {
  name: string;
  displayName: string;
  currentVersion: string;
  latestVersion: string;
  installed: boolean;
  hasUpdate: boolean;
}

export interface HealLayerAction {
  layer: string;
  target: string;
  success: boolean;
  updated: boolean;
  rolledBack?: boolean;
  message: string;
}

export interface HealHistoryItem {
  timestamp: string;
  trigger: string;
  success: boolean;
  durationMs: number;
  summary: string;
  actions?: HealLayerAction[];
  rebootRequired: boolean;
}

export interface HealPolicy {
  autoHealEnabled: boolean;
  schedule: string;
  autoReboot: boolean;
}

export interface HealStatusReport {
  checkedAt: string;
  posture: 'healthy' | 'updates_pending' | 'reboot_required' | string;
  postureLabel: string;
  core: {
    components: HealComponentCheck[];
    pendingCount: number;
    healthy: boolean;
  };
  os: {
    distro: string;
    packageManager: string;
    openwrtProtected?: boolean;
    securityUpdates: string[];
    securityCount: number;
    staleServices: string[];
    healthy: boolean;
  };
  kernel: {
    runningKernel: string;
    installedKernel?: string;
    rebootRequired: boolean;
    rebootReason?: string;
    affectedPkgs?: string[];
    healthy: boolean;
  };
  timer: {
    supported: boolean;
    enabled: boolean;
    active: boolean;
    schedule: string;
    nextRun?: string;
    lastRun?: string;
  };
  policy: HealPolicy;
  history: HealHistoryItem[];
}

export interface FleetHealNodeResult {
  id: string;
  name: string;
  success: boolean;
  posture: string;
  summary: string;
  rebootRequired: boolean;
  rebooted?: boolean;
  doctorScoreAfterReboot?: number;
  circuitBroken?: boolean;
  skippedByCircuitBreaker?: boolean;
  actions?: HealLayerAction[];
}

export interface FleetHealReport {
  checkedAt: string;
  totalNodes: number;
  healthyNodes: number;
  rebootedNodes: number;
  circuitBreakerHit: boolean;
  circuitBreakerNote?: string;
  results: FleetHealNodeResult[];
}

export interface HealRunResponse {
  message: string;
  scope: 'local' | 'fleet';
  execution: HealHistoryItem;
  status: HealStatusReport;
  fleetReport?: FleetHealReport;
}

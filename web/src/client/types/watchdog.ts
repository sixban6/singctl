export interface ClientDaemonStatus {
  running: boolean;
  restarts: number;
  maxRestarts: number;
  totalRestarts: number;
  logPath: string;
  daemonVersion?: string;
  staleBinary?: boolean;
  versionMismatch?: boolean;
  lastHealthAt?: string;
  lastHealthOK?: boolean;
  failoverEnabled?: boolean;
  activeFailoverCount?: number;
}

export interface WatchdogActiveFailover {
  group: string;
  origin: string;
  current: string;
  lastDelayMs?: number;
  since?: string;
}

export interface WatchdogEventItem {
  time: string;
  action: string;
  summary: string;
  healthy?: boolean;
}

export interface WatchdogFailoverConfig {
  enabled: boolean;
  groups: string[];
  is_default_groups: boolean;
  default_groups: string[];
  patrol_interval: number;
  probe_timeout_ms: number;
  confirm_retries: number;
  auto_failback: boolean;
  failback_cooldown: number;
  max_failback_delay_ms: number;
  probe_urls: string[];
  is_default_probe_urls: boolean;
}

export interface WatchdogConfigDTO {
  interval: number;
  confirm_wait: number;
  max_restarts: number;
  sub_sync_enabled: boolean;
  sub_sync_interval: number;
  failover: WatchdogFailoverConfig;
}

export interface WatchdogSelectorGroup {
  name: string;
  now: string;
  failedOver?: boolean;
}

export interface WatchdogReport {
  daemon: {
    running: boolean;
    pid: number;
    daemonVersion: string;
    singctlVersion: string;
    staleBinary: boolean;
    versionMismatch: boolean;
    startedAt: string;
    restarts: number;
    maxRestarts: number;
    totalRestarts: number;
    logPath: string;
    logSizeBytes: number;
    logMaxBytes: number;
  };
  config: WatchdogConfigDTO;
  runtime: {
    lastHealthAt?: string;
    lastHealthOK?: boolean;
    lastHealthDetail?: string;
    lastHealthDelayMs?: number;
    lastSubSyncAt?: string;
    lastRuleSetAt?: string;
    activeFailovers?: WatchdogActiveFailover[];
    recentEvents?: WatchdogEventItem[];
  };
  selectorGroups: WatchdogSelectorGroup[];
  adguard: {
    supported: boolean;
    enabled: boolean;
    installed: boolean;
    healthy: boolean;
  };
  ok?: boolean;
  daemonReloaded?: boolean;
}

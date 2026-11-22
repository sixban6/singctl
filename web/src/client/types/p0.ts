export interface OOMShieldStatus {
  found: boolean;
  pid?: number;
  scoreAdj: number;
  protected: boolean;
  message?: string;
}

export interface SafeCommitState {
  token: string;
  reason?: string;
  armedAt: number;
  deadlineUnix: number;
  ttlSec: number;
  watcherPid?: number;
  singBoxWasRunning: boolean;
  firewallWasActive: boolean;
  dnsEngine?: string;
}

export interface SafeCommitRollbackRecord {
  token?: string;
  reason?: string;
  rolledBackAt: number;
  trigger: string;
  success: boolean;
  actions?: string[];
  error?: string;
}

export interface SafeCommitStatusReport {
  active: boolean;
  state?: SafeCommitState | null;
  remainingSec: number;
  lastRollback?: SafeCommitRollbackRecord | null;
  tailscaleOom: OOMShieldStatus;
}

export interface SafeCommitConfig {
  defaultTtlSec: number;
  protectTailscaleOom: boolean;
}

export type SafeCommitStatusResponse = SafeCommitStatusReport & {
  config: SafeCommitConfig;
};

export interface NotifyEventsConfig {
  watchdogHeal: boolean;
  safeCommitRollback: boolean;
  resourceGuard: boolean;
  auditHighRisk: boolean;
  newDevice: boolean;
  subOrNodeFail: boolean;
  serverQuotaOrBan: boolean;
}

export interface NotifyChannelsConfig {
  telegram: {
    enabled: boolean;
    botToken: string;
    chatId: string;
    apiBaseUrl: string;
  };
  bark: {
    enabled: boolean;
    serverUrl: string;
    deviceKey: string;
    group: string;
  };
  feishu: {
    enabled: boolean;
    webhookUrl: string;
    secret: string;
  };
  wecom: {
    enabled: boolean;
    webhookUrl: string;
  };
  webhook: {
    enabled: boolean;
    url: string;
    headerName: string;
    headerValue: string;
  };
}

export interface NotifyConfigDTO {
  enabled: boolean;
  cooldownMinutes: number;
  dailyLimit: number;
  quietHours: string;
  events: NotifyEventsConfig;
  channels: NotifyChannelsConfig;
}

export interface NotifySecretStatus {
  telegramBotToken: boolean;
  barkDeviceKey: boolean;
  feishuWebhookUrl: boolean;
  feishuSecret: boolean;
  wecomWebhookUrl: boolean;
  webhookHeaderValue: boolean;
}

export interface NotifyHistoryRecord {
  time: string;
  eventType: string;
  severity: 'info' | 'warn' | 'critical' | string;
  title: string;
  channels: string[];
  success: boolean;
  error?: string;
}

export interface NotifyDeliveryResult {
  channel: string;
  ok: boolean;
  error?: string;
  latencyMs: number;
}

export interface NotifyConfigResponse {
  config: NotifyConfigDTO;
  secretStatus: NotifySecretStatus;
  recentHistory: NotifyHistoryRecord[];
}

export type DoctorStatus = 'pass' | 'warn' | 'fail' | 'skip';

export interface DoctorCheckResult {
  id: string;
  category: string;
  title: string;
  status: DoctorStatus;
  summary: string;
  detail?: string;
  advice?: string;
  fixAction?: string;
  fixLabel?: string;
  durationMs: number;
}

export interface DoctorReport {
  score: number;
  overall: DoctorStatus;
  passed: number;
  warnings: number;
  failed: number;
  skipped: number;
  durationMs: number;
  checkedAt: string;
  checks: DoctorCheckResult[];
}

import { SafeCommitStatusReport } from './p0';

export interface WifiRadioInfo {
  device: string;
  driver: string;
  phy?: string;
  band: '2g' | '5g' | '6g' | string;
  hardware?: string;
  disabled: boolean;
  up: boolean;
  channel: string;
  currentChannel?: number;
  frequencyGhz?: string;
  htmode: string;
  country?: string;
  txPowerPct: number;
  txPowerDbm?: number;
  bitRateMbps?: number;
  muBeamformer: boolean;
  whnat: boolean;
  overlappingChannel: boolean;
  dfsChannel: boolean;
  supportedModes?: string[];
  recommendChannels?: number[];
  interfaceCount: number;
  clientCount: number;
  rxPackets: number;
  rxErrors: number;
  rxDropped: number;
  txPackets: number;
  txDropped: number;
  rxErrorRatePct: number;
  packetLossRatePct: number;
}

export interface WifiSSIDInfo {
  section: string;
  device: string;
  band: string;
  ifname?: string;
  ssid: string;
  network: string;
  bridge?: string;
  encryption: string;
  passwordConfigured: boolean;
  disabled: boolean;
  isolate: boolean;
  ieee80211k: boolean;
  clientCount: number;
  rxPackets: number;
  rxErrors: number;
  rxDropped: number;
  txPackets: number;
  txDropped: number;
  rxErrorRatePct: number;
  packetLossRatePct: number;
  dualBandPaired: boolean;
  canUpgradeDualBand: boolean;
}

export interface WifiClientInfo {
  mac: string;
  hostname?: string;
  ip?: string;
  ifname: string;
  ssid: string;
  band: string;
  signalDbm: number;
  rxMbps: number;
  txMbps: number;
  bandwidthMhz?: number;
  weakSignal: boolean;
}

export interface WifiDiagnosisItem {
  id: string;
  severity: 'critical' | 'warn' | 'info' | string;
  band?: string;
  title: string;
  detail: string;
  actionHint?: string;
  autoFix: boolean;
}

export interface WifiChannelStat {
  channel: number;
  band: string;
  apCount: number;
  strongestDbm?: number;
  score: number;
  level: 'clean' | 'moderate' | 'busy' | string;
  nonOverlapping: boolean;
  dfs: boolean;
  recommended: boolean;
  current: boolean;
}

export interface WifiScanResult {
  scannedAt: number;
  channels2g: WifiChannelStat[];
  channels5g: WifiChannelStat[];
  recommended2gChannel?: number;
  recommended5gChannel?: number;
  summary: string;
  warnings?: string[];
}

export interface WifiRPSInterfaceStatus {
  interface: string;
  currentMask: string;
  targetMask: string;
  balanced: boolean;
}

export interface SocketTuneStatus {
  supported: boolean;
  profile: string;
  totalMemMb: number;
  rmemMax: number;
  wmemMax: number;
  rmemDefault: number;
  wmemDefault: number;
  recommendedRmemMax: number;
  recommendedWmemMax: number;
  recommendedRmemDefault: number;
  recommendedWmemDefault: number;
  defaultQdisc: string;
  recommendedQdisc: string;
  tcpCongestion: string;
  bbrAvailable: boolean;
  bbrEnabled: boolean;
  udpRcvbufErrors: number;
  udpSndbufErrors: number;
  maxBufferOptimal: boolean;
  defaultBufferOptimal: boolean;
  excessiveDefault: boolean;
  defaultBottleneck: boolean;
  qdiscOptimal: boolean;
  optimal: boolean;
  summary: string;
}

export interface WifiChassisStatus {
  supported: boolean;
  cpuCores: number;
  totalMemMb: number;
  rpsInterfaces: WifiRPSInterfaceStatus[];
  rpsOptimal: boolean;
  conntrackCount: number;
  conntrackMax: number;
  recommendedConntrack: number;
  conntrackOptimal: boolean;
  socketBuffer?: SocketTuneStatus;
  optimal: boolean;
}

export interface WifiOptimizationStep {
  target: string;
  field: string;
  before: string;
  after: string;
  reason: string;
}

export interface WifiOverview {
  supported: boolean;
  unsupportedHint?: string;
  driver?: string;
  healthScore: number;
  healthLevel: 'excellent' | 'good' | 'warn' | 'critical' | string;
  healthSummary: string;
  radios: WifiRadioInfo[];
  ssids: WifiSSIDInfo[];
  clients: WifiClientInfo[];
  diagnostics: WifiDiagnosisItem[];
  autoOptimizePlan: WifiOptimizationStep[];
  chassis: WifiChassisStatus;
  sampledAt: number;
  statsScope?: 'boot' | 'post_optimize' | 'retest' | string;
  statsBaselineAt?: number;
  statsWindowSec?: number;
}

export interface WifiRadioPatch {
  device: string;
  disabled?: boolean;
  channel?: string;
  htmode?: string;
  txPowerPct?: number;
  ieee80211k?: boolean;
}

export interface WifiApplyRequest {
  action: 'auto_optimize' | 'dual_band_merge' | 'tune_radio';
  sourceSection?: string;
  recommended2gChannel?: number;
  recommended5gChannel?: number;
  preferred5gWidth?: 'HE80' | 'HE160';
  radios?: WifiRadioPatch[];
  ttlSec?: number;
  dryRun?: boolean;
}

export interface WifiApplyResponse {
  ok: boolean;
  dryRun?: boolean;
  action: string;
  summary: string;
  changes: WifiOptimizationStep[];
  reloaded?: boolean;
  asyncReload?: boolean;
  bridgeVerified?: boolean;
  bridgeWaitMs?: number;
  warnings?: string[];
  safeCommitToken?: string;
  safeCommitTtlSec?: number;
  safeCommit?: SafeCommitStatusReport;
  overview?: WifiOverview;
}

export interface WifiChassisApplyRequest {
  enableRps: boolean;
  tuneConntrack: boolean;
  conntrackMax?: number;
  tuneSocketBuffer?: boolean;
}

export interface WifiChassisApplyResponse {
  ok: boolean;
  actions: string[];
  warnings?: string[];
  restartSingBoxRecommended?: boolean;
  chassis: WifiChassisStatus;
}

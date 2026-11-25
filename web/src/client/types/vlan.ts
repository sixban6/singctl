import { SafeCommitStatusResponse } from './p0';

export type VlanDriverKind = 'dsa' | 'swconfig' | 'softrouter' | 'unsupported';
export type VlanPortMode = 'off' | 'access' | 'trunk';
export type VlanProxyMode = 'follow' | 'direct' | 'side_router';
export type VlanIPv6Mode = 'off' | 'relay' | 'server';
export type VlanPresetKind = 'iot' | 'wifi' | 'guest' | 'wired';
export type VlanRelationTone = 'ok' | 'warn' | 'danger' | 'neutral' | 'accent';

export interface VlanPortInfo {
  name: string;
  label: string;
  switchPort?: string;
  isWan: boolean;
  isMgmt: boolean;
  linkUp: boolean;
  speedMbps: number;
  untaggedSegmentId?: string;
  taggedSegmentIds?: string[];
}

export interface VlanRadioInfo {
  name: string;
  band: string;
  bandLabel: string;
  phy?: string;
  driverType?: string;
}

export interface VlanWirelessSSIDInfo {
  section: string;
  device: string;
  band: string;
  ssid: string;
  network: string;
  encryption: string;
  isolate: boolean;
  disabled: boolean;
  managedBySingCtl: boolean;
  passwordConfigured: boolean;
}

export interface VlanWirelessSpec {
  enabled: boolean;
  section?: string;
  radio?: string;
  band?: string;
  ssid?: string;
  password?: string;
  passwordConfigured?: boolean;
  encryption?: string; // "psk2" | "sae-mixed"
  isolate: boolean;
}

export interface VlanSecurityPolicy {
  allowWan: boolean;
  blockRouterMgmt: boolean;
  blockUpstreamLan: boolean;
  allowFromMainLan: boolean;
  allowForwardTo?: string[];
  trustedSourceIps?: string[];
  allowMdns: boolean;
}

export interface VlanRelationBadge {
  tone: VlanRelationTone;
  text: string;
}

export interface VlanSegment {
  id: string;
  displayName: string;
  preset?: string;
  vlanId: number;
  device: string;
  ipAddr: string;
  netmask: string;
  cidr: string;
  dhcpStart: number;
  dhcpLimit: number;
  leaseTime: string;
  dhcpDns?: string[];
  ipv6Mode: VlanIPv6Mode | string;
  proxyMode: VlanProxyMode | string;
  isPrimaryLan: boolean;
  isCallerMgmt: boolean;
  managedBySingCtl: boolean;
  onlineClients: number;
  ports?: Record<string, VlanPortMode | string>;
  wireless?: VlanWirelessSpec | null;
  policy: VlanSecurityPolicy;
  relations?: VlanRelationBadge[];
}

export interface VlanPresetTemplate {
  id: VlanPresetKind | string;
  title: string;
  tagline: string;
  recommendedName: string;
  suggestedId: string;
  suggestedVlanId: number;
  suggestedIpAddr: string;
  defaultIpv6Mode: VlanIPv6Mode | string;
  defaultProxyMode: VlanProxyMode | string;
  defaultWireless: VlanWirelessSpec;
  defaultPolicy: VlanSecurityPolicy;
}

export interface VlanOverview {
  supported: boolean;
  unsupportedReason?: string;
  driver: VlanDriverKind | string;
  driverLabel: string;
  boardModel?: string;
  wanDevice?: string;
  wanIp?: string;
  wanSubnet?: string;
  callerIp?: string;
  callerSegmentId?: string;
  callerPort?: string;
  sideRouterIp?: string;
  ports: VlanPortInfo[];
  radios: VlanRadioInfo[];
  existingSsids: VlanWirelessSSIDInfo[];
  segments: VlanSegment[];
  presets: VlanPresetTemplate[];
  warnings?: string[];
}

export interface VlanSaveSegmentRequest {
  id: string;
  displayName?: string;
  preset?: string;
  vlanId: number;
  ipAddr: string;
  netmask?: string;
  dhcpStart?: number;
  dhcpLimit?: number;
  leaseTime?: string;
  dhcpDns?: string[];
  ipv6Mode?: VlanIPv6Mode | string;
  proxyMode?: VlanProxyMode | string;
  ports?: Record<string, VlanPortMode | string>;
  wireless?: VlanWirelessSpec | null;
  policy: VlanSecurityPolicy;
  allowModifyMgmt?: boolean;
  ttlSec?: number;
}

export interface VlanPreviewResult {
  valid: boolean;
  errors?: string[];
  warnings?: string[];
  plainSummary?: string[];
  uciCommands?: string[];
  proxyBypassCidrs?: string[];
  upstreamRouteHint?: string;
}

export interface VlanApplyResponse {
  ok: boolean;
  segmentId: string;
  plainSummary?: string[];
  uciCommands?: string[];
  warnings?: string[];
  upstreamRouteHint?: string;
  safeCommitToken?: string;
  safeCommitTtlSec?: number;
  safeCommit?: SafeCommitStatusResponse;
  overview?: VlanOverview;
}

export interface VlanWirelessSecretResponse {
  segmentId: string;
  section?: string;
  ssid?: string;
  passwordConfigured: boolean;
  password?: string;
}

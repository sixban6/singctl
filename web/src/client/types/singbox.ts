export interface ClientSingBoxStatus {
  running: boolean;
  installed: boolean;
  version: string;
  configExists: boolean;
  configPath: string;
}

export type SbProxyMode = 'rule' | 'global' | 'direct' | string;

export interface SbProxyNodeMeta {
  name: string;
  type: string;
  delay: number;
  tested?: boolean;
  udp?: boolean;
}

export interface SbProxyGroup {
  name: string;
  type: 'Selector' | 'URLTest' | 'Fallback' | 'LoadBalance' | string;
  canSelect: boolean;
  now?: string;
  resolvedChain?: string[];
  resolvedNode?: string;
  resolvedDelay?: number;
  all: string[];
  usedBy?: string[];
  usedByCount?: number;
  failedOver?: boolean;
  failoverFrom?: string;
  failoverSince?: string;
}

export interface SbProxiesSnapshot {
  running: boolean;
  mode: SbProxyMode;
  primaryGroup?: string;
  primaryNode?: string;
  primaryDelay?: number;
  groups: SbProxyGroup[];
  nodes: Record<string, SbProxyNodeMeta>;
  error?: string;
}

export interface SbTrafficSnapshot {
  running: boolean;
  up: number;
  down: number;
  uploadTotal: number;
  downloadTotal: number;
  connections: number;
  memory: number;
  error?: string;
}

export interface SbConfigResponse {
  path: string;
  exists: boolean;
  content: string;
  backups: string[];
  checkable: boolean;
  preserveManualConfig?: boolean;
}

export interface ClientRoutingGroupInfo {
  tag: string;
  type: string;
  default?: string;
  count: number;
}

export interface TrafficCategoryInfo {
  id: string;
  label: string;
  description: string;
  defaultDest: string;
}

export interface ClientRoutingPresetState {
  id: string;
  name: string;
  category: string;
  categoryLabel: string;
  description: string;
  domainsSummary: string;
  defaultOn: boolean;
  defaultOutbound: string;
  enabled: boolean;
  selectedGroup: string;
  effectiveDest: string;
  customized: boolean;
}

export interface ClientRoutingReport {
  groups: ClientRoutingGroupInfo[];
  directTag: string;
  categories: TrafficCategoryInfo[];
  items: ClientRoutingPresetState[];
  enabledCount: number;
  customCount: number;
  totalCount: number;
  hasConfig: boolean;
  lastError?: string;
}

export interface GroupMacroInfo {
  id: string;
  label: string;
  description: string;
  pattern: string;
}

export interface GroupTemplateSnippet {
  id: string;
  name: string;
  description: string;
  content: string;
}

export interface LeafOutboundInfo {
  tag: string;
  type: string;
  subs?: string[];
}

export interface CompiledGroupPreview {
  name: string;
  type: 'selector' | 'urltest' | string;
  builtin: boolean;
  customized: boolean;
  fallbackUsed?: boolean;
  fallbackTag?: string;
  default?: string;
  attachedTo?: string[];
  failover?: boolean;
  members: string[];
  leafMatchCount: number;
  totalCount: number;
}

export interface GroupsPreviewReport {
  mode: 'merge' | 'replace' | string;
  defaultOutbound?: string;
  dnsDetour?: string;
  totalLeafNodes: number;
  leafNodes: LeafOutboundInfo[];
  subNames?: string[];
  groups: CompiledGroupPreview[];
  warnings?: string[];
}

export interface ClientGroupsGetResponse {
  path: string;
  exists: boolean;
  content: string;
  hasLiveConfig: boolean;
  macros: GroupMacroInfo[];
  templates: GroupTemplateSnippet[];
  preview?: GroupsPreviewReport;
  parseError?: string;
}

export interface ClientGroupsPreviewResponse {
  ok: boolean;
  hasLiveConfig?: boolean;
  preview?: GroupsPreviewReport;
  error?: string;
}

export interface ClientGroupsPutResponse {
  ok: boolean;
  exists: boolean;
  applied: boolean;
  content: string;
  message: string;
  preview?: GroupsPreviewReport;
  routingReport?: ClientRoutingReport;
}

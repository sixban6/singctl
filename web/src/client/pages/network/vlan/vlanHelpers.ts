import { redactInlineSensitive } from '../../../../lib/privacyMask';
import {
  VlanOverview,
  VlanPortMode,
  VlanPresetTemplate,
  VlanSaveSegmentRequest,
  VlanSegment,
} from '../../../types';

export interface SegmentTheme {
  border: string;
  hoverBorder: string;
  bg: string;
  text: string;
  dot: string;
  bar: string;
  pillBg: string;
}

const THEMES: Record<string, SegmentTheme> = {
  lan: {
    border: 'border-emerald-500/35',
    hoverBorder: 'hover:border-emerald-500/55',
    bg: 'bg-emerald-500/10',
    text: 'text-emerald-300',
    dot: 'bg-emerald-400',
    bar: 'bg-emerald-500',
    pillBg: 'bg-emerald-500/15 border-emerald-500/35 text-emerald-300',
  },
  wifi: {
    border: 'border-sky-500/35',
    hoverBorder: 'hover:border-sky-500/55',
    bg: 'bg-sky-500/10',
    text: 'text-sky-300',
    dot: 'bg-sky-400',
    bar: 'bg-sky-500',
    pillBg: 'bg-sky-500/15 border-sky-500/35 text-sky-300',
  },
  iot: {
    border: 'border-amber-500/35',
    hoverBorder: 'hover:border-amber-500/55',
    bg: 'bg-amber-500/10',
    text: 'text-amber-300',
    dot: 'bg-amber-400',
    bar: 'bg-amber-500',
    pillBg: 'bg-amber-500/15 border-amber-500/35 text-amber-300',
  },
  guest: {
    border: 'border-violet-500/35',
    hoverBorder: 'hover:border-violet-500/55',
    bg: 'bg-violet-500/10',
    text: 'text-violet-300',
    dot: 'bg-violet-400',
    bar: 'bg-violet-500',
    pillBg: 'bg-violet-500/15 border-violet-500/35 text-violet-300',
  },
  wired: {
    border: 'border-cyan-500/35',
    hoverBorder: 'hover:border-cyan-500/55',
    bg: 'bg-cyan-500/10',
    text: 'text-cyan-300',
    dot: 'bg-cyan-400',
    bar: 'bg-cyan-500',
    pillBg: 'bg-cyan-500/15 border-cyan-500/35 text-cyan-300',
  },
};

export function getSegmentTheme(segId?: string, preset?: string): SegmentTheme {
  if (segId === 'lan') return THEMES.lan;
  if (preset && THEMES[preset]) return THEMES[preset];
  if (segId && THEMES[segId]) return THEMES[segId];
  return THEMES.wired;
}

export function formatSpeedMbps(speedMbps: number): string {
  if (speedMbps >= 10000) return `${(speedMbps / 1000).toFixed(0)}G`;
  if (speedMbps >= 2500) return '2.5G';
  if (speedMbps >= 1000) return '1G';
  if (speedMbps > 0) return `${speedMbps}M`;
  return '';
}

export function buildDraftFromPreset(preset: VlanPresetTemplate): VlanSaveSegmentRequest {
  return {
    id: preset.suggestedId,
    displayName: preset.recommendedName,
    preset: preset.id,
    vlanId: preset.suggestedVlanId,
    ipAddr: preset.suggestedIpAddr,
    netmask: '255.255.255.0',
    dhcpStart: 100,
    dhcpLimit: 150,
    leaseTime: preset.id === 'guest' ? '2h' : '12h',
    ipv6Mode: preset.defaultIpv6Mode || 'off',
    proxyMode: preset.defaultProxyMode || 'direct',
    ports: {},
    wireless: {
      enabled: Boolean(preset.defaultWireless?.enabled),
      radio: preset.defaultWireless?.radio || '',
      band: preset.defaultWireless?.band || '',
      ssid: preset.defaultWireless?.ssid || '',
      password: '',
      passwordConfigured: false,
      encryption: preset.defaultWireless?.encryption || 'psk2',
      isolate: Boolean(preset.defaultWireless?.isolate),
    },
    policy: {
      allowWan: preset.defaultPolicy?.allowWan ?? true,
      blockRouterMgmt: preset.defaultPolicy?.blockRouterMgmt ?? true,
      blockUpstreamLan: preset.defaultPolicy?.blockUpstreamLan ?? true,
      allowFromMainLan: preset.defaultPolicy?.allowFromMainLan ?? true,
      allowForwardTo: [...(preset.defaultPolicy?.allowForwardTo ?? [])],
      trustedSourceIps: [...(preset.defaultPolicy?.trustedSourceIps ?? [])],
      allowMdns: preset.defaultPolicy?.allowMdns ?? false,
    },
    ttlSec: 180,
  };
}

export function buildDraftFromSegment(seg: VlanSegment, overview: VlanOverview): VlanSaveSegmentRequest {
  const ports: Record<string, VlanPortMode> = {};
  if (seg.ports) {
    for (const [k, v] of Object.entries(seg.ports)) {
      if (v === 'access' || v === 'trunk') {
        ports[k] = v;
      }
    }
  }
  const defaultRadio = overview.radios[0]?.name || '';
  return {
    id: seg.id,
    displayName: seg.displayName || seg.id,
    preset: seg.preset || 'wifi',
    vlanId: seg.vlanId > 0 ? seg.vlanId : 10,
    ipAddr: seg.ipAddr,
    netmask: seg.netmask || '255.255.255.0',
    dhcpStart: seg.dhcpStart || 100,
    dhcpLimit: seg.dhcpLimit || 150,
    leaseTime: seg.leaseTime || '12h',
    ipv6Mode: seg.ipv6Mode || 'off',
    proxyMode: seg.proxyMode || 'follow',
    ports,
    wireless: seg.wireless
      ? {
          enabled: seg.wireless.enabled,
          section: seg.wireless.section,
          radio: seg.wireless.radio || defaultRadio,
          band: seg.wireless.band,
          ssid: seg.wireless.ssid || '',
          password: '',
          passwordConfigured: Boolean(seg.wireless.passwordConfigured),
          encryption: seg.wireless.encryption || 'psk2',
          isolate: Boolean(seg.wireless.isolate),
        }
      : {
          enabled: false,
          radio: defaultRadio,
          ssid: '',
          password: '',
          passwordConfigured: false,
          encryption: 'psk2',
          isolate: seg.preset === 'iot' || seg.preset === 'guest',
        },
    policy: {
      allowWan: seg.policy?.allowWan ?? true,
      blockRouterMgmt: seg.policy?.blockRouterMgmt ?? false,
      blockUpstreamLan: seg.policy?.blockUpstreamLan ?? false,
      allowFromMainLan: seg.policy?.allowFromMainLan ?? false,
      allowForwardTo: [...(seg.policy?.allowForwardTo ?? [])],
      trustedSourceIps: [...(seg.policy?.trustedSourceIps ?? [])],
      allowMdns: seg.policy?.allowMdns ?? false,
    },
    ttlSec: 180,
  };
}

export function maskVlanText(text: string, privacyMask: boolean): string {
  if (!privacyMask || !text) return text;
  return redactInlineSensitive(text, true);
}

export function isPrivateIPv4(ip?: string): boolean {
  if (!ip) return false;
  return (
    ip.startsWith('10.') ||
    ip.startsWith('192.168.') ||
    /^172\.(1[6-9]|2\d|3[0-1])\./.test(ip)
  );
}

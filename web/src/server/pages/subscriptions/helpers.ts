import { SubscriptionAccessLogItem, SubscriptionRiskSummary, SubscriptionsResponse } from '../../types';

export const PREVIEW_TARGETS = [
  { key: 'ClashMeta', label: 'Clash.Meta / Mihomo' },
  { key: 'Sing-Box', label: 'Sing-box v1.14' },
  { key: 'Shadowrocket', label: 'Base64 通用订阅' },
  { key: 'Surge', label: 'Surge' },
  { key: 'Loon', label: 'Loon' },
  { key: 'plain', label: '明文 URI 列表' },
];

export const formatEffectiveUA = (ua?: string): string => {
  if (!ua) return '';
  const lower = ua.toLowerCase();
  if (lower.includes('v2rayng')) return 'v2rayNG';
  if (lower.includes('shadowrocket')) return 'Shadowrocket';
  if (lower.includes('clash') || lower.includes('mihomo')) return 'Clash.Meta';
  if (lower.includes('sing-box') || lower.includes('sfa/') || lower.includes('sfi/')) return 'Sing-box';
  return ua.length > 20 ? `${ua.slice(0, 20)}...` : ua;
};

export interface CachedSubAudit {
  logs: SubscriptionAccessLogItem[];
  riskSummary?: SubscriptionRiskSummary;
  bannedIps?: string[];
}

export function buildClientImportItems(data: SubscriptionsResponse | null) {
  return [
    {
      name: 'Shadowrocket',
      desc: 'iOS 跨协议网络客户端',
      icon: '🚀',
      scheme: data?.importLinks?.shadowrocket,
    },
    {
      name: 'Clash Verge / Mihomo',
      desc: '跨平台 Clash.Meta 内核客户端',
      icon: '⚡',
      scheme: data?.importLinks?.clash,
    },
    {
      name: 'Sing-box 官方客户端',
      desc: 'iOS SFI / Android SFA / 桌面端 v1.14',
      icon: '📦',
      scheme: data?.importLinks?.singbox,
    },
    {
      name: 'Surge',
      desc: '高级网络分析与托管配置客户端',
      icon: '🌊',
      scheme: data?.importLinks?.surge,
    },
    {
      name: 'Loon',
      desc: '支持 VLESS Reality 与 Hysteria2',
      icon: '🎈',
      scheme: data?.importLinks?.loon,
    },
  ];
}

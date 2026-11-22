export interface SubscriptionSourceItem {
  name: string;
  displayName: string;
  source: 'local' | 'remote';
  url: string;
  content: string;
  remark: string;
  enabled: boolean;
  autoManaged: boolean;
  nodeCount: number;
  userAgent?: string;
  proxyMode?: string;
  effectiveUa?: string;
  usedProxy?: string;
  lastFetchedAt?: string;
  lastError?: string;
}

export interface SourceUpsertInput {
  name?: string;
  displayName: string;
  source: 'local' | 'remote';
  url?: string;
  content?: string;
  remark?: string;
  userAgent?: string;
  proxyMode?: string;
  enabled?: boolean;
}

export interface SubscriptionPreviewResponse {
  target: string;
  filename: string;
  contentType: string;
  nodeCount: number;
  content: string;
}

export interface SubscriptionsResponse {
  engine?: string;
  substoreKey?: string;
  substoreAdminUrl: string;
  subscriptionUrl: string;
  sources?: SubscriptionSourceItem[];
  importLinks: {
    shadowrocket: string;
    clash: string;
    singbox: string;
    surge: string;
    loon: string;
  };
  nodes: {
    hy2: {
      link: string;
      domain: string;
      port: number;
    };
    vless: {
      link: string;
      sni: string;
      port: number;
    };
  };
}

export interface SubscriptionAccessLogItem {
  timestamp: string;
  ip: string;
  countryCode?: string;
  geo?: string;
  flag?: string;
  clientApp: string;
  userAgent?: string;
  target: string;
  collection?: string;
  nodeCount: number;
  status: 'ok' | 'denied';
}

export interface SubscriptionRiskSummary {
  level: 'safe' | 'warn' | 'high';
  uniqueIps24h: number;
  uniqueCountries24h: number;
  deniedHits24h: number;
  suspiciousUaHits24h: number;
  reasons: string[];
}

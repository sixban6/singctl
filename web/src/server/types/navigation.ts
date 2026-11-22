export const SERVER_TAB_KEYS = [
  'overview',
  'services',
  'warp',
  'subscriptions',
  'fleet',
  'camouflage',
  'logs',
  'diagnostics',
  'security',
] as const;

export type TabKey = (typeof SERVER_TAB_KEYS)[number];

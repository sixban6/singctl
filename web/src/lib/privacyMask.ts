export const PRIVACY_MASK_STORAGE_KEY = 'singctl:net:privacy-mask';
export const PRIVACY_MASK_EVENT = 'singctl:privacy-mask-change';

export function readPrivacyMaskPref(): boolean {
  if (typeof window === 'undefined') return false;
  try {
    return window.localStorage.getItem(PRIVACY_MASK_STORAGE_KEY) === '1';
  } catch {
    return false;
  }
}

export function writePrivacyMaskPref(enabled: boolean): void {
  if (typeof window === 'undefined') return;
  try {
    window.localStorage.setItem(PRIVACY_MASK_STORAGE_KEY, enabled ? '1' : '0');
  } catch {
    // ignore storage failures (private browsing)
  }
  window.dispatchEvent(new CustomEvent<boolean>(PRIVACY_MASK_EVENT, { detail: enabled }));
}

/**
 * Full IP redaction: replaces IPv4/IPv6/CIDR/host strings with solid dots so
 * zero prefix octets or subnet fingerprints remain visible in screenshots.
 */
export function maskFullIP(ip?: string, masked?: boolean): string {
  const clean = (ip || '').trim();
  if (!clean) return '-';
  if (!masked) return clean;
  return '••••••••';
}

export function maskSensitiveText(val?: string, masked?: boolean, placeholder = '已遮挡'): string {
  const clean = (val || '').trim();
  if (!clean) return '';
  if (!masked) return clean;
  return placeholder;
}

const IPV4_CIDR_PORT_RE = /\b(?:\d{1,3}\.){3}\d{1,3}(?:\/\d{1,2})?(?::\d{1,5})?\b/g;
const IPV6_CIDR_RE = /\[?(?:[0-9a-fA-F]{0,4}::[0-9a-fA-F:]{0,39}|(?:[0-9a-fA-F]{1,4}:){3,7}[0-9a-fA-F]{0,4})(?:\/\d{1,3})?\]?(?::\d{1,5})?/g;
const TS_KEY_RE = /\btskey-[A-Za-z0-9_-]+\b/g;

export function redactInlineSensitive(text?: string, masked?: boolean): string {
  if (!text) return '';
  if (!masked) return text;
  return text
    .replace(TS_KEY_RE, '[已遮挡密钥]')
    .replace(IPV4_CIDR_PORT_RE, '[已遮挡]')
    .replace(IPV6_CIDR_RE, '[已遮挡]');
}

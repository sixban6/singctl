import { AdGuardUpstreamMode } from '../../types';

export function formatNumber(n: number): string {
  if (!Number.isFinite(n)) return '0';
  return n.toLocaleString('zh-CN');
}

export function formatDurationSec(totalSec: number): string {
  const s = Math.max(0, Math.floor(totalSec));
  const m = Math.floor(s / 60);
  const rem = s % 60;
  if (m >= 60) {
    const h = Math.floor(m / 60);
    const rm = m % 60;
    return `${h} 小时 ${rm} 分 ${rem} 秒`;
  }
  if (m > 0) return `${m} 分 ${rem.toString().padStart(2, '0')} 秒`;
  return `${rem} 秒`;
}

export const UPSTREAM_MODE_OPTIONS: { key: AdGuardUpstreamMode; label: string; shortDesc: string }[] = [
  { key: 'parallel', label: '并行竞速 (推荐)', shortDesc: '同时请求全部上游，每次自动采用最快返回' },
  { key: 'fastest_addr', label: '最快 IP 优选', shortDesc: '并发查询并优选网络延迟最低的目标地址' },
  { key: 'load_balance', label: '负载均衡', shortDesc: '按响应质量在多条加密上游间动态分摊' },
];

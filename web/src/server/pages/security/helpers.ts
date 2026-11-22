import { AuditLogItem, HealStatusReport } from '../../types';

export function inferAuditCategory(log: AuditLogItem): string {
  if (log.category) return log.category;
  const act = log.action || '';
  if (act.includes('登录') || act.includes('密码') || act.includes('凭证') || act.includes('路径')) return 'login';
  if (
    act.includes('拉黑') ||
    act.includes('封禁') ||
    act.includes('解封') ||
    act.includes('自愈') ||
    act.includes('抗探测') ||
    act.includes('快照')
  )
    return 'security';
  if (act.includes('舰队') || act.includes('子节点')) return 'fleet';
  if (act.includes('订阅')) return 'subscription';
  return 'service';
}

export function generateRandomStrongPassword(): string {
  const upper = 'ABCDEFGHJKLMNPQRSTUVWXYZ';
  const lower = 'abcdefghijkmnopqrstuvwxyz';
  const digits = '23456789';
  const symbols = '!@#$%^&*-_=+';

  const pickRandom = (charset: string, count: number): string[] => {
    const arr = new Uint32Array(count);
    window.crypto.getRandomValues(arr);
    return Array.from(arr, (v) => charset[v % charset.length]);
  };

  const chars = [
    ...pickRandom(upper, 3),
    ...pickRandom(lower, 5),
    ...pickRandom(digits, 4),
    ...pickRandom(symbols, 4),
  ];

  const shuffleBuf = new Uint32Array(chars.length);
  window.crypto.getRandomValues(shuffleBuf);
  for (let i = chars.length - 1; i > 0; i--) {
    const j = shuffleBuf[i] % (i + 1);
    [chars[i], chars[j]] = [chars[j], chars[i]];
  }

  return chars.join('');
}

export function computePostureBadge(healStatus: HealStatusReport | null): { cls: string; text: string } {
  if (!healStatus) return { cls: 'bg-slate-800 text-slate-300 border-slate-700', text: '正在扫描...' };
  if (healStatus.posture === 'healthy') {
    return {
      cls: 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30',
      text: healStatus.postureLabel || '三层防线已全面免疫',
    };
  }
  if (healStatus.posture === 'reboot_required') {
    return {
      cls: 'bg-sky-500/15 text-sky-200 border-sky-500/30',
      text: healStatus.postureLabel || '补丁已装·待滚动重启生效',
    };
  }
  return {
    cls: 'bg-amber-500/15 text-amber-200 border-amber-500/30',
    text: healStatus.postureLabel || '发现待修复安全更新',
  };
}

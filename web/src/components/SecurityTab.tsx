import React, { useEffect, useState } from 'react';
import { ServerStatusResponse } from '../types';
import { Badge, PageHeader, SegmentedTabs } from '../ui';
import { SnifferGuardSubTab } from './security/SnifferGuardSubTab';
import { StealthAccessSubTab } from './security/StealthAccessSubTab';
import { SelfHealSubTab } from './security/SelfHealSubTab';
import { AdminBackupSubTab } from './security/AdminBackupSubTab';

export const SECURITY_SUB_TABS = ['sniffer', 'stealth', 'heal', 'admin'] as const;
export type SecuritySubTabKey = (typeof SECURITY_SUB_TABS)[number];

const SUB_TAB_ITEMS: { key: SecuritySubTabKey; label: string }[] = [
  { key: 'sniffer', label: '嗅探防御与审计' },
  { key: 'stealth', label: '隐蔽入口' },
  { key: 'heal', label: '三层自愈' },
  { key: 'admin', label: '账号 · 证书 · 灾备' },
];

function normalizeSubTab(raw?: string): SecuritySubTabKey {
  return (SECURITY_SUB_TABS as readonly string[]).includes(raw || '')
    ? (raw as SecuritySubTabKey)
    : 'sniffer';
}

interface SecurityTabProps {
  status: ServerStatusResponse | null;
  onRefresh: () => void;
  sub?: string;
  onChangeSub?: (sub: SecuritySubTabKey) => void;
}

export const SecurityTab: React.FC<SecurityTabProps> = ({
  status,
  onRefresh,
  sub,
  onChangeSub,
}) => {
  const [activeSub, setActiveSub] = useState<SecuritySubTabKey>(() => normalizeSubTab(sub));

  useEffect(() => {
    if (sub !== undefined) {
      setActiveSub(normalizeSubTab(sub));
    }
  }, [sub]);

  const handleSelectSub = (next: string) => {
    const valid = normalizeSubTab(next);
    setActiveSub(valid);
    onChangeSub?.(valid);
  };

  return (
    <div className="space-y-5">
      <PageHeader
        title="安全与隐身治理中心"
        description="主动嗅探对抗、无特征随机入口、三层自动漏洞自愈与 AES-256-GCM 加密灾备"
        badge={
          <Badge
            tone={status?.services?.caddy?.running ? 'ok' : 'warn'}
            dot={Boolean(status?.services?.caddy?.running)}
          >
            {status?.services?.caddy?.running ? 'Caddy 隐身保护运行中' : 'Caddy 反代离线'}
          </Badge>
        }
      />

      <SegmentedTabs items={SUB_TAB_ITEMS} value={activeSub} onChange={handleSelectSub} />

      {activeSub === 'sniffer' && <SnifferGuardSubTab status={status} />}
      {activeSub === 'stealth' && <StealthAccessSubTab status={status} />}
      {activeSub === 'heal' && <SelfHealSubTab onRefresh={onRefresh} />}
      {activeSub === 'admin' && <AdminBackupSubTab status={status} onRefresh={onRefresh} />}
    </div>
  );
};

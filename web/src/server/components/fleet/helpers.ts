import { FleetAuthType, FleetBootstrapInput, FleetNode, FleetSummary } from '../../types';

export type ModalMode = 'existing' | 'bootstrap';

export const DEFAULT_SUMMARY: FleetSummary = {
  total: 0,
  online: 0,
  totalSyncedEndpoints: 0,
  avgDoctorScore: 0,
};

export const FLEET_PROBE_COOLDOWN_MS = 45_000;

export interface CachedFleetList {
  nodes: FleetNode[];
  summary: FleetSummary;
}

export function authTypeLabel(t: FleetAuthType): string {
  switch (t) {
    case 'inline_key':
      return '托管私钥 (0600)';
    case 'key_file':
      return '主控免密密钥';
    case 'ssh_alias':
      return 'SSH Config 别名';
    case 'password':
      return 'SSH 密码认证';
    default:
      return t;
  }
}

export function createInitialFleetForm(mode: ModalMode = 'bootstrap', defaultTargetSshPort = 2222): FleetBootstrapInput {
  return {
    id: '',
    name: '',
    host: '',
    port: mode === 'bootstrap' ? 22 : 2222,
    user: 'root',
    authType: mode === 'bootstrap' ? 'password' : 'inline_key',
    sshAlias: '',
    keyPath: '~/.ssh/id_ed25519',
    privateKey: '',
    password: '',
    autoSync: true,
    nodeDomain: '',
    substoreDomain: '',
    cfDnsKey: '',
    nodeTag: '',
    sni: '',
    hardenSsh: true,
    targetSshPort: defaultTargetSshPort,
    extraAuthorizedKeys: '',
  };
}

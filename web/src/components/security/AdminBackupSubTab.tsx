import React, { useEffect, useState } from 'react';
import {
  Check,
  Copy,
  Dices,
  Download,
  Eye,
  EyeOff,
  Globe,
  KeyRound,
  Lock,
  RefreshCw,
  Upload,
  X,
} from 'lucide-react';
import { api } from '../../api';
import { CertHealthItem, ServerStatusResponse } from '../../types';
import { Badge, Button, ConfirmDialog, SectionCard, useToast } from '../../ui';

interface AdminBackupSubTabProps {
  status: ServerStatusResponse | null;
  onRefresh: () => void;
}

export const AdminBackupSubTab: React.FC<AdminBackupSubTabProps> = ({ status, onRefresh }) => {
  const { success, error } = useToast();

  // Credentials state
  const [currentPassword, setCurrentPassword] = useState('');
  const [newUsername, setNewUsername] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [showNewPassword, setShowNewPassword] = useState(false);
  const [loadingCreds, setLoadingCreds] = useState(false);

  // Certs & Backup state
  const [certs, setCerts] = useState<CertHealthItem[]>(status?.certs || []);
  const [loadingCerts, setLoadingCerts] = useState(false);
  const [backupPassphrase, setBackupPassphrase] = useState('');
  const [exportingBackup, setExportingBackup] = useState(false);
  const [restorePassphrase, setRestorePassphrase] = useState('');
  const [restoreFileContent, setRestoreFileContent] = useState('');
  const [restoreFileName, setRestoreFileName] = useState('');
  const [restoringBackup, setRestoringBackup] = useState(false);
  const [confirmRestore, setConfirmRestore] = useState(false);

  useEffect(() => {
    if (status?.certs) {
      setCerts(status.certs);
    }
  }, [status?.certs]);

  const hasMinLength = newPassword.length >= 8;
  const hasUpper = /[A-Z]/.test(newPassword);
  const hasLower = /[a-z]/.test(newPassword);
  const hasDigit = /[0-9]/.test(newPassword);
  const isPasswordValid = hasMinLength && hasUpper && hasLower && hasDigit;

  const handleGenerateRandomPassword = async () => {
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

    const generated = chars.join('');
    setNewPassword(generated);
    setConfirmPassword(generated);
    setShowNewPassword(true);

    try {
      await navigator.clipboard.writeText(generated);
      success('已生成 16 位随机强密码并复制到剪贴板，请输入当前密码后保存');
    } catch {
      success('已生成 16 位随机强密码并填入输入框，请复制保存');
    }
  };

  const handleCopyNewPassword = async () => {
    if (!newPassword) return;
    try {
      await navigator.clipboard.writeText(newPassword);
      success('新管理密码已复制到剪贴板');
    } catch {
      error('复制失败，请手动选中复制');
    }
  };

  const handleUpdateCreds = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!currentPassword) {
      error('请输入当前管理密码以验证身份');
      return;
    }
    if (newUsername.trim().toLowerCase() === 'admin') {
      error('管理账号禁止使用默认 admin，请指定专属个性化用户名');
      return;
    }
    if (!isPasswordValid) {
      error('新密码必须至少8位且同时包含大写字母、小写字母和数字');
      return;
    }
    if (newPassword !== confirmPassword) {
      error('两次输入的新密码不一致');
      return;
    }

    setLoadingCreds(true);
    try {
      const res = await api.updateCredentials({
        currentPassword,
        newUsername: newUsername.trim() || status?.admin?.username || 'singctl',
        newPassword,
      });
      success(res.message);
      setCurrentPassword('');
      setNewPassword('');
      setConfirmPassword('');
      onRefresh();
    } catch (err: unknown) {
      error(err instanceof Error ? err.message : '更新凭据失败');
    } finally {
      setLoadingCreds(false);
    }
  };

  const fetchCerts = async (force = true) => {
    setLoadingCerts(true);
    try {
      const res = await api.getCerts(force);
      setCerts(res.certs || []);
    } catch (err: unknown) {
      error(err instanceof Error ? err.message : '读取证书状态失败');
    } finally {
      setLoadingCerts(false);
    }
  };

  const handleExportBackup = async () => {
    const pass = backupPassphrase.trim();
    if (pass.length < 8) {
      error('备份加密口令长度至少需要 8 位字符');
      return;
    }
    setExportingBackup(true);
    try {
      const res = await api.exportBackup(pass);
      const blob = new Blob([res.data], { type: 'application/json;charset=utf-8' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = res.filename || 'singctl-master-backup.enc.json';
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
      success(res.message || '加密灾备快照已下载');
      setBackupPassphrase('');
    } catch (err: unknown) {
      error(err instanceof Error ? err.message : '导出加密快照失败');
    } finally {
      setExportingBackup(false);
    }
  };

  const handleSelectRestoreFile = (e: React.ChangeEvent<HTMLInputElement>) => {
    const f = e.target.files?.[0];
    if (!f) return;
    setRestoreFileName(f.name);
    const reader = new FileReader();
    reader.onload = () => {
      setRestoreFileContent(typeof reader.result === 'string' ? reader.result : '');
    };
    reader.readAsText(f);
  };

  const executeRestoreBackup = async () => {
    setConfirmRestore(false);
    const pass = restorePassphrase.trim();
    if (pass.length < 8 || !restoreFileContent.trim()) {
      error('请先选择加密快照文件并输入至少 8 位解密口令');
      return;
    }
    setRestoringBackup(true);
    try {
      const res = await api.restoreBackup(pass, restoreFileContent);
      success(res.message || '灾备快照已成功恢复');
      setRestorePassphrase('');
      setRestoreFileContent('');
      setRestoreFileName('');
      onRefresh();
    } catch (err: unknown) {
      error(err instanceof Error ? err.message : '恢复灾备快照失败');
    } finally {
      setRestoringBackup(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Admin Credentials */}
      <SectionCard
        title="修改管理员账号与强密码"
        subtitle="禁止使用默认 admin，密码需严格满足至少 8 位并包含大小写字母与数字"
        icon={<KeyRound className="w-4 h-4" />}
      >
        <form onSubmit={handleUpdateCreds} className="space-y-4 max-w-xl">
          <div>
            <label className="block text-xs font-medium text-secondary mb-1.5">
              当前管理密码 <span className="text-rose-400">*</span>
            </label>
            <input
              type="password"
              value={currentPassword}
              onChange={(e) => setCurrentPassword(e.target.value)}
              placeholder="输入当前密码以确认身份"
              required
              className="sc-input w-full px-3.5 py-2 text-xs font-mono"
            />
          </div>

          <div>
            <label className="block text-xs font-medium text-secondary mb-1.5">
              新管理员用户名（当前:{' '}
              <span className="font-mono text-accent">{status?.admin?.username}</span>）
            </label>
            <input
              type="text"
              value={newUsername}
              onChange={(e) => setNewUsername(e.target.value)}
              placeholder="自定义专属账号 (禁止为 admin)"
              className="sc-input w-full px-3.5 py-2 text-xs font-mono"
            />
          </div>

          <div>
            <div className="flex flex-wrap items-center justify-between gap-2 mb-1.5">
              <label className="block text-xs font-medium text-secondary">
                新管理密码 <span className="text-rose-400">*</span>
              </label>
              <div className="flex items-center gap-1.5">
                <Button
                  type="button"
                  size="xs"
                  variant="secondary"
                  onClick={handleGenerateRandomPassword}
                  icon={<Dices className="w-3.5 h-3.5" />}
                >
                  随机生成强密码
                </Button>
                <Button
                  type="button"
                  size="xs"
                  variant="ghost"
                  onClick={() => setShowNewPassword((v) => !v)}
                  icon={
                    showNewPassword ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />
                  }
                >
                  {showNewPassword ? '隐藏' : '明文'}
                </Button>
                {newPassword && (
                  <Button
                    type="button"
                    size="xs"
                    variant="ghost"
                    onClick={handleCopyNewPassword}
                    icon={<Copy className="w-3.5 h-3.5" />}
                  >
                    复制
                  </Button>
                )}
              </div>
            </div>
            <input
              type={showNewPassword ? 'text' : 'password'}
              value={newPassword}
              onChange={(e) => setNewPassword(e.target.value)}
              placeholder="至少 8 位，包含大写、小写、数字"
              required
              className="sc-input w-full px-3.5 py-2 text-xs font-mono"
            />
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 mt-2.5 text-[11px] font-mono">
              {[
                { ok: hasMinLength, label: '长度 ≥ 8 位' },
                { ok: hasUpper, label: '包含大写字母' },
                { ok: hasLower, label: '包含小写字母' },
                { ok: hasDigit, label: '包含数字' },
              ].map((item) => (
                <div
                  key={item.label}
                  className="flex items-center gap-1"
                  style={{ color: item.ok ? 'var(--status-ok)' : 'var(--text-muted)' }}
                >
                  {item.ok ? <Check className="w-3 h-3" /> : <X className="w-3 h-3" />}
                  <span>{item.label}</span>
                </div>
              ))}
            </div>
          </div>

          <div>
            <label className="block text-xs font-medium text-secondary mb-1.5">
              确认新管理密码 <span className="text-rose-400">*</span>
            </label>
            <input
              type={showNewPassword ? 'text' : 'password'}
              value={confirmPassword}
              onChange={(e) => setConfirmPassword(e.target.value)}
              placeholder="再次输入新管理密码"
              required
              className="sc-input w-full px-3.5 py-2 text-xs font-mono"
            />
          </div>

          <div className="pt-1">
            <Button
              type="submit"
              variant="primary"
              loading={loadingCreds}
              disabled={!isPasswordValid}
              icon={<Lock className="w-3.5 h-3.5" />}
            >
              立即保存修改凭据
            </Button>
          </div>
        </form>
      </SectionCard>

      {/* TLS Certs + Encrypted Backup */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
        <SectionCard
          title="TLS 证书到期监控"
          subtitle="直读本机 Caddy 证书链与回环握手状态，剩余不足 14 天自动高亮提醒"
          icon={<Globe className="w-4 h-4" />}
          actions={
            <Button
              size="xs"
              variant="secondary"
              loading={loadingCerts}
              onClick={() => void fetchCerts(true)}
              icon={<RefreshCw className="w-3.5 h-3.5" />}
            >
              立即巡检
            </Button>
          }
        >
          <div className="space-y-2.5">
            {certs.length === 0 ? (
              <div className="p-5 text-center rounded-xl bg-surface2 border border-subtle text-xs text-muted">
                暂未配置服务端域名或点击右上角「立即巡检」获取实时证书有效期
              </div>
            ) : (
              certs.map((c) => (
                <div
                  key={c.domain}
                  className="p-3.5 rounded-xl bg-surface2 border border-subtle space-y-1.5"
                >
                  <div className="flex items-center justify-between gap-2 flex-wrap">
                    <div className="flex items-center gap-2">
                      <span className="font-mono font-semibold text-xs text-primary">{c.domain}</span>
                      <Badge tone="neutral">{c.role}</Badge>
                    </div>
                    <Badge
                      tone={
                        c.status === 'healthy'
                          ? 'ok'
                          : c.status === 'expiring'
                          ? 'warn'
                          : c.status === 'expired'
                          ? 'danger'
                          : 'neutral'
                      }
                    >
                      {c.status === 'healthy'
                        ? `有效 · 剩 ${c.daysRemaining} 天`
                        : c.status === 'expiring'
                        ? `即将到期 · 剩 ${c.daysRemaining} 天`
                        : c.status === 'expired'
                        ? '已过期'
                        : '未检出本地证书'}
                    </Badge>
                  </div>
                  <div className="flex flex-wrap items-center justify-between gap-2 text-[11px] text-muted">
                    <span>签发机构: {c.issuer || '-'}</span>
                    {c.notAfter && <span className="font-mono">到期: {c.notAfter}</span>}
                  </div>
                  {c.message && c.status !== 'healthy' && (
                    <div className="text-[11px]" style={{ color: 'var(--status-warn)' }}>
                      {c.message}
                    </div>
                  )}
                </div>
              ))
            )}
          </div>
        </SectionCard>

        <SectionCard
          title="主控与舰队加密快照备份 / 恢复"
          subtitle="AES-256-GCM 零明文落盘打包主控配置、SubHub 订阅源、舰队节点与 SSH 私钥"
          icon={<Lock className="w-4 h-4" />}
        >
          <div className="space-y-3.5">
            <div className="p-3.5 rounded-xl bg-surface2 border border-subtle space-y-2.5">
              <div className="text-xs font-semibold text-primary">1. 导出加密快照文件 (.enc.json)</div>
              <div className="flex flex-col sm:flex-row gap-2">
                <input
                  type="password"
                  value={backupPassphrase}
                  onChange={(e) => setBackupPassphrase(e.target.value)}
                  placeholder="设置加密口令 (至少 8 位字符，请牢记)"
                  className="sc-input flex-1 px-3 py-2 text-xs font-mono"
                />
                <Button
                  size="sm"
                  variant="primary"
                  loading={exportingBackup}
                  disabled={backupPassphrase.trim().length < 8}
                  onClick={handleExportBackup}
                  icon={<Download className="w-3.5 h-3.5" />}
                >
                  加密导出快照
                </Button>
              </div>
            </div>

            <div className="p-3.5 rounded-xl bg-surface2 border border-subtle space-y-2.5">
              <div className="flex items-center justify-between gap-2">
                <span className="text-xs font-semibold text-primary">2. 从加密快照恢复迁移</span>
                <label className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-surface1 hover:border-strong border border-subtle text-[11px] text-primary cursor-pointer transition-colors">
                  <Upload className="w-3 h-3 text-accent" />
                  <span>{restoreFileName ? `已选: ${restoreFileName}` : '选择 .enc.json 文件'}</span>
                  <input
                    type="file"
                    accept=".json,application/json"
                    onChange={handleSelectRestoreFile}
                    className="hidden"
                  />
                </label>
              </div>
              <div className="flex flex-col sm:flex-row gap-2">
                <input
                  type="password"
                  value={restorePassphrase}
                  onChange={(e) => setRestorePassphrase(e.target.value)}
                  placeholder="输入导出时设置的解密口令"
                  className="sc-input flex-1 px-3 py-2 text-xs font-mono"
                />
                <Button
                  size="sm"
                  variant="secondary"
                  loading={restoringBackup}
                  disabled={!restoreFileContent || restorePassphrase.trim().length < 8}
                  onClick={() => setConfirmRestore(true)}
                  icon={<Upload className="w-3.5 h-3.5" />}
                >
                  解密并恢复
                </Button>
              </div>
            </div>
          </div>
        </SectionCard>
      </div>

      <ConfirmDialog
        open={confirmRestore}
        title={`确认使用快照「${restoreFileName || '加密快照'}」覆盖恢复？`}
        description="将恢复本机配置、舰队节点清单、SSH 管理私钥与聚合订阅源；恢复前系统会自动以 0600 权限备份现有配置文件。"
        confirmText="确认恢复迁移"
        danger
        onConfirm={() => void executeRestoreBackup()}
        onCancel={() => setConfirmRestore(false)}
      />
    </div>
  );
};

import React, { useState } from 'react';
import { CertHealthItem } from '../../types';
import { api } from '../../api';
import { useToast } from '../../../ui';
import { Download, Globe, Lock, RefreshCw, Upload } from 'lucide-react';

export const CertAndBackupGrid: React.FC<{
  certs: CertHealthItem[];
  loadingCerts: boolean;
  onRefreshCerts: () => void;
  onRefreshParent: () => void;
  onRefreshAuditLogs: () => void;
}> = ({ certs, loadingCerts, onRefreshCerts, onRefreshParent, onRefreshAuditLogs }) => {
  const { success, error } = useToast();
  const [backupPassphrase, setBackupPassphrase] = useState('');
  const [exportingBackup, setExportingBackup] = useState(false);
  const [restorePassphrase, setRestorePassphrase] = useState('');
  const [restoreFileContent, setRestoreFileContent] = useState('');
  const [restoreFileName, setRestoreFileName] = useState('');
  const [restoringBackup, setRestoringBackup] = useState(false);

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
      onRefreshAuditLogs();
    } catch (err: any) {
      error(err.message || '导出加密快照失败');
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

  const handleRestoreBackup = async () => {
    const pass = restorePassphrase.trim();
    if (pass.length < 8 || !restoreFileContent.trim()) {
      error('请先选择加密快照文件并输入至少 8 位解密口令');
      return;
    }
    if (
      !window.confirm(
        `确定要使用快照文件「${restoreFileName || '加密快照'}」恢复本机配置、舰队节点与聚合订阅吗？\n\n恢复前系统会自动以 0600 权限备份现有配置文件。`,
      )
    ) {
      return;
    }
    setRestoringBackup(true);
    try {
      const res = await api.restoreBackup(pass, restoreFileContent);
      success(res.message || '灾备快照已成功恢复');
      setRestorePassphrase('');
      setRestoreFileContent('');
      setRestoreFileName('');
      onRefreshParent();
      onRefreshAuditLogs();
    } catch (err: any) {
      error(err.message || '恢复灾备快照失败');
    } finally {
      setRestoringBackup(false);
    }
  };

  return (
    <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
      {/* TLS Certificate Health Card */}
      <div className="p-4 sm:p-6 rounded-2xl glass-card flex flex-col justify-between">
        <div>
          <div className="flex items-center justify-between gap-2 pb-4 border-b border-slate-800">
            <div>
              <div className="flex items-center gap-2 text-cyan-400 text-xs font-semibold uppercase tracking-wider mb-1">
                <Globe className="w-3.5 h-3.5" />
                <span>ACME 证书健康与续签预警</span>
              </div>
              <h3 className="text-lg font-bold text-white tracking-tight">TLS 证书到期监控</h3>
              <p className="text-xs text-slate-400 mt-0.5">
                直读本机 Caddy 证书链与回环握手状态，剩余不足 14 天自动高亮提醒
              </p>
            </div>
            <button
              type="button"
              onClick={onRefreshCerts}
              disabled={loadingCerts}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-xl bg-slate-900 hover:bg-slate-800 border border-slate-800 text-xs text-slate-300 transition-all shrink-0 disabled:opacity-50"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${loadingCerts ? 'animate-spin' : ''}`} />
              <span>立即巡检</span>
            </button>
          </div>

          <div className="mt-4 space-y-2.5">
            {certs.length === 0 ? (
              <div className="p-5 text-center rounded-xl bg-slate-950/40 border border-slate-800/80 text-xs text-slate-400">
                暂未配置服务端域名或点击右上角「立即巡检」获取实时证书有效期
              </div>
            ) : (
              certs.map((c) => {
                const statusBadge =
                  c.status === 'healthy'
                    ? 'bg-emerald-500/10 text-emerald-300 border-emerald-500/25'
                    : c.status === 'expiring'
                    ? 'bg-amber-500/15 text-amber-300 border-amber-500/30'
                    : c.status === 'expired'
                    ? 'bg-rose-500/20 text-rose-300 border-rose-500/35'
                    : 'bg-slate-800 text-slate-400 border-slate-700';
                return (
                  <div
                    key={c.domain}
                    className="p-3.5 rounded-xl bg-slate-950/60 border border-slate-800/80 space-y-1.5"
                  >
                    <div className="flex items-center justify-between gap-2 flex-wrap">
                      <div className="flex items-center gap-2">
                        <span className="font-mono font-semibold text-xs text-white">{c.domain}</span>
                        <span className="px-2 py-0.5 rounded bg-slate-900 border border-slate-800 text-[10px] text-slate-400">
                          {c.role}
                        </span>
                      </div>
                      <span className={`px-2 py-0.5 rounded-md border text-[11px] font-mono font-semibold ${statusBadge}`}>
                        {c.status === 'healthy'
                          ? `有效 · 剩余 ${c.daysRemaining} 天`
                          : c.status === 'expiring'
                          ? `即将到期 · 剩 ${c.daysRemaining} 天`
                          : c.status === 'expired'
                          ? '已过期'
                          : '未检出本地证书'}
                      </span>
                    </div>
                    <div className="flex flex-wrap items-center justify-between gap-2 text-[11px] text-slate-400">
                      <span>签发机构: {c.issuer || '-'}</span>
                      {c.notAfter && <span className="font-mono">到期: {c.notAfter}</span>}
                    </div>
                    {c.message && c.status !== 'healthy' && (
                      <div className="text-[11px] text-amber-300">{c.message}</div>
                    )}
                  </div>
                );
              })
            )}
          </div>
        </div>
      </div>

      {/* Encrypted Disaster-Recovery Backup & Restore Card */}
      <div className="p-4 sm:p-6 rounded-2xl glass-card flex flex-col justify-between">
        <div>
          <div className="pb-4 border-b border-slate-800">
            <div className="flex items-center gap-2 text-emerald-400 text-xs font-semibold uppercase tracking-wider mb-1">
              <Lock className="w-3.5 h-3.5" />
              <span>AES-256-GCM 零明文落盘灾备</span>
            </div>
            <h3 className="text-lg font-bold text-white tracking-tight">主控与舰队加密快照备份 / 恢复</h3>
            <p className="text-xs text-slate-400 mt-0.5">
              一键加密打包主控配置、SubHub 全部订阅源、舰队节点清单与 SSH 管理私钥；换机时上传即可满血迁移
            </p>
          </div>

          <div className="mt-4 space-y-3">
            {/* Export Box */}
            <div className="p-3.5 rounded-xl bg-slate-950/60 border border-slate-800/80 space-y-2.5">
              <div className="text-xs font-semibold text-slate-200">1. 导出加密快照文件 (.enc.json)</div>
              <div className="flex flex-col sm:flex-row gap-2">
                <input
                  type="password"
                  value={backupPassphrase}
                  onChange={(e) => setBackupPassphrase(e.target.value)}
                  placeholder="设置加密口令 (至少 8 位字符，请牢记)"
                  className="flex-1 bg-slate-900 border border-slate-800 rounded-xl px-3 py-2 text-xs text-white placeholder:text-slate-500 focus:outline-none focus:border-emerald-500 font-mono"
                />
                <button
                  type="button"
                  onClick={handleExportBackup}
                  disabled={exportingBackup || backupPassphrase.trim().length < 8}
                  className="inline-flex items-center justify-center gap-1.5 px-4 py-2 rounded-xl bg-emerald-500 hover:bg-emerald-600 text-slate-950 text-xs font-bold transition-all shrink-0 disabled:opacity-50"
                >
                  <Download className="w-3.5 h-3.5" />
                  <span>{exportingBackup ? '正在加密导出...' : '加密导出快照'}</span>
                </button>
              </div>
            </div>

            {/* Restore Box */}
            <div className="p-3.5 rounded-xl bg-slate-950/60 border border-slate-800/80 space-y-2.5">
              <div className="flex items-center justify-between gap-2">
                <span className="text-xs font-semibold text-slate-200">2. 从加密快照恢复迁移</span>
                <label className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-700 text-[11px] text-slate-200 cursor-pointer transition-colors">
                  <Upload className="w-3 h-3 text-sky-400" />
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
                  className="flex-1 bg-slate-900 border border-slate-800 rounded-xl px-3 py-2 text-xs text-white placeholder:text-slate-500 focus:outline-none focus:border-sky-500 font-mono"
                />
                <button
                  type="button"
                  onClick={handleRestoreBackup}
                  disabled={restoringBackup || !restoreFileContent || restorePassphrase.trim().length < 8}
                  className="inline-flex items-center justify-center gap-1.5 px-4 py-2 rounded-xl bg-sky-500/20 hover:bg-sky-500/30 border border-sky-500/35 text-sky-200 text-xs font-semibold transition-all shrink-0 disabled:opacity-50"
                >
                  <Upload className="w-3.5 h-3.5" />
                  <span>{restoringBackup ? '正在解密恢复...' : '解密并恢复'}</span>
                </button>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

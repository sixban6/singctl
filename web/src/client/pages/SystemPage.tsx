import React, { useRef, useState } from 'react';
import {
  Cpu,
  Copy,
  Download,
  Gauge,
  LogOut,
  RefreshCw,
  ShieldCheck,
  Smartphone,
  Upload,
} from 'lucide-react';
import {
  Badge,
  Button,
  ConfirmDialog,
  PageHeader,
  QRCodeBox,
  SectionCard,
  SlideDrawer,
  useToast,
} from '../../ui';
import { clientApi } from '../api';
import { ClientStatusResponse } from '../types';

export interface SystemPageProps {
  status: ClientStatusResponse | null;
  busy: boolean;
  onAction: (name: string, params?: Record<string, unknown>, confirmMsg?: string) => void;
  onRestored?: () => void;
}

export const SystemPage: React.FC<SystemPageProps> = ({ status, busy, onAction, onRestored }) => {
  const { success, error } = useToast();
  const [pwaOpen, setPwaOpen] = useState(false);
  const [pwaUrl, setPwaUrl] = useState('');
  const [pwaLoading, setPwaLoading] = useState(false);
  const [logoutOpen, setLogoutOpen] = useState(false);

  // 网关全量配置加密备份与还原
  const [exportPass, setExportPass] = useState('');
  const [exporting, setExporting] = useState(false);
  const [restoreFileName, setRestoreFileName] = useState('');
  const [restoreData, setRestoreData] = useState('');
  const [restorePass, setRestorePass] = useState('');
  const [restoring, setRestoring] = useState(false);
  const [restoreConfirmOpen, setRestoreConfirmOpen] = useState(false);
  const fileInputRef = useRef<HTMLInputElement | null>(null);

  const openPwaDrawer = async () => {
    setPwaOpen(true);
    if (pwaUrl) return;
    setPwaLoading(true);
    try {
      const res = await clientApi.getSessionUrl();
      setPwaUrl(res.url);
    } catch {
      try {
        const token = localStorage.getItem('sc_token');
        const u = new URL(window.location.origin + window.location.pathname);
        if (token) u.searchParams.set('token', token);
        setPwaUrl(u.toString());
      } catch (err: unknown) {
        error(err instanceof Error ? err.message : '生成免密地址失败');
      }
    } finally {
      setPwaLoading(false);
    }
  };

  const copyPwaUrl = async () => {
    if (!pwaUrl) return;
    try {
      await navigator.clipboard.writeText(pwaUrl);
      success('已复制免密访问链接！用 iPhone Safari 打开「添加到主屏幕」即可免输密码');
    } catch {
      error('复制失败，请手动选中复制');
    }
  };

  const doLogout = async () => {
    try {
      await clientApi.logout();
      localStorage.removeItem('sc_token');
      window.location.href = '/';
    } catch (err: unknown) {
      error(err instanceof Error ? err.message : '退出失败');
    }
  };

  const handleExportBackup = async (e: React.FormEvent) => {
    e.preventDefault();
    const pass = exportPass.trim();
    if (pass.length < 8) {
      error('备份加密口令长度至少需要 8 位字符');
      return;
    }
    setExporting(true);
    try {
      const res = await clientApi.exportBackup(pass);
      const blob = new Blob([res.data], { type: 'application/json;charset=utf-8' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = res.filename || 'singctl-client-backup.enc.json';
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);

      const included: string[] = [];
      if (res.summary?.hasSingctlCfg) included.push('主配置');
      if (res.summary?.hasGroups) included.push('分组编排');
      if (res.summary?.hasAdGuard) included.push('AdGuard');
      if (res.summary?.hasSingBox) included.push('sing-box');
      success(
        `${res.message || '加密备份快照已下载'}${included.length ? `（已打包: ${included.join(' / ')}）` : ''}`,
      );
      setExportPass('');
    } catch (err: unknown) {
      error(`导出加密备份失败：${err instanceof Error ? err.message : '未知错误'}`);
    } finally {
      setExporting(false);
    }
  };

  const handleSelectRestoreFile = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    e.target.value = '';
    if (!file) return;
    if (file.size > 4 * 1024 * 1024) {
      error('备份文件过大（不能超过 4 MB）');
      return;
    }
    try {
      const text = await file.text();
      setRestoreFileName(file.name);
      setRestoreData(text);
    } catch (err: unknown) {
      error(`读取备份文件失败：${err instanceof Error ? err.message : '未知错误'}`);
    }
  };

  const handlePrepareRestore = (e: React.FormEvent) => {
    e.preventDefault();
    if (!restoreData.trim()) {
      error('请先选择要恢复的加密备份快照 (.enc.json)');
      return;
    }
    if (restorePass.trim().length < 8) {
      error('解密口令长度至少需要 8 位字符');
      return;
    }
    setRestoreConfirmOpen(true);
  };

  const handleConfirmRestore = async () => {
    setRestoring(true);
    try {
      const res = await clientApi.restoreBackup(restorePass.trim(), restoreData);
      setRestoreConfirmOpen(false);
      setRestorePass('');
      setRestoreData('');
      setRestoreFileName('');
      success(res.message || '网关加密备份快照已恢复并热应用生效');
      onRestored?.();
    } catch (err: unknown) {
      error(`恢复备份失败：${err instanceof Error ? err.message : '未知错误'}`);
    } finally {
      setRestoring(false);
    }
  };

  const h = status?.host;
  const sb = status?.singbox;
  const ts = status?.tailscale;

  return (
    <div className="space-y-5">
      <PageHeader
        title="系统与维护"
        description="软件版本升级、链路带宽测速、网关加密灾备迁移与会话安全"
        actions={
          status?.authEnabled ? (
            <Button
              size="sm"
              variant="danger"
              onClick={() => setLogoutOpen(true)}
              icon={<LogOut className="w-3.5 h-3.5" />}
            >
              退出登录
            </Button>
          ) : undefined
        }
      />

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <SectionCard title="组件版本与运行环境" icon={<Cpu className="w-4 h-4" />}>
          <div className="divide-y divide-[var(--border-subtle)] text-xs sm:text-sm">
            {[
              ['SingCtl 版本', `v${String(status?.singctlVersion || 'dev').replace(/^v/, '')}`],
              ['sing-box 内核', sb?.installed ? (sb.version ? `v${sb.version}` : '已安装') : '未安装'],
              ['Tailscale', ts?.installed ? (ts.version ? `v${ts.version}` : '已安装') : '未安装'],
              ['singctl 配置路径', status?.config?.path || '-'],
              ['sing-box 配置路径', sb?.configPath || '-'],
              ['运行平台', h ? `${h.os}/${h.arch}${h.openwrt ? ' · OpenWrt' : ''}` : '-'],
            ].map(([k, v]) => (
              <div key={k} className="flex items-center justify-between py-2.5 gap-3">
                <span className="text-secondary shrink-0">{k}</span>
                <span className="font-mono text-primary truncate tnum">{v}</span>
              </div>
            ))}
          </div>
        </SectionCard>

        <div className="space-y-4">
          <SectionCard title="软件在线自更新" icon={<RefreshCw className="w-4 h-4" />}>
            <p className="text-xs sm:text-sm text-secondary mb-3">
              从 GitHub Release 拉取最新二进制并核验 SHA-256，更新完成后自动平滑热重启 WebUI 服务。
            </p>
            <Button variant="primary" disabled={busy} onClick={() => onAction('update-self')}>
              检查并更新 singctl
            </Button>
          </SectionCard>

          <SectionCard title="全链路带宽测速" icon={<Gauge className="w-4 h-4" />}>
            <p className="text-xs sm:text-sm text-secondary mb-3">
              测试当前网关代理出口上下行实际带宽（耗时约 1 分钟，在实时终端抽屉查看进度）。
            </p>
            <div className="flex flex-wrap gap-2.5">
              <Button disabled={busy} onClick={() => onAction('speedtest')}>
                开始带宽测速
              </Button>
              <Button variant="secondary" onClick={openPwaDrawer} icon={<Smartphone className="w-3.5 h-3.5" />}>
                手机主屏幕免密二维码
              </Button>
            </div>
          </SectionCard>
        </div>
      </div>

      {/* 网关配置全量 AES-256-GCM 加密备份与一键迁移还原 */}
      <SectionCard
        title="网关配置加密备份与迁移"
        icon={<ShieldCheck className="w-4 h-4" />}
        subtitle="PBKDF2 + AES-256-GCM 内存中强加密 · 一键备份并在刷机/换机后完整恢复"
        actions={<Badge tone="ok">AES-256-GCM</Badge>}
      >
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          <form
            onSubmit={(e) => void handleExportBackup(e)}
            className="p-4 rounded-xl bg-surface2 border border-subtle space-y-3"
          >
            <div className="space-y-1">
              <div className="text-sm font-medium text-primary">导出加密备份包</div>
              <p className="text-xs text-secondary leading-relaxed">
                自动打包 <code className="font-mono">singctl.yaml</code>、<code className="font-mono">groups.yaml</code>、
                <code className="font-mono">AdGuardHome.yaml</code> 与 <code className="font-mono">config.json</code>。
              </p>
            </div>
            <label className="block space-y-1 text-xs">
              <span className="text-secondary">设置加密口令（至少 8 位）</span>
              <input
                type="password"
                autoComplete="new-password"
                value={exportPass}
                onChange={(e) => setExportPass(e.target.value)}
                placeholder="输入高强度加密口令…"
                className="w-full h-9 px-3 rounded-xl bg-surface1 border border-subtle text-primary font-mono focus:outline-none focus:border-strong"
              />
            </label>
            <Button
              type="submit"
              size="sm"
              variant="primary"
              loading={exporting}
              disabled={busy || exporting}
              icon={<Download className="w-3.5 h-3.5" />}
            >
              导出加密快照 (.enc.json)
            </Button>
          </form>

          <form
            onSubmit={handlePrepareRestore}
            className="p-4 rounded-xl bg-surface2 border border-subtle space-y-3"
          >
            <div className="space-y-1">
              <div className="text-sm font-medium text-primary">从快照一键还原</div>
              <p className="text-xs text-secondary leading-relaxed">
                写入前严格校验 YAML/JSON 与 <code className="font-mono">sing-box check</code>，还原前自动备份本机原配置（0600 权限）。
              </p>
            </div>
            <div className="flex flex-wrap items-center gap-2">
              <input
                ref={fileInputRef}
                type="file"
                accept=".json,.enc.json,application/json"
                className="hidden"
                onChange={(e) => void handleSelectRestoreFile(e)}
              />
              <Button
                type="button"
                size="sm"
                variant="secondary"
                disabled={restoring || busy}
                onClick={() => fileInputRef.current?.click()}
                icon={<Upload className="w-3.5 h-3.5" />}
              >
                选择加密快照文件
              </Button>
              <span className="text-xs font-mono text-muted truncate max-w-[220px]">
                {restoreFileName || '尚未选择文件'}
              </span>
            </div>
            <label className="block space-y-1 text-xs">
              <span className="text-secondary">输入解密口令</span>
              <input
                type="password"
                autoComplete="current-password"
                value={restorePass}
                onChange={(e) => setRestorePass(e.target.value)}
                placeholder="输入导出时设置的口令…"
                className="w-full h-9 px-3 rounded-xl bg-surface1 border border-subtle text-primary font-mono focus:outline-none focus:border-strong"
              />
            </label>
            <Button
              type="submit"
              size="sm"
              loading={restoring}
              disabled={busy || restoring || !restoreData.trim()}
              icon={<ShieldCheck className="w-3.5 h-3.5" />}
            >
              校验并恢复备份
            </Button>
          </form>
        </div>
      </SectionCard>

      <SlideDrawer
        open={pwaOpen}
        onClose={() => setPwaOpen(false)}
        title="手机免密主屏幕快捷入口"
        subtitle="手机浏览器扫描打开并选择「添加到主屏幕」，即可享受 30 天免密直连"
      >
        <div className="flex flex-col items-center text-center space-y-4 py-2">
          {pwaLoading ? (
            <div className="w-44 h-44 rounded-2xl bg-surface2 animate-pulse" />
          ) : pwaUrl ? (
            <>
              <QRCodeBox value={pwaUrl} size={184} />
              <div className="w-full p-3 rounded-xl bg-surface2 border border-subtle font-mono text-xs text-primary break-all select-all">
                {pwaUrl}
              </div>
              <Button variant="primary" onClick={copyPwaUrl} icon={<Copy className="w-3.5 h-3.5" />}>
                复制免密访问链接
              </Button>
            </>
          ) : (
            <p className="text-xs text-muted">未能获取当前局域网免密链接。</p>
          )}
        </div>
      </SlideDrawer>

      <ConfirmDialog
        open={restoreConfirmOpen}
        title="确认从加密备份还原网关配置"
        description={`确认使用快照「${restoreFileName || '加密快照'}」恢复 singctl.yaml、groups.yaml 与 AdGuardHome.yaml 并无损热重载生效？覆盖前系统会自动以 0600 权限备份当前本机文件。`}
        confirmText="确认恢复并热应用"
        loading={restoring}
        onConfirm={() => void handleConfirmRestore()}
        onCancel={() => setRestoreConfirmOpen(false)}
      />

      <ConfirmDialog
        open={logoutOpen}
        title="退出当前 WebUI 会话"
        description="确认清除本地 30 天持久化免密 Cookie 并退出登录？"
        confirmText="退出登录"
        onConfirm={doLogout}
        onCancel={() => setLogoutOpen(false)}
      />
    </div>
  );
};

import React, { useEffect, useRef, useState } from 'react';
import {
  Cpu,
  Copy,
  Download,
  FileCode,
  Gauge,
  Globe,
  LogOut,
  RefreshCw,
  Save,
  ShieldCheck,
  Smartphone,
  Stethoscope,
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
import { copyToClipboard } from '../../lib/clipboard';
import { ClientStatusResponse } from '../types';
import { DoctorDrawer } from './dash/DoctorDrawer';
import { AutoStartCard } from './system/AutoStartCard';
import { NotifyConfigCard } from './system/NotifyConfigCard';
import { SafeCommitCard } from './system/SafeCommitCard';

export interface SystemPageProps {
  status: ClientStatusResponse | null;
  busy: boolean;
  onAction: (name: string, params?: Record<string, unknown>, confirmMsg?: string) => void;
  onRefreshStatus?: () => void;
  onRestored?: () => void;
}

export const SystemPage: React.FC<SystemPageProps> = ({
  status,
  busy,
  onAction,
  onRefreshStatus,
  onRestored,
}) => {
  const { success, error } = useToast();
  const [doctorOpen, setDoctorOpen] = useState(false);
  const [pwaOpen, setPwaOpen] = useState(false);
  const [pwaUrl, setPwaUrl] = useState('');
  const [pwaLoading, setPwaLoading] = useState(false);
  const [logoutOpen, setLogoutOpen] = useState(false);

  // 网关全量配置加密备份与还原
  const [exportPass, setExportPass] = useState('');
  const [includeRuleSets, setIncludeRuleSets] = useState(true);
  const [exporting, setExporting] = useState(false);
  const [restoreFileName, setRestoreFileName] = useState('');
  const [restoreData, setRestoreData] = useState('');
  const [restorePass, setRestorePass] = useState('');
  const [restoring, setRestoring] = useState(false);
  const [restoreConfirmOpen, setRestoreConfirmOpen] = useState(false);
  const fileInputRef = useRef<HTMLInputElement | null>(null);

  // 全局 GitHub 镜像加速 + singctl.yaml 高级源码抽屉
  const [mirrorUrl, setMirrorUrl] = useState('');
  const [mirrorLoading, setMirrorLoading] = useState(true);
  const [mirrorSaving, setMirrorSaving] = useState(false);
  const [rawYamlOpen, setRawYamlOpen] = useState(false);
  const [rawYamlPath, setRawYamlPath] = useState('');
  const [rawYaml, setRawYaml] = useState('');
  const [rawYamlLoading, setRawYamlLoading] = useState(false);
  const [rawYamlSaving, setRawYamlSaving] = useState(false);

  useEffect(() => {
    let cancelled = false;
    setMirrorLoading(true);
    clientApi
      .getConfig()
      .then((res) => {
        if (cancelled) return;
        setMirrorUrl(res.config?.github?.mirror_url || '');
        if (res.path) setRawYamlPath(res.path);
      })
      .catch(() => {
        // ignore transient mount read error
      })
      .finally(() => {
        if (!cancelled) setMirrorLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const handleSaveMirror = async (e: React.FormEvent) => {
    e.preventDefault();
    setMirrorSaving(true);
    try {
      const res = await clientApi.saveSystemMirror(mirrorUrl.trim());
      setMirrorUrl(res.mirrorUrl || '');
      success('GitHub 加速镜像设置已保存');
      onRestored?.();
    } catch (err: unknown) {
      error(`保存镜像地址失败：${err instanceof Error ? err.message : '未知错误'}`);
    } finally {
      setMirrorSaving(false);
    }
  };

  const openRawYamlDrawer = async () => {
    setRawYamlOpen(true);
    setRawYamlLoading(true);
    try {
      const res = await clientApi.getConfigRaw();
      setRawYamlPath(res.path || '');
      setRawYaml(res.content || '');
    } catch (err: unknown) {
      error(`读取 singctl.yaml 原文失败：${err instanceof Error ? err.message : '未知错误'}`);
    } finally {
      setRawYamlLoading(false);
    }
  };

  const handleSaveRawYaml = async () => {
    setRawYamlSaving(true);
    try {
      await clientApi.saveConfigRaw(rawYaml);
      success('YAML 配置已校验并保存（已自动备份原文件）');
      try {
        const res = await clientApi.getConfig();
        setMirrorUrl(res.config?.github?.mirror_url || '');
      } catch {
        // ignore
      }
      setRawYamlOpen(false);
      onRestored?.();
    } catch (err: unknown) {
      error(`保存 YAML 失败：${err instanceof Error ? err.message : '未知错误'}`);
    } finally {
      setRawYamlSaving(false);
    }
  };

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
      await copyToClipboard(pwaUrl);
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
      const res = await clientApi.exportBackup(pass, includeRuleSets);
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
      if (res.summary?.hasSingBoxBase) included.push('三路合并基线');
      if ((res.summary?.ruleSetCount ?? 0) > 0) {
        included.push(`${res.summary.ruleSetCount} 项离线规则集`);
      }
      success(
        `${res.message || '加密备份快照已下载'}${included.length ? `（已打包: ${included.join(' / ')}）` : ''}`,
        6000,
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
    if (file.size > 16 * 1024 * 1024) {
      error('备份文件过大（不能超过 16 MB）');
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
      const parts: string[] = [res.message || '网关加密备份快照已恢复并热应用生效'];
      if ((res.ruleSetCount ?? 0) > 0 && !parts[0].includes('离线规则集')) {
        parts.push(`离线规则集: ${res.ruleSetCount} 项`);
      }
      if (res.adaptations?.length) {
        parts.push(`跨机硬件自适配: ${res.adaptations.join('；')}`);
      }
      success(parts.join(' ｜ '), res.adaptations?.length ? 8500 : 5500);
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
        description="软件版本升级、安全回滚保险丝、主动告警推送、网关加密灾备迁移与会话安全"
        actions={
          <>
            <Button
              size="sm"
              variant="secondary"
              onClick={() => setDoctorOpen(true)}
              icon={<Stethoscope className="w-3.5 h-3.5 text-emerald-400" />}
            >
              一键深度体检
            </Button>
            {status?.authEnabled && (
              <Button
                size="sm"
                variant="danger"
                onClick={() => setLogoutOpen(true)}
                icon={<LogOut className="w-3.5 h-3.5" />}
              >
                退出登录
              </Button>
            )}
          </>
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

      {/* 开机自启动与掉电恢复开关 */}
      <AutoStartCard
        liveAutoStart={status?.autoStart}
        busy={busy}
        onRefreshStatus={onRefreshStatus ?? onRestored}
      />

      {/* 远端安全回滚保险丝与 tailscaled OOM 免疫 */}
      <SafeCommitCard
        liveSafeCommit={status?.safeCommit}
        busy={busy}
        onRefreshStatus={onRefreshStatus ?? onRestored}
      />

      {/* 多渠道主动消息推送与防刷屏 */}
      <NotifyConfigCard busy={busy} />

      {/* 全局下载加速与 singctl.yaml 主配置源码 */}
      <SectionCard
        title="全局加速与主配置"
        icon={<Globe className="w-4 h-4" />}
        subtitle="GitHub 加速镜像供内核/Tailscale/自更新共用；低频高级字段可直接通过 YAML 源码编辑"
      >
        <form onSubmit={(e) => void handleSaveMirror(e)} className="space-y-3 text-xs">
          <div className="grid grid-cols-1 md:grid-cols-12 gap-3 items-end">
            <label className="md:col-span-7 block space-y-1">
              <span className="text-secondary">GitHub 加速镜像 (`github.mirror_url`，留空直连)</span>
              <input
                type="text"
                disabled={mirrorLoading}
                value={mirrorUrl}
                onChange={(e) => setMirrorUrl(e.target.value)}
                placeholder="https://gh-proxy.com"
                className="w-full h-9 px-3 rounded-xl bg-surface2 border border-subtle text-primary font-mono focus:outline-none focus:border-strong"
              />
            </label>
            <div className="md:col-span-5 flex flex-wrap items-center gap-2">
              <Button
                type="submit"
                size="sm"
                variant="primary"
                loading={mirrorSaving}
                disabled={mirrorLoading || busy}
                icon={<Save className="w-3.5 h-3.5" />}
              >
                保存镜像地址
              </Button>
              <Button
                type="button"
                size="sm"
                variant="secondary"
                disabled={busy}
                onClick={() => void openRawYamlDrawer()}
                icon={<FileCode className="w-3.5 h-3.5" />}
              >
                编辑 singctl.yaml 源码
              </Button>
            </div>
          </div>
        </form>
      </SectionCard>

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
                <code className="font-mono">AdGuardHome.yaml</code>、<code className="font-mono">config.json</code> 及三路合并基线。
              </p>
            </div>
            <label className="flex items-start gap-2 text-xs text-secondary cursor-pointer select-none">
              <input
                type="checkbox"
                checked={includeRuleSets}
                onChange={(e) => setIncludeRuleSets(e.target.checked)}
                className="mt-0.5 rounded border-subtle bg-surface1 accent-emerald-500"
              />
              <span className="leading-relaxed">
                同时打包离线规则集（<code className="font-mono">.srs</code> + <code className="font-mono">manifest.json</code>，推荐，新机断网也能直接恢复）
              </span>
            </label>
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
              <div className="text-sm font-medium text-primary">从加密快照一键还原</div>
              <p className="text-xs text-secondary leading-relaxed">
                落盘前全量校验 YAML/JSON/规则集归档（上限 16 MB）与 <code className="font-mono">sing-box check</code>，支持跨硬件自适配与失败全事务原子回滚。
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

      <SlideDrawer
        open={rawYamlOpen}
        onClose={() => setRawYamlOpen(false)}
        title="编辑 singctl.yaml 主配置源码"
        subtitle={
          rawYamlPath
            ? `${rawYamlPath} · 保留全部人工注释与高级字段，保存前自动校验 YAML 语法并创建备份`
            : '保留全部人工注释与高级字段'
        }
        size="xl"
        headerExtra={
          <Button
            size="xs"
            variant="ghost"
            onClick={() => void openRawYamlDrawer()}
            disabled={rawYamlLoading || rawYamlSaving}
            icon={<RefreshCw className={`w-3.5 h-3.5 ${rawYamlLoading ? 'animate-spin' : ''}`} />}
          >
            重新加载
          </Button>
        }
        footer={
          <div className="flex items-center justify-end gap-2">
            <Button variant="secondary" onClick={() => setRawYamlOpen(false)} disabled={rawYamlSaving}>
              取消
            </Button>
            <Button
              variant="primary"
              loading={rawYamlSaving}
              disabled={rawYamlLoading}
              onClick={() => void handleSaveRawYaml()}
              icon={<Save className="w-3.5 h-3.5" />}
            >
              校验并保存 YAML
            </Button>
          </div>
        }
      >
        {rawYamlLoading ? (
          <div className="py-12 text-center text-xs text-slate-400">正在读取配置文件…</div>
        ) : (
          <textarea
            value={rawYaml}
            onChange={(e) => setRawYaml(e.target.value)}
            spellCheck={false}
            rows={24}
            className="w-full p-3.5 rounded-xl bg-[var(--console-bg)] text-slate-200 border border-subtle font-mono text-xs leading-relaxed focus:outline-none focus:border-strong"
          />
        )}
      </SlideDrawer>
      <DoctorDrawer
        open={doctorOpen}
        onClose={() => setDoctorOpen(false)}
        onFixed={onRefreshStatus ?? onRestored}
      />
    </div>
  );
};

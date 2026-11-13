import React, { useState } from 'react';
import { Cpu, RefreshCw, Gauge, Smartphone, LogOut, Copy } from 'lucide-react';
import {
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
}

export const SystemPage: React.FC<SystemPageProps> = ({ status, busy, onAction }) => {
  const { success, error } = useToast();
  const [pwaOpen, setPwaOpen] = useState(false);
  const [pwaUrl, setPwaUrl] = useState('');
  const [pwaLoading, setPwaLoading] = useState(false);
  const [logoutOpen, setLogoutOpen] = useState(false);

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

  const h = status?.host;
  const sb = status?.singbox;
  const ts = status?.tailscale;

  return (
    <div className="space-y-5">
      <PageHeader
        title="系统与维护"
        description="软件版本升级、链路带宽测速、iPhone 免密桌面应用与会话安全"
        actions={
          status?.authEnabled ? (
            <Button size="sm" variant="danger" onClick={() => setLogoutOpen(true)} icon={<LogOut className="w-3.5 h-3.5" />}>
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

      <SlideDrawer
        open={pwaOpen}
        onClose={() => setPwaOpen(false)}
        title="手机免密主屏幕快捷入口"
        subtitle="iPhone Safari 扫码打开并选择「添加到主屏幕」，即可享受 30 天免密直连"
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

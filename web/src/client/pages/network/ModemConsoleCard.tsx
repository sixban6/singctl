import React from 'react';
import {
  ExternalLink,
  Maximize2,
  Minimize2,
  Monitor,
  Power,
  RefreshCw,
  User,
  Wifi,
  Zap,
} from 'lucide-react';
import { Button, SectionCard } from '../../../ui';
import { ModemStatusResponse } from '../../types';

export interface ModemConsoleCardProps {
  status?: ModemStatusResponse;
  busy: boolean;
  privacyMask: boolean;
  effectiveModemIP: string;
  consoleRunning: boolean;
  consoleOpening: boolean;
  consoleClosing: boolean;
  iframeSrc: string | null;
  iframeKey: number;
  fullscreen: boolean;
  normalPort: number;
  currentTargetPort: number;
  hasSuperCred: boolean;
  hasUserCred: boolean;
  loginBusySlot: 'super' | 'user' | null;
  iframeRef: React.RefObject<HTMLIFrameElement | null>;
  onIframeLoad: () => void;
  onRefreshFrame: () => void;
  onToggleFullscreen: () => void;
  onOpenPort: (port: number, newWindow?: boolean) => void;
  onOneClickLogin: (slot: 'super' | 'user') => void;
  onCloseConsole: () => void;
}

export const ModemConsoleCard: React.FC<ModemConsoleCardProps> = ({
  status,
  busy,
  privacyMask,
  effectiveModemIP,
  consoleRunning,
  consoleOpening,
  consoleClosing,
  iframeSrc,
  iframeKey,
  fullscreen,
  normalPort,
  currentTargetPort,
  hasSuperCred,
  hasUserCred,
  loginBusySlot,
  iframeRef,
  onIframeLoad,
  onRefreshFrame,
  onToggleFullscreen,
  onOpenPort,
  onOneClickLogin,
  onCloseConsole,
}) => {
  const adminPort = status?.adminPort;

  return (
    <div
      className={
        fullscreen
          ? 'fixed inset-0 z-50 bg-slate-950/95 backdrop-blur-md p-3 sm:p-5 flex flex-col gap-3'
          : ''
      }
    >
      <SectionCard
        title="光猫内嵌控制台"
        icon={<Monitor className="w-4 h-4" />}
        subtitle={
          consoleRunning
            ? `已通过端口 :${status?.console?.port || 8091} 反向代理连接至 :${currentTargetPort}（15 分钟无操作自动休眠）`
            : '按需开启认证隔离隧道，支持普通后台 / 8080 装维超管口切换与一键填充登录（支持 Tailscale 远程访问）'
        }
        actions={
          consoleRunning ? (
            <div className="flex items-center gap-1.5 flex-wrap">
              {adminPort && (
                <div className="flex items-center rounded-lg border border-subtle overflow-hidden">
                  <button
                    type="button"
                    onClick={() => onOpenPort(normalPort, false)}
                    className={`px-2 py-1 text-[11px] font-medium cursor-pointer transition-colors ${
                      currentTargetPort !== adminPort
                        ? 'bg-emerald-500/20 text-emerald-300'
                        : 'text-secondary hover:text-primary'
                    }`}
                  >
                    普通 :{normalPort}
                  </button>
                  <button
                    type="button"
                    onClick={() => onOpenPort(adminPort, false)}
                    className={`px-2 py-1 text-[11px] font-medium cursor-pointer transition-colors border-l border-subtle ${
                      currentTargetPort === adminPort
                        ? 'bg-amber-500/20 text-amber-300'
                        : 'text-secondary hover:text-primary'
                    }`}
                  >
                    超管 :{adminPort}
                  </button>
                </div>
              )}
              {hasSuperCred && (
                <Button
                  size="xs"
                  variant="primary"
                  loading={loginBusySlot === 'super'}
                  icon={<Zap className="w-3 h-3" />}
                  onClick={() => onOneClickLogin('super')}
                >
                  超管一键登录
                </Button>
              )}
              {hasUserCred && (
                <Button
                  size="xs"
                  variant="secondary"
                  loading={loginBusySlot === 'user'}
                  icon={<User className="w-3 h-3" />}
                  onClick={() => onOneClickLogin('user')}
                >
                  普通登录
                </Button>
              )}
              <Button size="xs" variant="ghost" icon={<RefreshCw className="w-3 h-3" />} onClick={onRefreshFrame}>
                刷新
              </Button>
              <Button
                size="xs"
                variant="ghost"
                icon={fullscreen ? <Minimize2 className="w-3 h-3" /> : <Maximize2 className="w-3 h-3" />}
                onClick={onToggleFullscreen}
              >
                {fullscreen ? '退出全屏' : '全屏'}
              </Button>
              <Button
                size="xs"
                variant="ghost"
                icon={<ExternalLink className="w-3 h-3" />}
                loading={consoleOpening}
                onClick={() => onOpenPort(currentTargetPort, true)}
              >
                新窗口
              </Button>
              <Button
                size="xs"
                variant="secondary"
                loading={consoleClosing}
                icon={<Power className="w-3 h-3 text-rose-400" />}
                onClick={onCloseConsole}
              >
                关闭
              </Button>
            </div>
          ) : undefined
        }
      >
        {privacyMask ? (
          <div className="py-10 text-center text-xs text-secondary">
            隐私完全遮挡已开启，内嵌光猫控制台已自动隐藏。关闭右上角隐私遮挡即可连接登录。
          </div>
        ) : iframeSrc ? (
          <iframe
            ref={iframeRef}
            key={iframeKey}
            src={iframeSrc}
            onLoad={onIframeLoad}
            title="上游光猫内嵌管理台"
            sandbox="allow-same-origin allow-scripts allow-forms allow-popups allow-modals allow-downloads"
            className={`w-full rounded-xl border border-subtle bg-white ${
              fullscreen ? 'h-[calc(100vh-145px)] min-h-[540px]' : 'h-[72vh] min-h-[620px]'
            }`}
          />
        ) : (
          <div className="py-10 px-4 text-center space-y-4">
            <div className="w-12 h-12 rounded-2xl bg-emerald-500/10 border border-emerald-500/25 flex items-center justify-center mx-auto">
              <Wifi className="w-6 h-6 text-emerald-400" />
            </div>
            <div className="space-y-1 max-w-lg mx-auto">
              <div className="text-sm font-semibold text-primary">
                {effectiveModemIP
                  ? `准备就绪：将代理连接至 ${status?.scheme || 'http'}://${effectiveModemIP}:${normalPort}${adminPort ? `（另探测到装维超管入口 :${adminPort}）` : ''}`
                  : '未自动探测到可达的光猫管理地址'}
              </div>
              <p className="text-xs text-secondary leading-relaxed">
                已内置防跳框拦截破除、CSRF 来源头重写及一键凭据自动填充；关闭或闲置 15 分钟自动释放端口。
              </p>
            </div>
            <div className="flex items-center justify-center gap-2 flex-wrap">
              {hasSuperCred && (
                <Button
                  variant="primary"
                  loading={loginBusySlot === 'super'}
                  disabled={busy || !effectiveModemIP}
                  icon={<Zap className="w-4 h-4" />}
                  onClick={() => onOneClickLogin('super')}
                >
                  超管一键直登{adminPort ? ` (:${adminPort})` : ''}
                </Button>
              )}
              <Button
                variant={hasSuperCred ? 'secondary' : 'primary'}
                loading={consoleOpening}
                disabled={busy || !effectiveModemIP}
                icon={<Monitor className="w-4 h-4" />}
                onClick={() => onOpenPort(normalPort, false)}
              >
                打开普通后台 (:{normalPort})
              </Button>
              {adminPort && (
                <Button
                  variant="secondary"
                  loading={consoleOpening}
                  disabled={busy || !effectiveModemIP}
                  icon={<Zap className="w-4 h-4 text-amber-400" />}
                  onClick={() => onOpenPort(adminPort, false)}
                >
                  打开超管入口 (:{adminPort})
                </Button>
              )}
              <Button
                variant="ghost"
                loading={consoleOpening}
                disabled={busy || !effectiveModemIP}
                icon={<ExternalLink className="w-4 h-4" />}
                onClick={() => onOpenPort(adminPort || normalPort, true)}
              >
                新窗口打开
              </Button>
            </div>
          </div>
        )}
      </SectionCard>
    </div>
  );
};

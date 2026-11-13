import React, { useEffect, useState, useCallback, useMemo } from 'react';
import { Monitor, RefreshCw, ExternalLink } from 'lucide-react';
import { Badge, Button, PageHeader, SectionCard } from '../../ui';
import { ClientStatusResponse } from '../types';

export interface PanelPageProps {
  status: ClientStatusResponse | null;
}

export const PanelPage: React.FC<PanelPageProps> = ({ status }) => {
  const [connected, setConnected] = useState<boolean | null>(null);
  const [reloadNonce, setReloadNonce] = useState(0);

  const checkHealth = useCallback(async () => {
    setConnected(null);
    try {
      const r = await fetch('/clash/version', { credentials: 'same-origin' });
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      await r.json();
      setConnected(true);
    } catch {
      setConnected(false);
    }
  }, []);

  useEffect(() => {
    void checkHealth();
  }, [checkHealth, reloadNonce]);

  const frameSrc = useMemo(() => {
    if (!connected) return 'about:blank';
    let src = '/clash/ui/';
    try {
      if (localStorage.getItem('xdBackendAutoSet') !== window.location.origin) {
        const port = window.location.port || (window.location.protocol === 'https:' ? '443' : '80');
        const qs = `hostname=${encodeURIComponent(window.location.hostname)}&port=${encodeURIComponent(port)}&secret=`;
        src += `?${qs}#/setup?${qs}`;
        localStorage.setItem('xdBackendAutoSet', window.location.origin);
      }
    } catch {
      // ignore storage failure
    }
    return src;
  }, [connected]);

  const panelURL = status?.singbox?.panelURL || '#';

  return (
    <div className="space-y-4">
      <PageHeader
        title="Clash 控制面板"
        description={status?.singbox?.panelURL || '通过 WebUI 同源反代 /clash/ui/ 访问'}
        badge={
          connected === null ? (
            <Badge tone="neutral">检测中…</Badge>
          ) : connected ? (
            <Badge tone="ok" dot pulse>
              已连接
            </Badge>
          ) : (
            <Badge tone="danger" dot>
              不可用
            </Badge>
          )
        }
        actions={
          <>
            <Button
              size="sm"
              onClick={() => setReloadNonce((n) => n + 1)}
              icon={<RefreshCw className="w-3.5 h-3.5" />}
            >
              重新检测
            </Button>
            {status?.singbox?.panelURL && (
              <Button
                size="sm"
                variant="primary"
                onClick={() => window.open(panelURL, '_blank', 'noopener')}
                icon={<ExternalLink className="w-3.5 h-3.5" />}
              >
                新窗口打开
              </Button>
            )}
          </>
        }
      />

      <SectionCard noPadding>
        {connected === false ? (
          <div className="py-16 px-4 text-center space-y-2">
            <Monitor className="w-8 h-8 text-muted mx-auto" />
            <div className="text-sm font-medium text-primary">Clash API 当前不可达</div>
            <p className="text-xs text-secondary">请确认 sing-box 已启动且配置开启了 `clash_api.external_controller`。</p>
          </div>
        ) : (
          <iframe
            key={reloadNonce}
            title="Clash Panel"
            src={frameSrc}
            className="w-full h-[calc(100vh-12rem)] min-h-[540px] border-0 bg-[var(--bg-canvas)]"
          />
        )}
      </SectionCard>
    </div>
  );
};

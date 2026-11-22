import React, { useState } from 'react';
import { Copy, ExternalLink } from 'lucide-react';
import { Button, QRCodeBox, SlideDrawer } from '../../../ui';

export interface DashIOSImportDrawerProps {
  open: boolean;
  loading: boolean;
  iosUrl: string;
  iosImportUrl: string;
  onClose: () => void;
  onCopy: (text: string, msg: string) => void;
}

export const DashIOSImportDrawer: React.FC<DashIOSImportDrawerProps> = ({
  open,
  loading,
  iosUrl,
  iosImportUrl,
  onClose,
  onCopy,
}) => {
  const [qrMode, setQrMode] = useState<'import' | 'raw'>('import');

  return (
    <SlideDrawer
      open={open}
      onClose={onClose}
      title="移动端 · Sing-Box 扫描导入"
      subtitle="同一局域网下使用手机相机或 iOS / Android Sing-Box 客户端扫描即可同步完整分流配置"
    >
      <div className="flex flex-col items-center text-center space-y-4 py-2">
        {loading ? (
          <div className="w-44 h-44 rounded-2xl bg-surface2 animate-pulse" />
        ) : iosUrl ? (
          <>
            <div className="inline-flex items-center p-1 rounded-xl bg-surface2 border border-subtle text-xs">
              <button
                type="button"
                onClick={() => setQrMode('import')}
                className={`px-3 py-1 rounded-lg font-medium transition-colors cursor-pointer ${
                  qrMode === 'import'
                    ? 'bg-[var(--accent)] text-white shadow-sm'
                    : 'text-secondary hover:text-primary'
                }`}
              >
                客户端一键扫描导入
              </button>
              <button
                type="button"
                onClick={() => setQrMode('raw')}
                className={`px-3 py-1 rounded-lg font-medium transition-colors cursor-pointer ${
                  qrMode === 'raw'
                    ? 'bg-[var(--accent)] text-white shadow-sm'
                    : 'text-secondary hover:text-primary'
                }`}
              >
                纯配置链接
              </button>
            </div>
            <QRCodeBox value={qrMode === 'import' ? iosImportUrl : iosUrl} size={184} />
            <div className="w-full p-3 rounded-xl bg-surface2 border border-subtle font-mono text-xs text-primary break-all select-all">
              {iosUrl}
            </div>
            <div className="flex flex-wrap items-center justify-center gap-2">
              <a
                href={iosImportUrl}
                className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-xl text-xs font-semibold bg-emerald-500 hover:bg-emerald-400 text-slate-950 shadow-sm transition-colors"
              >
                <ExternalLink className="w-3.5 h-3.5" />
                一键打开 Sing-Box 导入
              </a>
              <Button
                variant="primary"
                onClick={() => onCopy(iosUrl, '已复制移动端配置同步地址')}
                icon={<Copy className="w-3.5 h-3.5" />}
              >
                复制配置链接
              </Button>
              <Button
                variant="secondary"
                onClick={() => {
                  window.open(iosUrl, '_blank', 'noopener');
                }}
              >
                直接下载 JSON
              </Button>
            </div>
          </>
        ) : (
          <p className="text-xs text-muted">未能生成链接，请确认已配置订阅且处于局域网中。</p>
        )}
      </div>
    </SlideDrawer>
  );
};

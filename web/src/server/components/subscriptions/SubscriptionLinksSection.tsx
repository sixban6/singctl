import React from 'react';
import { SubscriptionsResponse } from '../../types';
import { Check, Copy, Download, FileCode2, Info, KeyRound, QrCode, RefreshCw, Sparkles } from 'lucide-react';
import { buildClientImportItems } from './helpers';

export const UnifiedSubscriptionCard: React.FC<{
  data: SubscriptionsResponse | null;
  totalNodes: number;
  copiedKey: string | null;
  rotatingKey: boolean;
  loading: boolean;
  onCopyText: (text: string, key: string) => void;
  onShowQRCode: (url: string) => void;
  onFetchPreview: (target: string) => void;
  onRotateKey: () => void;
  onReload: () => void;
}> = ({
  data,
  totalNodes,
  copiedKey,
  rotatingKey,
  loading,
  onCopyText,
  onShowQRCode,
  onFetchPreview,
  onRotateKey,
  onReload,
}) => {
  return (
    <div className="p-6 rounded-2xl glass-card relative overflow-hidden">
      <div className="absolute top-0 right-0 w-64 h-64 bg-emerald-500/10 rounded-full blur-3xl pointer-events-none"></div>

      <div className="flex flex-wrap items-center justify-between gap-2 mb-2">
        <div className="flex items-center gap-2 text-emerald-400 text-xs font-semibold uppercase tracking-wider">
          <Sparkles className="w-3.5 h-3.5" />
          <span>Go 原生聚合分发中枢 (SubHub · 零容器依赖)</span>
        </div>
        <span className="px-2.5 py-0.5 rounded-full text-[11px] font-mono bg-emerald-500/10 text-emerald-300 border border-emerald-500/20">
          已聚合 {totalNodes} 个可用节点
        </span>
      </div>

      <h2 className="text-xl font-bold text-white tracking-tight">统一全平台订阅链接</h2>
      <p className="text-xs text-slate-400 mt-1 max-w-2xl">
        由 SingCtl 内置 Go 引擎实时聚合本机 Reality / Hysteria2 节点与自定义外部订阅源，支持根据客户端类型自动下发对应格式配置
      </p>

      {/* URL Bar */}
      <div className="mt-5 p-3 rounded-xl bg-slate-950/70 border border-slate-800 flex flex-col lg:flex-row items-stretch lg:items-center justify-between gap-3 font-mono text-xs text-slate-300">
        <span className="truncate select-all">{data?.subscriptionUrl || '订阅地址生成中...'}</span>
        <div className="flex flex-wrap items-center gap-2 shrink-0">
          <button
            onClick={() => onCopyText(data?.subscriptionUrl || '', 'sub-url')}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-emerald-500 hover:bg-emerald-600 text-slate-950 font-semibold text-xs transition-colors"
          >
            {copiedKey === 'sub-url' ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
            <span>{copiedKey === 'sub-url' ? '已复制' : '复制订阅'}</span>
          </button>
          <button
            onClick={() => onShowQRCode(data?.subscriptionUrl || '')}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs transition-colors"
          >
            <QrCode className="w-3.5 h-3.5" />
            <span>二维码</span>
          </button>
          <button
            onClick={() => onFetchPreview('ClashMeta')}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-purple-500/20 hover:bg-purple-500/30 border border-purple-500/30 text-purple-200 text-xs font-semibold transition-colors"
            title="在线预览 Clash.Meta、Sing-box、Surge、Loon 等目标转换结果"
          >
            <FileCode2 className="w-3.5 h-3.5 text-purple-400" />
            <span>预览转换配置</span>
          </button>
          <button
            onClick={onRotateKey}
            disabled={rotatingKey}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-amber-500/10 hover:bg-amber-500/20 border border-amber-500/30 text-amber-300 text-xs font-medium transition-colors disabled:opacity-50"
            title="重置随机订阅路径密钥，使泄露的旧订阅链接立即失效"
          >
            <KeyRound className={`w-3.5 h-3.5 ${rotatingKey ? 'animate-spin' : ''}`} />
            <span>轮换密钥</span>
          </button>
          <button
            onClick={onReload}
            title="刷新订阅状态"
            className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-white transition-colors"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
          </button>
        </div>
      </div>

      {/* Sync Hint Banner */}
      <div className="mt-3.5 flex items-center gap-2 text-xs text-slate-400 bg-emerald-950/20 border border-emerald-500/20 rounded-xl px-3.5 py-2">
        <Info className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
        <span>
          支持通过 URL 参数强制指定输出格式：<code className="text-emerald-300">?target=ClashMeta</code>、
          <code className="text-emerald-300">?target=Sing-Box</code>、<code className="text-emerald-300">?target=Surge</code>、
          <code className="text-emerald-300">?target=Loon</code> 或按客户端 User-Agent 自动识别。
        </span>
      </div>
    </div>
  );
};

export const ClientImportsAndDirectLinks: React.FC<{
  data: SubscriptionsResponse | null;
  copiedKey: string | null;
  onCopyText: (text: string, key: string) => void;
  onShowQRCode: (url: string) => void;
}> = ({ data, copiedKey, onCopyText, onShowQRCode }) => {
  const clients = buildClientImportItems(data);

  return (
    <>
      {/* One-Click Import Clients Grid */}
      <div>
        <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider mb-3 px-1">
          客户端一键导入 (DeepLink 唤醒)
        </h3>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
          {clients.map((c) => (
            <div key={c.name} className="p-4 rounded-2xl glass-card glass-card-hover flex flex-col justify-between">
              <div>
                <div className="flex items-center gap-2.5">
                  <span className="text-2xl">{c.icon}</span>
                  <div>
                    <h4 className="font-semibold text-sm text-white">{c.name}</h4>
                    <p className="text-[11px] text-slate-400">{c.desc}</p>
                  </div>
                </div>
              </div>
              <div className="mt-4 pt-3 border-t border-slate-800 flex items-center justify-between">
                <a
                  href={c.scheme}
                  className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-emerald-500/10 hover:bg-emerald-500/20 text-emerald-300 border border-emerald-500/20 text-xs font-semibold transition-all"
                >
                  <Download className="w-3.5 h-3.5" />
                  <span>一键导入配置</span>
                </a>
                <button
                  onClick={() => onShowQRCode(c.scheme || '')}
                  className="p-1.5 text-slate-400 hover:text-white rounded-lg hover:bg-slate-800 transition-colors"
                  title="查看导入二维码"
                >
                  <QrCode className="w-4 h-4" />
                </button>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Direct Node Links */}
      <div className="p-5 rounded-2xl glass-card space-y-4">
        <h3 className="text-sm font-semibold text-white">本机单节点直连链接 (URI)</h3>
        <div className="space-y-3">
          {data?.nodes?.hy2?.link && (
            <div className="p-3 rounded-xl bg-slate-950/60 border border-slate-800 flex items-center justify-between gap-3 text-xs font-mono">
              <div className="truncate text-slate-300">
                <span className="text-emerald-400 font-semibold mr-2">[Hysteria 2]</span>
                {data.nodes.hy2.link}
              </div>
              <button
                onClick={() => onCopyText(data.nodes.hy2.link, 'hy2')}
                className="px-2.5 py-1 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 shrink-0 text-xs flex items-center gap-1"
              >
                {copiedKey === 'hy2' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                <span>复制</span>
              </button>
            </div>
          )}
          {data?.nodes?.vless?.link && (
            <div className="p-3 rounded-xl bg-slate-950/60 border border-slate-800 flex items-center justify-between gap-3 text-xs font-mono">
              <div className="truncate text-slate-300">
                <span className="text-purple-400 font-semibold mr-2">[VLESS Reality]</span>
                {data.nodes.vless.link}
              </div>
              <button
                onClick={() => onCopyText(data.nodes.vless.link, 'vless')}
                className="px-2.5 py-1 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 shrink-0 text-xs flex items-center gap-1"
              >
                {copiedKey === 'vless' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                <span>复制</span>
              </button>
            </div>
          )}
        </div>
      </div>
    </>
  );
};

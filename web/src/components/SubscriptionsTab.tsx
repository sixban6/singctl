import React, { useEffect, useState, useRef } from 'react';
import { SubscriptionsResponse } from '../types';
import { api } from '../api';
import { useToast } from './Toast';
import { Copy, QrCode, ExternalLink, Check, Download, ShieldAlert, Sparkles, X, RefreshCw, Info } from 'lucide-react';
import QRCode from 'qrcode';

export const SubscriptionsTab: React.FC = () => {
  const { success, error } = useToast();
  const [data, setData] = useState<SubscriptionsResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const [qrModalURL, setQrModalURL] = useState<string | null>(null);
  const qrCanvasRef = useRef<HTMLCanvasElement | null>(null);

  useEffect(() => {
    loadData();
  }, []);

  const loadData = async () => {
    setLoading(true);
    try {
      const res = await api.getSubscriptions();
      setData(res);
    } catch (err: any) {
      error(err.message || '获取订阅信息失败');
    } finally {
      setLoading(false);
    }
  };

  const copyText = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    success('已复制到剪贴板');
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const showQRCode = (url: string) => {
    setQrModalURL(url);
  };

  useEffect(() => {
    if (qrModalURL && qrCanvasRef.current) {
      QRCode.toCanvas(qrCanvasRef.current, qrModalURL, {
        width: 256,
        margin: 2,
        color: {
          dark: '#0f172a',
          light: '#ffffff',
        },
      });
    }
  }, [qrModalURL]);

  if (loading && !data) {
    return (
      <div className="p-12 text-center text-slate-400 glass-card rounded-2xl">
        <div className="animate-spin w-6 h-6 border-2 border-emerald-500 border-t-transparent rounded-full mx-auto mb-3"></div>
        <span>正在读取节点与订阅配置...</span>
      </div>
    );
  }

  const clients = [
    {
      name: 'Shadowrocket',
      desc: 'iOS 跨协议网络客户端',
      icon: '🚀',
      scheme: data?.importLinks?.shadowrocket,
      color: 'from-blue-600 to-indigo-600',
    },
    {
      name: 'Clash Verge / Meta',
      desc: '跨平台主流内核客户端',
      icon: '⚡',
      scheme: data?.importLinks?.clash,
      color: 'from-amber-500 to-orange-600',
    },
    {
      name: 'Sing-box 官方客户端',
      desc: '原生全协议内核客户端',
      icon: '📦',
      scheme: data?.importLinks?.singbox,
      color: 'from-emerald-600 to-teal-600',
    },
    {
      name: 'Surge',
      desc: '高级网络分析与定制客户端',
      icon: '🌊',
      scheme: data?.importLinks?.surge,
      color: 'from-cyan-600 to-blue-700',
    },
    {
      name: 'Loon',
      desc: '高扩展性网络代理工具',
      icon: '🎈',
      scheme: data?.importLinks?.loon,
      color: 'from-purple-600 to-pink-600',
    },
  ];

  return (
    <div className="space-y-6">
      {/* Top Card: Unified Subscription */}
      <div className="p-6 rounded-2xl glass-card relative overflow-hidden">
        <div className="absolute top-0 right-0 w-64 h-64 bg-emerald-500/10 rounded-full blur-3xl pointer-events-none"></div>

        <div className="flex items-center gap-2 text-emerald-400 text-xs font-semibold uppercase tracking-wider mb-2">
          <Sparkles className="w-3.5 h-3.5" />
          <span>聚合分发中枢</span>
        </div>
        <h2 className="text-xl font-bold text-white tracking-tight">统一全平台订阅链接</h2>
        <p className="text-xs text-slate-400 mt-1 max-w-2xl">
          由 Sub-Store 自动聚合本 VPS 上的全部 Reality 和 Hysteria2 节点，支持自动转换目标客户端配置
        </p>

        {/* URL Bar */}
        <div className="mt-5 p-3 rounded-xl bg-slate-950/70 border border-slate-800 flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3 font-mono text-xs text-slate-300">
          <span className="truncate select-all">{data?.subscriptionUrl || '订阅地址生成中...'}</span>
          <div className="flex items-center gap-2 shrink-0">
            <button
              onClick={() => copyText(data?.subscriptionUrl || '', 'sub-url')}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-emerald-500 hover:bg-emerald-600 text-slate-950 font-semibold text-xs transition-colors"
            >
              {copiedKey === 'sub-url' ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
              <span>{copiedKey === 'sub-url' ? '已复制' : '复制订阅'}</span>
            </button>
            <button
              onClick={() => showQRCode(data?.subscriptionUrl || '')}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs transition-colors"
            >
              <QrCode className="w-3.5 h-3.5" />
              <span>二维码</span>
            </button>
            {data?.substoreAdminUrl && (
              <a
                href={data.substoreAdminUrl}
                target="_blank"
                rel="noreferrer"
                title="打开 Sub-Store 后台 (自动携带完整免密鉴权凭证)"
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-purple-500/20 hover:bg-purple-500/30 border border-purple-500/30 text-purple-200 text-xs font-semibold transition-colors"
              >
                <ExternalLink className="w-3.5 h-3.5 text-purple-400" />
                <span>Sub-Store 订阅源 (免密)</span>
              </a>
            )}
            <button
              onClick={loadData}
              title="重新拉取最新订阅"
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
            提示：若在控制台修改了 Reality 伪装域名 (SNI) 或端口，配置已由服务端热生效，请记得在手机/电脑客户端点击【更新订阅】同步节点。
          </span>
        </div>
      </div>

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
                  onClick={() => showQRCode(c.scheme || '')}
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
        <h3 className="text-sm font-semibold text-white">单节点直连链接 (URI)</h3>
        <div className="space-y-3">
          {data?.nodes?.hy2?.link && (
            <div className="p-3 rounded-xl bg-slate-950/60 border border-slate-800 flex items-center justify-between gap-3 text-xs font-mono">
              <div className="truncate text-slate-300">
                <span className="text-emerald-400 font-semibold mr-2">[Hysteria 2]</span>
                {data.nodes.hy2.link}
              </div>
              <button
                onClick={() => copyText(data.nodes.hy2.link, 'hy2')}
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
                onClick={() => copyText(data.nodes.vless.link, 'vless')}
                className="px-2.5 py-1 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 shrink-0 text-xs flex items-center gap-1"
              >
                {copiedKey === 'vless' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                <span>复制</span>
              </button>
            </div>
          )}
        </div>
      </div>

      {/* QR Code Modal */}
      {qrModalURL && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-md">
          <div className="bg-slate-900 border border-slate-800 rounded-3xl p-6 max-w-sm w-full flex flex-col items-center text-center shadow-2xl relative">
            <button
              onClick={() => setQrModalURL(null)}
              className="absolute top-4 right-4 p-1.5 rounded-xl hover:bg-slate-800 text-slate-400 hover:text-white transition-colors"
            >
              <X className="w-4 h-4" />
            </button>
            <h4 className="text-base font-bold text-white mt-1">手机扫码快速导入</h4>
            <p className="text-xs text-slate-400 mt-1">使用 Shadowrocket 或支持二维码的客户端扫码</p>
            <div className="mt-5 p-3 bg-white rounded-2xl shadow-inner">
              <canvas ref={qrCanvasRef} className="rounded-lg"></canvas>
            </div>
            <p className="text-[11px] font-mono text-slate-400 mt-4 break-all max-w-xs line-clamp-2">
              {qrModalURL}
            </p>
          </div>
        </div>
      )}
    </div>
  );
};

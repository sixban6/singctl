import React from 'react';
import { SourceUpsertInput, SubscriptionPreviewResponse } from '../../types';
import { QRCodeBox } from '../../../ui';
import { Check, Copy, Download, FileCode2, RefreshCw, X } from 'lucide-react';
import { PREVIEW_TARGETS } from './helpers';

export const SourceUpsertModal: React.FC<{
  editingSource: SourceUpsertInput;
  setEditingSource: (v: SourceUpsertInput | null) => void;
  isAutoManagedEdit: boolean;
  savingSource: boolean;
  onSave: (e: React.FormEvent) => void;
}> = ({ editingSource, setEditingSource, isAutoManagedEdit, savingSource, onSave }) => {
  return (
    <div className="fixed inset-0 z-50 flex items-end sm:items-center justify-center sm:p-4 bg-slate-950/85 backdrop-blur-md">
      <form
        onSubmit={onSave}
        className="bg-slate-900 border-t sm:border border-slate-800 rounded-t-3xl sm:rounded-3xl w-full max-w-xl max-h-[92dvh] overflow-y-auto shadow-2xl pb-safe"
      >
        <div className="flex items-center justify-between px-6 py-4 border-b border-slate-800">
          <div>
            <h4 className="text-base font-bold text-white">
              {editingSource.name ? '编辑聚合节点源' : '添加节点源 / 外部订阅'}
            </h4>
            <p className="text-xs text-slate-400 mt-0.5">
              保存后无需重启容器，SubHub 将立即合并进全平台订阅链接
            </p>
          </div>
          <button
            type="button"
            onClick={() => setEditingSource(null)}
            className="p-1.5 rounded-xl hover:bg-slate-800 text-slate-400 hover:text-white"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        <div className="p-6 space-y-4">
          {!isAutoManagedEdit && (
            <div className="grid grid-cols-2 gap-2 p-1 rounded-xl bg-slate-950 border border-slate-800 text-xs">
              <button
                type="button"
                onClick={() => setEditingSource({ ...editingSource, source: 'local' })}
                className={`py-2 rounded-lg font-semibold transition-colors ${
                  editingSource.source === 'local'
                    ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30'
                    : 'text-slate-400 hover:text-white'
                }`}
              >
                粘贴节点链接 (Local URIs)
              </button>
              <button
                type="button"
                onClick={() => setEditingSource({ ...editingSource, source: 'remote' })}
                className={`py-2 rounded-lg font-semibold transition-colors ${
                  editingSource.source === 'remote'
                    ? 'bg-blue-500/20 text-blue-300 border border-blue-500/30'
                    : 'text-slate-400 hover:text-white'
                }`}
              >
                远程外部订阅 (HTTP/HTTPS)
              </button>
            </div>
          )}

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <div>
              <label className="block text-xs text-slate-400 mb-1">显示名称 *</label>
              <input
                type="text"
                required
                value={editingSource.displayName}
                onChange={(e) => setEditingSource({ ...editingSource, displayName: e.target.value })}
                placeholder="例如: 日本备用 VPS / 主力机场"
                className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-xs text-white focus:outline-none focus:border-emerald-500"
              />
            </div>
            <div>
              <label className="block text-xs text-slate-400 mb-1">备注说明 (可选)</label>
              <input
                type="text"
                value={editingSource.remark || ''}
                onChange={(e) => setEditingSource({ ...editingSource, remark: e.target.value })}
                placeholder="例如: 东京 CN2 GIA"
                className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-xs text-white focus:outline-none focus:border-emerald-500"
              />
            </div>
          </div>

          {editingSource.source === 'remote' ? (
            <div className="space-y-3.5">
              <div>
                <label className="block text-xs text-slate-400 mb-1">远程订阅 URL *</label>
                <input
                  type="url"
                  required
                  value={editingSource.url || ''}
                  onChange={(e) => setEditingSource({ ...editingSource, url: e.target.value })}
                  placeholder="https://example.com/api/v1/client/subscribe?token=..."
                  className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-xs font-mono text-emerald-300 focus:outline-none focus:border-blue-500"
                />
                <p className="text-[11px] text-slate-500 mt-1.5">
                  全格式支持 Base64 URI、Clash YAML 与 Sing-box JSON，内置反爬 UA 自动协商与 10 分钟容灾缓存。
                </p>
              </div>

              <div className="p-3.5 rounded-xl bg-slate-950/70 border border-slate-800/80 space-y-3">
                <div className="text-[11px] font-semibold text-slate-300">反爬伪装与拉取通道策略 (Anti-WAF Options)</div>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                  <div>
                    <label className="block text-[11px] text-slate-400 mb-1">客户端 User-Agent 伪装</label>
                    <select
                      value={editingSource.userAgent || 'auto'}
                      onChange={(e) => setEditingSource({ ...editingSource, userAgent: e.target.value })}
                      className="w-full bg-slate-900 border border-slate-800 rounded-xl px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-blue-500"
                    >
                      <option value="auto">智能自适应协商 (推荐)</option>
                      <option value="v2rayng">v2rayNG (轻量 Base64 URI)</option>
                      <option value="shadowrocket">Shadowrocket (iOS CFNetwork)</option>
                      <option value="clashmeta">Clash.Meta / Mihomo (YAML)</option>
                      <option value="singbox">Sing-box SFA (JSON)</option>
                    </select>
                  </div>
                  <div>
                    <label className="block text-[11px] text-slate-400 mb-1">拉取出口通道</label>
                    <select
                      value={editingSource.proxyMode || 'auto'}
                      onChange={(e) => setEditingSource({ ...editingSource, proxyMode: e.target.value })}
                      className="w-full bg-slate-900 border border-slate-800 rounded-xl px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-blue-500"
                    >
                      <option value="auto">智能容灾 (直连优先 · 失败转 WARP)</option>
                      <option value="direct">强制本机直连 (Direct)</option>
                      <option value="warp">强制走 WARP SOCKS5 (127.0.0.1:40000)</option>
                    </select>
                  </div>
                </div>
              </div>
            </div>
          ) : (
            <div>
              <label className="block text-xs text-slate-400 mb-1">
                节点分享链接 (每行一条 URI，或粘贴 Base64 / Clash YAML / Sing-box JSON) *
              </label>
              <textarea
                rows={6}
                required
                value={editingSource.content || ''}
                onChange={(e) => setEditingSource({ ...editingSource, content: e.target.value })}
                placeholder={'vless://uuid@host:443?security=reality&sni=...#Node-1\nhysteria2://pass@host:443/?sni=...#Node-2'}
                className="w-full bg-slate-950 border border-slate-800 rounded-xl p-3 text-xs font-mono text-emerald-300 focus:outline-none focus:border-emerald-500"
              />
            </div>
          )}
        </div>

        <div className="px-6 py-4 bg-slate-950/60 border-t border-slate-800 flex items-center justify-end gap-2.5">
          <button
            type="button"
            onClick={() => setEditingSource(null)}
            className="px-4 py-2 rounded-xl text-xs text-slate-400 hover:text-white hover:bg-slate-800"
          >
            取消
          </button>
          <button
            type="submit"
            disabled={savingSource}
            className="flex items-center gap-1.5 px-4 py-2 rounded-xl bg-emerald-500 hover:bg-emerald-600 text-slate-950 font-semibold text-xs transition-colors disabled:opacity-50"
          >
            {savingSource && <RefreshCw className="w-3.5 h-3.5 animate-spin" />}
            <span>{savingSource ? '正在校验并保存...' : '保存节点源'}</span>
          </button>
        </div>
      </form>
    </div>
  );
};

export const ConversionPreviewModal: React.FC<{
  previewTarget: string;
  previewData: SubscriptionPreviewResponse | null;
  loadingPreview: boolean;
  copiedKey: string | null;
  onSelectTarget: (target: string) => void;
  onCopyContent: () => void;
  onDownload: () => void;
  onClose: () => void;
}> = ({
  previewTarget,
  previewData,
  loadingPreview,
  copiedKey,
  onSelectTarget,
  onCopyContent,
  onDownload,
  onClose,
}) => {
  return (
    <div className="fixed inset-0 z-50 flex items-end sm:items-center justify-center sm:p-4 bg-slate-950/85 backdrop-blur-md">
      <div className="bg-slate-900 border-t sm:border border-slate-800 rounded-t-3xl sm:rounded-3xl w-full max-w-4xl max-h-[90dvh] flex flex-col overflow-hidden shadow-2xl pb-safe">
        <div className="flex items-center justify-between px-6 py-4 border-b border-slate-800">
          <div>
            <h4 className="text-base font-bold text-white flex items-center gap-2">
              <FileCode2 className="w-4 h-4 text-purple-400" />
              <span>多客户端订阅实时转换预览</span>
              {previewData && (
                <span className="px-2 py-0.5 rounded-md text-[11px] font-mono bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                  {previewData.nodeCount} 个节点
                </span>
              )}
            </h4>
            <p className="text-xs text-slate-400 mt-0.5 font-mono">
              {previewData?.filename || '选择目标格式查看 SubHub 实时渲染结果'}
            </p>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-xl hover:bg-slate-800 text-slate-400 hover:text-white"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        <div className="px-6 py-3 bg-slate-950/60 border-b border-slate-800 flex flex-wrap items-center justify-between gap-2">
          <div className="flex flex-wrap items-center gap-1.5">
            {PREVIEW_TARGETS.map((t) => (
              <button
                key={t.key}
                onClick={() => onSelectTarget(t.key)}
                className={`px-3 py-1.5 rounded-xl text-xs font-mono transition-colors ${
                  previewTarget === t.key
                    ? 'bg-purple-500/20 text-purple-200 border border-purple-500/40 font-semibold'
                    : 'bg-slate-900 text-slate-400 hover:text-white border border-slate-800'
                }`}
              >
                {t.label}
              </button>
            ))}
          </div>
          {previewData && (
            <div className="flex items-center gap-2">
              <button
                onClick={onCopyContent}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs"
              >
                {copiedKey === 'preview-copy' ? (
                  <Check className="w-3.5 h-3.5 text-emerald-400" />
                ) : (
                  <Copy className="w-3.5 h-3.5" />
                )}
                <span>复制内容</span>
              </button>
              <button
                onClick={onDownload}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-xl bg-emerald-500/15 hover:bg-emerald-500/25 border border-emerald-500/30 text-emerald-300 text-xs font-semibold"
              >
                <Download className="w-3.5 h-3.5" />
                <span>下载文件</span>
              </button>
            </div>
          )}
        </div>

        <div className="p-5 flex-1 overflow-y-auto bg-[#060913] font-mono text-xs text-slate-300">
          {loadingPreview ? (
            <div className="py-16 text-center text-slate-400">
              <RefreshCw className="w-5 h-5 animate-spin mx-auto mb-2 text-purple-400" />
              <span>正在实时生成 {previewTarget} 配置...</span>
            </div>
          ) : (
            <pre className="whitespace-pre-wrap break-all leading-relaxed">{previewData?.content || ''}</pre>
          )}
        </div>
      </div>
    </div>
  );
};

export const QRCodeModal: React.FC<{ url: string; onClose: () => void }> = ({ url, onClose }) => {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-md">
      <div className="bg-slate-900 border border-slate-800 rounded-3xl p-6 max-w-sm w-full flex flex-col items-center text-center shadow-2xl relative">
        <button
          onClick={onClose}
          className="absolute top-4 right-4 p-1.5 rounded-xl hover:bg-slate-800 text-slate-400 hover:text-white transition-colors"
        >
          <X className="w-4 h-4" />
        </button>
        <h4 className="text-base font-bold text-white mt-1">手机扫码快速导入</h4>
        <p className="text-xs text-slate-400 mt-1">使用 Shadowrocket 或支持二维码的客户端扫码</p>
        <QRCodeBox value={url} size={236} className="mt-5" />
        <p className="text-[11px] font-mono text-slate-400 mt-4 break-all max-w-xs line-clamp-2">{url}</p>
      </div>
    </div>
  );
};

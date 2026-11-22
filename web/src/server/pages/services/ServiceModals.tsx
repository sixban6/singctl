import React from 'react';
import { CheckCircle2, Edit3, Save, X } from 'lucide-react';

interface ConfigEditorModalProps {
  viewingConfig: { service: string; path: string; content: string };
  editedConfig: string;
  setEditedConfig: (v: string) => void;
  savingConfig: boolean;
  onClose: () => void;
  onSave: () => void;
}

export const ConfigEditorModal: React.FC<ConfigEditorModalProps> = ({
  viewingConfig,
  editedConfig,
  setEditedConfig,
  savingConfig,
  onClose,
  onSave,
}) => {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/85 backdrop-blur-md">
      <div className="bg-slate-900 border border-slate-800 rounded-3xl w-full max-w-4xl max-h-[90vh] flex flex-col shadow-2xl overflow-hidden">
        <div className="flex items-center justify-between p-4 sm:px-6 border-b border-slate-800">
          <div className="flex items-center gap-2.5">
            <div className="p-2 rounded-xl bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
              <Edit3 className="w-4 h-4" />
            </div>
            <div>
              <h3 className="font-semibold text-sm text-white flex items-center gap-2">
                <span>在线配置编辑</span>
                <span className="text-xs px-2 py-0.5 rounded-md bg-slate-800 text-slate-400 font-mono">
                  {viewingConfig.service}
                </span>
              </h3>
              <p className="text-xs text-slate-500 font-mono mt-0.5">{viewingConfig.path}</p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 hover:bg-slate-800 rounded-xl text-slate-400 hover:text-white transition-colors"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        <div className="p-4 sm:px-6 flex-1 flex flex-col overflow-hidden bg-slate-950/70">
          <p className="text-[11px] text-slate-500 mb-2 font-mono">
            💡 保存时将自动进行语法校验并重载服务；原配置会自动备份为 .bak 文件
          </p>
          <textarea
            value={editedConfig}
            onChange={(e) => setEditedConfig(e.target.value)}
            spellCheck={false}
            className="w-full flex-1 bg-slate-950 border border-slate-800/80 rounded-2xl p-4 font-mono text-xs text-emerald-300/90 leading-relaxed focus:outline-none focus:border-emerald-500/50 resize-none selection:bg-emerald-500/30"
            rows={20}
          />
        </div>

        <div className="p-4 sm:px-6 border-t border-slate-800 flex items-center justify-between bg-slate-900">
          <span className="text-xs text-slate-500 font-mono">
            {editedConfig.split('\n').length} 行 · {new Blob([editedConfig]).size} 字节
          </span>
          <div className="flex items-center gap-2.5">
            <button
              onClick={onClose}
              className="px-4 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-medium transition-colors"
            >
              取消
            </button>
            <button
              onClick={onSave}
              disabled={savingConfig}
              className="flex items-center gap-1.5 px-5 py-2 rounded-xl bg-emerald-500 hover:bg-emerald-600 text-slate-950 text-xs font-semibold shadow-lg shadow-emerald-500/20 transition-all disabled:opacity-50"
            >
              <Save className={`w-3.5 h-3.5 ${savingConfig ? 'animate-spin' : ''}`} />
              <span>{savingConfig ? '正在校验并重载...' : '保存并重载服务'}</span>
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

export const ClientSyncNoticeModal: React.FC<{ onClose: () => void }> = ({ onClose }) => {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm animate-fade-in">
      <div className="w-full max-w-md bg-slate-900 border border-slate-800 rounded-2xl shadow-2xl p-6 text-center space-y-4">
        <div className="w-12 h-12 rounded-2xl bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 flex items-center justify-center mx-auto">
          <CheckCircle2 className="w-6 h-6" />
        </div>
        <div>
          <h4 className="text-base font-bold text-white">服务端核心配置已生效</h4>
          <p className="text-xs text-slate-300 mt-2 leading-relaxed">
            Reality 伪装 SNI / 核心服务配置已在 VPS 完成热重载并同步至 Sub-Store。
          </p>
          <div className="mt-3 p-3 rounded-xl bg-slate-950 border border-slate-800 text-left text-xs text-amber-300 flex items-start gap-2">
            <span className="text-base leading-none">📱</span>
            <span>
              <strong>重要提醒</strong>：请在您的手机/电脑客户端（如 Shadowrocket、Clash Verge、Sing-box 等）中点击
              <strong>【更新订阅】</strong>，以拉取最新节点连接参数！
            </span>
          </div>
        </div>
        <button
          onClick={onClose}
          className="w-full py-2.5 rounded-xl bg-emerald-500 hover:bg-emerald-600 text-slate-950 font-semibold text-xs transition-colors shadow-lg shadow-emerald-500/20"
        >
          我知道了，已了解
        </button>
      </div>
    </div>
  );
};

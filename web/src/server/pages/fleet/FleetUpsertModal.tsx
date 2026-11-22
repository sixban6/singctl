import React from 'react';
import { FleetAuthType, FleetBootstrapDefaults, FleetBootstrapInput, FleetBootstrapPlan } from '../../types';
import { ChevronDown, ChevronUp, RefreshCw, Rocket, Search, ShieldCheck, Sparkles, X } from 'lucide-react';
import { ModalMode } from './helpers';

export const FleetUpsertModal: React.FC<{
  modalMode: ModalMode;
  setModalMode: (m: ModalMode) => void;
  isEditingExisting: boolean;
  submitting: boolean;
  form: FleetBootstrapInput;
  setForm: React.Dispatch<React.SetStateAction<FleetBootstrapInput>>;
  defaults: FleetBootstrapDefaults | null;
  previewPlan: FleetBootstrapPlan | null;
  setPreviewPlan: (p: FleetBootstrapPlan | null) => void;
  previewLoading: boolean;
  showAdvancedBootstrap: boolean;
  setShowAdvancedBootstrap: React.Dispatch<React.SetStateAction<boolean>>;
  onPreviewBootstrap: () => void;
  onSubmit: (e: React.FormEvent) => void;
  onClose: () => void;
}> = ({
  modalMode,
  setModalMode,
  isEditingExisting,
  submitting,
  form,
  setForm,
  defaults,
  previewPlan,
  setPreviewPlan,
  previewLoading,
  showAdvancedBootstrap,
  setShowAdvancedBootstrap,
  onPreviewBootstrap,
  onSubmit,
  onClose,
}) => {
  return (
    <div className="fixed inset-0 z-50 flex items-end sm:items-center justify-center sm:p-4 bg-slate-950/85 backdrop-blur-md">
      <form
        onSubmit={onSubmit}
        className="bg-slate-900 border-t sm:border border-slate-800 rounded-t-3xl sm:rounded-3xl w-full max-w-2xl max-h-[92dvh] sm:max-h-[90vh] flex flex-col overflow-hidden shadow-2xl"
      >
        <div className="flex items-center justify-between px-5 sm:px-6 py-4 border-b border-slate-800 shrink-0">
          <div className="min-w-0">
            <h4 className="text-sm sm:text-base font-bold text-white flex items-center gap-2">
              {modalMode === 'bootstrap' ? (
                <>
                  <Rocket className="w-4 h-4 text-sky-400 shrink-0" />
                  <span>新购裸机智能零配置开荒纳管</span>
                </>
              ) : (
                <>
                  <ShieldCheck className="w-4 h-4 text-emerald-400 shrink-0" />
                  <span>{isEditingExisting ? `编辑舰队子节点 #${form.id}` : '纳管已有 SingCtl 子节点'}</span>
                </>
              )}
            </h4>
            <p className="text-[11px] sm:text-xs text-slate-400 mt-0.5">
              凭据以 0600 权限保存在主控 <code className="text-slate-300">/etc/singctl/</code>，加固后自动擦除初始明文密码
            </p>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="p-2 rounded-xl hover:bg-slate-800 text-slate-400 hover:text-white shrink-0"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        <div className="p-5 sm:p-6 overflow-y-auto space-y-4">
          {!isEditingExisting && (
            <div className="grid grid-cols-2 gap-2 p-1 rounded-xl bg-slate-950 border border-slate-800 text-xs">
              <button
                type="button"
                onClick={() => {
                  setModalMode('bootstrap');
                  setPreviewPlan(null);
                  setForm((prev) => ({
                    ...prev,
                    port: 22,
                    authType: 'password',
                  }));
                }}
                className={`py-2 rounded-lg font-semibold transition-colors ${
                  modalMode === 'bootstrap'
                    ? 'bg-sky-500/20 text-sky-200 border border-sky-500/30'
                    : 'text-slate-400 hover:text-white'
                }`}
              >
                新机 60s 零配置开荒
              </button>
              <button
                type="button"
                onClick={() => {
                  setModalMode('existing');
                  setForm((prev) => ({
                    ...prev,
                    port: prev.port === 22 ? 2222 : prev.port,
                    authType: prev.authType === 'password' && !prev.password ? 'inline_key' : prev.authType,
                  }));
                }}
                className={`py-2 rounded-lg font-semibold transition-colors ${
                  modalMode === 'existing'
                    ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30'
                    : 'text-slate-400 hover:text-white'
                }`}
              >
                纳管已安装节点
              </button>
            </div>
          )}

          {modalMode === 'bootstrap' ? (
            <>
              {/* Master Auto-Inheritance Banner */}
              <div className="p-3.5 rounded-2xl bg-emerald-500/10 border border-emerald-500/25 space-y-1.5">
                <div className="flex items-center gap-1.5 text-xs font-semibold text-emerald-300">
                  <Sparkles className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                  <span>已自动继承本机主控配置（只需填新机 IP 与初始密码）</span>
                </div>
                <p className="text-[11px] text-slate-300 leading-relaxed font-mono">
                  • 节点代号与中文名：按新机 IP 归属地自动分配（同地区多台自动递增如 sg2）
                  <br />• 节点域名与解析：
                  {defaults?.hasMasterCfToken
                    ? `自动在 *.cdn.${defaults.suggestedRootZone || '主控根域名'} 下创建灰云仅 DNS 解析`
                    : '主控未检出 CF Token，请在下方高级选项填入'}
                  <br />• 安全与协议参数：SSH 22→{form.targetSshPort || 2222} 免密禁密码 · SNI=
                  {defaults?.defaultSni || 'swdist.apple.com'} · HY2={defaults?.hy2Up || 50}/{defaults?.hy2Down || 300}M
                </p>
              </div>

              {/* Minimal 2 Primary Inputs */}
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3.5">
                <div>
                  <label className="block text-xs font-medium text-slate-300 mb-1.5">
                    1. 新服务器公网 IP 地址 <span className="text-rose-400">*</span>
                  </label>
                  <input
                    type="text"
                    required={form.authType !== 'ssh_alias'}
                    value={form.host}
                    onChange={(e) => {
                      setForm({ ...form, host: e.target.value });
                      setPreviewPlan(null);
                    }}
                    placeholder="例如: 203.0.113.10"
                    className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3.5 py-2.5 text-xs font-mono text-white focus:outline-none focus:border-sky-500"
                  />
                </div>

                {form.authType === 'password' ? (
                  <div>
                    <label className="block text-xs font-medium text-slate-300 mb-1.5">
                      2. root 初始 SSH 密码 <span className="text-rose-400">*</span>
                    </label>
                    <input
                      type="password"
                      required
                      value={form.password || ''}
                      onChange={(e) => setForm({ ...form, password: e.target.value })}
                      placeholder="粘贴云厂商初始 root 密码"
                      className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3.5 py-2.5 text-xs font-mono text-white focus:outline-none focus:border-sky-500"
                    />
                  </div>
                ) : (
                  <div>
                    <label className="block text-xs font-medium text-slate-300 mb-1.5">2. SSH 私钥路径 / 凭据</label>
                    <input
                      type="text"
                      value={form.keyPath || ''}
                      onChange={(e) => setForm({ ...form, keyPath: e.target.value })}
                      placeholder="~/.ssh/id_ed25519"
                      className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3.5 py-2.5 text-xs font-mono text-white focus:outline-none focus:border-sky-500"
                    />
                  </div>
                )}
              </div>

              {/* Instant Preview Button & Plan Card */}
              <div className="flex flex-wrap items-center justify-between gap-2">
                <button
                  type="button"
                  onClick={onPreviewBootstrap}
                  disabled={previewLoading || !form.host.trim()}
                  className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-xl bg-slate-950 hover:bg-slate-800 border border-slate-800 text-xs text-sky-300 transition-colors disabled:opacity-50"
                >
                  <Search className={`w-3.5 h-3.5 ${previewLoading ? 'animate-spin' : ''}`} />
                  <span>{previewLoading ? '正在探测 IP 归属地与根域名...' : '预览将自动分配的代号与域名'}</span>
                </button>

                <button
                  type="button"
                  onClick={() => setShowAdvancedBootstrap((v) => !v)}
                  className="inline-flex items-center gap-1 text-xs text-slate-400 hover:text-slate-200"
                >
                  <span>高级自定义选项（可选）</span>
                  {showAdvancedBootstrap ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
                </button>
              </div>

              {previewPlan && (
                <div className="p-3.5 rounded-2xl bg-sky-950/25 border border-sky-500/30 text-xs font-mono space-y-1 text-slate-200">
                  <div>
                    • 自动识别代号与名称 :{' '}
                    <span className="text-emerald-300 font-semibold">
                      {previewPlan.id} ({previewPlan.name})
                    </span>
                  </div>
                  <div>
                    • 自动绑定灰云域名   : <span className="text-sky-300 font-semibold">{previewPlan.domain || '需手动指定'}</span>
                  </div>
                  <div>
                    • 安全基线与伪装参数 : SSH {form.port || 22}→{previewPlan.targetSshPort} · SNI={previewPlan.sni}
                  </div>
                </div>
              )}

              {/* Collapsible Optional Overrides */}
              {showAdvancedBootstrap && (
                <div className="p-4 rounded-2xl bg-slate-950/80 border border-slate-800 space-y-3.5">
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                    <div>
                      <label className="block text-xs text-slate-400 mb-1">自定义代号 ID (留空按归属地自动分配)</label>
                      <input
                        type="text"
                        value={form.id || ''}
                        onChange={(e) => setForm({ ...form, id: e.target.value })}
                        placeholder="例如: jp1 或 sg2"
                        className="w-full bg-slate-900 border border-slate-800 rounded-xl px-3 py-2 text-xs font-mono text-white"
                      />
                    </div>
                    <div>
                      <label className="block text-xs text-slate-400 mb-1">自定义显示名称 (留空自动生成中文名)</label>
                      <input
                        type="text"
                        value={form.name || ''}
                        onChange={(e) => setForm({ ...form, name: e.target.value })}
                        placeholder="例如: 日本·东京"
                        className="w-full bg-slate-900 border border-slate-800 rounded-xl px-3 py-2 text-xs text-white"
                      />
                    </div>
                  </div>

                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                    <div>
                      <label className="block text-xs text-slate-400 mb-1">自定义绑定域名 (留空自动分配并创建 DNS)</label>
                      <input
                        type="text"
                        value={form.nodeDomain || ''}
                        onChange={(e) => setForm({ ...form, nodeDomain: e.target.value })}
                        placeholder={
                          defaults?.suggestedRootZone ? `留空自动分配 <id>.${defaults.suggestedRootZone}` : 'jp1.example.com'
                        }
                        className="w-full bg-slate-900 border border-slate-800 rounded-xl px-3 py-2 text-xs font-mono text-white"
                      />
                    </div>
                    <div>
                      <label className="block text-xs text-slate-400 mb-1">
                        Cloudflare Token {defaults?.hasMasterCfToken ? '(留空复用主控)' : '*'}
                      </label>
                      <input
                        type="password"
                        required={!defaults?.hasMasterCfToken}
                        value={form.cfDnsKey || ''}
                        onChange={(e) => setForm({ ...form, cfDnsKey: e.target.value })}
                        placeholder={defaults?.hasMasterCfToken ? '已默认继承主控 cf_dns_key' : '输入 Cloudflare DNS Token'}
                        className="w-full bg-slate-900 border border-slate-800 rounded-xl px-3 py-2 text-xs font-mono text-white"
                      />
                    </div>
                  </div>

                  <div className="grid grid-cols-3 gap-3">
                    <div>
                      <label className="block text-xs text-slate-400 mb-1">初始 SSH 端口</label>
                      <input
                        type="number"
                        value={form.port || 22}
                        onChange={(e) => setForm({ ...form, port: Number(e.target.value) || 22 })}
                        className="w-full bg-slate-900 border border-slate-800 rounded-xl px-3 py-2 text-xs font-mono text-white"
                      />
                    </div>
                    <div>
                      <label className="block text-xs text-slate-400 mb-1">加固收敛端口</label>
                      <input
                        type="number"
                        value={form.targetSshPort || 2222}
                        onChange={(e) => setForm({ ...form, targetSshPort: Number(e.target.value) || 2222 })}
                        className="w-full bg-slate-900 border border-slate-800 rounded-xl px-3 py-2 text-xs font-mono text-white"
                      />
                    </div>
                    <div>
                      <label className="block text-xs text-slate-400 mb-1">伪装 SNI</label>
                      <input
                        type="text"
                        value={form.sni || ''}
                        onChange={(e) => setForm({ ...form, sni: e.target.value })}
                        placeholder={defaults?.defaultSni || 'swdist.apple.com'}
                        className="w-full bg-slate-900 border border-slate-800 rounded-xl px-3 py-2 text-xs font-mono text-white"
                      />
                    </div>
                  </div>

                  <label className="flex items-center gap-2 text-xs text-emerald-300 cursor-pointer select-none">
                    <input
                      type="checkbox"
                      checked={form.hardenSsh !== false}
                      onChange={(e) => setForm({ ...form, hardenSsh: e.target.checked })}
                      className="rounded border-slate-700 bg-slate-900 text-emerald-500"
                    />
                    <span>自动注入主控免密公钥、验证切换 SSH 端口并禁用密码登录</span>
                  </label>
                </div>
              )}
            </>
          ) : (
            /* Existing Node Upsert Mode */
            <>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs text-slate-400 mb-1">节点代号 ID (英文/数字，唯一) *</label>
                  <input
                    type="text"
                    required
                    disabled={isEditingExisting}
                    value={form.id || ''}
                    onChange={(e) => setForm({ ...form, id: e.target.value })}
                    placeholder="例如: jp 或 us-lax"
                    className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-xs font-mono text-white focus:outline-none focus:border-emerald-500 disabled:opacity-60"
                  />
                </div>
                <div>
                  <label className="block text-xs text-slate-400 mb-1">节点显示名称 *</label>
                  <input
                    type="text"
                    required
                    value={form.name || ''}
                    onChange={(e) => setForm({ ...form, name: e.target.value })}
                    placeholder="例如: 日本东京"
                    className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-xs text-white focus:outline-none focus:border-emerald-500"
                  />
                </div>
              </div>

              <div>
                <label className="block text-xs text-slate-400 mb-1">SSH 认证方式</label>
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-xs">
                  {(
                    [
                      { k: 'inline_key', label: '粘贴 SSH 私钥' },
                      { k: 'key_file', label: '主控密钥路径' },
                      { k: 'ssh_alias', label: 'SSH Config 别名' },
                      { k: 'password', label: 'SSH 密码' },
                    ] as { k: FleetAuthType; label: string }[]
                  ).map((opt) => (
                    <button
                      key={opt.k}
                      type="button"
                      onClick={() => setForm({ ...form, authType: opt.k })}
                      className={`py-2 px-2 rounded-xl border font-medium transition-colors ${
                        form.authType === opt.k
                          ? 'bg-emerald-500/15 border-emerald-500/40 text-emerald-300'
                          : 'bg-slate-950 border-slate-800 text-slate-400 hover:text-white'
                      }`}
                    >
                      {opt.label}
                    </button>
                  ))}
                </div>
              </div>

              {form.authType === 'ssh_alias' ? (
                <div>
                  <label className="block text-xs text-slate-400 mb-1">主控 ~/.ssh/config 主机别名 *</label>
                  <input
                    type="text"
                    required
                    value={form.sshAlias || ''}
                    onChange={(e) => setForm({ ...form, sshAlias: e.target.value, host: e.target.value })}
                    placeholder="例如: tokyo-vps"
                    className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-xs font-mono text-white focus:outline-none focus:border-emerald-500"
                  />
                </div>
              ) : (
                <div className="grid grid-cols-1 sm:grid-cols-4 gap-3">
                  <div className="sm:col-span-2">
                    <label className="block text-xs text-slate-400 mb-1">服务器公网 IP 或域名 *</label>
                    <input
                      type="text"
                      required
                      value={form.host}
                      onChange={(e) => setForm({ ...form, host: e.target.value })}
                      placeholder="203.0.113.10"
                      className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-xs font-mono text-white focus:outline-none focus:border-emerald-500"
                    />
                  </div>
                  <div>
                    <label className="block text-xs text-slate-400 mb-1">SSH 端口</label>
                    <input
                      type="number"
                      value={form.port || 2222}
                      onChange={(e) => setForm({ ...form, port: Number(e.target.value) || 2222 })}
                      className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-xs font-mono text-white focus:outline-none focus:border-emerald-500"
                    />
                  </div>
                  <div>
                    <label className="block text-xs text-slate-400 mb-1">SSH 用户</label>
                    <input
                      type="text"
                      value={form.user || 'root'}
                      onChange={(e) => setForm({ ...form, user: e.target.value })}
                      className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-xs font-mono text-white focus:outline-none focus:border-emerald-500"
                    />
                  </div>
                </div>
              )}

              {form.authType === 'inline_key' && (
                <div>
                  <label className="block text-xs text-slate-400 mb-1">
                    SSH 私钥内容 (PEM) {isEditingExisting ? '（留空则保留原托管私钥）' : '*'}
                  </label>
                  <textarea
                    rows={4}
                    required={!isEditingExisting}
                    value={form.privateKey || ''}
                    onChange={(e) => setForm({ ...form, privateKey: e.target.value })}
                    placeholder="-----BEGIN OPENSSH PRIVATE KEY-----&#10;..."
                    className="w-full bg-slate-950 border border-slate-800 rounded-xl p-3 text-xs font-mono text-emerald-300 focus:outline-none focus:border-emerald-500"
                  />
                </div>
              )}

              {form.authType === 'password' && (
                <div>
                  <label className="block text-xs text-slate-400 mb-1">
                    SSH 登录密码 {isEditingExisting ? '（留空则保留原密码）' : '*'}
                  </label>
                  <input
                    type="password"
                    required={!isEditingExisting}
                    value={form.password || ''}
                    onChange={(e) => setForm({ ...form, password: e.target.value })}
                    placeholder="输入目标服务器 SSH 密码"
                    className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-xs font-mono text-white focus:outline-none focus:border-emerald-500"
                  />
                </div>
              )}

              {form.authType === 'key_file' && (
                <div>
                  <label className="block text-xs text-slate-400 mb-1">主控服务器上的私钥路径 *</label>
                  <input
                    type="text"
                    required
                    value={form.keyPath || ''}
                    onChange={(e) => setForm({ ...form, keyPath: e.target.value })}
                    placeholder="/etc/singctl/fleet_keys/master_ed25519"
                    className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-xs font-mono text-white focus:outline-none focus:border-emerald-500"
                  />
                </div>
              )}

              <label className="flex items-center gap-2 text-xs text-slate-300 cursor-pointer select-none pt-1">
                <input
                  type="checkbox"
                  checked={!!form.autoSync}
                  onChange={(e) => setForm({ ...form, autoSync: e.target.checked })}
                  className="rounded border-slate-700 bg-slate-950 text-emerald-500"
                />
                <span>保存后立即通过 SSH 提取该节点 HY2 / Reality 链接并汇入本机总订阅</span>
              </label>
            </>
          )}
        </div>

        <div className="drawer-footer-safe bg-slate-950/80 border-t border-slate-800 flex items-center justify-end gap-2.5 shrink-0">
          <button
            type="button"
            onClick={onClose}
            disabled={submitting}
            className="px-4 py-2 rounded-xl text-xs text-slate-400 hover:text-white hover:bg-slate-800"
          >
            取消
          </button>
          <button
            type="submit"
            disabled={submitting}
            className={`flex items-center gap-1.5 px-4 py-2.5 rounded-xl font-semibold text-xs transition-colors disabled:opacity-50 ${
              modalMode === 'bootstrap'
                ? 'bg-sky-500 hover:bg-sky-600 text-slate-950'
                : 'bg-emerald-500 hover:bg-emerald-600 text-slate-950'
            }`}
          >
            {submitting && <RefreshCw className="w-3.5 h-3.5 animate-spin" />}
            <span>
              {submitting
                ? modalMode === 'bootstrap'
                  ? '正在全自动加固与部署 (约40-90秒)...'
                  : '正在连接并保存...'
                : modalMode === 'bootstrap'
                ? '一键开荒并汇入总订阅'
                : '保存子节点'}
            </span>
          </button>
        </div>
      </form>
    </div>
  );
};

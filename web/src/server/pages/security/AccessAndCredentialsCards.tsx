import React, { useState } from 'react';
import { ServerStatusResponse } from '../../types';
import { api } from '../../api';
import { useToast } from '../../../ui';
import { copyToClipboard } from '../../../lib/clipboard';
import { Check, Copy, Dices, Eye, EyeOff, KeyRound, Lock, Shield, X } from 'lucide-react';
import { generateRandomStrongPassword } from './helpers';

export const AccessAndCredentialsCards: React.FC<{
  status: ServerStatusResponse | null;
  onRefresh: () => void;
}> = ({ status, onRefresh }) => {
  const { success, error } = useToast();
  const [currentPassword, setCurrentPassword] = useState('');
  const [newUsername, setNewUsername] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [showNewPassword, setShowNewPassword] = useState(false);
  const [loadingCreds, setLoadingCreds] = useState(false);
  const [loadingPath, setLoadingPath] = useState(false);

  // 密码规则校验
  const hasMinLength = newPassword.length >= 8;
  const hasUpper = /[A-Z]/.test(newPassword);
  const hasLower = /[a-z]/.test(newPassword);
  const hasDigit = /[0-9]/.test(newPassword);
  const isPasswordValid = hasMinLength && hasUpper && hasLower && hasDigit;

  const handleGenerateRandomPassword = async () => {
    const generated = generateRandomStrongPassword();
    setNewPassword(generated);
    setConfirmPassword(generated);
    setShowNewPassword(true);

    try {
      await copyToClipboard(generated);
      success('已生成 16 位随机强密码并自动复制到剪贴板，请输入当前密码后保存');
    } catch {
      success('已生成 16 位随机强密码并填入输入框，请复制保存');
    }
  };

  const handleCopyNewPassword = async () => {
    if (!newPassword) return;
    try {
      await copyToClipboard(newPassword);
      success('新管理密码已复制到剪贴板');
    } catch {
      error('复制失败，请手动选中复制');
    }
  };

  const handleUpdateCreds = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!currentPassword) {
      error('请输入当前管理密码以验证身份');
      return;
    }
    if (newUsername.trim().toLowerCase() === 'admin') {
      error('管理账号禁止使用默认 admin，请指定专属个性化用户名');
      return;
    }
    if (!isPasswordValid) {
      error('新密码必须至少8位且同时包含大写字母、小写字母和数字');
      return;
    }
    if (newPassword !== confirmPassword) {
      error('两次输入的新密码不一致');
      return;
    }

    setLoadingCreds(true);
    try {
      const res = await api.updateCredentials({
        currentPassword,
        newUsername: newUsername.trim() || status?.admin?.username || 'singctl',
        newPassword,
      });
      success(res.message);
      setCurrentPassword('');
      setNewPassword('');
      setConfirmPassword('');
      onRefresh();
    } catch (err: any) {
      error(err.message || '更新凭据失败');
    } finally {
      setLoadingCreds(false);
    }
  };

  const handleRegeneratePath = async () => {
    if (!window.confirm('确定要重新生成随机隐蔽访问路径吗？生成后 Caddy 将立即热重载，您需要使用新链接访问。')) {
      return;
    }
    setLoadingPath(true);
    try {
      const res = await api.regeneratePath();
      success('全新随机隐蔽路径已生成');
      setTimeout(() => {
        window.location.href = res.httpsUrl;
      }, 1500);
    } catch (err: any) {
      error(err.message || '重新生成失败');
      setLoadingPath(false);
    }
  };

  return (
    <>
      {/* ═══════════════════════ 2. Secret Path Management ═══════════════════════ */}
      <div className="p-4 sm:p-6 rounded-2xl glass-card">
        <div className="flex items-center gap-2 text-emerald-400 text-xs font-semibold uppercase tracking-wider mb-2">
          <Shield className="w-3.5 h-3.5" />
          <span>无特征隐形反代</span>
        </div>
        <h2 className="text-lg sm:text-xl font-bold text-white tracking-tight">专属随机隐蔽入口路径</h2>
        <p className="text-xs text-slate-400 mt-1 max-w-2xl">
          绝不包含任何 <code className="text-rose-400 font-mono">admin</code> 等特征词，外部访问根目录及未授权路径一律显示静态伪装站点或 404，对全网爬虫完全隐身
        </p>

        <div className="mt-4 sm:mt-5 p-4 rounded-xl bg-slate-950/70 border border-slate-800 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
          <div className="font-mono text-xs min-w-0 w-full">
            <div className="text-slate-500">当前 HTTPS 专属访问 URL:</div>
            <div className="text-emerald-400 font-semibold mt-1 break-all select-all">
              {status?.admin?.httpsUrl || '加载中...'}
            </div>
            <div className="text-slate-500 text-[11px] mt-1">
              本地映射: 127.0.0.1:{status?.admin?.port || 8092} (公网端口严密关闭)
            </div>
          </div>
          <button
            onClick={handleRegeneratePath}
            disabled={loadingPath}
            className="w-full sm:w-auto flex items-center justify-center gap-2 px-4 py-2.5 rounded-xl bg-slate-900 hover:bg-slate-800 border border-slate-700/60 text-slate-200 text-xs font-semibold shrink-0 transition-all disabled:opacity-50"
          >
            <Dices className={`w-4 h-4 text-emerald-400 ${loadingPath ? 'animate-spin' : ''}`} />
            <span>重新生成随机路径</span>
          </button>
        </div>
      </div>

      {/* ═══════════════════════ 3. Admin Credentials ═══════════════════════ */}
      <div className="p-4 sm:p-6 rounded-2xl glass-card">
        <div className="flex items-center gap-2 text-purple-400 text-xs font-semibold uppercase tracking-wider mb-2">
          <KeyRound className="w-3.5 h-3.5" />
          <span>身份与凭据治理</span>
        </div>
        <h3 className="text-lg sm:text-xl font-bold text-white tracking-tight">修改管理员账号与强密码</h3>
        <p className="text-xs text-slate-400 mt-1">
          禁止使用默认 admin，密码需严格满足至少 8 位并包含大小写字母与数字
        </p>

        <form onSubmit={handleUpdateCreds} className="mt-5 space-y-4 max-w-xl">
          <div>
            <label className="block text-xs font-medium text-slate-300 mb-1.5">
              当前管理密码 <span className="text-rose-400">*</span>
            </label>
            <input
              type="password"
              value={currentPassword}
              onChange={(e) => setCurrentPassword(e.target.value)}
              placeholder="输入当前密码以确认身份"
              required
              className="w-full bg-slate-950/80 border border-slate-800 rounded-xl px-3.5 py-2.5 text-xs text-slate-200 placeholder:text-slate-600 focus:outline-none focus:border-emerald-500 font-mono"
            />
          </div>

          <div>
            <label className="block text-xs font-medium text-slate-300 mb-1.5">
              新管理员用户名 (当前: <span className="text-emerald-400 font-mono">{status?.admin?.username}</span>)
            </label>
            <input
              type="text"
              value={newUsername}
              onChange={(e) => setNewUsername(e.target.value)}
              placeholder="自定义专属账号 (禁止为 admin)"
              className="w-full bg-slate-950/80 border border-slate-800 rounded-xl px-3.5 py-2.5 text-xs text-slate-200 placeholder:text-slate-600 focus:outline-none focus:border-emerald-500 font-mono"
            />
          </div>

          <div>
            <div className="flex flex-wrap items-center justify-between gap-2 mb-1.5">
              <label className="block text-xs font-medium text-slate-300">
                新管理密码 <span className="text-rose-400">*</span>
              </label>
              <div className="flex items-center gap-1.5">
                <button
                  type="button"
                  onClick={handleGenerateRandomPassword}
                  className="inline-flex items-center gap-1 px-2.5 py-1 rounded-lg bg-emerald-500/15 hover:bg-emerald-500/25 border border-emerald-500/30 text-emerald-300 text-[11px] font-medium transition-all"
                >
                  <Dices className="w-3.5 h-3.5" />
                  <span>随机生成强密码</span>
                </button>
                <button
                  type="button"
                  onClick={() => setShowNewPassword((v) => !v)}
                  className="inline-flex items-center gap-1 px-2 py-1 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-800 text-slate-300 text-[11px] transition-all"
                  title={showNewPassword ? '隐藏密码' : '显示明文'}
                >
                  {showNewPassword ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
                  <span>{showNewPassword ? '隐藏' : '明文'}</span>
                </button>
                {newPassword && (
                  <button
                    type="button"
                    onClick={handleCopyNewPassword}
                    className="inline-flex items-center gap-1 px-2 py-1 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-800 text-slate-300 text-[11px] transition-all"
                    title="复制新密码"
                  >
                    <Copy className="w-3.5 h-3.5" />
                    <span>复制</span>
                  </button>
                )}
              </div>
            </div>
            <input
              type={showNewPassword ? 'text' : 'password'}
              value={newPassword}
              onChange={(e) => setNewPassword(e.target.value)}
              placeholder="至少 8 位，包含大写、小写、数字（可点击右上角一键生成）"
              required
              className="w-full bg-slate-950/80 border border-slate-800 rounded-xl px-3.5 py-2.5 text-xs text-slate-200 placeholder:text-slate-600 focus:outline-none focus:border-emerald-500 font-mono"
            />
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 mt-2.5 text-[11px] font-mono">
              <div className={`flex items-center gap-1 ${hasMinLength ? 'text-emerald-400' : 'text-slate-500'}`}>
                {hasMinLength ? <Check className="w-3 h-3" /> : <X className="w-3 h-3" />}
                <span>长度 ≥ 8 位</span>
              </div>
              <div className={`flex items-center gap-1 ${hasUpper ? 'text-emerald-400' : 'text-slate-500'}`}>
                {hasUpper ? <Check className="w-3 h-3" /> : <X className="w-3 h-3" />}
                <span>包含大写字母</span>
              </div>
              <div className={`flex items-center gap-1 ${hasLower ? 'text-emerald-400' : 'text-slate-500'}`}>
                {hasLower ? <Check className="w-3 h-3" /> : <X className="w-3 h-3" />}
                <span>包含小写字母</span>
              </div>
              <div className={`flex items-center gap-1 ${hasDigit ? 'text-emerald-400' : 'text-slate-500'}`}>
                {hasDigit ? <Check className="w-3 h-3" /> : <X className="w-3 h-3" />}
                <span>包含阿拉伯数字</span>
              </div>
            </div>
          </div>

          <div>
            <label className="block text-xs font-medium text-slate-300 mb-1.5">
              确认新管理密码 <span className="text-rose-400">*</span>
            </label>
            <input
              type={showNewPassword ? 'text' : 'password'}
              value={confirmPassword}
              onChange={(e) => setConfirmPassword(e.target.value)}
              placeholder="再次输入新管理密码"
              required
              className="w-full bg-slate-950/80 border border-slate-800 rounded-xl px-3.5 py-2.5 text-xs text-slate-200 placeholder:text-slate-600 focus:outline-none focus:border-emerald-500 font-mono"
            />
          </div>

          <div className="pt-2">
            <button
              type="submit"
              disabled={loadingCreds || !isPasswordValid}
              className="w-full sm:w-auto flex items-center justify-center gap-2 px-5 py-2.5 rounded-xl bg-emerald-500 hover:bg-emerald-600 text-slate-950 font-semibold text-xs transition-all shadow-lg shadow-emerald-500/20 disabled:opacity-50"
            >
              <Lock className="w-4 h-4" />
              <span>{loadingCreds ? '正在保存...' : '立即保存修改凭据'}</span>
            </button>
          </div>
        </form>
      </div>
    </>
  );
};

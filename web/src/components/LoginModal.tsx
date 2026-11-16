import React, { useRef, useState } from 'react';
import { api } from '../api';
import { Lock, User, Activity, AlertCircle, ArrowRight } from 'lucide-react';

interface LoginModalProps {
  isOpen: boolean;
  onSuccess: (username: string) => void;
}

export const LoginModal: React.FC<LoginModalProps> = ({ isOpen, onSuccess }) => {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [errorMsg, setErrorMsg] = useState('');
  const abortRef = useRef<AbortController | null>(null);

  if (!isOpen) return null;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    abortRef.current?.abort();
    const ctrl = new AbortController();
    abortRef.current = ctrl;

    setLoading(true);
    setErrorMsg('');
    try {
      const res = await api.login(username.trim(), password, ctrl.signal);
      onSuccess(res.username);
    } catch (err: any) {
      if (!ctrl.signal.aborted) {
        setErrorMsg(err.message || '用户名或密码错误');
      }
    } finally {
      if (abortRef.current === ctrl) {
        abortRef.current = null;
        setLoading(false);
      }
    }
  };

  const handleCancel = () => {
    abortRef.current?.abort();
    abortRef.current = null;
    setLoading(false);
    setErrorMsg('已取消当前请求，请重新点击登录');
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center modal-safe bg-slate-950/85 backdrop-blur-xl">
      <div className="bg-slate-900/90 border border-slate-800 rounded-3xl p-7 max-w-sm w-full shadow-2xl relative overflow-hidden">
        {/* Ambient Glow */}
        <div className="absolute top-0 right-0 w-32 h-32 bg-emerald-500/10 rounded-full blur-2xl pointer-events-none"></div>

        {/* Brand Icon */}
        <div className="w-12 h-12 rounded-2xl bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center text-emerald-400 mb-4 glow-green">
          <Activity className="w-6 h-6" />
        </div>

        <h3 className="text-xl font-bold text-white tracking-tight">管理后台身份验证</h3>
        <p className="text-xs text-slate-400 mt-1">请输入管理员账号和强密码以解锁控制面板</p>

        {errorMsg && (
          <div className="mt-4 p-3 rounded-xl bg-rose-500/10 border border-rose-500/20 text-rose-300 text-xs flex items-center gap-2">
            <AlertCircle className="w-4 h-4 shrink-0" />
            <span>{errorMsg}</span>
          </div>
        )}

        <form onSubmit={handleSubmit} className="mt-5 space-y-3.5">
          <div>
            <label className="block text-xs font-medium text-slate-300 mb-1">管理员账号</label>
            <div className="relative">
              <User className="w-4 h-4 text-slate-500 absolute left-3.5 top-3" />
              <input
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="请输入用户名"
                required
                autoFocus
                className="w-full bg-slate-950/80 border border-slate-800 rounded-xl pl-10 pr-3.5 py-2.5 text-xs text-slate-200 placeholder:text-slate-600 focus:outline-none focus:border-emerald-500 font-mono"
              />
            </div>
          </div>

          <div>
            <label className="block text-xs font-medium text-slate-300 mb-1">管理密码</label>
            <div className="relative">
              <Lock className="w-4 h-4 text-slate-500 absolute left-3.5 top-3" />
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="请输入密码"
                required
                className="w-full bg-slate-950/80 border border-slate-800 rounded-xl pl-10 pr-3.5 py-2.5 text-xs text-slate-200 placeholder:text-slate-600 focus:outline-none focus:border-emerald-500 font-mono"
              />
            </div>
          </div>

          <div className="pt-2 space-y-2">
            <button
              type="submit"
              disabled={loading}
              className="w-full flex items-center justify-center gap-2 py-2.5 rounded-xl bg-emerald-500 hover:bg-emerald-600 text-slate-950 font-semibold text-xs transition-all shadow-lg shadow-emerald-500/20 disabled:opacity-50"
            >
              <span>{loading ? '正在验证...' : '登录管理后台'}</span>
              <ArrowRight className="w-4 h-4" />
            </button>
            {loading && (
              <button
                type="button"
                onClick={handleCancel}
                className="w-full py-1.5 rounded-lg text-[11px] font-mono text-slate-400 hover:text-slate-200 transition-colors"
              >
                长时间无响应？点击中断并重试
              </button>
            )}
          </div>
        </form>

        <p className="text-[11px] text-slate-500 text-center mt-5">
          🔒 纯会话保护 · 浏览器关闭自动退出
        </p>
      </div>
    </div>
  );
};

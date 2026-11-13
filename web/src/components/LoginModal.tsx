import React, { useState } from 'react';
import { api } from '../api';
import { Lock, User, Zap, AlertCircle, ArrowRight } from 'lucide-react';
import { Button } from '../ui';

interface LoginModalProps {
  isOpen: boolean;
  onSuccess: (username: string) => void;
}

export const LoginModal: React.FC<LoginModalProps> = ({ isOpen, onSuccess }) => {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [errorMsg, setErrorMsg] = useState('');

  if (!isOpen) return null;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setErrorMsg('');
    try {
      const res = await api.login(username.trim(), password);
      onSuccess(res.username);
    } catch (err: unknown) {
      setErrorMsg(err instanceof Error ? err.message : '用户名或密码错误');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-xl">
      <div className="console-card rounded-3xl p-7 max-w-sm w-full shadow-2xl relative overflow-hidden animate-sc-in">
        <div className="w-12 h-12 rounded-2xl bg-sky-500/12 border border-sky-500/25 flex items-center justify-center text-accent mb-4">
          <Zap className="w-6 h-6" />
        </div>

        <h3 className="text-xl font-bold text-primary tracking-tight">管理后台身份验证</h3>
        <p className="text-xs text-secondary mt-1">请输入管理员账号和密码以解锁控制台</p>

        {errorMsg && (
          <div className="mt-4 p-3 rounded-xl bg-rose-500/10 border border-rose-500/25 text-rose-400 text-xs flex items-center gap-2">
            <AlertCircle className="w-4 h-4 shrink-0" />
            <span>{errorMsg}</span>
          </div>
        )}

        <form onSubmit={handleSubmit} className="mt-5 space-y-3.5">
          <div>
            <label className="block text-xs font-medium text-secondary mb-1.5">管理员账号</label>
            <div className="relative">
              <User className="w-4 h-4 text-muted absolute left-3.5 top-3" />
              <input
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="请输入用户名"
                required
                autoFocus
                className="sc-input w-full pl-10 pr-3.5 py-2.5 text-xs font-mono"
              />
            </div>
          </div>

          <div>
            <label className="block text-xs font-medium text-secondary mb-1.5">管理密码</label>
            <div className="relative">
              <Lock className="w-4 h-4 text-muted absolute left-3.5 top-3" />
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="请输入密码"
                required
                className="sc-input w-full pl-10 pr-3.5 py-2.5 text-xs font-mono"
              />
            </div>
          </div>

          <div className="pt-2">
            <Button
              type="submit"
              variant="primary"
              loading={loading}
              className="w-full py-2.5"
              icon={!loading ? <ArrowRight className="w-4 h-4" /> : undefined}
            >
              {loading ? '正在验证...' : '登录管理后台'}
            </Button>
          </div>
        </form>

        <p className="text-[11px] text-muted text-center mt-5">
          纯会话保护 · 支持浏览器 Cookie 自动续期
        </p>
      </div>
    </div>
  );
};

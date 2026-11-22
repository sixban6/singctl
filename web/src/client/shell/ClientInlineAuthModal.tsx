import React, { useCallback, useEffect, useState } from 'react';
import { Lock } from 'lucide-react';
import { Button, useToast } from '../../ui';
import { clientApi, CLIENT_AUTH_EVENT } from '../api';

export interface ClientInlineAuthModalProps {
  suppressPopup: boolean;
  onVerified: () => Promise<void>;
}

export const ClientInlineAuthModal: React.FC<ClientInlineAuthModalProps> = ({
  suppressPopup,
  onVerified,
}) => {
  const { success } = useToast();
  const [authModalOpen, setAuthModalOpen] = useState(false);
  const [authPassword, setAuthPassword] = useState('');
  const [authSubmitting, setAuthSubmitting] = useState(false);
  const [authError, setAuthError] = useState('');

  useEffect(() => {
    const onUnauthorized = () => {
      if (suppressPopup) return;
      setAuthModalOpen(true);
    };
    window.addEventListener(CLIENT_AUTH_EVENT, onUnauthorized);
    return () => window.removeEventListener(CLIENT_AUTH_EVENT, onUnauthorized);
  }, [suppressPopup]);

  const handleInlineLogin = useCallback(
    async (e: React.FormEvent) => {
      e.preventDefault();
      if (!authPassword || authSubmitting) return;
      setAuthSubmitting(true);
      setAuthError('');
      try {
        await clientApi.login(authPassword);
        setAuthModalOpen(false);
        setAuthPassword('');
        success('验证成功，已恢复会话');
        await onVerified();
      } catch (err) {
        setAuthError((err as Error).message || '访问口令验证失败');
      } finally {
        setAuthSubmitting(false);
      }
    },
    [authPassword, authSubmitting, onVerified, success],
  );

  if (!authModalOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/75 backdrop-blur-sm p-4">
      <form
        onSubmit={(e) => void handleInlineLogin(e)}
        className="w-full max-w-sm rounded-2xl border border-slate-800 bg-slate-900 p-6 shadow-2xl space-y-4"
      >
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-cyan-500/15 border border-cyan-400/25 flex items-center justify-center text-cyan-400 shrink-0">
            <Lock className="w-5 h-5" />
          </div>
          <div>
            <h3 className="text-base font-semibold text-slate-100">需要验证访问口令</h3>
            <p className="text-xs text-slate-400">会话已过期或服务已启用口令保护</p>
          </div>
        </div>

        {authError && (
          <div className="rounded-xl border border-rose-500/30 bg-rose-500/10 px-3 py-2 text-xs text-rose-300">
            {authError}
          </div>
        )}

        <div className="space-y-1.5">
          <label className="block text-xs font-medium text-slate-300">WebUI 访问口令</label>
          <input
            type="password"
            value={authPassword}
            onChange={(e) => setAuthPassword(e.target.value)}
            placeholder="请输入访问口令"
            autoFocus
            required
            className="w-full h-10 rounded-xl border border-slate-700 bg-slate-950 px-3 text-sm text-slate-100 placeholder:text-slate-500 focus:border-cyan-500 focus:outline-none"
          />
        </div>

        <div className="flex items-center justify-end gap-2 pt-1">
          <Button
            type="submit"
            variant="primary"
            loading={authSubmitting}
            disabled={!authPassword || authSubmitting}
            className="w-full justify-center"
          >
            {authSubmitting ? '正在验证...' : '验证并恢复控制台'}
          </Button>
        </div>
      </form>
    </div>
  );
};

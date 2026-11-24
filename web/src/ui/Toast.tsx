import React, { createContext, useContext, useState, useCallback } from 'react';
import { CheckCircle2, AlertCircle, AlertTriangle, Info, X } from 'lucide-react';

export type ToastType = 'success' | 'error' | 'warn' | 'info';

export interface ToastAction {
  label: string;
  onClick: () => void | Promise<void>;
}

interface ToastItem {
  id: string;
  type: ToastType;
  message: string;
  action?: ToastAction;
}

interface ToastContextType {
  toast: (message: string, type?: ToastType, durationMs?: number, action?: ToastAction) => void;
  success: (message: string, durationMs?: number, action?: ToastAction) => void;
  error: (message: string, durationMs?: number) => void;
  warn: (message: string, durationMs?: number) => void;
}

const ToastContext = createContext<ToastContextType | null>(null);

export const ToastProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [toasts, setToasts] = useState<ToastItem[]>([]);

  const removeToast = useCallback((id: string) => {
    setToasts((prev) => prev.filter((t) => t.id !== id));
  }, []);

  const toast = useCallback(
    (message: string, type: ToastType = 'info', durationMs = 4200, action?: ToastAction) => {
      const id = Math.random().toString(36).slice(2, 10);
      setToasts((prev) => [...prev.slice(-4), { id, type, message, action }]);
      setTimeout(() => removeToast(id), durationMs);
    },
    [removeToast],
  );

  const success = useCallback(
    (msg: string, ms?: number, action?: ToastAction) => toast(msg, 'success', ms, action),
    [toast],
  );
  const error = useCallback((msg: string, ms?: number) => toast(msg, 'error', ms), [toast]);
  const warn = useCallback((msg: string, ms?: number) => toast(msg, 'warn', ms), [toast]);

  return (
    <ToastContext.Provider value={{ toast, success, error, warn }}>
      {children}
      <div className="fixed bottom-mobile-toast md:bottom-5 left-4 right-4 sm:left-auto sm:right-6 z-[70] flex flex-col gap-2 sm:max-w-sm sm:w-full pointer-events-none">
        {toasts.map((t) => {
          const borderStyle =
            t.type === 'success'
              ? { borderColor: 'var(--status-ok)' }
              : t.type === 'error'
              ? { borderColor: 'var(--status-danger)' }
              : t.type === 'warn'
              ? { borderColor: 'var(--status-warn)' }
              : undefined;

          return (
            <div
              key={t.id}
              style={borderStyle}
              className="pointer-events-auto flex items-center justify-between gap-2.5 px-3.5 py-2.5 rounded-xl bg-surface1 border border-strong text-primary shadow-xl animate-sc-in"
            >
              <div className="flex items-center gap-2.5 text-xs sm:text-sm font-medium min-w-0">
                {t.type === 'success' && (
                  <CheckCircle2 className="w-4 h-4 shrink-0" style={{ color: 'var(--status-ok)' }} />
                )}
                {t.type === 'error' && (
                  <AlertCircle className="w-4 h-4 shrink-0" style={{ color: 'var(--status-danger)' }} />
                )}
                {t.type === 'warn' && (
                  <AlertTriangle className="w-4 h-4 shrink-0" style={{ color: 'var(--status-warn)' }} />
                )}
                {t.type === 'info' && (
                  <Info className="w-4 h-4 shrink-0" style={{ color: 'var(--accent)' }} />
                )}
                <span className="break-words">{t.message}</span>
              </div>
              <div className="flex items-center gap-1 shrink-0">
                {t.action && (
                  <button
                    type="button"
                    onClick={() => {
                      const act = t.action;
                      removeToast(t.id);
                      void act?.onClick();
                    }}
                    className="px-2 py-1 rounded-lg bg-accent/15 hover:bg-accent/25 text-accent text-xs font-semibold transition-colors cursor-pointer"
                  >
                    {t.action.label}
                  </button>
                )}
                <button
                  type="button"
                  onClick={() => removeToast(t.id)}
                  className="p-1 rounded-lg text-muted hover:text-primary hover:bg-surfaceHover transition-colors shrink-0 cursor-pointer"
                >
                  <X className="w-3.5 h-3.5" />
                </button>
              </div>
            </div>
          );
        })}
      </div>
    </ToastContext.Provider>
  );
};

export const useToast = () => {
  const ctx = useContext(ToastContext);
  if (!ctx) throw new Error('useToast must be used within ToastProvider');
  return ctx;
};

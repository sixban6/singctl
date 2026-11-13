import React, { createContext, useContext, useState, useCallback } from 'react';
import { CheckCircle2, AlertCircle, AlertTriangle, Info, X } from 'lucide-react';

export type ToastType = 'success' | 'error' | 'warn' | 'info';

interface ToastItem {
  id: string;
  type: ToastType;
  message: string;
}

interface ToastContextType {
  toast: (message: string, type?: ToastType, durationMs?: number) => void;
  success: (message: string, durationMs?: number) => void;
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
    (message: string, type: ToastType = 'info', durationMs = 4200) => {
      const id = Math.random().toString(36).slice(2, 10);
      setToasts((prev) => [...prev.slice(-4), { id, type, message }]);
      setTimeout(() => removeToast(id), durationMs);
    },
    [removeToast],
  );

  const success = useCallback((msg: string, ms?: number) => toast(msg, 'success', ms), [toast]);
  const error = useCallback((msg: string, ms?: number) => toast(msg, 'error', ms), [toast]);
  const warn = useCallback((msg: string, ms?: number) => toast(msg, 'warn', ms), [toast]);

  return (
    <ToastContext.Provider value={{ toast, success, error, warn }}>
      {children}
      <div className="fixed bottom-20 md:bottom-5 right-4 z-[70] flex flex-col gap-2 max-w-sm w-[calc(100vw-2rem)] sm:w-full pointer-events-none">
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
              <button
                type="button"
                onClick={() => removeToast(t.id)}
                className="p-1 rounded-lg text-muted hover:text-primary hover:bg-surfaceHover transition-colors shrink-0"
              >
                <X className="w-3.5 h-3.5" />
              </button>
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

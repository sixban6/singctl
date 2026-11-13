import React, { useEffect } from 'react';
import { createPortal } from 'react-dom';
import { X } from 'lucide-react';

export type DrawerSize = 'md' | 'lg' | 'xl';

const SIZE_MAX_WIDTH: Record<DrawerSize, string> = {
  md: 'max-w-[520px]',
  lg: 'max-w-[700px]',
  xl: 'max-w-[900px]',
};

export interface SlideDrawerProps {
  open: boolean;
  onClose: () => void;
  title: React.ReactNode;
  subtitle?: React.ReactNode;
  size?: DrawerSize;
  headerExtra?: React.ReactNode;
  footer?: React.ReactNode;
  children: React.ReactNode;
}

export const SlideDrawer: React.FC<SlideDrawerProps> = ({
  open,
  onClose,
  title,
  subtitle,
  size = 'md',
  headerExtra,
  footer,
  children,
}) => {
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', onKey);
    const prevOverflow = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
    return () => {
      window.removeEventListener('keydown', onKey);
      document.body.style.overflow = prevOverflow;
    };
  }, [open, onClose]);

  if (!open) return null;

  return createPortal(
    <div
      className="fixed inset-0 z-50 flex justify-end bg-slate-950/75 backdrop-blur-sm animate-sc-in"
      onClick={onClose}
      role="dialog"
      aria-modal="true"
    >
      <div
        className={`w-full ${SIZE_MAX_WIDTH[size]} h-full max-h-[100dvh] bg-slate-900/95 backdrop-blur-xl border-l border-slate-800 shadow-2xl flex flex-col`}
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-start justify-between gap-3 px-5 py-4 border-b border-slate-800/80 shrink-0">
          <div className="min-w-0">
            <h3 className="text-base font-semibold text-white truncate">{title}</h3>
            {subtitle && <p className="text-xs text-slate-400 mt-0.5 break-all">{subtitle}</p>}
          </div>
          <div className="flex items-center gap-2 shrink-0">
            {headerExtra}
            <button
              type="button"
              onClick={onClose}
              className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800/70 transition-colors"
              aria-label="关闭抽屉"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
        </div>

        <div className="flex-1 min-h-0 overflow-y-auto p-5 space-y-4">{children}</div>

        {footer && (
          <div
            className="px-5 pt-3.5 border-t border-slate-800/80 bg-slate-950/80 flex items-center justify-end gap-2.5 shrink-0"
            style={{ paddingBottom: 'calc(0.875rem + env(safe-area-inset-bottom, 0px))' }}
          >
            <div className="w-full">{footer}</div>
          </div>
        )}
      </div>
    </div>,
    document.body,
  );
};

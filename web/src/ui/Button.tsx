import React from 'react';
import { Loader2 } from 'lucide-react';

export type ButtonVariant = 'primary' | 'secondary' | 'ghost' | 'danger';
export type ButtonSize = 'xs' | 'sm' | 'md';

export interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: ButtonVariant;
  size?: ButtonSize;
  loading?: boolean;
  icon?: React.ReactNode;
}

const SIZE_CLASSES: Record<ButtonSize, string> = {
  xs: 'h-7 px-2.5 text-[11px] rounded-lg gap-1.5',
  sm: 'h-8 px-3 text-xs rounded-xl gap-1.5',
  md: 'h-9 px-4 text-sm rounded-xl gap-2',
};

const VARIANT_CLASSES: Record<ButtonVariant, string> = {
  primary:
    'font-semibold bg-emerald-500 hover:bg-emerald-400 active:bg-emerald-600 text-slate-950 border border-emerald-400/30 shadow-sm shadow-emerald-500/20',
  secondary:
    'font-medium bg-slate-900 hover:bg-slate-800/90 text-slate-200 border border-slate-800 hover:border-emerald-500/35',
  ghost:
    'font-medium bg-transparent text-slate-400 hover:text-white hover:bg-slate-900/70 border border-transparent',
  danger:
    'font-semibold bg-rose-500/10 hover:bg-rose-500/20 text-rose-300 border border-rose-500/25',
};

export const Button: React.FC<ButtonProps> = ({
  variant = 'secondary',
  size = 'sm',
  loading = false,
  icon,
  disabled,
  className = '',
  children,
  style,
  type = 'button',
  ...rest
}) => (
  <button
    type={type}
    disabled={disabled || loading}
    style={style}
    className={`inline-flex items-center justify-center whitespace-nowrap transition-all duration-150 disabled:opacity-50 disabled:pointer-events-none select-none cursor-pointer ${SIZE_CLASSES[size]} ${VARIANT_CLASSES[variant]} ${className}`}
    {...rest}
  >
    {loading ? (
      <Loader2 className="w-3.5 h-3.5 animate-spin shrink-0" />
    ) : icon ? (
      <span className="shrink-0 flex items-center">{icon}</span>
    ) : null}
    {children}
  </button>
);

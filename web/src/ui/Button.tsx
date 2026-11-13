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
  sm: 'h-8 px-3 text-xs rounded-lg gap-1.5',
  md: 'h-9 px-3.5 text-sm rounded-xl gap-2',
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
}) => {
  let variantClass = '';
  let variantStyle: React.CSSProperties | undefined;

  switch (variant) {
    case 'primary':
      variantClass = 'font-semibold border border-transparent hover:brightness-110 active:brightness-95 shadow-sm';
      variantStyle = {
        backgroundColor: 'var(--accent)',
        color: 'var(--on-accent)',
      };
      break;
    case 'secondary':
      variantClass =
        'font-medium bg-surface2 text-primary border border-subtle hover:border-strong hover:bg-surfaceHover';
      break;
    case 'ghost':
      variantClass =
        'font-medium bg-transparent text-secondary border border-transparent hover:text-primary hover:bg-surfaceHover';
      break;
    case 'danger':
      variantClass = 'font-semibold border hover:brightness-110';
      variantStyle = {
        backgroundColor: 'var(--status-danger-soft)',
        color: 'var(--status-danger)',
        borderColor: 'color-mix(in srgb, var(--status-danger) 28%, transparent)',
      };
      break;
  }

  return (
    <button
      type={type}
      disabled={disabled || loading}
      style={{ ...variantStyle, ...style }}
      className={`inline-flex items-center justify-center whitespace-nowrap transition-all duration-150 disabled:opacity-50 disabled:pointer-events-none select-none cursor-pointer ${SIZE_CLASSES[size]} ${variantClass} ${className}`}
      {...rest}
    >
      {loading ? <Loader2 className="w-3.5 h-3.5 animate-spin shrink-0" /> : icon ? <span className="shrink-0 flex items-center">{icon}</span> : null}
      {children}
    </button>
  );
};

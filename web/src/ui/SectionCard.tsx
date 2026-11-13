import React, { useState } from 'react';
import { ChevronDown, ChevronRight } from 'lucide-react';

export interface SectionCardProps {
  title?: React.ReactNode;
  subtitle?: React.ReactNode;
  icon?: React.ReactNode;
  badge?: React.ReactNode;
  actions?: React.ReactNode;
  collapsible?: boolean;
  defaultOpen?: boolean;
  noPadding?: boolean;
  className?: string;
  children: React.ReactNode;
}

export const SectionCard: React.FC<SectionCardProps> = ({
  title,
  subtitle,
  icon,
  badge,
  actions,
  collapsible = false,
  defaultOpen = true,
  noPadding = false,
  className = '',
  children,
}) => {
  const [open, setOpen] = useState(defaultOpen);
  const hasHeader = Boolean(title || actions || badge);

  return (
    <section className={`console-card rounded-2xl overflow-hidden ${className}`}>
      {hasHeader && (
        <div
          className={`flex flex-wrap items-center justify-between gap-3 px-4 sm:px-5 py-3.5 ${
            open ? 'border-b border-subtle' : ''
          }`}
        >
          <div className="flex items-center gap-2.5 min-w-0">
            {collapsible && (
              <button
                type="button"
                onClick={() => setOpen((v) => !v)}
                className="p-1 -ml-1 rounded-lg text-secondary hover:text-primary hover:bg-surfaceHover transition-colors"
                aria-expanded={open}
              >
                {open ? <ChevronDown className="w-4 h-4" /> : <ChevronRight className="w-4 h-4" />}
              </button>
            )}
            {icon && (
              <div
                className="w-8 h-8 rounded-xl flex items-center justify-center shrink-0"
                style={{ backgroundColor: 'var(--accent-soft)', color: 'var(--accent)' }}
              >
                {icon}
              </div>
            )}
            <div className="min-w-0">
              <div className="flex items-center gap-2 flex-wrap">
                {title && <h2 className="text-sm font-semibold text-primary tracking-tight">{title}</h2>}
                {badge}
              </div>
              {subtitle && <p className="text-xs text-secondary mt-0.5 truncate">{subtitle}</p>}
            </div>
          </div>
          {actions && <div className="flex items-center gap-2 flex-wrap">{actions}</div>}
        </div>
      )}
      {open && <div className={noPadding ? '' : 'p-4 sm:p-5'}>{children}</div>}
    </section>
  );
};

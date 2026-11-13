import React from 'react';

export interface PageHeaderProps {
  title: React.ReactNode;
  description?: React.ReactNode;
  badge?: React.ReactNode;
  actions?: React.ReactNode;
  className?: string;
}

export const PageHeader: React.FC<PageHeaderProps> = ({
  title,
  description,
  badge,
  actions,
  className = '',
}) => (
  <div className={`flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 ${className}`}>
    <div className="min-w-0">
      <div className="flex items-center gap-2.5 flex-wrap">
        <h1 className="text-lg sm:text-xl font-bold text-primary tracking-tight">{title}</h1>
        {badge}
      </div>
      {description && <p className="text-xs sm:text-sm text-secondary mt-1">{description}</p>}
    </div>
    {actions && <div className="flex items-center gap-2 flex-wrap shrink-0">{actions}</div>}
  </div>
);

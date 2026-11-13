import React from 'react';

export interface SegmentedTabItem<T extends string = string> {
  key: T;
  label: string;
  icon?: React.ReactNode;
  badge?: React.ReactNode;
}

export interface SegmentedTabsProps<T extends string = string> {
  items: SegmentedTabItem<NoInfer<T>>[];
  value: T;
  onChange: (key: T) => void;
  className?: string;
}

export function SegmentedTabs<T extends string = string>({
  items,
  value,
  onChange,
  className = '',
}: SegmentedTabsProps<T>) {
  return (
    <div
      className={`inline-flex flex-wrap items-center gap-1 p-1 rounded-xl bg-surface2 border border-subtle ${className}`}
      role="tablist"
    >
      {items.map((item) => {
        const active = item.key === value;
        return (
          <button
            key={item.key}
            type="button"
            role="tab"
            aria-selected={active}
            onClick={() => onChange(item.key)}
            style={
              active
                ? {
                    backgroundColor: 'var(--bg-surface-1)',
                    color: 'var(--accent)',
                    borderColor: 'var(--border-subtle)',
                  }
                : undefined
            }
            className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium border border-transparent transition-all whitespace-nowrap cursor-pointer ${
              active ? 'shadow-sm font-semibold' : 'text-secondary hover:text-primary'
            }`}
          >
            {item.icon && <span className="shrink-0 flex items-center">{item.icon}</span>}
            <span>{item.label}</span>
            {item.badge !== undefined && <span className="ml-0.5">{item.badge}</span>}
          </button>
        );
      })}
    </div>
  );
}

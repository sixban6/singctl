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
      className={`flex sm:inline-flex items-center gap-1 p-1 rounded-xl bg-slate-950/70 border border-slate-800/80 max-w-full overflow-x-auto no-scrollbar ${className}`}
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
            className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium border transition-all whitespace-nowrap cursor-pointer ${
              active
                ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30 shadow-sm font-semibold'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/60 border-transparent'
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

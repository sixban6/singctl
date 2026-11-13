import React from 'react';

export const Skeleton: React.FC<{ className?: string }> = ({ className = '' }) => (
  <div className={`animate-pulse rounded-lg bg-surface2 ${className}`} />
);

export const CardSkeleton: React.FC<{ rows?: number }> = ({ rows = 3 }) => (
  <div className="console-card rounded-2xl p-5 space-y-3">
    <div className="flex items-center justify-between">
      <Skeleton className="h-4 w-32" />
      <Skeleton className="h-5 w-16 rounded-full" />
    </div>
    {Array.from({ length: rows }).map((_, i) => (
      <Skeleton key={i} className={`h-3.5 ${i === rows - 1 ? 'w-2/3' : 'w-full'}`} />
    ))}
  </div>
);

export const TableSkeleton: React.FC<{ rows?: number; cols?: number }> = ({ rows = 5, cols = 5 }) => (
  <div className="p-4 space-y-2.5">
    {Array.from({ length: rows }).map((_, r) => (
      <div key={r} className="grid gap-3" style={{ gridTemplateColumns: `repeat(${cols}, minmax(0, 1fr))` }}>
        {Array.from({ length: cols }).map((__, c) => (
          <Skeleton key={c} className="h-6" />
        ))}
      </div>
    ))}
  </div>
);

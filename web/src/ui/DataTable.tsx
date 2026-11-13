import React from 'react';
import { ArrowDown, ArrowUp, ArrowUpDown } from 'lucide-react';
import { TableSkeleton } from './Skeleton';

export interface DataColumn<T> {
  key: string;
  header: React.ReactNode;
  align?: 'left' | 'right' | 'center';
  sortKey?: string;
  className?: string;
  headerClassName?: string;
  render: (row: T, index: number) => React.ReactNode;
}

export interface DataTableProps<T> {
  columns: DataColumn<T>[];
  rows: T[];
  rowKey: (row: T, index: number) => string;
  loading?: boolean;
  emptyText?: string;
  emptyAction?: React.ReactNode;
  onRowClick?: (row: T, index: number) => void;
  rowClassName?: (row: T, index: number) => string;
  sortBy?: string;
  sortDir?: 'asc' | 'desc';
  onSort?: (key: string) => void;
  compact?: boolean;
}

export function DataTable<T>({
  columns,
  rows,
  rowKey,
  loading = false,
  emptyText = '暂无数据',
  emptyAction,
  onRowClick,
  rowClassName,
  sortBy,
  sortDir,
  onSort,
  compact = false,
}: DataTableProps<T>) {
  if (loading && rows.length === 0) {
    return <TableSkeleton rows={5} cols={Math.min(6, Math.max(3, columns.length))} />;
  }

  if (!rows.length) {
    return (
      <div className="py-12 px-4 text-center space-y-2.5">
        <p className="text-xs sm:text-sm text-muted">{emptyText}</p>
        {emptyAction && <div className="flex justify-center">{emptyAction}</div>}
      </div>
    );
  }

  const cellPad = compact ? 'px-3 py-2' : 'px-3.5 py-2.5 sm:px-4 sm:py-3';

  return (
    <div className="overflow-x-auto">
      <table className="w-full border-collapse text-left">
        <thead>
          <tr className="border-b border-subtle bg-surface2/70">
            {columns.map((col) => {
              const sortable = Boolean(col.sortKey && onSort);
              const isActive = sortable && sortBy === col.sortKey;
              const alignClass =
                col.align === 'right' ? 'text-right' : col.align === 'center' ? 'text-center' : 'text-left';

              return (
                <th
                  key={col.key}
                  className={`${cellPad} text-[11px] font-semibold uppercase tracking-wider text-muted whitespace-nowrap select-none ${alignClass} ${
                    col.headerClassName || ''
                  }`}
                >
                  {sortable ? (
                    <button
                      type="button"
                      onClick={() => onSort?.(col.sortKey!)}
                      className={`inline-flex items-center gap-1 hover:text-primary transition-colors cursor-pointer ${
                        isActive ? 'text-accent' : ''
                      }`}
                    >
                      <span>{col.header}</span>
                      {isActive ? (
                        sortDir === 'asc' ? (
                          <ArrowUp className="w-3 h-3" />
                        ) : (
                          <ArrowDown className="w-3 h-3" />
                        )
                      ) : (
                        <ArrowUpDown className="w-3 h-3 opacity-45" />
                      )}
                    </button>
                  ) : (
                    col.header
                  )}
                </th>
              );
            })}
          </tr>
        </thead>
        <tbody className="divide-y divide-[var(--border-subtle)] text-xs sm:text-[13px]">
          {rows.map((row, idx) => {
            const customCls = rowClassName ? rowClassName(row, idx) : '';
            return (
              <tr
                key={rowKey(row, idx)}
                onClick={onRowClick ? () => onRowClick(row, idx) : undefined}
                className={`transition-colors ${
                  onRowClick ? 'cursor-pointer hover:bg-surfaceHover/60' : 'hover:bg-surface2/45'
                } ${customCls}`}
              >
                {columns.map((col) => {
                  const alignClass =
                    col.align === 'right' ? 'text-right' : col.align === 'center' ? 'text-center' : 'text-left';
                  return (
                    <td key={col.key} className={`${cellPad} align-middle text-primary ${alignClass} ${col.className || ''}`}>
                      {col.render(row, idx)}
                    </td>
                  );
                })}
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

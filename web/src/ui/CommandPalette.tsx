import React, { useState, useEffect, useMemo } from 'react';
import { Search, CornerDownLeft } from 'lucide-react';

export interface CommandItem {
  id: string;
  label: string;
  hint?: string;
  group?: string;
  icon?: React.ReactNode;
  keywords?: string;
  onSelect: () => void;
}

export interface CommandPaletteProps {
  open: boolean;
  onClose: () => void;
  items: CommandItem[];
  placeholder?: string;
}

export const CommandPalette: React.FC<CommandPaletteProps> = ({
  open,
  onClose,
  items,
  placeholder = '搜索页面或快捷操作…',
}) => {
  const [query, setQuery] = useState('');
  const [activeIdx, setActiveIdx] = useState(0);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return items;
    return items.filter((item) => {
      const hay = `${item.label} ${item.hint || ''} ${item.group || ''} ${item.keywords || ''}`.toLowerCase();
      return hay.includes(q);
    });
  }, [items, query]);

  useEffect(() => {
    setActiveIdx(0);
  }, [query, open]);

  useEffect(() => {
    if (!open) {
      setQuery('');
      return;
    }
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        e.preventDefault();
        onClose();
      } else if (e.key === 'ArrowDown') {
        e.preventDefault();
        setActiveIdx((i) => (filtered.length ? (i + 1) % filtered.length : 0));
      } else if (e.key === 'ArrowUp') {
        e.preventDefault();
        setActiveIdx((i) => (filtered.length ? (i - 1 + filtered.length) % filtered.length : 0));
      } else if (e.key === 'Enter' && filtered[activeIdx]) {
        e.preventDefault();
        filtered[activeIdx].onSelect();
        onClose();
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [open, filtered, activeIdx, onClose]);

  if (!open) return null;

  return (
    <div
      className="fixed inset-0 z-[65] flex items-start justify-center pt-[12vh] p-4 bg-black/65 backdrop-blur-sm animate-sc-in"
      onClick={onClose}
      role="dialog"
      aria-modal="true"
    >
      <div
        className="w-full max-w-lg console-card rounded-2xl border border-strong shadow-2xl overflow-hidden"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center gap-2.5 px-4 py-3 border-b border-subtle">
          <Search className="w-4 h-4 text-muted shrink-0" />
          <input
            autoFocus
            type="text"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder={placeholder}
            className="flex-1 bg-transparent text-sm text-primary placeholder:text-muted focus:outline-none"
          />
          <kbd className="hidden sm:inline-flex px-1.5 py-0.5 text-[10px] font-mono rounded border border-subtle text-muted bg-surface2">
            ESC
          </kbd>
        </div>

        <div className="max-h-[55vh] overflow-y-auto p-1.5">
          {filtered.length === 0 ? (
            <div className="py-8 text-center text-xs text-muted">没有匹配的页面或指令</div>
          ) : (
            filtered.map((item, idx) => {
              const selected = idx === activeIdx;
              return (
                <button
                  key={item.id}
                  type="button"
                  onMouseEnter={() => setActiveIdx(idx)}
                  onClick={() => {
                    item.onSelect();
                    onClose();
                  }}
                  style={selected ? { backgroundColor: 'var(--accent-soft)' } : undefined}
                  className={`w-full flex items-center justify-between gap-3 px-3 py-2.5 rounded-xl text-left transition-colors cursor-pointer ${
                    selected ? 'text-primary' : 'text-secondary hover:bg-surface2'
                  }`}
                >
                  <div className="flex items-center gap-2.5 min-w-0">
                    {item.icon && (
                      <span className="shrink-0" style={{ color: selected ? 'var(--accent)' : 'var(--text-muted)' }}>
                        {item.icon}
                      </span>
                    )}
                    <div className="min-w-0">
                      <div className="text-xs sm:text-sm font-medium truncate text-primary">{item.label}</div>
                      {item.hint && <div className="text-[11px] text-muted truncate">{item.hint}</div>}
                    </div>
                  </div>
                  <div className="flex items-center gap-2 shrink-0">
                    {item.group && (
                      <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-surface2 text-muted border border-subtle">
                        {item.group}
                      </span>
                    )}
                    {selected && <CornerDownLeft className="w-3.5 h-3.5 text-muted" />}
                  </div>
                </button>
              );
            })
          )}
        </div>
      </div>
    </div>
  );
};

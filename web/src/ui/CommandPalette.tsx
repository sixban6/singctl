import React, { useState, useEffect, useMemo } from 'react';
import { createPortal } from 'react-dom';
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

  return createPortal(
    <div
      className="fixed inset-0 z-[65] flex items-start justify-center pt-[calc(3.5rem+env(safe-area-inset-top,0px))] sm:pt-[12vh] p-3 sm:p-4 pb-safe bg-slate-950/75 backdrop-blur-md animate-sc-in"
      onClick={onClose}
      role="dialog"
      aria-modal="true"
    >
      <div
        className="w-full max-w-lg bg-slate-900/95 backdrop-blur-xl rounded-2xl border border-slate-800 shadow-2xl overflow-hidden"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center gap-2.5 px-4 py-3 border-b border-slate-800/80">
          <Search className="w-4 h-4 text-emerald-400 shrink-0" />
          <input
            autoFocus
            type="text"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder={placeholder}
            className="flex-1 bg-transparent text-sm text-white placeholder:text-slate-500 focus:outline-none"
          />
          <kbd className="hidden sm:inline-flex px-1.5 py-0.5 text-[10px] font-mono rounded border border-slate-800 text-slate-400 bg-slate-950">
            ESC
          </kbd>
        </div>

        <div className="max-h-[60dvh] overflow-y-auto p-1.5">
          {filtered.length === 0 ? (
            <div className="py-8 text-center text-xs text-slate-500">没有匹配的页面或指令</div>
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
                  className={`w-full flex items-center justify-between gap-3 px-3 py-2.5 rounded-xl text-left transition-colors cursor-pointer ${
                    selected
                      ? 'bg-emerald-500/10 text-emerald-300 border border-emerald-500/25'
                      : 'text-slate-300 hover:bg-slate-800/60 border border-transparent'
                  }`}
                >
                  <div className="flex items-center gap-2.5 min-w-0">
                    {item.icon && (
                      <span className={`shrink-0 ${selected ? 'text-emerald-400' : 'text-slate-500'}`}>
                        {item.icon}
                      </span>
                    )}
                    <div className="min-w-0">
                      <div className="text-xs sm:text-sm font-medium truncate text-white">{item.label}</div>
                      {item.hint && <div className="text-[11px] text-slate-400 truncate">{item.hint}</div>}
                    </div>
                  </div>
                  <div className="flex items-center gap-2 shrink-0">
                    {item.group && (
                      <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-950 text-slate-400 border border-slate-800">
                        {item.group}
                      </span>
                    )}
                    {selected && <CornerDownLeft className="w-3.5 h-3.5 text-emerald-400" />}
                  </div>
                </button>
              );
            })
          )}
        </div>
      </div>
    </div>,
    document.body,
  );
};

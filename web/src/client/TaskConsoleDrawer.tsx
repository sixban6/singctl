import React, { useEffect, useRef } from 'react';
import { Terminal, Copy, Trash2, ChevronDown, Loader2 } from 'lucide-react';
import { Button } from '../ui';

export interface TaskConsoleDrawerProps {
  open: boolean;
  running: boolean;
  title: string;
  cmd: string;
  lines: string[];
  onClose: () => void;
  onClear: () => void;
  onCopy: () => void;
}

export const TaskConsoleDrawer: React.FC<TaskConsoleDrawerProps> = ({
  open,
  running,
  title,
  cmd,
  lines,
  onClose,
  onClear,
  onCopy,
}) => {
  const bodyRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (open && bodyRef.current) {
      bodyRef.current.scrollTop = bodyRef.current.scrollHeight;
    }
  }, [open, lines.length]);

  if (!open) return null;

  return (
    <div className="fixed bottom-mobile-nav md:bottom-0 left-0 right-0 z-50 px-page-safe pb-3 sm:pb-4 pointer-events-none">
      <div className="max-w-5xl mx-auto pointer-events-auto rounded-2xl border border-strong shadow-2xl overflow-hidden bg-[#070a10] text-slate-200 animate-sc-in">
        <div className="flex items-center justify-between gap-3 px-4 py-2.5 border-b border-white/10 bg-[#0d121d]">
          <div className="flex items-center gap-2.5 min-w-0">
            {running ? (
              <Loader2 className="w-4 h-4 animate-spin text-emerald-400 shrink-0" />
            ) : (
              <Terminal className="w-4 h-4 text-emerald-400 shrink-0" />
            )}
            <span className="text-xs font-semibold text-white truncate">{title || '任务控制台'}</span>
            {cmd && (
              <span className="hidden sm:inline text-[11px] font-mono text-slate-400 truncate max-w-md">
                {cmd}
              </span>
            )}
          </div>
          <div className="flex items-center gap-1.5 shrink-0">
            <Button size="xs" variant="ghost" onClick={onCopy} icon={<Copy className="w-3 h-3" />}>
              复制
            </Button>
            <Button size="xs" variant="ghost" onClick={onClear} icon={<Trash2 className="w-3 h-3" />}>
              清空
            </Button>
            <Button size="xs" variant="ghost" onClick={onClose} icon={<ChevronDown className="w-3.5 h-3.5" />}>
              收起
            </Button>
          </div>
        </div>

        <div
          ref={bodyRef}
          className="h-56 sm:h-64 overflow-y-auto px-4 py-3 font-mono text-[11.5px] leading-relaxed space-y-0.5 select-text"
        >
          {lines.length === 0 ? (
            <div className="text-slate-500">等待任务输出…</div>
          ) : (
            lines.map((line, idx) => {
              const colorClass = line.includes('[SUCCESS]')
                ? 'text-emerald-400'
                : line.includes('[ERROR]')
                ? 'text-rose-400'
                : line.includes('[WARN]')
                ? 'text-amber-300'
                : line.includes('[INFO]')
                ? 'text-sky-300'
                : 'text-slate-300';
              return (
                <div key={idx} className={`whitespace-pre-wrap break-all ${colorClass}`}>
                  {line}
                </div>
              );
            })
          )}
        </div>
      </div>
    </div>
  );
};

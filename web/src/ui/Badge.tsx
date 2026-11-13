import React from 'react';

export type BadgeTone = 'ok' | 'warn' | 'danger' | 'accent' | 'neutral';

export interface BadgeProps {
  tone?: BadgeTone;
  dot?: boolean;
  pulse?: boolean;
  children: React.ReactNode;
  className?: string;
  title?: string;
}

const TONE_STYLES: Record<BadgeTone, React.CSSProperties> = {
  ok: {
    backgroundColor: 'var(--status-ok-soft)',
    color: 'var(--status-ok)',
    borderColor: 'color-mix(in srgb, var(--status-ok) 25%, transparent)',
  },
  warn: {
    backgroundColor: 'var(--status-warn-soft)',
    color: 'var(--status-warn)',
    borderColor: 'color-mix(in srgb, var(--status-warn) 25%, transparent)',
  },
  danger: {
    backgroundColor: 'var(--status-danger-soft)',
    color: 'var(--status-danger)',
    borderColor: 'color-mix(in srgb, var(--status-danger) 25%, transparent)',
  },
  accent: {
    backgroundColor: 'var(--accent-soft)',
    color: 'var(--accent)',
    borderColor: 'color-mix(in srgb, var(--accent) 25%, transparent)',
  },
  neutral: {
    backgroundColor: 'var(--bg-surface-2)',
    color: 'var(--text-secondary)',
    borderColor: 'var(--border-subtle)',
  },
};

const DOT_COLORS: Record<BadgeTone, string> = {
  ok: 'var(--status-ok)',
  warn: 'var(--status-warn)',
  danger: 'var(--status-danger)',
  accent: 'var(--accent)',
  neutral: 'var(--text-muted)',
};

export const StatusDot: React.FC<{ tone?: BadgeTone; pulse?: boolean; className?: string }> = ({
  tone = 'neutral',
  pulse = false,
  className = '',
}) => (
  <span className={`relative inline-flex h-2 w-2 shrink-0 ${className}`}>
    {pulse && (
      <span
        className="animate-ping absolute inline-flex h-full w-full rounded-full opacity-60"
        style={{ backgroundColor: DOT_COLORS[tone] }}
      />
    )}
    <span
      className="relative inline-flex rounded-full h-2 w-2"
      style={{ backgroundColor: DOT_COLORS[tone] }}
    />
  </span>
);

export const Badge: React.FC<BadgeProps> = ({
  tone = 'neutral',
  dot = false,
  pulse = false,
  children,
  className = '',
  title,
}) => (
  <span
    title={title}
    style={TONE_STYLES[tone]}
    className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-[11px] font-medium border whitespace-nowrap tnum ${className}`}
  >
    {dot && <StatusDot tone={tone} pulse={pulse} />}
    {children}
  </span>
);

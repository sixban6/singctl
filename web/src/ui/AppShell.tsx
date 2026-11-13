import React, { useState, useEffect, useMemo } from 'react';
import {
  Zap,
  PanelLeftClose,
  PanelLeftOpen,
  Search,
  Sun,
  Moon,
  MoreHorizontal,
  X,
  Check,
} from 'lucide-react';
import { ThemeMode } from '../hooks/useTheme';
import { CommandPalette, CommandItem } from './CommandPalette';

export interface NavItemConfig<T extends string = string> {
  key: T;
  label: string;
  shortLabel: string;
  desc: string;
  icon: React.ComponentType<{ className?: string }>;
  badge?: React.ReactNode;
}

export interface NavGroupConfig<T extends string = string> {
  title: string;
  items: NavItemConfig<T>[];
}

export interface AppShellProps<T extends string = string> {
  brandTitle: string;
  brandSubtitle?: string;
  version?: string;
  groups: NavGroupConfig<T>[];
  activeTab: T;
  onSelectTab: (tab: T) => void;
  mobilePrimaryKeys?: readonly T[];
  statusPill?: React.ReactNode;
  topbarActions?: React.ReactNode;
  banner?: React.ReactNode;
  theme: ThemeMode;
  onToggleTheme: () => void;
  extraCommandItems?: CommandItem[];
  children: React.ReactNode;
}

const SIDEBAR_STORAGE_KEY = 'sc-sidebar-collapsed';

function readInitialCollapsed(): boolean {
  try {
    const saved = localStorage.getItem(SIDEBAR_STORAGE_KEY);
    if (saved === '1') return true;
    if (saved === '0') return false;
  } catch {
    // ignore
  }
  if (typeof window !== 'undefined') {
    return window.innerWidth < 1280;
  }
  return false;
}

export function AppShell<T extends string = string>({
  brandTitle,
  brandSubtitle,
  version,
  groups,
  activeTab,
  onSelectTab,
  mobilePrimaryKeys,
  statusPill,
  topbarActions,
  banner,
  theme,
  onToggleTheme,
  extraCommandItems = [],
  children,
}: AppShellProps<T>) {
  const [collapsed, setCollapsed] = useState<boolean>(readInitialCollapsed);
  const [moreOpen, setMoreOpen] = useState(false);
  const [cmdOpen, setCmdOpen] = useState(false);

  const flatItems = useMemo(() => groups.flatMap((g) => g.items.map((item) => ({ ...item, groupTitle: g.title }))), [groups]);
  const activeItem = flatItems.find((i) => i.key === activeTab) || flatItems[0];

  const { primaryMobile, overflowMobile } = useMemo(() => {
    if (mobilePrimaryKeys && mobilePrimaryKeys.length > 0) {
      const primary = mobilePrimaryKeys
        .map((k) => flatItems.find((i) => i.key === k))
        .filter((i): i is (typeof flatItems)[number] => Boolean(i))
        .slice(0, 4);
      const primarySet = new Set(primary.map((i) => i.key));
      const overflow = flatItems.filter((i) => !primarySet.has(i.key));
      return { primaryMobile: primary, overflowMobile: overflow };
    }
    return { primaryMobile: flatItems.slice(0, 4), overflowMobile: flatItems.slice(4) };
  }, [flatItems, mobilePrimaryKeys]);

  const activeOverflow = overflowMobile.find((i) => i.key === activeTab);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        setCmdOpen((v) => !v);
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, []);

  const toggleCollapsed = () => {
    setCollapsed((prev) => {
      const next = !prev;
      try {
        localStorage.setItem(SIDEBAR_STORAGE_KEY, next ? '1' : '0');
      } catch {
        // ignore
      }
      return next;
    });
  };

  const commandItems = useMemo<CommandItem[]>(() => {
    const navCommands: CommandItem[] = flatItems.map((item) => {
      const Icon = item.icon;
      return {
        id: `nav:${item.key}`,
        label: item.label,
        hint: item.desc,
        group: item.groupTitle,
        keywords: `${item.key} ${item.shortLabel}`,
        icon: <Icon className="w-4 h-4" />,
        onSelect: () => onSelectTab(item.key),
      };
    });
    return [...navCommands, ...extraCommandItems];
  }, [flatItems, extraCommandItems, onSelectTab]);

  return (
    <div className="min-h-dvh flex bg-canvas text-primary">
      {/* Desktop Collapsible Sidebar (>= 768px) */}
      <aside
        className={`hidden md:flex flex-col shrink-0 border-r border-subtle bg-surface1 sticky top-0 h-screen transition-[width] duration-200 z-30 ${
          collapsed ? 'w-[68px]' : 'w-[232px]'
        }`}
      >
        {/* Brand Row */}
        <div
          className={`h-14 flex items-center border-b border-subtle shrink-0 ${
            collapsed ? 'justify-center px-2' : 'justify-between px-4'
          }`}
        >
          <div className="flex items-center gap-2.5 min-w-0">
            <div
              className="w-8 h-8 rounded-xl flex items-center justify-center shrink-0 shadow-sm"
              style={{ backgroundColor: 'var(--accent-soft)', color: 'var(--accent)' }}
            >
              <Zap className="w-4 h-4" />
            </div>
            {!collapsed && (
              <div className="min-w-0">
                <div className="flex items-center gap-1.5">
                  <span className="text-sm font-bold tracking-tight text-primary truncate">{brandTitle}</span>
                  {version && (
                    <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-surface2 text-secondary border border-subtle tnum">
                      v{String(version).replace(/^v/, '')}
                    </span>
                  )}
                </div>
                {brandSubtitle && (
                  <p className="text-[11px] font-mono text-muted truncate max-w-[140px]">{brandSubtitle}</p>
                )}
              </div>
            )}
          </div>
          {!collapsed && (
            <button
              type="button"
              onClick={toggleCollapsed}
              title="收起侧边栏"
              className="p-1.5 rounded-lg text-muted hover:text-primary hover:bg-surfaceHover transition-colors"
            >
              <PanelLeftClose className="w-4 h-4" />
            </button>
          )}
        </div>

        {/* Navigation Groups */}
        <nav className="flex-1 overflow-y-auto px-2.5 py-3 space-y-4">
          {groups.map((group) => (
            <div key={group.title} className="space-y-1">
              {!collapsed ? (
                <div className="px-2.5 pb-1 text-[10px] font-semibold uppercase tracking-wider text-muted">
                  {group.title}
                </div>
              ) : (
                <div className="h-px bg-[var(--border-subtle)] mx-2 my-1.5" />
              )}
              {group.items.map((item) => {
                const Icon = item.icon;
                const active = activeTab === item.key;
                return (
                  <button
                    key={item.key}
                    type="button"
                    title={collapsed ? `${item.label} · ${item.desc}` : undefined}
                    onClick={() => onSelectTab(item.key)}
                    style={
                      active
                        ? {
                            backgroundColor: 'var(--accent-soft)',
                            color: 'var(--accent)',
                          }
                        : undefined
                    }
                    className={`w-full flex items-center ${
                      collapsed ? 'justify-center px-0 py-2.5' : 'justify-between px-2.5 py-2'
                    } rounded-xl text-xs font-medium transition-colors cursor-pointer ${
                      active ? 'font-semibold' : 'text-secondary hover:text-primary hover:bg-surfaceHover/70'
                    }`}
                  >
                    <div className="flex items-center gap-2.5 min-w-0">
                      <Icon className="w-4 h-4 shrink-0" />
                      {!collapsed && <span className="truncate">{item.label}</span>}
                    </div>
                    {!collapsed && item.badge}
                  </button>
                );
              })}
            </div>
          ))}
        </nav>

        {/* Bottom Collapse Expand & Command Hint */}
        <div className="p-2.5 border-t border-subtle space-y-1.5 shrink-0">
          {collapsed ? (
            <button
              type="button"
              onClick={toggleCollapsed}
              title="展开侧边栏"
              className="w-full flex items-center justify-center py-2 rounded-xl text-muted hover:text-primary hover:bg-surfaceHover transition-colors"
            >
              <PanelLeftOpen className="w-4 h-4" />
            </button>
          ) : (
            <button
              type="button"
              onClick={() => setCmdOpen(true)}
              className="w-full flex items-center justify-between px-2.5 py-1.5 rounded-xl bg-surface2 border border-subtle text-[11px] text-muted hover:text-primary hover:border-strong transition-colors"
            >
              <span className="flex items-center gap-1.5">
                <Search className="w-3.5 h-3.5" />
                <span>快速跳转 / 指令</span>
              </span>
              <kbd className="font-mono text-[10px] px-1.5 py-0.5 rounded bg-surface1 border border-subtle">⌘K</kbd>
            </button>
          )}
        </div>
      </aside>

      {/* Main Content Area */}
      <div className="flex-1 min-w-0 flex flex-col">
        {/* Compact Sticky Topbar */}
        <header className="sticky top-0 z-30 h-14 border-b border-subtle bg-surface1/85 backdrop-blur-xl px-3.5 sm:px-6 flex items-center justify-between gap-2.5">
          {/* Left: Mobile Brand OR Desktop Active Breadcrumb */}
          <div className="flex items-center gap-2.5 min-w-0">
            <div
              className="md:hidden w-8 h-8 rounded-xl flex items-center justify-center shrink-0"
              style={{ backgroundColor: 'var(--accent-soft)', color: 'var(--accent)' }}
            >
              <Zap className="w-4 h-4" />
            </div>
            <div className="min-w-0">
              <div className="flex items-center gap-2 text-xs sm:text-sm font-semibold text-primary truncate">
                <span className="md:hidden">{brandTitle}</span>
                {activeItem && (
                  <span className="hidden md:inline-flex items-center gap-1.5 text-secondary font-normal">
                    <span>{activeItem.groupTitle}</span>
                    <span className="text-muted">/</span>
                    <span className="text-primary font-semibold">{activeItem.label}</span>
                  </span>
                )}
                {version && (
                  <span className="md:hidden text-[10px] font-mono px-1.5 py-0.5 rounded bg-surface2 text-secondary border border-subtle tnum">
                    v{String(version).replace(/^v/, '')}
                  </span>
                )}
              </div>
              {brandSubtitle && (
                <p className="md:hidden text-[11px] font-mono text-muted truncate max-w-[160px]">{brandSubtitle}</p>
              )}
            </div>
          </div>

          {/* Right Controls */}
          <div className="flex items-center gap-2 shrink-0">
            {statusPill}

            <button
              type="button"
              onClick={() => setCmdOpen(true)}
              title="快速指令面板 (Cmd/Ctrl + K)"
              className="md:hidden p-2 rounded-lg bg-surface2 border border-subtle text-secondary hover:text-primary transition-colors"
            >
              <Search className="w-4 h-4" />
            </button>

            <button
              type="button"
              onClick={onToggleTheme}
              title={theme === 'dark' ? '切换浅色模式' : '切换暗色模式'}
              className="p-2 rounded-lg bg-surface2 border border-subtle text-secondary hover:text-primary hover:border-strong transition-colors"
              aria-label="切换明暗主题"
            >
              {theme === 'dark' ? <Sun className="w-4 h-4" /> : <Moon className="w-4 h-4" />}
            </button>

            {topbarActions}
          </div>
        </header>

        {banner}

        <main className="flex-1 w-full max-w-[1480px] mx-auto px-3.5 sm:px-6 lg:px-8 py-4 sm:py-6 pb-mobile-nav md:pb-8 space-y-5 animate-sc-in">
          {activeOverflow && (
            <div
              className="md:hidden flex items-center justify-between px-3.5 py-2 rounded-xl border text-xs"
              style={{
                backgroundColor: 'var(--accent-soft)',
                borderColor: 'color-mix(in srgb, var(--accent) 25%, transparent)',
                color: 'var(--accent)',
              }}
            >
              <div className="flex items-center gap-2 font-medium">
                <activeOverflow.icon className="w-4 h-4" />
                <span>当前视图：{activeOverflow.label}</span>
              </div>
              <button type="button" onClick={() => setMoreOpen(true)} className="text-[11px] underline">
                切换
              </button>
            </div>
          )}

          {children}
        </main>
      </div>

      {/* Mobile Frosted Bottom Tab Bar (< 768px) */}
      <nav
        aria-label="移动端主导航"
        className="md:hidden fixed bottom-0 left-0 right-0 z-40 border-t border-subtle bg-surface1/92 backdrop-blur-2xl pb-safe"
      >
        <div className="grid grid-cols-5 h-16 px-1">
          {primaryMobile.map((item) => {
            const Icon = item.icon;
            const active = activeTab === item.key;
            return (
              <button
                key={item.key}
                type="button"
                onClick={() => {
                  setMoreOpen(false);
                  onSelectTab(item.key);
                }}
                style={active ? { color: 'var(--accent)' } : undefined}
                className={`flex flex-col items-center justify-center gap-1 rounded-xl transition-colors ${
                  active ? '' : 'text-secondary'
                }`}
              >
                <div
                  style={active ? { backgroundColor: 'var(--accent-soft)' } : undefined}
                  className="px-3 py-1 rounded-full transition-colors"
                >
                  <Icon className="w-4 h-4" />
                </div>
                <span className="text-[11px] font-medium leading-none">{item.shortLabel}</span>
              </button>
            );
          })}

          <button
            type="button"
            onClick={() => setMoreOpen((v) => !v)}
            style={activeOverflow || moreOpen ? { color: 'var(--accent)' } : undefined}
            className={`flex flex-col items-center justify-center gap-1 rounded-xl transition-colors ${
              activeOverflow || moreOpen ? '' : 'text-secondary'
            }`}
          >
            <div
              style={activeOverflow || moreOpen ? { backgroundColor: 'var(--accent-soft)' } : undefined}
              className="px-3 py-1 rounded-full transition-colors"
            >
              <MoreHorizontal className="w-4 h-4" />
            </div>
            <span className="text-[11px] font-medium leading-none">
              {activeOverflow ? activeOverflow.shortLabel : '更多'}
            </span>
          </button>
        </div>
      </nav>

      {/* Mobile Bottom Sheet for Overflow Tabs */}
      {moreOpen && (
        <div
          className="md:hidden fixed inset-0 z-50 bg-black/60 backdrop-blur-sm flex items-end"
          onClick={() => setMoreOpen(false)}
        >
          <div
            className="w-full bg-surface1 border-t border-strong rounded-t-3xl p-5 pb-safe space-y-3 shadow-2xl max-h-[80vh] overflow-y-auto"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="w-10 h-1 rounded-full bg-[var(--border-strong)] mx-auto mb-1" />
            <div className="flex items-center justify-between">
              <span className="text-sm font-semibold text-primary">全部功能模块</span>
              <button
                type="button"
                onClick={() => setMoreOpen(false)}
                className="p-1.5 rounded-lg bg-surface2 text-secondary hover:text-primary"
              >
                <X className="w-4 h-4" />
              </button>
            </div>
            <div className="space-y-3">
              {groups.map((g) => (
                <div key={g.title} className="space-y-1.5">
                  <div className="text-[10px] font-semibold uppercase tracking-wider text-muted px-1">{g.title}</div>
                  {g.items.map((item) => {
                    const Icon = item.icon;
                    const active = activeTab === item.key;
                    return (
                      <button
                        key={item.key}
                        type="button"
                        onClick={() => {
                          onSelectTab(item.key);
                          setMoreOpen(false);
                        }}
                        style={
                          active
                            ? {
                                backgroundColor: 'var(--accent-soft)',
                                borderColor: 'color-mix(in srgb, var(--accent) 30%, transparent)',
                              }
                            : undefined
                        }
                        className={`w-full flex items-center justify-between p-3 rounded-2xl border transition-all text-left ${
                          active ? 'text-primary' : 'bg-surface2 border-subtle text-secondary'
                        }`}
                      >
                        <div className="flex items-center gap-3 min-w-0">
                          <div
                            className="p-2 rounded-xl bg-surface1"
                            style={active ? { color: 'var(--accent)' } : undefined}
                          >
                            <Icon className="w-4 h-4" />
                          </div>
                          <div className="min-w-0">
                            <div className="text-sm font-semibold text-primary">{item.label}</div>
                            <div className="text-[11px] text-secondary truncate">{item.desc}</div>
                          </div>
                        </div>
                        {active && <Check className="w-4 h-4 shrink-0" style={{ color: 'var(--accent)' }} />}
                      </button>
                    );
                  })}
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      <CommandPalette open={cmdOpen} onClose={() => setCmdOpen(false)} items={commandItems} />
    </div>
  );
}

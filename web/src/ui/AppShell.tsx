import React, { useState, useEffect, useMemo } from 'react';
import { Activity, Search, MoreHorizontal, X, Check } from 'lucide-react';
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
  brandIcon?: React.ReactNode;
  brandIconClassName?: string;
  version?: string;
  groups: NavGroupConfig<T>[];
  activeTab: T;
  onSelectTab: (tab: T) => void;
  mobilePrimaryKeys?: readonly T[];
  statusPill?: React.ReactNode;
  topbarActions?: React.ReactNode;
  banner?: React.ReactNode;
  footerText?: string;
  theme?: ThemeMode;
  onToggleTheme?: () => void;
  extraCommandItems?: CommandItem[];
  children: React.ReactNode;
}

export function AppShell<T extends string = string>({
  brandTitle,
  brandSubtitle,
  brandIcon,
  brandIconClassName,
  version,
  groups,
  activeTab,
  onSelectTab,
  mobilePrimaryKeys,
  statusPill,
  topbarActions,
  banner,
  footerText = 'SingCtl Client Gateway · 极简零外部依赖 · 单二进制内嵌静态控制台',
  extraCommandItems = [],
  children,
}: AppShellProps<T>) {
  const [moreOpen, setMoreOpen] = useState(false);
  const [cmdOpen, setCmdOpen] = useState(false);

  const flatItems = useMemo(
    () => groups.flatMap((g) => g.items.map((item) => ({ ...item, groupTitle: g.title }))),
    [groups],
  );

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
  const isOverflowActive = Boolean(activeOverflow);

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
    <div className="min-h-dvh flex flex-col bg-[#080d1a] text-slate-100 overflow-x-clip">
      {/* Sticky Frosted Glass Header — 1:1 Aligned with Server Console */}
      <header className="sticky top-0 z-40 w-full border-b border-slate-800/80 bg-slate-950/80 backdrop-blur-xl pt-safe">
        <div className="max-w-[1440px] mx-auto px-page-safe h-14 sm:h-16 flex items-center justify-between gap-2">
          {/* Brand */}
          <div className="flex items-center gap-2 sm:gap-3 min-w-0">
            <div
              className={`w-8 h-8 sm:w-9 sm:h-9 rounded-xl flex items-center justify-center shrink-0 ${
                brandIconClassName || 'bg-emerald-500/10 border border-emerald-500/20 glow-green'
              }`}
            >
              {brandIcon || <Activity className="w-4 h-4 sm:w-5 sm:h-5 text-emerald-400" />}
            </div>
            <div className="min-w-0">
              <div className="flex items-center gap-1.5 sm:gap-2">
                <span className="font-bold text-sm sm:text-base tracking-tight text-white whitespace-nowrap shrink-0">
                  {brandTitle}
                </span>
                {version && (
                  <span
                    title={version}
                    className="text-[10px] sm:text-xs px-1.5 sm:px-2 py-0.5 rounded-full bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 font-mono font-medium max-w-[96px] sm:max-w-none truncate"
                  >
                    <span className="sm:hidden">
                      {(version.startsWith('v') ? version : `v${version}`).replace(/\+.*$/, '')}
                    </span>
                    <span className="hidden sm:inline">
                      {version.startsWith('v') ? version : `v${version}`}
                    </span>
                  </span>
                )}
              </div>
              {brandSubtitle && (
                <p className="text-[11px] text-slate-400 font-mono truncate max-w-[150px] xs:max-w-[200px] sm:max-w-xs">
                  {brandSubtitle}
                </p>
              )}
            </div>
          </div>

          {/* Right Status Chips & Actions */}
          <div className="flex items-center gap-1.5 sm:gap-2.5 shrink-0">
            {statusPill && <div className="hidden sm:flex items-center">{statusPill}</div>}

            <button
              type="button"
              onClick={() => setCmdOpen(true)}
              title="快捷跳转与操作 (⌘K)"
              className="hidden sm:inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg bg-slate-900 border border-slate-800 hover:border-emerald-500/30 text-xs text-slate-300 transition-colors cursor-pointer"
            >
              <Search className="w-3.5 h-3.5 text-emerald-400" />
              <span className="hidden lg:inline text-slate-400">快捷指令</span>
              <kbd className="text-[10px] font-mono text-slate-500 px-1 rounded bg-slate-950 border border-slate-800">
                ⌘K
              </kbd>
            </button>

            <button
              type="button"
              onClick={() => setCmdOpen(true)}
              title="快捷跳转"
              aria-label="快捷跳转"
              className="sm:hidden p-1.5 rounded-lg bg-slate-900 border border-slate-800 text-slate-300"
            >
              <Search className="w-3.5 h-3.5 text-emerald-400" />
            </button>

            {topbarActions && (
              <div className="flex items-center gap-1.5 sm:gap-2 pl-2 border-l border-slate-800">
                {topbarActions}
              </div>
            )}
          </div>
        </div>
      </header>

      {/* Main Container matching Server Console max-w-[1440px] */}
      <main className="flex-1 max-w-[1440px] w-full mx-auto px-page-safe py-4 sm:py-6 pb-mobile-nav md:pb-8 space-y-5 sm:space-y-6">
        {banner}

        {/* Desktop & Tablet Horizontal Tab Strip (>= 768px) */}
        <nav
          aria-label="主导航"
          className="hidden md:flex items-center gap-1.5 lg:gap-2 border-b border-slate-800/80 overflow-x-auto py-2 no-scrollbar"
        >
          {flatItems.map((tab) => {
            const Icon = tab.icon;
            const active = activeTab === tab.key;
            return (
              <button
                key={tab.key}
                type="button"
                onClick={() => onSelectTab(tab.key)}
                className={`flex items-center gap-2 px-3.5 py-2 rounded-xl text-xs lg:text-sm font-medium whitespace-nowrap transition-all duration-150 cursor-pointer ${
                  active
                    ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 shadow-sm'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/60 border border-transparent'
                }`}
              >
                <Icon className={`w-4 h-4 ${active ? 'text-emerald-400' : 'text-slate-400'}`} />
                <span>{tab.label}</span>
                {tab.badge && <span className="ml-0.5 flex items-center">{tab.badge}</span>}
              </button>
            );
          })}
        </nav>

        {/* Mobile Active Overflow Indicator (< 768px) */}
        {activeOverflow && (
          <div className="md:hidden flex items-center justify-between px-3.5 py-2 rounded-xl bg-emerald-500/10 border border-emerald-500/25 text-xs text-emerald-300">
            <div className="flex items-center gap-2 font-medium">
              <activeOverflow.icon className="w-4 h-4 text-emerald-400" />
              <span>当前视图：{activeOverflow.label}</span>
            </div>
            <button
              type="button"
              onClick={() => setMoreOpen(true)}
              className="text-[11px] font-mono text-slate-300 underline cursor-pointer"
            >
              切换功能
            </button>
          </div>
        )}

        <div className="pt-1 sm:pt-2">{children}</div>
      </main>

      <footer className="hidden md:block border-t border-slate-900 py-5 text-center text-xs text-slate-600 font-mono">
        {footerText}
      </footer>

      {/* Mobile Frosted-Glass Bottom Tab Bar (< 768px, iOS Safe-Area Adapted) */}
      <nav
        aria-label="移动端主导航"
        className="md:hidden fixed bottom-0 left-0 right-0 z-40 border-t border-slate-800/90 bg-slate-950/90 backdrop-blur-2xl pb-safe pl-safe pr-safe"
      >
        <div className="grid grid-cols-5 h-16 px-2">
          {primaryMobile.map((tab) => {
            const Icon = tab.icon;
            const active = activeTab === tab.key;
            return (
              <button
                key={tab.key}
                type="button"
                onClick={() => {
                  setMoreOpen(false);
                  onSelectTab(tab.key);
                }}
                className={`flex flex-col items-center justify-center gap-1 rounded-xl transition-colors ${
                  active ? 'text-emerald-400' : 'text-slate-400 active:text-slate-200'
                }`}
              >
                <div
                  className={`px-3 py-1 rounded-full transition-colors relative ${
                    active ? 'bg-emerald-500/15' : 'bg-transparent'
                  }`}
                >
                  <Icon className="w-4 h-4" />
                </div>
                <span className="text-[11px] font-medium leading-none">{tab.shortLabel}</span>
              </button>
            );
          })}

          {overflowMobile.length > 0 && (
            <button
              type="button"
              onClick={() => setMoreOpen((v) => !v)}
              className={`flex flex-col items-center justify-center gap-1 rounded-xl transition-colors ${
                isOverflowActive || moreOpen ? 'text-emerald-400' : 'text-slate-400 active:text-slate-200'
              }`}
            >
              <div
                className={`px-3 py-1 rounded-full transition-colors ${
                  isOverflowActive || moreOpen ? 'bg-emerald-500/15' : 'bg-transparent'
                }`}
              >
                <MoreHorizontal className="w-4 h-4" />
              </div>
              <span className="text-[11px] font-medium leading-none">
                {activeOverflow ? activeOverflow.shortLabel : '更多'}
              </span>
            </button>
          )}
        </div>
      </nav>

      {/* Mobile Bottom Sheet for Overflow Tabs */}
      {moreOpen && (
        <div
          className="md:hidden fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-sm flex items-end"
          onClick={() => setMoreOpen(false)}
        >
          <div
            className="w-full bg-slate-900 border-t border-slate-800 rounded-t-3xl sheet-safe space-y-3 shadow-2xl max-h-[calc(82dvh-env(safe-area-inset-top,0px))] overflow-y-auto"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="w-10 h-1 rounded-full bg-slate-700 mx-auto mb-1" />
            <div className="flex items-center justify-between">
              <span className="text-sm font-bold text-white">更多网关管理与运维功能</span>
              <button
                type="button"
                onClick={() => setMoreOpen(false)}
                className="p-1.5 rounded-xl text-slate-400 hover:text-white bg-slate-800/70"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="space-y-2 pt-1 pb-3">
              {overflowMobile.map((tab) => {
                const Icon = tab.icon;
                const active = activeTab === tab.key;
                return (
                  <button
                    key={tab.key}
                    type="button"
                    onClick={() => {
                      onSelectTab(tab.key);
                      setMoreOpen(false);
                    }}
                    className={`w-full flex items-center justify-between p-3.5 rounded-2xl border text-left transition-colors ${
                      active
                        ? 'bg-emerald-500/10 border-emerald-500/35 text-emerald-300'
                        : 'bg-slate-950/70 border-slate-800 text-slate-200 active:bg-slate-800'
                    }`}
                  >
                    <div className="flex items-center gap-3 min-w-0">
                      <div
                        className={`w-9 h-9 rounded-xl flex items-center justify-center shrink-0 ${
                          active ? 'bg-emerald-500/20 text-emerald-400' : 'bg-slate-900 text-slate-400'
                        }`}
                      >
                        <Icon className="w-4 h-4" />
                      </div>
                      <div className="min-w-0">
                        <div className="text-sm font-semibold truncate">{tab.label}</div>
                        <div className="text-[11px] text-slate-400 mt-0.5 truncate">{tab.desc}</div>
                      </div>
                    </div>
                    {active && <Check className="w-4 h-4 text-emerald-400 shrink-0" />}
                  </button>
                );
              })}
            </div>
          </div>
        </div>
      )}

      <CommandPalette open={cmdOpen} onClose={() => setCmdOpen(false)} items={commandItems} />
    </div>
  );
}

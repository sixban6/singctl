import React from 'react';
import { LayoutDashboard, Server, Link2, Terminal, Globe, Shield } from 'lucide-react';

export type TabKey = 'overview' | 'services' | 'subscriptions' | 'logs' | 'diagnostics' | 'security';

interface NavigationProps {
  currentTab: TabKey;
  onChangeTab: (tab: TabKey) => void;
}

export const Navigation: React.FC<NavigationProps> = ({ currentTab, onChangeTab }) => {
  const tabs = [
    { key: 'overview' as TabKey, label: '总览与监控', icon: LayoutDashboard },
    { key: 'services' as TabKey, label: '核心服务管控', icon: Server },
    { key: 'subscriptions' as TabKey, label: '节点与订阅分发', icon: Link2 },
    { key: 'logs' as TabKey, label: '终端实时日志', icon: Terminal },
    { key: 'diagnostics' as TabKey, label: 'WARP与链路体检', icon: Globe },
    { key: 'security' as TabKey, label: '凭据与隐蔽安全', icon: Shield },
  ];

  return (
    <nav className="flex space-x-1 sm:space-x-2 border-b border-slate-800/80 overflow-x-auto py-2 no-scrollbar">
      {tabs.map((tab) => {
        const Icon = tab.icon;
        const active = currentTab === tab.key;
        return (
          <button
            key={tab.key}
            onClick={() => onChangeTab(tab.key)}
            className={`flex items-center gap-2 px-3.5 py-2 rounded-xl text-xs sm:text-sm font-medium whitespace-nowrap transition-all duration-150 ${
              active
                ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 shadow-sm'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/60 border border-transparent'
            }`}
          >
            <Icon className={`w-4 h-4 ${active ? 'text-emerald-400' : 'text-slate-400'}`} />
            <span>{tab.label}</span>
          </button>
        );
      })}
    </nav>
  );
};

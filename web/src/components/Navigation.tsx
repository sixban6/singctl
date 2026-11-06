import React, { useState } from 'react';
import {
  LayoutDashboard,
  Server,
  Link2,
  Network,
  Terminal,
  Globe,
  Shield,
  Radar,
  MoreHorizontal,
  X,
  Check,
} from 'lucide-react';

export type TabKey = 'overview' | 'services' | 'subscriptions' | 'fleet' | 'camouflage' | 'logs' | 'diagnostics' | 'security';

interface NavigationProps {
  currentTab: TabKey;
  onChangeTab: (tab: TabKey) => void;
}

export const Navigation: React.FC<NavigationProps> = ({ currentTab, onChangeTab }) => {
  const [moreOpen, setMoreOpen] = useState(false);

  const allTabs = [
    { key: 'overview' as TabKey, label: '总览与监控', shortLabel: '总览', icon: LayoutDashboard, desc: '实时流量遥测、健康评分与解锁看板' },
    { key: 'services' as TabKey, label: '核心服务管控', shortLabel: '服务', icon: Server, desc: '四核守护进程生命周期与配置在线编辑' },
    { key: 'subscriptions' as TabKey, label: '节点与订阅分发', shortLabel: '订阅', icon: Link2, desc: '全平台订阅链接、防盗刷审计与二维码' },
    { key: 'fleet' as TabKey, label: '全球节点舰队', shortLabel: '舰队', icon: Network, desc: '新机零配置开荒、全网体检与凭据换血' },
    { key: 'security' as TabKey, label: '安全与自愈中心', shortLabel: '安全自愈', icon: Shield, desc: '三层漏洞自动热修复、隐蔽入口与防爆破' },
    { key: 'camouflage' as TabKey, label: '伪装与抗探测评估', shortLabel: '伪装评估', icon: Radar, desc: '五维黑盒协议特征审讯、源站比对与双栈证书核验' },
    { key: 'diagnostics' as TabKey, label: '回程链路探测', shortLabel: '回程', icon: Globe, desc: '三网回程路由追踪 (CN2 GIA / 9929 / CMI)' },
    { key: 'logs' as TabKey, label: '终端实时日志', shortLabel: '日志', icon: Terminal, desc: 'SSE 零轮询彩色实时服务日志流' },
  ];

  const primaryMobileTabs = allTabs.slice(0, 4);
  const overflowMobileTabs = allTabs.slice(4);
  const isOverflowActive = overflowMobileTabs.some((t) => t.key === currentTab);
  const activeOverflowTab = overflowMobileTabs.find((t) => t.key === currentTab);

  return (
    <>
      {/* Desktop & Tablet Horizontal Tab Strip (>= 768px) */}
      <nav className="hidden md:flex items-center gap-1.5 lg:gap-2 border-b border-slate-800/80 overflow-x-auto py-2 no-scrollbar">
        {allTabs.map((tab) => {
          const Icon = tab.icon;
          const active = currentTab === tab.key;
          return (
            <button
              key={tab.key}
              onClick={() => onChangeTab(tab.key)}
              className={`flex items-center gap-2 px-3.5 py-2 rounded-xl text-xs lg:text-sm font-medium whitespace-nowrap transition-all duration-150 ${
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

      {/* Mobile Active Secondary Header Indicator (when viewing More tab on < 768px) */}
      {activeOverflowTab && (
        <div className="md:hidden flex items-center justify-between px-3.5 py-2 rounded-xl bg-emerald-500/10 border border-emerald-500/25 text-xs text-emerald-300">
          <div className="flex items-center gap-2 font-medium">
            <activeOverflowTab.icon className="w-4 h-4 text-emerald-400" />
            <span>当前视图：{activeOverflowTab.label}</span>
          </div>
          <button
            type="button"
            onClick={() => setMoreOpen(true)}
            className="text-[11px] font-mono text-slate-300 underline"
          >
            切换功能
          </button>
        </div>
      )}

      {/* Mobile Frosted-Glass Bottom Tab Bar (< 768px, iOS Safe-Area Adapted) */}
      <nav
        aria-label="移动端主导航"
        className="md:hidden fixed bottom-0 left-0 right-0 z-40 border-t border-slate-800/90 bg-slate-950/90 backdrop-blur-2xl pb-safe"
      >
        <div className="grid grid-cols-5 h-16 px-1">
          {primaryMobileTabs.map((tab) => {
            const Icon = tab.icon;
            const active = currentTab === tab.key;
            return (
              <button
                key={tab.key}
                type="button"
                onClick={() => {
                  setMoreOpen(false);
                  onChangeTab(tab.key);
                }}
                className={`flex flex-col items-center justify-center gap-1 rounded-xl transition-colors ${
                  active ? 'text-emerald-400' : 'text-slate-400 active:text-slate-200'
                }`}
              >
                <div
                  className={`px-3 py-1 rounded-full transition-colors ${
                    active ? 'bg-emerald-500/15' : 'bg-transparent'
                  }`}
                >
                  <Icon className="w-4 h-4" />
                </div>
                <span className="text-[11px] font-medium leading-none">{tab.shortLabel}</span>
              </button>
            );
          })}

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
              {activeOverflowTab ? activeOverflowTab.shortLabel : '更多'}
            </span>
          </button>
        </div>
      </nav>

      {/* Mobile Bottom Sheet for Overflow Tabs */}
      {moreOpen && (
        <div
          className="md:hidden fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-sm flex items-end"
          onClick={() => setMoreOpen(false)}
        >
          <div
            className="w-full bg-slate-900 border-t border-slate-800 rounded-t-3xl p-5 pb-safe space-y-3 shadow-2xl"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="w-10 h-1 rounded-full bg-slate-700 mx-auto mb-1" />
            <div className="flex items-center justify-between">
              <span className="text-sm font-bold text-white">更多运维与安全中枢</span>
              <button
                type="button"
                onClick={() => setMoreOpen(false)}
                className="p-1.5 rounded-xl text-slate-400 hover:text-white bg-slate-800/70"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="space-y-2 pt-1 pb-3">
              {overflowMobileTabs.map((tab) => {
                const Icon = tab.icon;
                const active = currentTab === tab.key;
                return (
                  <button
                    key={tab.key}
                    type="button"
                    onClick={() => {
                      onChangeTab(tab.key);
                      setMoreOpen(false);
                    }}
                    className={`w-full flex items-center justify-between p-3.5 rounded-2xl border text-left transition-colors ${
                      active
                        ? 'bg-emerald-500/10 border-emerald-500/35 text-emerald-300'
                        : 'bg-slate-950/70 border-slate-800 text-slate-200 active:bg-slate-800'
                    }`}
                  >
                    <div className="flex items-center gap-3">
                      <div
                        className={`w-9 h-9 rounded-xl flex items-center justify-center ${
                          active ? 'bg-emerald-500/20 text-emerald-400' : 'bg-slate-900 text-slate-400'
                        }`}
                      >
                        <Icon className="w-4 h-4" />
                      </div>
                      <div>
                        <div className="text-sm font-semibold">{tab.label}</div>
                        <div className="text-[11px] text-slate-400 mt-0.5">{tab.desc}</div>
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
    </>
  );
};

import React from 'react';
import { ArrowUpCircle, CheckCircle2, RefreshCw } from 'lucide-react';

export interface ServiceUpdateState {
  checked: boolean;
  hasUpdate: boolean;
  latestVersion: string;
  message?: string;
}

export type UpdateStateMap = Record<string, ServiceUpdateState>;

interface UpgradeActionButtonProps {
  service: string;
  color: 'emerald' | 'blue' | 'purple' | 'amber';
  updateStates: UpdateStateMap;
  loading: string | null;
  onCheckUpdate: (service: string) => void;
  onExecuteUpgrade: (service: string) => void;
}

export const UpgradeActionButton: React.FC<UpgradeActionButtonProps> = ({
  service,
  color,
  updateStates,
  loading,
  onCheckUpdate,
  onExecuteUpgrade,
}) => {
  const info = updateStates[service];
  const isChecking = loading === `${service}-check`;
  const isUpgrading = loading === `${service}-upgrade`;

  // 1. 若检测到新版本: 渲染高亮醒目的立即升级按钮
  if (info?.hasUpdate) {
    const gradients = {
      emerald: 'from-emerald-500 to-teal-600 hover:from-emerald-400 hover:to-teal-500 shadow-emerald-500/20',
      blue: 'from-blue-500 to-indigo-600 hover:from-blue-400 hover:to-indigo-500 shadow-blue-500/20',
      purple: 'from-purple-500 to-pink-600 hover:from-purple-400 hover:to-pink-500 shadow-purple-500/20',
      amber: 'from-amber-500 to-orange-600 hover:from-amber-400 hover:to-orange-500 shadow-amber-500/20',
    };

    return (
      <button
        onClick={() => onExecuteUpgrade(service)}
        disabled={isUpgrading}
        className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-gradient-to-r ${gradients[color]} text-white shadow-lg text-xs font-bold transition-all`}
        title={`检测到远端新版本 (v${info.latestVersion})，点击立即下载并平滑重启`}
      >
        <ArrowUpCircle className={`w-3.5 h-3.5 ${isUpgrading ? 'animate-spin' : ''}`} />
        <span>{isUpgrading ? '正在平滑升级...' : `立即升级至 v${info.latestVersion}`}</span>
      </button>
    );
  }

  // 2. 若已检查且已是最新版本: 渲染已是最新状态
  if (info?.checked && !info.hasUpdate) {
    return (
      <button
        onClick={() => onCheckUpdate(service)}
        disabled={isChecking}
        className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-emerald-500/10 hover:bg-emerald-500/20 border border-emerald-500/30 text-xs font-semibold text-emerald-400 transition-colors"
        title="当前核心已是最新稳定版本 (点击可重新探查)"
      >
        <CheckCircle2 className={`w-3.5 h-3.5 ${isChecking ? 'animate-spin' : 'text-emerald-400'}`} />
        <span>{isChecking ? '探查中...' : '已是最新'}</span>
      </button>
    );
  }

  // 3. 默认初始状态: 检查更新
  const themeBorders = {
    emerald: 'bg-emerald-500/10 hover:bg-emerald-500/20 border-emerald-500/30 text-emerald-300',
    blue: 'bg-blue-500/10 hover:bg-blue-500/20 border-blue-500/30 text-blue-300',
    purple: 'bg-purple-500/10 hover:bg-purple-500/20 border-purple-500/30 text-purple-300',
    amber: 'bg-amber-500/10 hover:bg-amber-500/20 border-amber-500/30 text-amber-300',
  };

  return (
    <button
      onClick={() => onCheckUpdate(service)}
      disabled={isChecking}
      className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg border text-xs font-semibold transition-colors ${themeBorders[color]}`}
      title="在线检查远端版本更新"
    >
      <RefreshCw className={`w-3.5 h-3.5 ${isChecking ? 'animate-spin' : ''}`} />
      <span>{isChecking ? '检查中...' : '检查更新'}</span>
    </button>
  );
};

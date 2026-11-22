import React, { useState } from 'react';
import { ServerStatusResponse, TabKey } from '../types';
import { api } from '../api';
import { useToast } from '../../ui';
import { UpdateStateMap, UpgradeActionButton } from './services/UpgradeActionButton';
import { CoreServiceGrid } from './services/CoreServiceGrid';
import { KernelAndSniGrid } from './services/KernelAndSniGrid';
import { ClientSyncNoticeModal, ConfigEditorModal } from './services/ServiceModals';

export interface ServicesTabProps {
  status: ServerStatusResponse | null;
  onRefresh: () => void;
  onOpenLogs: (service: string) => void;
  onNavigate?: (tab: TabKey) => void;
}

export const ServicesTab: React.FC<ServicesTabProps> = ({ status, onRefresh, onOpenLogs, onNavigate }) => {
  const { success, error } = useToast();
  const [loading, setLoading] = useState<string | null>(null);
  const [viewingConfig, setViewingConfig] = useState<{ service: string; path: string; content: string } | null>(null);
  const [editedConfig, setEditedConfig] = useState<string>('');
  const [savingConfig, setSavingConfig] = useState(false);

  const [enablingBBR, setEnablingBBR] = useState(false);
  const [editingSNI, setEditingSNI] = useState(false);
  const [sniInput, setSniInput] = useState('');
  const [updatingSNI, setUpdatingSNI] = useState(false);
  const [showSyncNotice, setShowSyncNotice] = useState(false);

  // 状态字典: service -> { checked, hasUpdate, latestVersion, message }
  const [updateStates, setUpdateStates] = useState<UpdateStateMap>({});

  const handleCheckUpdate = async (service: string) => {
    const key = `${service}-check`;
    setLoading(key);
    try {
      const res = await api.checkServiceUpdate(service);
      setUpdateStates((prev) => ({
        ...prev,
        [service]: {
          checked: true,
          hasUpdate: res.hasUpdate,
          latestVersion: res.latestVersion,
          message: res.message,
        },
      }));
      if (res.hasUpdate) {
        success(`发现新版本 (v${res.latestVersion})，可点击升级按钮`);
      } else {
        success(res.message || `${service} 已是最新稳定版本，无需更新`);
      }
    } catch (err: any) {
      error(err.message || `${service} 检查更新失败`);
    } finally {
      setLoading(null);
    }
  };

  const handleExecuteUpgrade = async (service: string) => {
    const key = `${service}-upgrade`;
    setLoading(key);
    try {
      const res = await api.upgradeService(service);
      success(res.message || `${service} 平滑升级成功`);
      setUpdateStates((prev) => {
        const next = { ...prev };
        delete next[service];
        return next;
      });
      setTimeout(onRefresh, res.willRestartUI ? 2800 : 1500);
    } catch (err: any) {
      error(err.message || `${service} 升级失败`);
    } finally {
      setLoading(null);
    }
  };

  const handleEnableBBR = async () => {
    setEnablingBBR(true);
    try {
      const res = await api.enableBBR();
      success(res.message);
      setTimeout(onRefresh, 1000);
    } catch (err: any) {
      error(err.message || '启用 BBR 失败');
    } finally {
      setEnablingBBR(false);
    }
  };

  const handleRegenerateMaskSite = async () => {
    setLoading('caddy-mask');
    try {
      const res = await api.regenerateMaskSite();
      success(res.message);
    } catch (err: any) {
      error(err.message || '重新生成伪装站失败');
    } finally {
      setLoading(null);
    }
  };

  const handleSaveSNI = async () => {
    if (!sniInput.trim()) return;
    setUpdatingSNI(true);
    try {
      const res = await api.updateSNI(sniInput.trim());
      success(res.message);
      setEditingSNI(false);
      setShowSyncNotice(true);
      setTimeout(onRefresh, 1500);
    } catch (err: any) {
      error(err.message || '更新 SNI 失败');
    } finally {
      setUpdatingSNI(false);
    }
  };

  const handleAction = async (service: string, action: 'start' | 'stop' | 'restart' | 'reload') => {
    const key = `${service}-${action}`;
    setLoading(key);
    try {
      const res = await api.serviceAction(service, action);
      success(res.message);
      setTimeout(onRefresh, 1000);
    } catch (err: any) {
      error(err.message || '操作执行失败');
    } finally {
      setLoading(null);
    }
  };

  const handleViewConfig = async (service: string) => {
    try {
      const res = await api.getServiceConfig(service);
      setViewingConfig(res);
      setEditedConfig(res.content);
    } catch (err: any) {
      error(err.message || '无法获取配置文件');
    }
  };

  const handleSaveConfig = async () => {
    if (!viewingConfig) return;
    setSavingConfig(true);
    try {
      const res = await api.updateServiceConfig(viewingConfig.service, editedConfig);
      success(res.message);
      setViewingConfig(null);
      setShowSyncNotice(true);
      setTimeout(onRefresh, 1200);
    } catch (err: any) {
      error(err.message || '保存配置失败');
    } finally {
      setSavingConfig(false);
    }
  };

  return (
    <div className="space-y-6">
      <div className="p-5 rounded-2xl glass-card flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <h2 className="text-lg font-semibold text-white tracking-tight flex items-center gap-2 flex-wrap">
            <span>四核服务运维控制台</span>
            {status?.version && (
              <span className="px-2 py-0.5 rounded-md bg-purple-500/15 text-purple-300 border border-purple-500/30 text-xs font-mono">
                SingCtl {status.version.startsWith('v') ? status.version : `v${status.version}`}
              </span>
            )}
          </h2>
          <p className="text-xs text-slate-400 mt-1">
            支持对 SingCtl 主程序与四大核心服务进行版本巡检、平滑热升级、实时日志调取以及配置预检编辑
          </p>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          <UpgradeActionButton
            service="singctl"
            color="purple"
            updateStates={updateStates}
            loading={loading}
            onCheckUpdate={handleCheckUpdate}
            onExecuteUpgrade={handleExecuteUpgrade}
          />
        </div>
      </div>

      <CoreServiceGrid
        status={status}
        loading={loading}
        updateStates={updateStates}
        onCheckUpdate={handleCheckUpdate}
        onExecuteUpgrade={handleExecuteUpgrade}
        onServiceAction={handleAction}
        onOpenLogs={onOpenLogs}
        onViewConfig={handleViewConfig}
        onRegenerateMaskSite={handleRegenerateMaskSite}
        onNavigate={onNavigate}
      />

      <KernelAndSniGrid
        status={status}
        enablingBBR={enablingBBR}
        onEnableBBR={handleEnableBBR}
        editingSNI={editingSNI}
        setEditingSNI={setEditingSNI}
        sniInput={sniInput}
        setSniInput={setSniInput}
        updatingSNI={updatingSNI}
        onSaveSNI={handleSaveSNI}
      />

      {viewingConfig && (
        <ConfigEditorModal
          viewingConfig={viewingConfig}
          editedConfig={editedConfig}
          setEditedConfig={setEditedConfig}
          savingConfig={savingConfig}
          onClose={() => setViewingConfig(null)}
          onSave={handleSaveConfig}
        />
      )}

      {showSyncNotice && <ClientSyncNoticeModal onClose={() => setShowSyncNotice(false)} />}
    </div>
  );
};

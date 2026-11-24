import React, { useEffect, useRef, useState } from 'react';
import {
  AlertTriangle,
  Check,
  Copy,
  Dices,
  Eye,
  EyeOff,
  KeyRound,
  Wifi,
  X,
} from 'lucide-react';
import { Badge, Button, useToast } from '../../../../ui';
import { copyPlainText } from '../../../lib/leakProbes';
import { VlanRadioInfo, VlanWirelessSpec } from '../../../types';
import { generateReadableWifiPassword, maskVlanText } from './vlanHelpers';

export interface AppliedWifiCredential {
  segmentName: string;
  ssid: string;
  password: string;
  createdAt: number;
}

export interface VlanWirelessCardProps {
  hasRadios: boolean;
  isEdit: boolean;
  proMode: boolean;
  radios: VlanRadioInfo[];
  wifi: VlanWirelessSpec;
  onChange: (next: VlanWirelessSpec) => void;
}

export const VlanWirelessCard: React.FC<VlanWirelessCardProps> = ({
  hasRadios,
  isEdit,
  proMode,
  radios,
  wifi,
  onChange,
}) => {
  const { success } = useToast();
  const [showPass, setShowPass] = useState(false);
  const [copiedMode, setCopiedMode] = useState<'none' | 'random' | 'copy'>('none');
  const copyTimerRef = useRef<number | null>(null);

  useEffect(() => {
    return () => {
      if (copyTimerRef.current !== null) {
        window.clearTimeout(copyTimerRef.current);
      }
    };
  }, []);

  const flashCopied = (mode: 'random' | 'copy') => {
    setCopiedMode(mode);
    if (copyTimerRef.current !== null) {
      window.clearTimeout(copyTimerRef.current);
    }
    copyTimerRef.current = window.setTimeout(() => {
      setCopiedMode('none');
      copyTimerRef.current = null;
    }, 2000);
  };

  const handleGeneratePassword = () => {
    const pwd = generateReadableWifiPassword();
    onChange({ ...wifi, password: pwd });
    setShowPass(true);
    // 在同一用户点击手势栈内同步发起复制，确保 iOS Safari 剪贴板权限 100% 生效
    void copyPlainText(pwd)
      .then(() => {
        flashCopied('random');
        success('已生成高强度随机 Wi-Fi 密码并复制到剪贴板');
      })
      .catch(() => {
        success('已生成高强度随机 Wi-Fi 密码');
      });
  };

  const handleCopyPassword = () => {
    const pwd = wifi.password || '';
    if (!pwd) return;
    void copyPlainText(pwd)
      .then(() => {
        flashCopied('copy');
        success('已复制 Wi-Fi 密码');
      })
      .catch(() => {
        // 浏览器禁用剪贴板时静默降级不阻断配置流程
      });
  };

  const highlightRandom = !isEdit && !wifi.password;
  const showReconnectWarn = isEdit && Boolean(wifi.passwordConfigured) && Boolean(wifi.password);

  return (
    <div className="rounded-xl border border-slate-800/80 bg-slate-950/50 p-3.5 space-y-3">
      <div className="flex items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <Wifi className="w-4 h-4 text-sky-400" />
          <div>
            <div className="text-xs font-medium text-white">开启专属 Wi-Fi</div>
            <div className="text-[11px] text-slate-400">
              {hasRadios ? '为该隔离网独立广播一个无线名称' : '当前设备未检测到无线网卡，仅支持有线网口分配'}
            </div>
          </div>
        </div>
        <input
          type="checkbox"
          disabled={!hasRadios}
          checked={Boolean(wifi.enabled) && hasRadios}
          onChange={(e) =>
            onChange({ ...wifi, enabled: e.target.checked, radio: wifi.radio || radios[0]?.name })
          }
          className="h-4 w-4 rounded border-slate-600 accent-emerald-500 cursor-pointer disabled:opacity-40"
        />
      </div>

      {hasRadios && wifi.enabled && (
        <div className="pt-2 border-t border-slate-800/70 space-y-3">
          <div className="grid sm:grid-cols-2 gap-3">
            <label className="space-y-1">
              <span className="text-[11px] text-slate-400">Wi-Fi 名称 (SSID)</span>
              <input
                type="text"
                value={wifi.ssid || ''}
                onChange={(e) => onChange({ ...wifi, ssid: e.target.value })}
                placeholder="例如：Home-IoT"
                className="w-full rounded-xl border border-slate-700/90 bg-slate-900/90 px-3 py-2 text-xs text-white focus:border-emerald-500/70 focus:outline-none"
              />
            </label>

            <div className="space-y-1">
              <span className="block text-[11px] text-slate-400">
                连接密码{wifi.passwordConfigured ? '（留空保持原密码不变）' : '（至少 8 位）'}
              </span>
              <div className="flex items-center gap-1.5">
                <div className="relative flex-1 min-w-0">
                  <input
                    type={showPass ? 'text' : 'password'}
                    value={wifi.password || ''}
                    onChange={(e) => onChange({ ...wifi, password: e.target.value })}
                    placeholder={wifi.passwordConfigured ? '已设置密码，留空不修改' : '输入或点右侧随机生成'}
                    className="w-full rounded-xl border border-slate-700/90 bg-slate-900/90 pl-3 pr-8 py-2 text-xs font-mono text-white focus:border-emerald-500/70 focus:outline-none"
                  />
                  <button
                    type="button"
                    onClick={() => setShowPass((v) => !v)}
                    className="absolute right-2.5 top-1/2 -translate-y-1/2 text-slate-400 hover:text-white cursor-pointer"
                    aria-label="显示或隐藏密码"
                    title={showPass ? '隐藏密码' : '显示明文'}
                  >
                    {showPass ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
                  </button>
                </div>

                <button
                  type="button"
                  onClick={handleGeneratePassword}
                  title="一键生成无混淆易读随机密码并复制（xxxx-xxxx-xxxx）"
                  className={`inline-flex items-center gap-1 px-2.5 py-2 rounded-xl border text-xs font-medium shrink-0 transition-colors cursor-pointer ${
                    copiedMode === 'random'
                      ? 'border-emerald-500/70 bg-emerald-500/20 text-emerald-200'
                      : highlightRandom
                        ? 'border-emerald-500/60 bg-emerald-500/15 text-emerald-300 hover:bg-emerald-500/25'
                        : 'border-slate-700/90 bg-slate-900/90 text-slate-200 hover:border-emerald-500/50 hover:text-emerald-300'
                  }`}
                >
                  {copiedMode === 'random' ? (
                    <>
                      <Check className="w-3.5 h-3.5 text-emerald-300" />
                      <span>已复制</span>
                    </>
                  ) : (
                    <>
                      <Dices className="w-3.5 h-3.5 text-emerald-400" />
                      <span>随机</span>
                    </>
                  )}
                </button>

                <button
                  type="button"
                  disabled={!wifi.password}
                  onClick={handleCopyPassword}
                  title="复制当前密码"
                  aria-label="复制当前密码"
                  className="inline-flex items-center justify-center p-2 rounded-xl border border-slate-700/90 bg-slate-900/90 text-slate-300 hover:border-slate-600 hover:text-white disabled:opacity-35 disabled:cursor-not-allowed transition-colors cursor-pointer shrink-0"
                >
                  {copiedMode === 'copy' ? (
                    <Check className="w-3.5 h-3.5 text-emerald-400" />
                  ) : (
                    <Copy className="w-3.5 h-3.5" />
                  )}
                </button>
              </div>
              {highlightRandom && (
                <p className="text-[11px] text-emerald-300/85">
                  点「随机」一键生成高强度易读密码（不含 0/O/1/l 易混淆字符，自动复制）
                </p>
              )}
              {showReconnectWarn && (
                <div className="flex items-start gap-1.5 rounded-lg border border-amber-500/35 bg-amber-500/10 px-2.5 py-1.5 text-[11px] text-amber-200">
                  <AlertTriangle className="w-3.5 h-3.5 text-amber-400 shrink-0 mt-0.5" />
                  <span>修改密码后，原先连在该 Wi-Fi 下的设备需使用新密码重新连接</span>
                </div>
              )}
            </div>
          </div>

          <div className="grid sm:grid-cols-2 gap-3">
            <label className="space-y-1">
              <span className="text-[11px] text-slate-400">无线频段</span>
              <select
                value={wifi.radio || radios[0]?.name || ''}
                onChange={(e) => onChange({ ...wifi, radio: e.target.value })}
                className="w-full rounded-xl border border-slate-700/90 bg-slate-900/90 px-3 py-2 text-xs text-white focus:border-emerald-500/70 focus:outline-none"
              >
                {radios.map((r) => (
                  <option key={r.name} value={r.name}>
                    {r.bandLabel}
                    {r.band === '2g' ? '（推荐老设备/智能家居）' : '（高速低延迟）'}
                    {proMode ? ` · ${r.name}` : ''}
                  </option>
                ))}
              </select>
            </label>

            <label className="space-y-1">
              <span className="text-[11px] text-slate-400">加密兼容模式</span>
              <select
                value={wifi.encryption || 'psk2'}
                onChange={(e) => onChange({ ...wifi, encryption: e.target.value })}
                className="w-full rounded-xl border border-slate-700/90 bg-slate-900/90 px-3 py-2 text-xs text-white focus:border-emerald-500/70 focus:outline-none"
              >
                <option value="psk2">老设备高兼容模式 (WPA2 · 适合智能家居)</option>
                <option value="sae-mixed">高速安全模式 (WPA2/WPA3 混合)</option>
              </select>
            </label>
          </div>

          <label className="flex items-start justify-between gap-3 rounded-xl border border-slate-800/80 bg-slate-950/50 px-3.5 py-2.5 cursor-pointer hover:border-slate-700 transition-colors">
            <div className="min-w-0">
              <div className="text-xs font-medium text-white">同网段无线设备互不可见（防横向传染）</div>
              <div className="text-[11px] text-slate-400 mt-0.5 leading-relaxed">
                开启后，连上同一个 Wi-Fi 的扫地机/访客手机彼此无法互相扫描或通信
              </div>
            </div>
            <input
              type="checkbox"
              checked={Boolean(wifi.isolate)}
              onChange={(e) => onChange({ ...wifi, isolate: e.target.checked })}
              className="mt-1 h-4 w-4 rounded border-slate-600 bg-slate-900 accent-emerald-500 shrink-0 cursor-pointer"
            />
          </label>
        </div>
      )}
    </div>
  );
};

export interface VlanWifiCredentialBannerProps {
  credential: AppliedWifiCredential | null;
  privacyMask: boolean;
  onDismiss: () => void;
}

export const VlanWifiCredentialBanner: React.FC<VlanWifiCredentialBannerProps> = ({
  credential,
  privacyMask,
  onDismiss,
}) => {
  const { success } = useToast();
  const [copiedKey, setCopiedKey] = useState<'none' | 'pass' | 'both'>('none');

  if (!credential) return null;

  const handleCopy = (kind: 'pass' | 'both') => {
    const text =
      kind === 'pass'
        ? credential.password
        : `Wi-Fi 名称 (SSID): ${credential.ssid}\n连接密码: ${credential.password}`;
    void copyPlainText(text)
      .then(() => {
        setCopiedKey(kind);
        success(kind === 'pass' ? '已复制新 Wi-Fi 密码' : '已复制 Wi-Fi 名称与密码');
        window.setTimeout(() => setCopiedKey('none'), 2000);
      })
      .catch(() => {
        // ignore clipboard denial
      });
  };

  return (
    <div className="rounded-2xl border border-emerald-500/40 bg-gradient-to-r from-emerald-950/75 via-slate-900/90 to-sky-950/65 p-4 shadow-lg">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div className="flex items-start gap-3 min-w-0">
          <div className="w-9 h-9 rounded-xl bg-emerald-500/15 border border-emerald-500/30 flex items-center justify-center shrink-0">
            <KeyRound className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="min-w-0 space-y-1">
            <div className="flex flex-wrap items-center gap-2">
              <span className="text-xs sm:text-sm font-semibold text-white">
                新 Wi-Fi 凭据速记卡 · {credential.segmentName}
              </span>
              <Badge tone="ok">仅内存临时展示</Badge>
            </div>
            <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs font-mono">
              <span className="text-slate-300">
                SSID:{' '}
                <strong className="text-sky-300">{maskVlanText(credential.ssid, privacyMask)}</strong>
              </span>
              <span className="text-slate-300">
                密码:{' '}
                <strong className="text-emerald-300">
                  {privacyMask ? '••••••••••••' : credential.password}
                </strong>
              </span>
            </div>
            <p className="text-[11px] text-slate-400">
              该密码绝不落盘到浏览器缓存，刷新页面、10 分钟后或触发安全回滚时将自动销毁，请及时保存给配网设备。
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2 shrink-0 flex-wrap">
          <Button
            size="xs"
            variant="primary"
            icon={copiedKey === 'pass' ? <Check className="w-3 h-3" /> : <Copy className="w-3 h-3" />}
            onClick={() => handleCopy('pass')}
          >
            {copiedKey === 'pass' ? '已复制密码' : '复制密码'}
          </Button>
          <Button
            size="xs"
            variant="secondary"
            icon={copiedKey === 'both' ? <Check className="w-3 h-3" /> : <Copy className="w-3 h-3" />}
            onClick={() => handleCopy('both')}
          >
            {copiedKey === 'both' ? '已复制全部' : '复制 SSID + 密码'}
          </Button>
          <button
            type="button"
            onClick={onDismiss}
            aria-label="关闭速记卡"
            title="关闭速记卡"
            className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-white/10 transition-colors cursor-pointer"
          >
            <X className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>
    </div>
  );
};

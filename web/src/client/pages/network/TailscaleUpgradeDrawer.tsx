import React, { useCallback, useEffect, useState } from 'react';
import {
  AlertTriangle,
  CheckCircle2,
  Cpu,
  Download,
  HardDrive,
  RefreshCw,
  ShieldCheck,
  Terminal,
} from 'lucide-react';
import { Badge, Button, SlideDrawer, formatBytes } from '../../../ui';
import { clientApi } from '../../api';
import { redactInlineSensitive } from '../../lib/privacyMask';
import { TailscaleUpgradePreflight } from '../../types';

export interface TailscaleUpgradeDrawerProps {
  open: boolean;
  busy: boolean;
  privacyMask: boolean;
  onClose: () => void;
  onStartUpgrade: (force: boolean) => void;
}

export const TailscaleUpgradeDrawer: React.FC<TailscaleUpgradeDrawerProps> = ({
  open,
  busy,
  privacyMask,
  onClose,
  onStartUpgrade,
}) => {
  const [preflight, setPreflight] = useState<TailscaleUpgradePreflight | null>(null);
  const [preflightLoading, setPreflightLoading] = useState(false);
  const [preflightError, setPreflightError] = useState('');
  const [forceReinstall, setForceReinstall] = useState(false);
  const [showSwapLogTail, setShowSwapLogTail] = useState(false);

  const loadUpgradePreflight = useCallback(async () => {
    setPreflightLoading(true);
    setPreflightError('');
    try {
      const rep = await clientApi.getTailscaleUpgradePreflight();
      setPreflight(rep);
    } catch (err) {
      setPreflightError((err as Error)?.message || '读取升级体检信息失败');
    } finally {
      setPreflightLoading(false);
    }
  }, []);

  useEffect(() => {
    if (open) {
      setForceReinstall(false);
      setShowSwapLogTail(false);
      void loadUpgradePreflight();
    }
  }, [open, loadUpgradePreflight]);

  useEffect(() => {
    const onDone = () => {
      if (open) {
        void loadUpgradePreflight();
      }
    };
    window.addEventListener('singctl:ts-upgrade-done', onDone);
    return () => window.removeEventListener('singctl:ts-upgrade-done', onDone);
  }, [open, loadUpgradePreflight]);

  return (
    <SlideDrawer
      open={open}
      onClose={onClose}
      title="Tailscale 零失联安全升级 · 升级前体检"
      subtitle="Phase 1 零 /tmp 流式落盘与 SHA256/ELF 兼容预检；Phase 2 脱离父进程原子切换 + 25s 健康门禁自动回滚"
      size="lg"
      headerExtra={
        <Button
          size="xs"
          variant="ghost"
          onClick={() => void loadUpgradePreflight()}
          disabled={preflightLoading}
          icon={<RefreshCw className={`w-3.5 h-3.5 ${preflightLoading ? 'animate-spin' : ''}`} />}
        >
          重新体检
        </Button>
      }
      footer={
        <div className="flex flex-wrap items-center justify-between gap-3">
          <span className="text-[11px] text-slate-400">
            {preflight?.supported
              ? preflight.viaTailscale
                ? '经 Tailscale 访问已启用 2s 优雅缓冲与自动重连'
                : '失败时将在 25s 内自动还原旧版本并重启隧道'
              : '当前平台不支持在线升级'}
          </span>
          <div className="flex items-center gap-2">
            <Button variant="secondary" onClick={onClose}>
              取消
            </Button>
            <Button
              variant="primary"
              disabled={
                busy ||
                preflightLoading ||
                !preflight?.supported ||
                (preflight.upToDate && !forceReinstall ? true : !preflight.canForceProceed)
              }
              icon={<Download className="w-3.5 h-3.5" />}
              onClick={() => {
                onClose();
                onStartUpgrade(forceReinstall);
              }}
            >
              {preflight?.upToDate && forceReinstall ? '强制重刷当前版本' : '开始零失联升级'}
            </Button>
          </div>
        </div>
      }
    >
      {preflightLoading && !preflight ? (
        <div className="py-10 text-center text-xs text-slate-400 flex items-center justify-center gap-2">
          <RefreshCw className="w-4 h-4 animate-spin text-sky-400" />
          正在直连 GitHub API 获取版本摘要并检测 Flash / 内存环境…
        </div>
      ) : preflightError ? (
        <div className="p-3.5 rounded-xl border border-rose-500/35 bg-rose-500/10 text-xs text-rose-200 space-y-2">
          <div className="font-semibold flex items-center gap-1.5">
            <AlertTriangle className="w-4 h-4 shrink-0" />
            升级前体检失败
          </div>
          <p className="leading-relaxed">{preflightError}</p>
        </div>
      ) : preflight ? (
        <div className="space-y-4 text-xs">
          {!preflight.supported ? (
            <div className="p-3.5 rounded-xl border border-amber-500/35 bg-amber-500/10 text-amber-200 space-y-1">
              <div className="font-semibold">当前系统不受支持</div>
              <p>{preflight.unsupportedReason || '仅支持 Linux / OpenWrt 设备。'}</p>
            </div>
          ) : (
            <>
              {preflight.viaTailscale && (
                <div className="p-3 rounded-xl border border-sky-500/30 bg-sky-500/10 text-sky-200 flex items-start gap-2.5 leading-relaxed">
                  <ShieldCheck className="w-4 h-4 shrink-0 mt-0.5 text-sky-300" />
                  <div>
                    <div className="font-semibold text-white">已检测到通过 Tailscale 隧道远程访问控制台</div>
                    <div className="text-[11px] text-sky-200/90 mt-0.5">
                      切换过程将在独立会话（setsid）中运行，并在停止旧隧道前预留 2 秒缓冲；期间 WebUI 将自动进入无感重连等待（不弹过期登录框）。
                    </div>
                  </div>
                </div>
              )}

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <div className="p-3.5 rounded-xl border border-subtle bg-surface2/70 space-y-2">
                  <div className="flex items-center justify-between gap-2">
                    <span className="font-semibold text-primary">版本与产物元数据</span>
                    <Badge tone={preflight.hasOfficialDigest ? 'ok' : 'warn'}>
                      {preflight.hasOfficialDigest ? 'SHA256 官方强校验' : '大小校验'}
                    </Badge>
                  </div>
                  <div className="space-y-1.5 text-[11px]">
                    <div className="flex justify-between gap-2">
                      <span className="text-secondary">版本变化</span>
                      <span className="font-mono text-primary">
                        {preflight.currentVersion || '未安装'} → {preflight.latestVersion || '-'}
                      </span>
                    </div>
                    <div className="flex justify-between gap-2">
                      <span className="text-secondary">目标架构 / 形态</span>
                      <span className="font-mono text-primary">
                        {preflight.arch || '-'}{' '}
                        {preflight.combinedMinimal ? '· 精简合体版' : '· 标准双二进制'}
                      </span>
                    </div>
                    <div className="flex justify-between gap-2">
                      <span className="text-secondary">服务管理器</span>
                      <span className="font-mono text-primary">
                        {preflight.initSystem === 'procd'
                          ? 'OpenWrt procd'
                          : preflight.initSystem === 'systemd'
                            ? 'Linux systemd'
                            : preflight.initSystem || '未识别'}
                      </span>
                    </div>
                  </div>
                </div>

                <div className="p-3.5 rounded-xl border border-subtle bg-surface2/70 space-y-2">
                  <div className="flex items-center justify-between gap-2">
                    <span className="font-semibold text-primary flex items-center gap-1.5">
                      <HardDrive className="w-3.5 h-3.5 text-sky-400" />
                      存储与内存体检
                    </span>
                    <Badge tone={preflight.blockedReasons?.length ? 'danger' : 'ok'}>
                      {preflight.blockedReasons?.length ? '门禁拦截' : '空间充裕'}
                    </Badge>
                  </div>
                  <div className="space-y-1.5 text-[11px]">
                    <div className="flex justify-between gap-2">
                      <span className="text-secondary">Flash 剩余空间</span>
                      <span className="font-mono text-primary">
                        {formatBytes(preflight.flashFreeBytes)}
                      </span>
                    </div>
                    <div className="flex justify-between gap-2">
                      <span className="text-secondary">安全切换所需（含回滚）</span>
                      <span className="font-mono text-primary">
                        {formatBytes(preflight.requiredFreeBytes)}
                      </span>
                    </div>
                    <div className="flex justify-between gap-2">
                      <span className="text-secondary flex items-center gap-1">
                        <Cpu className="w-3 h-3" />
                        可用内存 / Swap
                      </span>
                      <span className="font-mono text-primary">
                        {formatBytes(preflight.memAvailableBytes)}
                        {preflight.swapFreeBytes > 0 ? ` / ${formatBytes(preflight.swapFreeBytes)}` : ''}
                      </span>
                    </div>
                    <div className="text-[10.5px] text-emerald-300/90 pt-0.5">
                      ✓ 流式直写 Flash · 0 MB /tmp 内存占用
                    </div>
                  </div>
                </div>
              </div>

              {(preflight.blockedReasons?.length ?? 0) > 0 && (
                <div className="p-3.5 rounded-xl border border-rose-500/35 bg-rose-500/10 text-rose-200 space-y-1.5">
                  <div className="font-semibold flex items-center gap-1.5">
                    <AlertTriangle className="w-4 h-4 shrink-0" />
                    以下安全门禁阻止本次升级：
                  </div>
                  <ul className="list-disc pl-5 space-y-1 text-[11px]">
                    {preflight.blockedReasons?.map((r, i) => (
                      <li key={i}>{r}</li>
                    ))}
                  </ul>
                </div>
              )}

              {(preflight.warnings?.length ?? 0) > 0 && (
                <div className="p-3 rounded-xl border border-amber-500/30 bg-amber-500/10 text-amber-200 space-y-1 text-[11px]">
                  {preflight.warnings?.map((w, i) => (
                    <div key={i}>• {w}</div>
                  ))}
                </div>
              )}

              {preflight.upToDate && (
                <div className="p-3.5 rounded-xl border border-emerald-500/30 bg-emerald-500/10 space-y-2.5">
                  <div className="flex items-center gap-2 text-emerald-200 font-semibold">
                    <CheckCircle2 className="w-4 h-4 shrink-0" />
                    当前已是最新版本 ({preflight.currentVersion})
                  </div>
                  <label className="flex items-start gap-2 text-[11px] text-slate-200 cursor-pointer select-none">
                    <input
                      type="checkbox"
                      checked={forceReinstall}
                      disabled={!preflight.canForceProceed}
                      onChange={(e) => setForceReinstall(e.target.checked)}
                      className="accent-[var(--accent)] mt-0.5 w-3.5 h-3.5"
                    />
                    <span>
                      强制重刷当前版本（<code className="font-mono">--force</code>）：可用于验证零失联切换流程、切换为精简合体版或修复受损二进制。
                    </span>
                  </label>
                </div>
              )}

              {preflight.activeSwap && preflight.activeSwap.phase !== 'idle' && (
                <div className="p-3.5 rounded-xl border border-subtle bg-surface2/60 space-y-2">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <span className="font-semibold text-primary flex items-center gap-1.5">
                      <Terminal className="w-3.5 h-3.5 text-slate-400" />
                      最近一次后台切换记录
                    </span>
                    <Badge
                      tone={
                        preflight.activeSwap.phase === 'succeeded'
                          ? 'ok'
                          : preflight.activeSwap.phase === 'rolled_back' || preflight.activeSwap.phase === 'failed'
                            ? 'warn'
                            : 'accent'
                      }
                    >
                      {preflight.activeSwap.phase}
                    </Badge>
                  </div>
                  {preflight.activeSwap.message && (
                    <div className="text-[11px] text-secondary leading-relaxed">
                      {redactInlineSensitive(preflight.activeSwap.message, privacyMask)}
                    </div>
                  )}
                  {preflight.activeSwap.error && (
                    <div className="text-[11px] text-rose-300 font-mono">
                      {redactInlineSensitive(preflight.activeSwap.error, privacyMask)}
                    </div>
                  )}
                  {preflight.activeSwap.logTail && (
                    <div>
                      <button
                        type="button"
                        onClick={() => setShowSwapLogTail((v) => !v)}
                        className="text-[11px] text-sky-400 hover:text-sky-300 underline cursor-pointer"
                      >
                        {showSwapLogTail ? '收起切换日志' : '展开详细切换日志'}
                      </button>
                      {showSwapLogTail && (
                        <pre className="mt-2 p-2.5 rounded-lg bg-[#070a10] border border-white/10 text-[10.5px] font-mono text-slate-300 max-h-48 overflow-auto whitespace-pre-wrap break-all">
                          {redactInlineSensitive(preflight.activeSwap.logTail, privacyMask)}
                        </pre>
                      )}
                    </div>
                  )}
                </div>
              )}
            </>
          )}
        </div>
      ) : null}
    </SlideDrawer>
  );
};

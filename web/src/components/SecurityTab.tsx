import React, { useState, useEffect } from 'react';
import {
  ServerStatusResponse,
  BannedIP,
  AuditLogItem,
  HealStatusReport,
  FleetHealReport,
} from '../types';
import { api } from '../api';
import { useToast } from './Toast';
import {
  Shield,
  KeyRound,
  Dices,
  Lock,
  ShieldAlert,
  ShieldCheck,
  Check,
  X,
  RefreshCw,
  Unlock,
  AlertOctagon,
  ClipboardList,
  Cpu,
  Layers,
  HardDrive,
  Clock,
  Zap,
  Network,
  CheckCircle2,
  AlertTriangle,
} from 'lucide-react';

interface SecurityTabProps {
  status: ServerStatusResponse | null;
  onRefresh: () => void;
}

export const SecurityTab: React.FC<SecurityTabProps> = ({ status, onRefresh }) => {
  const { success, error } = useToast();
  const [currentPassword, setCurrentPassword] = useState('');
  const [newUsername, setNewUsername] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [loadingCreds, setLoadingCreds] = useState(false);
  const [loadingPath, setLoadingPath] = useState(false);

  // 3-Layer Security Self-Healing State
  const [healStatus, setHealStatus] = useState<HealStatusReport | null>(null);
  const [loadingHeal, setLoadingHeal] = useState(true);
  const [runningHealScope, setRunningHealScope] = useState<'local' | 'fleet' | null>(null);
  const [savingPolicy, setSavingPolicy] = useState(false);
  const [syncPolicyToFleet, setSyncPolicyToFleet] = useState(true);
  const [lastFleetHeal, setLastFleetHeal] = useState<FleetHealReport | null>(null);

  // 防爆破封禁 IP 列表状态
  const [bans, setBans] = useState<BannedIP[]>([]);
  const [loadingBans, setLoadingBans] = useState(false);
  const [unbanningIP, setUnbanningIP] = useState<string | null>(null);

  // 最近管理操作审计状态
  const [auditLogs, setAuditLogs] = useState<AuditLogItem[]>(status?.auditLogs || []);
  const [loadingAudit, setLoadingAudit] = useState(false);

  const fetchHealStatus = async (silent = false) => {
    if (!silent) setLoadingHeal(true);
    try {
      const rep = await api.getHealStatus();
      setHealStatus(rep);
    } catch {
      // non-fatal
    } finally {
      if (!silent) setLoadingHeal(false);
    }
  };

  const fetchBans = async () => {
    setLoadingBans(true);
    try {
      const res = await api.getBans();
      setBans(res.bans || []);
    } catch {
      // silent
    } finally {
      setLoadingBans(false);
    }
  };

  const fetchAuditLogs = async () => {
    setLoadingAudit(true);
    try {
      const res = await api.getAuditLogs();
      setAuditLogs(res.logs || []);
    } catch {
      // silent
    } finally {
      setLoadingAudit(false);
    }
  };

  useEffect(() => {
    fetchHealStatus();
    fetchBans();
    fetchAuditLogs();
  }, []);

  useEffect(() => {
    if (status?.auditLogs) {
      setAuditLogs(status.auditLogs);
    }
  }, [status?.auditLogs]);

  const handleRunHeal = async (scope: 'local' | 'fleet') => {
    if (scope === 'fleet') {
      if (
        !window.confirm(
          '确定对全舰队与本机执行「三层自动化安全自愈」吗？\n\n• 核心组件与系统安全补丁将在后台并发无感热修复（失败秒级回滚）\n• 需加载新内核的子节点将按【单台串行滚动重启 + 异常熔断】方式执行，保障全网永不断流。'
        )
      ) {
        return;
      }
    }
    setRunningHealScope(scope);
    try {
      const res = await api.runHeal({
        scope,
        allowReboot: scope === 'fleet',
      });
      success(res.message);
      setHealStatus(res.status);
      if (res.fleetReport) {
        setLastFleetHeal(res.fleetReport);
      }
      onRefresh();
      await fetchAuditLogs();
    } catch (err: any) {
      error(err.message || '执行安全自愈失败');
    } finally {
      setRunningHealScope(null);
    }
  };

  const handleTogglePolicy = async (nextEnabled: boolean, nextAutoReboot: boolean) => {
    setSavingPolicy(true);
    try {
      const res = await api.updateHealPolicy({
        autoHealEnabled: nextEnabled,
        schedule: healStatus?.policy?.schedule || '*-*-* 04:00:00',
        autoReboot: nextAutoReboot,
        applyToFleet: syncPolicyToFleet,
      });
      success(res.message);
      setHealStatus(res.status);
      await fetchAuditLogs();
    } catch (err: any) {
      error(err.message || '保存自动自愈策略失败');
    } finally {
      setSavingPolicy(false);
    }
  };

  const handleUnban = async (ip: string) => {
    setUnbanningIP(ip);
    try {
      const res = await api.unban(ip);
      success(res.message || `已成功解除 IP ${ip} 的封锁`);
      await fetchBans();
    } catch (err: any) {
      error(err.message || '解封失败');
    } finally {
      setUnbanningIP(null);
    }
  };

  // 密码规则校验
  const hasMinLength = newPassword.length >= 8;
  const hasUpper = /[A-Z]/.test(newPassword);
  const hasLower = /[a-z]/.test(newPassword);
  const hasDigit = /[0-9]/.test(newPassword);
  const isPasswordValid = hasMinLength && hasUpper && hasLower && hasDigit;

  const handleUpdateCreds = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!currentPassword) {
      error('请输入当前管理密码以验证身份');
      return;
    }
    if (newUsername.trim().toLowerCase() === 'admin') {
      error('管理账号禁止使用默认 admin，请指定专属个性化用户名');
      return;
    }
    if (!isPasswordValid) {
      error('新密码必须至少8位且同时包含大写字母、小写字母和数字');
      return;
    }
    if (newPassword !== confirmPassword) {
      error('两次输入的新密码不一致');
      return;
    }

    setLoadingCreds(true);
    try {
      const res = await api.updateCredentials({
        currentPassword,
        newUsername: newUsername.trim() || status?.admin?.username || 'singctl',
        newPassword,
      });
      success(res.message);
      setCurrentPassword('');
      setNewPassword('');
      setConfirmPassword('');
      onRefresh();
    } catch (err: any) {
      error(err.message || '更新凭据失败');
    } finally {
      setLoadingCreds(false);
    }
  };

  const handleRegeneratePath = async () => {
    if (!window.confirm('确定要重新生成随机隐蔽访问路径吗？生成后 Caddy 将立即热重载，您需要使用新链接访问。')) {
      return;
    }
    setLoadingPath(true);
    try {
      const res = await api.regeneratePath();
      success('全新随机隐蔽路径已生成');
      setTimeout(() => {
        window.location.href = res.httpsUrl;
      }, 1500);
    } catch (err: any) {
      error(err.message || '重新生成失败');
      setLoadingPath(false);
    }
  };

  const postureBadge = (() => {
    if (!healStatus) return { cls: 'bg-slate-800 text-slate-300 border-slate-700', text: '正在扫描...' };
    if (healStatus.posture === 'healthy') {
      return {
        cls: 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30',
        text: healStatus.postureLabel || '三层防线已全面免疫',
      };
    }
    if (healStatus.posture === 'reboot_required') {
      return {
        cls: 'bg-sky-500/15 text-sky-200 border-sky-500/30',
        text: healStatus.postureLabel || '补丁已装·待滚动重启生效',
      };
    }
    return {
      cls: 'bg-amber-500/15 text-amber-200 border-amber-500/30',
      text: healStatus.postureLabel || '发现待修复安全更新',
    };
  })();

  return (
    <div className="space-y-5 sm:space-y-6">
      {/* ═══════════════════════ 1. 3-Layer Automated Security Self-Healing Center ═══════════════════════ */}
      <div className="p-4 sm:p-6 rounded-2xl glass-card border border-emerald-500/20 space-y-5">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2 text-emerald-400 text-xs font-semibold uppercase tracking-wider mb-1">
              <ShieldCheck className="w-4 h-4" />
              <span>AI 时代主动漏洞防御 · 零常驻内存开销</span>
            </div>
            <div className="flex flex-wrap items-center gap-2.5">
              <h2 className="text-lg sm:text-xl font-bold text-white tracking-tight">三层自动化安全漏洞自愈中心</h2>
              <span className={`px-2.5 py-0.5 rounded-full text-xs font-semibold border ${postureBadge.cls}`}>
                {postureBadge.text}
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-1 max-w-3xl leading-relaxed">
              兼顾安全修复速度与业务高可用：核心二进制采用「SHA-256 校验 + 沙盒配置预检 + 异常秒级回滚」，系统补丁严格保留自定义 SSH 2222 配置并热重载残留动态库，多节点内核采用单台串行滚动重启与故障熔断。
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2 shrink-0">
            <button
              type="button"
              onClick={() => handleRunHeal('local')}
              disabled={!!runningHealScope}
              className="flex items-center gap-1.5 px-3.5 py-2 rounded-xl bg-emerald-500 hover:bg-emerald-600 text-slate-950 font-semibold text-xs transition-all shadow-lg shadow-emerald-500/15 disabled:opacity-50"
            >
              <Zap className={`w-3.5 h-3.5 ${runningHealScope === 'local' ? 'animate-bounce' : ''}`} />
              <span>{runningHealScope === 'local' ? '正在本机自愈...' : '立即自愈本机'}</span>
            </button>
            <button
              type="button"
              onClick={() => handleRunHeal('fleet')}
              disabled={!!runningHealScope}
              className="flex items-center gap-1.5 px-3.5 py-2 rounded-xl bg-sky-500/15 hover:bg-sky-500/25 border border-sky-500/30 text-sky-200 font-semibold text-xs transition-all disabled:opacity-50"
            >
              <Network className={`w-3.5 h-3.5 text-sky-400 ${runningHealScope === 'fleet' ? 'animate-spin' : ''}`} />
              <span>{runningHealScope === 'fleet' ? '正在全网协同自愈...' : '全舰队协同自愈'}</span>
            </button>
            <button
              type="button"
              onClick={() => fetchHealStatus(false)}
              disabled={loadingHeal || !!runningHealScope}
              className="flex items-center gap-1.5 px-3 py-2 rounded-xl bg-slate-900 hover:bg-slate-800 border border-slate-800 text-xs text-slate-300 transition-all disabled:opacity-50"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${loadingHeal ? 'animate-spin' : ''}`} />
              <span>重新扫描</span>
            </button>
          </div>
        </div>

        {/* 3 Defense Layer Cards */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3.5">
          {/* Layer 1: Core Stack */}
          <div className="p-4 rounded-2xl bg-slate-950/70 border border-slate-800/90 space-y-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2 text-xs font-semibold text-white">
                <Layers className="w-4 h-4 text-emerald-400" />
                <span>第一层 · 核心代理栈</span>
              </div>
              <span
                className={`text-[11px] font-mono px-2 py-0.5 rounded-md ${
                  healStatus?.core?.healthy
                    ? 'bg-emerald-500/10 text-emerald-400'
                    : 'bg-amber-500/15 text-amber-300'
                }`}
              >
                {healStatus ? (healStatus.core.healthy ? '全部最新 ✓' : `${healStatus.core.pendingCount} 项待升`) : '--'}
              </span>
            </div>
            <div className="space-y-1.5 text-xs font-mono">
              {(healStatus?.core?.components || []).filter((c) => c.installed).map((c) => (
                <div key={c.name} className="flex items-center justify-between gap-2 text-[11px]">
                  <span className="text-slate-400 truncate">{c.displayName}</span>
                  {c.hasUpdate ? (
                    <span className="text-amber-300 shrink-0">
                      v{c.currentVersion} → v{c.latestVersion}
                    </span>
                  ) : (
                    <span className="text-emerald-400 shrink-0">v{c.currentVersion} ✓</span>
                  )}
                </div>
              ))}
            </div>
            <div className="text-[11px] text-slate-500 pt-1 border-t border-slate-800/70">
              金丝雀校验 + <code className="text-slate-400">.heal.bak</code> 15s 异常秒级回滚
            </div>
          </div>

          {/* Layer 2: OS Security & Shared Libraries */}
          <div className="p-4 rounded-2xl bg-slate-950/70 border border-slate-800/90 space-y-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2 text-xs font-semibold text-white">
                <HardDrive className="w-4 h-4 text-sky-400" />
                <span>第二层 · 系统与应用库</span>
              </div>
              <span
                className={`text-[11px] font-mono px-2 py-0.5 rounded-md ${
                  healStatus?.os?.healthy ? 'bg-emerald-500/10 text-emerald-400' : 'bg-amber-500/15 text-amber-300'
                }`}
              >
                {healStatus ? (healStatus.os.healthy ? '零高危漏洞 ✓' : '待热修补') : '--'}
              </span>
            </div>
            <div className="space-y-1.5 text-[11px] font-mono">
              <div className="flex items-center justify-between gap-2">
                <span className="text-slate-400">发行版环境</span>
                <span className="text-slate-200 truncate max-w-[160px]">{healStatus?.os?.distro || '--'}</span>
              </div>
              <div className="flex items-center justify-between gap-2">
                <span className="text-slate-400">安全仓库补丁</span>
                <span className={healStatus?.os?.securityCount ? 'text-amber-300' : 'text-emerald-400'}>
                  {healStatus ? `${healStatus.os.securityCount} 个待装` : '--'}
                </span>
              </div>
              <div className="flex items-center justify-between gap-2">
                <span className="text-slate-400">内存残留旧 .so</span>
                <span className={healStatus?.os?.staleServices?.length ? 'text-amber-300' : 'text-emerald-400'}>
                  {healStatus
                    ? healStatus.os.staleServices?.length
                      ? healStatus.os.staleServices.join(', ')
                      : '干净无残留 ✓'
                    : '--'}
                </span>
              </div>
            </div>
            <div className="text-[11px] text-slate-500 pt-1 border-t border-slate-800/70">
              强制 <code className="text-slate-400">--force-confold</code> 保护 SSH 2222 配置
            </div>
          </div>

          {/* Layer 3: Kernel & Rolling Reboot */}
          <div className="p-4 rounded-2xl bg-slate-950/70 border border-slate-800/90 space-y-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2 text-xs font-semibold text-white">
                <Cpu className="w-4 h-4 text-purple-400" />
                <span>第三层 · 内核与滚动重启</span>
              </div>
              <span
                className={`text-[11px] font-mono px-2 py-0.5 rounded-md ${
                  healStatus?.kernel?.healthy ? 'bg-emerald-500/10 text-emerald-400' : 'bg-sky-500/15 text-sky-300'
                }`}
              >
                {healStatus ? (healStatus.kernel.rebootRequired ? '待重启加载' : '无需重启 ✓') : '--'}
              </span>
            </div>
            <div className="space-y-1.5 text-[11px] font-mono">
              <div className="flex items-center justify-between gap-2">
                <span className="text-slate-400">当前运行内核</span>
                <span className="text-slate-200 truncate max-w-[165px]">{healStatus?.kernel?.runningKernel || '--'}</span>
              </div>
              <div className="flex items-center justify-between gap-2">
                <span className="text-slate-400">磁盘最新内核</span>
                <span className="text-slate-300 truncate max-w-[165px]">
                  {healStatus?.kernel?.installedKernel || healStatus?.kernel?.runningKernel || '--'}
                </span>
              </div>
              {healStatus?.kernel?.rebootReason && (
                <div className="text-sky-300 text-[10px] leading-snug pt-0.5">{healStatus.kernel.rebootReason}</div>
              )}
            </div>
            <div className="text-[11px] text-slate-500 pt-1 border-t border-slate-800/70">
              舰队每次最多重启 1 台 · 超时自动熔断中止
            </div>
          </div>
        </div>

        {/* Automated Daily 04:00 Timer Policy Bar */}
        <div className="p-4 rounded-2xl bg-slate-950/60 border border-slate-800 flex flex-col lg:flex-row lg:items-center justify-between gap-3.5">
          <div className="space-y-1">
            <div className="flex items-center gap-2 text-xs font-semibold text-white">
              <Clock className="w-4 h-4 text-emerald-400" />
              <span>凌晨维护窗口自动巡检与自愈守护 (systemd timer)</span>
              {healStatus?.timer?.enabled && (
                <span className="px-2 py-0.5 rounded bg-emerald-500/15 text-emerald-300 text-[10px] font-mono">
                  已启用 · {healStatus.timer.schedule}
                </span>
              )}
            </div>
            <p className="text-[11px] text-slate-400">
              默认每日凌晨 <code className="text-slate-300">04:00</code> 低峰期自动唤醒巡检修复，执行完毕即退出，平时常驻内存为 0MB
              {healStatus?.timer?.nextRun ? `（下次触发: ${healStatus.timer.nextRun}）` : ''}
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-3 text-xs">
            <label className="inline-flex items-center gap-1.5 text-slate-300 cursor-pointer select-none">
              <input
                type="checkbox"
                checked={syncPolicyToFleet}
                onChange={(e) => setSyncPolicyToFleet(e.target.checked)}
                className="rounded border-slate-700 bg-slate-900 text-emerald-500"
              />
              <span>同步下发至全部子节点</span>
            </label>

            <label className="inline-flex items-center gap-1.5 text-slate-300 cursor-pointer select-none">
              <input
                type="checkbox"
                disabled={savingPolicy}
                checked={!!healStatus?.policy?.autoReboot}
                onChange={(e) =>
                  handleTogglePolicy(healStatus?.policy?.autoHealEnabled ?? true, e.target.checked)
                }
                className="rounded border-slate-700 bg-slate-900 text-sky-500"
              />
              <span>允许凌晨窗口自动重启新内核</span>
            </label>

            <button
              type="button"
              disabled={savingPolicy}
              onClick={() =>
                handleTogglePolicy(
                  !healStatus?.policy?.autoHealEnabled,
                  !!healStatus?.policy?.autoReboot
                )
              }
              className={`px-3.5 py-1.5 rounded-xl font-semibold transition-all disabled:opacity-50 ${
                healStatus?.policy?.autoHealEnabled
                  ? 'bg-rose-500/15 hover:bg-rose-500/25 border border-rose-500/30 text-rose-200'
                  : 'bg-emerald-500/20 hover:bg-emerald-500/30 border border-emerald-500/35 text-emerald-200'
              }`}
            >
              {savingPolicy
                ? '正在应用...'
                : healStatus?.policy?.autoHealEnabled
                ? '关闭定时自愈'
                : '开启每日 04:00 自动自愈'}
            </button>
          </div>
        </div>

        {/* Fleet Heal Result Summary if Triggered */}
        {lastFleetHeal && lastFleetHeal.results.length > 0 && (
          <div className="p-3.5 rounded-2xl bg-slate-950/80 border border-sky-500/25 space-y-2 text-xs font-mono">
            <div className="flex items-center justify-between text-sky-300 font-semibold">
              <span>最近一次舰队协同自愈结果 ({lastFleetHeal.healthyNodes}/{lastFleetHeal.totalNodes} 健康)</span>
              <button
                type="button"
                onClick={() => setLastFleetHeal(null)}
                className="text-slate-400 hover:text-white"
              >
                <X className="w-3.5 h-3.5" />
              </button>
            </div>
            {lastFleetHeal.circuitBreakerHit && (
              <div className="p-2 rounded-lg bg-rose-500/15 border border-rose-500/30 text-rose-200 flex items-center gap-2">
                <AlertTriangle className="w-4 h-4 shrink-0" />
                <span>{lastFleetHeal.circuitBreakerNote}</span>
              </div>
            )}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
              {lastFleetHeal.results.map((r) => (
                <div
                  key={r.id}
                  className="p-2.5 rounded-xl bg-slate-900/80 border border-slate-800 flex items-start gap-2"
                >
                  {r.success ? (
                    <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0 mt-0.5" />
                  ) : (
                    <AlertTriangle className="w-3.5 h-3.5 text-rose-400 shrink-0 mt-0.5" />
                  )}
                  <div className="min-w-0">
                    <div className="font-semibold text-white">
                      {r.name} (#{r.id})
                    </div>
                    <div className="text-[11px] text-slate-400 break-words">{r.summary}</div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Recent Self-Healing History */}
        {healStatus?.history && healStatus.history.length > 0 && (
          <div className="space-y-2">
            <div className="text-xs font-semibold text-slate-400">最近自愈记录</div>
            <div className="space-y-1.5 max-h-40 overflow-y-auto pr-1">
              {healStatus.history.slice(0, 5).map((h, i) => (
                <div
                  key={`${h.timestamp}-${i}`}
                  className="px-3 py-2 rounded-xl bg-slate-950/50 border border-slate-800/70 flex flex-col sm:flex-row sm:items-center justify-between gap-1 text-xs font-mono"
                >
                  <div className="flex items-center gap-2 min-w-0">
                    <span className={h.success ? 'text-emerald-400' : 'text-amber-400'}>
                      {h.success ? '✓' : '!'}
                    </span>
                    <span className="text-slate-200 font-sans truncate">{h.summary}</span>
                  </div>
                  <div className="text-[11px] text-slate-500 shrink-0">
                    [{h.trigger}] {new Date(h.timestamp).toLocaleString()}
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* ═══════════════════════ 2. Secret Path Management ═══════════════════════ */}
      <div className="p-4 sm:p-6 rounded-2xl glass-card">
        <div className="flex items-center gap-2 text-emerald-400 text-xs font-semibold uppercase tracking-wider mb-2">
          <Shield className="w-3.5 h-3.5" />
          <span>无特征隐形反代</span>
        </div>
        <h2 className="text-lg sm:text-xl font-bold text-white tracking-tight">专属随机隐蔽入口路径</h2>
        <p className="text-xs text-slate-400 mt-1 max-w-2xl">
          绝不包含任何 <code className="text-rose-400 font-mono">admin</code> 等特征词，外部访问根目录及未授权路径一律显示静态伪装站点或 404，对全网爬虫完全隐身
        </p>

        <div className="mt-4 sm:mt-5 p-4 rounded-xl bg-slate-950/70 border border-slate-800 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
          <div className="font-mono text-xs min-w-0 w-full">
            <div className="text-slate-500">当前 HTTPS 专属访问 URL:</div>
            <div className="text-emerald-400 font-semibold mt-1 break-all select-all">
              {status?.admin?.httpsUrl || '加载中...'}
            </div>
            <div className="text-slate-500 text-[11px] mt-1">
              本地映射: 127.0.0.1:{status?.admin?.port || 8092} (公网端口严密关闭)
            </div>
          </div>
          <button
            onClick={handleRegeneratePath}
            disabled={loadingPath}
            className="w-full sm:w-auto flex items-center justify-center gap-2 px-4 py-2.5 rounded-xl bg-slate-900 hover:bg-slate-800 border border-slate-700/60 text-slate-200 text-xs font-semibold shrink-0 transition-all disabled:opacity-50"
          >
            <Dices className={`w-4 h-4 text-emerald-400 ${loadingPath ? 'animate-spin' : ''}`} />
            <span>重新生成随机路径</span>
          </button>
        </div>
      </div>

      {/* ═══════════════════════ 3. Admin Credentials ═══════════════════════ */}
      <div className="p-4 sm:p-6 rounded-2xl glass-card">
        <div className="flex items-center gap-2 text-purple-400 text-xs font-semibold uppercase tracking-wider mb-2">
          <KeyRound className="w-3.5 h-3.5" />
          <span>身份与凭据治理</span>
        </div>
        <h3 className="text-lg sm:text-xl font-bold text-white tracking-tight">修改管理员账号与强密码</h3>
        <p className="text-xs text-slate-400 mt-1">
          禁止使用默认 admin，密码需严格满足至少 8 位并包含大小写字母与数字
        </p>

        <form onSubmit={handleUpdateCreds} className="mt-5 space-y-4 max-w-xl">
          <div>
            <label className="block text-xs font-medium text-slate-300 mb-1.5">
              当前管理密码 <span className="text-rose-400">*</span>
            </label>
            <input
              type="password"
              value={currentPassword}
              onChange={(e) => setCurrentPassword(e.target.value)}
              placeholder="输入当前密码以确认身份"
              required
              className="w-full bg-slate-950/80 border border-slate-800 rounded-xl px-3.5 py-2.5 text-xs text-slate-200 placeholder:text-slate-600 focus:outline-none focus:border-emerald-500 font-mono"
            />
          </div>

          <div>
            <label className="block text-xs font-medium text-slate-300 mb-1.5">
              新管理员用户名 (当前: <span className="text-emerald-400 font-mono">{status?.admin?.username}</span>)
            </label>
            <input
              type="text"
              value={newUsername}
              onChange={(e) => setNewUsername(e.target.value)}
              placeholder="自定义专属账号 (禁止为 admin)"
              className="w-full bg-slate-950/80 border border-slate-800 rounded-xl px-3.5 py-2.5 text-xs text-slate-200 placeholder:text-slate-600 focus:outline-none focus:border-emerald-500 font-mono"
            />
          </div>

          <div>
            <label className="block text-xs font-medium text-slate-300 mb-1.5">
              新管理密码 <span className="text-rose-400">*</span>
            </label>
            <input
              type="password"
              value={newPassword}
              onChange={(e) => setNewPassword(e.target.value)}
              placeholder="至少 8 位，包含大写、小写、数字"
              required
              className="w-full bg-slate-950/80 border border-slate-800 rounded-xl px-3.5 py-2.5 text-xs text-slate-200 placeholder:text-slate-600 focus:outline-none focus:border-emerald-500 font-mono"
            />
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 mt-2.5 text-[11px] font-mono">
              <div className={`flex items-center gap-1 ${hasMinLength ? 'text-emerald-400' : 'text-slate-500'}`}>
                {hasMinLength ? <Check className="w-3 h-3" /> : <X className="w-3 h-3" />}
                <span>长度 ≥ 8 位</span>
              </div>
              <div className={`flex items-center gap-1 ${hasUpper ? 'text-emerald-400' : 'text-slate-500'}`}>
                {hasUpper ? <Check className="w-3 h-3" /> : <X className="w-3 h-3" />}
                <span>包含大写字母</span>
              </div>
              <div className={`flex items-center gap-1 ${hasLower ? 'text-emerald-400' : 'text-slate-500'}`}>
                {hasLower ? <Check className="w-3 h-3" /> : <X className="w-3 h-3" />}
                <span>包含小写字母</span>
              </div>
              <div className={`flex items-center gap-1 ${hasDigit ? 'text-emerald-400' : 'text-slate-500'}`}>
                {hasDigit ? <Check className="w-3 h-3" /> : <X className="w-3 h-3" />}
                <span>包含阿拉伯数字</span>
              </div>
            </div>
          </div>

          <div>
            <label className="block text-xs font-medium text-slate-300 mb-1.5">
              确认新管理密码 <span className="text-rose-400">*</span>
            </label>
            <input
              type="password"
              value={confirmPassword}
              onChange={(e) => setConfirmPassword(e.target.value)}
              placeholder="再次输入新管理密码"
              required
              className="w-full bg-slate-950/80 border border-slate-800 rounded-xl px-3.5 py-2.5 text-xs text-slate-200 placeholder:text-slate-600 focus:outline-none focus:border-emerald-500 font-mono"
            />
          </div>

          <div className="pt-2">
            <button
              type="submit"
              disabled={loadingCreds || !isPasswordValid}
              className="w-full sm:w-auto flex items-center justify-center gap-2 px-5 py-2.5 rounded-xl bg-emerald-500 hover:bg-emerald-600 text-slate-950 font-semibold text-xs transition-all shadow-lg shadow-emerald-500/20 disabled:opacity-50"
            >
              <Lock className="w-4 h-4" />
              <span>{loadingCreds ? '正在保存...' : '立即保存修改凭据'}</span>
            </button>
          </div>
        </form>
      </div>

      {/* ═══════════════════════ 4. IP Rate Limiting & Anti-Brute-Force Card (Mobile Cards + Desktop Table) ═══════════════════════ */}
      <div className="p-4 sm:p-6 rounded-2xl glass-card">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-4 border-b border-slate-800">
          <div>
            <div className="flex items-center gap-2 text-rose-400 text-xs font-semibold uppercase tracking-wider mb-1">
              <AlertOctagon className="w-3.5 h-3.5" />
              <span>智能防御与防暴力破解</span>
            </div>
            <h3 className="text-lg sm:text-xl font-bold text-white tracking-tight flex flex-wrap items-center gap-2">
              <span>登录失败 IP 拦截看板</span>
              {bans.length > 0 ? (
                <span className="px-2.5 py-0.5 rounded-full bg-rose-500/20 text-rose-300 border border-rose-500/30 text-xs font-semibold">
                  拦截中: {bans.length} 个 IP
                </span>
              ) : (
                <span className="px-2.5 py-0.5 rounded-full bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 text-xs font-semibold">
                  全绿无拦截
                </span>
              )}
            </h3>
            <p className="text-xs text-slate-400 mt-0.5">
              规则：10 分钟内累计输错密码 3 次，自动封锁源 IP 15 分钟并返回 HTTP 429。
            </p>
          </div>

          <div className="flex items-center gap-2 self-start sm:self-auto">
            <button
              onClick={fetchBans}
              disabled={loadingBans}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-xl bg-slate-900 hover:bg-slate-800 border border-slate-800 text-xs text-slate-300 transition-all disabled:opacity-50"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${loadingBans ? 'animate-spin' : ''}`} />
              <span>刷新列表</span>
            </button>
            {bans.length > 0 && (
              <button
                onClick={() => handleUnban('all')}
                disabled={unbanningIP === 'all'}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-xl bg-rose-500/20 hover:bg-rose-500/30 border border-rose-500/30 text-xs text-rose-200 font-semibold transition-all disabled:opacity-50"
              >
                <Unlock className="w-3.5 h-3.5" />
                <span>解封全部</span>
              </button>
            )}
          </div>
        </div>

        <div className="mt-4">
          {bans.length === 0 ? (
            <div className="py-8 text-center rounded-xl bg-slate-950/40 border border-slate-800/80">
              <ShieldCheck className="w-9 h-9 text-emerald-400 mx-auto mb-2 opacity-80" />
              <div className="text-sm font-semibold text-slate-200">当前系统安全，未拦截任何异常 IP</div>
              <p className="text-xs text-slate-500 mt-1 max-w-md mx-auto px-3">
                实时守护运行中。发生恶意密码试探时，受限 IP 将在此处展示并支持一键解除。
              </p>
            </div>
          ) : (
            <>
              {/* Mobile Stacked Cards (< 768px) */}
              <div className="md:hidden space-y-2.5">
                {bans.map((b) => (
                  <div
                    key={b.ip}
                    className="p-3.5 rounded-xl bg-slate-950/70 border border-slate-800 space-y-2 text-xs font-mono"
                  >
                    <div className="flex items-center justify-between gap-2">
                      <span className="text-white font-semibold break-all">{b.ip}</span>
                      <span className="px-2 py-0.5 rounded bg-rose-500/20 text-rose-300 text-[10px] shrink-0">
                        已封锁 (429)
                      </span>
                    </div>
                    {(b.flag || b.geo || b.isp) && (
                      <div className="text-[11px] text-slate-400 font-sans">
                        {b.flag} {b.geo} {b.isp ? `· ${b.isp}` : ''}
                      </div>
                    )}
                    <div className="flex items-center justify-between pt-1">
                      <span className="text-amber-300 text-[11px]">剩余约 {b.remainingMinutes} 分钟</span>
                      <button
                        onClick={() => handleUnban(b.ip)}
                        disabled={unbanningIP === b.ip}
                        className="px-3 py-1.5 rounded-lg bg-emerald-500/20 border border-emerald-500/30 text-emerald-300 text-xs font-sans font-medium"
                      >
                        {unbanningIP === b.ip ? '解封中...' : '立即解封'}
                      </button>
                    </div>
                  </div>
                ))}
              </div>

              {/* Desktop Table (>= 768px) */}
              <div className="hidden md:block overflow-x-auto">
                <table className="w-full text-left text-xs font-mono">
                  <thead>
                    <tr className="border-b border-slate-800 text-slate-400">
                      <th className="py-2.5 px-3">受限源 IP</th>
                      <th className="py-2.5 px-3">状态</th>
                      <th className="py-2.5 px-3">剩余封锁时间</th>
                      <th className="py-2.5 px-3 text-right">运维操作</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60">
                    {bans.map((b) => (
                      <tr key={b.ip} className="hover:bg-slate-900/40 transition-colors">
                        <td className="py-3 px-3 text-white font-semibold">
                          <div className="flex items-center gap-2 flex-wrap">
                            <span className="w-2 h-2 rounded-full bg-rose-500 animate-pulse shrink-0"></span>
                            <span>{b.ip}</span>
                            {(b.flag || b.geo || b.isp) && (
                              <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md bg-slate-800/90 border border-slate-700/60 text-[10px] text-slate-300 font-sans font-normal">
                                {b.flag && <span>{b.flag}</span>}
                                {b.geo && <span>{b.geo}</span>}
                                {b.isp && <span className="text-slate-500">· {b.isp}</span>}
                              </span>
                            )}
                          </div>
                        </td>
                        <td className="py-3 px-3">
                          <span className="px-2 py-0.5 rounded-md bg-rose-500/20 text-rose-300 border border-rose-500/30 text-[11px]">
                            已封锁 (429)
                          </span>
                        </td>
                        <td className="py-3 px-3 text-amber-300 font-medium">
                          约 {b.remainingMinutes} 分钟 ({b.remainingSeconds} 秒)
                        </td>
                        <td className="py-3 px-3 text-right">
                          <button
                            onClick={() => handleUnban(b.ip)}
                            disabled={unbanningIP === b.ip}
                            className="px-3 py-1.5 rounded-lg bg-emerald-500/20 hover:bg-emerald-500/30 border border-emerald-500/30 text-emerald-300 text-xs font-sans font-medium transition-all disabled:opacity-50"
                          >
                            {unbanningIP === b.ip ? '正在解封...' : '立即解封'}
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </>
          )}
        </div>
      </div>

      {/* ═══════════════════════ 5. Recent Management Operations Audit Card (Mobile Cards + Desktop Table) ═══════════════════════ */}
      <div className="p-4 sm:p-6 rounded-2xl glass-card">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-4 border-b border-slate-800">
          <div>
            <div className="flex items-center gap-2 text-indigo-400 text-xs font-semibold uppercase tracking-wider mb-1">
              <ClipboardList className="w-3.5 h-3.5" />
              <span>操作审计与合规追溯</span>
            </div>
            <h3 className="text-lg sm:text-xl font-bold text-white tracking-tight flex items-center gap-2">
              <span>最近管理操作</span>
              <span className="px-2.5 py-0.5 rounded-full bg-indigo-500/10 text-indigo-300 border border-indigo-500/20 text-xs font-semibold">
                共 {auditLogs.length} 条记录
              </span>
            </h3>
            <p className="text-xs text-slate-400 mt-0.5">
              记录最近管理操作的时间、动作与来源 IP，绝不记录任何明文密码或会话秘钥。
            </p>
          </div>

          <div className="flex items-center gap-2 self-start sm:self-auto">
            <button
              onClick={fetchAuditLogs}
              disabled={loadingAudit}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-xl bg-slate-900 hover:bg-slate-800 border border-slate-800 text-xs text-slate-300 transition-all disabled:opacity-50"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${loadingAudit ? 'animate-spin' : ''}`} />
              <span>刷新记录</span>
            </button>
          </div>
        </div>

        <div className="mt-4">
          {auditLogs.length === 0 ? (
            <div className="py-8 text-center rounded-xl bg-slate-950/40 border border-slate-800/80">
              <ClipboardList className="w-9 h-9 text-slate-600 mx-auto mb-2 opacity-80" />
              <div className="text-sm font-semibold text-slate-400">暂无管理操作记录</div>
            </div>
          ) : (
            <>
              {/* Mobile Stacked Audit Cards (< 768px) */}
              <div className="md:hidden space-y-2 max-h-80 overflow-y-auto pr-1">
                {auditLogs.map((log, idx) => (
                  <div
                    key={`${log.time}-${idx}`}
                    className="p-3 rounded-xl bg-slate-950/60 border border-slate-800/80 space-y-1 text-xs"
                  >
                    <div className="font-medium text-slate-100 break-words">{log.action}</div>
                    <div className="flex flex-wrap items-center justify-between gap-1 text-[11px] font-mono text-slate-400">
                      <span>{log.time}</span>
                      <span className="text-emerald-400">
                        {log.flag ? `${log.flag} ` : ''}
                        {log.ip}
                      </span>
                    </div>
                  </div>
                ))}
              </div>

              {/* Desktop Audit Table (>= 768px) */}
              <div className="hidden md:block overflow-x-auto max-h-80 overflow-y-auto">
                <table className="w-full text-left text-xs font-mono">
                  <thead className="sticky top-0 bg-slate-900/90 backdrop-blur-md z-10">
                    <tr className="border-b border-slate-800 text-slate-400">
                      <th className="py-2.5 px-3">操作时间</th>
                      <th className="py-2.5 px-3">管理动作</th>
                      <th className="py-2.5 px-3 text-right">来源客户端 IP</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60">
                    {auditLogs.map((log, idx) => (
                      <tr key={`${log.time}-${idx}`} className="hover:bg-slate-900/40 transition-colors">
                        <td className="py-3 px-3 text-slate-400 whitespace-nowrap">{log.time}</td>
                        <td className="py-3 px-3 text-slate-200">
                          <span className="font-sans font-medium text-slate-200">{log.action}</span>
                        </td>
                        <td className="py-3 px-3 text-right whitespace-nowrap">
                          <div className="flex items-center justify-end gap-1.5 flex-wrap">
                            <span className="text-emerald-400 font-semibold">{log.ip}</span>
                            {(log.flag || log.geo || log.isp) && (
                              <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md bg-slate-800/90 border border-slate-700/60 text-[10px] text-slate-300 font-sans font-normal">
                                {log.flag && <span>{log.flag}</span>}
                                {log.geo && <span>{log.geo}</span>}
                                {log.isp && <span className="text-slate-500">· {log.isp}</span>}
                              </span>
                            )}
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </>
          )}
        </div>
      </div>

      {/* Session Security Policy Card */}
      <div className="p-4 sm:p-5 rounded-2xl glass-card flex items-start gap-3.5 border-emerald-500/20 bg-emerald-950/10">
        <div className="p-2.5 rounded-xl bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 shrink-0">
          <ShieldAlert className="w-5 h-5" />
        </div>
        <div>
          <h4 className="font-semibold text-sm text-white">会话安全策略 (纯会话，无长期免密)</h4>
          <p className="text-xs text-slate-300 mt-1 leading-relaxed">
            管理面板采用严苛的 <strong>Session Cookie</strong> 认证。无论在手机 Safari 还是桌面浏览器中，关闭标签页或杀掉后台凭据即失效，并具备 <strong>2 小时空闲超时</strong> 自动登出保护。
          </p>
        </div>
      </div>
    </div>
  );
};

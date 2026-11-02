import React, { useState, useEffect } from 'react';
import { ServerStatusResponse, BannedIP } from '../types';
import { api } from '../api';
import { useToast } from './Toast';
import { Shield, KeyRound, Dices, Lock, UserCheck, ShieldAlert, ShieldCheck, Check, X, RefreshCw, Unlock, AlertOctagon } from 'lucide-react';

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

  // 防爆破封禁 IP 列表状态
  const [bans, setBans] = useState<BannedIP[]>([]);
  const [loadingBans, setLoadingBans] = useState(false);
  const [unbanningIP, setUnbanningIP] = useState<string | null>(null);

  const fetchBans = async () => {
    setLoadingBans(true);
    try {
      const res = await api.getBans();
      setBans(res.bans || []);
    } catch (err: any) {
      // 静默处理，若未登录或网络异常不阻断其他卡片
    } finally {
      setLoadingBans(false);
    }
  };

  useEffect(() => {
    fetchBans();
  }, []);

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

  return (
    <div className="space-y-6">
      {/* Secret Path Management */}
      <div className="p-6 rounded-2xl glass-card">
        <div className="flex items-center gap-2 text-emerald-400 text-xs font-semibold uppercase tracking-wider mb-2">
          <Shield className="w-3.5 h-3.5" />
          <span>无特征隐形反代</span>
        </div>
        <h2 className="text-xl font-bold text-white tracking-tight">专属随机隐蔽入口路径</h2>
        <p className="text-xs text-slate-400 mt-1 max-w-2xl">
          绝不包含任何 <code className="text-rose-400 font-mono">admin</code> 等特征词，外部访问根目录及未授权路径一律显示静态伪装站点或 404，对全网爬虫完全隐身
        </p>

        <div className="mt-5 p-4 rounded-xl bg-slate-950/70 border border-slate-800 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
          <div className="font-mono text-xs">
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
            className="flex items-center gap-2 px-4 py-2 rounded-xl bg-slate-900 hover:bg-slate-800 border border-slate-700/60 text-slate-200 text-xs font-semibold shrink-0 transition-all disabled:opacity-50"
          >
            <Dices className={`w-4 h-4 text-emerald-400 ${loadingPath ? 'animate-spin' : ''}`} />
            <span>重新生成随机路径</span>
          </button>
        </div>
      </div>

      {/* Admin Credentials */}
      <div className="p-6 rounded-2xl glass-card">
        <div className="flex items-center gap-2 text-purple-400 text-xs font-semibold uppercase tracking-wider mb-2">
          <KeyRound className="w-3.5 h-3.5" />
          <span>身份与凭据治理</span>
        </div>
        <h3 className="text-xl font-bold text-white tracking-tight">修改管理员账号与强密码</h3>
        <p className="text-xs text-slate-400 mt-1">
          禁止使用默认 admin，密码需严格满足至少 8 位并包含大小写字母与数字
        </p>

        <form onSubmit={handleUpdateCreds} className="mt-6 space-y-4 max-w-xl">
          {/* Current Password */}
          <div>
            <label className="block text-xs font-medium text-slate-300 mb-1.5">
              当前管理密码 <span className="text-rose-400">*</span>
            </label>
            <div className="relative">
              <input
                type="password"
                value={currentPassword}
                onChange={(e) => setCurrentPassword(e.target.value)}
                placeholder="输入当前密码以确认身份"
                required
                className="w-full bg-slate-950/80 border border-slate-800 rounded-xl px-3.5 py-2.5 text-xs text-slate-200 placeholder:text-slate-600 focus:outline-none focus:border-emerald-500 font-mono"
              />
            </div>
          </div>

          {/* New Username */}
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

          {/* New Password */}
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
            {/* Live Password Rules Checklist */}
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

          {/* Confirm Password */}
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
              className="flex items-center gap-2 px-5 py-2.5 rounded-xl bg-emerald-500 hover:bg-emerald-600 text-slate-950 font-semibold text-xs transition-all shadow-lg shadow-emerald-500/20 disabled:opacity-50"
            >
              <Lock className="w-4 h-4" />
              <span>{loadingCreds ? '正在保存...' : '立即保存修改凭据'}</span>
            </button>
          </div>
        </form>
      </div>

      {/* IP Rate Limiting & Anti-Brute-Force Card */}
      <div className="p-6 rounded-2xl glass-card">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-4 border-b border-slate-800">
          <div>
            <div className="flex items-center gap-2 text-rose-400 text-xs font-semibold uppercase tracking-wider mb-1">
              <AlertOctagon className="w-3.5 h-3.5" />
              <span>智能防御与防暴力破解</span>
            </div>
            <h3 className="text-xl font-bold text-white tracking-tight flex items-center gap-2">
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
              规则：10 分钟内累计输错密码 3 次，系统将自动封锁源 IP 15 分钟并返回 HTTP 429。本机回环受白名单免锁保护。
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
                <span>一键解封全部</span>
              </button>
            )}
          </div>
        </div>

        {/* Bans Content */}
        <div className="mt-4">
          {bans.length === 0 ? (
            <div className="py-8 text-center rounded-xl bg-slate-950/40 border border-slate-800/80">
              <ShieldCheck className="w-9 h-9 text-emerald-400 mx-auto mb-2 opacity-80" />
              <div className="text-sm font-semibold text-slate-200">当前系统安全，未拦截任何异常 IP</div>
              <p className="text-xs text-slate-500 mt-1 max-w-md mx-auto">
                实时守护运行中。当发生针对面板的字典撞库或恶意密码试探时，受限 IP 将在此处展示，支持倒计时观察与一键即时解除。
              </p>
            </div>
          ) : (
            <div className="overflow-x-auto">
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
                      <td className="py-3 px-3 text-white font-semibold flex items-center gap-2">
                        <span className="w-2 h-2 rounded-full bg-rose-500 animate-pulse"></span>
                        <span>{b.ip}</span>
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
          )}
        </div>
      </div>

      {/* Session Security Policy Card */}
      <div className="p-5 rounded-2xl glass-card flex items-start gap-3.5 border-emerald-500/20 bg-emerald-950/10">
        <div className="p-2.5 rounded-xl bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
          <ShieldAlert className="w-5 h-5" />
        </div>
        <div>
          <h4 className="font-semibold text-sm text-white">会话安全策略 (纯会话，无长期免密)</h4>
          <p className="text-xs text-slate-300 mt-1 leading-relaxed">
            管理面板采用行业严苛的 <strong>Session Cookie</strong> 认证。无论是在手机 Safari 还是桌面电脑中，一旦关闭浏览器标签页或杀掉后台，凭据立即失效，再次打开必须重新输入用户名与密码。同时服务端具备 <strong>2 小时空闲超时</strong>，防止终端遗留风险。
          </p>
        </div>
      </div>
    </div>
  );
};

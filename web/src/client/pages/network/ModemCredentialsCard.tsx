import React, { useState } from 'react';
import {
  AlertTriangle,
  CheckCircle2,
  Copy,
  Edit3,
  Eye,
  EyeOff,
  KeyRound,
  Plus,
  Save,
  Trash2,
  User,
  Zap,
} from 'lucide-react';
import { Badge, Button, SectionCard, useToast } from '../../../ui';
import { maskFullIP } from '../../../lib/privacyMask';
import { clientApi } from '../../api';
import { ModemCredentialsSummary } from '../../types';

export interface ModemCredentialsCardProps {
  credentials?: ModemCredentialsSummary;
  busy: boolean;
  privacyMask?: boolean;
  canAutoLogin: boolean;
  adminPort?: number;
  loginBusySlot: 'super' | 'user' | null;
  onCredentialsChange: (next: ModemCredentialsSummary) => void;
  onOneClickLogin: (slot: 'super' | 'user') => void;
}

const DEFAULT_SUPERADMIN_TEMPLATES = [
  { label: '中国电信', username: 'telecomadmin', password: 'nE7jA%5m' },
  { label: '中国移动', username: 'CMCCAdmin', password: 'aDm8H%MdA' },
  { label: '中国联通', username: 'CUAdmin', password: 'CUAdmin' },
  { label: '华为原厂', username: 'telecomadmin', password: 'admintelecom' },
];

async function copyTextSafe(text: string): Promise<void> {
  if (typeof navigator !== 'undefined' && navigator.clipboard?.writeText) {
    try {
      await navigator.clipboard.writeText(text);
      return;
    } catch {
      // Fallback below for non-HTTPS LAN sessions
    }
  }
  const ta = document.createElement('textarea');
  ta.value = text;
  ta.setAttribute('readonly', 'true');
  ta.style.position = 'fixed';
  ta.style.opacity = '0';
  document.body.appendChild(ta);
  ta.select();
  const ok = document.execCommand('copy');
  document.body.removeChild(ta);
  if (!ok) {
    throw new Error('浏览器拒绝剪贴板写入');
  }
}

export const ModemCredentialsCard: React.FC<ModemCredentialsCardProps> = ({
  credentials,
  busy,
  privacyMask = false,
  canAutoLogin,
  adminPort,
  loginBusySlot,
  onCredentialsChange,
  onOneClickLogin,
}) => {
  const { success, error, toast } = useToast();
  const [editingSlot, setEditingSlot] = useState<'super' | 'user' | null>(null);
  const [formUser, setFormUser] = useState('');
  const [formPass, setFormPass] = useState('');
  const [showPass, setShowPass] = useState(false);
  const [saving, setSaving] = useState(false);
  const [clearingSlot, setClearingSlot] = useState<'super' | 'user' | null>(null);
  const [copyingKey, setCopyingKey] = useState<string | null>(null);

  const slots: {
    key: 'super' | 'user';
    title: string;
    subtitle: string;
    defaultUserHint: string;
    icon: React.ReactNode;
  }[] = [
    {
      key: 'super',
      title: '超级管理员（超密）',
      subtitle: adminPort
        ? `改桥接 / DMZ / 关闭光猫 DHCP 必用（将优先直连装维口 :${adminPort}）`
        : '改桥接 / DMZ / 关闭光猫 DHCP 必用，存好防止装维改密后遗忘',
      defaultUserHint: '例如 telecomadmin / CMCCAdmin / CUAdmin',
      icon: <KeyRound className="w-4 h-4 text-amber-400" />,
    },
    {
      key: 'user',
      title: '普通用户（背面贴纸）',
      subtitle: '日常查光衰、设备状态与重启光猫用',
      defaultUserHint: '例如 useradmin / admin / user',
      icon: <User className="w-4 h-4 text-sky-400" />,
    },
  ];

  const openEditor = (slot: 'super' | 'user') => {
    if (privacyMask) {
      toast('隐私完全遮挡开启期间不允许编辑光猫凭据', 'warn');
      return;
    }
    const existing = credentials?.[slot];
    setEditingSlot(slot);
    setFormUser(existing?.username || (slot === 'super' ? 'telecomadmin' : 'useradmin'));
    setFormPass('');
    setShowPass(false);
  };

  const handleSave = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!editingSlot || privacyMask) return;
    setSaving(true);
    try {
      const res = await clientApi.saveModemCredentials({
        slot: editingSlot,
        username: formUser.trim(),
        password: formPass,
      });
      onCredentialsChange(res.credentials);
      setEditingSlot(null);
      setFormPass('');
      success(res.message);
    } catch (err: unknown) {
      error(err instanceof Error ? err.message : '保存光猫凭据失败');
    } finally {
      setSaving(false);
    }
  };

  const handleClear = async (slot: 'super' | 'user') => {
    if (privacyMask) return;
    setClearingSlot(slot);
    try {
      const res = await clientApi.saveModemCredentials({ slot, clear: true });
      onCredentialsChange(res.credentials);
      if (editingSlot === slot) setEditingSlot(null);
      success(res.message);
    } catch (err: unknown) {
      error(err instanceof Error ? err.message : '清空凭据失败');
    } finally {
      setClearingSlot(null);
    }
  };

  const handleCopy = async (slot: 'super' | 'user', field: 'username' | 'password') => {
    if (privacyMask) {
      toast('隐私遮挡开启期间已禁用复制明文凭据', 'warn');
      return;
    }
    const key = `${slot}:${field}`;
    setCopyingKey(key);
    try {
      const cred = await clientApi.useModemCredential({ slot });
      await copyTextSafe(field === 'username' ? cred.username : cred.password);
      success(field === 'username' ? `已复制账号 (${cred.username})` : '已复制登录密码到剪贴板');
    } catch (err: unknown) {
      error(err instanceof Error ? err.message : '读取凭据失败');
    } finally {
      setCopyingKey(null);
    }
  };

  return (
    <SectionCard
      title="光猫凭据保险箱与一键登录"
      icon={<KeyRound className="w-4 h-4" />}
      subtitle="双槽独立以 0600 权限保存于路由器本机，密码不在列表明文回显；支持内嵌控制台一键填入并提交登录"
    >
      <div className="space-y-3">
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">
          {slots.map((s) => {
            const meta = credentials?.[s.key];
            const isEditing = editingSlot === s.key;
            return (
              <div
                key={s.key}
                className="rounded-xl border border-subtle bg-surface2/60 p-3.5 flex flex-col justify-between gap-3"
              >
                <div className="space-y-1.5">
                  <div className="flex items-center justify-between gap-2 flex-wrap">
                    <div className="flex items-center gap-2 text-xs font-semibold text-primary">
                      {s.icon}
                      <span>{s.title}</span>
                    </div>
                    {meta?.saved ? (
                      <Badge tone="ok" dot>
                        0600 已保存 · {privacyMask ? '••••••' : maskFullIP(meta.username || '', false)}
                      </Badge>
                    ) : (
                      <Badge tone="neutral">未录入</Badge>
                    )}
                  </div>
                  <p className="text-[11px] text-secondary leading-relaxed">{s.subtitle}</p>
                </div>

                {isEditing ? (
                  <form onSubmit={(e) => void handleSave(e)} className="space-y-2.5 pt-2 border-t border-subtle/60">
                    {s.key === 'super' && (
                      <div className="space-y-1.5">
                        <div className="text-[11px] text-muted">常见运营商初始默认超密（点击速填参考）：</div>
                        <div className="flex flex-wrap gap-1.5">
                          {DEFAULT_SUPERADMIN_TEMPLATES.map((tpl) => (
                            <button
                              key={tpl.label}
                              type="button"
                              onClick={() => {
                                setFormUser(tpl.username);
                                setFormPass(tpl.password);
                              }}
                              className="px-2 py-1 rounded-lg text-[11px] border border-subtle bg-surface3/60 hover:bg-surface3 text-primary transition-colors cursor-pointer"
                            >
                              {tpl.label} ({tpl.username})
                            </button>
                          ))}
                        </div>
                        <div className="rounded-lg border border-amber-500/30 bg-amber-500/10 px-2.5 py-1.5 text-[11px] text-amber-200 flex items-start gap-1.5">
                          <AlertTriangle className="w-3.5 h-3.5 text-amber-400 shrink-0 mt-0.5" />
                          <span>
                            现网光猫超密多由省端 RMS 动态下发；默认模板请勿连续试错超过 2 次以免锁死，推荐向装维索取后存入此处。
                          </span>
                        </div>
                      </div>
                    )}

                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                      <div>
                        <label className="block text-[11px] text-muted mb-1">登录账号</label>
                        <input
                          type="text"
                          required
                          value={formUser}
                          onChange={(e) => setFormUser(e.target.value)}
                          placeholder={s.defaultUserHint}
                          className="sc-input h-8 px-2.5 text-xs font-mono w-full"
                        />
                      </div>
                      <div>
                        <label className="block text-[11px] text-muted mb-1">
                          登录密码{meta?.saved ? '（留空则保留原密码）' : ''}
                        </label>
                        <div className="relative">
                          <input
                            type={showPass ? 'text' : 'password'}
                            required={!meta?.saved}
                            value={formPass}
                            onChange={(e) => setFormPass(e.target.value)}
                            placeholder={meta?.saved ? '留空保持原密码' : '输入光猫密码'}
                            className="sc-input h-8 px-2.5 pr-8 text-xs font-mono w-full"
                          />
                          <button
                            type="button"
                            onClick={() => setShowPass((v) => !v)}
                            className="absolute right-2 top-1/2 -translate-y-1/2 text-muted hover:text-primary"
                            title={showPass ? '隐藏密码' : '显示密码'}
                          >
                            {showPass ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
                          </button>
                        </div>
                      </div>
                    </div>

                    <div className="flex items-center gap-2 justify-end">
                      <Button size="xs" variant="ghost" onClick={() => setEditingSlot(null)}>
                        取消
                      </Button>
                      <Button
                        size="xs"
                        type="submit"
                        variant="primary"
                        loading={saving}
                        icon={<Save className="w-3 h-3" />}
                      >
                        保存至 0600 保险箱
                      </Button>
                    </div>
                  </form>
                ) : (
                  <div className="flex items-center gap-1.5 flex-wrap pt-1">
                    {meta?.saved ? (
                      <>
                        <Button
                          size="xs"
                          variant={s.key === 'super' ? 'primary' : 'secondary'}
                          loading={loginBusySlot === s.key}
                          disabled={busy || privacyMask || !canAutoLogin}
                          icon={
                            s.key === 'super' ? (
                              <Zap className="w-3 h-3" />
                            ) : (
                              <CheckCircle2 className="w-3 h-3" />
                            )
                          }
                          onClick={() => onOneClickLogin(s.key)}
                        >
                          {s.key === 'super' ? '超管一键登录' : '普通账号登录'}
                        </Button>
                        <Button
                          size="xs"
                          variant="ghost"
                          loading={copyingKey === `${s.key}:username`}
                          disabled={busy || privacyMask}
                          icon={<Copy className="w-3 h-3" />}
                          onClick={() => void handleCopy(s.key, 'username')}
                        >
                          复制账号
                        </Button>
                        <Button
                          size="xs"
                          variant="ghost"
                          loading={copyingKey === `${s.key}:password`}
                          disabled={busy || privacyMask}
                          icon={<Copy className="w-3 h-3" />}
                          onClick={() => void handleCopy(s.key, 'password')}
                        >
                          复制密码
                        </Button>
                        <Button
                          size="xs"
                          variant="ghost"
                          disabled={busy || privacyMask}
                          icon={<Edit3 className="w-3 h-3" />}
                          onClick={() => openEditor(s.key)}
                        >
                          修改
                        </Button>
                        <Button
                          size="xs"
                          variant="ghost"
                          loading={clearingSlot === s.key}
                          disabled={busy || privacyMask}
                          icon={<Trash2 className="w-3 h-3 text-rose-400" />}
                          onClick={() => void handleClear(s.key)}
                        >
                          清空
                        </Button>
                      </>
                    ) : (
                      <Button
                        size="xs"
                        variant="secondary"
                        disabled={busy || privacyMask}
                        icon={<Plus className="w-3 h-3" />}
                        onClick={() => openEditor(s.key)}
                      >
                        录入{s.key === 'super' ? '超密' : '普通账号'}
                      </Button>
                    )}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </div>
    </SectionCard>
  );
};

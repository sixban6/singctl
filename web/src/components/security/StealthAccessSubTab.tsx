import React, { useState } from 'react';
import { Check, Copy, Dices, Shield, ShieldAlert } from 'lucide-react';
import { api } from '../../api';
import { ServerStatusResponse } from '../../types';
import { Badge, Button, ConfirmDialog, SectionCard, useToast } from '../../ui';

interface StealthAccessSubTabProps {
  status: ServerStatusResponse | null;
}

export const StealthAccessSubTab: React.FC<StealthAccessSubTabProps> = ({ status }) => {
  const { success, error } = useToast();
  const [loadingPath, setLoadingPath] = useState(false);
  const [confirmRegen, setConfirmRegen] = useState(false);
  const [copied, setCopied] = useState(false);

  const copyHttpsUrl = async () => {
    const url = status?.admin?.httpsUrl;
    if (!url) return;
    try {
      await navigator.clipboard.writeText(url);
      setCopied(true);
      success('隐蔽控制台访问链接已复制');
      window.setTimeout(() => setCopied(false), 2000);
    } catch {
      error('复制失败，请手动复制');
    }
  };

  const executeRegeneratePath = async () => {
    setConfirmRegen(false);
    setLoadingPath(true);
    try {
      const res = await api.regeneratePath();
      success('全新随机隐蔽路径已生成，即将跳转至新入口…');
      window.setTimeout(() => {
        window.location.href = res.httpsUrl;
      }, 1500);
    } catch (err: unknown) {
      error(err instanceof Error ? err.message : '重新生成失败');
      setLoadingPath(false);
    }
  };

  return (
    <div className="space-y-6">
      <SectionCard
        title="专属随机隐蔽入口路径"
        subtitle="绝不包含任何 admin / login 等特征词，根路径及未授权路径一律回落伪装站点或 404，对全网扫描器完全隐身"
        icon={<Shield className="w-4 h-4" />}
        badge={<Badge tone="ok" dot>无特征隐形反代</Badge>}
      >
        <div className="p-4 rounded-xl bg-surface2 border border-subtle flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div className="font-mono text-xs min-w-0 space-y-1 flex-1">
            <div className="text-muted">当前 HTTPS 专属访问 URL:</div>
            <div className="font-semibold text-accent break-all select-all">
              {status?.admin?.httpsUrl || '加载中…'}
            </div>
            <div className="text-muted text-[11px]">
              本地回环监听: 127.0.0.1:{status?.admin?.port || 8092}（公网管理端口严密隔离关闭）
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-2 shrink-0">
            <Button
              size="sm"
              variant="secondary"
              disabled={!status?.admin?.httpsUrl}
              onClick={copyHttpsUrl}
              icon={copied ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
            >
              {copied ? '已复制' : '复制入口链接'}
            </Button>
            <Button
              size="sm"
              variant="primary"
              loading={loadingPath}
              onClick={() => setConfirmRegen(true)}
              icon={<Dices className="w-3.5 h-3.5" />}
            >
              重新生成随机路径
            </Button>
          </div>
        </div>
      </SectionCard>

      <SectionCard
        title="会话安全策略 (纯会话，无长期免密)"
        icon={<ShieldAlert className="w-4 h-4" />}
      >
        <p className="text-xs sm:text-sm text-secondary leading-relaxed">
          管理面板采用严格的 <strong className="text-primary">HttpOnly / SameSite Session Cookie</strong> 认证，不签发持久免密令牌。无论在手机 Safari 还是桌面浏览器中，关闭会话标签页后凭据即失效，并具备{' '}
          <strong className="text-primary">2 小时空闲超时</strong> 自动登出与异常尝试 3 次锁定 15 分钟保护。
        </p>
      </SectionCard>

      <ConfirmDialog
        open={confirmRegen}
        title="确认重新生成随机隐蔽访问路径？"
        description="生成后 Caddy 将立即热重载新路径，旧路径将即刻返回 404/伪装页面，浏览器会在 1.5 秒后自动重定向至全新随机地址，请及时更新书签。"
        confirmText="确认轮换路径"
        danger
        onConfirm={() => void executeRegeneratePath()}
        onCancel={() => setConfirmRegen(false)}
      />
    </div>
  );
};

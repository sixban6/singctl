import React, { useCallback, useEffect, useState } from 'react';
import {
  Bell,
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  History,
  RefreshCw,
  Save,
  Send,
  XCircle,
} from 'lucide-react';
import { Badge, BadgeTone, Button, SectionCard, useToast } from '../../../ui';
import { clientApi } from '../../api';
import {
  NotifyConfigDTO,
  NotifyDeliveryResult,
  NotifyEventsConfig,
  NotifyHistoryRecord,
  NotifySecretStatus,
} from '../../types';
import { NotifyChannelKey, NotifyChannelPanel } from './NotifyChannelPanel';

export interface NotifyConfigCardProps {
  busy?: boolean;
}

const DEFAULT_SECRET_STATUS: NotifySecretStatus = {
  telegramBotToken: false,
  barkDeviceKey: false,
  feishuWebhookUrl: false,
  feishuSecret: false,
  wecomWebhookUrl: false,
  webhookHeaderValue: false,
};

function createDefaultNotifyConfig(): NotifyConfigDTO {
  return {
    enabled: false,
    cooldownMinutes: 15,
    dailyLimit: 50,
    quietHours: '',
    events: {
      watchdogHeal: true,
      safeCommitRollback: true,
      resourceGuard: true,
      auditHighRisk: true,
      newDevice: true,
      subOrNodeFail: true,
      serverQuotaOrBan: true,
    },
    channels: {
      telegram: { enabled: false, botToken: '', chatId: '', apiBaseUrl: '' },
      bark: { enabled: false, serverUrl: 'https://api.day.app', deviceKey: '', group: 'SingCtl' },
      feishu: { enabled: false, webhookUrl: '', secret: '' },
      wecom: { enabled: false, webhookUrl: '' },
      webhook: { enabled: false, url: '', headerName: '', headerValue: '' },
    },
  };
}

function normalizeNotifyConfig(raw?: Partial<NotifyConfigDTO> | null): NotifyConfigDTO {
  const def = createDefaultNotifyConfig();
  if (!raw) return def;
  return {
    enabled: Boolean(raw.enabled),
    cooldownMinutes: raw.cooldownMinutes ?? def.cooldownMinutes,
    dailyLimit: raw.dailyLimit ?? def.dailyLimit,
    quietHours: raw.quietHours ?? '',
    events: { ...def.events, ...(raw.events || {}) },
    channels: {
      telegram: { ...def.channels.telegram, ...(raw.channels?.telegram || {}) },
      bark: { ...def.channels.bark, ...(raw.channels?.bark || {}) },
      feishu: { ...def.channels.feishu, ...(raw.channels?.feishu || {}) },
      wecom: { ...def.channels.wecom, ...(raw.channels?.wecom || {}) },
      webhook: { ...def.channels.webhook, ...(raw.channels?.webhook || {}) },
    },
  };
}

const CLIENT_EVENT_ITEMS: {
  key: keyof Omit<NotifyEventsConfig, 'serverQuotaOrBan'>;
  title: string;
  desc: string;
}[] = [
  { key: 'watchdogHeal', title: '看门狗自愈与恢复', desc: 'sing-box 异常拉起或恢复健康' },
  { key: 'safeCommitRollback', title: '安全保险丝自动回滚', desc: '远端配置超时触发回滚保护' },
  { key: 'resourceGuard', title: '内存/闪存资源告警', desc: '低内存或 /overlay 空间紧张' },
  { key: 'auditHighRisk', title: '审计高危行为命中', desc: '异常流量识别或自动封禁事件' },
  { key: 'newDevice', title: '新设备首次接入', desc: '局域网发现未知 MAC 终端' },
  { key: 'subOrNodeFail', title: '订阅/节点切换异常', desc: '订阅拉取失败或节点容灾异常' },
];

function severityBadgeTone(severity: string): BadgeTone {
  switch (severity) {
    case 'critical':
      return 'danger';
    case 'warn':
      return 'warn';
    default:
      return 'accent';
  }
}

export const NotifyConfigCard: React.FC<NotifyConfigCardProps> = ({ busy = false }) => {
  const { success, error } = useToast();
  const [config, setConfig] = useState<NotifyConfigDTO>(() => createDefaultNotifyConfig());
  const [secretStatus, setSecretStatus] = useState<NotifySecretStatus>(DEFAULT_SECRET_STATUS);
  const [history, setHistory] = useState<NotifyHistoryRecord[]>([]);
  const [activeChannel, setActiveChannel] = useState<NotifyChannelKey>('telegram');
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [testingTarget, setTestingTarget] = useState<string | null>(null);
  const [lastTestResults, setLastTestResults] = useState<NotifyDeliveryResult[]>([]);
  const [historyOpen, setHistoryOpen] = useState(false);

  const loadConfig = useCallback(async () => {
    setLoading(true);
    try {
      const res = await clientApi.getNotifyConfig();
      setConfig(normalizeNotifyConfig(res.config));
      setSecretStatus({ ...DEFAULT_SECRET_STATUS, ...(res.secretStatus || {}) });
      setHistory(Array.isArray(res.recentHistory) ? res.recentHistory : []);
    } catch (err: unknown) {
      error(`读取主动推送配置失败：${err instanceof Error ? err.message : '未知错误'}`);
    } finally {
      setLoading(false);
    }
  }, [error]);

  useEffect(() => {
    void loadConfig();
  }, [loadConfig]);

  const handleSave = async (e: React.FormEvent) => {
    e.preventDefault();
    setSaving(true);
    try {
      const payload: NotifyConfigDTO = {
        ...config,
        cooldownMinutes: Math.min(1440, Math.max(1, Math.round(Number(config.cooldownMinutes) || 15))),
        dailyLimit: Math.min(1000, Math.max(1, Math.round(Number(config.dailyLimit) || 50))),
        quietHours: config.quietHours.trim(),
      };
      const res = await clientApi.saveNotifyConfig(payload);
      setConfig(normalizeNotifyConfig(res.config));
      setSecretStatus({ ...DEFAULT_SECRET_STATUS, ...(res.secretStatus || {}) });
      success('主动消息推送配置已保存并热生效');
    } catch (err: unknown) {
      error(`保存推送配置失败：${err instanceof Error ? err.message : '未知错误'}`);
    } finally {
      setSaving(false);
    }
  };

  const handleTest = async (channel?: NotifyChannelKey) => {
    const target = channel || 'all';
    setTestingTarget(target);
    setLastTestResults([]);
    try {
      const res = await clientApi.testNotify({
        channel,
        config,
      });
      const results = Array.isArray(res.results) ? res.results : [];
      setLastTestResults(results);
      if (Array.isArray(res.recentHistory)) {
        setHistory(res.recentHistory);
      }
      if (res.ok) {
        const okCount = results.filter((r) => r.ok).length;
        success(
          channel
            ? `渠道 ${channel} 测试消息发送成功`
            : `测试推送完成：${okCount}/${results.length} 个渠道送达成功`,
        );
      } else {
        const firstErr = results.find((r) => !r.ok)?.error;
        error(firstErr ? `测试推送失败：${firstErr}` : '未命中可用推送渠道或发送失败');
      }
    } catch (err: unknown) {
      error(`测试推送请求失败：${err instanceof Error ? err.message : '未知错误'}`);
    } finally {
      setTestingTarget(null);
    }
  };

  const enabledChannelCount = Object.values(config.channels).filter((ch) => ch.enabled).length;

  return (
    <SectionCard
      title="多渠道主动消息推送与防刷屏"
      icon={<Bell className="w-4 h-4" />}
      subtitle="支持 Telegram / Bark / 飞书 / 企业微信 / 通用 Webhook，内置事件冷却、每日限额与夜间静默"
      badge={
        config.enabled ? (
          <Badge tone="ok" dot>
            已开启 · {enabledChannelCount} 渠道
          </Badge>
        ) : (
          <Badge tone="neutral">未启用</Badge>
        )
      }
      actions={
        <Button
          size="xs"
          variant="ghost"
          disabled={loading}
          onClick={() => void loadConfig()}
          icon={<RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />}
        >
          刷新
        </Button>
      }
    >
      <form onSubmit={(e) => void handleSave(e)} className="space-y-4">
        {/* Global Policy Controls */}
        <div className="p-3.5 rounded-xl bg-surface2 border border-subtle space-y-3">
          <div className="flex flex-wrap items-center justify-between gap-2 pb-2.5 border-b border-subtle">
            <label className="inline-flex items-center gap-2 text-xs sm:text-sm font-medium text-primary cursor-pointer select-none">
              <input
                type="checkbox"
                checked={config.enabled}
                disabled={loading || busy}
                onChange={(e) => setConfig((prev) => ({ ...prev, enabled: e.target.checked }))}
                className="rounded border-subtle bg-surface1 accent-emerald-500"
              />
              <span>启用全局主动推送告警</span>
            </label>
            <span className="text-[11px] text-muted">
              敏感凭据已做脱敏隔离，留空或保持掩码即保留已保存密钥
            </span>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs">
            <label className="block space-y-1">
              <span className="text-secondary">冷却时间（分钟，1~1440）</span>
              <input
                type="number"
                min={1}
                max={1440}
                disabled={loading || busy}
                value={config.cooldownMinutes}
                onChange={(e) =>
                  setConfig((prev) => ({
                    ...prev,
                    cooldownMinutes: Number(e.target.value) || 15,
                  }))
                }
                className="w-full h-9 px-3 rounded-xl bg-surface1 border border-subtle text-primary font-mono tnum focus:outline-none focus:border-strong"
              />
            </label>
            <label className="block space-y-1">
              <span className="text-secondary">每日上限（条，1~1000）</span>
              <input
                type="number"
                min={1}
                max={1000}
                disabled={loading || busy}
                value={config.dailyLimit}
                onChange={(e) =>
                  setConfig((prev) => ({
                    ...prev,
                    dailyLimit: Number(e.target.value) || 50,
                  }))
                }
                className="w-full h-9 px-3 rounded-xl bg-surface1 border border-subtle text-primary font-mono tnum focus:outline-none focus:border-strong"
              />
            </label>
            <label className="block space-y-1">
              <span className="text-secondary">静默时段（如 23:00-07:30）</span>
              <input
                type="text"
                disabled={loading || busy}
                value={config.quietHours}
                onChange={(e) => setConfig((prev) => ({ ...prev, quietHours: e.target.value }))}
                placeholder="23:00-07:30（留空不静默）"
                className="w-full h-9 px-3 rounded-xl bg-surface1 border border-subtle text-primary font-mono focus:outline-none focus:border-strong"
              />
            </label>
          </div>
        </div>

        {/* 6 Events Grid */}
        <div className="space-y-2">
          <div className="text-xs font-medium text-secondary">触发告警事件类型</div>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2.5">
            {CLIENT_EVENT_ITEMS.map((ev) => {
              const checked = Boolean(config.events[ev.key]);
              return (
                <label
                  key={ev.key}
                  className={`p-2.5 rounded-xl border transition-colors flex items-start gap-2.5 cursor-pointer select-none ${
                    checked
                      ? 'bg-emerald-500/5 border-emerald-500/25'
                      : 'bg-surface2 border-subtle hover:border-slate-700'
                  }`}
                >
                  <input
                    type="checkbox"
                    checked={checked}
                    disabled={loading || busy}
                    onChange={(e) =>
                      setConfig((prev) => ({
                        ...prev,
                        events: { ...prev.events, [ev.key]: e.target.checked },
                      }))
                    }
                    className="mt-0.5 rounded border-subtle bg-surface1 accent-emerald-500 shrink-0"
                  />
                  <div className="min-w-0">
                    <div className="text-xs font-medium text-primary truncate">{ev.title}</div>
                    <div className="text-[11px] text-muted truncate mt-0.5">{ev.desc}</div>
                  </div>
                </label>
              );
            })}
          </div>
        </div>

        {/* 5 Channels Segmented Tabs */}
        <NotifyChannelPanel
          channels={config.channels}
          secretStatus={secretStatus}
          activeChannel={activeChannel}
          onChangeTab={setActiveChannel}
          onChangeChannels={(updater) =>
            setConfig((prev) => ({ ...prev, channels: updater(prev.channels) }))
          }
          onTestChannel={(ch) => void handleTest(ch)}
          testingChannel={testingTarget}
          disabled={loading || busy}
        />

        {/* Test Delivery Feedback */}
        {lastTestResults.length > 0 && (
          <div className="p-3 rounded-xl bg-slate-950/70 border border-slate-800 space-y-1.5 text-xs">
            <div className="text-[11px] font-semibold text-slate-300">本次测试投递结果</div>
            <div className="space-y-1">
              {lastTestResults.map((item, idx) => (
                <div
                  key={`${item.channel}-${idx}`}
                  className="flex flex-wrap items-center justify-between gap-2 font-mono text-[11px]"
                >
                  <div className="flex items-center gap-1.5 min-w-0">
                    {item.ok ? (
                      <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                    ) : (
                      <XCircle className="w-3.5 h-3.5 text-rose-400 shrink-0" />
                    )}
                    <span className="text-primary font-semibold">{item.channel}</span>
                    {item.error && <span className="text-rose-300 break-all">· {item.error}</span>}
                  </div>
                  <span className="text-muted tnum shrink-0">{item.latencyMs}ms</span>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Footer Save & Test All Buttons */}
        <div className="flex flex-wrap items-center justify-between gap-2.5 pt-1">
          <div className="flex flex-wrap items-center gap-2">
            <Button
              type="submit"
              size="sm"
              variant="primary"
              loading={saving}
              disabled={loading || busy}
              icon={<Save className="w-3.5 h-3.5" />}
            >
              保存推送配置
            </Button>
            <Button
              type="button"
              size="sm"
              variant="secondary"
              loading={testingTarget === 'all'}
              disabled={loading || busy || (Boolean(testingTarget) && testingTarget !== 'all')}
              onClick={() => void handleTest()}
              icon={<Send className="w-3.5 h-3.5" />}
            >
              测试全部已启用渠道
            </Button>
          </div>
          <span className="text-[11px] text-muted">测试支持直接预览当前表单，无需先保存</span>
        </div>

        {/* Collapsible Recent Push History (up to 50) */}
        <div className="rounded-xl bg-surface2 border border-subtle overflow-hidden">
          <button
            type="button"
            onClick={() => setHistoryOpen((v) => !v)}
            className="w-full px-3.5 py-2.5 flex items-center justify-between gap-2 text-xs hover:bg-slate-800/30 transition-colors cursor-pointer"
            aria-expanded={historyOpen}
          >
            <div className="flex items-center gap-2">
              {historyOpen ? (
                <ChevronDown className="w-3.5 h-3.5 text-slate-400" />
              ) : (
                <ChevronRight className="w-3.5 h-3.5 text-slate-400" />
              )}
              <History className="w-3.5 h-3.5 text-slate-400" />
              <span className="font-medium text-primary">近期推送历史（最多 50 条）</span>
            </div>
            <Badge tone="neutral">{history.length} 条</Badge>
          </button>

          {historyOpen && (
            <div className="border-t border-subtle max-h-72 overflow-y-auto divide-y divide-[var(--border-subtle)] text-xs">
              {history.length === 0 ? (
                <div className="px-3.5 py-5 text-center text-muted">暂无推送历史记录</div>
              ) : (
                history.slice(0, 50).map((rec, idx) => (
                  <div key={`${rec.time}-${idx}`} className="px-3.5 py-2.5 space-y-1">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <div className="flex items-center gap-1.5 min-w-0">
                        {rec.success ? (
                          <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                        ) : (
                          <XCircle className="w-3.5 h-3.5 text-rose-400 shrink-0" />
                        )}
                        <span className="font-medium text-primary truncate">{rec.title}</span>
                        <Badge tone={severityBadgeTone(rec.severity)} className="!text-[10px]">
                          {rec.severity}
                        </Badge>
                      </div>
                      <span className="font-mono text-[11px] text-muted tnum shrink-0">
                        {rec.time}
                      </span>
                    </div>
                    <div className="flex flex-wrap items-center gap-2 pl-5 text-[11px] font-mono text-secondary">
                      <span>事件：{rec.eventType}</span>
                      <span>· 渠道：{rec.channels?.length ? rec.channels.join(', ') : '-'}</span>
                      {rec.error && <span className="text-rose-300 break-all">· {rec.error}</span>}
                    </div>
                  </div>
                ))
              )}
            </div>
          )}
        </div>
      </form>
    </SectionCard>
  );
};

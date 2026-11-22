import React from 'react';
import { Bell, CheckCircle2, Globe, MessageSquare, Send, Smartphone, Webhook } from 'lucide-react';
import { Badge, Button, SegmentedTabs, StatusDot } from '../../../ui';
import { NotifyChannelsConfig, NotifySecretStatus } from '../../types';

export type NotifyChannelKey = keyof NotifyChannelsConfig;

export interface NotifyChannelPanelProps {
  channels: NotifyChannelsConfig;
  secretStatus: NotifySecretStatus;
  activeChannel: NotifyChannelKey;
  onChangeTab: (tab: NotifyChannelKey) => void;
  onChangeChannels: (updater: (prev: NotifyChannelsConfig) => NotifyChannelsConfig) => void;
  onTestChannel: (channel: NotifyChannelKey) => void;
  testingChannel: string | null;
  disabled?: boolean;
}

const INPUT_CLASS =
  'w-full h-9 px-3 rounded-xl bg-surface1 border border-subtle text-xs text-primary font-mono focus:outline-none focus:border-strong disabled:opacity-55';

function SecretLabel({ label, configured }: { label: string; configured: boolean }) {
  return (
    <span className="flex items-center justify-between gap-2 text-secondary">
      <span>{label}</span>
      {configured && (
        <Badge tone="ok" className="!px-1.5 !py-0 !text-[10px]">
          已配置
        </Badge>
      )}
    </span>
  );
}

export const NotifyChannelPanel: React.FC<NotifyChannelPanelProps> = ({
  channels,
  secretStatus,
  activeChannel,
  onChangeTab,
  onChangeChannels,
  onTestChannel,
  testingChannel,
  disabled = false,
}) => {
  const tabItems: { key: NotifyChannelKey; label: string; icon: React.ReactNode; badge?: React.ReactNode }[] = [
    {
      key: 'telegram',
      label: 'Telegram',
      icon: <Send className="w-3.5 h-3.5" />,
      badge: channels.telegram.enabled ? <StatusDot tone="ok" /> : undefined,
    },
    {
      key: 'bark',
      label: 'Bark',
      icon: <Smartphone className="w-3.5 h-3.5" />,
      badge: channels.bark.enabled ? <StatusDot tone="ok" /> : undefined,
    },
    {
      key: 'feishu',
      label: '飞书',
      icon: <MessageSquare className="w-3.5 h-3.5" />,
      badge: channels.feishu.enabled ? <StatusDot tone="ok" /> : undefined,
    },
    {
      key: 'wecom',
      label: '企业微信',
      icon: <Bell className="w-3.5 h-3.5" />,
      badge: channels.wecom.enabled ? <StatusDot tone="ok" /> : undefined,
    },
    {
      key: 'webhook',
      label: '通用 Webhook',
      icon: <Webhook className="w-3.5 h-3.5" />,
      badge: channels.webhook.enabled ? <StatusDot tone="ok" /> : undefined,
    },
  ];

  const isTestingCurrent = testingChannel === activeChannel;
  const isAnyTesting = Boolean(testingChannel);
  const maskedHint = '已配置（留空或保持掩码不修改）';

  const renderChannelHeader = (title: string, enabled: boolean, onToggle: (checked: boolean) => void) => (
    <div className="flex flex-wrap items-center justify-between gap-2 pb-2.5 border-b border-subtle">
      <label className="inline-flex items-center gap-2 text-xs font-medium text-primary cursor-pointer select-none">
        <input
          type="checkbox"
          checked={enabled}
          disabled={disabled}
          onChange={(e) => onToggle(e.target.checked)}
          className="rounded border-subtle bg-surface1 accent-emerald-500"
        />
        <span>启用 {title} 推送</span>
        {enabled && (
          <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
        )}
      </label>
      <Button
        size="xs"
        variant="secondary"
        loading={isTestingCurrent}
        disabled={disabled || (isAnyTesting && !isTestingCurrent)}
        onClick={() => onTestChannel(activeChannel)}
        icon={<Send className="w-3 h-3" />}
      >
        测试当前渠道
      </Button>
    </div>
  );

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="text-xs font-medium text-secondary">推送渠道配置（5 渠道零外部依赖）</div>
        <SegmentedTabs items={tabItems} value={activeChannel} onChange={onChangeTab} />
      </div>

      <div className="p-3.5 rounded-xl bg-surface2 border border-subtle space-y-3 text-xs">
        {activeChannel === 'telegram' && (
          <>
            {renderChannelHeader('Telegram Bot', channels.telegram.enabled, (checked) =>
              onChangeChannels((prev) => ({
                ...prev,
                telegram: { ...prev.telegram, enabled: checked },
              })),
            )}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              <label className="block space-y-1">
                <SecretLabel label="Bot Token" configured={secretStatus.telegramBotToken} />
                <input
                  type="password"
                  autoComplete="off"
                  disabled={disabled}
                  value={channels.telegram.botToken}
                  onChange={(e) =>
                    onChangeChannels((prev) => ({
                      ...prev,
                      telegram: { ...prev.telegram, botToken: e.target.value },
                    }))
                  }
                  placeholder={secretStatus.telegramBotToken ? maskedHint : '123456:your_bot_token'}
                  className={INPUT_CLASS}
                />
              </label>
              <label className="block space-y-1">
                <span className="text-secondary">Chat ID</span>
                <input
                  type="text"
                  disabled={disabled}
                  value={channels.telegram.chatId}
                  onChange={(e) =>
                    onChangeChannels((prev) => ({
                      ...prev,
                      telegram: { ...prev.telegram, chatId: e.target.value },
                    }))
                  }
                  placeholder="-1001234567890 或个人数字 Chat ID"
                  className={INPUT_CLASS}
                />
              </label>
            </div>
            <label className="block space-y-1">
              <span className="text-secondary inline-flex items-center gap-1">
                <Globe className="w-3 h-3" />
                API 反代地址（可选，留空默认官方）
              </span>
              <input
                type="text"
                disabled={disabled}
                value={channels.telegram.apiBaseUrl}
                onChange={(e) =>
                  onChangeChannels((prev) => ({
                    ...prev,
                    telegram: { ...prev.telegram, apiBaseUrl: e.target.value },
                  }))
                }
                placeholder="https://api.telegram.org"
                className={INPUT_CLASS}
              />
            </label>
          </>
        )}

        {activeChannel === 'bark' && (
          <>
            {renderChannelHeader('Bark (iOS)', channels.bark.enabled, (checked) =>
              onChangeChannels((prev) => ({
                ...prev,
                bark: { ...prev.bark, enabled: checked },
              })),
            )}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              <label className="block space-y-1">
                <SecretLabel label="Device Key" configured={secretStatus.barkDeviceKey} />
                <input
                  type="password"
                  autoComplete="off"
                  disabled={disabled}
                  value={channels.bark.deviceKey}
                  onChange={(e) =>
                    onChangeChannels((prev) => ({
                      ...prev,
                      bark: { ...prev.bark, deviceKey: e.target.value },
                    }))
                  }
                  placeholder={secretStatus.barkDeviceKey ? maskedHint : 'your_bark_device_key'}
                  className={INPUT_CLASS}
                />
              </label>
              <label className="block space-y-1">
                <span className="text-secondary">消息分组（Group）</span>
                <input
                  type="text"
                  disabled={disabled}
                  value={channels.bark.group}
                  onChange={(e) =>
                    onChangeChannels((prev) => ({
                      ...prev,
                      bark: { ...prev.bark, group: e.target.value },
                    }))
                  }
                  placeholder="SingCtl"
                  className={INPUT_CLASS}
                />
              </label>
            </div>
            <label className="block space-y-1">
              <span className="text-secondary">Bark 服务器地址（可选）</span>
              <input
                type="text"
                disabled={disabled}
                value={channels.bark.serverUrl}
                onChange={(e) =>
                  onChangeChannels((prev) => ({
                    ...prev,
                    bark: { ...prev.bark, serverUrl: e.target.value },
                  }))
                }
                placeholder="https://api.day.app"
                className={INPUT_CLASS}
              />
            </label>
          </>
        )}

        {activeChannel === 'feishu' && (
          <>
            {renderChannelHeader('飞书自定义机器人', channels.feishu.enabled, (checked) =>
              onChangeChannels((prev) => ({
                ...prev,
                feishu: { ...prev.feishu, enabled: checked },
              })),
            )}
            <label className="block space-y-1">
              <SecretLabel label="Webhook URL" configured={secretStatus.feishuWebhookUrl} />
              <input
                type="text"
                autoComplete="off"
                disabled={disabled}
                value={channels.feishu.webhookUrl}
                onChange={(e) =>
                  onChangeChannels((prev) => ({
                    ...prev,
                    feishu: { ...prev.feishu, webhookUrl: e.target.value },
                  }))
                }
                placeholder={
                  secretStatus.feishuWebhookUrl
                    ? maskedHint
                    : 'https://open.feishu.cn/open-apis/bot/v2/hook/your_hook_id'
                }
                className={INPUT_CLASS}
              />
            </label>
            <label className="block space-y-1">
              <SecretLabel label="签名校验密钥（可选）" configured={secretStatus.feishuSecret} />
              <input
                type="password"
                autoComplete="off"
                disabled={disabled}
                value={channels.feishu.secret}
                onChange={(e) =>
                  onChangeChannels((prev) => ({
                    ...prev,
                    feishu: { ...prev.feishu, secret: e.target.value },
                  }))
                }
                placeholder={secretStatus.feishuSecret ? maskedHint : 'your_feishu_sign_secret'}
                className={INPUT_CLASS}
              />
            </label>
          </>
        )}

        {activeChannel === 'wecom' && (
          <>
            {renderChannelHeader('企业微信群机器人', channels.wecom.enabled, (checked) =>
              onChangeChannels((prev) => ({
                ...prev,
                wecom: { ...prev.wecom, enabled: checked },
              })),
            )}
            <label className="block space-y-1">
              <SecretLabel label="Webhook URL" configured={secretStatus.wecomWebhookUrl} />
              <input
                type="text"
                autoComplete="off"
                disabled={disabled}
                value={channels.wecom.webhookUrl}
                onChange={(e) =>
                  onChangeChannels((prev) => ({
                    ...prev,
                    wecom: { ...prev.wecom, webhookUrl: e.target.value },
                  }))
                }
                placeholder={
                  secretStatus.wecomWebhookUrl
                    ? maskedHint
                    : 'https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=your_wecom_key'
                }
                className={INPUT_CLASS}
              />
            </label>
          </>
        )}

        {activeChannel === 'webhook' && (
          <>
            {renderChannelHeader('通用 JSON Webhook', channels.webhook.enabled, (checked) =>
              onChangeChannels((prev) => ({
                ...prev,
                webhook: { ...prev.webhook, enabled: checked },
              })),
            )}
            <label className="block space-y-1">
              <span className="text-secondary">Webhook URL</span>
              <input
                type="text"
                disabled={disabled}
                value={channels.webhook.url}
                onChange={(e) =>
                  onChangeChannels((prev) => ({
                    ...prev,
                    webhook: { ...prev.webhook, url: e.target.value },
                  }))
                }
                placeholder="https://hooks.example.com/singctl"
                className={INPUT_CLASS}
              />
            </label>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              <label className="block space-y-1">
                <span className="text-secondary">自定义请求头名称（可选）</span>
                <input
                  type="text"
                  disabled={disabled}
                  value={channels.webhook.headerName}
                  onChange={(e) =>
                    onChangeChannels((prev) => ({
                      ...prev,
                      webhook: { ...prev.webhook, headerName: e.target.value },
                    }))
                  }
                  placeholder="Authorization"
                  className={INPUT_CLASS}
                />
              </label>
              <label className="block space-y-1">
                <SecretLabel label="自定义请求头值（可选）" configured={secretStatus.webhookHeaderValue} />
                <input
                  type="password"
                  autoComplete="off"
                  disabled={disabled}
                  value={channels.webhook.headerValue}
                  onChange={(e) =>
                    onChangeChannels((prev) => ({
                      ...prev,
                      webhook: { ...prev.webhook, headerValue: e.target.value },
                    }))
                  }
                  placeholder={secretStatus.webhookHeaderValue ? maskedHint : 'Bearer your_webhook_token'}
                  className={INPUT_CLASS}
                />
              </label>
            </div>
          </>
        )}
      </div>
    </div>
  );
};

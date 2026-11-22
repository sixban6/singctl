// 文件职责：提供 config.NotifyConfig 到 notify.Options 的零反射转换与配置保存前合法性校验。
package notify

import (
	"errors"
	"fmt"
	"strings"

	"singctl/internal/config"
)

// OptionsFromConfig 将配置模型 config.NotifyConfig 转换为通知调度器运行期 Options。
func OptionsFromConfig(cfg config.NotifyConfig) Options {
	ev := cfg.EffectiveEvents()
	return Options{
		Enabled:         cfg.Enabled,
		CooldownMinutes: cfg.EffectiveCooldownMinutes(),
		DailyLimit:      cfg.EffectiveDailyLimit(),
		QuietHours:      cfg.EffectiveQuietHours(),
		EnabledEvents: map[EventType]bool{
			EventWatchdogHeal:       ev.WatchdogHeal,
			EventSafeCommitRollback: ev.SafeCommitRollback,
			EventResourceGuard:      ev.ResourceGuard,
			EventAuditHighRisk:      ev.AuditHighRisk,
			EventNewDevice:          ev.NewDevice,
			EventSubOrNodeFail:      ev.SubOrNodeFail,
			EventServerQuotaOrBan:   ev.ServerQuotaOrBan,
		},
		Telegram: TelegramConfig{
			Enabled:    cfg.Channels.Telegram.Enabled,
			BotToken:   strings.TrimSpace(cfg.Channels.Telegram.BotToken),
			ChatID:     strings.TrimSpace(cfg.Channels.Telegram.ChatID),
			APIBaseURL: strings.TrimSpace(cfg.Channels.Telegram.APIBaseURL),
		},
		Bark: BarkConfig{
			Enabled:   cfg.Channels.Bark.Enabled,
			ServerURL: cfg.Channels.Bark.EffectiveServerURL(),
			DeviceKey: strings.TrimSpace(cfg.Channels.Bark.DeviceKey),
			Group:     strings.TrimSpace(cfg.Channels.Bark.Group),
		},
		Feishu: FeishuConfig{
			Enabled:    cfg.Channels.Feishu.Enabled,
			WebhookURL: strings.TrimSpace(cfg.Channels.Feishu.WebhookURL),
			Secret:     strings.TrimSpace(cfg.Channels.Feishu.Secret),
		},
		WeCom: WeComConfig{
			Enabled:    cfg.Channels.WeCom.Enabled,
			WebhookURL: strings.TrimSpace(cfg.Channels.WeCom.WebhookURL),
		},
		Webhook: WebhookConfig{
			Enabled:     cfg.Channels.Webhook.Enabled,
			URL:         strings.TrimSpace(cfg.Channels.Webhook.URL),
			HeaderName:  strings.TrimSpace(cfg.Channels.Webhook.HeaderName),
			HeaderValue: cfg.Channels.Webhook.HeaderValue,
		},
	}
}

// ValidateConfig 校验通知配置中的静默时段、限流参数及全部已启用渠道的 URL、凭据与自定义 Header 安全性。
func ValidateConfig(cfg config.NotifyConfig) error {
	if cfg.CooldownMinutes < 0 {
		return errors.New("cooldown minutes must be >= 0")
	}
	if cfg.DailyLimit < 0 {
		return errors.New("daily limit must be >= 0")
	}
	if _, err := ParseQuietHours(cfg.QuietHours); err != nil {
		return err
	}

	opts := OptionsFromConfig(cfg)
	if opts.Telegram.Enabled {
		if _, _, err := validateTelegramConfig(opts.Telegram); err != nil {
			return err
		}
	}
	if opts.Bark.Enabled {
		if _, _, _, err := validateBarkConfig(opts.Bark); err != nil {
			return err
		}
	}
	if opts.Feishu.Enabled {
		if _, err := validateFeishuConfig(opts.Feishu); err != nil {
			return err
		}
	}
	if opts.WeCom.Enabled {
		if _, err := validateWeComConfig(opts.WeCom); err != nil {
			return err
		}
	}
	if opts.Webhook.Enabled {
		if _, _, _, err := validateWebhookConfig(opts.Webhook); err != nil {
			return err
		}
		if opts.Webhook.HeaderValue != "" {
			if err := ValidateHeaderValue(opts.Webhook.HeaderValue); err != nil {
				return fmt.Errorf("invalid webhook header value: %w", err)
			}
		}
	}
	return nil
}

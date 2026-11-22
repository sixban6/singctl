// 文件职责：验证 notify.OptionsFromConfig 与 notify.ValidateConfig 的配置桥接、默认值归一化与安全注入拦截。
package notify_test

import (
	"strings"
	"testing"

	"singctl/internal/config"
	"singctl/internal/notify"
)

func TestOptionsFromConfig_DefaultsAndChannelMapping(t *testing.T) {
	cfg := config.NotifyConfig{
		Enabled: true,
		Channels: config.NotifyChannelsConfig{
			Telegram: config.TelegramNotifyConfig{
				Enabled:  true,
				BotToken: "123456:test-bot-token",
				ChatID:   "999000111",
			},
			Bark: config.BarkNotifyConfig{
				Enabled:   true,
				DeviceKey: "bark-test-device-key",
			},
			Feishu: config.FeishuNotifyConfig{
				Enabled:    true,
				WebhookURL: "https://example.com/open-apis/bot/v2/hook/test",
				Secret:     "feishu-test-secret",
			},
			WeCom: config.WeComNotifyConfig{
				Enabled:    true,
				WebhookURL: "https://example.com/cgi-bin/webhook/send?key=test",
			},
			Webhook: config.GenericWebhookConfig{
				Enabled:     true,
				URL:         "https://example.com/webhook",
				HeaderName:  "X-SingCtl-Token",
				HeaderValue: "secret-header-val",
			},
		},
	}

	opts := notify.OptionsFromConfig(cfg)
	if !opts.Enabled {
		t.Fatal("expected opts.Enabled=true")
	}
	if opts.CooldownMinutes != config.NotifyDefaultCooldownMinutes {
		t.Fatalf("CooldownMinutes = %d, want %d", opts.CooldownMinutes, config.NotifyDefaultCooldownMinutes)
	}
	if opts.DailyLimit != config.NotifyDefaultDailyLimit {
		t.Fatalf("DailyLimit = %d, want %d", opts.DailyLimit, config.NotifyDefaultDailyLimit)
	}
	for _, ev := range []notify.EventType{
		notify.EventWatchdogHeal,
		notify.EventSafeCommitRollback,
		notify.EventResourceGuard,
		notify.EventAuditHighRisk,
		notify.EventNewDevice,
		notify.EventSubOrNodeFail,
		notify.EventServerQuotaOrBan,
	} {
		if !opts.EnabledEvents[ev] {
			t.Fatalf("expected default event %q enabled", ev)
		}
	}
	if opts.Bark.ServerURL != config.NotifyDefaultBarkServerURL {
		t.Fatalf("Bark.ServerURL = %q, want %q", opts.Bark.ServerURL, config.NotifyDefaultBarkServerURL)
	}
	if opts.Telegram.BotToken != "123456:test-bot-token" || opts.Telegram.ChatID != "999000111" {
		t.Fatalf("unexpected telegram mapping: %+v", opts.Telegram)
	}
	if opts.Webhook.HeaderName != "X-SingCtl-Token" || opts.Webhook.HeaderValue != "secret-header-val" {
		t.Fatalf("unexpected webhook mapping: %+v", opts.Webhook)
	}
}

func TestValidateConfig_BoundariesAndInjectionRejection(t *testing.T) {
	cases := []struct {
		name    string
		cfg     config.NotifyConfig
		wantErr string
	}{
		{
			name: "empty_disabled_ok",
			cfg:  config.NotifyConfig{},
		},
		{
			name: "valid_quiet_hours_and_webhook_ok",
			cfg: config.NotifyConfig{
				Enabled:    true,
				QuietHours: "23:00-07:30",
				Channels: config.NotifyChannelsConfig{
					Webhook: config.GenericWebhookConfig{
						Enabled:     true,
						URL:         "https://example.com/hook",
						HeaderName:  "Authorization",
						HeaderValue: "Bearer demo-token",
					},
				},
			},
		},
		{
			name: "invalid_quiet_hours",
			cfg: config.NotifyConfig{
				QuietHours: "25:99-07:00",
			},
			wantErr: "quiet",
		},
		{
			name: "negative_cooldown",
			cfg: config.NotifyConfig{
				CooldownMinutes: -5,
			},
			wantErr: "cooldown",
		},
		{
			name: "negative_daily_limit",
			cfg: config.NotifyConfig{
				DailyLimit: -1,
			},
			wantErr: "daily",
		},
		{
			name: "telegram_missing_token_when_enabled",
			cfg: config.NotifyConfig{
				Channels: config.NotifyChannelsConfig{
					Telegram: config.TelegramNotifyConfig{
						Enabled: true,
						ChatID:  "12345",
					},
				},
			},
			wantErr: "telegram",
		},
		{
			name: "telegram_bad_api_base_scheme",
			cfg: config.NotifyConfig{
				Channels: config.NotifyChannelsConfig{
					Telegram: config.TelegramNotifyConfig{
						Enabled:    true,
						BotToken:   "123:abc",
						ChatID:     "12345",
						APIBaseURL: "file:///etc/passwd",
					},
				},
			},
			wantErr: "url",
		},
		{
			name: "bark_invalid_server_url",
			cfg: config.NotifyConfig{
				Channels: config.NotifyChannelsConfig{
					Bark: config.BarkNotifyConfig{
						Enabled:   true,
						DeviceKey: "key123",
						ServerURL: "ftp://example.com",
					},
				},
			},
			wantErr: "url",
		},
		{
			name: "feishu_invalid_url",
			cfg: config.NotifyConfig{
				Channels: config.NotifyChannelsConfig{
					Feishu: config.FeishuNotifyConfig{
						Enabled:    true,
						WebhookURL: "javascript:alert(1)",
					},
				},
			},
			wantErr: "feishu",
		},
		{
			name: "wecom_invalid_url",
			cfg: config.NotifyConfig{
				Channels: config.NotifyChannelsConfig{
					WeCom: config.WeComNotifyConfig{
						Enabled:    true,
						WebhookURL: "not-a-url",
					},
				},
			},
			wantErr: "wecom",
		},
		{
			name: "webhook_crlf_header_injection",
			cfg: config.NotifyConfig{
				Channels: config.NotifyChannelsConfig{
					Webhook: config.GenericWebhookConfig{
						Enabled:     true,
						URL:         "https://example.com/hook",
						HeaderName:  "X-Auth",
						HeaderValue: "ok\r\nX-Injected: evil",
					},
				},
			},
			wantErr: "header",
		},
		{
			name: "webhook_invalid_header_name",
			cfg: config.NotifyConfig{
				Channels: config.NotifyChannelsConfig{
					Webhook: config.GenericWebhookConfig{
						Enabled:     true,
						URL:         "https://example.com/hook",
						HeaderName:  "Bad Header Name",
						HeaderValue: "val",
					},
				},
			},
			wantErr: "header",
		},
		{
			name: "disabled_channel_with_empty_fields_allowed",
			cfg: config.NotifyConfig{
				Enabled: true,
				Channels: config.NotifyChannelsConfig{
					Feishu: config.FeishuNotifyConfig{Enabled: false, WebhookURL: ""},
					Webhook: config.GenericWebhookConfig{
						Enabled: true,
						URL:     "https://example.com/ok",
					},
				},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := notify.ValidateConfig(tc.cfg)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("expected nil error, got %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.wantErr)
			}
			if !strings.Contains(strings.ToLower(err.Error()), tc.wantErr) {
				t.Fatalf("error %q does not contain %q", err.Error(), tc.wantErr)
			}
		})
	}
}

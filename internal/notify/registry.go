// 文件职责：提供 OCP 声明式渠道工厂注册表与统一 URL/参数安全过滤的渠道装配入口。
package notify

import "strings"

type channelFactory struct {
	name       string
	configured func(opts Options) bool
	build      func(opts Options) Channel
}

var channelFactories = []channelFactory{
	{
		name:       ChannelTelegram,
		configured: func(o Options) bool { return o.Telegram.Enabled },
		build:      func(o Options) Channel { return NewTelegramChannel(o.Telegram) },
	},
	{
		name:       ChannelBark,
		configured: func(o Options) bool { return o.Bark.Enabled },
		build:      func(o Options) Channel { return NewBarkChannel(o.Bark) },
	},
	{
		name:       ChannelFeishu,
		configured: func(o Options) bool { return o.Feishu.Enabled },
		build:      func(o Options) Channel { return NewFeishuChannel(o.Feishu) },
	},
	{
		name:       ChannelWeCom,
		configured: func(o Options) bool { return o.WeCom.Enabled },
		build:      func(o Options) Channel { return NewWeComChannel(o.WeCom) },
	},
	{
		name:       ChannelWebhook,
		configured: func(o Options) bool { return o.Webhook.Enabled },
		build:      func(o Options) Channel { return NewWebhookChannel(o.Webhook) },
	},
}

// BuildChannels 按声明式注册表顺序构建所有已启用且通过 URL/参数安全校验的渠道实例。
func BuildChannels(opts Options) []Channel {
	channels := make([]Channel, 0, len(channelFactories))
	for _, factory := range channelFactories {
		ch := factory.build(opts)
		if ch != nil && ch.Enabled() {
			channels = append(channels, ch)
		}
	}
	return channels
}

// KnownChannelNames 按注册表声明顺序返回所有受支持的推送渠道名。
func KnownChannelNames() []string {
	names := make([]string, 0, len(channelFactories))
	for _, factory := range channelFactories {
		names = append(names, factory.name)
	}
	return names
}

func lookupChannelFactory(name string) (channelFactory, bool) {
	target := strings.ToLower(strings.TrimSpace(name))
	for _, factory := range channelFactories {
		if factory.name == target {
			return factory, true
		}
	}
	return channelFactory{}, false
}

// 文件职责：定义通知引擎核心领域类型、事件枚举、渠道配置、Channel 接口、投递结果与历史记录契约。
package notify

import (
	"context"
	"maps"
	"net/http"
	"time"
)

// Severity 表示告警严重级别。
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityWarn     Severity = "warn"
	SeverityCritical Severity = "critical"
)

// EventType 表示支持主动推送的系统事件类型。
type EventType string

const (
	EventWatchdogHeal       EventType = "watchdog_heal"
	EventSafeCommitRollback EventType = "safe_commit_rollback"
	EventResourceGuard      EventType = "resource_guard"
	EventAuditHighRisk      EventType = "audit_high_risk"
	EventNewDevice          EventType = "new_device"
	EventSubOrNodeFail      EventType = "sub_or_node_fail"
	EventServerQuotaOrBan   EventType = "server_quota_or_ban"
	EventTest               EventType = "test"
)

// 标准渠道名称常量。
const (
	ChannelTelegram = "telegram"
	ChannelBark     = "bark"
	ChannelFeishu   = "feishu"
	ChannelWeCom    = "wecom"
	ChannelWebhook  = "webhook"
)

// 默认引擎策略参数与端点常量。
const (
	DefaultTelegramAPIBase = "https://api.telegram.org"
	DefaultBarkServerURL   = "https://api.day.app"
	DefaultCooldownMinutes = 15
	DefaultDailyLimit      = 50
	DefaultSendTimeout     = 6 * time.Second
	MaxQueueSize           = 32
	MaxHistorySize         = 50
)

// Event 表示待投递的单条通知事件。
type Event struct {
	Type      EventType `json:"eventType"`
	Severity  Severity  `json:"severity"`
	DedupKey  string    `json:"dedupKey,omitempty"`
	Hostname  string    `json:"hostname,omitempty"`
	Title     string    `json:"title"`
	Body      string    `json:"body"`
	Resolved  bool      `json:"resolved"`
	Timestamp time.Time `json:"timestamp"`
}

// TelegramConfig 定义 Telegram Bot API 推送配置。
type TelegramConfig struct {
	Enabled    bool   `json:"enabled"`
	BotToken   string `json:"botToken,omitempty"`
	ChatID     string `json:"chatId,omitempty"`
	APIBaseURL string `json:"apiBaseUrl,omitempty"`
}

// BarkConfig 定义 Bark iOS 推送配置。
type BarkConfig struct {
	Enabled   bool   `json:"enabled"`
	ServerURL string `json:"serverUrl,omitempty"`
	DeviceKey string `json:"deviceKey,omitempty"`
	Group     string `json:"group,omitempty"`
}

// FeishuConfig 定义飞书自定义机器人 Webhook 推送配置。
type FeishuConfig struct {
	Enabled    bool   `json:"enabled"`
	WebhookURL string `json:"webhookUrl,omitempty"`
	Secret     string `json:"secret,omitempty"`
}

// WeComConfig 定义企业微信机器人 Webhook 推送配置。
type WeComConfig struct {
	Enabled    bool   `json:"enabled"`
	WebhookURL string `json:"webhookUrl,omitempty"`
}

// WebhookConfig 定义通用结构化 JSON Webhook 推送配置。
type WebhookConfig struct {
	Enabled     bool   `json:"enabled"`
	URL         string `json:"url,omitempty"`
	HeaderName  string `json:"headerName,omitempty"`
	HeaderValue string `json:"headerValue,omitempty"`
}

// Options 定义通知引擎的完整运行策略与各推送渠道参数。
type Options struct {
	Enabled         bool
	CooldownMinutes int
	DailyLimit      int
	QuietHours      string
	EnabledEvents   map[EventType]bool
	Telegram        TelegramConfig
	Bark            BarkConfig
	Feishu          FeishuConfig
	WeCom           WeComConfig
	Webhook         WebhookConfig
}

// Clone 返回 Options 的深拷贝，隔离外部 map 修改。
func (o Options) Clone() Options {
	cp := o
	cp.EnabledEvents = maps.Clone(o.EnabledEvents)
	return cp
}

// Channel 定义单个推送渠道的统一契约。
type Channel interface {
	Name() string
	Enabled() bool
	Send(ctx context.Context, client *http.Client, ev Event) error
}

// DeliveryResult 表示单次向指定渠道投递的执行结果。
type DeliveryResult struct {
	Channel   string `json:"channel"`
	OK        bool   `json:"ok"`
	Error     string `json:"error,omitempty"`
	LatencyMs int64  `json:"latencyMs"`
}

// HistoryRecord 表示内存有界环形缓冲区中的近期推送审计记录。
type HistoryRecord struct {
	Time      string    `json:"time"`
	EventType EventType `json:"eventType"`
	Severity  Severity  `json:"severity"`
	Title     string    `json:"title"`
	Channels  []string  `json:"channels"`
	Success   bool      `json:"success"`
	Error     string    `json:"error,omitempty"`
}

// DispatcherDeps 定义调度器的显式可注入外部依赖（零值时回退生产默认实现）。
type DispatcherDeps struct {
	HTTPClient  *http.Client
	NowFunc     func() time.Time
	Hostname    string
	SendTimeout time.Duration
	Logf        func(format string, args ...any)
}

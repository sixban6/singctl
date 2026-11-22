// 文件职责：定义主动推送通知配置模型（NotifyConfig）与远端安全回滚保险丝配置模型（SafeCommitConfig），含脱敏拷贝、密钥保留合并与宽容反序列化。
package config

import (
	"encoding/json"
	"net/url"
	"slices"
	"strings"

	"singctl/internal/constant"

	"gopkg.in/yaml.v3"
)

const (
	NotifyDefaultCooldownMinutes = 15
	NotifyMinCooldownMinutes     = 1
	NotifyMaxCooldownMinutes     = 1440

	NotifyDefaultDailyLimit = 50
	NotifyMinDailyLimit     = 1
	NotifyMaxDailyLimit     = 1000

	NotifyDefaultBarkServerURL = "https://api.day.app"
	NotifySecretMask           = "********"
	notifyMaskMarker           = "****"
)

// NotifyEventsConfig 定义主动告警事件开关集合。
type NotifyEventsConfig struct {
	WatchdogHeal       bool `yaml:"watchdog_heal" json:"watchdogHeal"`
	SafeCommitRollback bool `yaml:"safe_commit_rollback" json:"safeCommitRollback"`
	ResourceGuard      bool `yaml:"resource_guard" json:"resourceGuard"`
	AuditHighRisk      bool `yaml:"audit_high_risk" json:"auditHighRisk"`
	NewDevice          bool `yaml:"new_device" json:"newDevice"`
	SubOrNodeFail      bool `yaml:"sub_or_node_fail" json:"subOrNodeFail"`
	ServerQuotaOrBan   bool `yaml:"server_quota_or_ban" json:"serverQuotaOrBan"`
	explicit           bool `yaml:"-" json:"-"`
}

// TelegramNotifyConfig 定义 Telegram Bot 推送渠道配置。
type TelegramNotifyConfig struct {
	Enabled    bool   `yaml:"enabled,omitempty" json:"enabled"`
	BotToken   string `yaml:"bot_token,omitempty" json:"botToken"`
	ChatID     string `yaml:"chat_id,omitempty" json:"chatId"`
	APIBaseURL string `yaml:"api_base_url,omitempty" json:"apiBaseUrl"`
}

// BarkNotifyConfig 定义 iOS Bark 推送渠道配置。
type BarkNotifyConfig struct {
	Enabled   bool   `yaml:"enabled,omitempty" json:"enabled"`
	ServerURL string `yaml:"server_url,omitempty" json:"serverUrl"`
	DeviceKey string `yaml:"device_key,omitempty" json:"deviceKey"`
	Group     string `yaml:"group,omitempty" json:"group"`
}

// FeishuNotifyConfig 定义飞书自定义机器人推送渠道配置。
type FeishuNotifyConfig struct {
	Enabled    bool   `yaml:"enabled,omitempty" json:"enabled"`
	WebhookURL string `yaml:"webhook_url,omitempty" json:"webhookUrl"`
	Secret     string `yaml:"secret,omitempty" json:"secret"`
}

// WeComNotifyConfig 定义企业微信群机器人推送渠道配置。
type WeComNotifyConfig struct {
	Enabled    bool   `yaml:"enabled,omitempty" json:"enabled"`
	WebhookURL string `yaml:"webhook_url,omitempty" json:"webhookUrl"`
}

// GenericWebhookConfig 定义通用 JSON Webhook 推送渠道配置。
type GenericWebhookConfig struct {
	Enabled     bool   `yaml:"enabled,omitempty" json:"enabled"`
	URL         string `yaml:"url,omitempty" json:"url"`
	HeaderName  string `yaml:"header_name,omitempty" json:"headerName"`
	HeaderValue string `yaml:"header_value,omitempty" json:"headerValue"`
}

// NotifyChannelsConfig 聚合 5 大零外部依赖推送渠道配置。
type NotifyChannelsConfig struct {
	Telegram TelegramNotifyConfig `yaml:"telegram,omitempty" json:"telegram"`
	Bark     BarkNotifyConfig     `yaml:"bark,omitempty" json:"bark"`
	Feishu   FeishuNotifyConfig   `yaml:"feishu,omitempty" json:"feishu"`
	WeCom    WeComNotifyConfig    `yaml:"wecom,omitempty" json:"wecom"`
	Webhook  GenericWebhookConfig `yaml:"webhook,omitempty" json:"webhook"`
}

// NotifySecretStatus 指示各渠道敏感凭据是否已配置，供前端在脱敏展示时识别。
type NotifySecretStatus struct {
	TelegramBotToken   bool `json:"telegramBotToken"`
	BarkDeviceKey      bool `json:"barkDeviceKey"`
	FeishuWebhookURL   bool `json:"feishuWebhookUrl"`
	FeishuSecret       bool `json:"feishuSecret"`
	WeComWebhookURL    bool `json:"wecomWebhookUrl"`
	WebhookHeaderValue bool `json:"webhookHeaderValue"`
}

// NotifyConfig 定义客户端/服务端通用的主动消息推送与防刷屏配置模型。
type NotifyConfig struct {
	Enabled         bool                 `yaml:"enabled,omitempty" json:"enabled"`
	CooldownMinutes int                  `yaml:"cooldown_minutes,omitempty" json:"cooldownMinutes"`
	DailyLimit      int                  `yaml:"daily_limit,omitempty" json:"dailyLimit"`
	QuietHours      string               `yaml:"quiet_hours,omitempty" json:"quietHours"`
	Events          NotifyEventsConfig   `yaml:"events,omitempty" json:"events"`
	Channels        NotifyChannelsConfig `yaml:"channels,omitempty" json:"channels"`
}

// SafeCommitConfig 定义远端高危配置变更自动回滚保险丝与 tailscaled OOM 免疫保护策略。
type SafeCommitConfig struct {
	DefaultTTLSec       int   `yaml:"default_ttl_sec,omitempty" json:"defaultTtlSec"`
	ProtectTailscaleOOM *bool `yaml:"protect_tailscale_oom,omitempty" json:"protectTailscaleOom,omitempty"`
}

// DefaultNotifyEvents 返回全部告警事件默认启用集。
func DefaultNotifyEvents() NotifyEventsConfig {
	return NotifyEventsConfig{
		WatchdogHeal:       true,
		SafeCommitRollback: true,
		ResourceGuard:      true,
		AuditHighRisk:      true,
		NewDevice:          true,
		SubOrNodeFail:      true,
		ServerQuotaOrBan:   true,
	}
}

func (e NotifyEventsConfig) anyEnabled() bool {
	return e.WatchdogHeal ||
		e.SafeCommitRollback ||
		e.ResourceGuard ||
		e.AuditHighRisk ||
		e.NewDevice ||
		e.SubOrNodeFail ||
		e.ServerQuotaOrBan
}

// IsZero 满足 yaml.IsZeroer 与 encoding/json omitzero，判断事件集合是否完全未显式配置。
func (e NotifyEventsConfig) IsZero() bool {
	return !e.explicit && !e.anyEnabled()
}

// EffectiveEvents 在全部未显式配置时返回默认启用集，否则返回当前显式事件配置。
func (e NotifyEventsConfig) EffectiveEvents() NotifyEventsConfig {
	if !e.explicit && !e.anyEnabled() {
		return DefaultNotifyEvents()
	}
	out := e
	out.explicit = false
	return out
}

type rawNotifyEventsPtr struct {
	WatchdogHeal       *bool `yaml:"watchdog_heal" json:"watchdogHeal"`
	SafeCommitRollback *bool `yaml:"safe_commit_rollback" json:"safeCommitRollback"`
	ResourceGuard      *bool `yaml:"resource_guard" json:"resourceGuard"`
	AuditHighRisk      *bool `yaml:"audit_high_risk" json:"auditHighRisk"`
	NewDevice          *bool `yaml:"new_device" json:"newDevice"`
	SubOrNodeFail      *bool `yaml:"sub_or_node_fail" json:"subOrNodeFail"`
	ServerQuotaOrBan   *bool `yaml:"server_quota_or_ban" json:"serverQuotaOrBan"`
}

func (e *NotifyEventsConfig) applyRawPtr(raw rawNotifyEventsPtr) {
	hasAny := raw.WatchdogHeal != nil ||
		raw.SafeCommitRollback != nil ||
		raw.ResourceGuard != nil ||
		raw.AuditHighRisk != nil ||
		raw.NewDevice != nil ||
		raw.SubOrNodeFail != nil ||
		raw.ServerQuotaOrBan != nil
	if !hasAny {
		*e = NotifyEventsConfig{}
		return
	}
	merged := DefaultNotifyEvents()
	if raw.WatchdogHeal != nil {
		merged.WatchdogHeal = *raw.WatchdogHeal
	}
	if raw.SafeCommitRollback != nil {
		merged.SafeCommitRollback = *raw.SafeCommitRollback
	}
	if raw.ResourceGuard != nil {
		merged.ResourceGuard = *raw.ResourceGuard
	}
	if raw.AuditHighRisk != nil {
		merged.AuditHighRisk = *raw.AuditHighRisk
	}
	if raw.NewDevice != nil {
		merged.NewDevice = *raw.NewDevice
	}
	if raw.SubOrNodeFail != nil {
		merged.SubOrNodeFail = *raw.SubOrNodeFail
	}
	if raw.ServerQuotaOrBan != nil {
		merged.ServerQuotaOrBan = *raw.ServerQuotaOrBan
	}
	merged.explicit = true
	*e = merged
}

// UnmarshalYAML 解析 notify.events，对未出现的字段回落默认值并标记显式配置状态。
func (e *NotifyEventsConfig) UnmarshalYAML(node *yaml.Node) error {
	var raw rawNotifyEventsPtr
	if err := node.Decode(&raw); err != nil {
		return err
	}
	e.applyRawPtr(raw)
	return nil
}

// UnmarshalJSON 解析前端 JSON 事件开关集合，对未传入的键回落默认值并标记显式配置状态。
func (e *NotifyEventsConfig) UnmarshalJSON(data []byte) error {
	var raw rawNotifyEventsPtr
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	e.applyRawPtr(raw)
	return nil
}

// HasSecret 判断 Telegram 渠道是否已配置 BotToken。
func (t TelegramNotifyConfig) HasSecret() bool {
	return strings.TrimSpace(t.BotToken) != ""
}

// HasSecret 判断 Bark 渠道是否已配置 DeviceKey。
func (b BarkNotifyConfig) HasSecret() bool {
	return strings.TrimSpace(b.DeviceKey) != ""
}

// EffectiveServerURL 返回归一化后的 Bark 服务地址（默认 https://api.day.app）。
func (b BarkNotifyConfig) EffectiveServerURL() string {
	trimmed := strings.TrimRight(strings.TrimSpace(b.ServerURL), "/")
	if trimmed == "" {
		return NotifyDefaultBarkServerURL
	}
	return trimmed
}

// HasSecret 判断飞书渠道是否已配置 WebhookURL 或签名 Secret。
func (f FeishuNotifyConfig) HasSecret() bool {
	return strings.TrimSpace(f.WebhookURL) != "" || strings.TrimSpace(f.Secret) != ""
}

// HasSecret 判断企业微信渠道是否已配置 WebhookURL。
func (w WeComNotifyConfig) HasSecret() bool {
	return strings.TrimSpace(w.WebhookURL) != ""
}

// HasSecret 判断通用 Webhook 渠道是否已配置认证 HeaderValue。
func (g GenericWebhookConfig) HasSecret() bool {
	return strings.TrimSpace(g.HeaderValue) != ""
}

// IsZero 判断所有推送渠道是否均处于默认零值状态。
func (c NotifyChannelsConfig) IsZero() bool {
	return !c.Telegram.Enabled &&
		strings.TrimSpace(c.Telegram.BotToken) == "" &&
		strings.TrimSpace(c.Telegram.ChatID) == "" &&
		strings.TrimSpace(c.Telegram.APIBaseURL) == "" &&
		!c.Bark.Enabled &&
		strings.TrimSpace(c.Bark.ServerURL) == "" &&
		strings.TrimSpace(c.Bark.DeviceKey) == "" &&
		strings.TrimSpace(c.Bark.Group) == "" &&
		!c.Feishu.Enabled &&
		strings.TrimSpace(c.Feishu.WebhookURL) == "" &&
		strings.TrimSpace(c.Feishu.Secret) == "" &&
		!c.WeCom.Enabled &&
		strings.TrimSpace(c.WeCom.WebhookURL) == "" &&
		!c.Webhook.Enabled &&
		strings.TrimSpace(c.Webhook.URL) == "" &&
		strings.TrimSpace(c.Webhook.HeaderName) == "" &&
		strings.TrimSpace(c.Webhook.HeaderValue) == ""
}

// EffectiveCooldownMinutes 返回归一化后的去重冷却分钟数（默认 15，范围 1..1440）。
func (n NotifyConfig) EffectiveCooldownMinutes() int {
	if n.CooldownMinutes <= 0 {
		return NotifyDefaultCooldownMinutes
	}
	return min(NotifyMaxCooldownMinutes, max(NotifyMinCooldownMinutes, n.CooldownMinutes))
}

// EffectiveDailyLimit 返回归一化后的每日最大推送上限（默认 50，范围 1..1000）。
func (n NotifyConfig) EffectiveDailyLimit() int {
	if n.DailyLimit <= 0 {
		return NotifyDefaultDailyLimit
	}
	return min(NotifyMaxDailyLimit, max(NotifyMinDailyLimit, n.DailyLimit))
}

// EffectiveQuietHours 返回去首尾空白后的静默时间段配置。
func (n NotifyConfig) EffectiveQuietHours() string {
	return strings.TrimSpace(n.QuietHours)
}

// EffectiveEvents 返回归一化后的告警事件开关集合。
func (n NotifyConfig) EffectiveEvents() NotifyEventsConfig {
	return n.Events.EffectiveEvents()
}

// IsEmpty 判断 NotifyConfig 是否完全为空（用于 AST 落盘清理避免污染干净配置）。
func (n NotifyConfig) IsEmpty() bool {
	return !n.Enabled &&
		n.CooldownMinutes == 0 &&
		n.DailyLimit == 0 &&
		strings.TrimSpace(n.QuietHours) == "" &&
		n.Events.IsZero() &&
		n.Channels.IsZero()
}

// IsZero 满足 yaml.IsZeroer 与 json omitzero。
func (n NotifyConfig) IsZero() bool {
	return n.IsEmpty()
}

// HasSecret 判断任意通知渠道是否配置了敏感凭据。
func (n NotifyConfig) HasSecret() bool {
	return n.Channels.Telegram.HasSecret() ||
		n.Channels.Bark.HasSecret() ||
		n.Channels.Feishu.HasSecret() ||
		n.Channels.WeCom.HasSecret() ||
		n.Channels.Webhook.HasSecret()
}

// SecretStatus 返回各渠道敏感凭据是否已配置的逐项布尔状态。
func (n NotifyConfig) SecretStatus() NotifySecretStatus {
	return NotifySecretStatus{
		TelegramBotToken:   strings.TrimSpace(n.Channels.Telegram.BotToken) != "",
		BarkDeviceKey:      strings.TrimSpace(n.Channels.Bark.DeviceKey) != "",
		FeishuWebhookURL:   strings.TrimSpace(n.Channels.Feishu.WebhookURL) != "",
		FeishuSecret:       strings.TrimSpace(n.Channels.Feishu.Secret) != "",
		WeComWebhookURL:    strings.TrimSpace(n.Channels.WeCom.WebhookURL) != "",
		WebhookHeaderValue: strings.TrimSpace(n.Channels.Webhook.HeaderValue) != "",
	}
}

// IsMaskedSecret 判断给定字符串是否为脱敏掩码值。
func IsMaskedSecret(v string) bool {
	s := strings.TrimSpace(v)
	return strings.Contains(s, notifyMaskMarker) || strings.Contains(strings.ToUpper(s), "%2A%2A%2A%2A")
}

func maskSecretValue(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return ""
	}
	if IsMaskedSecret(s) {
		return s
	}
	if len(s) < 12 {
		return NotifySecretMask
	}
	return s[:2] + notifyMaskMarker + s[len(s)-2:]
}

func maskWebhookURL(raw string, maskTailPath bool) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return ""
	}
	if IsMaskedSecret(s) {
		return s
	}
	u, err := url.Parse(s)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return maskSecretValue(s)
	}

	var b strings.Builder
	b.WriteString(u.Scheme)
	b.WriteString("://")
	if u.User != nil {
		b.WriteString(notifyMaskMarker)
		b.WriteByte('@')
	}
	b.WriteString(u.Host)

	maskedPath := u.EscapedPath()
	if u.RawQuery == "" && maskTailPath {
		trimmedEscaped := strings.TrimRight(maskedPath, "/")
		trimmedRaw := strings.TrimRight(u.Path, "/")
		escIdx := strings.LastIndex(trimmedEscaped, "/")
		rawIdx := strings.LastIndex(trimmedRaw, "/")
		if escIdx >= 0 && rawIdx >= 0 && rawIdx+1 < len(trimmedRaw) {
			maskedPath = trimmedEscaped[:escIdx+1] + maskSecretValue(trimmedRaw[rawIdx+1:])
		}
	}
	b.WriteString(maskedPath)

	if u.RawQuery != "" {
		q := u.Query()
		keys := make([]string, 0, len(q))
		for k := range q {
			keys = append(keys, k)
		}
		slices.Sort(keys)
		parts := make([]string, 0, len(keys))
		for _, k := range keys {
			for _, v := range q[k] {
				parts = append(parts, url.QueryEscape(k)+"="+maskSecretValue(v))
			}
		}
		b.WriteByte('?')
		b.WriteString(strings.Join(parts, "&"))
	}
	if u.Fragment != "" {
		b.WriteByte('#')
		b.WriteString(u.EscapedFragment())
	}
	return b.String()
}

// Redacted 返回脱敏拷贝，对各渠道明文密钥与 Webhook 凭据段进行掩码。
func (n NotifyConfig) Redacted() NotifyConfig {
	out := n.Clone()
	out.Channels.Telegram.BotToken = maskSecretValue(out.Channels.Telegram.BotToken)
	out.Channels.Bark.DeviceKey = maskSecretValue(out.Channels.Bark.DeviceKey)
	out.Channels.Feishu.WebhookURL = maskWebhookURL(out.Channels.Feishu.WebhookURL, true)
	out.Channels.Feishu.Secret = maskSecretValue(out.Channels.Feishu.Secret)
	out.Channels.WeCom.WebhookURL = maskWebhookURL(out.Channels.WeCom.WebhookURL, true)
	out.Channels.Webhook.URL = maskWebhookURL(out.Channels.Webhook.URL, false)
	out.Channels.Webhook.HeaderValue = maskSecretValue(out.Channels.Webhook.HeaderValue)
	return out
}

func preserveSecret(incoming, existing string) string {
	trimmed := strings.TrimSpace(incoming)
	if trimmed == "" || IsMaskedSecret(trimmed) {
		return strings.TrimSpace(existing)
	}
	return trimmed
}

// MergePreservingSecrets 将前端提交配置与原配置合并，当回传密钥为空或掩码值时自动保留原密钥。
func (n NotifyConfig) MergePreservingSecrets(existing NotifyConfig) NotifyConfig {
	out := n.Clone()
	out.QuietHours = strings.TrimSpace(out.QuietHours)

	out.Channels.Telegram.BotToken = preserveSecret(out.Channels.Telegram.BotToken, existing.Channels.Telegram.BotToken)
	out.Channels.Telegram.ChatID = strings.TrimSpace(out.Channels.Telegram.ChatID)
	out.Channels.Telegram.APIBaseURL = strings.TrimSpace(out.Channels.Telegram.APIBaseURL)

	out.Channels.Bark.ServerURL = strings.TrimSpace(out.Channels.Bark.ServerURL)
	out.Channels.Bark.DeviceKey = preserveSecret(out.Channels.Bark.DeviceKey, existing.Channels.Bark.DeviceKey)
	out.Channels.Bark.Group = strings.TrimSpace(out.Channels.Bark.Group)

	out.Channels.Feishu.WebhookURL = preserveSecret(out.Channels.Feishu.WebhookURL, existing.Channels.Feishu.WebhookURL)
	out.Channels.Feishu.Secret = preserveSecret(out.Channels.Feishu.Secret, existing.Channels.Feishu.Secret)

	out.Channels.WeCom.WebhookURL = preserveSecret(out.Channels.WeCom.WebhookURL, existing.Channels.WeCom.WebhookURL)

	out.Channels.Webhook.URL = preserveSecret(out.Channels.Webhook.URL, existing.Channels.Webhook.URL)
	out.Channels.Webhook.HeaderName = strings.TrimSpace(out.Channels.Webhook.HeaderName)
	out.Channels.Webhook.HeaderValue = preserveSecret(out.Channels.Webhook.HeaderValue, existing.Channels.Webhook.HeaderValue)
	return out
}

// Clone 返回 NotifyConfig 的深拷贝。
func (n NotifyConfig) Clone() NotifyConfig {
	return n
}

// UnmarshalYAML 宽容解析 notify 配置段（支持数字/字符串混写并自动清理空白）。
func (n *NotifyConfig) UnmarshalYAML(node *yaml.Node) error {
	var raw struct {
		Enabled         bool                 `yaml:"enabled"`
		CooldownMinutes any                  `yaml:"cooldown_minutes"`
		DailyLimit      any                  `yaml:"daily_limit"`
		QuietHours      string               `yaml:"quiet_hours"`
		Events          NotifyEventsConfig   `yaml:"events"`
		Channels        NotifyChannelsConfig `yaml:"channels"`
	}
	if err := node.Decode(&raw); err != nil {
		return err
	}
	n.Enabled = raw.Enabled
	n.QuietHours = strings.TrimSpace(raw.QuietHours)
	n.Events = raw.Events
	n.Channels = NotifyChannelsConfig{
		Telegram: TelegramNotifyConfig{
			Enabled:    raw.Channels.Telegram.Enabled,
			BotToken:   strings.TrimSpace(raw.Channels.Telegram.BotToken),
			ChatID:     strings.TrimSpace(raw.Channels.Telegram.ChatID),
			APIBaseURL: strings.TrimSpace(raw.Channels.Telegram.APIBaseURL),
		},
		Bark: BarkNotifyConfig{
			Enabled:   raw.Channels.Bark.Enabled,
			ServerURL: strings.TrimSpace(raw.Channels.Bark.ServerURL),
			DeviceKey: strings.TrimSpace(raw.Channels.Bark.DeviceKey),
			Group:     strings.TrimSpace(raw.Channels.Bark.Group),
		},
		Feishu: FeishuNotifyConfig{
			Enabled:    raw.Channels.Feishu.Enabled,
			WebhookURL: strings.TrimSpace(raw.Channels.Feishu.WebhookURL),
			Secret:     strings.TrimSpace(raw.Channels.Feishu.Secret),
		},
		WeCom: WeComNotifyConfig{
			Enabled:    raw.Channels.WeCom.Enabled,
			WebhookURL: strings.TrimSpace(raw.Channels.WeCom.WebhookURL),
		},
		Webhook: GenericWebhookConfig{
			Enabled:     raw.Channels.Webhook.Enabled,
			URL:         strings.TrimSpace(raw.Channels.Webhook.URL),
			HeaderName:  strings.TrimSpace(raw.Channels.Webhook.HeaderName),
			HeaderValue: strings.TrimSpace(raw.Channels.Webhook.HeaderValue),
		},
	}
	if raw.CooldownMinutes != nil {
		if v, err := parseIntAny(raw.CooldownMinutes); err == nil {
			n.CooldownMinutes = v
		}
	}
	if raw.DailyLimit != nil {
		if v, err := parseIntAny(raw.DailyLimit); err == nil {
			n.DailyLimit = v
		}
	}
	return nil
}

// EffectiveTTLSec 返回归一化后的安全回滚倒计时秒数（默认 180，范围 60..600）。
func (s SafeCommitConfig) EffectiveTTLSec() int {
	if s.DefaultTTLSec <= 0 {
		return constant.SafeCommitDefaultTTLSec
	}
	return min(constant.SafeCommitMaxTTLSec, max(constant.SafeCommitMinTTLSec, s.DefaultTTLSec))
}

// IsProtectTailscaleOOM 判断是否启用 tailscaled OOM 免疫保护（nil 或 true 默认启用）。
func (s SafeCommitConfig) IsProtectTailscaleOOM() bool {
	return s.ProtectTailscaleOOM == nil || *s.ProtectTailscaleOOM
}

// SetProtectTailscaleOOM 设置 tailscaled OOM 免疫开关（启用时置 nil 保持干净配置，关闭时显式写 false）。
func (s *SafeCommitConfig) SetProtectTailscaleOOM(enabled bool) {
	if enabled {
		s.ProtectTailscaleOOM = nil
		return
	}
	s.ProtectTailscaleOOM = new(false)
}

// IsEmpty 判断 SafeCommitConfig 是否为默认零值。
func (s SafeCommitConfig) IsEmpty() bool {
	return s.DefaultTTLSec == 0 && s.ProtectTailscaleOOM == nil
}

// IsZero 满足 yaml.IsZeroer 与 json omitzero。
func (s SafeCommitConfig) IsZero() bool {
	return s.IsEmpty()
}

// Clone 返回 SafeCommitConfig 的深拷贝（隔离指针字段）。
func (s SafeCommitConfig) Clone() SafeCommitConfig {
	return SafeCommitConfig{
		DefaultTTLSec:       s.DefaultTTLSec,
		ProtectTailscaleOOM: cloneBoolPtr(s.ProtectTailscaleOOM),
	}
}

// UnmarshalYAML 宽容解析 safe_commit 配置段（支持数字/字符串混写）。
func (s *SafeCommitConfig) UnmarshalYAML(node *yaml.Node) error {
	var raw struct {
		DefaultTTLSec       any   `yaml:"default_ttl_sec"`
		ProtectTailscaleOOM *bool `yaml:"protect_tailscale_oom"`
	}
	if err := node.Decode(&raw); err != nil {
		return err
	}
	s.ProtectTailscaleOOM = cloneBoolPtr(raw.ProtectTailscaleOOM)
	if raw.DefaultTTLSec != nil {
		if v, err := parseIntAny(raw.DefaultTTLSec); err == nil {
			s.DefaultTTLSec = v
		}
	}
	return nil
}

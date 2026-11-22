// 文件职责：实现通用结构化 JSON Webhook 推送渠道（支持自定义认证请求头及防注入校验）。
package notify

import (
	"cmp"
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"
)

type webhookChannel struct {
	cfg WebhookConfig
}

type webhookEventPayload struct {
	EventType EventType `json:"eventType"`
	Severity  Severity  `json:"severity"`
	DedupKey  string    `json:"dedupKey"`
	Hostname  string    `json:"hostname"`
	Title     string    `json:"title"`
	Body      string    `json:"body"`
	Resolved  bool      `json:"resolved"`
	Timestamp string    `json:"timestamp"`
}

// NewWebhookChannel 创建通用 Webhook 推送渠道实例。
func NewWebhookChannel(cfg WebhookConfig) Channel {
	return &webhookChannel{cfg: cfg}
}

func (c *webhookChannel) Name() string { return ChannelWebhook }

func (c *webhookChannel) Enabled() bool {
	if !c.cfg.Enabled {
		return false
	}
	_, _, _, err := validateWebhookConfig(c.cfg)
	return err == nil
}

func validateWebhookConfig(cfg WebhookConfig) (endpoint, headerName, headerValue string, err error) {
	if _, err := ValidateHTTPURL(cfg.URL); err != nil {
		return "", "", "", fmt.Errorf("invalid webhook url: %w", err)
	}
	endpoint = strings.TrimSpace(cfg.URL)
	if cfg.HeaderName != "" {
		if err := ValidateHeaderName(cfg.HeaderName); err != nil {
			return "", "", "", fmt.Errorf("invalid webhook header name: %w", err)
		}
		if err := ValidateHeaderValue(cfg.HeaderValue); err != nil {
			return "", "", "", fmt.Errorf("invalid webhook header value: %w", err)
		}
		headerName = cfg.HeaderName
		headerValue = cfg.HeaderValue
	}
	return endpoint, headerName, headerValue, nil
}

func (c *webhookChannel) Send(ctx context.Context, client *http.Client, ev Event) error {
	endpoint, headerName, headerValue, err := validateWebhookConfig(c.cfg)
	if err != nil {
		return err
	}
	var extraHeaders map[string]string
	if headerName != "" {
		extraHeaders = map[string]string{headerName: headerValue}
	}
	payload := webhookEventPayload{
		EventType: ev.Type,
		Severity:  cmp.Or(ev.Severity, SeverityInfo),
		DedupKey:  ev.DedupKey,
		Hostname:  ev.Hostname,
		Title:     ev.Title,
		Body:      ev.Body,
		Resolved:  ev.Resolved,
		Timestamp: eventTimestamp(ev).Format(time.RFC3339),
	}
	_, err = postJSON(ctx, client, endpoint, payload, extraHeaders)
	return err
}

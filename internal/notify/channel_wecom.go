// 文件职责：实现企业微信自定义机器人 Markdown Webhook 推送渠道。
package notify

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

const maxWeComMarkdownBytes = 4096

type wecomChannel struct {
	cfg WeComConfig
}

type wecomWebhookReq struct {
	MsgType  string            `json:"msgtype"`
	Markdown wecomMarkdownBody `json:"markdown"`
}

type wecomMarkdownBody struct {
	Content string `json:"content"`
}

// NewWeComChannel 创建企业微信推送渠道实例。
func NewWeComChannel(cfg WeComConfig) Channel {
	return &wecomChannel{cfg: cfg}
}

func (c *wecomChannel) Name() string { return ChannelWeCom }

func (c *wecomChannel) Enabled() bool {
	if !c.cfg.Enabled {
		return false
	}
	_, err := validateWeComConfig(c.cfg)
	return err == nil
}

func validateWeComConfig(cfg WeComConfig) (string, error) {
	if _, err := ValidateHTTPURL(cfg.WebhookURL); err != nil {
		return "", fmt.Errorf("invalid wecom webhook url: %w", err)
	}
	return strings.TrimSpace(cfg.WebhookURL), nil
}

func formatWeComMarkdown(ev Event) string {
	emoji, label := severityBadge(ev)
	color := "comment"
	switch {
	case ev.Resolved:
		color = "info"
	case ev.Severity == SeverityCritical || ev.Severity == SeverityWarn:
		color = "warning"
	}
	title := cmp.Or(strings.TrimSpace(ev.Title), string(ev.Type), "SingCtl 通知")

	var b strings.Builder
	fmt.Fprintf(&b, "### %s <font color=\"%s\">[%s]</font> %s", emoji, color, label, title)
	if host := strings.TrimSpace(ev.Hostname); host != "" {
		b.WriteString("\n> 主机：`")
		b.WriteString(host)
		b.WriteString("`")
	}
	if ev.Type != "" {
		b.WriteString("\n> 事件：`")
		b.WriteString(string(ev.Type))
		b.WriteString("`")
	}
	if body := strings.TrimSpace(ev.Body); body != "" {
		b.WriteString("\n> 详情：")
		b.WriteString(body)
	}
	b.WriteString("\n> 时间：")
	b.WriteString(eventTimestamp(ev).Format(time.RFC3339))
	return truncateBytesUTF8(b.String(), maxWeComMarkdownBytes)
}

func (c *wecomChannel) Send(ctx context.Context, client *http.Client, ev Event) error {
	endpoint, err := validateWeComConfig(c.cfg)
	if err != nil {
		return err
	}
	payload := wecomWebhookReq{
		MsgType: "markdown",
		Markdown: wecomMarkdownBody{
			Content: formatWeComMarkdown(ev),
		},
	}
	respBody, err := postJSON(ctx, client, endpoint, payload, nil)
	if err != nil {
		return err
	}
	var apiResp struct {
		ErrCode int    `json:"errcode"`
		ErrMsg  string `json:"errmsg"`
	}
	if len(respBody) > 0 && json.Unmarshal(respBody, &apiResp) == nil && apiResp.ErrCode != 0 {
		return fmt.Errorf("wecom api error %d: %s", apiResp.ErrCode, cmp.Or(apiResp.ErrMsg, "unknown error"))
	}
	return nil
}

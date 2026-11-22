// 文件职责：实现 Bark iOS 推送渠道（支持 timeSensitive 穿透专注模式与末尾斜杠兼容）。
package notify

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

const defaultBarkGroup = "SingCtl"

type barkChannel struct {
	cfg BarkConfig
}

type barkPushReq struct {
	DeviceKey string `json:"device_key"`
	Title     string `json:"title"`
	Body      string `json:"body"`
	Group     string `json:"group"`
	Level     string `json:"level"`
}

// NewBarkChannel 创建 Bark 推送渠道实例。
func NewBarkChannel(cfg BarkConfig) Channel {
	return &barkChannel{cfg: cfg}
}

func (c *barkChannel) Name() string { return ChannelBark }

func (c *barkChannel) Enabled() bool {
	if !c.cfg.Enabled {
		return false
	}
	_, _, _, err := validateBarkConfig(c.cfg)
	return err == nil
}

func validateBarkConfig(cfg BarkConfig) (endpoint, deviceKey, group string, err error) {
	deviceKey = strings.TrimSpace(cfg.DeviceKey)
	if deviceKey == "" {
		return "", "", "", errors.New("bark device key is empty")
	}
	if hasControlChars(deviceKey) {
		return "", "", "", errors.New("bark device key contains control characters")
	}
	base := cmp.Or(strings.TrimSpace(cfg.ServerURL), DefaultBarkServerURL)
	if _, err := ValidateHTTPURL(base); err != nil {
		return "", "", "", fmt.Errorf("invalid bark server url: %w", err)
	}
	endpoint = strings.TrimRight(base, "/") + "/push"
	group = cmp.Or(strings.TrimSpace(cfg.Group), defaultBarkGroup)
	return endpoint, deviceKey, group, nil
}

func (c *barkChannel) Send(ctx context.Context, client *http.Client, ev Event) error {
	endpoint, deviceKey, group, err := validateBarkConfig(c.cfg)
	if err != nil {
		return err
	}

	level := "active"
	if ev.Severity == SeverityCritical {
		level = "timeSensitive"
	}

	var bodyBuilder strings.Builder
	if host := strings.TrimSpace(ev.Hostname); host != "" {
		bodyBuilder.WriteString("[")
		bodyBuilder.WriteString(host)
		bodyBuilder.WriteString("] ")
	}
	bodyBuilder.WriteString(cmp.Or(strings.TrimSpace(ev.Body), strings.TrimSpace(ev.Title), string(ev.Type)))
	bodyBuilder.WriteString("\n")
	bodyBuilder.WriteString(eventTimestamp(ev).Format(time.RFC3339))

	payload := barkPushReq{
		DeviceKey: deviceKey,
		Title:     truncateRunes(formatPlainTitle(ev), 256),
		Body:      truncateRunes(bodyBuilder.String(), 2048),
		Group:     group,
		Level:     level,
	}
	respBody, err := postJSON(ctx, client, endpoint, payload, nil)
	if err != nil {
		return err
	}
	var apiResp struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	}
	if len(respBody) > 0 && json.Unmarshal(respBody, &apiResp) == nil && apiResp.Code != 0 && apiResp.Code != http.StatusOK {
		return fmt.Errorf("bark api error %d: %s", apiResp.Code, cmp.Or(apiResp.Message, "unknown error"))
	}
	return nil
}

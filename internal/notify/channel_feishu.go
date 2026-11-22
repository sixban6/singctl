// 文件职责：实现飞书自定义机器人 Webhook 推送渠道（支持官方 HMAC-SHA256 签名校验）。
package notify

import (
	"cmp"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

const maxFeishuTextRunes = 4096

type feishuChannel struct {
	cfg FeishuConfig
}

type feishuWebhookReq struct {
	Timestamp string            `json:"timestamp,omitempty"`
	Sign      string            `json:"sign,omitempty"`
	MsgType   string            `json:"msg_type"`
	Content   feishuTextContent `json:"content"`
}

type feishuTextContent struct {
	Text string `json:"text"`
}

// NewFeishuChannel 创建飞书推送渠道实例。
func NewFeishuChannel(cfg FeishuConfig) Channel {
	return &feishuChannel{cfg: cfg}
}

func (c *feishuChannel) Name() string { return ChannelFeishu }

func (c *feishuChannel) Enabled() bool {
	if !c.cfg.Enabled {
		return false
	}
	_, err := validateFeishuConfig(c.cfg)
	return err == nil
}

func validateFeishuConfig(cfg FeishuConfig) (string, error) {
	if _, err := ValidateHTTPURL(cfg.WebhookURL); err != nil {
		return "", fmt.Errorf("invalid feishu webhook url: %w", err)
	}
	return strings.TrimSpace(cfg.WebhookURL), nil
}

func computeFeishuSign(timestamp int64, secret string) (string, string) {
	ts := strconv.FormatInt(timestamp, 10)
	stringToSign := ts + "\n" + secret
	mac := hmac.New(sha256.New, []byte(stringToSign))
	return ts, base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

func (c *feishuChannel) Send(ctx context.Context, client *http.Client, ev Event) error {
	endpoint, err := validateFeishuConfig(c.cfg)
	if err != nil {
		return err
	}
	payload := feishuWebhookReq{
		MsgType: "text",
		Content: feishuTextContent{
			Text: truncateRunes(formatPlainMessage(ev), maxFeishuTextRunes),
		},
	}
	if secret := strings.TrimSpace(c.cfg.Secret); secret != "" {
		payload.Timestamp, payload.Sign = computeFeishuSign(eventTimestamp(ev).Unix(), secret)
	}

	respBody, err := postJSON(ctx, client, endpoint, payload, nil)
	if err != nil {
		return err
	}
	var apiResp struct {
		Code          int    `json:"code"`
		Msg           string `json:"msg"`
		StatusCode    int    `json:"StatusCode"`
		StatusMessage string `json:"StatusMessage"`
	}
	if len(respBody) > 0 && json.Unmarshal(respBody, &apiResp) == nil {
		if apiResp.Code != 0 {
			return fmt.Errorf("feishu api error %d: %s", apiResp.Code, cmp.Or(apiResp.Msg, "unknown error"))
		}
		if apiResp.StatusCode != 0 {
			return fmt.Errorf("feishu api error %d: %s", apiResp.StatusCode, cmp.Or(apiResp.StatusMessage, "unknown error"))
		}
	}
	return nil
}

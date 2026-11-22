// 文件职责：实现 Telegram Bot API 纯文本安全排版推送渠道。
package notify

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

const maxTelegramTextRunes = 4096

type telegramChannel struct {
	cfg TelegramConfig
}

type telegramSendMessageReq struct {
	ChatID                string `json:"chat_id"`
	Text                  string `json:"text"`
	DisableWebPagePreview bool   `json:"disable_web_page_preview"`
}

// NewTelegramChannel 创建 Telegram 推送渠道实例。
func NewTelegramChannel(cfg TelegramConfig) Channel {
	return &telegramChannel{cfg: cfg}
}

func (c *telegramChannel) Name() string { return ChannelTelegram }

func (c *telegramChannel) Enabled() bool {
	if !c.cfg.Enabled {
		return false
	}
	_, _, err := validateTelegramConfig(c.cfg)
	return err == nil
}

func validateTelegramConfig(cfg TelegramConfig) (endpoint string, chatID string, err error) {
	token := strings.TrimSpace(cfg.BotToken)
	if token == "" {
		return "", "", errors.New("telegram bot token is empty")
	}
	if hasControlChars(token) || strings.ContainsAny(token, " \t/?#@\\") {
		return "", "", errors.New("telegram bot token contains invalid characters")
	}
	chatID = strings.TrimSpace(cfg.ChatID)
	if chatID == "" {
		return "", "", errors.New("telegram chat id is empty")
	}
	if hasControlChars(chatID) {
		return "", "", errors.New("telegram chat id contains control characters")
	}
	base := cmp.Or(strings.TrimSpace(cfg.APIBaseURL), DefaultTelegramAPIBase)
	if _, err := ValidateHTTPURL(base); err != nil {
		return "", "", fmt.Errorf("invalid telegram api base url: %w", err)
	}
	endpoint = strings.TrimRight(base, "/") + "/bot" + token + "/sendMessage"
	return endpoint, chatID, nil
}

func (c *telegramChannel) Send(ctx context.Context, client *http.Client, ev Event) error {
	endpoint, chatID, err := validateTelegramConfig(c.cfg)
	if err != nil {
		return err
	}
	payload := telegramSendMessageReq{
		ChatID:                chatID,
		Text:                  truncateRunes(formatPlainMessage(ev), maxTelegramTextRunes),
		DisableWebPagePreview: true,
	}
	respBody, err := postJSON(ctx, client, endpoint, payload, nil)
	if err != nil {
		return err
	}
	var apiResp struct {
		OK          *bool  `json:"ok"`
		ErrorCode   int    `json:"error_code"`
		Description string `json:"description"`
	}
	if len(respBody) > 0 && json.Unmarshal(respBody, &apiResp) == nil && apiResp.OK != nil && !*apiResp.OK {
		return fmt.Errorf("telegram api error %d: %s", apiResp.ErrorCode, cmp.Or(apiResp.Description, "unknown error"))
	}
	return nil
}

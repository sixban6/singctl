// 文件职责：提供通知渠道共享的 HTTP URL/请求头防注入校验、脱敏错误包装、消息排版与 JSON POST 辅助。
package notify

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	maxResponseBodyBytes = 64 << 10
	maxErrorSnippetRunes = 200
	notifyUserAgent      = "singctl-notify/1.0"
)

func hasControlChars(s string) bool {
	for i := range len(s) {
		if s[i] < 0x20 || s[i] == 0x7f {
			return true
		}
	}
	return false
}

// ValidateHTTPURL 严格校验 URL 仅允许 http:// 或 https:// 且无控制字符与空主机名。
func ValidateHTTPURL(raw string) (*url.URL, error) {
	if hasControlChars(raw) {
		return nil, errors.New("url contains control characters")
	}
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil, errors.New("url is empty")
	}
	u, err := url.Parse(trimmed)
	if err != nil {
		return nil, fmt.Errorf("invalid url: %w", err)
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return nil, fmt.Errorf("unsupported url scheme %q (only http/https allowed)", u.Scheme)
	}
	if u.Host == "" || u.Hostname() == "" {
		return nil, errors.New("url missing host")
	}
	return u, nil
}

// ValidateHeaderName 严格校验 HTTP Header 名称符合 RFC 7230 token 规范。
func ValidateHeaderName(name string) error {
	if name == "" {
		return errors.New("header name is empty")
	}
	for i := range len(name) {
		b := name[i]
		isAlpha := (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
		isDigit := b >= '0' && b <= '9'
		isTokenPunct := strings.IndexByte("!#$%&'*+-.^_`|~", b) >= 0
		if !isAlpha && !isDigit && !isTokenPunct {
			return fmt.Errorf("header name contains invalid character %q", b)
		}
	}
	return nil
}

// ValidateHeaderValue 校验 HTTP Header 值不包含 CR/LF/NUL 等控制字符以防请求头注入。
func ValidateHeaderValue(val string) error {
	for i := range len(val) {
		b := val[i]
		if (b < 0x20 && b != '\t') || b == 0x7f {
			return errors.New("header value contains control characters")
		}
	}
	return nil
}

// redactURLError 剥离 *url.Error 中可能携带的 BotToken、Webhook 路径与查询密钥，同时保留底层错误链。
func redactURLError(err error) error {
	if err == nil {
		return nil
	}
	if ue, ok := errors.AsType[*url.Error](err); ok {
		safeURL := "***"
		if u, parseErr := url.Parse(ue.URL); parseErr == nil && u.Scheme != "" && u.Host != "" {
			safeURL = u.Scheme + "://" + u.Host + "/***"
		}
		return fmt.Errorf("%s %s: %w", ue.Op, safeURL, ue.Err)
	}
	return err
}

func resolveHTTPClient(client *http.Client) *http.Client {
	if client != nil {
		return client
	}
	return &http.Client{
		Timeout: DefaultSendTimeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return errors.New("stopped after 5 redirects")
			}
			if _, err := ValidateHTTPURL(req.URL.String()); err != nil {
				return err
			}
			return nil
		},
	}
}

func postJSON(ctx context.Context, client *http.Client, endpoint string, payload any, extraHeaders map[string]string) ([]byte, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if _, err := ValidateHTTPURL(endpoint); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(raw))
	if err != nil {
		return nil, redactURLError(err)
	}
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	req.Header.Set("User-Agent", notifyUserAgent)
	for k, v := range extraHeaders {
		req.Header.Set(k, v)
	}

	resp, err := resolveHTTPClient(client).Do(req)
	if err != nil {
		return nil, redactURLError(err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBodyBytes))
	if err != nil {
		return nil, redactURLError(err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		snippet := sanitizeSnippet(string(body), maxErrorSnippetRunes)
		if snippet == "" {
			return nil, fmt.Errorf("http status %d", resp.StatusCode)
		}
		return nil, fmt.Errorf("http status %d: %s", resp.StatusCode, snippet)
	}
	return body, nil
}

func sanitizeSnippet(s string, maxRunes int) string {
	cleaned := strings.TrimSpace(strings.NewReplacer("\r", " ", "\n", " ").Replace(s))
	return truncateRunes(cleaned, maxRunes)
}

func truncateRunes(s string, maxRunes int) string {
	if maxRunes <= 0 {
		return ""
	}
	runes := []rune(s)
	if len(runes) <= maxRunes {
		return s
	}
	if maxRunes <= 3 {
		return string(runes[:maxRunes])
	}
	return string(runes[:maxRunes-3]) + "..."
}

func truncateBytesUTF8(s string, maxBytes int) string {
	if maxBytes <= 0 || len(s) <= maxBytes {
		return s
	}
	const ellipsis = "..."
	if maxBytes <= len(ellipsis) {
		return s[:maxBytes]
	}
	limit := maxBytes - len(ellipsis)
	cut := 0
	for idx := range s {
		if idx > limit {
			break
		}
		cut = idx
	}
	return s[:cut] + ellipsis
}

func severityBadge(ev Event) (emoji string, label string) {
	if ev.Resolved {
		return "✅", "已恢复"
	}
	switch ev.Severity {
	case SeverityCritical:
		return "🔴", "严重"
	case SeverityWarn:
		return "🟡", "警告"
	default:
		return "ℹ️", "通知"
	}
}

func eventTimestamp(ev Event) time.Time {
	if !ev.Timestamp.IsZero() {
		return ev.Timestamp
	}
	return time.Now()
}

func formatPlainTitle(ev Event) string {
	emoji, label := severityBadge(ev)
	title := cmp.Or(strings.TrimSpace(ev.Title), string(ev.Type), "SingCtl 通知")
	return fmt.Sprintf("%s [%s] %s", emoji, label, title)
}

func formatPlainMessage(ev Event) string {
	var b strings.Builder
	b.WriteString(formatPlainTitle(ev))
	if host := strings.TrimSpace(ev.Hostname); host != "" {
		b.WriteString("\n主机: ")
		b.WriteString(host)
	}
	if ev.Type != "" {
		b.WriteString("\n事件: ")
		b.WriteString(string(ev.Type))
	}
	if body := strings.TrimSpace(ev.Body); body != "" {
		b.WriteString("\n详情: ")
		b.WriteString(body)
	}
	b.WriteString("\n时间: ")
	b.WriteString(eventTimestamp(ev).Format(time.RFC3339))
	return b.String()
}

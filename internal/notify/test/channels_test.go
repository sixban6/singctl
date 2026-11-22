// 文件职责：覆盖 URL/Header 防注入校验、5 大标准库推送渠道报文/签名/错误脱敏及 OCP 渠道注册表测试。
package notify_test

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"singctl/internal/notify"
)

func sampleEvent(sev notify.Severity, resolved bool) notify.Event {
	return notify.Event{
		Type:      notify.EventWatchdogHeal,
		Severity:  sev,
		DedupKey:  "sing-box",
		Hostname:  "gw.example.com",
		Title:     "sing-box 重启自愈 [special_*_`~chars]",
		Body:      "检测到进程异常，已自动拉起 _markdown_ *bold* `code` <tag>",
		Resolved:  resolved,
		Timestamp: time.Date(2026, 11, 23, 8, 30, 0, 0, time.UTC),
	}
}

func TestValidateHTTPURL(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		wantErr bool
	}{
		{name: "valid_https", raw: "https://hook.example.com/notify", wantErr: false},
		{name: "valid_http_loopback", raw: "http://127.0.0.1:8080/push", wantErr: false},
		{name: "valid_https_with_query", raw: "https://hook.example.com/send?key=demo-key", wantErr: false},
		{name: "empty", raw: "", wantErr: true},
		{name: "whitespace_only", raw: "   ", wantErr: true},
		{name: "file_scheme", raw: "file:///etc/passwd", wantErr: true},
		{name: "ftp_scheme", raw: "ftp://files.example.com/hook", wantErr: true},
		{name: "javascript_scheme", raw: "javascript:alert(1)", wantErr: true},
		{name: "gopher_scheme", raw: "gopher://127.0.0.1:6379/_INFO", wantErr: true},
		{name: "missing_scheme", raw: "hook.example.com/notify", wantErr: true},
		{name: "missing_host", raw: "https:///only-path", wantErr: true},
		{name: "crlf_injection", raw: "https://hook.example.com/a\r\nX-Evil: 1", wantErr: true},
		{name: "lf_control_char", raw: "https://hook.example.com/a\n", wantErr: true},
		{name: "nul_control_char", raw: "https://hook.example.com/a\x00b", wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			u, err := notify.ValidateHTTPURL(tc.raw)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("ValidateHTTPURL(%q) expected error, got %v", tc.raw, u)
				}
				return
			}
			if err != nil || u == nil {
				t.Fatalf("ValidateHTTPURL(%q) unexpected error: %v", tc.raw, err)
			}
		})
	}
}

func TestValidateHeaderNameAndValue(t *testing.T) {
	nameCases := []struct {
		name    string
		val     string
		wantErr bool
	}{
		{name: "valid_authorization", val: "Authorization", wantErr: false},
		{name: "valid_custom_token", val: "X-SingCtl-Token_1", wantErr: false},
		{name: "empty", val: "", wantErr: true},
		{name: "with_space", val: "X-Bad Header", wantErr: true},
		{name: "with_colon", val: "X-Bad:Header", wantErr: true},
		{name: "with_crlf", val: "X-Bad\r\nInjected", wantErr: true},
		{name: "non_ascii", val: "X-中文", wantErr: true},
	}
	for _, tc := range nameCases {
		t.Run("name_"+tc.name, func(t *testing.T) {
			err := notify.ValidateHeaderName(tc.val)
			if (err != nil) != tc.wantErr {
				t.Fatalf("ValidateHeaderName(%q) err=%v, wantErr=%v", tc.val, err, tc.wantErr)
			}
		})
	}

	valCases := []struct {
		name    string
		val     string
		wantErr bool
	}{
		{name: "valid_bearer", val: "Bearer test-token-value", wantErr: false},
		{name: "valid_empty", val: "", wantErr: false},
		{name: "crlf_injection", val: "ok\r\nX-Evil: 1", wantErr: true},
		{name: "lf_injection", val: "ok\nevil", wantErr: true},
		{name: "nul_injection", val: "ok\x00evil", wantErr: true},
	}
	for _, tc := range valCases {
		t.Run("value_"+tc.name, func(t *testing.T) {
			err := notify.ValidateHeaderValue(tc.val)
			if (err != nil) != tc.wantErr {
				t.Fatalf("ValidateHeaderValue(%q) err=%v, wantErr=%v", tc.val, err, tc.wantErr)
			}
		})
	}
}

func TestTelegramChannel(t *testing.T) {
	var gotPath string
	var gotMethod string
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotMethod = r.Method
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &gotBody)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true,"result":{"message_id":42}}`))
	}))
	defer srv.Close()

	ch := notify.NewTelegramChannel(notify.TelegramConfig{
		Enabled:    true,
		BotToken:   "123456:fake-bot-token",
		ChatID:     "-1001234567890",
		APIBaseURL: srv.URL + "/",
	})
	if ch.Name() != notify.ChannelTelegram {
		t.Fatalf("Name() = %q, want %q", ch.Name(), notify.ChannelTelegram)
	}
	if !ch.Enabled() {
		t.Fatal("expected telegram channel enabled")
	}

	ev := sampleEvent(notify.SeverityCritical, false)
	if err := ch.Send(t.Context(), srv.Client(), ev); err != nil {
		t.Fatalf("Send failed: %v", err)
	}
	if gotMethod != http.MethodPost {
		t.Fatalf("method = %q, want POST", gotMethod)
	}
	if gotPath != "/bot123456:fake-bot-token/sendMessage" {
		t.Fatalf("path = %q, want /bot123456:fake-bot-token/sendMessage", gotPath)
	}
	if gotBody["chat_id"] != "-1001234567890" {
		t.Fatalf("chat_id = %v, want -1001234567890", gotBody["chat_id"])
	}
	if _, hasParseMode := gotBody["parse_mode"]; hasParseMode {
		t.Fatalf("telegram plain text must not set parse_mode, got %v", gotBody["parse_mode"])
	}
	text, _ := gotBody["text"].(string)
	if !strings.Contains(text, ev.Title) || !strings.Contains(text, ev.Hostname) {
		t.Fatalf("telegram text missing title or hostname: %q", text)
	}

	t.Run("api_error_response", func(t *testing.T) {
		errSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"ok":false,"error_code":400,"description":"chat not found"}`))
		}))
		defer errSrv.Close()
		badCh := notify.NewTelegramChannel(notify.TelegramConfig{
			Enabled:    true,
			BotToken:   "secret-tg-token-999",
			ChatID:     "12345",
			APIBaseURL: errSrv.URL,
		})
		err := badCh.Send(t.Context(), errSrv.Client(), ev)
		if err == nil || !strings.Contains(err.Error(), "chat not found") {
			t.Fatalf("expected telegram api error, got %v", err)
		}
		if strings.Contains(err.Error(), "secret-tg-token-999") {
			t.Fatalf("error leaked bot token: %v", err)
		}
	})

	t.Run("network_error_redacts_token", func(t *testing.T) {
		closedSrv := httptest.NewServer(http.NotFoundHandler())
		closedURL := closedSrv.URL
		closedSrv.Close()
		secretToken := "999999:SUPER_SECRET_BOT_TOKEN_XYZ"
		badCh := notify.NewTelegramChannel(notify.TelegramConfig{
			Enabled:    true,
			BotToken:   secretToken,
			ChatID:     "12345",
			APIBaseURL: closedURL,
		})
		err := badCh.Send(t.Context(), &http.Client{Timeout: time.Second}, ev)
		if err == nil {
			t.Fatal("expected network error against closed server")
		}
		if strings.Contains(err.Error(), secretToken) {
			t.Fatalf("network error leaked bot token: %v", err)
		}
	})

	t.Run("token_path_injection_rejected", func(t *testing.T) {
		injCh := notify.NewTelegramChannel(notify.TelegramConfig{
			Enabled:    true,
			BotToken:   "123/../../evil?x=1",
			ChatID:     "12345",
			APIBaseURL: srv.URL,
		})
		if injCh.Enabled() {
			t.Fatal("expected injected bot token channel to be disabled")
		}
		if err := injCh.Send(t.Context(), srv.Client(), ev); err == nil {
			t.Fatal("expected injected bot token Send to return error")
		}
	})
}

func TestBarkChannel(t *testing.T) {
	var paths []string
	var payloads []map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		var m map[string]any
		_ = json.NewDecoder(r.Body).Decode(&m)
		payloads = append(payloads, m)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"code":200,"message":"success"}`))
	}))
	defer srv.Close()

	// Test trailing slash compatibility + SeverityCritical -> timeSensitive
	chSlash := notify.NewBarkChannel(notify.BarkConfig{
		Enabled:   true,
		ServerURL: srv.URL + "///",
		DeviceKey: "bark-demo-key",
		Group:     "RouterAlerts",
	})
	if chSlash.Name() != notify.ChannelBark || !chSlash.Enabled() {
		t.Fatalf("unexpected bark metadata: name=%q enabled=%v", chSlash.Name(), chSlash.Enabled())
	}
	if err := chSlash.Send(t.Context(), srv.Client(), sampleEvent(notify.SeverityCritical, false)); err != nil {
		t.Fatalf("bark critical send failed: %v", err)
	}

	// Test no trailing slash + SeverityInfo -> non-timeSensitive + default group
	chNoSlash := notify.NewBarkChannel(notify.BarkConfig{
		Enabled:   true,
		ServerURL: srv.URL,
		DeviceKey: "bark-demo-key-2",
	})
	if err := chNoSlash.Send(t.Context(), srv.Client(), sampleEvent(notify.SeverityInfo, true)); err != nil {
		t.Fatalf("bark info send failed: %v", err)
	}

	if !slices.Equal(paths, []string{"/push", "/push"}) {
		t.Fatalf("paths = %v, want [/push /push]", paths)
	}
	if payloads[0]["device_key"] != "bark-demo-key" || payloads[0]["group"] != "RouterAlerts" || payloads[0]["level"] != "timeSensitive" {
		t.Fatalf("unexpected critical bark payload: %+v", payloads[0])
	}
	if payloads[1]["device_key"] != "bark-demo-key-2" || payloads[1]["group"] == "" || payloads[1]["level"] == "timeSensitive" {
		t.Fatalf("unexpected info bark payload: %+v", payloads[1])
	}

	t.Run("api_non_200_code", func(t *testing.T) {
		errSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`{"code":400,"message":"invalid device key"}`))
		}))
		defer errSrv.Close()
		ch := notify.NewBarkChannel(notify.BarkConfig{Enabled: true, ServerURL: errSrv.URL, DeviceKey: "bad-key"})
		if err := ch.Send(t.Context(), errSrv.Client(), sampleEvent(notify.SeverityWarn, false)); err == nil {
			t.Fatal("expected error for bark code=400")
		}
	})
}

func TestFeishuChannel(t *testing.T) {
	var gotBodies []map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var m map[string]any
		_ = json.NewDecoder(r.Body).Decode(&m)
		gotBodies = append(gotBodies, m)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"code":0,"msg":"success"}`))
	}))
	defer srv.Close()

	secret := "feishu-test-signing-secret"
	ev := sampleEvent(notify.SeverityWarn, false)

	// 1. With Secret: verify official HMAC-SHA256(key = timestamp+"\n"+secret, msg = "") Base64 signature
	chSigned := notify.NewFeishuChannel(notify.FeishuConfig{
		Enabled:    true,
		WebhookURL: srv.URL + "/open-apis/bot/v2/hook/demo",
		Secret:     secret,
	})
	if chSigned.Name() != notify.ChannelFeishu || !chSigned.Enabled() {
		t.Fatalf("unexpected feishu metadata: name=%q enabled=%v", chSigned.Name(), chSigned.Enabled())
	}
	if err := chSigned.Send(t.Context(), srv.Client(), ev); err != nil {
		t.Fatalf("feishu signed send failed: %v", err)
	}

	// 2. Without Secret: must not include sign/timestamp
	chPlain := notify.NewFeishuChannel(notify.FeishuConfig{
		Enabled:    true,
		WebhookURL: srv.URL + "/open-apis/bot/v2/hook/demo",
	})
	if err := chPlain.Send(t.Context(), srv.Client(), ev); err != nil {
		t.Fatalf("feishu unsigned send failed: %v", err)
	}

	if len(gotBodies) != 2 {
		t.Fatalf("expected 2 requests, got %d", len(gotBodies))
	}
	signed := gotBodies[0]
	if signed["msg_type"] != "text" {
		t.Fatalf("feishu msg_type = %v, want text", signed["msg_type"])
	}
	tsStr, _ := signed["timestamp"].(string)
	signStr, _ := signed["sign"].(string)
	if tsStr == "" || signStr == "" {
		t.Fatalf("feishu signed request missing timestamp/sign: %+v", signed)
	}
	mac := hmac.New(sha256.New, []byte(tsStr+"\n"+secret))
	wantSign := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	if signStr != wantSign {
		t.Fatalf("feishu sign mismatch: got %q, want %q (ts=%s)", signStr, wantSign, tsStr)
	}

	unsigned := gotBodies[1]
	if _, hasSign := unsigned["sign"]; hasSign {
		t.Fatalf("unsigned feishu request should not include sign: %+v", unsigned)
	}

	t.Run("api_error_code", func(t *testing.T) {
		errSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`{"code":19021,"msg":"sign match fail"}`))
		}))
		defer errSrv.Close()
		ch := notify.NewFeishuChannel(notify.FeishuConfig{Enabled: true, WebhookURL: errSrv.URL, Secret: "wrong"})
		if err := ch.Send(t.Context(), errSrv.Client(), ev); err == nil || !strings.Contains(err.Error(), "19021") {
			t.Fatalf("expected feishu error code 19021, got %v", err)
		}
	})

	t.Run("legacy_status_code_error", func(t *testing.T) {
		errSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`{"StatusCode":19024,"StatusMessage":"key words not in content"}`))
		}))
		defer errSrv.Close()
		ch := notify.NewFeishuChannel(notify.FeishuConfig{Enabled: true, WebhookURL: errSrv.URL})
		if err := ch.Send(t.Context(), errSrv.Client(), ev); err == nil || !strings.Contains(err.Error(), "19024") {
			t.Fatalf("expected feishu StatusCode 19024 error, got %v", err)
		}
	})
}

func TestWeComChannel(t *testing.T) {
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"errcode":0,"errmsg":"ok"}`))
	}))
	defer srv.Close()

	ev := sampleEvent(notify.SeverityCritical, false)
	ch := notify.NewWeComChannel(notify.WeComConfig{
		Enabled:    true,
		WebhookURL: srv.URL + "/cgi-bin/webhook/send?key=demo-wecom-key",
	})
	if ch.Name() != notify.ChannelWeCom || !ch.Enabled() {
		t.Fatalf("unexpected wecom metadata: name=%q enabled=%v", ch.Name(), ch.Enabled())
	}
	if err := ch.Send(t.Context(), srv.Client(), ev); err != nil {
		t.Fatalf("wecom send failed: %v", err)
	}
	if gotBody["msgtype"] != "markdown" {
		t.Fatalf("wecom msgtype = %v, want markdown", gotBody["msgtype"])
	}
	md, _ := gotBody["markdown"].(map[string]any)
	content, _ := md["content"].(string)
	if !strings.Contains(content, ev.Title) || !strings.Contains(content, ev.Hostname) {
		t.Fatalf("wecom markdown missing title/hostname: %q", content)
	}

	t.Run("oversized_utf8_markdown_truncated_safely", func(t *testing.T) {
		var gotMD string
		longSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var m map[string]any
			_ = json.NewDecoder(r.Body).Decode(&m)
			if md, ok := m["markdown"].(map[string]any); ok {
				gotMD, _ = md["content"].(string)
			}
			_, _ = w.Write([]byte(`{"errcode":0,"errmsg":"ok"}`))
		}))
		defer longSrv.Close()

		longEv := sampleEvent(notify.SeverityInfo, true)
		longEv.Body = strings.Repeat("中文告警详情", 1200)
		longCh := notify.NewWeComChannel(notify.WeComConfig{Enabled: true, WebhookURL: longSrv.URL})
		if err := longCh.Send(t.Context(), nil, longEv); err != nil {
			t.Fatalf("wecom oversized utf8 send failed: %v", err)
		}
		if len(gotMD) > 4096 || !strings.HasSuffix(gotMD, "...") {
			t.Fatalf("expected truncated <=4096 bytes with ellipsis, got len=%d", len(gotMD))
		}
	})

	t.Run("api_errcode_nonzero", func(t *testing.T) {
		errSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`{"errcode":93000,"errmsg":"invalid webhook url"}`))
		}))
		defer errSrv.Close()
		badCh := notify.NewWeComChannel(notify.WeComConfig{Enabled: true, WebhookURL: errSrv.URL})
		if err := badCh.Send(t.Context(), errSrv.Client(), ev); err == nil || !strings.Contains(err.Error(), "93000") {
			t.Fatalf("expected wecom errcode 93000, got %v", err)
		}
	})
}

func TestWebhookChannel(t *testing.T) {
	var gotHeader string
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeader = r.Header.Get("X-SingCtl-Auth")
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	ev := sampleEvent(notify.SeverityWarn, true)
	ch := notify.NewWebhookChannel(notify.WebhookConfig{
		Enabled:     true,
		URL:         srv.URL + "/alerts",
		HeaderName:  "X-SingCtl-Auth",
		HeaderValue: "Bearer test-webhook-secret",
	})
	if ch.Name() != notify.ChannelWebhook || !ch.Enabled() {
		t.Fatalf("unexpected webhook metadata: name=%q enabled=%v", ch.Name(), ch.Enabled())
	}
	if err := ch.Send(t.Context(), srv.Client(), ev); err != nil {
		t.Fatalf("webhook send failed: %v", err)
	}
	if gotHeader != "Bearer test-webhook-secret" {
		t.Fatalf("custom header = %q, want Bearer test-webhook-secret", gotHeader)
	}

	requiredKeys := []string{"eventType", "severity", "dedupKey", "hostname", "title", "body", "resolved", "timestamp"}
	for _, k := range requiredKeys {
		if _, ok := gotBody[k]; !ok {
			t.Fatalf("webhook JSON payload missing required key %q: %+v", k, gotBody)
		}
	}
	if gotBody["eventType"] != string(ev.Type) || gotBody["severity"] != string(ev.Severity) || gotBody["resolved"] != true {
		t.Fatalf("unexpected webhook field values: %+v", gotBody)
	}

	t.Run("invalid_header_name_rejected", func(t *testing.T) {
		badCh := notify.NewWebhookChannel(notify.WebhookConfig{
			Enabled:     true,
			URL:         srv.URL + "/alerts",
			HeaderName:  "X-Bad\r\nHeader",
			HeaderValue: "ok",
		})
		if badCh.Enabled() {
			t.Fatal("expected webhook with invalid header name to be disabled")
		}
		if err := badCh.Send(t.Context(), srv.Client(), ev); err == nil {
			t.Fatal("expected error for invalid header name")
		}
	})

	t.Run("invalid_header_value_rejected", func(t *testing.T) {
		badCh := notify.NewWebhookChannel(notify.WebhookConfig{
			Enabled:     true,
			URL:         srv.URL + "/alerts",
			HeaderName:  "X-Valid",
			HeaderValue: "val\r\nX-Evil: 1",
		})
		if badCh.Enabled() {
			t.Fatal("expected webhook with CRLF header value to be disabled")
		}
		if err := badCh.Send(t.Context(), srv.Client(), ev); err == nil {
			t.Fatal("expected error for CRLF header value")
		}
	})

	t.Run("non_2xx_http_status", func(t *testing.T) {
		errSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "upstream failed", http.StatusBadGateway)
		}))
		defer errSrv.Close()
		badCh := notify.NewWebhookChannel(notify.WebhookConfig{Enabled: true, URL: errSrv.URL})
		err := badCh.Send(t.Context(), errSrv.Client(), ev)
		if err == nil || !strings.Contains(err.Error(), "502") {
			t.Fatalf("expected 502 error, got %v", err)
		}
	})

	t.Run("context_deadline_exceeded_preserved", func(t *testing.T) {
		stopSrv := make(chan struct{})
		slowSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			select {
			case <-r.Context().Done():
			case <-stopSrv:
			}
		}))
		defer slowSrv.Close()
		defer close(stopSrv)

		ctx, cancel := context.WithTimeout(t.Context(), 40*time.Millisecond)
		defer cancel()
		slowCh := notify.NewWebhookChannel(notify.WebhookConfig{Enabled: true, URL: slowSrv.URL})
		err := slowCh.Send(ctx, slowSrv.Client(), ev)
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("expected DeadlineExceeded, got %v", err)
		}
	})
}

func TestRegistryBuildChannelsAndSecurityFiltering(t *testing.T) {
	wantKnown := []string{
		notify.ChannelTelegram,
		notify.ChannelBark,
		notify.ChannelFeishu,
		notify.ChannelWeCom,
		notify.ChannelWebhook,
	}
	if got := notify.KnownChannelNames(); !slices.Equal(got, wantKnown) {
		t.Fatalf("KnownChannelNames() = %v, want %v", got, wantKnown)
	}

	opts := notify.Options{
		Telegram: notify.TelegramConfig{Enabled: true, BotToken: "123:demo", ChatID: "100", APIBaseURL: "https://tg.example.com"},
		Bark:     notify.BarkConfig{Enabled: true, DeviceKey: "demo-bark-key"}, // uses default https://api.day.app
		Feishu:   notify.FeishuConfig{Enabled: true, WebhookURL: "file:///etc/passwd"},
		WeCom:    notify.WeComConfig{Enabled: true, WebhookURL: "https://qy.example.com/hook\r\nX-Inject: 1"},
		Webhook:  notify.WebhookConfig{Enabled: true, URL: "http://192.0.2.10:8080/hook"},
	}

	channels := notify.BuildChannels(opts)
	var names []string
	for _, ch := range channels {
		names = append(names, ch.Name())
	}
	wantActive := []string{notify.ChannelTelegram, notify.ChannelBark, notify.ChannelWebhook}
	if !slices.Equal(names, wantActive) {
		t.Fatalf("BuildChannels active = %v, want %v (invalid scheme/CRLF channels must be excluded)", names, wantActive)
	}

	// Verify Options.Clone deep-copies EnabledEvents map
	orig := notify.Options{
		Enabled:       true,
		EnabledEvents: map[notify.EventType]bool{notify.EventWatchdogHeal: true},
	}
	cloned := orig.Clone()
	cloned.EnabledEvents[notify.EventWatchdogHeal] = false
	if !orig.EnabledEvents[notify.EventWatchdogHeal] {
		t.Fatal("Options.Clone did not deep-copy EnabledEvents map")
	}
}

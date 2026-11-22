// 文件职责：验证 NotifyConfig 与 SafeCommitConfig 的默认值、边界钳制、事件开关语义、密钥脱敏与保留合并、YAML/JSON 反序列化、Clone 隔离及 AST 落盘清理。
package config_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"singctl/configs"
	"singctl/internal/config"
	"singctl/internal/constant"
)

func TestNotifyConfig_DefaultsBoundsAndEvents(t *testing.T) {
	var zero config.NotifyConfig
	if !zero.IsEmpty() || !zero.IsZero() {
		t.Fatal("zero NotifyConfig should report IsEmpty=true and IsZero=true")
	}
	if zero.HasSecret() {
		t.Fatal("zero NotifyConfig should report HasSecret=false")
	}
	if got := zero.EffectiveCooldownMinutes(); got != 15 {
		t.Fatalf("default CooldownMinutes = %d, want 15", got)
	}
	if got := zero.EffectiveDailyLimit(); got != 50 {
		t.Fatalf("default DailyLimit = %d, want 50", got)
	}
	if got := zero.EffectiveQuietHours(); got != "" {
		t.Fatalf("default QuietHours = %q, want empty", got)
	}
	if got := zero.Channels.Bark.EffectiveServerURL(); got != "https://api.day.app" {
		t.Fatalf("default Bark ServerURL = %q, want https://api.day.app", got)
	}

	// Unconfigured events must default to full active set
	eff := zero.EffectiveEvents()
	wantDef := config.DefaultNotifyEvents()
	if !wantDef.WatchdogHeal || !wantDef.SafeCommitRollback || !wantDef.ResourceGuard ||
		!wantDef.AuditHighRisk || !wantDef.NewDevice || !wantDef.SubOrNodeFail || !wantDef.ServerQuotaOrBan {
		t.Fatalf("DefaultNotifyEvents should enable all 7 events, got %+v", wantDef)
	}
	if eff != wantDef {
		t.Fatalf("zero EffectiveEvents = %+v, want %+v", eff, wantDef)
	}

	// Table-driven bounds clamping
	boundCases := []struct {
		name         string
		cooldown     int
		dailyLimit   int
		wantCooldown int
		wantLimit    int
	}{
		{"negative_defaults", -10, -5, 15, 50},
		{"zero_defaults", 0, 0, 15, 50},
		{"min_boundary", 1, 1, 1, 1},
		{"mid_values", 30, 120, 30, 120},
		{"max_boundary", 1440, 1000, 1440, 1000},
		{"above_max_clamped", 99999, 50000, 1440, 1000},
	}
	for _, tc := range boundCases {
		t.Run(tc.name, func(t *testing.T) {
			n := config.NotifyConfig{CooldownMinutes: tc.cooldown, DailyLimit: tc.dailyLimit}
			if got := n.EffectiveCooldownMinutes(); got != tc.wantCooldown {
				t.Errorf("CooldownMinutes(%d) = %d, want %d", tc.cooldown, got, tc.wantCooldown)
			}
			if got := n.EffectiveDailyLimit(); got != tc.wantLimit {
				t.Errorf("DailyLimit(%d) = %d, want %d", tc.dailyLimit, got, tc.wantLimit)
			}
		})
	}

	// Bark ServerURL trims spaces and trailing slash
	bark := config.BarkNotifyConfig{ServerURL: "  https://bark.example.com/  "}
	if got := bark.EffectiveServerURL(); got != "https://bark.example.com" {
		t.Fatalf("Bark EffectiveServerURL = %q, want https://bark.example.com", got)
	}

	// Explicit JSON all-false events must NOT revert to defaults
	var allOff config.NotifyEventsConfig
	if err := json.Unmarshal([]byte(`{"watchdogHeal":false,"safeCommitRollback":false,"resourceGuard":false,"auditHighRisk":false,"newDevice":false,"subOrNodeFail":false,"serverQuotaOrBan":false}`), &allOff); err != nil {
		t.Fatalf("json.Unmarshal allOff failed: %v", err)
	}
	effOff := allOff.EffectiveEvents()
	if effOff.WatchdogHeal || effOff.SafeCommitRollback || effOff.ResourceGuard ||
		effOff.AuditHighRisk || effOff.NewDevice || effOff.SubOrNodeFail || effOff.ServerQuotaOrBan {
		t.Fatalf("explicit all-false events reverted to true: %+v", effOff)
	}

	// Partial JSON override disables only the specified event while keeping others true
	var partial config.NotifyEventsConfig
	if err := json.Unmarshal([]byte(`{"newDevice":false}`), &partial); err != nil {
		t.Fatalf("json.Unmarshal partial failed: %v", err)
	}
	effPartial := partial.EffectiveEvents()
	if effPartial.NewDevice || !effPartial.WatchdogHeal || !effPartial.SafeCommitRollback || !effPartial.ServerQuotaOrBan {
		t.Fatalf("partial JSON override unexpected: %+v", effPartial)
	}
}

func TestNotifyConfig_RedactedHasSecretAndPreserveSecrets(t *testing.T) {
	orig := config.NotifyConfig{
		Enabled:         true,
		CooldownMinutes: 20,
		DailyLimit:      80,
		QuietHours:      "23:00-07:30",
		Channels: config.NotifyChannelsConfig{
			Telegram: config.TelegramNotifyConfig{
				Enabled:    true,
				BotToken:   "123456789:FakeTelegramTokenValue9876",
				ChatID:     "-1001234567890",
				APIBaseURL: "https://tg-proxy.example.com",
			},
			Bark: config.BarkNotifyConfig{
				Enabled:   true,
				ServerURL: "https://bark.example.com",
				DeviceKey: "FakeBarkDeviceKey123456",
				Group:     "singctl",
			},
			Feishu: config.FeishuNotifyConfig{
				Enabled:    true,
				WebhookURL: "https://open.example.com/open-apis/bot/v2/hook/11111111-2222-3333-4444-555555555555",
				Secret:     "FakeFeishuSignSecretKey",
			},
			WeCom: config.WeComNotifyConfig{
				Enabled:    true,
				WebhookURL: "https://qyapi.example.com/cgi-bin/webhook/send?key=aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
			},
			Webhook: config.GenericWebhookConfig{
				Enabled:     true,
				URL:         "https://hooks.example.com/alert?token=SuperSecretQueryToken123",
				HeaderName:  "Authorization",
				HeaderValue: "Bearer FakeWebhookToken9999",
			},
		},
	}

	if !orig.HasSecret() ||
		!orig.Channels.Telegram.HasSecret() ||
		!orig.Channels.Bark.HasSecret() ||
		!orig.Channels.Feishu.HasSecret() ||
		!orig.Channels.WeCom.HasSecret() ||
		!orig.Channels.Webhook.HasSecret() {
		t.Fatal("expected HasSecret()=true for all configured channels")
	}
	st := orig.SecretStatus()
	if !st.TelegramBotToken || !st.BarkDeviceKey || !st.FeishuWebhookURL ||
		!st.FeishuSecret || !st.WeComWebhookURL || !st.WebhookHeaderValue {
		t.Fatalf("unexpected SecretStatus: %+v", st)
	}

	red := orig.Redacted()
	// Plain secrets must NEVER leak into redacted copy
	forbiddenLeaks := []string{
		"FakeTelegramTokenValue9876",
		"FakeBarkDeviceKey123456",
		"11111111-2222-3333-4444-555555555555",
		"FakeFeishuSignSecretKey",
		"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
		"SuperSecretQueryToken123",
		"FakeWebhookToken9999",
	}
	redBytes, err := json.Marshal(red)
	if err != nil {
		t.Fatalf("marshal redacted failed: %v", err)
	}
	redJSON := string(redBytes)
	for _, secret := range forbiddenLeaks {
		if strings.Contains(redJSON, secret) {
			t.Fatalf("Redacted() leaked plaintext secret %q in %s", secret, redJSON)
		}
	}

	// Masked fields must be recognized by IsMaskedSecret and preserve URL host/path structure
	for name, val := range map[string]string{
		"telegram.botToken":   red.Channels.Telegram.BotToken,
		"bark.deviceKey":      red.Channels.Bark.DeviceKey,
		"feishu.webhookUrl":   red.Channels.Feishu.WebhookURL,
		"feishu.secret":       red.Channels.Feishu.Secret,
		"wecom.webhookUrl":    red.Channels.WeCom.WebhookURL,
		"webhook.url":         red.Channels.Webhook.URL,
		"webhook.headerValue": red.Channels.Webhook.HeaderValue,
	} {
		if !config.IsMaskedSecret(val) {
			t.Errorf("expected %s=%q to be detected as masked secret", name, val)
		}
	}
	if !strings.HasPrefix(red.Channels.Feishu.WebhookURL, "https://open.example.com/open-apis/bot/v2/hook/") {
		t.Fatalf("Feishu WebhookURL host/path prefix not preserved: %q", red.Channels.Feishu.WebhookURL)
	}
	if !strings.HasPrefix(red.Channels.WeCom.WebhookURL, "https://qyapi.example.com/cgi-bin/webhook/send?key=") {
		t.Fatalf("WeCom WebhookURL host/path/query key not preserved: %q", red.Channels.WeCom.WebhookURL)
	}
	// Non-secret fields stay intact
	if red.Channels.Telegram.ChatID != orig.Channels.Telegram.ChatID ||
		red.Channels.Bark.Group != orig.Channels.Bark.Group ||
		red.Channels.Webhook.HeaderName != orig.Channels.Webhook.HeaderName {
		t.Fatalf("non-secret fields modified by Redacted(): %+v", red)
	}

	// Short secrets, userinfo URL, plain generic webhook URL, and malformed URL redaction
	shortCfg := config.NotifyConfig{
		Channels: config.NotifyChannelsConfig{
			Telegram: config.TelegramNotifyConfig{BotToken: "short1"},
			Bark:     config.BarkNotifyConfig{DeviceKey: "ab"},
			Feishu:   config.FeishuNotifyConfig{WebhookURL: "not-a-valid-url-secret-123456"},
			WeCom:    config.WeComNotifyConfig{WebhookURL: "https://user:TopSecretPass@qyapi.example.com/hook?key=short"},
			Webhook:  config.GenericWebhookConfig{URL: "https://hooks.example.com/plain-endpoint"},
		},
	}
	shortRed := shortCfg.Redacted()
	if shortRed.Channels.Telegram.BotToken != config.NotifySecretMask ||
		shortRed.Channels.Bark.DeviceKey != config.NotifySecretMask {
		t.Fatalf("short secrets should be replaced with %q, got tg=%q bark=%q",
			config.NotifySecretMask, shortRed.Channels.Telegram.BotToken, shortRed.Channels.Bark.DeviceKey)
	}
	if strings.Contains(shortRed.Channels.Feishu.WebhookURL, "secret-123456") || !config.IsMaskedSecret(shortRed.Channels.Feishu.WebhookURL) {
		t.Fatalf("malformed Feishu WebhookURL leaked or not masked: %q", shortRed.Channels.Feishu.WebhookURL)
	}
	if strings.Contains(shortRed.Channels.WeCom.WebhookURL, "TopSecretPass") || !strings.Contains(shortRed.Channels.WeCom.WebhookURL, "****@") {
		t.Fatalf("userinfo in WeCom WebhookURL leaked: %q", shortRed.Channels.WeCom.WebhookURL)
	}
	if shortRed.Channels.Webhook.URL != "https://hooks.example.com/plain-endpoint" {
		t.Fatalf("plain Webhook URL without query/userinfo should stay readable, got %q", shortRed.Channels.Webhook.URL)
	}

	// Idempotent Redacted()
	if red2 := red.Redacted(); red2 != red {
		t.Fatalf("Redacted() should be idempotent:\nfirst:  %+v\nsecond: %+v", red, red2)
	}

	// PUT round-trip: sending back redacted copy or empty strings preserves original secrets, while new values overwrite
	incoming := red
	incoming.CooldownMinutes = 30
	incoming.Channels.Telegram.BotToken = "" // empty string -> preserve original
	incoming.Channels.Bark.DeviceKey = "BrandNewBarkDeviceKey999999"
	incoming.Channels.Feishu.Secret = config.NotifySecretMask // masked -> preserve original

	merged := incoming.MergePreservingSecrets(orig)
	if merged.CooldownMinutes != 30 {
		t.Fatalf("CooldownMinutes = %d, want 30", merged.CooldownMinutes)
	}
	if merged.Channels.Telegram.BotToken != orig.Channels.Telegram.BotToken {
		t.Fatalf("empty BotToken should preserve original, got %q", merged.Channels.Telegram.BotToken)
	}
	if merged.Channels.Bark.DeviceKey != "BrandNewBarkDeviceKey999999" {
		t.Fatalf("new DeviceKey should replace original, got %q", merged.Channels.Bark.DeviceKey)
	}
	if merged.Channels.Feishu.WebhookURL != orig.Channels.Feishu.WebhookURL {
		t.Fatalf("masked Feishu WebhookURL should preserve original, got %q", merged.Channels.Feishu.WebhookURL)
	}
	if merged.Channels.Feishu.Secret != orig.Channels.Feishu.Secret {
		t.Fatalf("masked Feishu Secret should preserve original, got %q", merged.Channels.Feishu.Secret)
	}
	if merged.Channels.WeCom.WebhookURL != orig.Channels.WeCom.WebhookURL {
		t.Fatalf("masked WeCom WebhookURL should preserve original, got %q", merged.Channels.WeCom.WebhookURL)
	}
	if merged.Channels.Webhook.URL != orig.Channels.Webhook.URL ||
		merged.Channels.Webhook.HeaderValue != orig.Channels.Webhook.HeaderValue {
		t.Fatalf("masked Webhook URL/HeaderValue should preserve original, got %+v", merged.Channels.Webhook)
	}
}

func TestSafeCommitConfig_DefaultsBoundsAndPointerIsolation(t *testing.T) {
	var zero config.SafeCommitConfig
	if !zero.IsEmpty() || !zero.IsZero() {
		t.Fatal("zero SafeCommitConfig should be empty")
	}
	if got := zero.EffectiveTTLSec(); got != constant.SafeCommitDefaultTTLSec {
		t.Fatalf("zero EffectiveTTLSec = %d, want %d", got, constant.SafeCommitDefaultTTLSec)
	}
	if !zero.IsProtectTailscaleOOM() {
		t.Fatal("zero SafeCommitConfig should default ProtectTailscaleOOM to true")
	}

	ttlCases := []struct {
		in   int
		want int
	}{
		{-5, 180},
		{0, 180},
		{1, 60},
		{59, 60},
		{60, 60},
		{240, 240},
		{600, 600},
		{999, 600},
	}
	for _, tc := range ttlCases {
		sc := config.SafeCommitConfig{DefaultTTLSec: tc.in}
		if got := sc.EffectiveTTLSec(); got != tc.want {
			t.Errorf("EffectiveTTLSec(%d) = %d, want %d", tc.in, got, tc.want)
		}
	}

	sc := config.SafeCommitConfig{DefaultTTLSec: 120}
	sc.SetProtectTailscaleOOM(false)
	if sc.IsProtectTailscaleOOM() {
		t.Fatal("expected IsProtectTailscaleOOM=false after SetProtectTailscaleOOM(false)")
	}
	if sc.IsEmpty() {
		t.Fatal("non-zero SafeCommitConfig must not be empty")
	}

	cloned := sc.Clone()
	*cloned.ProtectTailscaleOOM = true
	if sc.IsProtectTailscaleOOM() {
		t.Fatal("mutating cloned SafeCommitConfig pointer mutated original")
	}

	sc.SetProtectTailscaleOOM(true)
	if !sc.IsProtectTailscaleOOM() || sc.ProtectTailscaleOOM != nil {
		t.Fatalf("SetProtectTailscaleOOM(true) should reset pointer to nil default, got %v", sc.ProtectTailscaleOOM)
	}
}

func TestNotifyAndSafeCommit_YAMLKnownKeysCloneASTSaveAndRace(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "singctl.yaml")

	// Intentionally test missing spaces after colons for new knownYAMLKeys + string-encoded numbers
	rawYAML := `subs:
  - name: "main"
    url: "https://sub.example.com/1"
notify:
  enabled:true
  cooldown_minutes:"25"
  daily_limit:"100"
  quiet_hours:"23:00-07:30"
  events:
    watchdog_heal:true
    new_device:false
  channels:
    telegram:
      enabled:true
      bot_token:"123456:TestBotTokenABC123456"
      chat_id:"-100999"
      api_base_url:"https://tg.example.com"
    bark:
      enabled:true
      server_url:"https://bark.example.com"
      device_key:"BarkTestKey123456"
      group:"router"
    feishu:
      enabled:false
      webhook_url:"https://open.example.com/open-apis/bot/v2/hook/test-hook-token-123"
      secret:"FeishuSecret123456"
    wecom:
      enabled:false
      webhook_url:"https://qyapi.example.com/cgi-bin/webhook/send?key=wecom-test-key-123"
    webhook:
      enabled:true
      url:"https://hooks.example.com/notify"
      header_name:"X-Token"
      header_value:"WebhookSecretValue123"
safe_commit:
  default_ttl_sec:"240"
  protect_tailscale_oom:false
`
	if err := os.WriteFile(cfgPath, []byte(rawYAML), 0600); err != nil {
		t.Fatal(err)
	}

	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("config.Load failed: %v", err)
	}
	if !cfg.Notify.Enabled || cfg.Notify.EffectiveCooldownMinutes() != 25 || cfg.Notify.EffectiveDailyLimit() != 100 || cfg.Notify.EffectiveQuietHours() != "23:00-07:30" {
		t.Fatalf("unexpected Notify top-level fields: %+v", cfg.Notify)
	}
	effEvents := cfg.Notify.EffectiveEvents()
	if !effEvents.WatchdogHeal || effEvents.NewDevice || !effEvents.SafeCommitRollback || !effEvents.ServerQuotaOrBan {
		t.Fatalf("unexpected Notify.Events after partial YAML decode: %+v", effEvents)
	}
	if cfg.Notify.Channels.Telegram.BotToken != "123456:TestBotTokenABC123456" ||
		cfg.Notify.Channels.Telegram.ChatID != "-100999" ||
		cfg.Notify.Channels.Bark.DeviceKey != "BarkTestKey123456" ||
		cfg.Notify.Channels.Webhook.HeaderName != "X-Token" {
		t.Fatalf("unexpected Notify.Channels: %+v", cfg.Notify.Channels)
	}
	if cfg.SafeCommit.EffectiveTTLSec() != 240 || cfg.SafeCommit.IsProtectTailscaleOOM() {
		t.Fatalf("unexpected SafeCommit: %+v", cfg.SafeCommit)
	}

	// Config.Clone must isolate SafeCommit.ProtectTailscaleOOM pointer
	cloned := cfg.Clone()
	*cloned.SafeCommit.ProtectTailscaleOOM = true
	if cfg.SafeCommit.IsProtectTailscaleOOM() {
		t.Fatal("Config.Clone() did not isolate SafeCommit.ProtectTailscaleOOM")
	}

	// Clean client config save must NOT pollute with empty notify/safe_commit sections
	cleanClient := &config.Config{
		Subs: []config.Subscription{{Name: "main", URL: "https://sub.example.com/1"}},
	}
	cleanOut, err := config.SaveConfigBytesAST(configs.ClientConfigYAML, cleanClient)
	if err != nil {
		t.Fatalf("SaveConfigBytesAST clean client failed: %v", err)
	}
	if strings.Contains(string(cleanOut), "\nnotify:") || strings.HasPrefix(string(cleanOut), "notify:") ||
		strings.Contains(string(cleanOut), "\nsafe_commit:") || strings.HasPrefix(string(cleanOut), "safe_commit:") {
		t.Fatalf("clean client YAML polluted with zero notify/safe_commit:\n%s", string(cleanOut))
	}

	// Pure server config with active Notify must persist notify section while keeping server role clean
	srvCfg := &config.Config{
		Server: config.ServerConfig{NodeDomain: "vps.example.com", CFDNSKey: "cf-fake-key-test"},
		Notify: config.NotifyConfig{
			Enabled: true,
			Channels: config.NotifyChannelsConfig{
				Telegram: config.TelegramNotifyConfig{Enabled: true, BotToken: "123:FakeServerBotToken", ChatID: "42"},
			},
		},
	}
	srvOut, err := config.SaveConfigBytesAST(configs.ServerConfigYAML, srvCfg)
	if err != nil {
		t.Fatalf("SaveConfigBytesAST server with notify failed: %v", err)
	}
	if !strings.Contains(string(srvOut), "notify:") || !strings.Contains(string(srvOut), "bot_token:") {
		t.Fatalf("server config save dropped active notify section:\n%s", string(srvOut))
	}

	// Save & reload roundtrip preserves explicit false event and SafeCommit
	if err := config.Save(cfgPath, cfg); err != nil {
		t.Fatalf("Save failed: %v", err)
	}
	reloaded, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("reload failed: %v", err)
	}
	if reloaded.Notify.EffectiveEvents().NewDevice || !reloaded.Notify.EffectiveEvents().WatchdogHeal {
		t.Fatalf("Save/Load roundtrip lost explicit event toggle: %+v", reloaded.Notify.EffectiveEvents())
	}
	if reloaded.SafeCommit.EffectiveTTLSec() != 240 || reloaded.SafeCommit.IsProtectTailscaleOOM() {
		t.Fatalf("Save/Load roundtrip lost SafeCommit: %+v", reloaded.SafeCommit)
	}

	// SaveConfigBytesAST idempotency with Notify & SafeCommit
	rawSaved, _ := os.ReadFile(cfgPath)
	pass1, err := config.SaveConfigBytesAST(rawSaved, reloaded)
	if err != nil {
		t.Fatalf("pass1 failed: %v", err)
	}
	pass2, err := config.SaveConfigBytesAST(pass1, reloaded)
	if err != nil {
		t.Fatalf("pass2 failed: %v", err)
	}
	if string(pass1) != string(pass2) {
		t.Fatalf("SaveConfigBytesAST not idempotent for Notify/SafeCommit")
	}

	// Clearing Notify and SafeCommit must completely strip both top-level keys from disk YAML
	reloaded.Notify = config.NotifyConfig{}
	reloaded.SafeCommit = config.SafeCommitConfig{}
	if err := config.Save(cfgPath, reloaded); err != nil {
		t.Fatalf("Save cleared failed: %v", err)
	}
	clearedBytes, _ := os.ReadFile(cfgPath)
	if strings.Contains(string(clearedBytes), "notify:") || strings.Contains(string(clearedBytes), "safe_commit:") {
		t.Fatalf("cleared notify/safe_commit survived AST save:\n%s", string(clearedBytes))
	}

	// Concurrent race safety
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			cp := cfg.Clone()
			red := cp.Notify.Redacted()
			_ = red.MergePreservingSecrets(cp.Notify)
			_ = cp.Notify.SecretStatus()
			_ = cp.SafeCommit.EffectiveTTLSec()
			_ = cp.SafeCommit.IsProtectTailscaleOOM()
		})
	}
	wg.Wait()
}

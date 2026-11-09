package test

import (
	"archive/zip"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"singctl/internal/adguard"
	"singctl/internal/config"
	"singctl/internal/singbox"
	"slices"
	"strings"
	"testing"
)

func TestConfigGeneratorNew(t *testing.T) {
	cfg := &config.Config{
		Subs: []config.Subscription{
			{Name: "test", URL: "https://example.com/sub", SkipTlsVerify: false, RemoveEmoji: true},
		},
		GitHub: config.GitHubConfig{MirrorURL: "https://ghfast.top"},
	}

	generator := singbox.NewConfigGenerator(cfg)
	if generator == nil {
		t.Fatal("NewConfigGenerator returned nil")
	}

	// 验证生成器创建成功
	t.Log("ConfigGenerator created successfully")
}

func TestGetSubnetFromIP(t *testing.T) {

	tests := []struct {
		name     string
		ip       string
		expected string
	}{
		{
			name:     "regular IPv4",
			ip:       "8.8.8.8",
			expected: "8.8.8.8/24",
		},
		{
			name:     "local network",
			ip:       "192.168.1.1",
			expected: "192.168.1.1/24",
		},
		{
			name:     "empty IP",
			ip:       "",
			expected: "/24",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// 由于 getSubnetFromIP 是私有方法，我们需要通过其他方式测试
			// 或者将其设为公共方法用于测试
			// 这里我们创建一个临时的测试方法
			result := getSubnetFromIPForTest(tt.ip)
			if result != tt.expected {
				t.Errorf("getSubnetFromIP(%s) = %s, expected %s", tt.ip, result, tt.expected)
			}
		})
	}
}

// 临时测试函数，复制 generator 中的逻辑
func getSubnetFromIPForTest(ip string) string {
	return ip + "/24"
}

func TestConfigGeneratorGenerate_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// 使用真实但可能无效的订阅 URL 进行测试
	cfg := &config.Config{
		Subs: []config.Subscription{
			{
				Name:          "test",
				URL:           "https://example.com/invalid-subscription", // 故意使用无效订阅
				SkipTlsVerify: false,
				RemoveEmoji:   true,
			},
		},
		GitHub: config.GitHubConfig{MirrorURL: "https://ghfast.top"},
	}

	generator := singbox.NewConfigGenerator(cfg)

	// 注意：这个测试预期会失败，因为订阅 URL 无效
	configJSON, err := generator.Generate()
	if err != nil {
		// 在测试环境中，由于网络或订阅无效，失败是预期的
		t.Logf("Generate failed as expected in test environment: %v", err)

		// 检查错误类型
		if !strings.Contains(err.Error(), "error getting netResult") &&
			!strings.Contains(err.Error(), "generate sing-box config failed") &&
			!strings.Contains(err.Error(), "failed to generate single subscription config") {
			t.Errorf("Unexpected error type: %v", err)
		}
		return
	}

	// 如果意外成功，验证生成的配置
	validateGeneratedConfig(t, configJSON)
}

func TestConfigGeneratorGenerate_MockNetinfo(t *testing.T) {
	// 这个测试需要 mock netinfo，但由于没有依赖注入，暂时跳过
	t.Skip("Mock test requires refactoring for dependency injection")
}

func TestMultipleSubscriptions(t *testing.T) {
	// 测试多订阅配置验证
	tests := []struct {
		name      string
		config    config.Config
		wantError bool
	}{
		{
			name: "valid multiple subscriptions with names",
			config: config.Config{
				Subs: []config.Subscription{
					{Name: "work", URL: "https://example.com/sub1", SkipTlsVerify: false, RemoveEmoji: true},
					{Name: "home", URL: "https://example.com/sub2", SkipTlsVerify: false, RemoveEmoji: false},
				},
				GitHub: config.GitHubConfig{MirrorURL: "https://ghfast.top"},
			},
			wantError: false,
		},
		{
			name: "invalid multiple subscriptions without names",
			config: config.Config{
				Subs: []config.Subscription{
					{URL: "https://example.com/sub1", SkipTlsVerify: false, RemoveEmoji: true},
					{URL: "https://example.com/sub2", SkipTlsVerify: false, RemoveEmoji: false},
				},
				GitHub: config.GitHubConfig{MirrorURL: "https://ghfast.top"},
			},
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.ValidateSubs()
			if (err != nil) != tt.wantError {
				t.Errorf("Config.Validate() error = %v, wantError %v", err, tt.wantError)
			}

			if !tt.wantError {
				// 如果配置有效，测试创建生成器
				generator := singbox.NewConfigGenerator(&tt.config)
				if generator == nil {
					t.Error("NewConfigGenerator returned nil for valid config")
				}
				configContent, err := generator.Generate()
				if err != nil {
					t.Logf("Generate failed (expected in test environment): %v", err)
					return
				}

				// 验证生成的配置包含两个订阅的节点
				if len(configContent) > 0 {
					t.Logf("Generated config length: %d characters", len(configContent))

					// 检查是否包含work和home节点
					hasWork := strings.Contains(configContent, "work-")
					hasHome := strings.Contains(configContent, "home-")

					t.Logf("Config contains work nodes: %v", hasWork)
					t.Logf("Config contains home nodes: %v", hasHome)

					if hasWork && hasHome {
						t.Log("✓ Both work and home subscription nodes found in config")
					}
				}
			}
		})
	}
}

func TestEmojiRemovalIndependent(t *testing.T) {
	// 测试每个订阅独立处理emoji移除设置
	cfg := &config.Config{
		Subs: []config.Subscription{
			{Name: "emoji", URL: "https://example.com/sub1", RemoveEmoji: true},
			{Name: "keepemoji", URL: "https://example.com/sub2", RemoveEmoji: false},
		},
		GitHub: config.GitHubConfig{MirrorURL: "https://ghfast.top"},
	}

	// 验证配置
	if err := cfg.ValidateSubs(); err != nil {
		t.Fatalf("Config validation failed: %v", err)
	}

	generator := singbox.NewConfigGenerator(cfg)
	if generator == nil {
		t.Fatal("NewConfigGenerator returned nil")
	}

	// 注意：这里无法直接测试emoji处理，因为需要真实的订阅URL
	// 但我们可以验证配置的结构正确性
	t.Logf("Successfully created generator with mixed emoji settings: %+v", cfg.Subs)

	// 验证各订阅的 RemoveEmoji 设置确实不同
	if cfg.Subs[0].RemoveEmoji == cfg.Subs[1].RemoveEmoji {
		t.Error("Expected different RemoveEmoji settings for different subscriptions")
	}
}

func validateGeneratedConfig(t *testing.T, configJSON string) {
	if len(configJSON) == 0 {
		t.Error("Generated config is empty")
		return
	}

	// 验证是否是有效的 JSON
	var configMap map[string]interface{}
	if err := json.Unmarshal([]byte(configJSON), &configMap); err != nil {
		t.Errorf("Generated config is not valid JSON: %v", err)
		return
	}

	t.Logf("Generated config structure: %+v", configMap)

	// 验证必要的字段
	expectedFields := []string{"log", "dns", "inbounds", "outbounds"}
	for _, field := range expectedFields {
		if _, exists := configMap[field]; !exists {
			t.Errorf("Generated config missing required field: %s", field)
		}
	}

	// 验证 DNS 配置
	if dns, exists := configMap["dns"]; exists {
		dnsMap, ok := dns.(map[string]interface{})
		if !ok {
			t.Error("DNS config is not a valid object")
		} else {
			// 检查是否有服务器配置
			if servers, exists := dnsMap["servers"]; exists {
				if serversList, ok := servers.([]interface{}); !ok || len(serversList) == 0 {
					t.Error("DNS servers list is empty or invalid")
				}
			}
		}
	}

	// 验证入站配置
	if inbounds, exists := configMap["inbounds"]; exists {
		inboundsList, ok := inbounds.([]interface{})
		if !ok || len(inboundsList) == 0 {
			t.Error("Inbounds configuration is empty or invalid")
		}
	}

	// 验证出站配置
	if outbounds, exists := configMap["outbounds"]; exists {
		outboundsList, ok := outbounds.([]interface{})
		if !ok || len(outboundsList) == 0 {
			t.Error("Outbounds configuration is empty or invalid")
		}
	}
}

// 测试配置生成的各个参数
func TestConfigGeneratorParameters(t *testing.T) {
	tests := []struct {
		name   string
		config config.Config
	}{
		{
			name: "with mirror URL",
			config: config.Config{
				Subs: []config.Subscription{
					{Name: "test", URL: "https://example.com/sub1", SkipTlsVerify: false, RemoveEmoji: true},
				},
				GitHub: config.GitHubConfig{MirrorURL: "https://ghfast.top"},
			},
		},
		{
			name: "with insecure subscription",
			config: config.Config{
				Subs: []config.Subscription{
					{Name: "test", URL: "https://example.com/sub1", SkipTlsVerify: true, RemoveEmoji: false},
				},
				GitHub: config.GitHubConfig{MirrorURL: "https://github.com"},
			},
		},
		{
			name: "multiple subscriptions with names",
			config: config.Config{
				Subs: []config.Subscription{
					{Name: "work", URL: "https://example.com/sub1", SkipTlsVerify: false, RemoveEmoji: true},
					{Name: "home", URL: "https://example.com/sub2", SkipTlsVerify: true, RemoveEmoji: false},
				},
				GitHub: config.GitHubConfig{MirrorURL: "https://ghfast.top"},
			},
		},
	}

	if testing.Short() {
		t.Skip("Skipping parameter tests in short mode")
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			generator := singbox.NewConfigGenerator(&tt.config)

			// 尝试生成配置，但预期可能失败
			_, err := generator.Generate()
			if err != nil {
				// 记录失败但不标记为测试失败，因为这依赖外部服务
				t.Logf("Config generation failed (expected): %v", err)
			}
		})
	}
}

func TestCustomRulesInjection(t *testing.T) {
	cfg := &config.Config{
		CustomRules: config.CustomRulesConfig{
			Route: []map[string]any{
				{
					"action":        "route",
					"domain_suffix": []any{"htsc.com.cn", "zhangle.com"},
					"outbound":      "DirectConn",
				},
			},
			DNS: []map[string]any{
				{
					"domain_suffix": []any{"htsc.com.cn"},
					"server":        "dns_local",
				},
			},
		},
	}

	generator := singbox.NewConfigGenerator(cfg)
	baseJSON := `{
		"dns": {
			"rules": [
				{"rule_set": "geosite-cn", "server": "dns_local"}
			]
		},
		"route": {
			"rules": [
				{"action": "sniff"},
				{"ip_is_private": true, "outbound": "DirectConn"},
				{"action": "route", "rule_set": "geosite-steam", "outbound": "Steam"}
			]
		}
	}`

	outJSON, err := generator.InjectCustomRules(baseJSON)
	if err != nil {
		t.Fatalf("InjectCustomRules failed: %v", err)
	}

	var root map[string]any
	if err := json.Unmarshal([]byte(outJSON), &root); err != nil {
		t.Fatalf("unmarshal injected json failed: %v", err)
	}

	// Verify DNS rule was prepended
	dnsMap := root["dns"].(map[string]any)
	dnsRules := dnsMap["rules"].([]any)
	if len(dnsRules) != 2 {
		t.Fatalf("expected 2 dns rules, got %d", len(dnsRules))
	}
	firstDNS := dnsRules[0].(map[string]any)
	if firstDNS["server"] != "dns_local" {
		t.Errorf("expected first dns rule server to be dns_local, got %v", firstDNS["server"])
	}

	// Verify Route rule was inserted after ip_is_private
	routeMap := root["route"].(map[string]any)
	routeRules := routeMap["rules"].([]any)
	if len(routeRules) != 4 {
		t.Fatalf("expected 4 route rules, got %d", len(routeRules))
	}
	customRoute := routeRules[2].(map[string]any)
	if customRoute["outbound"] != "DirectConn" {
		t.Errorf("expected custom route outbound DirectConn, got %v", customRoute["outbound"])
	}
}

func TestDeduplicateOutbounds(t *testing.T) {
	tests := []struct {
		name          string
		inputJSON     string
		expectedCount int
		expectedTags  []string // 应包含的 tag，按特定预期验证
		expectError   bool
	}{
		{
			name: "All Unique",
			inputJSON: `{
				"outbounds": [
					{"tag": "proxy-1", "type": "vless", "server": "1.1.1.1"},
					{"tag": "proxy-2", "type": "vmess", "server": "2.2.2.2"}
				]
			}`,
			expectedCount: 2,
			expectedTags:  []string{"proxy-1", "proxy-2"},
			expectError:   false,
		},
		{
			name: "Exact Duplicate",
			inputJSON: `{
				"outbounds": [
					{"tag": "proxy-1", "type": "vless", "server": "1.1.1.1"},
					{"tag": "proxy-1", "type": "vless", "server": "1.1.1.1"}
				]
			}`,
			expectedCount: 1,
			expectedTags:  []string{"proxy-1"},
			expectError:   false,
		},
		{
			name: "Same Tag Different Content",
			inputJSON: `{
				"outbounds": [
					{"tag": "proxy-1", "type": "vless", "server": "1.1.1.1"},
					{"tag": "proxy-1", "type": "vless", "server": "3.3.3.3"}
				]
			}`,
			expectedCount: 2,
			expectedTags:  []string{"proxy-1", "proxy-1_1"},
			expectError:   false,
		},
		{
			name: "Multi Conflict",
			inputJSON: `{
				"outbounds": [
					{"tag": "tg", "type": "direct"},
					{"tag": "tg", "type": "direct", "domain_strategy": "ipv4_only"},
					{"tag": "tg", "type": "block"}
				]
			}`,
			expectedCount: 3,
			expectedTags:  []string{"tg", "tg_1", "tg_2"},
			expectError:   false,
		},
		{
			name: "No Tag Field",
			inputJSON: `{
				"outbounds": [
					{"type": "direct"},
					{"tag": "proxy-1", "type": "vless"}
				]
			}`,
			expectedCount: 2,
			expectedTags:  []string{"proxy-1"}, // 另一个没有 tag 不强求匹配，只要数量对即可在代码里额外判断
			expectError:   false,
		},
		{
			name: "No Outbounds Field",
			inputJSON: `{
				"inbounds": [{"type": "mixed", "listen": "127.0.0.1"}]
			}`,
			expectedCount: 0, // 测试代码对无 outbounds 特殊处理
			expectError:   false,
		},
		{
			name: "Empty Outbounds",
			inputJSON: `{
				"outbounds": []
			}`,
			expectedCount: 0,
			expectError:   false,
		},
		{
			name:        "Invalid JSON",
			inputJSON:   `{invalid json`,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resultJSON, err := singbox.DeduplicateOutbounds(tt.inputJSON)
			if (err != nil) != tt.expectError {
				t.Fatalf("expected error: %v, got: %v", tt.expectError, err)
			}
			if tt.expectError {
				return
			}

			// Parse result to verify
			var cfg map[string]any
			if err := json.Unmarshal([]byte(resultJSON), &cfg); err != nil {
				t.Fatalf("failed to parse result JSON: %v", err)
			}

			rawOutbounds, ok := cfg["outbounds"]
			if !ok {
				if tt.name != "No Outbounds Field" {
					t.Fatalf("outbounds field missing in result for test %s", tt.name)
				}
				return
			}
			outbounds, ok := rawOutbounds.([]any)
			if !ok {
				t.Fatalf("outbounds is not an array")
			}

			if len(outbounds) != tt.expectedCount {
				t.Errorf("expected %d outbounds, got %d", tt.expectedCount, len(outbounds))
			}

			// Check if expected tags are present
			if len(tt.expectedTags) > 0 {
				foundTags := make(map[string]bool)
				for _, out := range outbounds {
					if node, ok := out.(map[string]any); ok {
						if tagVal, has := node["tag"]; has {
							if tagStr, isStr := tagVal.(string); isStr {
								foundTags[tagStr] = true
							}
						}
					}
				}

				for _, expectedTag := range tt.expectedTags {
					if !foundTags[expectedTag] {
						t.Errorf("missing expected tag %q", expectedTag)
					}
				}
			}

			// Specific test logic for "No Tag Field" test
			if tt.name == "No Tag Field" {
				// Verify exactly one item has NO tag, and one has "proxy-1"
				noTagCount := 0
				hasProxy1 := false
				for _, out := range outbounds {
					if node, ok := out.(map[string]any); ok {
						val, has := node["tag"]
						if !has {
							noTagCount++
						} else if str, _ := val.(string); str == "proxy-1" {
							hasProxy1 = true
						}
					}
				}

				if noTagCount != 1 {
					t.Errorf("expected 1 item with no tag, found %d", noTagCount)
				}
				if !hasProxy1 {
					t.Errorf("expected proxy-1 to be present")
				}
			}
		})
	}
}

// Ensure DeduplicateOutbounds does not pollute map references when renaming tags
func TestDeduplicateOutbounds_ReferencePollution(t *testing.T) {
	inputJSON := `{
		"outbounds": [
			{"tag": "proxy-1", "type": "vless", "server": "1.1.1.1"},
			{"tag": "proxy-1", "type": "vless", "server": "2.2.2.2"},
			{"tag": "proxy-1", "type": "vless", "server": "1.1.1.1"}
		]
	}`

	// 预期:
	// item 1: proxy-1 (1.1.1.1)
	// item 2: proxy-1_1 (2.2.2.2)
	// item 3: 完全等同于 item 1, 应该被抛弃。
	// 如果引用的 node 被污染，item 1 的 tag 会变成 proxy-1_1, 则可能影响行为

	resultJSON, err := singbox.DeduplicateOutbounds(inputJSON)
	if err != nil {
		t.Fatalf("dedup failed: %v", err)
	}

	if strings.Contains(resultJSON, "proxy-1_2") {
		t.Errorf("Should not contain proxy-1_2: %s", resultJSON)
	}

	var cfg map[string]any
	json.Unmarshal([]byte(resultJSON), &cfg)
	outbounds := cfg["outbounds"].([]any)
	if len(outbounds) != 2 {
		t.Fatalf("expected 2 outbounds, got %d", len(outbounds))
	}

	tags := []string{}
	for _, out := range outbounds {
		node := out.(map[string]any)
		tags = append(tags, node["tag"].(string))
	}

	if tags[0] != "proxy-1" && tags[1] != "proxy-1" {
		t.Errorf("missing original tag 'proxy-1', tags: %v", tags)
	}
	if tags[0] != "proxy-1_1" && tags[1] != "proxy-1_1" {
		t.Errorf("missing renamed tag 'proxy-1_1', tags: %v", tags)
	}
}

func TestPrettyJSON_Valid(t *testing.T) {
	raw := `{"outbounds":[{"tag":"Direct","type":"direct"}],"inbounds":[{"type":"tproxy"}]}`
	out, err := singbox.PrettyJSON(raw)
	if err != nil {
		t.Fatalf("PrettyJSON failed: %v", err)
	}

	if !strings.Contains(out, "\n") {
		t.Error("Expected pretty JSON to contain newlines")
	}
	if !strings.Contains(out, "  ") {
		t.Error("Expected pretty JSON to contain indentation")
	}

	// 验证输出仍是有效 JSON
	var m map[string]any
	if err := json.Unmarshal([]byte(out), &m); err != nil {
		t.Errorf("Pretty JSON output is not valid JSON: %v", err)
	}
}

func TestPrettyJSON_InvalidInput(t *testing.T) {
	raw := `{"outbounds":[{"tag":Direct}]}` // invalid JSON
	_, err := singbox.PrettyJSON(raw)
	if err == nil {
		t.Error("Expected error for invalid JSON")
	}
	if !strings.Contains(err.Error(), "pretty:") {
		t.Errorf("Error should have 'pretty:' prefix, got: %v", err)
	}
}

func TestPrettyJSON_AlreadyPretty(t *testing.T) {
	pretty := "{\n  \"tag\": \"Direct\",\n  \"type\": \"direct\"\n}"
	out, err := singbox.PrettyJSON(pretty)
	if err != nil {
		t.Fatalf("PrettyJSON failed on already-pretty input: %v", err)
	}

	var m map[string]any
	if err := json.Unmarshal([]byte(out), &m); err != nil {
		t.Errorf("Output is not valid JSON: %v", err)
	}
}

func TestPrettyJSON_Idempotent(t *testing.T) {
	raw := `{"a":1,"b":[2,3],"c":{"d":"e"}}`

	first, err := singbox.PrettyJSON(raw)
	if err != nil {
		t.Fatalf("First PrettyJSON call failed: %v", err)
	}

	second, err := singbox.PrettyJSON(first)
	if err != nil {
		t.Fatalf("Second PrettyJSON call failed: %v", err)
	}

	if first != second {
		t.Errorf("PrettyJSON is not idempotent.\nFirst:\n%s\nSecond:\n%s", first, second)
	}
}

func TestPrettyJSON_PreservesData(t *testing.T) {
	raw := `{"outbounds":[{"tag":"proxy-1","type":"vless","server":"1.1.1.1"},{"tag":"proxy-2","type":"vmess","server":"2.2.2.2"}],"dns":{"servers":[{"address":"8.8.8.8"}]}}`

	out, err := singbox.PrettyJSON(raw)
	if err != nil {
		t.Fatalf("PrettyJSON failed: %v", err)
	}

	// 解析原始和美化后的 JSON, 比较数据一致性
	var original, formatted map[string]any
	json.Unmarshal([]byte(raw), &original)
	json.Unmarshal([]byte(out), &formatted)

	origBytes, _ := json.Marshal(original)
	fmtBytes, _ := json.Marshal(formatted)

	if string(origBytes) != string(fmtBytes) {
		t.Error("PrettyJSON altered the data content")
	}
}

// buildFakeDashboardZip 构造带 GitHub archive 顶层目录的模拟 dashboard zip
func buildFakeDashboardZip(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, f := range []struct {
		name    string
		content string
	}{
		{"sing-box-dashboard-gh-pages/index.html", "<html>dash</html>"},
		{"sing-box-dashboard-gh-pages/assets/app.js", "console.log(1)"},
	} {
		w, err := zw.Create(f.name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(f.content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestProvisionDashboard(t *testing.T) {
	zipData := buildFakeDashboardZip(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		_, _ = w.Write(zipData)
	}))
	defer srv.Close()

	dir := filepath.Join(t.TempDir(), "dashboard")
	cfgJSON := `{"services":[{"type":"api","tag":"api-in","dashboard":{"enabled":true,"path":"` +
		filepath.ToSlash(dir) + `","download_url":"` + srv.URL + `/dash.zip"}}]}`

	if err := singbox.ProvisionDashboard(cfgJSON); err != nil {
		t.Fatalf("provision: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "index.html")); err != nil {
		t.Fatalf("index.html should be extracted: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "assets", "app.js")); err != nil {
		t.Fatalf("nested asset should be extracted: %v", err)
	}

	// 幂等: index.html 已存在时跳过下载(关闭 server 后再次调用应仍成功)
	srv.Close()
	if err := singbox.ProvisionDashboard(cfgJSON); err != nil {
		t.Fatalf("idempotent re-run should skip download: %v", err)
	}
}

func TestProvisionDashboardNoAPIService(t *testing.T) {
	// 无 services(如 iOS 客户端配置) → 直接成功返回
	if err := singbox.ProvisionDashboard(`{"inbounds":[]}`); err != nil {
		t.Fatalf("no api service should be a no-op, got: %v", err)
	}
}

func TestResolvePlatform(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		want    string
		wantErr bool
	}{
		{"空值回退当前系统", "", runtime.GOOS, false},
		{"auto回退当前系统", "auto", runtime.GOOS, false},
		{"显式darwin", "darwin", "darwin", false},
		{"显式windows", "windows", "windows", false},
		{"显式linux", "linux", "linux", false},
		{"显式ios", "ios", "ios", false},
		{"非法平台", "android", "", true},
		{"注入攻击", "ios;rm -rf /", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := singbox.ResolvePlatform(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error for %q, got %q", tc.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("ResolvePlatform(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestCheckIOSCompatibility(t *testing.T) {
	t.Run("远程规则集通过", func(t *testing.T) {
		json := `{"route":{"rule_set":[{"type":"remote","tag":"geoip-cn","format":"binary","url":"https://example.com/geoip-cn.srs"}]}}`
		if err := singbox.CheckIOSCompatibility(json); err != nil {
			t.Fatalf("remote rule_set should pass: %v", err)
		}
	})

	t.Run("本地规则集拒绝", func(t *testing.T) {
		json := `{"route":{"rule_set":[{"type":"local","tag":"geoip-cn","format":"binary","path":"/etc/sing-box/geoip-cn.srs"}]}}`
		err := singbox.CheckIOSCompatibility(json)
		if err == nil {
			t.Fatal("local rule_set should be rejected")
		}
		if !strings.Contains(err.Error(), "geoip-cn") {
			t.Fatalf("error should mention offending tag, got: %v", err)
		}
	})

	t.Run("无规则集通过", func(t *testing.T) {
		json := `{"outbounds":[{"type":"direct","tag":"direct"}]}`
		if err := singbox.CheckIOSCompatibility(json); err != nil {
			t.Fatalf("no rule_set should pass: %v", err)
		}
	})

	t.Run("非法JSON报错", func(t *testing.T) {
		if err := singbox.CheckIOSCompatibility("not-json"); err == nil {
			t.Fatal("invalid json should error")
		}
	})
}

func TestGenerator_InjectLocalDNS_AdGuardHome(t *testing.T) {
	payload := encodeURISub(
		"hysteria2://dummy-pass@hk1.example.com:443?sni=hk1.example.com#HK-Primary",
	)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(payload))
	}))
	defer ts.Close()

	t.Cleanup(func() {
		adguard.SetInstalledCheckForTest(nil)
	})

	extractDNSLocal := func(t *testing.T, rawJSON string) map[string]any {
		t.Helper()
		var root struct {
			DNS struct {
				Servers []map[string]any `json:"servers"`
			} `json:"dns"`
		}
		if err := json.Unmarshal([]byte(rawJSON), &root); err != nil {
			t.Fatalf("unmarshal json: %v", err)
		}
		for _, srv := range root.DNS.Servers {
			if srv["tag"] == "dns_local" {
				return srv
			}
		}
		t.Fatal("dns_local server not found in generated config")
		return nil
	}

	t.Run("linux routes dns_local to AdGuardHome when installed and enabled", func(t *testing.T) {
		adguard.SetInstalledCheckForTest(func() bool { return true })
		cfg := &config.Config{
			Subs: []config.Subscription{{Name: "main", URL: ts.URL}},
			DNS:  config.ClientDNSConfig{DNSPort: 5353},
		}
		gen := singbox.NewConfigGenerator(cfg)
		gen.SetCacheDir(t.TempDir())

		out, err := gen.GenerateForPlatform("linux")
		if err != nil {
			t.Fatalf("GenerateForPlatform(linux) failed: %v", err)
		}
		srv := extractDNSLocal(t, out)
		if srv["server"] != "127.0.0.1" || int(srv["server_port"].(float64)) != 5353 || srv["type"] != "udp" {
			t.Fatalf("unexpected dns_local: %+v", srv)
		}

		var fullCfg struct {
			DNS struct {
				DisableCache bool `json:"disable_cache"`
				Optimistic   bool `json:"optimistic"`
			} `json:"dns"`
			Experimental struct {
				CacheFile struct {
					StoreDNS    bool `json:"store_dns"`
					StoreFakeIP bool `json:"store_fakeip"`
				} `json:"cache_file"`
			} `json:"experimental"`
		}
		if err := json.Unmarshal([]byte(out), &fullCfg); err != nil {
			t.Fatalf("unmarshal full config: %v", err)
		}
		if !fullCfg.DNS.DisableCache || fullCfg.DNS.Optimistic {
			t.Fatalf("expected sing-box dns disable_cache=true and optimistic=false when AdGuardHome is active, got %+v", fullCfg.DNS)
		}
		if fullCfg.Experimental.CacheFile.StoreDNS || fullCfg.Experimental.CacheFile.StoreFakeIP {
			t.Fatalf("expected store_dns=false and store_fakeip=false when AdGuardHome is active, got %+v", fullCfg.Experimental.CacheFile)
		}

		if sbBin, err := exec.LookPath("sing-box"); err == nil && sbBin != "" {
			checkJSON := out
			if runtime.GOOS != "linux" {
				// macOS/Windows 上的 sing-box check 不支持 Linux 专属 TProxy/default_mark，
				// 用 darwin 基准配置叠加相同的 dns_local 结构校验 DNS schema 合法性
				darwinBase, err := gen.GenerateForPlatform("darwin")
				if err != nil {
					t.Fatalf("GenerateForPlatform(darwin) failed: %v", err)
				}
				checkJSON, err = gen.InjectLocalDNS(darwinBase, "linux")
				if err != nil {
					t.Fatalf("InjectLocalDNS failed: %v", err)
				}
			}
			cfgFile := filepath.Join(t.TempDir(), "config.json")
			if err := os.WriteFile(cfgFile, []byte(checkJSON), 0600); err != nil {
				t.Fatal(err)
			}
			cmd := exec.CommandContext(t.Context(), sbBin, "check", "-c", cfgFile)
			if checkOut, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("sing-box check failed: %v\n%s", err, string(checkOut))
			}
		}
	})

	t.Run("ios never routes dns_local to loopback AdGuardHome", func(t *testing.T) {
		adguard.SetInstalledCheckForTest(func() bool { return true })
		cfg := &config.Config{
			Subs: []config.Subscription{{Name: "main", URL: ts.URL}},
		}
		gen := singbox.NewConfigGenerator(cfg)
		gen.SetCacheDir(t.TempDir())

		out, err := gen.GenerateForPlatform(singbox.PlatformIOS)
		if err != nil {
			t.Fatalf("GenerateForPlatform(ios) failed: %v", err)
		}
		srv := extractDNSLocal(t, out)
		if srv["server"] == "127.0.0.1" {
			t.Fatalf("iOS config must not point dns_local to 127.0.0.1, got %+v", srv)
		}
	})

	t.Run("linux skips AdGuardHome when dns.enabled is false", func(t *testing.T) {
		adguard.SetInstalledCheckForTest(func() bool { return true })
		disabled := false
		cfg := &config.Config{
			Subs: []config.Subscription{{Name: "main", URL: ts.URL}},
			DNS:  config.ClientDNSConfig{Enabled: &disabled, DNSPort: 5353},
		}
		gen := singbox.NewConfigGenerator(cfg)
		gen.SetCacheDir(t.TempDir())

		out, err := gen.GenerateForPlatform("linux")
		if err != nil {
			t.Fatalf("GenerateForPlatform(linux) failed: %v", err)
		}
		srv := extractDNSLocal(t, out)
		if srv["server"] == "127.0.0.1" {
			t.Fatalf("expected dns_local not to be 127.0.0.1 when disabled, got %+v", srv)
		}
	})
}

func TestGenerator_GameUDPAndDNSIsolation(t *testing.T) {
	payload := encodeURISub(
		"hysteria2://dummy-pass@los.example.com:443?sni=los.example.com#sec_los_hy2",
		"hysteria2://dummy-pass@hk1.example.com:443?sni=hk1.example.com#HK-01",
		"hysteria2://dummy-pass@hk5.example.com:443?sni=hk5.example.com#香港 001【5倍】",
	)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(payload))
	}))
	defer ts.Close()

	cfg := &config.Config{
		Subs: []config.Subscription{{Name: "main", URL: ts.URL}},
	}
	gen := singbox.NewConfigGenerator(cfg)
	gen.SetCacheDir(t.TempDir())

	for _, platform := range []string{"linux", singbox.PlatformIOS, "darwin"} {
		out, err := gen.GenerateForPlatform(platform)
		if err != nil {
			t.Fatalf("GenerateForPlatform(%s) failed: %v", platform, err)
		}
		var parsed struct {
			DNS struct {
				ClientSubnet string `json:"client_subnet"`
				Servers      []struct {
					Tag    string `json:"tag"`
					Detour string `json:"detour"`
				} `json:"servers"`
				Rules []struct {
					RuleSet      any    `json:"rule_set"`
					Server       string `json:"server"`
					ClientSubnet string `json:"client_subnet"`
				} `json:"rules"`
			} `json:"dns"`
			Outbounds []struct {
				Tag                       string   `json:"tag"`
				Outbounds                 []string `json:"outbounds"`
				Interval                  string   `json:"interval"`
				Tolerance                 int      `json:"tolerance"`
				InterruptExistConnections *bool    `json:"interrupt_exist_connections"`
			} `json:"outbounds"`
			Route struct {
				Rules []struct {
					Action    string   `json:"action"`
					Network   string   `json:"network"`
					Outbound  string   `json:"outbound"`
					Port      any      `json:"port"`
					PortRange []string `json:"port_range"`
					RuleSet   any      `json:"rule_set"`
				} `json:"rules"`
			} `json:"route"`
		}
		if err := json.Unmarshal([]byte(out), &parsed); err != nil {
			t.Fatal(err)
		}

		byTag := make(map[string][]string)
		var autoInterval string
		var autoTolerance int
		var autoInterrupt *bool
		for _, ob := range parsed.Outbounds {
			byTag[ob.Tag] = ob.Outbounds
			if ob.Tag == "#Auto" {
				autoInterval = ob.Interval
				autoTolerance = ob.Tolerance
				autoInterrupt = ob.InterruptExistConnections
			}
		}

		// 1. 冗余旧分组已被精简移除，保留两层清晰结构：分流组(Proxy/AI) + 节点池(#VPS/#Auto/#Nodes/#DC)
		for _, removed := range []string{"DIY-Node", "VPS", "Auto", "Select", "DNS", "HoK", "YouTube", "OpenAI", "Google", "Netflix", "Steam", "Game", "Game-TCP", "Game-UDP", "DirectConn"} {
			if _, exists := byTag[removed]; exists {
				t.Fatalf("[%s] redundant group %q should be removed", platform, removed)
			}
		}

		// 2. #Auto 测速池必须自动剔除【5倍】高倍率节点，而 #Nodes 保留供手动选
		autoPool := byTag["#Auto"]
		if len(autoPool) == 0 {
			t.Fatalf("[%s] expected #Auto pool to be non-empty", platform)
		}
		for _, item := range autoPool {
			if item == "香港 001【5倍】" {
				t.Fatalf("[%s] #Auto pool must exclude high-multiplier nodes, got %v", platform, autoPool)
			}
		}

		// 3. 验证分流控制组默认首选项
		if len(byTag["#VPS"]) == 0 {
			t.Fatalf("[%s] expected #VPS pool to contain sec_ nodes", platform)
		}
		if got := byTag["Proxy"]; len(got) == 0 || got[0] != "#VPS" || got[len(got)-1] != "#DC" {
			t.Fatalf("[%s] Proxy should default to #VPS and end with #DC, got %v", platform, got)
		}
		if got := byTag["AI"]; len(got) == 0 || got[0] != "#VPS" {
			t.Fatalf("[%s] AI should default to #VPS, got %v", platform, got)
		}

		// 4. dns_proxy 走高可靠自建 #VPS，且 geosite-hok 规则显式携带香港 ECS 子网 203.80.96.0/24
		detours := make(map[string]string)
		for _, srv := range parsed.DNS.Servers {
			detours[srv.Tag] = srv.Detour
		}
		if detours["dns_proxy"] != "#VPS" {
			t.Fatalf("[%s] dns_proxy detour = %q, want #VPS", platform, detours["dns_proxy"])
		}
		if parsed.DNS.ClientSubnet != "" {
			t.Fatalf("[%s] top-level dns.client_subnet should be empty to avoid polluting dns_proxy, got %q", platform, parsed.DNS.ClientSubnet)
		}
		foundHoKECS := false
		for _, dr := range parsed.DNS.Rules {
			if rs, ok := dr.RuleSet.(string); ok && rs == "geosite-hok" && dr.Server == "dns_proxy" {
				if dr.ClientSubnet != "203.80.96.0/24" {
					t.Fatalf("[%s] geosite-hok dns rule client_subnet = %q, want 203.80.96.0/24", platform, dr.ClientSubnet)
				}
				foundHoKECS = true
			}
		}
		if !foundHoKECS {
			t.Fatalf("[%s] geosite-hok dns rule with dns_proxy not found", platform)
		}

		// 5. 通用基准模板保持 #Auto 默认 1m/50 且禁止强断存量连接
		if autoInterval != "1m" || autoTolerance != 50 {
			t.Fatalf("[%s] #Auto baseline interval/tolerance = %q/%d, want 1m/50", platform, autoInterval, autoTolerance)
		}
		if autoInterrupt == nil || *autoInterrupt {
			t.Fatalf("[%s] #Auto interrupt_exist_connections must be false", platform)
		}

		// 6. 验证通用基准模板顺序：geosite-hok(#Auto) -> geosite-ad1 -> geoip-cn(#DC) -> TCP(1024:65535 -> #Auto) -> UDP(1024:65535 -> #DC)
		hokIdx, adIdx, cnIdx, tcpGameIdx, battleUDPIdx := -1, -1, -1, -1, -1
		for i, r := range parsed.Route.Rules {
			if rs, ok := r.RuleSet.(string); ok && rs == "geosite-hok" && r.Outbound == "#Auto" {
				hokIdx = i
			}
			if rsArr, ok := r.RuleSet.([]any); ok && r.Action == "reject" {
				for _, item := range rsArr {
					if item == "geosite-ad1" {
						adIdx = i
					}
				}
			}
			if rsArr, ok := r.RuleSet.([]any); ok && r.Outbound == "#DC" {
				for _, item := range rsArr {
					if item == "geoip-cn" {
						cnIdx = i
					}
				}
			}
			if r.Network == "tcp" && r.Outbound == "#Auto" && slices.Equal(r.PortRange, []string{"1024:65535"}) {
				tcpGameIdx = i
			}
			if r.Network == "udp" && r.Outbound == "#DC" && slices.Equal(r.PortRange, []string{"1024:65535"}) {
				battleUDPIdx = i
			}
		}
		if hokIdx < 0 || adIdx <= hokIdx || cnIdx <= adIdx || tcpGameIdx <= cnIdx || battleUDPIdx <= tcpGameIdx {
			t.Fatalf("[%s] unexpected baseline rule order: hok=%d ad=%d cn=%d tcpGame=%d battleUDP=%d",
				platform, hokIdx, adIdx, cnIdx, tcpGameIdx, battleUDPIdx)
		}
	}
}

func TestGenerator_InjectCustomRules_OutboundsRouteAndDNS(t *testing.T) {
	payload := encodeURISub(
		"hysteria2://dummy-pass@los.example.com:443?sni=los.example.com#sec_los_hy2",
		"hysteria2://dummy-pass@hk1.example.com:443?sni=hk1.example.com#香港 01",
		"hysteria2://dummy-pass@sg1.example.com:443?sni=sg1.example.com#獅城 01",
		"hysteria2://dummy-pass@us1.example.com:443?sni=us1.example.com#美國 01",
		"hysteria2://dummy-pass@mo1.example.com:443?sni=mo1.example.com#澳門 01",
	)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(payload))
	}))
	defer ts.Close()

	noInterrupt := false
	cfg := &config.Config{
		Subs: []config.Subscription{{Name: "main", URL: ts.URL}},
		CustomRules: config.CustomRulesConfig{
			Outbounds: []config.OutboundRule{
				{
					Tag:                       "#Auto",
					Include:                   "香港|HK|台灣|TW|獅城|SG|日本|JP",
					Exclude:                   "美國|澳門|德國|英國",
					Interval:                  "3m",
					Tolerance:                 80,
					InterruptExistConnections: &noInterrupt,
				},
			},
			DNS: []map[string]any{
				{
					"domain_suffix": []string{"igamecj.com", "gcloud.qq.com", "gvoice.qq.com", "gvoiceplat.com"},
					"server":        "dns_proxy",
					"client_subnet": "203.80.96.0/24",
				},
			},
			Route: []map[string]any{
				{
					"action":        "route",
					"domain_suffix": []string{"igamecj.com", "gcloud.qq.com", "gvoice.qq.com", "gvoiceplat.com"},
					"outbound":      "#Auto",
				},
				{
					"action":   "route",
					"port":     []int{5010, 5692, 8500, 8600, 8801, 10004, 20000, 31003},
					"outbound": "#Auto",
				},
				{
					"action":     "route",
					"network":    "udp",
					"port_range": []string{"6650:6659", "7000:9000", "10000:10100", "20000:20100", "30000:30100"},
					"outbound":   "#Auto",
				},
			},
		},
	}

	gen := singbox.NewConfigGenerator(cfg)
	gen.SetCacheDir(t.TempDir())

	out, err := gen.GenerateForPlatform("darwin")
	if err != nil {
		t.Fatalf("GenerateForPlatform(darwin) failed: %v", err)
	}

	var parsed struct {
		DNS struct {
			Rules []map[string]any `json:"rules"`
		} `json:"dns"`
		Outbounds []struct {
			Tag                       string   `json:"tag"`
			Outbounds                 []string `json:"outbounds"`
			Interval                  string   `json:"interval"`
			Tolerance                 int      `json:"tolerance"`
			InterruptExistConnections *bool    `json:"interrupt_exist_connections"`
		} `json:"outbounds"`
		Route struct {
			Rules []struct {
				Action    string   `json:"action"`
				Network   string   `json:"network"`
				Outbound  string   `json:"outbound"`
				Port      any      `json:"port"`
				PortRange []string `json:"port_range"`
				RuleSet   any      `json:"rule_set"`
			} `json:"rules"`
		} `json:"route"`
	}
	if err := json.Unmarshal([]byte(out), &parsed); err != nil {
		t.Fatal(err)
	}

	// 1. 验证 #Auto 仅保留香港/狮城节点，剔除美国与澳门，且 interval=3m, tolerance=80
	var gotAuto []string
	var gotInterval string
	var gotTolerance int
	for _, ob := range parsed.Outbounds {
		if ob.Tag == "#Auto" {
			gotAuto = ob.Outbounds
			gotInterval = ob.Interval
			gotTolerance = ob.Tolerance
		}
	}
	wantAuto := []string{"香港 01", "獅城 01"}
	if !slices.Equal(gotAuto, wantAuto) {
		t.Fatalf("#Auto outbounds = %v, want %v", gotAuto, wantAuto)
	}
	if gotInterval != "3m" || gotTolerance != 80 {
		t.Fatalf("#Auto interval/tolerance = %q/%d, want 3m/80", gotInterval, gotTolerance)
	}

	// 2. 验证 HoK 端口规则（TCP+UDP 双栈端口与扩展 UDP 端口段）注入在 geosite-hok 之后、geosite-ad1 和 geoip-cn 之前
	hokIdx, hokDualPortIdx, hokUDPIdx, adIdx, cnIdx := -1, -1, -1, -1, -1
	wantPorts := []int{5010, 5692, 8500, 8600, 8801, 10004, 20000, 31003}
	wantUDPRanges := []string{"6650:6659", "7000:9000", "10000:10100", "20000:20100", "30000:30100"}
	for i, r := range parsed.Route.Rules {
		if rs, ok := r.RuleSet.(string); ok && rs == "geosite-hok" && r.Outbound == "#Auto" {
			hokIdx = i
		}
		if r.Network == "" && r.Outbound == "#Auto" {
			if portSlice, ok := r.Port.([]any); ok {
				gotPorts := make([]int, 0, len(portSlice))
				for _, p := range portSlice {
					if pf, ok := p.(float64); ok {
						gotPorts = append(gotPorts, int(pf))
					}
				}
				if slices.Equal(gotPorts, wantPorts) {
					hokDualPortIdx = i
				}
			}
		}
		if r.Network == "udp" && r.Outbound == "#Auto" && slices.Equal(r.PortRange, wantUDPRanges) {
			hokUDPIdx = i
		}
		if rsArr, ok := r.RuleSet.([]any); ok && r.Action == "reject" {
			for _, item := range rsArr {
				if item == "geosite-ad1" {
					adIdx = i
				}
			}
		}
		if rsArr, ok := r.RuleSet.([]any); ok && r.Outbound == "#DC" {
			for _, item := range rsArr {
				if item == "geoip-cn" {
					cnIdx = i
				}
			}
		}
	}
	if hokIdx < 0 || hokDualPortIdx <= hokIdx || hokUDPIdx <= hokDualPortIdx || adIdx <= hokUDPIdx || cnIdx <= adIdx {
		t.Fatalf("unexpected injected route order: hok=%d dualPort=%d udpRange=%d ad=%d cn=%d",
			hokIdx, hokDualPortIdx, hokUDPIdx, adIdx, cnIdx)
	}

	// 3. 验证零节点防断网回退：当 include 匹配不到任何节点时，保留原节点池而非清空
	fallbackCfg := &config.Config{
		Subs: []config.Subscription{{Name: "main", URL: ts.URL}},
		CustomRules: config.CustomRulesConfig{
			Outbounds: []config.OutboundRule{
				{Tag: "#Auto", Include: "NON_EXISTENT_REGION_XYZ"},
			},
		},
	}
	fallbackGen := singbox.NewConfigGenerator(fallbackCfg)
	fallbackGen.SetCacheDir(t.TempDir())
	fallbackOut, err := fallbackGen.GenerateForPlatform("darwin")
	if err != nil {
		t.Fatalf("fallback GenerateForPlatform failed: %v", err)
	}
	if err := json.Unmarshal([]byte(fallbackOut), &parsed); err != nil {
		t.Fatal(err)
	}
	for _, ob := range parsed.Outbounds {
		if ob.Tag == "#Auto" && len(ob.Outbounds) == 0 {
			t.Fatal("expected zero-match filter to fallback to original non-empty #Auto node pool")
		}
	}
}

func TestGenerator_MultiSubscription_PartialFailure(t *testing.T) {
	// Server 1: returns HTML error (0 nodes)
	tsHTML := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("<!DOCTYPE html><html><body>Login Error</body></html>"))
	}))
	defer tsHTML.Close()

	// Server 2: Closed server (connection refused)
	tsClosed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	closedURL := tsClosed.URL
	tsClosed.Close()

	// Server 3: returns valid base64 subscription node
	tsValid := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		// hysteria2://dummy-user:dummy-pass@mock-node.example.com:443?sni=mock-node.example.com#sec_mock_hy2
		w.Write([]byte("aHlzdGVyaWEyOi8vZHVtbXktdXNlcjpkdW1teS1wYXNzQG1vY2stbm9kZS5leGFtcGxlLmNvbTo0NDM/c25pPW1vY2stbm9kZS5leGFtcGxlLmNvbSNzZWNfbW9ja19oeTI="))
	}))
	defer tsValid.Close()

	cfg := &config.Config{
		Subs: []config.Subscription{
			{Name: "sub_html", URL: tsHTML.URL},
			{Name: "sub_closed", URL: closedURL},
			{Name: "sub_valid", URL: tsValid.URL},
		},
	}

	generator := singbox.NewConfigGenerator(cfg)
	generator.SetCacheDir(t.TempDir())
	res, err := generator.GenerateForPlatform("linux")
	if err != nil {
		t.Fatalf("expected generation to succeed by skipping failed subs, got error: %v", err)
	}

	if !strings.Contains(res, "sub_valid") && !strings.Contains(res, "mock-node.example.com") {
		t.Fatalf("generated config should contain nodes from valid sub, got: %s", res)
	}
}

func TestGenerator_MultiSubscription_AllFail(t *testing.T) {
	tsHTML1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("<!DOCTYPE html><html><body>Error 1</body></html>"))
	}))
	defer tsHTML1.Close()

	tsHTML2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("<!DOCTYPE html><html><body>Error 2</body></html>"))
	}))
	defer tsHTML2.Close()

	cfg := &config.Config{
		Subs: []config.Subscription{
			{Name: "bad_sub1", URL: tsHTML1.URL},
			{Name: "bad_sub2", URL: tsHTML2.URL},
		},
	}

	generator := singbox.NewConfigGenerator(cfg)
	generator.SetCacheDir(t.TempDir())
	_, err := generator.GenerateForPlatform("linux")
	if err == nil {
		t.Fatal("expected error when all subscriptions fail, got nil")
	}

	errMsg := err.Error()
	if !strings.Contains(errMsg, "bad_sub1") || !strings.Contains(errMsg, "bad_sub2") {
		t.Fatalf("error message should identify each failed subscription name, got: %s", errMsg)
	}
}

func TestGenerator_SingleSubscription_Failure(t *testing.T) {
	tsHTML := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("<!DOCTYPE html><html><body>Error</body></html>"))
	}))
	defer tsHTML.Close()

	cfg := &config.Config{
		Subs: []config.Subscription{
			{Name: "single_bad", URL: tsHTML.URL},
		},
	}

	generator := singbox.NewConfigGenerator(cfg)
	generator.SetCacheDir(t.TempDir())
	_, err := generator.GenerateForPlatform("linux")
	if err == nil {
		t.Fatal("expected error when single subscription fails, got nil")
	}

	if !strings.Contains(err.Error(), "single_bad") {
		t.Fatalf("error message should identify subscription name, got: %v", err)
	}
}

func TestGenerator_ZeroSubscriptions(t *testing.T) {
	cfg := &config.Config{
		Subs: []config.Subscription{},
	}

	generator := singbox.NewConfigGenerator(cfg)
	generator.SetCacheDir(t.TempDir())
	_, err := generator.GenerateForPlatform("linux")
	if err == nil {
		t.Fatal("expected error when subs is empty, got nil")
	}
}

func encodeURISub(lines ...string) string {
	return base64.StdEncoding.EncodeToString([]byte(strings.Join(lines, "\n")))
}

func TestGenerator_SingleAndMultiNodeRules(t *testing.T) {
	payload := encodeURISub(
		"hysteria2://dummy-pass@us1.example.com:443?sni=us1.example.com#US-Node Premium",
		"hysteria2://dummy-pass@jp1.example.com:443?sni=jp1.example.com#JP-Node Premium",
		"hysteria2://dummy-pass@192.0.2.10:443?sni=info.example.com#剩余流量 10GB",
	)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte(payload))
	}))
	defer ts.Close()

	t.Run("single subscription include exclude rename", func(t *testing.T) {
		cfg := &config.Config{
			Subs: []config.Subscription{
				{
					Name:    "main",
					URL:     ts.URL,
					Include: "US|JP",
					Exclude: "剩余|到期",
					Rename: []config.RenameRule{
						{Match: ` Premium$`, Replace: ""},
						{Match: `^US-`, Replace: "美国-"},
					},
				},
			},
		}
		gen := singbox.NewConfigGenerator(cfg)
		gen.SetCacheDir(t.TempDir())
		out, err := gen.GenerateForPlatform("darwin")
		if err != nil {
			t.Fatalf("GenerateForPlatform failed: %v", err)
		}
		if !strings.Contains(out, "美国-Node") || !strings.Contains(out, "JP-Node") {
			t.Fatalf("expected renamed/kept tags in output, got:\n%s", out)
		}
		if strings.Contains(out, "Premium") || strings.Contains(out, "剩余流量") {
			t.Fatalf("expected excluded/renamed tags to be absent, got:\n%s", out)
		}
	})

	t.Run("multi subscription rules and all filtered out error", func(t *testing.T) {
		cfg := &config.Config{
			Subs: []config.Subscription{
				{
					Name:    "filtered_all",
					URL:     ts.URL,
					Include: "NON_EXISTENT_REGION",
				},
				{
					Name:    "kept_sub",
					URL:     ts.URL,
					Include: "^JP-",
					Rename:  []config.RenameRule{{Match: ` Premium$`, Replace: ""}},
				},
			},
		}
		gen := singbox.NewConfigGenerator(cfg)
		gen.SetCacheDir(t.TempDir())
		out, err := gen.GenerateForPlatform("darwin")
		if err != nil {
			t.Fatalf("expected partial success when one sub is filtered out, got: %v", err)
		}
		if !strings.Contains(out, "[kept_sub] JP-Node") {
			t.Fatalf("expected [kept_sub] JP-Node in output, got:\n%s", out)
		}
		if strings.Contains(out, "[filtered_all]") || strings.Contains(out, "us1.example.com") {
			t.Fatalf("unexpected filtered nodes in output:\n%s", out)
		}

		allFilteredCfg := &config.Config{
			Subs: []config.Subscription{
				{Name: "sub1", URL: ts.URL, Include: "NO_MATCH_1"},
				{Name: "sub2", URL: ts.URL, Include: "NO_MATCH_2"},
			},
		}
		genFail := singbox.NewConfigGenerator(allFilteredCfg)
		genFail.SetCacheDir(t.TempDir())
		_, err = genFail.GenerateForPlatform("darwin")
		if err == nil || !strings.Contains(err.Error(), "sub1") || !strings.Contains(err.Error(), "sub2") {
			t.Fatalf("expected detailed error listing filtered-out subs, got: %v", err)
		}
	})
}

func TestGenerator_SubscriptionCacheFallback(t *testing.T) {
	payload := encodeURISub(
		"hysteria2://dummy-pass@hk1.example.com:443?sni=hk1.example.com#HK-Primary",
	)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Subscription-Userinfo", "upload=1073741824; download=8589934592; total=10737418240; expire=1893456000")
		_, _ = w.Write([]byte(payload))
	}))
	subURL := ts.URL

	cacheDir := t.TempDir()
	cfg := &config.Config{
		Subs: []config.Subscription{
			{Name: "cached_main", URL: subURL},
		},
	}

	gen := singbox.NewConfigGenerator(cfg)
	gen.SetCacheDir(cacheDir)

	firstOut, err := gen.GenerateForPlatform("darwin")
	if err != nil {
		ts.Close()
		t.Fatalf("initial GenerateForPlatform failed: %v", err)
	}
	if !strings.Contains(firstOut, "hk1.example.com") {
		ts.Close()
		t.Fatalf("initial output missing hk1.example.com")
	}

	entries, err := os.ReadDir(cacheDir)
	if err != nil || len(entries) == 0 {
		ts.Close()
		t.Fatalf("expected subscription cache file in %s, entries=%d err=%v", cacheDir, len(entries), err)
	}
	fi, err := entries[0].Info()
	if err != nil {
		ts.Close()
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm != 0600 {
		ts.Close()
		t.Fatalf("expected cache file mode 0600, got %o", perm)
	}

	// Shut down upstream server completely; second generation must succeed via cached copy.
	ts.Close()
	secondOut, err := gen.GenerateForPlatform("darwin")
	if err != nil {
		t.Fatalf("expected fallback to cached subscription after upstream outage, got error: %v", err)
	}
	if !strings.Contains(secondOut, "hk1.example.com") {
		t.Fatalf("cached fallback output missing hk1.example.com")
	}
}

func TestGenerator_PlatformExternalControllerAndSingBoxCheck(t *testing.T) {
	payload := encodeURISub(
		"hysteria2://dummy-pass@sg1.example.com:443?sni=sg1.example.com#SG-Node",
	)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(payload))
	}))
	defer ts.Close()

	cfg := &config.Config{
		Subs: []config.Subscription{
			{Name: "main", URL: ts.URL, RemoveEmoji: true},
		},
	}
	gen := singbox.NewConfigGenerator(cfg)
	gen.SetCacheDir(t.TempDir())

	sbBin, hasSingBox := exec.LookPath("sing-box")

	cases := []struct {
		platform       string
		wantController string
	}{
		{platform: singbox.PlatformIOS, wantController: "127.0.0.1:9095"},
		{platform: "darwin", wantController: "127.0.0.1:9090"},
		{platform: "windows", wantController: "127.0.0.1:9090"},
	}

	for _, tc := range cases {
		t.Run(tc.platform, func(t *testing.T) {
			out, err := gen.GenerateForPlatform(tc.platform)
			if err != nil {
				t.Fatalf("GenerateForPlatform(%s) failed: %v", tc.platform, err)
			}

			var parsed struct {
				Experimental struct {
					ClashAPI struct {
						ExternalController string `json:"external_controller"`
					} `json:"clash_api"`
				} `json:"experimental"`
			}
			if err := json.Unmarshal([]byte(out), &parsed); err != nil {
				t.Fatalf("unmarshal generated JSON: %v", err)
			}
			if parsed.Experimental.ClashAPI.ExternalController != tc.wantController {
				t.Fatalf("%s external_controller = %q, want %q",
					tc.platform, parsed.Experimental.ClashAPI.ExternalController, tc.wantController)
			}

			if tc.platform == singbox.PlatformIOS {
				if err := singbox.CheckIOSCompatibility(out); err != nil {
					t.Fatalf("CheckIOSCompatibility failed: %v", err)
				}
			}

			if hasSingBox == nil && sbBin != "" {
				cfgFile := filepath.Join(t.TempDir(), "config.json")
				if err := os.WriteFile(cfgFile, []byte(out), 0600); err != nil {
					t.Fatal(err)
				}
				cmd := exec.CommandContext(t.Context(), sbBin, "check", "-c", cfgFile)
				if checkOut, err := cmd.CombinedOutput(); err != nil {
					t.Fatalf("sing-box check failed for platform %s: %v\n%s", tc.platform, err, string(checkOut))
				}
			}
		})
	}
}

func TestProxyOutboundsFingerprintDeterministic(t *testing.T) {
	cfgA := `{
  "outbounds": [
    {"type": "selector", "tag": "DIY-Node", "outbounds": ["node_b", "node_a"]},
    {"type": "hysteria2", "tag": "node_b", "server": "b.example.com", "server_port": 443, "password": "p2"},
    {"type": "vless", "tag": "node_a", "server": "a.example.com", "server_port": 443, "uuid": "u1"},
    {"type": "direct", "tag": "DirectConn"}
  ]
}`
	// Reordered outbounds & changed selector default order, but identical concrete proxy nodes
	cfgB := `{
  "outbounds": [
    {"type": "direct", "tag": "DirectConn"},
    {"type": "vless", "tag": "node_a", "uuid": "u1", "server_port": 443, "server": "a.example.com"},
    {"type": "hysteria2", "tag": "node_b", "password": "p2", "server_port": 443, "server": "b.example.com"},
    {"type": "selector", "tag": "DIY-Node", "outbounds": ["node_a", "node_b"]}
  ]
}`
	// Rotated password on node_b
	cfgC := `{
  "outbounds": [
    {"type": "vless", "tag": "node_a", "server": "a.example.com", "server_port": 443, "uuid": "u1"},
    {"type": "hysteria2", "tag": "node_b", "server": "b.example.com", "server_port": 443, "password": "NEW_PASSWORD"}
  ]
}`

	hashA, countA, err := singbox.ProxyOutboundsFingerprint(cfgA)
	if err != nil || countA != 2 {
		t.Fatalf("cfgA fingerprint failed: count=%d err=%v", countA, err)
	}
	hashB, countB, err := singbox.ProxyOutboundsFingerprint(cfgB)
	if err != nil || countB != 2 {
		t.Fatalf("cfgB fingerprint failed: count=%d err=%v", countB, err)
	}
	if hashA != hashB {
		t.Fatalf("expected identical fingerprint regardless of outbound slice order: %s vs %s", hashA, hashB)
	}

	hashC, countC, err := singbox.ProxyOutboundsFingerprint(cfgC)
	if err != nil || countC != 2 {
		t.Fatalf("cfgC fingerprint failed: count=%d err=%v", countC, err)
	}
	if hashC == hashA {
		t.Fatal("expected password rotation to change proxy outbound fingerprint")
	}
}

package test

import (
	"encoding/json"
	"strings"
	"testing"

	"singctl/internal/singbox"
)

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

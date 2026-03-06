package test

import (
	"encoding/json"
	"strings"
	"testing"

	"singctl/internal/singbox"
)

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

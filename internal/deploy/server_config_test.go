package deploy

import (
	"encoding/json"
	"testing"
)

func TestServerConfigTemplate_RejectsPrivateIPs(t *testing.T) {
	raw, err := templateFiles.ReadFile("templates/server_config.json")
	if err != nil {
		t.Fatalf("read server_config.json: %v", err)
	}

	var parsed struct {
		Route struct {
			Rules []map[string]any `json:"rules"`
		} `json:"route"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatalf("server_config.json is invalid JSON: %v", err)
	}

	foundPrivateReject := false
	for _, rule := range parsed.Route.Rules {
		ipPrivate, ok := rule["ip_is_private"].(bool)
		if !ok || !ipPrivate {
			continue
		}
		if rule["outbound"] != nil {
			t.Fatalf("ip_is_private rule must not route to outbound %v (SSRF/loopback bypass risk)", rule["outbound"])
		}
		if rule["action"] != "reject" {
			t.Fatalf("expected ip_is_private rule action='reject', got %v", rule["action"])
		}
		foundPrivateReject = true
	}

	if !foundPrivateReject {
		t.Fatal("server_config.json must include an ip_is_private reject rule")
	}
}

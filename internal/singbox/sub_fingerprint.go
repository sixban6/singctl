package singbox

import (
	"bytes"
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"
)

// ProxyOutboundsFingerprint extracts all concrete proxy outbounds from a sing-box JSON config
// (excluding structural selector/urltest/direct/block/dns entries), sorts them deterministically,
// and returns a canonical SHA-256 hex digest along with the concrete proxy outbound count.
func ProxyOutboundsFingerprint(configJSON string) (hash string, proxyCount int, err error) {
	var root struct {
		Outbounds []map[string]any `json:"outbounds"`
	}
	if err := json.Unmarshal([]byte(configJSON), &root); err != nil {
		return "", 0, fmt.Errorf("parse sing-box config outbounds: %w", err)
	}

	proxies := make([]map[string]any, 0, len(root.Outbounds))
	for _, ob := range root.Outbounds {
		typ, _ := ob["type"].(string)
		switch strings.ToLower(strings.TrimSpace(typ)) {
		case "", "selector", "urltest", "direct", "block", "dns":
			continue
		default:
			proxies = append(proxies, ob)
		}
	}

	slices.SortFunc(proxies, func(a, b map[string]any) int {
		tagA, _ := a["tag"].(string)
		tagB, _ := b["tag"].(string)
		return cmp.Compare(tagA, tagB)
	})

	canonical, err := json.Marshal(proxies)
	if err != nil {
		return "", 0, fmt.Errorf("canonicalize proxy outbounds: %w", err)
	}
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:]), len(proxies), nil
}

type clashProxiesResp struct {
	Proxies map[string]struct {
		Type string   `json:"type"`
		Now  string   `json:"now"`
		All  []string `json:"all"`
	} `json:"proxies"`
}

// SnapshotClashSelections queries the local Clash API (if reachable) and captures
// each Selector group's currently active outbound choice before a config reload.
func SnapshotClashSelections() map[string]string {
	client := &http.Client{Timeout: 2 * time.Second}
	secret := ClashAPISecret()

	for _, base := range ClashAPIEndpoints() {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, base+"/proxies", nil)
		if err != nil {
			continue
		}
		if secret != "" {
			req.Header.Set("Authorization", "Bearer "+secret)
		}
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		var parsed clashProxiesResp
		decErr := json.NewDecoder(resp.Body).Decode(&parsed)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK || decErr != nil {
			continue
		}

		selections := make(map[string]string)
		for name, p := range parsed.Proxies {
			if strings.EqualFold(p.Type, "Selector") && strings.TrimSpace(p.Now) != "" {
				selections[name] = p.Now
			}
		}
		return selections
	}
	return nil
}

// RestoreClashSelections restores previously captured Selector choices via the Clash API
// for any group whose selected outbound tag still exists in the reloaded configuration.
func RestoreClashSelections(selections map[string]string) {
	if len(selections) == 0 {
		return
	}
	client := &http.Client{Timeout: 2 * time.Second}
	secret := ClashAPISecret()

	for _, base := range ClashAPIEndpoints() {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, base+"/proxies", nil)
		if err != nil {
			continue
		}
		if secret != "" {
			req.Header.Set("Authorization", "Bearer "+secret)
		}
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		var parsed clashProxiesResp
		decErr := json.NewDecoder(resp.Body).Decode(&parsed)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK || decErr != nil {
			continue
		}

		for group, desired := range selections {
			cur, exists := parsed.Proxies[group]
			if !exists || cur.Now == desired || !slices.Contains(cur.All, desired) {
				continue
			}
			body, _ := json.Marshal(map[string]string{"name": desired})
			putURL := base + "/proxies/" + url.PathEscape(group)
			putReq, err := http.NewRequestWithContext(context.Background(), http.MethodPut, putURL, bytes.NewReader(body))
			if err != nil {
				continue
			}
			putReq.Header.Set("Content-Type", "application/json")
			if secret != "" {
				putReq.Header.Set("Authorization", "Bearer "+secret)
			}
			if putResp, err := client.Do(putReq); err == nil {
				_ = putResp.Body.Close()
			}
		}
		return
	}
}

// 文件职责：验证客户端 WebUI 统一 /api/dns/* 三引擎接口、dns-switch 流式动作、状态摘要双字段兼容及 V2 备份三引擎自适配。
package webui_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"singctl/internal/adguard"
	"singctl/internal/common/sysinfo"
	"singctl/internal/config"
	"singctl/internal/constant"
	"singctl/internal/localdns"
	"singctl/internal/platform/servicemgr"
	"singctl/internal/singbox"
	"singctl/internal/webui"
)

func TestWebUI_UnifiedDNSAPI_SingBoxAndEngineSwitch(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "singctl.yaml")
	sbPath := filepath.Join(tmpDir, "config.json")
	smartBin := filepath.Join(tmpDir, "smartdns")
	smartConf := filepath.Join(tmpDir, "smartdns.conf")
	smartRules := filepath.Join(tmpDir, "smartdns-rules.d")

	sbRaw := `{
  "dns": {
    "servers": [
      {"tag": "dns_local", "type": "https", "server": "223.5.5.5", "server_port": 443, "path": "/dns-query"}
    ],
    "rules": [
      {"rule_set": ["geosite-ad1", "geosite-ad2"], "action": "reject"}
    ]
  },
  "route": {
    "rule_set": [
      {"tag": "geosite-ad1", "type": "remote", "format": "binary", "url": "https://example.com/ad1.srs"},
      {"tag": "geosite-ad2", "type": "remote", "format": "binary", "url": "https://example.com/ad2.srs"}
    ],
    "rules": [
      {"rule_set": ["geosite-ad1", "geosite-ad2"], "action": "reject"}
    ]
  }
}`
	if err := os.WriteFile(sbPath, []byte(sbRaw), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(smartBin, []byte("#!/bin/sh\necho 'smartdns 1.2025.46'\n"), 0755); err != nil {
		t.Fatal(err)
	}

	cfg := &config.Config{
		DNS: config.ClientDNSConfig{
			Engine: constant.DNSEngineSingBox,
		},
	}
	if err := config.Save(cfgPath, cfg); err != nil {
		t.Fatal(err)
	}

	mockSvc := servicemgr.NewMock()
	const mib = 1024 * 1024

	srv := webui.New(webui.Options{
		ConfigPath:              cfgPath,
		SingBoxConfigPath:       sbPath,
		AdGuardBinPath:          filepath.Join(tmpDir, "missing-agh"),
		AdGuardConfigPath:       filepath.Join(tmpDir, "missing-agh.yaml"),
		SmartDNSBinPath:         smartBin,
		SmartDNSConfigPath:      smartConf,
		SmartDNSRulesDir:        smartRules,
		SmartDNSAuditLogPath:    filepath.Join(tmpDir, "smartdns-audit.log"),
		LocalDNSServiceMgr:      mockSvc,
		SkipAdGuardProbeForTest: true,
		AdGuardMemInfoForTest: func() sysinfo.MemInfo {
			return sysinfo.MemInfo{TotalBytes: 491040 * 1024, AvailableBytes: 210260 * 1024}
		},
		DiskSpaceForTest: func(string) (sysinfo.DiskSpace, error) {
			return sysinfo.DiskSpace{AvailBytes: 50 * mib}, nil
		},
		LocalDNSProbeDNSForTest: func(string, time.Duration) error { return nil },
		LocalDNSProbeResForTest: func(string, string, time.Duration) ([]string, time.Duration, error) {
			return []string{"192.0.2.1"}, 5 * time.Millisecond, nil
		},
		LocalDNSSyncSingBoxEnhancedForTest: func(_ context.Context, p, _ string, dnsCfg config.ClientDNSConfig, subs []string, now time.Time) (bool, error) {
			raw, _ := os.ReadFile(p)
			out, changed, err := singbox.ApplyEnhancedSingBoxDNSJSON(string(raw), dnsCfg, subs, now)
			if err == nil && changed {
				_ = os.WriteFile(p, []byte(out), 0600)
			}
			return changed, err
		},
		LocalDNSSyncSingBoxDNSLocalForTest: func(_ context.Context, p, _ string, useExternal bool, port int) (bool, error) {
			raw, _ := os.ReadFile(p)
			out, changed, err := singbox.PatchDNSLocalJSON(string(raw), useExternal, port)
			if err == nil && changed {
				_ = os.WriteFile(p, []byte(out), 0600)
			}
			return changed, err
		},
		DNSProbeUpstreamForTest: func(_ context.Context, upstreams []string, _ string, _ time.Duration) []adguard.UpstreamProbeItem {
			out := make([]adguard.UpstreamProbeItem, len(upstreams))
			for i, u := range upstreams {
				out[i] = adguard.UpstreamProbeItem{Address: u, Name: u, Protocol: "DoH", Healthy: true, LatencyMs: int64(15 + i*5), Resolved: "192.0.2.1"}
			}
			return out
		},
	})

	doReq := func(method, path string, payload any) *httptest.ResponseRecorder {
		t.Helper()
		var body []byte
		if payload != nil {
			body, _ = json.Marshal(payload)
		}
		req := httptest.NewRequest(method, path, bytes.NewReader(body))
		if method != http.MethodGet {
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Requested-With", "SingCtlWebUI")
		}
		rec := httptest.NewRecorder()
		srv.Mux.ServeHTTP(rec, req)
		return rec
	}

	// 1. GET /api/dns/overview returns singbox active + n60pro recommends smartdns
	rec := doReq(http.MethodGet, "/api/dns/overview", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/dns/overview code=%d body=%s", rec.Code, rec.Body.String())
	}
	var ov localdns.OverviewSnapshot
	if err := json.Unmarshal(rec.Body.Bytes(), &ov); err != nil {
		t.Fatal(err)
	}
	if ov.ActiveEngine != constant.DNSEngineSingBox || !ov.Installed || ov.RecommendedEngine != constant.DNSEngineSmartDNS || len(ov.Engines) != 3 {
		t.Fatalf("unexpected overview: active=%q installed=%v rec=%q engines=%d", ov.ActiveEngine, ov.Installed, ov.RecommendedEngine, len(ov.Engines))
	}

	// 2. GET /api/dns/config-preview
	rec = doReq(http.MethodGet, "/api/dns/config-preview", nil)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "dns_local") {
		t.Fatalf("GET /api/dns/config-preview code=%d body=%s", rec.Code, rec.Body.String())
	}

	// 3. POST /api/dns/block-aaaa
	rec = doReq(http.MethodPost, "/api/dns/block-aaaa", map[string]any{"enabled": true})
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"blockAAAA":true`) {
		t.Fatalf("POST /api/dns/block-aaaa code=%d body=%s", rec.Code, rec.Body.String())
	}

	// 4. GET /api/status returns BOTH "dns" and "adguard" summaries
	rec = doReq(http.MethodGet, "/api/status", nil)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"dns"`) || !strings.Contains(rec.Body.String(), `"adguard"`) {
		t.Fatalf("GET /api/status missing dns/adguard: %s", rec.Body.String())
	}

	// 5. POST /api/dns/engine switch singbox -> smartdns
	rec = doReq(http.MethodPost, "/api/dns/engine", map[string]any{"engine": "smartdns"})
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /api/dns/engine code=%d body=%s", rec.Code, rec.Body.String())
	}
	var swRes localdns.SwitchResult
	if err := json.Unmarshal(rec.Body.Bytes(), &swRes); err != nil {
		t.Fatal(err)
	}
	if !swRes.OK || swRes.ActiveEngine != constant.DNSEngineSmartDNS || swRes.Overview == nil {
		t.Fatalf("unexpected switch response: %+v", swRes)
	}

	// 6. Action builder supports dns-switch and --engine on dns-install
	swArgs := webui.DnsSwitchArgs(map[string]any{"engine": "smartdns", "forceLowMemory": true})
	if strings.Join(swArgs, " ") != "dns switch --engine smartdns --force-low-memory" {
		t.Fatalf("unexpected DnsSwitchArgs: %v", swArgs)
	}
	instArgs := webui.DnsInstallArgs(map[string]any{"engine": "smartdns"})
	if !strings.Contains(strings.Join(instArgs, " "), "--engine smartdns") {
		t.Fatalf("expected --engine smartdns in DnsInstallArgs, got %v", instArgs)
	}
}

func TestWebUI_BackupV2_SmartDNSSelfAdaptation(t *testing.T) {
	tmpDir := t.TempDir()
	srcCfg := filepath.Join(tmpDir, "src-singctl.yaml")
	srcSB := filepath.Join(tmpDir, "src-sb.json")
	srcSmartConf := filepath.Join(tmpDir, "src-smartdns.conf")

	_ = os.WriteFile(srcCfg, []byte("dns:\n  engine: smartdns\n  dns_port: 5353\n"), 0600)
	sbJSON := buildValidTestSingBoxWithAdGuardAndAd2(t, tmpDir, true, false)
	_ = os.WriteFile(srcSB, []byte(sbJSON), 0600)
	_ = os.WriteFile(srcSmartConf, []byte("bind 127.0.0.1:5353\nserver-https https://223.5.5.5/dns-query\n"), 0600)

	srcSrv := webui.New(webui.Options{
		ConfigPath:              srcCfg,
		SingBoxConfigPath:       srcSB,
		AdGuardConfigPath:       filepath.Join(tmpDir, "missing-agh.yaml"),
		SmartDNSConfigPath:      srcSmartConf,
		SkipAdGuardProbeForTest: true,
	})

	expRec := postBackupJSON(srcSrv, "/api/backup/export", map[string]any{
		"passphrase":      "BackupPass2026!",
		"includeRuleSets": false,
	})
	if expRec.Code != http.StatusOK {
		t.Fatalf("export failed: code=%d body=%s", expRec.Code, expRec.Body.String())
	}
	var expResp struct {
		Data    string `json:"data"`
		Summary struct {
			HasSmartDNS bool `json:"hasSmartDNS"`
		} `json:"summary"`
	}
	if err := json.Unmarshal(expRec.Body.Bytes(), &expResp); err != nil {
		t.Fatal(err)
	}
	if !expResp.Summary.HasSmartDNS {
		t.Fatalf("expected hasSmartDNS=true in backup export summary, body=%s", expRec.Body.String())
	}

	// Restore onto target machine WITH SmartDNS installed (and NO AdGuard) -> keeps 127.0.0.1:5353 and restores smartdns.conf!
	dstDir := filepath.Join(tmpDir, "dst-smartdns")
	_ = os.MkdirAll(dstDir, 0755)
	dstCfg := filepath.Join(dstDir, "singctl.yaml")
	dstSB := filepath.Join(dstDir, "config.json")
	dstSmartBin := filepath.Join(dstDir, "smartdns")
	dstSmartConf := filepath.Join(dstDir, "smartdns.conf")
	_ = os.WriteFile(dstSmartBin, []byte("#!/bin/sh\necho smartdns\n"), 0755)

	fakeBinDir := filepath.Join(tmpDir, "fake-bin")
	_ = os.MkdirAll(fakeBinDir, 0755)
	_ = os.WriteFile(filepath.Join(fakeBinDir, "sing-box"), []byte("#!/bin/sh\nexit 0\n"), 0755)
	t.Setenv("PATH", fakeBinDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	dstSrv := webui.New(webui.Options{
		ConfigPath:              dstCfg,
		SingBoxConfigPath:       dstSB,
		AdGuardBinPath:          filepath.Join(dstDir, "missing-agh"),
		AdGuardConfigPath:       filepath.Join(dstDir, "missing-agh.yaml"),
		SmartDNSBinPath:         dstSmartBin,
		SmartDNSConfigPath:      dstSmartConf,
		SkipAdGuardProbeForTest: true,
		AdGuardMemInfoForTest: func() sysinfo.MemInfo {
			return sysinfo.MemInfo{TotalBytes: 480 * 1024 * 1024, AvailableBytes: 205 * 1024 * 1024}
		},
	})

	resRec := postBackupJSON(dstSrv, "/api/backup/restore", map[string]any{
		"passphrase": "BackupPass2026!",
		"data":       expResp.Data,
	})
	if resRec.Code != http.StatusOK {
		t.Fatalf("restore failed: code=%d body=%s", resRec.Code, resRec.Body.String())
	}
	restoredConf, err := os.ReadFile(dstSmartConf)
	if err != nil || !strings.Contains(string(restoredConf), "server-https https://223.5.5.5/dns-query") {
		t.Fatalf("expected smartdns.conf restored, err=%v content=%s", err, string(restoredConf))
	}
	if linked, port := singbox.InspectSingBoxDNSLocal(dstSB); !linked || port != 5353 {
		t.Fatalf("expected dns_local preserved at 127.0.0.1:5353 when target has SmartDNS, got linked=%v port=%d", linked, port)
	}
}

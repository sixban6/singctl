// 文件职责：验证客户端网关配置 V2 加密灾备导出、离线规则集安全校验、跨硬件自适配与全事务原子回滚契约。
package webui_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"singctl/internal/common/sysinfo"
	"singctl/internal/config"
	"singctl/internal/singbox"
	"singctl/internal/webui"
)

type tarSpec struct {
	name     string
	body     []byte
	typeflag byte
	linkname string
}

func buildTestTarGz(t *testing.T, items []tarSpec) []byte {
	t.Helper()
	var buf bytes.Buffer
	gzw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gzw)
	for _, it := range items {
		tf := it.typeflag
		if tf == 0 {
			tf = tar.TypeReg
		}
		hdr := &tar.Header{
			Name:     it.name,
			Mode:     0600,
			Typeflag: tf,
			Linkname: it.linkname,
		}
		if tf == tar.TypeReg {
			hdr.Size = int64(len(it.body))
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("write tar header %s: %v", it.name, err)
		}
		if tf == tar.TypeReg && len(it.body) > 0 {
			if _, err := tw.Write(it.body); err != nil {
				t.Fatalf("write tar body %s: %v", it.name, err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gzw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func postBackupJSON(srv *webui.Server, path string, payload any) *httptest.ResponseRecorder {
	b, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Requested-With", "SingCtlWebUI")
	rec := httptest.NewRecorder()
	srv.Mux.ServeHTTP(rec, req)
	return rec
}

func buildValidTestSingBoxWithAdGuardAndAd2(t *testing.T, cacheDir string, useLocalAdGuard bool, includeAd2 bool) string {
	t.Helper()
	baseSB := buildValidTestSingBoxJSON(t, cacheDir)
	var doc map[string]any
	if err := json.Unmarshal([]byte(baseSB), &doc); err != nil {
		t.Fatal(err)
	}
	obs := doc["outbounds"].([]any)
	obs = append(obs, map[string]any{"type": "socks", "tag": "香港-01", "server": "198.51.100.41", "server_port": 1080})
	doc["outbounds"] = obs

	if useLocalAdGuard {
		dnsObj := doc["dns"].(map[string]any)
		srvs := dnsObj["servers"].([]any)
		srvs[0] = map[string]any{
			"tag":         "dns_local",
			"type":        "udp",
			"server":      "127.0.0.1",
			"server_port": 5353,
		}
		dnsObj["servers"] = srvs
	}
	if includeAd2 {
		dnsObj := doc["dns"].(map[string]any)
		dnsRules := dnsObj["rules"].([]any)
		dnsRules = append([]any{
			map[string]any{"rule_set": []string{"geosite-ad1", "geosite-ad2"}, "action": "reject"},
			map[string]any{"rule_set": "geosite-ad2", "action": "reject"},
		}, dnsRules...)
		dnsObj["rules"] = dnsRules

		routeObj := doc["route"].(map[string]any)
		rsList := routeObj["rule_set"].([]any)
		rsList = append(rsList, map[string]any{
			"tag":    "geosite-ad2",
			"type":   "remote",
			"format": "binary",
			"url":    "https://example.com/rules/geosite-ad2.srs",
		})
		routeObj["rule_set"] = rsList

		routeRules := routeObj["rules"].([]any)
		routeRules = append(routeRules,
			map[string]any{"action": "reject", "rule_set": []string{"geosite-ad1", "geosite-ad2"}},
			map[string]any{"action": "reject", "rule_set": "geosite-ad2"},
		)
		routeObj["rules"] = routeRules
	}

	b, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestClientBackupCrypto_V2RoundTripAndRejectsV1AndTamper(t *testing.T) {
	rsTar := buildTestTarGz(t, []tarSpec{
		{name: "geosite-cn.srs", body: []byte("SRS\x02dummy-cn")},
		{name: "manifest.json", body: []byte(`{"geosite-cn":{"url":"https://example.com/cn.srs"}}`)},
	})
	payload := webui.ClientBackupPayload{
		Version:         "1.14.200",
		ExportedAt:      "2026-11-22T12:00:00Z",
		SingctlYAML:     "subs:\n  - name: main\n    url: https://sub.example.com/api?token=testtoken\n",
		GroupsYAML:      "version: 1\nmode: merge\ngroups:\n  - name: \"#HK\"\n    type: urltest\n    match: [\"@hk\"]\n",
		SingBoxBaseJSON: `{"log":{"level":"warn"}}`,
		RuleSetsTarGz:   rsTar,
		RuleSetCount:    1,
	}

	if _, err := webui.EncryptClientBackupBundle("1234567", payload); err == nil {
		t.Fatal("expected passphrase < 8 chars to fail")
	}

	envBytes, err := webui.EncryptClientBackupBundle("GatewayPass#2026", payload)
	if err != nil {
		t.Fatalf("webui.EncryptClientBackupBundle failed: %v", err)
	}
	if strings.Contains(string(envBytes), "sub.example.com") || strings.Contains(string(envBytes), "testtoken") {
		t.Fatalf("encrypted envelope leaked plaintext secret")
	}

	var envMap map[string]any
	if err := json.Unmarshal(envBytes, &envMap); err != nil {
		t.Fatal(err)
	}
	if gotFmt, _ := envMap["format"].(string); gotFmt != "SINGCTL-CLIENT-BAK-V2" {
		t.Fatalf("expected format SINGCTL-CLIENT-BAK-V2, got %q", gotFmt)
	}

	if _, err := webui.DecryptClientBackupBundle("WrongPass#2026", envBytes); err == nil {
		t.Fatal("expected wrong passphrase to fail GCM auth")
	}

	// 验证篡改密文会被 GCM 认证拦截
	ct, _ := envMap["ciphertext"].(string)
	tampered := map[string]any{
		"format":     envMap["format"],
		"iterations": envMap["iterations"],
		"salt":       envMap["salt"],
		"nonce":      envMap["nonce"],
		"ciphertext": "AAAA" + ct[4:],
	}
	tamperedBytes, _ := json.Marshal(tampered)
	if _, err := webui.DecryptClientBackupBundle("GatewayPass#2026", tamperedBytes); err == nil {
		t.Fatal("expected tampered ciphertext to fail")
	}

	// 验证直接拒绝旧版 V1 客户端信封与服务端信封（零历史兼容）
	for _, oldFmt := range []string{"SINGCTL-CLIENT-BAK-V1", "SINGCTL-BAK-V1"} {
		oldBytes, _ := json.Marshal(map[string]any{
			"format":     oldFmt,
			"iterations": 210000,
			"salt":       envMap["salt"],
			"nonce":      envMap["nonce"],
			"ciphertext": envMap["ciphertext"],
		})
		if _, err := webui.DecryptClientBackupBundle("GatewayPass#2026", oldBytes); err == nil {
			t.Fatalf("expected format %q to be rejected", oldFmt)
		}
	}

	decoded, err := webui.DecryptClientBackupBundle("GatewayPass#2026", envBytes)
	if err != nil {
		t.Fatalf("webui.DecryptClientBackupBundle failed: %v", err)
	}
	if decoded.SingctlYAML != payload.SingctlYAML ||
		decoded.GroupsYAML != payload.GroupsYAML ||
		decoded.SingBoxBaseJSON != payload.SingBoxBaseJSON ||
		decoded.RuleSetCount != payload.RuleSetCount ||
		!bytes.Equal(decoded.RuleSetsTarGz, payload.RuleSetsTarGz) {
		t.Fatalf("decrypted V2 payload mismatch")
	}
}

func TestHandleClientBackup_V2ExportRuleSetsAndBaseSnapshot(t *testing.T) {
	srcDir := t.TempDir()
	srcCfgPath := filepath.Join(srcDir, "singctl.yaml")
	srcGroupsPath := filepath.Join(srcDir, "groups.yaml")
	srcAghPath := filepath.Join(srcDir, "AdGuardHome.yaml")
	srcSBDir := filepath.Join(srcDir, "sb")
	srcSBPath := filepath.Join(srcSBDir, "config.json")
	srcBasePath := singbox.BaseSnapshotPath(srcSBPath)
	srcRuleSetDir := filepath.Join(srcSBDir, "rule_sets")
	if err := os.MkdirAll(srcRuleSetDir, 0755); err != nil {
		t.Fatal(err)
	}

	sbJSON := buildValidTestSingBoxWithAdGuardAndAd2(t, srcSBDir, true, true)
	for p, data := range map[string][]byte{
		srcCfgPath:                                        []byte("subs:\n  - name: main\n    url: https://sub.example.com/client?token=testtoken123\n"),
		srcGroupsPath:                                     []byte("version: 1\nmode: merge\ngroups:\n  - name: \"#HK\"\n    type: urltest\n    match: [\"@hk\"]\n"),
		srcAghPath:                                        []byte("dns:\n  port: 5353\n"),
		srcSBPath:                                         []byte(sbJSON),
		srcBasePath:                                       []byte(sbJSON),
		filepath.Join(srcRuleSetDir, "geosite-ad1.srs"):   []byte("SRS\x02ad1"),
		filepath.Join(srcRuleSetDir, "geosite-ad2.srs"):   []byte("SRS\x02ad2"),
		filepath.Join(srcRuleSetDir, "singctl-pcdn.srs"):  []byte("SRS\x02pcdn"),
		filepath.Join(srcRuleSetDir, "singctl-pcdn.srs.sha256"): []byte("abcdef1234567890\n"),
		filepath.Join(srcRuleSetDir, "manifest.json"):     []byte(`{"geosite-ad1":{"url":"https://example.com/ad1.srs"}}`),
		filepath.Join(srcRuleSetDir, "ignored.txt"):       []byte("do-not-pack"),
	} {
		if err := os.WriteFile(p, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	// 添加软链接验证打包时自动忽略
	_ = os.Symlink(filepath.Join(srcRuleSetDir, "geosite-ad1.srs"), filepath.Join(srcRuleSetDir, "symlink.srs"))

	srcSrv := webui.New(webui.Options{
		ConfigPath:              srcCfgPath,
		SingBoxConfigPath:       srcSBPath,
		AdGuardConfigPath:       srcAghPath,
		SkipAdGuardProbeForTest: true,
		Version:                 "v1.15.0",
		Listen:                  "127.0.0.1:0",
	})

	// 1. 默认导出（未传 includeRuleSets -> 默认 true）
	recExp := postBackupJSON(srcSrv, "/api/backup/export", map[string]any{"passphrase": "StrongGateway#2026"})
	if recExp.Code != http.StatusOK {
		t.Fatalf("export failed: code=%d body=%s", recExp.Code, recExp.Body.String())
	}
	var expResp struct {
		OK       bool   `json:"ok"`
		Message  string `json:"message"`
		Filename string `json:"filename"`
		Data     string `json:"data"`
		Summary  struct {
			HasSingctlCfg  bool `json:"hasSingctlCfg"`
			HasGroups      bool `json:"hasGroups"`
			HasAdGuard     bool `json:"hasAdGuard"`
			HasSingBox     bool `json:"hasSingBox"`
			HasSingBoxBase bool `json:"hasSingBoxBase"`
			RuleSetCount   int  `json:"ruleSetCount"`
		} `json:"summary"`
	}
	if err := json.Unmarshal(recExp.Body.Bytes(), &expResp); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.ToUpper(expResp.Message), "V2") {
		t.Fatalf("export user-facing message should not contain V2 hint, got %q", expResp.Message)
	}
	if !expResp.OK || !expResp.Summary.HasSingctlCfg || !expResp.Summary.HasGroups ||
		!expResp.Summary.HasAdGuard || !expResp.Summary.HasSingBox || !expResp.Summary.HasSingBoxBase ||
		expResp.Summary.RuleSetCount != 3 {
		t.Fatalf("unexpected V2 export summary: %+v", expResp.Summary)
	}

	payload, err := webui.DecryptClientBackupBundle("StrongGateway#2026", []byte(expResp.Data))
	if err != nil {
		t.Fatalf("decrypt exported V2 bundle failed: %v", err)
	}
	if payload.SingBoxBaseJSON == "" || len(payload.RuleSetsTarGz) == 0 || payload.RuleSetCount != 3 {
		t.Fatalf("expected base snapshot and 3 rulesets in payload, got baseLen=%d tarLen=%d count=%d",
			len(payload.SingBoxBaseJSON), len(payload.RuleSetsTarGz), payload.RuleSetCount)
	}

	// 验证 tar.gz 内容仅包含白名单普通文件（不含 ignored.txt 与 symlink.srs）
	gzr, err := gzip.NewReader(bytes.NewReader(payload.RuleSetsTarGz))
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(gzr)
	var archivedNames []string
	for {
		hdr, err := tr.Next()
		if err != nil {
			break
		}
		archivedNames = append(archivedNames, hdr.Name)
	}
	_ = gzr.Close()
	slices.Sort(archivedNames)
	wantNames := []string{"geosite-ad1.srs", "geosite-ad2.srs", "manifest.json", "singctl-pcdn.srs", "singctl-pcdn.srs.sha256"}
	if !slices.Equal(archivedNames, wantNames) {
		t.Fatalf("archived ruleset names mismatch: got %v, want %v", archivedNames, wantNames)
	}

	// 2. 显式 includeRuleSets=false 不打包规则集
	recNoRS := postBackupJSON(srcSrv, "/api/backup/export", map[string]any{
		"passphrase":      "StrongGateway#2026",
		"includeRuleSets": false,
	})
	if recNoRS.Code != http.StatusOK {
		t.Fatalf("export without rulesets failed: code=%d body=%s", recNoRS.Code, recNoRS.Body.String())
	}
	var noRSResp struct {
		Data    string `json:"data"`
		Summary struct {
			HasSingBoxBase bool `json:"hasSingBoxBase"`
			RuleSetCount   int  `json:"ruleSetCount"`
		} `json:"summary"`
	}
	if err := json.Unmarshal(recNoRS.Body.Bytes(), &noRSResp); err != nil {
		t.Fatal(err)
	}
	if !noRSResp.Summary.HasSingBoxBase || noRSResp.Summary.RuleSetCount != 0 {
		t.Fatalf("expected hasSingBoxBase=true ruleSetCount=0, got %+v", noRSResp.Summary)
	}
	pNoRS, err := webui.DecryptClientBackupBundle("StrongGateway#2026", []byte(noRSResp.Data))
	if err != nil {
		t.Fatal(err)
	}
	if len(pNoRS.RuleSetsTarGz) != 0 || pNoRS.RuleSetCount != 0 {
		t.Fatalf("expected empty RuleSetsTarGz when includeRuleSets=false")
	}
}

func TestHandleClientBackup_RuleSetArchiveSecurityRejection(t *testing.T) {
	tooManyFiles := make([]tarSpec, 0, 201)
	for i := range 201 {
		tooManyFiles = append(tooManyFiles, tarSpec{
			name: fmt.Sprintf("rs-%03d.srs", i),
			body: []byte("SRS\x02x"),
		})
	}
	bombBody := bytes.Repeat([]byte{0}, 33*1024*1024)

	cases := []struct {
		name  string
		specs []tarSpec
	}{
		{name: "path_traversal", specs: []tarSpec{{name: "../evil.srs", body: []byte("x")}}},
		{name: "absolute_path", specs: []tarSpec{{name: "/etc/sing-box/rule_sets/a.srs", body: []byte("x")}}},
		{name: "nested_subdir", specs: []tarSpec{{name: "sub/a.srs", body: []byte("x")}}},
		{name: "symlink", specs: []tarSpec{{name: "a.srs", typeflag: tar.TypeSymlink, linkname: "/etc/passwd"}}},
		{name: "hardlink", specs: []tarSpec{{name: "a.srs", typeflag: tar.TypeLink, linkname: "/etc/passwd"}}},
		{name: "disallowed_ext", specs: []tarSpec{{name: "evil.sh", body: []byte("rm -rf /")}}},
		{name: "invalid_manifest_json", specs: []tarSpec{{name: "manifest.json", body: []byte("{bad-json")}}},
		{name: "too_many_files", specs: tooManyFiles},
		{name: "gzip_bomb_over_32mib", specs: []tarSpec{{name: "bomb.srs", body: bombBody}}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dstDir := t.TempDir()
			cfgPath := filepath.Join(dstDir, "singctl.yaml")
			sbPath := filepath.Join(dstDir, "sb", "config.json")
			origCfg := "subs:\n  - name: keep\n    url: https://keep.example.com/sub\n"
			if err := os.WriteFile(cfgPath, []byte(origCfg), 0600); err != nil {
				t.Fatal(err)
			}

			malPayload := webui.ClientBackupPayload{
				Version:       "1.15.0",
				ExportedAt:    "2026-11-22T12:00:00Z",
				SingctlYAML:   "subs:\n  - name: attacker\n    url: https://attacker.example.com/sub\n",
				RuleSetsTarGz: buildTestTarGz(t, tc.specs),
				RuleSetCount:  len(tc.specs),
			}
			envBytes, err := webui.EncryptClientBackupBundle("SecurityPass#2026", malPayload)
			if err != nil {
				t.Fatal(err)
			}

			// 在隔离临时目录注入确定性 stub sing-box（兼容无 sing-box 的 CI 环境），命中非法协议时强制 check 返回非零以触发全事务回滚
		fakeBinDir := t.TempDir()
		fakeSBPath := filepath.Join(fakeBinDir, "sing-box")
		fakeSBScript := "#!/bin/sh\nif [ \"$1\" = \"check\" ]; then\n  for arg in \"$@\"; do\n    if [ -f \"$arg\" ] && grep -q 'nonexistent_proto_trigger_check_fail' \"$arg\"; then\n      echo 'invalid outbound type: nonexistent_proto_trigger_check_fail' >&2\n      exit 1\n    fi\n  done\nfi\nexit 0\n"
		if err := os.WriteFile(fakeSBPath, []byte(fakeSBScript), 0755); err != nil {
			t.Fatal(err)
		}
		t.Setenv("PATH", fakeBinDir+string(os.PathListSeparator)+os.Getenv("PATH"))

		srv := webui.New(webui.Options{
				ConfigPath:              cfgPath,
				SingBoxConfigPath:       sbPath,
				SkipAdGuardProbeForTest: true,
				Listen:                  "127.0.0.1:0",
			})
			rec := postBackupJSON(srv, "/api/backup/restore", map[string]any{
				"passphrase": "SecurityPass#2026",
				"data":       string(envBytes),
			})
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("expected 400 for %s, got %d: %s", tc.name, rec.Code, rec.Body.String())
			}
			// 校验零落盘污染
			afterCfg, _ := os.ReadFile(cfgPath)
			if string(afterCfg) != origCfg {
				t.Fatalf("expected singctl.yaml untouched after preflight rejection")
			}
			if _, err := os.Stat(filepath.Join(filepath.Dir(sbPath), "rule_sets")); !os.IsNotExist(err) {
				t.Fatalf("expected rule_sets dir not created on preflight rejection")
			}
		})
	}
}

func TestHandleClientBackup_V2RestoreCrossHardwareAdaptation(t *testing.T) {
	// 构造高配源机备份：开启本地 AdGuard (127.0.0.1:5353) + 含 geosite-ad2 规则与 .srs 归档
	srcDir := t.TempDir()
	sbJSON := buildValidTestSingBoxWithAdGuardAndAd2(t, srcDir, true, true)
	rsTar := buildTestTarGz(t, []tarSpec{
		{name: "geosite-ad1.srs", body: []byte("SRS\x02ad1")},
		{name: "geosite-ad2.srs", body: []byte("SRS\x02ad2-heavy")},
		{name: "geosite-cn.srs", body: []byte("SRS\x02cn")},
		{name: "manifest.json", body: []byte(`{"geosite-cn":{"url":"https://example.com/cn.srs"}}`)},
	})
	v2Payload := webui.ClientBackupPayload{
		Version:           "1.15.0",
		ExportedAt:        "2026-11-22T12:00:00Z",
		SingctlYAML:       "low_memory: auto\nsubs:\n  - name: main\n    url: https://sub.example.com/sub\n",
		GroupsYAML:        "version: 1\nmode: merge\ngroups:\n  - name: \"#HK\"\n    type: urltest\n    match: [\"@hk\"]\n",
		AdGuardYAML:       "dns:\n  port: 5353\n",
		SingBoxConfigJSON: sbJSON,
		SingBoxBaseJSON:   sbJSON,
		RuleSetsTarGz:     rsTar,
		RuleSetCount:      3,
	}
	envBytes, err := webui.EncryptClientBackupBundle("MigratePass#2026", v2Payload)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("low_memory_and_no_adguard_target_adapts_cleanly", func(t *testing.T) {
		dstDir := t.TempDir()
		dstCfg := filepath.Join(dstDir, "singctl.yaml")
		dstAgh := filepath.Join(dstDir, "agh", "AdGuardHome.yaml")
		dstSB := filepath.Join(dstDir, "sb", "config.json")
		dstRuleSetDir := filepath.Join(dstDir, "sb", "rule_sets")

		dstSrv := webui.New(webui.Options{
			ConfigPath:              dstCfg,
			SingBoxConfigPath:       dstSB,
			AdGuardConfigPath:       dstAgh,
			AdGuardBinPath:          filepath.Join(dstDir, "nonexistent-adguard"),
			AdGuardMemInfoForTest:   func() sysinfo.MemInfo { return sysinfo.MemInfo{TotalBytes: 256 * 1024 * 1024} },
			SkipAdGuardProbeForTest: true,
			Listen:                  "127.0.0.1:0",
		})

		rec := postBackupJSON(dstSrv, "/api/backup/restore", map[string]any{
			"passphrase": "MigratePass#2026",
			"data":       string(envBytes),
		})
		if rec.Code != http.StatusOK {
			t.Fatalf("restore failed: code=%d body=%s", rec.Code, rec.Body.String())
		}

		var resp struct {
			OK            bool     `json:"ok"`
			RestoredItems []string `json:"restoredItems"`
			RuleSetCount  int      `json:"ruleSetCount"`
			Adaptations   []string `json:"adaptations"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatal(err)
		}
		if !resp.OK || resp.RuleSetCount != 2 {
			t.Fatalf("expected ok=true ruleSetCount=2 (geosite-ad2 skipped), got %+v", resp)
		}
		if len(resp.Adaptations) < 2 {
			t.Fatalf("expected >=2 cross-hardware adaptations (AdGuard fallback + low-memory), got %v", resp.Adaptations)
		}

		// 验证核心文件 0600 落盘
		for _, fpath := range []string{dstCfg, config.GroupsPathForConfig(dstCfg), dstAgh, dstSB, singbox.BaseSnapshotPath(dstSB)} {
			st, statErr := os.Stat(fpath)
			if statErr != nil || st.Mode().Perm() != 0600 {
				t.Fatalf("expected restored file %s with 0600 perm, got %v (err=%v)", fpath, st, statErr)
			}
		}

		// 验证 geosite-ad2.srs 跳过未写入闪存，其余规则集完整落盘
		if _, err := os.Stat(filepath.Join(dstRuleSetDir, "geosite-ad2.srs")); !os.IsNotExist(err) {
			t.Fatalf("expected geosite-ad2.srs skipped on low-memory target")
		}
		for _, kept := range []string{"geosite-ad1.srs", "geosite-cn.srs", "manifest.json"} {
			if _, err := os.Stat(filepath.Join(dstRuleSetDir, kept)); err != nil {
				t.Fatalf("expected ruleset file %s restored, err=%v", kept, err)
			}
		}

		// 验证 config.json 与 .singctl-base 均已完成 DoH 回退与 geosite-ad2 剥离
		for _, checkPath := range []string{dstSB, singbox.BaseSnapshotPath(dstSB)} {
			raw, readErr := os.ReadFile(checkPath)
			if readErr != nil {
				t.Fatal(readErr)
			}
			txt := string(raw)
			if strings.Contains(txt, "geosite-ad2") {
				t.Fatalf("expected geosite-ad2 pruned from %s", filepath.Base(checkPath))
			}
			if !strings.Contains(txt, "geosite-ad1") {
				t.Fatalf("expected geosite-ad1 preserved in %s", filepath.Base(checkPath))
			}
			if strings.Contains(txt, `"127.0.0.1"`) {
				// 仅检查 dns_local 已回退到安全公网 UDP 53 DNS，不影响 mixed-in 监听地址
				linked, _ := singbox.InspectSingBoxDNSLocal(checkPath)
				if linked {
					t.Fatalf("expected dns_local in %s fallen back from 127.0.0.1 to public UDP DNS", filepath.Base(checkPath))
				}
			}
			var sbDoc struct {
				DNS struct {
					Servers []struct {
						Tag        string `json:"tag"`
						Type       string `json:"type"`
						Server     string `json:"server"`
						ServerPort int    `json:"server_port"`
					} `json:"servers"`
				} `json:"dns"`
			}
			if jErr := json.Unmarshal(raw, &sbDoc); jErr != nil {
				t.Fatal(jErr)
			}
			var foundLocal bool
			for _, srv := range sbDoc.DNS.Servers {
				if srv.Tag == "dns_local" {
					foundLocal = true
					if srv.Type != "udp" || srv.ServerPort != 53 || srv.Server == "" || srv.Server == "127.0.0.1" {
						t.Fatalf("expected safe public UDP 53 dns_local in %s, got %+v", filepath.Base(checkPath), srv)
					}
				}
			}
			if !foundLocal {
				t.Fatalf("expected dns_local server present in %s", filepath.Base(checkPath))
			}
		}
	})

	t.Run("high_memory_and_adguard_installed_keeps_original", func(t *testing.T) {
		dstDir := t.TempDir()
		dstCfg := filepath.Join(dstDir, "singctl.yaml")
		dstAgh := filepath.Join(dstDir, "agh", "AdGuardHome.yaml")
		dstAghBin := filepath.Join(dstDir, "AdGuardHome")
		if err := os.WriteFile(dstAghBin, []byte("#!/bin/sh\nexit 0\n"), 0755); err != nil {
			t.Fatal(err)
		}
		dstSB := filepath.Join(dstDir, "sb", "config.json")
		dstRuleSetDir := filepath.Join(dstDir, "sb", "rule_sets")

		dstSrv := webui.New(webui.Options{
			ConfigPath:              dstCfg,
			SingBoxConfigPath:       dstSB,
			AdGuardConfigPath:       dstAgh,
			AdGuardBinPath:          dstAghBin,
			AdGuardMemInfoForTest:   func() sysinfo.MemInfo { return sysinfo.MemInfo{TotalBytes: 2048 * 1024 * 1024} },
			SkipAdGuardProbeForTest: true,
			Listen:                  "127.0.0.1:0",
		})

		rec := postBackupJSON(dstSrv, "/api/backup/restore", map[string]any{
			"passphrase": "MigratePass#2026",
			"data":       string(envBytes),
		})
		if rec.Code != http.StatusOK {
			t.Fatalf("restore failed: code=%d body=%s", rec.Code, rec.Body.String())
		}
		var resp struct {
			OK           bool     `json:"ok"`
			RuleSetCount int      `json:"ruleSetCount"`
			Adaptations  []string `json:"adaptations"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatal(err)
		}
		if !resp.OK || resp.RuleSetCount != 3 || len(resp.Adaptations) != 0 {
			t.Fatalf("expected ok=true ruleSetCount=3 adaptations=[], got %+v", resp)
		}
		if _, err := os.Stat(filepath.Join(dstRuleSetDir, "geosite-ad2.srs")); err != nil {
			t.Fatalf("expected geosite-ad2.srs preserved on high-memory host: %v", err)
		}
		linked, port := singbox.InspectSingBoxDNSLocal(dstSB)
		if !linked || port != 5353 {
			t.Fatalf("expected dns_local preserved at 127.0.0.1:5353, got linked=%v port=%d", linked, port)
		}
		rawSB, _ := os.ReadFile(dstSB)
		if !strings.Contains(string(rawSB), "geosite-ad2") {
			t.Fatalf("expected geosite-ad2 preserved on high-memory host")
		}
	})
}

func TestHandleClientBackup_V2LiveReconcileAndFullAtomicRollback(t *testing.T) {
	t.Run("live_reconcile_preserves_clash_secret_and_compiles_groups", func(t *testing.T) {
		liveDir := t.TempDir()
		liveCfg := filepath.Join(liveDir, "singctl.yaml")
		liveAgh := filepath.Join(liveDir, "AdGuardHome.yaml")
		liveSB := filepath.Join(liveDir, "config.json")
		if err := os.WriteFile(liveCfg, []byte("subs:\n  - name: old\n    url: https://old.example.com/sub\n"), 0600); err != nil {
			t.Fatal(err)
		}
		liveBase := buildValidTestSingBoxWithAdGuardAndAd2(t, liveDir, false, false)
		var liveDoc map[string]any
		_ = json.Unmarshal([]byte(liveBase), &liveDoc)
		liveDoc["experimental"] = map[string]any{
			"clash_api": map[string]any{
				"external_controller": "127.0.0.1:9090",
				"secret":              "live-secret-keep",
			},
			"cache_file": map[string]any{
				"enabled": true,
				"path":    filepath.Join(liveDir, "cache.db"),
			},
		}
		liveBytes, _ := json.MarshalIndent(liveDoc, "", "  ")
		if err := os.WriteFile(liveSB, liveBytes, 0600); err != nil {
			t.Fatal(err)
		}

		srcSB := buildValidTestSingBoxWithAdGuardAndAd2(t, liveDir, false, false)
		backupPayload := webui.ClientBackupPayload{
			Version:           "1.15.0",
			ExportedAt:        "2026-11-22T12:00:00Z",
			SingctlYAML:       "subs:\n  - name: main\n    url: https://sub.example.com/sub\n",
			GroupsYAML:        "version: 1\nmode: merge\ngroups:\n  - name: \"#HK\"\n    type: urltest\n    match: [\"@hk\"]\n",
			SingBoxConfigJSON: srcSB,
		}
		envBytes, err := webui.EncryptClientBackupBundle("LivePass#2026", backupPayload)
		if err != nil {
			t.Fatal(err)
		}

		liveSrv := webui.New(webui.Options{
			ConfigPath:              liveCfg,
			SingBoxConfigPath:       liveSB,
			AdGuardConfigPath:       liveAgh,
			AdGuardMemInfoForTest:   func() sysinfo.MemInfo { return sysinfo.MemInfo{TotalBytes: 2048 * 1024 * 1024} },
			SkipAdGuardProbeForTest: true,
			Listen:                  "127.0.0.1:0",
		})
		rec := postBackupJSON(liveSrv, "/api/backup/restore", map[string]any{
			"passphrase": "LivePass#2026",
			"data":       string(envBytes),
		})
		if rec.Code != http.StatusOK {
			t.Fatalf("live reconcile restore failed: code=%d body=%s", rec.Code, rec.Body.String())
		}
		reconciledBytes, err := os.ReadFile(liveSB)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(reconciledBytes), "live-secret-keep") {
			t.Fatalf("expected live Clash secret preserved during restore reconcile")
		}
		liveGroups, _ := singbox.InspectClientRoutingOutbounds(string(reconciledBytes))
		var tags []string
		for _, g := range liveGroups {
			tags = append(tags, g.Tag)
		}
		if !slices.Contains(tags, "#HK") {
			t.Fatalf("expected restored groups.yaml (#HK) compiled into live config.json, got %v", tags)
		}
	})

	t.Run("full_transactional_rollback_when_singbox_step_fails", func(t *testing.T) {
		dir := t.TempDir()
		cfgPath := filepath.Join(dir, "singctl.yaml")
		groupsPath := config.GroupsPathForConfig(cfgPath)
		aghPath := filepath.Join(dir, "AdGuardHome.yaml")
		sbDir := filepath.Join(dir, "sb")
		sbPath := filepath.Join(sbDir, "config.json")
		basePath := singbox.BaseSnapshotPath(sbPath)
		rsDir := filepath.Join(sbDir, "rule_sets")
		if err := os.MkdirAll(rsDir, 0755); err != nil {
			t.Fatal(err)
		}

		origCfg := "subs:\n  - name: original\n    url: https://original.example.com/sub\n"
		origGroups := "version: 1\nmode: merge\ngroups:\n  - name: \"#ORIG\"\n    type: urltest\n    match: [\"@us\"]\n"
		origAgh := "dns:\n  port: 5353\nuser_rules:\n  - '||orig.example.com^'\n"
		origSB := buildValidTestSingBoxWithAdGuardAndAd2(t, sbDir, false, false)
		origBase := `{"log":{"level":"info"}}`
		origRS := []byte("SRS\x02original-ruleset")

		for p, data := range map[string][]byte{
			cfgPath:                              []byte(origCfg),
			groupsPath:                           []byte(origGroups),
			aghPath:                              []byte(origAgh),
			sbPath:                               []byte(origSB),
			basePath:                             []byte(origBase),
			filepath.Join(rsDir, "existing.srs"): origRS,
		} {
			if err := os.WriteFile(p, data, 0600); err != nil {
				t.Fatal(err)
			}
		}

		// 在隔离临时目录注入确定性 stub sing-box（兼容无 sing-box 的 CI 环境），命中非法协议时强制 check 返回非零以触发全事务回滚
		fakeBinDir := t.TempDir()
		fakeSBPath := filepath.Join(fakeBinDir, "sing-box")
		fakeSBScript := "#!/bin/sh\nif [ \"$1\" = \"check\" ]; then\n  for arg in \"$@\"; do\n    if [ -f \"$arg\" ] && grep -q 'nonexistent_proto_trigger_check_fail' \"$arg\"; then\n      echo 'invalid outbound type: nonexistent_proto_trigger_check_fail' >&2\n      exit 1\n    fi\n  done\nfi\nexit 0\n"
		if err := os.WriteFile(fakeSBPath, []byte(fakeSBScript), 0755); err != nil {
			t.Fatal(err)
		}
		t.Setenv("PATH", fakeBinDir+string(os.PathListSeparator)+os.Getenv("PATH"))

		srv := webui.New(webui.Options{
			ConfigPath:              cfgPath,
			SingBoxConfigPath:       sbPath,
			AdGuardConfigPath:       aghPath,
			AdGuardMemInfoForTest:   func() sysinfo.MemInfo { return sysinfo.MemInfo{TotalBytes: 2048 * 1024 * 1024} },
			SkipAdGuardProbeForTest: true,
			Listen:                  "127.0.0.1:0",
		})
		// 预热 cfgStore 确保回滚后内存快照同步刷新
		preSnap, err := srv.LoadConfigSnapshot()
		if err != nil || len(preSnap.Subs) != 1 || preSnap.Subs[0].Name != "original" {
			t.Fatalf("pre-warm cfgStore failed: snap=%+v err=%v", preSnap, err)
		}

		// 构造一个前置校验全部通过（语法合法 YAML/JSON/tar.gz），但在最终 sing-box check 阶段必定失败的快照
		badPayload := webui.ClientBackupPayload{
			Version:     "1.15.0",
			ExportedAt:  "2026-11-22T12:00:00Z",
			SingctlYAML: "subs:\n  - name: mutated\n    url: https://mutated.example.com/sub\n",
			GroupsYAML:  "version: 1\nmode: merge\ngroups:\n  - name: \"#MUTATED\"\n    type: urltest\n    match: [\"@hk\"]\n",
			AdGuardYAML: "dns:\n  port: 5354\n",
			SingBoxConfigJSON: `{
				"outbounds": [{"type": "nonexistent_proto_trigger_check_fail", "tag": "bad"}]
			}`,
			SingBoxBaseJSON: `{"log":{"level":"debug"}}`,
			RuleSetsTarGz: buildTestTarGz(t, []tarSpec{
				{name: "existing.srs", body: []byte("SRS\x02overwritten")},
				{name: "new-added.srs", body: []byte("SRS\x02brand-new")},
			}),
			RuleSetCount: 2,
		}
		envBytes, err := webui.EncryptClientBackupBundle("RollbackPass#2026", badPayload)
		if err != nil {
			t.Fatal(err)
		}

		rec := postBackupJSON(srv, "/api/backup/restore", map[string]any{
			"passphrase": "RollbackPass#2026",
			"data":       string(envBytes),
		})
		if rec.Code == http.StatusOK {
			t.Fatalf("expected restore to fail on invalid sing-box config/custom_rules, got 200: %s", rec.Body.String())
		}

		// 逐一断言所有已写文件与规则集目录完整字节级回滚
		for path, want := range map[string]string{
			cfgPath:                              origCfg,
			groupsPath:                           origGroups,
			aghPath:                              origAgh,
			sbPath:                               origSB,
			basePath:                             origBase,
			filepath.Join(rsDir, "existing.srs"): string(origRS),
		} {
			got, readErr := os.ReadFile(path)
			if readErr != nil {
				t.Fatalf("expected rolled-back file %s readable, err=%v", path, readErr)
			}
			if string(got) != want {
				t.Fatalf("file %s NOT rolled back!\ngot:\n%s\nwant:\n%s", filepath.Base(path), string(got), want)
			}
		}
		if _, err := os.Stat(filepath.Join(rsDir, "new-added.srs")); !os.IsNotExist(err) {
			t.Fatalf("expected newly added ruleset file new-added.srs removed on rollback")
		}
		// 断言 cfgStore 内存快照已同步回滚为 original
		postSnap, err := srv.LoadConfigSnapshot()
		if err != nil || len(postSnap.Subs) != 1 || postSnap.Subs[0].Name != "original" {
			t.Fatalf("expected cfgStore refreshed to original after rollback, got %+v (err=%v)", postSnap, err)
		}
	})
}

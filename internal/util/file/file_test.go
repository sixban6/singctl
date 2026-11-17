package file

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"unicode/utf8"
)

func TestWriteAtomic_ConcurrentSafetyAndPermissions(t *testing.T) {
	if err := WriteAtomic("", []byte("x"), 0600); err == nil {
		t.Fatal("expected error for empty target path")
	}

	tmpDir := t.TempDir()
	secretPath := filepath.Join(tmpDir, "nested", "secret.json")

	var wg sync.WaitGroup
	payloads := make([][]byte, 16)
	for i := range 16 {
		payloads[i] = bytes.Repeat([]byte{byte('a' + i)}, 512)
		wg.Add(1)
		go func(data []byte) {
			defer wg.Done()
			if err := WriteAtomic0600(secretPath, data); err != nil {
				t.Errorf("concurrent WriteAtomic0600 failed: %v", err)
			}
		}(payloads[i])
	}
	wg.Wait()

	got, err := os.ReadFile(secretPath)
	if err != nil {
		t.Fatalf("read final file: %v", err)
	}
	matched := false
	for _, p := range payloads {
		if bytes.Equal(got, p) {
			matched = true
			break
		}
	}
	if !matched {
		t.Fatalf("final file content corrupted under concurrent writes (len=%d)", len(got))
	}

	st, err := os.Stat(secretPath)
	if err != nil || st.Mode().Perm() != 0600 {
		t.Fatalf("expected 0600 mode on secret file, got %v (err=%v)", st, err)
	}

	entries, err := os.ReadDir(filepath.Dir(secretPath))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "secret.json" {
		t.Fatalf("expected zero leftover temp files in dir, got %v", entries)
	}

	pubPath := filepath.Join(tmpDir, "manifest.json")
	if err := WriteAtomic(pubPath, []byte("{}"), 0644); err != nil {
		t.Fatalf("WriteAtomic 0644 failed: %v", err)
	}
	pubSt, err := os.Stat(pubPath)
	if err != nil || pubSt.Mode().Perm() != 0644 {
		t.Fatalf("expected 0644 mode on public manifest, got %v (err=%v)", pubSt, err)
	}
}

func TestMaskSubscriptionURL_MasksCredentialsIPsAndUTF8(t *testing.T) {
	if got := MaskSubscriptionURL(""); got != "未配置" {
		t.Fatalf("expected 未配置, got %q", got)
	}
	if got := MaskSubscriptionURL("not-a-url"); got != "***" {
		t.Fatalf("expected ***, got %q", got)
	}

	// Must never leak BasicAuth credentials even on single-label hostnames
	credURL := "https://admin:my_super_secret_token@intranet/api/sub"
	maskedCred := MaskSubscriptionURL(credURL)
	if strings.Contains(maskedCred, "my_super_secret_token") || strings.Contains(maskedCred, "admin") {
		t.Fatalf("MaskSubscriptionURL leaked credentials: %q", maskedCred)
	}

	// Must mask IPv4 octets instead of leaking .0.113.45:8443
	ipURL := "https://203.0.113.45:8443/sub/secret_key"
	maskedIP := MaskSubscriptionURL(ipURL)
	if strings.Contains(maskedIP, "113.45") || strings.Contains(maskedIP, "secret_key") {
		t.Fatalf("MaskSubscriptionURL leaked public IP octets or path: %q", maskedIP)
	}

	// Must preserve valid UTF-8 on IDN multi-byte domain names
	idnURL := "https://机场订阅.example.com/api/v1?token=secret"
	maskedIDN := MaskSubscriptionURL(idnURL)
	if !utf8.ValidString(maskedIDN) {
		t.Fatalf("MaskSubscriptionURL produced invalid UTF-8: %q", maskedIDN)
	}
	if strings.Contains(maskedIDN, "secret") {
		t.Fatalf("MaskSubscriptionURL leaked token: %q", maskedIDN)
	}
}

func TestSafeReplace_InstallOrReplace_CopyDir_FindExecutable(t *testing.T) {
	dir := t.TempDir()
	targetBin := filepath.Join(dir, "bin", "singctl")
	srcV1 := filepath.Join(dir, "v1-bin")
	srcV2 := filepath.Join(dir, "v2-bin")
	if err := os.WriteFile(srcV1, []byte("#!/bin/sh\necho v1\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(srcV2, []byte("#!/bin/sh\necho v2\n"), 0644); err != nil {
		t.Fatal(err)
	}

	// 1. Fresh InstallOrReplace
	if err := InstallOrReplace(srcV1, targetBin); err != nil {
		t.Fatalf("InstallOrReplace v1 failed: %v", err)
	}
	origStat, err := os.Stat(targetBin)
	if err != nil {
		t.Fatal(err)
	}

	// 2. SafeReplace with missing source must NOT touch targetBin's inode/content
	if err := SafeReplace(targetBin, filepath.Join(dir, "nonexistent")); err == nil {
		t.Fatal("expected SafeReplace with nonexistent source to fail")
	}
	afterFailStat, err := os.Stat(targetBin)
	if err != nil {
		t.Fatalf("targetBin missing after failed SafeReplace: %v", err)
	}
	if !os.SameFile(origStat, afterFailStat) {
		t.Fatalf("SafeReplace modified/replaced targetBin inode even when staging newFile failed")
	}

	// 3. SafeReplace upgrade to v2
	if err := InstallOrReplace(srcV2, targetBin); err != nil {
		t.Fatalf("InstallOrReplace v2 failed: %v", err)
	}
	gotBody, err := os.ReadFile(targetBin)
	if err != nil || !strings.Contains(string(gotBody), "echo v2") {
		t.Fatalf("expected v2 content after SafeReplace, got %q (err=%v)", string(gotBody), err)
	}

	// 4. FindExecutable recursive discovery (exact + pattern + depth limit)
	nestedDir := filepath.Join(dir, "extract", "sub1", "sub2")
	if err := os.MkdirAll(nestedDir, 0755); err != nil {
		t.Fatal(err)
	}
	nestedBin := filepath.Join(nestedDir, "singctl-linux-amd64")
	if err := os.WriteFile(nestedBin, []byte("bin"), 0644); err != nil {
		t.Fatal(err)
	}
	found, err := FindExecutable(filepath.Join(dir, "extract"), "singctl")
	if err != nil || found != nestedBin {
		t.Fatalf("FindExecutable = (%q, %v), want (%q, nil)", found, err, nestedBin)
	}

	// 5. CopyDir skips .go files and preserves existing destination configs
	cfgSrc := filepath.Join(dir, "cfg_src")
	cfgDst := filepath.Join(dir, "cfg_dst")
	_ = os.MkdirAll(filepath.Join(cfgSrc, "sub"), 0755)
	_ = os.MkdirAll(cfgDst, 0755)
	_ = os.WriteFile(filepath.Join(cfgSrc, "embed.go"), []byte("package configs"), 0644)
	_ = os.WriteFile(filepath.Join(cfgSrc, "singctl.yaml"), []byte("new_tpl: true\n"), 0644)
	_ = os.WriteFile(filepath.Join(cfgSrc, "sub", "extra.yaml"), []byte("extra: 1\n"), 0644)
	_ = os.WriteFile(filepath.Join(cfgDst, "singctl.yaml"), []byte("user_cfg: keep\n"), 0600)

	if err := CopyDir(cfgSrc, cfgDst); err != nil {
		t.Fatalf("CopyDir failed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(cfgDst, "embed.go")); !os.IsNotExist(err) {
		t.Fatalf("CopyDir should skip .go files")
	}
	keptCfg, _ := os.ReadFile(filepath.Join(cfgDst, "singctl.yaml"))
	if string(keptCfg) != "user_cfg: keep\n" {
		t.Fatalf("CopyDir overwrote existing user config: %q", string(keptCfg))
	}
	if _, err := os.Stat(filepath.Join(cfgDst, "sub", "extra.yaml")); err != nil {
		t.Fatalf("CopyDir did not copy nested extra.yaml: %v", err)
	}
}

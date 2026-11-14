package doctor

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"singctl/internal/config"
	"singctl/internal/constant"
	"singctl/internal/deploy"
)

func TestCheckWebTerminal_MtlsVaultStates(t *testing.T) {
	base := t.TempDir()
	vaultDir := filepath.Join(base, "singctl", "mtls")
	caddyMtlsDir := filepath.Join(base, "caddy", "mtls")

	origVault := constant.SingctlMtlsDir
	origCaddyMtls := constant.CaddyMtlsDir
	origCaddyCA := constant.CaddyMtlsCACert
	t.Cleanup(func() {
		constant.SingctlMtlsDir = origVault
		constant.CaddyMtlsDir = origCaddyMtls
		constant.CaddyMtlsCACert = origCaddyCA
	})
	constant.SingctlMtlsDir = vaultDir
	constant.CaddyMtlsDir = caddyMtlsDir
	constant.CaddyMtlsCACert = filepath.Join(vaultDir, "ca.crt")

	binDir := t.TempDir()
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	if err := os.WriteFile(filepath.Join(binDir, "systemctl"), []byte("#!/bin/sh\necho active\nexit 0\n"), 0755); err != nil {
		t.Fatal(err)
	}

	findMtlsItem := func(rep *DoctorReport) (DoctorItem, bool) {
		for _, item := range rep.Items {
			if item.Name == "Web 终端 mTLS 证书" {
				return item, true
			}
		}
		return DoctorItem{}, false
	}

	// 1. Disabled -> omitted.
	repDisabled := &DoctorReport{}
	checkWebTerminal(&config.Config{}, repDisabled)
	if _, ok := findMtlsItem(repDisabled); ok {
		t.Fatal("did not expect WebTerminal mTLS item when WebTerminal is disabled")
	}

	cfg := &config.Config{
		Server: config.ServerConfig{
			WebTerminal: config.WebTerminalConfig{
				Enabled: true,
			},
		},
	}

	// 2. Vault CA missing -> fail with term install hint.
	repFail := &DoctorReport{}
	checkWebTerminal(cfg, repFail)
	itemFail, ok := findMtlsItem(repFail)
	if !ok || itemFail.Status != "fail" || !strings.Contains(itemFail.Detail, "singctl sr term install") {
		t.Fatalf("expected fail status with term install guidance, got %+v ok=%v", itemFail, ok)
	}

	// 3. Vault CA present, but config still references deprecated /etc/caddy/mtls/ca.crt -> warn with sync hint.
	if err := deploy.SaveMtlsBundleToVault(map[string][]byte{
		"ca.crt": []byte("-----BEGIN CERTIFICATE-----\nVAULT-CA\n-----END CERTIFICATE-----\n"),
	}); err != nil {
		t.Fatal(err)
	}
	cfg.Server.WebTerminal.MtlsCA = "/etc/caddy/mtls/ca.crt"
	repWarn := &DoctorReport{}
	checkWebTerminal(cfg, repWarn)
	itemWarn, ok := findMtlsItem(repWarn)
	if !ok || itemWarn.Status != "warn" || !strings.Contains(itemWarn.Detail, "singctl sr sync") {
		t.Fatalf("expected warn status when config still points to legacy Caddy path, got %+v ok=%v", itemWarn, ok)
	}

	// 4. Config upgraded to /etc/singctl/mtls/ca.crt -> ok.
	deploy.UpgradeLegacyMtlsConfig(cfg)
	repOK := &DoctorReport{}
	checkWebTerminal(cfg, repOK)
	itemOK, ok := findMtlsItem(repOK)
	if !ok || itemOK.Status != "ok" {
		t.Fatalf("expected ok status when unified mTLS CA exists, got %+v ok=%v", itemOK, ok)
	}
}

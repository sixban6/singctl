// 文件职责：验证服务端体检对 Web 终端 mTLS 证书保险库缺失、旧路径警告与升级收敛状态的判定。
package doctor_test

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"singctl/internal/config"
	"singctl/internal/constant"
	"singctl/internal/deploy"
	"singctl/internal/doctor"
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

	offlineDeps := doctor.Deps{
		GOOS:            "linux",
		GOARCH:          "amd64",
		NumCPU:          2,
		ReadFile:        func(string) ([]byte, error) { return nil, os.ErrNotExist },
		DialTCP:         func(string, time.Duration) error { return nil },
		HTTPGetStatus:   func(string, time.Duration) (int, time.Duration, error) { return http.StatusOK, time.Millisecond, nil },
		ProbeRealitySNI: func(string) (time.Duration, string, error) { return time.Millisecond, "1.3", nil },
		IsServiceActive: func(string) bool { return true },
		CheckMediaUnlock: func() *doctor.MediaUnlockReport {
			return nil
		},
	}

	findMtlsItem := func(rep *doctor.DoctorReport) (doctor.DoctorItem, bool) {
		for _, item := range rep.Items {
			if item.Name == "Web 终端 mTLS 证书" {
				return item, true
			}
		}
		return doctor.DoctorItem{}, false
	}

	// 1. Disabled -> omitted.
	repDisabled := doctor.RunServerDoctorWithDeps(t.Context(), &config.Config{}, offlineDeps)
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
	repFail := doctor.RunServerDoctorWithDeps(t.Context(), cfg, offlineDeps)
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
	repWarn := doctor.RunServerDoctorWithDeps(t.Context(), cfg, offlineDeps)
	itemWarn, ok := findMtlsItem(repWarn)
	if !ok || itemWarn.Status != "warn" || !strings.Contains(itemWarn.Detail, "singctl sr sync") {
		t.Fatalf("expected warn status when config still points to legacy Caddy path, got %+v ok=%v", itemWarn, ok)
	}

	// 4. Config upgraded to /etc/singctl/mtls/ca.crt -> ok.
	deploy.UpgradeLegacyMtlsConfig(cfg)
	repOK := doctor.RunServerDoctorWithDeps(t.Context(), cfg, offlineDeps)
	itemOK, ok := findMtlsItem(repOK)
	if !ok || itemOK.Status != "ok" {
		t.Fatalf("expected ok status when unified mTLS CA exists, got %+v ok=%v", itemOK, ok)
	}
}

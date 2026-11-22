// 文件职责：覆盖安全扫描解析器（APT/DNF/残留动态库/内核版本对比/定时策略）与高并发状态落盘测试。
package heal_test

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"

	"singctl/internal/heal"
)

func TestScannerParsers_And_ConcurrentStatePersistence(t *testing.T) {
	aptOut := `
Inst libssl3 [3.0.11-1~deb12u2] (3.0.13-1~deb12u1 Debian-Security:12/stable-security [amd64])
Inst htop [3.2.2-1] (3.2.2-2 Debian:12.5/stable [amd64])
Inst openssh-server [1:9.2p1-2] (1:9.2p1-2+deb12u3 custom-mirror [amd64])
`
	gotApt := heal.ParseAptSimulateSecurityUpdates(aptOut)
	if !slices.Equal(gotApt, []string{"libssl3", "openssh-server"}) {
		t.Fatalf("unexpected apt security pkgs: %v", gotApt)
	}

	dnfOut := `
Last metadata expiration check: 0:12:01 ago
openssl-libs.x86_64   1:3.0.7-27.el9_3   baseos
curl.x86_64           7.76.1-29.el9_4    appstream
`
	gotDnf := heal.ParseDnfSecurityCheckUpdate(dnfOut)
	if !slices.Equal(gotDnf, []string{"curl", "openssl-libs"}) {
		t.Fatalf("unexpected dnf security pkgs: %v", gotDnf)
	}

	if !heal.HasDeletedSharedLibInMaps("7f9a-7f9b r-xp /usr/lib/x86_64-linux-gnu/libssl.so.3 (deleted)\n") {
		t.Fatal("expected deleted libssl.so.3 to be detected")
	}
	if heal.HasDeletedSharedLibInMaps("7f9a-7f9b rw-s /dev/zero (deleted)\n") {
		t.Fatal("expected /dev/zero (deleted) non-.so mapping to be ignored")
	}

	if heal.CompareKernelVersions("6.1.0-18-amd64", "6.1.0-21-amd64") >= 0 {
		t.Fatal("expected 6.1.0-18-amd64 < 6.1.0-21-amd64")
	}
	if heal.CompareKernelVersions("v1.14.134", "1.14.134") != 0 {
		t.Fatal("expected v1.14.134 == 1.14.134")
	}

	if err := heal.ValidateSchedule("04:30"); err != nil {
		t.Fatalf("expected valid HH:MM schedule, got %v", err)
	}
	if err := heal.ValidateSchedule("rm -rf /"); err == nil {
		t.Fatal("expected invalid schedule to be rejected")
	}

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "singctl.yaml")

	var wg sync.WaitGroup
	for i := range 35 {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			_ = heal.SavePolicy(cfgPath, heal.HealPolicy{
				AutoHealEnabled: idx%2 == 0,
				Schedule:        "03:45",
			})
			_ = heal.RecordExecution(cfgPath, heal.HealHistoryItem{
				Trigger: "auto",
				Success: true,
				Summary: fmt.Sprintf("run-%d", idx),
			}, &heal.StatusReport{Posture: heal.PostureHealthy})
		}(i)
	}
	wg.Wait()

	statePath := heal.ResolveStateFilePath(cfgPath)
	st, err := os.Stat(statePath)
	if err != nil || st.Mode().Perm() != 0600 {
		t.Fatalf("expected 0600 security_heal.json, got %v (err=%v)", st, err)
	}
	loaded := heal.LoadPersistedState(statePath)
	if len(loaded.History) != 30 {
		t.Fatalf("expected history capped at 30 items, got %d", len(loaded.History))
	}
}

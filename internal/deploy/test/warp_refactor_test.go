// 文件职责：覆盖 WARP 候选 Endpoint 去重排序、wireproxy 配置规范化幂等性及预验证失败回滚单测。
package deploy_test

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"singctl/internal/deploy"
)

func TestWarpRefactor_TableDrivenBoundaries(t *testing.T) {
	t.Run("candidate_endpoint_dedup_priority_and_invalid_guards", func(t *testing.T) {
		var reg deploy.WarpRegResponse
		reg.Config.Interface.Addresses.V4 = "172.16.0.2"
		reg.Config.Peers = []struct {
			PublicKey string `json:"public_key"`
			Endpoint  struct {
				V4   string `json:"v4"`
				V6   string `json:"v6"`
				Host string `json:"host"`
			} `json:"endpoint"`
		}{
			{PublicKey: "test-pub"},
		}
		reg.Config.Peers[0].Endpoint.V4 = "198.51.100.5:2408"

		gotEmpty := deploy.BuildOrderedWarpCandidateEndpoints(nil, "engage.cloudflareclient.com:2408", &reg)
		if !slices.Equal(gotEmpty, []string{deploy.WarpCandidateEndpoints[0], "198.51.100.5:2408"}) {
			t.Fatalf("unexpected fallback candidates: %v", gotEmpty)
		}

		reg.Config.Peers[0].Endpoint.V4 = "198.51.100.5:0"
		gotOrdered := deploy.BuildOrderedWarpCandidateEndpoints(
			[]string{"162.159.192.1:2408", "162.159.195.1:500", "162.159.192.1:2408", " "},
			"162.159.195.1:500",
			&reg,
		)
		want := []string{"162.159.195.1:500", "162.159.192.1:2408"}
		if !slices.Equal(gotOrdered, want) {
			t.Fatalf("expected %v, got %v", want, gotOrdered)
		}
	})

	t.Run("normalize_wireproxy_config_idempotent_and_deadlock_fixes", func(t *testing.T) {
		legacy := `[Interface]
Address = 172.16.0.2/32, 2606:4700:110::2/128
PrivateKey = TEST_PRIV=

[Peer]
PublicKey = TEST_PUB=
Endpoint = engage.cloudflareclient.com:2408
PersistentKeepalive = 25

[Socks5]
BindAddress = 127.0.0.1:40000
`
		norm, changed := deploy.NormalizeWireproxyConfigContent(legacy)
		if !changed {
			t.Fatal("expected legacy wireproxy config to be normalized")
		}
		for _, mustHave := range []string{"MTU = 1280", "ResolveStrategy = ipv6", "Endpoint = " + deploy.WarpCandidateEndpoints[0]} {
			if !strings.Contains(norm, mustHave) {
				t.Fatalf("normalized config missing %q:\n%s", mustHave, norm)
			}
		}
		if strings.Contains(norm, "PersistentKeepalive") {
			t.Fatalf("expected PersistentKeepalive stripped to avoid deadlock:\n%s", norm)
		}
		_, changed2 := deploy.NormalizeWireproxyConfigContent(norm)
		if changed2 {
			t.Fatalf("expected NormalizeWireproxyConfigContent to be idempotent, got changed2=true:\n%s", norm)
		}
	})

	t.Run("staging_verify_failure_rolls_back_and_prunes_backups", func(t *testing.T) {
		tmp := t.TempDir()
		confPath := filepath.Join(tmp, "wireproxy.conf")
		unitPath := filepath.Join(tmp, "wireproxy.service")
		orig := deploy.BuildWireproxyConfig("172.16.0.2/32", "ORIG_PRIV=", "ORIG_PUB=", false)
		if err := os.WriteFile(confPath, []byte(orig), 0644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(unitPath, []byte("[Service]\nExecStart=/usr/local/bin/wireproxy -s -c "+confPath+"\n"), 0644); err != nil {
			t.Fatal(err)
		}
		for _, ts := range []string{"100", "101", "102", "103"} {
			if err := os.WriteFile(confPath+"."+ts+".bak", []byte("old"), 0600); err != nil {
				t.Fatal(err)
			}
		}

		restarts := 0
		_, _, err := deploy.RotateWarpIdentityWithDeps(&deploy.WarpRotateDeps{
			PathEnv: deploy.WireproxyPathEnv{
				PrimaryConf: confPath,
				UnitFiles:   []string{unitPath},
			},
			CandidateEndpoints: []string{"162.159.192.1:2408"},
			GenerateKeypair:    func() (string, string, error) { return "NEW_PRIV=", "NEW_PUB=", nil },
			RegisterWarp: func(string) (*deploy.WarpRegResponse, error) {
				var resp deploy.WarpRegResponse
				resp.Config.Interface.Addresses.V4 = "172.16.0.9"
				return &resp, nil
			},
			HasIPv6:        func() bool { return false },
			StageProbe:     func(ep, _ string) (string, string, bool) { return "198.51.100.77", "NRT", true },
			RestartService: func() error { restarts++; return nil },
			FetchExitInfo:  func(time.Duration) (string, string, string, bool) { return "", "", "", false },
		})
		if err == nil || !strings.Contains(err.Error(), "自动回滚") {
			t.Fatalf("expected live verify failure to roll back, got err=%v", err)
		}
		if restarts != 2 {
			t.Fatalf("expected apply+rollback restarts=2, got %d", restarts)
		}
		gotRaw, _ := os.ReadFile(confPath)
		if string(gotRaw) != orig {
			t.Fatalf("expected original config restored after rollback")
		}
		st, _ := os.Stat(confPath)
		if st.Mode().Perm() != 0600 {
			t.Fatalf("expected restored conf mode 0600, got %04o", st.Mode().Perm())
		}
		baks, _ := filepath.Glob(confPath + ".*.bak")
		if len(baks) > 3 {
			t.Fatalf("expected backup pruning to retain at most 3 files, got %v", baks)
		}

		var wg sync.WaitGroup
		for range 8 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_ = deploy.BuildOrderedWarpCandidateEndpoints(deploy.WarpCandidateEndpoints, deploy.WarpCandidateEndpoints[0], nil)
				_, _ = deploy.NormalizeWireproxyConfigContent(orig)
			}()
		}
		wg.Wait()
	})
}

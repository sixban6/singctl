//go:build !lite

// 文件职责：验证 CLI 舰队子命令拆解树、离线子节点生命周期管理与显式依赖注入剪贴板复制。
package cmd_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"

	"singctl/internal/cmd"
	"singctl/internal/fleet"
)

func TestCopyConfigToClipboard_ExplicitDIAndRaceSafe(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell test")
	}

	dir := t.TempDir()
	cfgFile := filepath.Join(dir, "config.json")
	if err := os.WriteFile(cfgFile, []byte(`{"outbounds":[{"type":"direct"}]}`), 0600); err != nil {
		t.Fatal(err)
	}
	captured := filepath.Join(dir, "clipboard.txt")

	t.Run("darwin_matching_default_copies_stdin", func(t *testing.T) {
		copied, err := cmd.CopyConfigToClipboard(cfgFile, cmd.ClipboardDeps{
			GOOS:                     "darwin",
			DefaultSingBoxConfigPath: cfgFile,
			CommandRunner: func(_ string, _ ...string) *exec.Cmd {
				return exec.Command("/bin/sh", "-c", `cat > "$1"`, "--", captured)
			},
		})
		if err != nil || !copied {
			t.Fatalf("CopyConfigToClipboard = (%v, %v), want (true, nil)", copied, err)
		}
		got, err := os.ReadFile(captured)
		if err != nil || !strings.Contains(string(got), `"direct"`) {
			t.Fatalf("unexpected captured clipboard content %q (err=%v)", string(got), err)
		}
	})

	t.Run("non_darwin_or_non_default_path_skips", func(t *testing.T) {
		called := false
		runner := func(_ string, _ ...string) *exec.Cmd {
			called = true
			return exec.Command("/bin/true")
		}
		if copied, err := cmd.CopyConfigToClipboard(cfgFile, cmd.ClipboardDeps{
			GOOS:                     "linux",
			DefaultSingBoxConfigPath: cfgFile,
			CommandRunner:            runner,
		}); err != nil || copied || called {
			t.Fatalf("linux should skip clipboard: copied=%v err=%v called=%v", copied, err, called)
		}

		if copied, err := cmd.CopyConfigToClipboard(filepath.Join(dir, "other.json"), cmd.ClipboardDeps{
			GOOS:                     "darwin",
			DefaultSingBoxConfigPath: cfgFile,
			CommandRunner:            runner,
		}); err != nil || copied || called {
			t.Fatalf("custom path should skip clipboard: copied=%v err=%v called=%v", copied, err, called)
		}
	})

	t.Run("missing_file_and_runner_failure_return_error", func(t *testing.T) {
		if copied, err := cmd.CopyConfigToClipboard(filepath.Join(dir, "missing.json"), cmd.ClipboardDeps{
			GOOS:                     "darwin",
			DefaultSingBoxConfigPath: filepath.Join(dir, "missing.json"),
			CommandRunner: func(_ string, _ ...string) *exec.Cmd {
				return exec.Command("/bin/true")
			},
		}); err == nil || copied {
			t.Fatalf("expected error for missing file, got copied=%v err=%v", copied, err)
		}

		if copied, err := cmd.CopyConfigToClipboard(cfgFile, cmd.ClipboardDeps{
			GOOS:                     "darwin",
			DefaultSingBoxConfigPath: cfgFile,
			CommandRunner: func(_ string, _ ...string) *exec.Cmd {
				return exec.Command("/bin/sh", "-c", "exit 1")
			},
		}); err == nil || copied {
			t.Fatalf("expected error for failing pbcopy command, got copied=%v err=%v", copied, err)
		}
	})

	t.Run("concurrent_di_calls_without_global_mutation", func(t *testing.T) {
		var wg sync.WaitGroup
		for range 10 {
			wg.Go(func() {
				copied, err := cmd.CopyConfigToClipboard(cfgFile, cmd.ClipboardDeps{
					GOOS:                     "darwin",
					DefaultSingBoxConfigPath: cfgFile,
					CommandRunner: func(_ string, _ ...string) *exec.Cmd {
						return exec.Command("/bin/sh", "-c", "cat >/dev/null")
					},
				})
				if err != nil || !copied {
					t.Errorf("concurrent CopyConfigToClipboard = (%v, %v)", copied, err)
				}
			})
		}
		wg.Wait()
	})
}

func TestFleetSubcommands_OfflineStoreLifecycleAndArgs(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "singctl.yaml")
	fleetPath := filepath.Join(dir, "fleet.yaml")
	if err := os.WriteFile(cfgPath, []byte("subs: []\n"), 0600); err != nil {
		t.Fatal(err)
	}

	flCmd := cmd.NewFleetCmd(cfgPath)
	var names []string
	for _, sub := range flCmd.Commands() {
		names = append(names, sub.Name())
	}
	for _, want := range []string{"list", "add", "remove", "sync", "probe", "doctor", "reset", "update", "new", "heal"} {
		if !slices.Contains(names, want) {
			t.Fatalf("missing fleet subcommand %q in %v", want, names)
		}
	}

	// 1. Offline add --sync=false -> creates 0600 fleet.yaml
	addTree := cmd.NewFleetCmd(cfgPath)
	addTree.SetArgs([]string{
		"--fleet-file", fleetPath,
		"add", "us1",
		"--name", "US-West",
		"--host", "198.51.100.25",
		"--port", "2222",
		"--sync=false",
	})
	if err := addTree.Execute(); err != nil {
		t.Fatalf("fleet add --sync=false failed: %v", err)
	}
	info, err := os.Stat(fleetPath)
	if err != nil {
		t.Fatalf("stat fleet.yaml: %v", err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0600 {
		t.Fatalf("expected fleet.yaml mode 0600, got %o", info.Mode().Perm())
	}

	// 2. Offline list
	listTree := cmd.NewFleetCmd(cfgPath)
	listTree.SetArgs([]string{"--fleet-file", fleetPath, "list"})
	if err := listTree.Execute(); err != nil {
		t.Fatalf("fleet list failed: %v", err)
	}

	// 3. Offline remove --keep-dns
	rmTree := cmd.NewFleetCmd(cfgPath)
	rmTree.SetArgs([]string{"--fleet-file", fleetPath, "remove", "us1", "--keep-dns"})
	if err := rmTree.Execute(); err != nil {
		t.Fatalf("fleet remove failed: %v", err)
	}

	// 4. Positional argument & host:port/user boundaries
	cmd.ApplyPositionalFleetNewArgs(nil, nil, false, false)

	bsIPv6 := fleet.BootstrapInput{Port: 22, User: "ubuntu"}
	cmd.ApplyPositionalFleetNewArgs([]string{"root@[2001:db8::10]:2200"}, &bsIPv6, true, true)
	if bsIPv6.Host != "2001:db8::10" || bsIPv6.Port != 22 || bsIPv6.User != "ubuntu" {
		t.Fatalf("expected explicit flags preserved for IPv6 arg, got %+v", bsIPv6)
	}

	host, port, user, ok := cmd.SplitHostPortUser("ops@node.example.com:2222")
	if !ok || host != "node.example.com" || port != 2222 || user != "ops" {
		t.Fatalf("SplitHostPortUser unexpected result: (%q, %d, %q, %v)", host, port, user, ok)
	}
	if _, _, _, badOK := cmd.SplitHostPortUser("   "); badOK {
		t.Fatal("expected empty SplitHostPortUser to return ok=false")
	}
}

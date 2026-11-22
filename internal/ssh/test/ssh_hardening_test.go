// 文件职责：验证远端 SSH 双端口安全过渡加固、防火墙端口边界校验与本地 ~/.ssh/config 强制 0600 收紧。
package ssh_test

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"singctl/internal/ssh"
)

type recordingExecutor struct {
	cmds    []string
	handler func(cmd string) (string, error)
}

func (r *recordingExecutor) Run(cmd string) (string, error) {
	r.cmds = append(r.cmds, cmd)
	if r.handler != nil {
		return r.handler(cmd)
	}
	return "", nil
}

func (r *recordingExecutor) InjectPublicKey(string) error { return nil }
func (r *recordingExecutor) Close() error                 { return nil }

func TestSshdHarden_And_FirewallManager_PortValidationAndCommands(t *testing.T) {
	exec := &recordingExecutor{
		handler: func(cmd string) (string, error) {
			switch {
			case strings.Contains(cmd, "sshd") && strings.Contains(cmd, "-T"):
				return "port 22\nport 2222\npasswordauthentication no\npubkeyauthentication yes\n", nil
			case strings.Contains(cmd, "getenforce"):
				return "Enforcing\n", nil
			case strings.Contains(cmd, "ufw status"):
				return "active\n", nil
			case strings.Contains(cmd, "firewall-cmd --state"):
				return "running\n", nil
			case strings.Contains(cmd, "iptables -S"):
				return "drop_policy\n", nil
			default:
				return "", nil
			}
		},
	}

	info, err := ssh.InspectRemoteSshd(exec)
	if err != nil {
		t.Fatalf("InspectRemoteSshd failed: %v", err)
	}
	if !slices.Equal(info.Ports, []int{22, 2222}) || info.PasswordAuth || !info.PubkeyAuth {
		t.Fatalf("unexpected RemoteSshdInfo: %+v", info)
	}

	harden := ssh.NewSshdHarden(exec)
	if err := harden.EnableDualPort(22, 70000); err == nil {
		t.Fatal("expected EnableDualPort to reject port > 65535")
	}
	if err := harden.FinalizeHardening(70000, true); err == nil {
		t.Fatal("expected FinalizeHardening to reject port > 65535")
	}
	if err := harden.EnableDualPort(22, 2222); err != nil {
		t.Fatalf("EnableDualPort(22, 2222) failed: %v", err)
	}
	if err := harden.FinalizeHardening(2222, true); err != nil {
		t.Fatalf("FinalizeHardening(2222, true) failed: %v", err)
	}
	if err := harden.RollbackToPort(99999); err != nil {
		t.Fatalf("RollbackToPort fallback failed: %v", err)
	}
	lastWrite := ""
	for _, c := range exec.cmds {
		if strings.Contains(c, ssh.HardeningConfPath) {
			lastWrite = c
		}
	}
	if !strings.Contains(lastWrite, "Port 22\n") {
		t.Fatalf("expected RollbackToPort(99999) to fall back to Port 22, got:\n%s", lastWrite)
	}

	fw := ssh.NewFirewallManager(exec)
	if err := fw.AllowPort(0); err == nil {
		t.Fatal("expected AllowPort(0) to return error")
	}
	if err := fw.AllowPort(70000); err == nil {
		t.Fatal("expected AllowPort(70000) to return error")
	}
	if err := fw.DisallowPort(-1); err == nil {
		t.Fatal("expected DisallowPort(-1) to return error")
	}
	if err := fw.AllowPort(2222); err != nil {
		t.Fatalf("AllowPort(2222) failed: %v", err)
	}
	if err := fw.DisallowPort(22); err != nil {
		t.Fatalf("DisallowPort(22) failed: %v", err)
	}
}

func TestLocalConfigManager_Enforces0600EvenOnPreExisting0644(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, ".ssh", "config")
	if err := os.MkdirAll(filepath.Dir(cfgPath), 0755); err != nil {
		t.Fatal(err)
	}
	// Pre-existing insecure 0644 ~/.ssh/config with user's custom entry
	initial := "Host personal-box\n    HostName 192.0.2.10\n    User dev\n"
	if err := os.WriteFile(cfgPath, []byte(initial), 0644); err != nil {
		t.Fatal(err)
	}

	mgr := ssh.NewLocalConfigManager(cfgPath)
	hosts := []*ssh.Host{
		{
			Name:       "edge-01",
			Host:       "node1.example.com",
			User:       "root",
			TargetPort: 2222,
			PrivateKey: "/tmp/test_ed25519",
		},
		{
			Name:        "skip-alias",
			IsAliasMode: true,
		},
	}
	if err := mgr.SyncHosts(hosts); err != nil {
		t.Fatalf("SyncHosts failed: %v", err)
	}

	st, err := os.Stat(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if perm := st.Mode().Perm(); perm != 0600 {
		t.Fatalf("expected ~/.ssh/config perm forced to 0600, got %04o", perm)
	}

	managed, err := mgr.ListManagedHosts()
	if err != nil || len(managed) != 1 || managed[0].Name != "edge-01" || managed[0].Port != 2222 {
		t.Fatalf("unexpected ListManagedHosts: (%+v, %v)", managed, err)
	}

	removed, err := mgr.CleanManagedHosts("edge-01")
	if err != nil || removed != 1 {
		t.Fatalf("CleanManagedHosts = (%d, %v), want (1, nil)", removed, err)
	}
	rawAfter, _ := os.ReadFile(cfgPath)
	if !strings.Contains(string(rawAfter), "Host personal-box") || strings.Contains(string(rawAfter), "edge-01") {
		t.Fatalf("unexpected config content after clean:\n%s", string(rawAfter))
	}
}

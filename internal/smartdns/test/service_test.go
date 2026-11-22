// 文件职责：验证 SmartDNS systemd/OpenWrt procd 服务单元渲染、servicemgr 启停重载、清缓存与本地 UDP DNS 探活。
package smartdns_test

import (
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"singctl/internal/platform/servicemgr"
	"singctl/internal/smartdns"
)

func TestBuildServiceUnits(t *testing.T) {
	unit := smartdns.BuildSystemdUnit("/usr/bin/smartdns", "/etc/singctl/smartdns.conf", "/tmp/singctl-smartdns.pid")
	for _, kw := range []string{
		"Type=simple",
		"ExecStart=/usr/bin/smartdns -f -c /etc/singctl/smartdns.conf -p /tmp/singctl-smartdns.pid",
		"Restart=on-failure",
		"MemoryMax=64M",
	} {
		if !strings.Contains(unit, kw) {
			t.Errorf("systemd unit missing %q:\n%s", kw, unit)
		}
	}

	procd := smartdns.BuildOpenWrtInitScript("/usr/bin/smartdns", "/etc/singctl/smartdns.conf", "/tmp/singctl-smartdns.pid")
	for _, kw := range []string{
		"#!/bin/sh /etc/rc.common",
		"USE_PROCD=1",
		`procd_open_instance "singctl-smartdns"`,
		`procd_set_param command "$PROG" -f -c "$CONF" -p "$PIDFILE"`,
		"procd_set_param respawn",
		`procd_set_param env "TZ=$TZ_VAL"`,
	} {
		if !strings.Contains(procd, kw) {
			t.Errorf("procd script missing %q:\n%s", kw, procd)
		}
	}
}

func TestManager_ServiceLifecycleWithMockServiceMgr(t *testing.T) {
	root := t.TempDir()
	binPath := filepath.Join(root, "smartdns")
	if err := os.WriteFile(binPath, []byte("#!/bin/sh\necho 'smartdns Release48.5'\n"), 0755); err != nil {
		t.Fatal(err)
	}
	mockSvc := servicemgr.NewMock()

	mgr := smartdns.NewManager(smartdns.ManagerOptions{
		BinaryPath:   binPath,
		ConfigDir:    filepath.Join(root, "etc"),
		AuditLogPath: filepath.Join(root, "audit.log"),
		LogFilePath:  filepath.Join(root, "smartdns.log"),
		PIDFilePath:  filepath.Join(root, "smartdns.pid"),
		GOOS:         "linux",
		GOARCH:       "arm64",
		ServiceMgr:   mockSvc,
		ProbeDNSFunc: func(string, time.Duration) error { return nil },
	})

	if err := mgr.Start(); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	if err := mgr.Reload(); err != nil {
		t.Fatalf("Reload failed: %v", err)
	}
	if err := mgr.ClearCache(); err != nil {
		t.Fatalf("ClearCache failed: %v", err)
	}
	if err := mgr.Restart(); err != nil {
		t.Fatalf("Restart failed: %v", err)
	}
	if err := mgr.Stop(); err != nil {
		t.Fatalf("Stop failed: %v", err)
	}

	calls := mockSvc.Calls()
	for _, expected := range []string{
		"enable singctl-smartdns",
		"start singctl-smartdns",
		"reload singctl-smartdns",
		"restart singctl-smartdns",
		"stop singctl-smartdns",
	} {
		if !slices.Contains(calls, expected) {
			t.Errorf("expected servicemgr call %q in %v", expected, calls)
		}
	}

	// Missing binary should fail Start and ClearCache
	_ = os.Remove(binPath)
	if err := mgr.Start(); err == nil {
		t.Error("expected Start to fail when binary missing")
	}
	if err := mgr.ClearCache(); err == nil {
		t.Error("expected ClearCache to fail when binary missing")
	}
}

func TestProbeDNS_LocalUDPLoopback(t *testing.T) {
	// Spin up an in-process synthetic UDP DNS responder on 127.0.0.1:0
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	defer pc.Close()

	go func() {
		buf := make([]byte, 512)
		for {
			n, addr, readErr := pc.ReadFrom(buf)
			if readErr != nil {
				return
			}
			if n < 12 {
				continue
			}
			resp := make([]byte, n)
			copy(resp, buf[:n])
			resp[2] |= 0x80 // QR=1 response flag
			_, _ = pc.WriteTo(resp, addr)
		}
	}()

	if err := smartdns.ProbeDNS(pc.LocalAddr().String(), 500*time.Millisecond); err != nil {
		t.Fatalf("ProbeDNS against synthetic UDP responder failed: %v", err)
	}

	// Closed port should fail
	closedPC, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closedAddr := closedPC.LocalAddr().String()
	_ = closedPC.Close()

	if err := smartdns.ProbeDNS(closedAddr, 150*time.Millisecond); err == nil {
		t.Fatal("expected ProbeDNS to fail against closed UDP port")
	}
}

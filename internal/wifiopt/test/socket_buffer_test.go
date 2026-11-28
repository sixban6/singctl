package wifiopt_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"singctl/internal/wifiopt"
)

func newFakeSocketBufferSideRouterEnv(t *testing.T, rmemDefault string) (*wifiopt.Env, map[string][]byte, *sync.Mutex) {
	t.Helper()
	tmp := t.TempDir()
	quicSysctl := filepath.Join(tmp, "99-quic-buffer.conf")
	sysctlFile := filepath.Join(tmp, "sysctl.conf")
	modDir := filepath.Join(tmp, "modules.d")
	_ = os.WriteFile(sysctlFile, []byte("# sysctl\n"), 0644)
	_ = os.MkdirAll(modDir, 0755)

	var mu sync.Mutex
	files := map[string][]byte{
		"/proc/meminfo":                                     []byte("MemTotal:       1843200 kB\n"),
		"/proc/sys/net/netfilter/nf_conntrack_max":          []byte("131072\n"),
		"/proc/sys/net/netfilter/nf_conntrack_count":        []byte("1024\n"),
		"/proc/sys/net/core/rmem_max":                       []byte("212992\n"),
		"/proc/sys/net/core/wmem_max":                       []byte("212992\n"),
		"/proc/sys/net/core/rmem_default":                   []byte(rmemDefault + "\n"),
		"/proc/sys/net/core/wmem_default":                   []byte(rmemDefault + "\n"),
		"/proc/sys/net/core/default_qdisc":                  []byte("fq_codel\n"),
		"/proc/sys/net/ipv4/tcp_congestion_control":         []byte("cubic\n"),
		"/proc/sys/net/ipv4/tcp_available_congestion_control": []byte("reno cubic bbr\n"),
		"/proc/net/snmp": []byte("Udp: InDatagrams NoPorts InErrors OutDatagrams RcvbufErrors SndbufErrors\nUdp: 10000 0 0 8000 256 0\n"),
	}

	env := &wifiopt.Env{
		GOOS:           "linux",
		SysctlFile:     sysctlFile,
		QuicSysctlFile: quicSysctl,
		ModulesDir:     modDir,
		CPUCount:       4,
		ReadFile: func(p string) ([]byte, error) {
			mu.Lock()
			defer mu.Unlock()
			if b, ok := files[p]; ok {
				return slices.Clone(b), nil
			}
			return os.ReadFile(p)
		},
		WriteFile0600: func(p string, d []byte) error {
			mu.Lock()
			defer mu.Unlock()
			if strings.HasPrefix(p, "/proc/") || strings.HasPrefix(p, "/sys/") {
				files[p] = slices.Clone(d)
				return nil
			}
			return os.WriteFile(p, d, 0644)
		},
		Glob: func(string) ([]string, error) { return nil, nil },
		RunCmd: func(_ context.Context, name string, args ...string) ([]byte, error) {
			mu.Lock()
			defer mu.Unlock()
			if name == "modprobe" {
				return nil, nil
			}
			if name == "sysctl" && len(args) >= 2 && args[0] == "-p" {
				raw, err := os.ReadFile(args[1])
				if err != nil {
					return nil, err
				}
				for line := range strings.SplitSeq(string(raw), "\n") {
					tline := strings.TrimSpace(line)
					if tline == "" || strings.HasPrefix(tline, "#") {
						continue
					}
					if k, v, ok := strings.Cut(tline, "="); ok {
						procPath := "/proc/sys/" + strings.ReplaceAll(strings.TrimSpace(k), ".", "/")
						files[procPath] = []byte(strings.TrimSpace(v) + "\n")
					}
				}
				return nil, nil
			}
			return nil, nil
		},
	}
	return env, files, &mu
}

func TestChassis_SocketBufferSideRouterSupportAndApply(t *testing.T) {
	// Even with NO eth* rps_cpus interfaces (e.g. non-Wi-Fi side-router), SocketBuffer makes Chassis Supported!
	env, files, mu := newFakeSocketBufferSideRouterEnv(t, "67108864")
	svc := wifiopt.NewService(*env)

	st := svc.InspectChassis(t.Context())
	if !st.Supported {
		t.Fatalf("expected ChassisStatus.Supported=true when SocketBuffer is supported")
	}
	if st.SocketBuffer == nil || !st.SocketBuffer.Supported || !st.SocketBuffer.ExcessiveDefault {
		t.Fatalf("expected SocketBuffer supported & ExcessiveDefault=true, got %+v", st.SocketBuffer)
	}
	if st.Optimal {
		t.Fatalf("expected ChassisStatus.Optimal=false when SocketBuffer is not optimal")
	}

	// Apply ONLY TuneSocketBuffer (without EnableRPS or TuneConntrack) must succeed!
	res, err := svc.ApplyChassis(t.Context(), wifiopt.ChassisApplyRequest{
		TuneSocketBuffer: true,
	})
	if err != nil {
		t.Fatalf("ApplyChassis(TuneSocketBuffer=true) failed: %v", err)
	}
	if !res.OK || !res.RestartSingBoxRecommended || !res.Chassis.Optimal {
		t.Fatalf("expected OK + RestartSingBoxRecommended + Optimal, got %+v", res)
	}
	if res.Chassis.SocketBuffer == nil || !res.Chassis.SocketBuffer.Optimal || res.Chassis.SocketBuffer.RmemDefault != 262144 {
		t.Fatalf("expected converged SocketBuffer (rmemDefault=262144, optimal=true), got %+v", res.Chassis.SocketBuffer)
	}
	mu.Lock()
	gotMax := strings.TrimSpace(string(files["/proc/sys/net/core/rmem_max"]))
	mu.Unlock()
	if gotMax != "16777216" {
		t.Fatalf("expected rmem_max=16777216, got %q", gotMax)
	}

	// Empty request (all false) must still return ErrInvalidRequest.
	if _, err := svc.ApplyChassis(t.Context(), wifiopt.ChassisApplyRequest{}); !errors.Is(err, wifiopt.ErrInvalidRequest) {
		t.Fatalf("expected ErrInvalidRequest on empty ChassisApplyRequest, got %v", err)
	}
}

func TestQuickSupported_TableDriven(t *testing.T) {
	tests := []struct {
		name      string
		isOpenWrt bool
		wireless  string
		missing   bool
		want      bool
	}{
		{
			name:      "non_openwrt_false",
			isOpenWrt: false,
			wireless:  "config wifi-device 'radio0'\n",
			want:      false,
		},
		{
			name:      "openwrt_missing_wireless_file",
			isOpenWrt: true,
			missing:   true,
			want:      false,
		},
		{
			name:      "openwrt_side_router_comments_only",
			isOpenWrt: true,
			wireless:  "# no wifi\n# config wifi-device 'fake'\n",
			want:      false,
		},
		{
			name:      "openwrt_with_wifi_device_true",
			isOpenWrt: true,
			wireless:  "config wifi-device 'MT7986_1_1'\n\toption type 'mtwifi'\n",
			want:      true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			runCalls := 0
			svc := wifiopt.NewService(wifiopt.Env{
				IsOpenWrt: func() bool { return tc.isOpenWrt },
				ReadFile: func(path string) ([]byte, error) {
					if tc.missing {
						return nil, os.ErrNotExist
					}
					return []byte(tc.wireless), nil
				},
				RunCmd: func(context.Context, string, ...string) ([]byte, error) {
					runCalls++
					return nil, errors.New("QuickSupported must not exec external commands")
				},
			})
			if got := svc.QuickSupported(); got != tc.want {
				t.Fatalf("QuickSupported() = %v, want %v", got, tc.want)
			}
			if runCalls != 0 {
				t.Fatalf("QuickSupported called RunCmd %d times (must be 0)", runCalls)
			}
		})
	}
}

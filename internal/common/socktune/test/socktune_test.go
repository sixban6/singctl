package socktune_test

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"singctl/internal/common/socktune"
)

type fakeFileInfo struct {
	name  string
	isDir bool
}

func (f fakeFileInfo) Name() string       { return f.name }
func (f fakeFileInfo) Size() int64        { return 0 }
func (f fakeFileInfo) Mode() os.FileMode  { return 0755 }
func (f fakeFileInfo) ModTime() time.Time { return time.Time{} }
func (f fakeFileInfo) IsDir() bool        { return f.isDir }
func (f fakeFileInfo) Sys() any           { return nil }

const sampleProcNetSnmp = `Ip: Forwarding DefaultTTL InReceives InHdrErrors InAddrErrors ForwDatagrams InUnknownProtos InDiscards InDelivers OutRequests OutDiscards OutNoRoutes ReasmTimeout ReasmReqds ReasmOKs ReasmFails FragOKs FragFails FragCreates
Ip: 1 64 12000 0 0 0 0 0 11000 9000 0 0 0 0 0 0 0 0 0
Udp: InDatagrams NoPorts InErrors OutDatagrams RcvbufErrors SndbufErrors InCsumErrors IgnoredMulti MemErrors
Udp: 500000 12 3 400000 1980 42 0 0 0
`

type memKernelFS struct {
	mu           sync.Mutex
	files        map[string][]byte
	dirs         map[string]bool
	cmds         []string
	modprobeErr  error
	readOnlyProc bool
	clampProc    bool // simulate kernel silently clamping/ignoring writes on readback
	baseDir      string
}

func newMemKernelFS(t *testing.T, memKB string) *memKernelFS {
	t.Helper()
	tmp := t.TempDir()
	fsMap := map[string][]byte{
		"/proc/meminfo":                                    []byte("MemTotal:       " + memKB + " kB\nMemAvailable:   " + memKB + " kB\n"),
		"/proc/sys/net/core/rmem_max":                      []byte("212992\n"),
		"/proc/sys/net/core/wmem_max":                      []byte("212992\n"),
		"/proc/sys/net/core/rmem_default":                  []byte("212992\n"),
		"/proc/sys/net/core/wmem_default":                  []byte("212992\n"),
		"/proc/sys/net/core/default_qdisc":                 []byte("fq_codel\n"),
		"/proc/sys/net/ipv4/tcp_congestion_control":        []byte("cubic\n"),
		"/proc/sys/net/ipv4/tcp_available_congestion_control": []byte("reno cubic bbr\n"),
		"/proc/net/snmp":                                   []byte(sampleProcNetSnmp),
	}
	return &memKernelFS{
		files:   fsMap,
		dirs:    map[string]bool{},
		baseDir: tmp,
	}
}

func (m *memKernelFS) sysctlPath(rel string) string {
	return filepath.Join(m.baseDir, rel)
}

func (m *memKernelFS) env() socktune.Env {
	quicFile := m.sysctlPath("99-quic-buffer.conf")
	conflict1 := m.sysctlPath("sysctl.conf")
	conflict2 := m.sysctlPath("99-custom.conf")
	conflict3 := m.sysctlPath("99-singctl-bbr.conf")
	return socktune.Env{
		GOOS:                "linux",
		QuicSysctlFile:      quicFile,
		ConflictSysctlFiles: []string{conflict1, conflict2, conflict3},
		ModulesDir:          m.sysctlPath("modules.d"),
		ReadFile: func(path string) ([]byte, error) {
			m.mu.Lock()
			defer m.mu.Unlock()
			if b, ok := m.files[path]; ok {
				return slices.Clone(b), nil
			}
			if b, err := os.ReadFile(path); err == nil {
				return b, nil
			}
			return nil, os.ErrNotExist
		},
		WriteFile: func(path string, data []byte, perm os.FileMode) error {
			if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
				return err
			}
			return os.WriteFile(path, data, perm)
		},
		WriteProc: func(path string, data []byte) error {
			m.mu.Lock()
			defer m.mu.Unlock()
			if m.readOnlyProc {
				return &fs.PathError{Op: "open", Path: path, Err: errors.New("read-only file system")}
			}
			if !m.clampProc {
				m.files[path] = slices.Clone(data)
			}
			return nil
		},
		Stat: func(path string) (os.FileInfo, error) {
			m.mu.Lock()
			isDir := m.dirs[path]
			m.mu.Unlock()
			if isDir {
				return fakeFileInfo{name: filepath.Base(path), isDir: true}, nil
			}
			return os.Stat(path)
		},
		RunCmd: func(_ context.Context, name string, args ...string) ([]byte, error) {
			m.mu.Lock()
			defer m.mu.Unlock()
			m.cmds = append(m.cmds, name+" "+strings.Join(args, " "))
			switch name {
			case "modprobe":
				if m.modprobeErr != nil {
					return []byte("modprobe: module not found"), m.modprobeErr
				}
				return nil, nil
			case "sysctl":
				if m.readOnlyProc {
					return []byte("sysctl: setting key \"net.core.rmem_max\": Read-only file system"), errors.New("exit status 255")
				}
				if len(args) >= 2 && args[0] == "-p" {
					raw, err := os.ReadFile(args[1])
					if err != nil {
						return nil, err
					}
					if !m.clampProc {
						for line := range strings.SplitSeq(string(raw), "\n") {
							tline := strings.TrimSpace(line)
							if tline == "" || strings.HasPrefix(tline, "#") {
								continue
							}
							k, v, ok := strings.Cut(tline, "=")
							if !ok {
								continue
							}
							k = strings.TrimSpace(k)
							v = strings.TrimSpace(v)
							procPath := "/proc/sys/" + strings.ReplaceAll(k, ".", "/")
							m.files[procPath] = []byte(v + "\n")
						}
					}
					return nil, nil
				}
				return nil, nil
			default:
				return nil, errors.New("unexpected cmd: " + name)
			}
		},
	}
}

func TestInspect_NonLinuxUnsupported(t *testing.T) {
	m := newMemKernelFS(t, "1048576")
	env := m.env()
	env.GOOS = "darwin"

	st := socktune.Inspect(socktune.ProfileClient, env)
	if st.Supported {
		t.Fatalf("expected Supported=false on darwin, got %+v", st)
	}

	_, err := socktune.Apply(t.Context(), socktune.ProfileClient, socktune.ApplyRequest{}, env)
	if !errors.Is(err, socktune.ErrUnsupported) {
		t.Fatalf("expected ErrUnsupported on darwin, got %v", err)
	}
}

func TestInspect_ClientMemoryTiersAndSnmpParsing(t *testing.T) {
	tests := []struct {
		name           string
		memKB          string
		wantMax        int
		wantDefault    int
	}{
		{name: "ultra_lowmem_230mb_ax3000t", memKB: "235520", wantMax: 2097152, wantDefault: 212992},
		{name: "mid_mem_479mb_n60pro", memKB: "490496", wantMax: 4194304, wantDefault: 212992},
		{name: "high_mem_1800mb_n1_n4120", memKB: "1843200", wantMax: 16777216, wantDefault: 262144},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m := newMemKernelFS(t, tc.memKB)
			st := socktune.Inspect(socktune.ProfileClient, m.env())
			if !st.Supported {
				t.Fatalf("expected Supported=true, got %+v", st)
			}
			if st.RecommendedRmemMax != tc.wantMax || st.RecommendedWmemMax != tc.wantMax {
				t.Errorf("recommended max = (%d,%d), want %d", st.RecommendedRmemMax, st.RecommendedWmemMax, tc.wantMax)
			}
			if st.RecommendedRmemDefault != tc.wantDefault || st.RecommendedWmemDefault != tc.wantDefault {
				t.Errorf("recommended default = (%d,%d), want %d", st.RecommendedRmemDefault, st.RecommendedWmemDefault, tc.wantDefault)
			}
			if st.UDPRcvbufErrors != 1980 || st.UDPSndbufErrors != 42 {
				t.Errorf("snmp UDP errors = (%d,%d), want (1980,42)", st.UDPRcvbufErrors, st.UDPSndbufErrors)
			}
			if st.Optimal {
				t.Errorf("expected Optimal=false when buffers are 212992 and BBR disabled")
			}
		})
	}
}

func TestApply_ClientExcessiveDefaultConvergenceAndBackup(t *testing.T) {
	m := newMemKernelFS(t, "1843200")
	m.files["/proc/sys/net/core/rmem_max"] = []byte("104857600\n")
	m.files["/proc/sys/net/core/rmem_default"] = []byte("67108864\n")
	m.files["/proc/sys/net/core/wmem_default"] = []byte("67108864\n")

	env := m.env()
	customPath := env.ConflictSysctlFiles[1]
	origCustom := "# user sysctl\nnet.core.rmem_max=104857600\nnet.core.rmem_default=67108864\nkernel.panic=10\n"
	if err := os.WriteFile(customPath, []byte(origCustom), 0644); err != nil {
		t.Fatal(err)
	}

	st := socktune.Inspect(socktune.ProfileClient, env)
	if !st.ExcessiveDefault || st.DefaultBufferOptimal || st.Optimal {
		t.Fatalf("expected ExcessiveDefault=true DefaultBufferOptimal=false Optimal=false, got %+v", st)
	}

	res, err := socktune.Apply(t.Context(), socktune.ProfileClient, socktune.ApplyRequest{}, env)
	if err != nil {
		t.Fatalf("Apply client failed: %v", err)
	}
	if !res.OK || !res.DefaultBufferChanged || !res.RestartRecommended || !res.Status.Optimal || res.Status.ExcessiveDefault {
		t.Fatalf("unexpected Apply result after convergence: %+v", res)
	}
	if res.Status.RmemDefault != 262144 || res.Status.WmemDefault != 262144 || res.Status.RmemMax != 16777216 {
		t.Fatalf("buffers not converged: %+v", res.Status)
	}

	// Conflict file must retain unrelated keys and have a .bak backup.
	bakBytes, err := os.ReadFile(customPath + ".bak")
	if err != nil || string(bakBytes) != origCustom {
		t.Fatalf("expected original backup at %s.bak, err=%v", customPath, err)
	}
	cleaned, _ := os.ReadFile(customPath)
	if strings.Contains(string(cleaned), "rmem_default") || !strings.Contains(string(cleaned), "kernel.panic=10") {
		t.Fatalf("conflict stripping malformed: %q", string(cleaned))
	}
}

func TestApply_ClientWithoutBBRModuleAndOpenWrtPersistence(t *testing.T) {
	t.Run("no_bbr_module_still_optimizes_buffers", func(t *testing.T) {
		m := newMemKernelFS(t, "490496")
		m.files["/proc/sys/net/ipv4/tcp_available_congestion_control"] = []byte("reno cubic\n")
		m.modprobeErr = errors.New("module tcp_bbr not found")

		res, err := socktune.Apply(t.Context(), socktune.ProfileClient, socktune.ApplyRequest{}, m.env())
		if err != nil {
			t.Fatalf("Apply without BBR failed: %v", err)
		}
		if len(res.Warnings) == 0 {
			t.Fatalf("expected warning when tcp_bbr unavailable")
		}
		if !res.Status.Optimal || res.Status.RmemMax != 4194304 || res.Status.BBREnabled {
			t.Fatalf("expected buffers optimal even without BBR, got %+v", res.Status)
		}
		raw, _ := os.ReadFile(m.env().QuicSysctlFile)
		if strings.Contains(string(raw), "tcp_congestion_control=bbr") {
			t.Fatalf("must not write bbr sysctl when kernel lacks tcp_bbr: %q", string(raw))
		}
	})

	t.Run("openwrt_modules_d_persists_bbr_fq", func(t *testing.T) {
		m := newMemKernelFS(t, "1843200")
		env := m.env()
		if err := os.MkdirAll(env.ModulesDir, 0755); err != nil {
			t.Fatal(err)
		}
		res, err := socktune.Apply(t.Context(), socktune.ProfileClient, socktune.ApplyRequest{}, env)
		if err != nil {
			t.Fatalf("Apply failed: %v", err)
		}
		if !res.Status.BBREnabled || res.Status.DefaultQdisc != "fq" {
			t.Fatalf("expected bbr+fq enabled, got %+v", res.Status)
		}
		modBytes, err := os.ReadFile(filepath.Join(env.ModulesDir, "99-singctl-bbr-fq"))
		if err != nil {
			t.Fatalf("expected OpenWrt modules.d persistence file: %v", err)
		}
		if !strings.Contains(string(modBytes), "tcp_bbr") || !strings.Contains(string(modBytes), "sch_fq") {
			t.Fatalf("unexpected modules.d content: %q", string(modBytes))
		}
	})
}

func TestInspectAndApply_ServerBottleneckAndPresets(t *testing.T) {
	// 512MB VPS recommends 4MB default; 1024MB VPS recommends 8MB default.
	m512 := newMemKernelFS(t, "524288")
	st512 := socktune.Inspect(socktune.ProfileServer, m512.env())
	if !st512.DefaultBottleneck || st512.RecommendedRmemMax != 16777216 || st512.RecommendedRmemDefault != 4194304 {
		t.Fatalf("unexpected 512MB server recommendation: %+v", st512)
	}

	m1024 := newMemKernelFS(t, "1048576")
	env1024 := m1024.env()
	st1024 := socktune.Inspect(socktune.ProfileServer, env1024)
	if !st1024.DefaultBottleneck || st1024.RecommendedRmemDefault != 8388608 {
		t.Fatalf("unexpected 1024MB server recommendation: %+v", st1024)
	}

	// Switch to 4m preset first.
	res4, err := socktune.Apply(t.Context(), socktune.ProfileServer, socktune.ApplyRequest{DefaultPreset: "4m"}, env1024)
	if err != nil {
		t.Fatalf("Apply 4m preset failed: %v", err)
	}
	if !res4.DefaultBufferChanged || !res4.RestartRecommended || !res4.Status.Optimal || res4.Status.DefaultBottleneck {
		t.Fatalf("unexpected 4m preset result: %+v", res4)
	}
	if res4.Status.RmemDefault != 4194304 {
		t.Fatalf("want rmemDefault=4194304, got %d", res4.Status.RmemDefault)
	}

	// Switch from 4m to 8m preset.
	res8, err := socktune.Apply(t.Context(), socktune.ProfileServer, socktune.ApplyRequest{DefaultPreset: "8m"}, env1024)
	if err != nil {
		t.Fatalf("Apply 8m preset failed: %v", err)
	}
	if !res8.DefaultBufferChanged || !res8.RestartRecommended || res8.Status.RmemDefault != 8388608 {
		t.Fatalf("unexpected 8m preset result: %+v", res8)
	}
}

func TestApply_ErrorBoundariesReadonlyInvalidAndClamp(t *testing.T) {
	t.Run("container_readonly_erofs", func(t *testing.T) {
		m := newMemKernelFS(t, "1048576")
		m.readOnlyProc = true
		_, err := socktune.Apply(t.Context(), socktune.ProfileServer, socktune.ApplyRequest{}, m.env())
		if !errors.Is(err, socktune.ErrReadOnlyKernel) {
			t.Fatalf("expected ErrReadOnlyKernel, got %v", err)
		}
	})

	t.Run("invalid_presets_and_out_of_range", func(t *testing.T) {
		m := newMemKernelFS(t, "1048576")
		cases := []struct {
			profile socktune.Profile
			req     socktune.ApplyRequest
		}{
			{socktune.ProfileServer, socktune.ApplyRequest{DefaultPreset: "8m; rm -rf /"}},
			{socktune.ProfileServer, socktune.ApplyRequest{DefaultPreset: "64m"}},
			{socktune.ProfileServer, socktune.ApplyRequest{RmemMax: -1}},
			{socktune.ProfileServer, socktune.ApplyRequest{RmemMax: 100 * 1024 * 1024 * 1024}},
			{socktune.ProfileClient, socktune.ApplyRequest{RmemDefault: 8388608}},
			{socktune.ProfileClient, socktune.ApplyRequest{RmemDefault: 1024}},
		}
		for _, tc := range cases {
			if _, err := socktune.Apply(t.Context(), tc.profile, tc.req, m.env()); !errors.Is(err, socktune.ErrInvalidRequest) {
				t.Errorf("expected ErrInvalidRequest for (%s, %+v), got %v", tc.profile, tc.req, err)
			}
		}
	})

	t.Run("readback_mismatch_rejected", func(t *testing.T) {
		m := newMemKernelFS(t, "1048576")
		m.clampProc = true
		_, err := socktune.Apply(t.Context(), socktune.ProfileServer, socktune.ApplyRequest{}, m.env())
		if err == nil || !strings.Contains(err.Error(), "回读") {
			t.Fatalf("expected readback verification error, got %v", err)
		}
	})
}

func TestInspectAndApply_IdempotentConcurrentRaceSafe(t *testing.T) {
	m := newMemKernelFS(t, "1048576")
	env := m.env()

	// Sequential repeated applies must be idempotent without duplicate keys.
	for range 2 {
		if _, err := socktune.Apply(t.Context(), socktune.ProfileServer, socktune.ApplyRequest{DefaultPreset: "8m"}, env); err != nil {
			t.Fatalf("repeated Apply failed: %v", err)
		}
	}
	raw, _ := os.ReadFile(env.QuicSysctlFile)
	if strings.Count(string(raw), "net.core.rmem_max=") != 1 {
		t.Fatalf("expected exactly 1 net.core.rmem_max line, got:\n%s", string(raw))
	}

	var wg sync.WaitGroup
	for i := range 8 {
		wg.Go(func() {
			if i%2 == 0 {
				st := socktune.Inspect(socktune.ProfileServer, env)
				if !st.Supported {
					t.Errorf("concurrent Inspect returned Unsupported")
				}
			} else {
				if _, err := socktune.Apply(t.Context(), socktune.ProfileServer, socktune.ApplyRequest{DefaultPreset: "8m"}, env); err != nil {
					t.Errorf("concurrent Apply failed: %v", err)
				}
			}
		})
	}
	wg.Wait()
}

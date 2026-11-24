package webui_test

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"

	"singctl/internal/platform/servicemgr"
	"singctl/internal/webui"
)

type recordingServiceMgr struct {
	*servicemgr.MockManager
	kind   servicemgr.InitKind
	mu     sync.Mutex
	events *[]string
	specs  []servicemgr.UnitSpec
}

func newRecordingServiceMgr(kind servicemgr.InitKind, events *[]string) *recordingServiceMgr {
	return &recordingServiceMgr{
		MockManager: servicemgr.NewMock(),
		kind:        kind,
		events:      events,
	}
}

func (r *recordingServiceMgr) Kind() servicemgr.InitKind { return r.kind }

func (r *recordingServiceMgr) InstallUnit(ctx context.Context, spec servicemgr.UnitSpec) error {
	r.mu.Lock()
	*r.events = append(*r.events, "install-unit:"+spec.Name)
	r.specs = append(r.specs, spec)
	r.mu.Unlock()
	return r.MockManager.InstallUnit(ctx, spec)
}

func (r *recordingServiceMgr) Stop(ctx context.Context, name string) error {
	r.mu.Lock()
	*r.events = append(*r.events, "stop:"+name)
	r.mu.Unlock()
	return r.MockManager.Stop(ctx, name)
}

func (r *recordingServiceMgr) Restart(ctx context.Context, name string) error {
	r.mu.Lock()
	*r.events = append(*r.events, "restart:"+name)
	r.mu.Unlock()
	return r.MockManager.Restart(ctx, name)
}

func TestWebService_BuildUnitSpec_ProcdAndSystemd(t *testing.T) {
	spec, err := webui.BuildWebUnitSpec("/usr/bin/singctl", "/etc/singctl/singctl.yaml", "[::]:8090")
	if err != nil {
		t.Fatalf("BuildWebUnitSpec unexpected error: %v", err)
	}
	if spec.Name != webui.WebServiceName {
		t.Fatalf("expected service name %q, got %q", webui.WebServiceName, spec.Name)
	}
	if len(spec.Env) != 0 {
		t.Fatalf("unit spec must never carry Env secrets, got %+v", spec.Env)
	}

	// OpenWrt procd checks (21.02 + 23.05+ compatibility)
	procdMustContain := []string{
		"#!/bin/sh /etc/rc.common",
		"START=95",
		"USE_PROCD=1",
		"procd_open_instance \"singctl-web\"",
		"procd_set_param command /usr/bin/singctl --config /etc/singctl/singctl.yaml web --managed -l :8090",
		"procd_set_param respawn 3600 5 0",
		"status_service()",
		"ubus call service list",
	}
	for _, want := range procdMustContain {
		if !strings.Contains(spec.ProcdBody, want) {
			t.Errorf("ProcdBody missing %q:\n%s", want, spec.ProcdBody)
		}
	}
	if strings.Contains(spec.ProcdBody, "SINGCTL_WEB_PASSWORD") || strings.Contains(spec.ProcdBody, "--password") {
		t.Errorf("ProcdBody must not leak password or env flags:\n%s", spec.ProcdBody)
	}

	// Linux systemd checks
	systemdMustContain := []string{
		"ExecStart=/usr/bin/singctl --config /etc/singctl/singctl.yaml web --managed -l :8090",
		"Restart=always",
		"OOMScoreAdjust=-500",
	}
	for _, want := range systemdMustContain {
		if !strings.Contains(spec.SystemdBody, want) {
			t.Errorf("SystemdBody missing %q:\n%s", want, spec.SystemdBody)
		}
	}
	if strings.Contains(spec.SystemdBody, "SINGCTL_WEB_PASSWORD") || strings.Contains(spec.SystemdBody, "--password") {
		t.Errorf("SystemdBody must not leak password or env flags:\n%s", spec.SystemdBody)
	}

	// Reject shell/unit injection payloads
	badCases := []struct {
		name   string
		exe    string
		cfg    string
		listen string
	}{
		{"empty_exe", "", "/etc/singctl/singctl.yaml", ":8090"},
		{"exe_semicolon", "/usr/bin/singctl;id", "/etc/singctl/singctl.yaml", ":8090"},
		{"cfg_newline", "/usr/bin/singctl", "/etc/singctl/singctl.yaml\nExecStart=/bin/sh", ":8090"},
		{"cfg_backtick", "/usr/bin/singctl", "/etc/singctl/`id`.yaml", ":8090"},
		{"listen_semicolon", "/usr/bin/singctl", "/etc/singctl/singctl.yaml", ":8090;reboot"},
		{"listen_newline", "/usr/bin/singctl", "/etc/singctl/singctl.yaml", ":8090\nRestart=no"},
		{"listen_dollar", "/usr/bin/singctl", "/etc/singctl/singctl.yaml", "$(id):8090"},
		{"listen_invalid_addr", "/usr/bin/singctl", "/etc/singctl/singctl.yaml", "not-a-host-port"},
	}
	for _, tc := range badCases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := webui.BuildWebUnitSpec(tc.exe, tc.cfg, tc.listen); err == nil {
				t.Fatalf("expected error for malformed input (%s, %s, %s), got nil", tc.exe, tc.cfg, tc.listen)
			}
		})
	}
}

func TestWebService_PasswordFile0600AndSpecialChars(t *testing.T) {
	tmp := t.TempDir()
	pwPath := filepath.Join(tmp, "sub", webui.WebPasswordFileName)
	specialSecret := `p'a"s$(reboot)` + "`id`" + `;|& $HOME 123`

	if err := webui.WriteWebPasswordFile(pwPath, specialSecret); err != nil {
		t.Fatalf("WriteWebPasswordFile failed: %v", err)
	}
	if runtime.GOOS != "windows" {
		fi, err := os.Stat(pwPath)
		if err != nil {
			t.Fatalf("stat password file failed: %v", err)
		}
		if got := fi.Mode().Perm(); got != 0600 {
			t.Fatalf("expected 0600 permission on password file, got %04o", got)
		}
	}

	got, err := webui.ReadWebPasswordFile(pwPath)
	if err != nil {
		t.Fatalf("ReadWebPasswordFile failed: %v", err)
	}
	if got != specialSecret {
		t.Fatalf("password mismatch: got %q, want %q", got, specialSecret)
	}

	// Resolution priority: flag > env > file
	t.Setenv("SINGCTL_WEB_PASSWORD", "")
	if resolved := webui.ResolveWebPasswordWithFile("", "", pwPath); resolved != specialSecret {
		t.Fatalf("expected file fallback %q, got %q", specialSecret, resolved)
	}
	t.Setenv("SINGCTL_WEB_PASSWORD", "env-secret")
	if resolved := webui.ResolveWebPasswordWithFile("", "", pwPath); resolved != "env-secret" {
		t.Fatalf("expected env priority, got %q", resolved)
	}
	if resolved := webui.ResolveWebPasswordWithFile("flag-secret", "", pwPath); resolved != "flag-secret" {
		t.Fatalf("expected flag priority, got %q", resolved)
	}

	// Empty password clears file idempotently
	if err := webui.WriteWebPasswordFile(pwPath, ""); err != nil {
		t.Fatalf("clearing password file failed: %v", err)
	}
	if _, err := os.Stat(pwPath); !os.IsNotExist(err) {
		t.Fatalf("expected password file removed, err=%v", err)
	}
	if err := webui.WriteWebPasswordFile(pwPath, ""); err != nil {
		t.Fatalf("second clear must be idempotent, got %v", err)
	}
}

func TestWebService_StartBackgroundWithDeps_HandoffLegacyStandalone(t *testing.T) {
	tmp := t.TempDir()
	prevState := webui.WebStatePathOverride
	webui.WebStatePathOverride = filepath.Join(tmp, "singctl-web.pid")
	t.Cleanup(func() { webui.WebStatePathOverride = prevState })

	cfgPath := filepath.Join(tmp, "singctl.yaml")
	pwPath := filepath.Join(tmp, webui.WebPasswordFileName)

	var events []string
	mgr := newRecordingServiceMgr(servicemgr.InitProcd, &events)

	deps := webui.BackgroundDeps{
		EmbeddedStatus:   func() (webui.WebState, bool) { return webui.WebState{}, false },
		ServiceMgr:       mgr,
		PasswordFilePath: pwPath,
		ExecutablePath:   "/usr/bin/singctl",
		HasLegacyStandalone: func() (webui.WebState, bool) {
			return webui.WebState{Pid: 4242, Listen: ":8090", ConfigPath: cfgPath, Password: "legacy-secret"}, true
		},
		StopStandalone: func() (bool, error) {
			events = append(events, "stop-standalone")
			return true, nil
		},
		WaitManagedReady: func(_ context.Context, _ servicemgr.Manager) (webui.WebState, bool) {
			return webui.WebState{Pid: 5353, Listen: ":8090", ConfigPath: cfgPath, ManagedBy: "procd"}, true
		},
	}

	err := webui.StartBackgroundWithDeps(webui.Options{
		ConfigPath: cfgPath,
		Listen:     ":8090",
	}, deps)
	if err != nil {
		t.Fatalf("StartBackgroundWithDeps failed: %v", err)
	}

	// Must stop legacy standalone process BEFORE InstallUnit so port :8090 is freed first
	wantOrder := []string{"stop-standalone", "install-unit:" + webui.WebServiceName}
	if !slices.Equal(events, wantOrder) {
		t.Fatalf("unexpected handoff order: got %v, want %v", events, wantOrder)
	}

	// Legacy password migrated safely to 0600 file and never embedded in unit spec
	migratedPw, err := webui.ReadWebPasswordFile(pwPath)
	if err != nil || migratedPw != "legacy-secret" {
		t.Fatalf("expected legacy password migrated to %s, got (%q, %v)", pwPath, migratedPw, err)
	}
	if len(mgr.specs) != 1 || strings.Contains(mgr.specs[0].ProcdBody, "legacy-secret") {
		t.Fatalf("unit spec must not contain password: %+v", mgr.specs)
	}
}

func TestWebService_StartBackgroundWithDeps_NoServiceFallsBackToStandalone(t *testing.T) {
	var events []string
	mgr := newRecordingServiceMgr(servicemgr.InitProcd, &events)
	standaloneCalled := false

	deps := webui.BackgroundDeps{
		EmbeddedStatus: func() (webui.WebState, bool) { return webui.WebState{}, false },
		ServiceMgr:     mgr,
		StartStandalone: func(_ webui.Options) error {
			standaloneCalled = true
			return nil
		},
	}

	if err := webui.StartBackgroundWithDeps(webui.Options{Listen: ":8090", NoService: true}, deps); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !standaloneCalled {
		t.Fatalf("expected fallback to standalone when NoService=true")
	}
	if len(events) != 0 {
		t.Fatalf("expected ServiceMgr not called when NoService=true, got %v", events)
	}
}

func TestWebService_StopAndStatusAndRestartWithDeps(t *testing.T) {
	tmp := t.TempDir()
	prevState := webui.WebStatePathOverride
	webui.WebStatePathOverride = filepath.Join(tmp, "singctl-web.pid")
	t.Cleanup(func() { webui.WebStatePathOverride = prevState })

	var events []string
	mgr := newRecordingServiceMgr(servicemgr.InitSystemd, &events)
	_ = mgr.Start(t.Context(), webui.WebServiceName)

	deps := webui.BackgroundDeps{
		EmbeddedStatus: func() (webui.WebState, bool) { return webui.WebState{}, false },
		ServiceMgr:     mgr,
		StopStandalone: func() (bool, error) { return false, nil },
	}

	// Status reports ManagedBy
	st, running := webui.WebStatusWithDeps(deps)
	if !running || st.ManagedBy != "systemd" {
		t.Fatalf("expected running managed systemd status, got running=%v st=%+v", running, st)
	}

	// Restart when already active calls mgr.Restart
	if err := webui.RestartWebWithDeps("/etc/singctl/singctl.yaml", deps); err != nil {
		t.Fatalf("RestartWebWithDeps failed: %v", err)
	}
	if !slices.Contains(events, "restart:"+webui.WebServiceName) {
		t.Fatalf("expected restart call on ServiceMgr, got %v", events)
	}

	// Stop calls mgr.Stop and is idempotent
	stopped, err := webui.StopWebWithDeps(deps)
	if err != nil || !stopped {
		t.Fatalf("expected stopped=true err=nil, got (%v, %v)", stopped, err)
	}
	if !slices.Contains(events, "stop:"+webui.WebServiceName) {
		t.Fatalf("expected stop call on ServiceMgr, got %v", events)
	}

	stopped2, err := webui.StopWebWithDeps(deps)
	if err != nil || stopped2 {
		t.Fatalf("expected second StopWebWithDeps idempotent (false, nil), got (%v, %v)", stopped2, err)
	}
}

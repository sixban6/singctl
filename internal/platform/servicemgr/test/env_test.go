// 文件职责：验证 servicemgr.UnitSpec.Env 在 Systemd 与 OpenWrt Procd 下的确定性渲染、防命令/指令注入及并发幂等性。
package servicemgr_test

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"singctl/internal/platform/servicemgr"
)

func TestUnitSpecEnv_SystemdAndProcdRenderingAndSecurity(t *testing.T) {
	ctx := t.Context()

	t.Run("procd_install_unit_renders_sorted_env_before_close_instance", func(t *testing.T) {
		dir := t.TempDir()
		runner := newFakeCmdRunner()
		mgr := servicemgr.NewProcd(runner, dir)
		initPath := filepath.Join(dir, "sing-box")
		baseBody := `#!/bin/sh /etc/rc.common

START=99
USE_PROCD=1

start_service() {
    procd_open_instance "sing-box"
    procd_set_param command /usr/bin/sing-box run -c /etc/sing-box/config.json
    procd_set_param respawn
    procd_close_instance
}
`
		spec := servicemgr.UnitSpec{
			Name:      "sing-box",
			ProcdPath: initPath,
			ProcdBody: baseBody,
			Env: map[string]string{
				"GOMEMLIMIT": "44MiB",
				"GOGC":       "50",
			},
		}
		if err := mgr.InstallUnit(ctx, spec); err != nil {
			t.Fatalf("Procd InstallUnit with Env failed: %v", err)
		}
		written, err := os.ReadFile(initPath)
		if err != nil {
			t.Fatalf("read procd script: %v", err)
		}
		got := string(written)
		wantLine := "procd_set_param env GOGC=50 GOMEMLIMIT=44MiB"
		if !strings.Contains(got, wantLine) {
			t.Fatalf("expected %q in procd script, got:\n%s", wantLine, got)
		}
		if strings.Index(got, wantLine) > strings.Index(got, "procd_close_instance") {
			t.Fatalf("expected procd_set_param env placed before procd_close_instance:\n%s", got)
		}

		// Idempotency when re-rendered with already injected body
		specAgain := spec
		specAgain.ProcdBody = got
		again, err := servicemgr.RenderProcdBody(specAgain)
		if err != nil {
			t.Fatalf("RenderProcdBody second pass failed: %v", err)
		}
		if strings.Count(again, "procd_set_param env") != 1 {
			t.Fatalf("expected idempotent single procd_set_param env line, got:\n%s", again)
		}
	})

	t.Run("systemd_install_unit_renders_sorted_environment_lines", func(t *testing.T) {
		dir := t.TempDir()
		runner := newFakeCmdRunner()
		mgr := servicemgr.NewSystemdWithDir(runner, dir)
		unitPath := filepath.Join(dir, "sing-box.service")
		baseUnit := `[Unit]
Description=sing-box service

[Service]
Type=simple
ExecStart=/usr/bin/sing-box run -c /etc/sing-box/config.json
Restart=on-failure

[Install]
WantedBy=multi-user.target
`
		spec := servicemgr.UnitSpec{
			Name:        "sing-box",
			SystemdPath: unitPath,
			SystemdBody: baseUnit,
			Env: map[string]string{
				"GOMEMLIMIT": "40MiB",
				"GOGC":       "50",
			},
		}
		if err := mgr.InstallUnit(ctx, spec); err != nil {
			t.Fatalf("Systemd InstallUnit with Env failed: %v", err)
		}
		written, err := os.ReadFile(unitPath)
		if err != nil {
			t.Fatalf("read systemd unit: %v", err)
		}
		got := string(written)
		if !strings.Contains(got, `Environment="GOGC=50"`) || !strings.Contains(got, `Environment="GOMEMLIMIT=40MiB"`) {
			t.Fatalf("expected Environment lines in systemd unit, got:\n%s", got)
		}
		svcIdx := strings.Index(got, "[Service]")
		instIdx := strings.Index(got, "[Install]")
		envIdx := strings.Index(got, `Environment="GOGC=50"`)
		if envIdx <= svcIdx || (instIdx > 0 && envIdx >= instIdx) {
			t.Fatalf("expected Environment injected inside [Service] section:\n%s", got)
		}

		// Idempotency when re-rendered
		specAgain := spec
		specAgain.SystemdBody = got
		again, err := servicemgr.RenderSystemdBody(specAgain)
		if err != nil {
			t.Fatalf("RenderSystemdBody second pass failed: %v", err)
		}
		if strings.Count(again, `Environment="GOMEMLIMIT=40MiB"`) != 1 {
			t.Fatalf("expected idempotent single Environment line, got:\n%s", again)
		}
	})

	t.Run("nil_or_empty_env_preserves_body_verbatim", func(t *testing.T) {
		orig := "[Unit]\nDescription=NoEnv\n"
		gotSys, err := servicemgr.RenderSystemdBody(servicemgr.UnitSpec{Name: "x", SystemdBody: orig})
		if err != nil || gotSys != orig {
			t.Fatalf("RenderSystemdBody empty env mutated body: %q err=%v", gotSys, err)
		}
		gotProcd, err := servicemgr.RenderProcdBody(servicemgr.UnitSpec{Name: "x", ProcdBody: orig})
		if err != nil || gotProcd != orig {
			t.Fatalf("RenderProcdBody empty env mutated body: %q err=%v", gotProcd, err)
		}
	})

	t.Run("rejects_malicious_env_keys_and_values_without_writing_files", func(t *testing.T) {
		badEnvs := []map[string]string{
			{"": "40MiB"},
			{"1BAD": "40MiB"},
			{"BAD KEY": "40MiB"},
			{"BAD=KEY": "40MiB"},
			{"GOMEMLIMIT;id": "40MiB"},
			{"GOMEMLIMIT\nExecStart": "40MiB"},
			{"GOMEMLIMIT": "40MiB\nExecStart=/bin/evil"},
			{"GOMEMLIMIT": "40MiB\r\nfoo"},
			{"GOMEMLIMIT": "40MiB\x00null"},
			{"GOMEMLIMIT": "$(id)"},
			{"GOMEMLIMIT": "`id`"},
			{"GOMEMLIMIT": "40MiB; rm -rf /"},
			{"GOMEMLIMIT": "40MiB' || evil"},
		}
		dir := t.TempDir()
		runner := newFakeCmdRunner()
		procdMgr := servicemgr.NewProcd(runner, dir)
		sysMgr := servicemgr.NewSystemdWithDir(runner, dir)
		mockMgr := servicemgr.NewMock()

		for i, bad := range badEnvs {
			if err := servicemgr.ValidateEnvMap(bad); err == nil {
				t.Fatalf("case[%d]: expected ValidateEnvMap error for %v", i, bad)
			}
			pPath := filepath.Join(dir, "bad-procd")
			if err := procdMgr.InstallUnit(ctx, servicemgr.UnitSpec{Name: "bad-procd", ProcdPath: pPath, ProcdBody: "#!/bin/sh\n", Env: bad}); err == nil {
				t.Fatalf("case[%d]: expected Procd InstallUnit to reject %v", i, bad)
			}
			if _, statErr := os.Stat(pPath); !os.IsNotExist(statErr) {
				t.Fatalf("case[%d]: Procd wrote file despite invalid Env", i)
			}
			sPath := filepath.Join(dir, "bad-sys.service")
			if err := sysMgr.InstallUnit(ctx, servicemgr.UnitSpec{Name: "bad-sys", SystemdPath: sPath, SystemdBody: "[Service]\n", Env: bad}); err == nil {
				t.Fatalf("case[%d]: expected Systemd InstallUnit to reject %v", i, bad)
			}
			if _, statErr := os.Stat(sPath); !os.IsNotExist(statErr) {
				t.Fatalf("case[%d]: Systemd wrote file despite invalid Env", i)
			}
			if err := mockMgr.InstallUnit(ctx, servicemgr.UnitSpec{Name: "bad-mock", Env: bad}); err == nil {
				t.Fatalf("case[%d]: expected MockManager InstallUnit to reject %v", i, bad)
			}
		}
	})

	t.Run("concurrent_render_race_safe", func(t *testing.T) {
		env := map[string]string{"GOMEMLIMIT": "44MiB", "GOGC": "50"}
		var wg sync.WaitGroup
		for range 8 {
			wg.Go(func() {
				if _, err := servicemgr.RenderSystemdBody(servicemgr.UnitSpec{Name: "sb", SystemdBody: "[Service]\nExecStart=/usr/bin/sing-box\n", Env: env}); err != nil {
					t.Errorf("concurrent RenderSystemdBody failed: %v", err)
				}
				if _, err := servicemgr.RenderProcdBody(servicemgr.UnitSpec{Name: "sb", ProcdBody: "start_service() {\n    procd_close_instance\n}\n", Env: env}); err != nil {
					t.Errorf("concurrent RenderProcdBody failed: %v", err)
				}
			})
		}
		wg.Wait()
	})
}

// 文件职责：提供客户端 WebUI Safe Commit 安全回滚保险丝状态查询、启动、确认解除、回滚执行、OOM 免疫与策略配置接口。
package webui

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"singctl/internal/config"
	"singctl/internal/constant"
	"singctl/internal/daemon"
	"singctl/internal/firewall"
	"singctl/internal/notify"
	"singctl/internal/safecommit"
	"singctl/internal/singbox"
	"singctl/internal/vlan"
	"singctl/internal/wifiopt"
)

type safeCommitConfigDTO struct {
	DefaultTTLSec       int  `json:"defaultTtlSec"`
	ProtectTailscaleOOM bool `json:"protectTailscaleOom"`
}

type safeCommitStatusResponse struct {
	safecommit.StatusReport
	Config safeCommitConfigDTO `json:"config"`
}

func safeCommitConfigFrom(cfg *config.Config) safeCommitConfigDTO {
	if cfg == nil {
		return safeCommitConfigDTO{
			DefaultTTLSec:       constant.SafeCommitDefaultTTLSec,
			ProtectTailscaleOOM: true,
		}
	}
	return safeCommitConfigDTO{
		DefaultTTLSec:       cfg.SafeCommit.EffectiveTTLSec(),
		ProtectTailscaleOOM: cfg.SafeCommit.IsProtectTailscaleOOM(),
	}
}

func (s *Server) safeCommitProcRoot() string {
	return strings.TrimSpace(s.opts.SafeCommitProcRoot)
}

func (s *Server) safeCommitManager() *safecommit.Manager {
	s.safeCommitMu.Lock()
	defer s.safeCommitMu.Unlock()
	if s.safeCommitMgr != nil {
		return s.safeCommitMgr
	}

	ops := s.buildSafeCommitRollbackOps()
	if s.opts.SafeCommitRollbackOps != nil {
		custom := *s.opts.SafeCommitRollbackOps
		userOnRolledBack := custom.OnRolledBack
		custom.OnRolledBack = func(rec safecommit.RollbackRecord) {
			if userOnRolledBack != nil {
				userOnRolledBack(rec)
			}
			s.onSafeCommitRolledBack(rec)
		}
		ops = custom
	}

	s.safeCommitMgr = safecommit.NewManager(safecommit.ManagerOptions{
		StateDir:     strings.TrimSpace(s.opts.SafeCommitStateDir),
		ProcRoot:     s.safeCommitProcRoot(),
		NowFunc:      s.opts.NowFunc,
		SpawnWatcher: s.opts.SafeCommitSpawnWatcher,
		KillWatcher:  s.opts.SafeCommitKillWatcher,
		RollbackOps:  ops,
	})
	return s.safeCommitMgr
}

func (s *Server) buildSafeCommitRollbackOps() safecommit.RollbackOps {
	return safecommit.RollbackOps{
		StopSingBox: func(context.Context) error {
			s.invalidateConfigStore()
			return singbox.New(s.readConfigOrEmpty()).Stop()
		},
		StartOrReloadSingBox: func(ctx context.Context) error {
			s.invalidateConfigStore()
			cfg := s.readConfigOrEmpty()
			sbPath := s.sbConfigPath()
			if raw, err := os.ReadFile(sbPath); err == nil && len(raw) > 0 {
				_ = singbox.SyncSandboxWorkConfig(ctx, sbPath, s.sbWorkConfigPath(), string(raw), ".rollback.tmp")
			}
			sb := singbox.New(cfg)
			if daemon.IsSingBoxRunning() {
				_ = sb.Stop()
			}
			return sb.Start()
		},
		DisableFirewall: func(context.Context) error {
			return firewall.Disable()
		},
		ReloadFirewall: func(context.Context) error {
			s.invalidateConfigStore()
			cfg := s.readConfigOrEmpty()
			return firewall.EnableWithOptions(firewall.OptionsFromConfig(cfg, ""), true)
		},
		ReloadDNS: func(ctx context.Context, engine string) error {
			s.invalidateConfigStore()
			cfg := s.readConfigOrEmpty()
			reg := s.newDNSRegistry(cfg)
			eng, ok := reg.Get(engine)
			if !ok || eng == nil {
				eng = reg.ActiveEngine()
			}
			if eng == nil || !eng.IsInstalled() {
				return nil
			}
			if err := eng.SyncCommonConfig(ctx); err != nil {
				return err
			}
			return eng.Restart(ctx)
		},
		ReloadOpenWrtNetwork:  vlan.ReloadOpenWrtNetwork,
		ReloadOpenWrtWireless: wifiopt.ReloadOpenWrtWireless,
		OnRolledBack:          s.onSafeCommitRolledBack,
	}
}

func (s *Server) onSafeCommitRolledBack(rec safecommit.RollbackRecord) {
	s.invalidateConfigStore()
	s.invalidateIOSCache()
	s.invalidateClashCache()
	_ = daemon.NotifyReload()

	cfg := s.readConfigOrEmpty()
	if s.notifier != nil {
		s.notifier.UpdateOptions(notify.OptionsFromConfig(cfg.Notify))
		body := fmt.Sprintf("触发方式: %s | 变更原因: %s | 动作数: %d",
			cmp.Or(rec.Trigger, "manual"),
			cmp.Or(rec.Reason, "未说明"),
			len(rec.Actions))
		if rec.Error != "" {
			body += " | 部分错误: " + rec.Error
		}
		s.notifier.Emit(notify.Event{
			Type:     notify.EventSafeCommitRollback,
			Severity: notify.SeverityCritical,
			DedupKey: cmp.Or(rec.Token, "safecommit"),
			Title:    "Safe Commit 安全回滚已触发",
			Body:     body,
		})
	}
}

func (s *Server) safeCommitStatusPayload(cfg *config.Config) safeCommitStatusResponse {
	return safeCommitStatusResponse{
		StatusReport: s.safeCommitManager().Status(),
		Config:       safeCommitConfigFrom(cfg),
	}
}

func absSnapshotPath(p string) string {
	trimmed := strings.TrimSpace(p)
	if trimmed == "" {
		return ""
	}
	if filepath.IsAbs(trimmed) {
		return filepath.Clean(trimmed)
	}
	if abs, err := filepath.Abs(trimmed); err == nil {
		return abs
	}
	return ""
}

func (s *Server) armSafeCommit(ctx context.Context, ttlSec int, reason string) (*safecommit.State, error) {
	return s.armSafeCommitWithExtraSnapshots(ctx, ttlSec, reason, nil)
}

func (s *Server) armSafeCommitWithExtraSnapshots(ctx context.Context, ttlSec int, reason string, extraSnapshots map[string]string) (*safecommit.State, error) {
	cfg := s.readConfigOrEmpty()
	effectiveTTL := ttlSec
	if effectiveTTL <= 0 {
		effectiveTTL = cfg.SafeCommit.EffectiveTTLSec()
	}
	if effectiveTTL < constant.SafeCommitMinTTLSec || effectiveTTL > constant.SafeCommitMaxTTLSec {
		return nil, fmt.Errorf("%w: got %d", safecommit.ErrInvalidTTL, ttlSec)
	}

	snapshots := make(map[string]string, 4+len(extraSnapshots))
	addSnap := func(name, path string) {
		if abs := absSnapshotPath(path); abs != "" {
			snapshots[name] = abs
		}
	}
	addSnap("singctl.yaml", configPathFor(s))
	addSnap("sing-box.json", s.sbConfigPath())
	addSnap("smartdns.conf", s.smartDNSConfigFilePath())
	addSnap("adguard.yaml", s.adguardConfigFilePath())
	for name, path := range extraSnapshots {
		addSnap(name, path)
	}

	sbRunning, fwActive := false, false
	if s.opts.SafeCommitBaselineForTest != nil {
		sbRunning, fwActive = s.opts.SafeCommitBaselineForTest()
	} else {
		sbRunning = daemon.IsSingBoxRunning()
		qs := firewall.InspectQuickStatus()
		fwActive = qs.KernelActive || qs.Enabled
	}

	dnsEngine := ""
	if active := s.newDNSRegistry(cfg).ActiveEngine(); active != nil {
		dnsEngine = active.ID()
	}

	return s.safeCommitManager().Arm(ctx, safecommit.ArmRequest{
		TTLSec:            effectiveTTL,
		Reason:            strings.TrimSpace(reason),
		SingBoxWasRunning: sbRunning,
		FirewallWasActive: fwActive,
		DNSEngine:         dnsEngine,
		SnapshotFiles:     snapshots,
	})
}

func (s *Server) handleSafeCommitStatusGet(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.safeCommitStatusPayload(s.readConfigOrEmpty()))
}

func (s *Server) handleSafeCommitArmPost(w http.ResponseWriter, r *http.Request) {
	var body struct {
		TTLSec int    `json:"ttlSec"`
		Reason string `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil && !errors.Is(err, io.EOF) {
		writeJSONError(w, http.StatusBadRequest, "请求格式错误: "+err.Error())
		return
	}

	if _, err := s.armSafeCommit(r.Context(), body.TTLSec, body.Reason); err != nil {
		if errors.Is(err, safecommit.ErrInvalidTTL) {
			writeJSONError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSONError(w, http.StatusInternalServerError, "启动安全回滚保险丝失败: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":     true,
		"status": s.safeCommitStatusPayload(s.readConfigOrEmpty()),
	})
}

func (s *Server) handleSafeCommitConfirmPost(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil && !errors.Is(err, io.EOF) {
		writeJSONError(w, http.StatusBadRequest, "请求格式错误: "+err.Error())
		return
	}

	confirmed, err := s.safeCommitManager().Confirm(body.Token)
	if err != nil {
		if errors.Is(err, safecommit.ErrTokenMismatch) {
			writeJSONError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSONError(w, http.StatusInternalServerError, "确认解除保险丝失败: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":        true,
		"confirmed": confirmed,
		"status":    s.safeCommitStatusPayload(s.readConfigOrEmpty()),
	})
}

func (s *Server) handleSafeCommitRollbackPost(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Trigger string `json:"trigger"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil && !errors.Is(err, io.EOF) {
		writeJSONError(w, http.StatusBadRequest, "请求格式错误: "+err.Error())
		return
	}

	rec, err := s.safeCommitManager().Rollback(r.Context(), cmp.Or(strings.TrimSpace(body.Trigger), "manual"))
	if rec == nil && err == nil {
		writeJSONError(w, http.StatusBadRequest, "当前没有激活的安全回滚保险丝")
		return
	}
	if rec == nil && err != nil {
		writeJSONError(w, http.StatusInternalServerError, "执行安全回滚失败: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":     rec.Success,
		"record": rec,
		"status": s.safeCommitStatusPayload(s.readConfigOrEmpty()),
	})
}

func (s *Server) handleSafeCommitOOMProtectPost(w http.ResponseWriter, r *http.Request) {
	var body struct{}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil && !errors.Is(err, io.EOF) {
		writeJSONError(w, http.StatusBadRequest, "请求格式错误: "+err.Error())
		return
	}

	st, err := safecommit.ProtectTailscaledOOM(s.safeCommitProcRoot())
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":           false,
			"tailscaleOom": st,
			"error":        err.Error(),
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":           true,
		"tailscaleOom": st,
	})
}

func (s *Server) handleSafeCommitConfigPut(w http.ResponseWriter, r *http.Request) {
	var body safeCommitConfigDTO
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "请求格式错误: "+err.Error())
		return
	}
	if body.DefaultTTLSec < constant.SafeCommitMinTTLSec || body.DefaultTTLSec > constant.SafeCommitMaxTTLSec {
		writeJSONError(w, http.StatusBadRequest, safecommit.ErrInvalidTTL.Error())
		return
	}

	updatedCfg, err := s.updateConfigTx(configTxOptions{
		SaveErrPrefix: "保存安全回滚配置失败: ",
	}, func(cfg *config.Config) error {
		cfg.SafeCommit.DefaultTTLSec = body.DefaultTTLSec
		cfg.SafeCommit.SetProtectTailscaleOOM(body.ProtectTailscaleOOM)
		return nil
	})
	if err != nil {
		writePartialSaveError(w, err)
		return
	}

	procRoot := s.safeCommitProcRoot()
	var oomStatus safecommit.OOMShieldStatus
	if body.ProtectTailscaleOOM && (runtime.GOOS == "linux" || procRoot != "") {
		oomStatus, _ = safecommit.ProtectTailscaledOOM(procRoot)
	} else {
		oomStatus = safecommit.InspectTailscaledOOM(procRoot)
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":           true,
		"config":       safeCommitConfigFrom(updatedCfg),
		"tailscaleOom": oomStatus,
	})
}

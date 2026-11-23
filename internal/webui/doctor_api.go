// 文件职责：提供客户端 WebUI 一键深度体检（8 项全链路检测）与白名单安全快捷修复接口。
package webui

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"singctl/internal/config"
	"singctl/internal/constant"
	"singctl/internal/doctor"
	"singctl/internal/safecommit"
	"singctl/internal/singbox"
)

var allowedDoctorFixActions = map[string]bool{
	"protect-tailscale-oom": true,
	"sync-dns-local":        true,
	"sync-smartdns-ipv6":    true,
	"disable-flow-offload":  true,
}

func (s *Server) doctorRunner() *doctor.Runner {
	if s.opts.DoctorRunner != nil {
		return s.opts.DoctorRunner
	}
	return doctor.NewDefaultRunner()
}

func (s *Server) buildDoctorQuickFixHandlers(cfg *config.Config, procRoot string) map[string]func(ctx context.Context) (string, error) {
	return map[string]func(ctx context.Context) (string, error){
		"protect-tailscale-oom": func(context.Context) (string, error) {
			st, err := safecommit.ProtectTailscaledOOM(procRoot)
			if err != nil {
				return "", err
			}
			return cmp.Or(st.Message, "已为 tailscaled 开启 OOM 免疫保护"), nil
		},
		"sync-dns-local": func(ctx context.Context) (string, error) {
			return s.quickFixSyncDNSLocal(ctx, cfg)
		},
		"sync-smartdns-ipv6": func(ctx context.Context) (string, error) {
			return s.quickFixSyncSmartDNSIPv6(ctx, cfg)
		},
	}
}

func (s *Server) quickFixSyncDNSLocal(ctx context.Context, cfg *config.Config) (string, error) {
	dnsPort := 5353
	dnsEnabled := true
	if cfg != nil {
		dnsPort = cfg.DNS.GetDNSPort()
		dnsEnabled = cfg.DNS.IsEnabled()
	}

	localAddr := net.JoinHostPort("127.0.0.1", strconv.Itoa(dnsPort))
	useExternal := false
	if dnsEnabled {
		if s.opts.LocalDNSProbeDNSForTest != nil {
			useExternal = s.opts.LocalDNSProbeDNSForTest(localAddr, 800*time.Millisecond) == nil
		} else {
			useExternal = doctor.ProbeLocalDNS(ctx, localAddr) == nil
		}
	}

	sbPath := s.sbConfigPath()
	workPath := s.sbWorkConfigPath()
	syncFn := s.opts.LocalDNSSyncSingBoxDNSLocalForTest
	if syncFn == nil {
		syncFn = singbox.SyncLiveSingBoxDNSLocal
	}
	changed, err := syncFn(ctx, sbPath, workPath, useExternal, dnsPort)
	if err != nil {
		return "", err
	}
	if useExternal {
		if changed {
			return fmt.Sprintf("已将 sing-box dns_local 同步至本地防劫持 DNS (127.0.0.1:%d) 并强制关闭内置缓存", dnsPort), nil
		}
		return fmt.Sprintf("sing-box dns_local 已指向本地防劫持 DNS (127.0.0.1:%d)，配置合规无需变更", dnsPort), nil
	}
	if changed {
		return "本地防劫持 DNS 未监听，已将 sing-box dns_local 切换为加密 DoH 兜底并关闭内置缓存", nil
	}
	return "sing-box dns_local 已处于加密 DoH 兜底合规状态", nil
}

func (s *Server) quickFixSyncSmartDNSIPv6(ctx context.Context, cfg *config.Config) (string, error) {
	reg := s.newDNSRegistry(cfg)
	sdEng, ok := reg.Get(constant.DNSEngineSmartDNS)
	if !ok || sdEng == nil || !sdEng.IsInstalled() {
		return "", errors.New("未检测到已安装的 SmartDNS 引擎")
	}
	if err := sdEng.SyncCommonConfig(ctx); err != nil {
		return "", err
	}
	mode := config.GatewayIPv6Off
	if cfg != nil {
		mode = cfg.Gateway.EffectiveIPv6Mode()
	}
	return fmt.Sprintf("已按 gateway.ipv6_mode=%s 同步 SmartDNS force-AAAA-SOA 策略", mode), nil
}

func (s *Server) buildDoctorEnv(cfg *config.Config) *doctor.Env {
	var env *doctor.Env
	if s.opts.DoctorEnvForTest != nil {
		env = s.opts.DoctorEnvForTest(cfg)
	}
	if env == nil {
		env = &doctor.Env{
			Config:            cfg,
			ConfigPath:        configPathFor(s),
			SingBoxConfigPath: s.sbConfigPath(),
			SmartDNSConfPath:  s.smartDNSConfigFilePath(),
			AdGuardConfPath:   s.adguardConfigFilePath(),
			ProcRoot:          s.safeCommitProcRoot(),
		}
	}
	if env.Config == nil {
		env.Config = cfg
	}
	procRoot := cmp.Or(strings.TrimSpace(env.ProcRoot), s.safeCommitProcRoot())
	defaults := s.buildDoctorQuickFixHandlers(cfg, procRoot)
	if env.QuickFixHandlers == nil {
		env.QuickFixHandlers = defaults
	} else {
		for k, fn := range defaults {
			if _, exists := env.QuickFixHandlers[k]; !exists {
				env.QuickFixHandlers[k] = fn
			}
		}
	}
	return env
}

func (s *Server) handleDoctorRun(w http.ResponseWriter, r *http.Request) {
	cfg := s.readConfigOrEmpty()
	report := s.doctorRunner().Run(r.Context(), s.buildDoctorEnv(cfg))
	writeJSON(w, http.StatusOK, report)
}

func (s *Server) handleDoctorFixPost(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Action string `json:"action"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "请求格式错误: "+err.Error())
		return
	}
	action := strings.TrimSpace(body.Action)
	if !allowedDoctorFixActions[action] {
		writeJSONError(w, http.StatusBadRequest, fmt.Sprintf("不支持或非法的快捷修复动作: %q", action))
		return
	}

	cfg := s.readConfigOrEmpty()
	msg, err := s.doctorRunner().Fix(r.Context(), s.buildDoctorEnv(cfg), action)
	if err != nil {
		if errors.Is(err, safecommit.ErrTailscaledNotFound) {
			writeJSONError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSONError(w, http.StatusInternalServerError, "快捷修复执行失败: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":      true,
		"action":  action,
		"message": msg,
	})
}

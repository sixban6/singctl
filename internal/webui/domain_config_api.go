package webui

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"strings"

	"singctl/internal/config"
	"singctl/internal/daemon"
)

type apiStatusError struct {
	status int
	msg    string
}

func (e *apiStatusError) Error() string { return e.msg }

func (s *Server) savePartialConfig(syncAdGuard bool, mutate func(cfg *config.Config) error) error {
	s.cfgMu.Lock()
	defer s.cfgMu.Unlock()

	cfgPath := configPathFor(s)
	cfg, err := config.Load(cfgPath)
	if err != nil || cfg == nil {
		cfg = &config.Config{}
	}
	if err := mutate(cfg); err != nil {
		return err
	}
	if err := backupConfig(cfgPath); err != nil {
		return &apiStatusError{status: http.StatusInternalServerError, msg: "备份配置失败: " + err.Error()}
	}
	if err := config.Save(cfgPath, cfg); err != nil {
		return &apiStatusError{status: http.StatusInternalServerError, msg: "保存配置失败: " + err.Error()}
	}
	if syncAdGuard {
		s.invalidateIOSCache()
		s.syncAdGuardSubWhitelistAsync(cfg)
	}
	_ = daemon.NotifyReload()
	return nil
}

func writePartialSaveError(w http.ResponseWriter, err error) {
	var apiErr *apiStatusError
	if errors.As(err, &apiErr) {
		writeJSONError(w, apiErr.status, apiErr.msg)
		return
	}
	writeJSONError(w, http.StatusBadRequest, err.Error())
}

// maskTailscaleAuthKey 生成安全遮蔽的 Tailscale Auth Key 提示，避免前端 GET 接口回传完整明文凭据。
func maskTailscaleAuthKey(key string) string {
	k := strings.TrimSpace(key)
	if k == "" {
		return ""
	}
	if len(k) < 16 {
		return "********"
	}
	prefixLen := min(11, len(k)-4)
	return k[:prefixLen] + "****" + k[len(k)-4:]
}

func normalizeAndValidateSubnets(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", nil
	}
	var normalized []string
	for part := range strings.SplitSeq(raw, ",") {
		p := strings.TrimSpace(part)
		if p == "" {
			continue
		}
		prefix, err := netip.ParsePrefix(p)
		if err != nil {
			return "", fmt.Errorf("通告子网格式无效 %q（示例: 192.168.1.0/24）: %w", p, err)
		}
		normalized = append(normalized, prefix.String())
	}
	return strings.Join(normalized, ","), nil
}

func tailscaleConfigResponse(cfg *config.Config) map[string]any {
	key := strings.TrimSpace(cfg.Tailscale.AuthKey)
	return map[string]any{
		"authKeySet":  key != "",
		"authKeyHint": maskTailscaleAuthKey(key),
		"subnets":     strings.TrimSpace(cfg.Tailscale.Subnets),
		"useBuild":    cfg.Tailscale.UseBuild,
	}
}

func (s *Server) handleTailscaleConfigGet(w http.ResponseWriter, r *http.Request) {
	cfg, err := config.Load(configPathFor(s))
	if err != nil || cfg == nil {
		writeJSONError(w, http.StatusInternalServerError, "加载配置失败")
		return
	}
	writeJSON(w, http.StatusOK, tailscaleConfigResponse(cfg))
}

func (s *Server) handleTailscaleConfigPut(w http.ResponseWriter, r *http.Request) {
	var body struct {
		AuthKey      string `json:"authKey"`
		ClearAuthKey bool   `json:"clearAuthKey"`
		Subnets      string `json:"subnets"`
		UseBuild     *bool  `json:"useBuild"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "请求格式错误: "+err.Error())
		return
	}

	subnets, err := normalizeAndValidateSubnets(body.Subnets)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}

	var resp map[string]any
	err = s.savePartialConfig(false, func(cfg *config.Config) error {
		if body.ClearAuthKey {
			cfg.Tailscale.AuthKey = ""
		} else if trimmed := strings.TrimSpace(body.AuthKey); trimmed != "" {
			cfg.Tailscale.AuthKey = trimmed
		}
		cfg.Tailscale.Subnets = subnets
		if body.UseBuild != nil {
			cfg.Tailscale.UseBuild = *body.UseBuild
		}
		resp = tailscaleConfigResponse(cfg)
		resp["ok"] = true
		return nil
	})
	if err != nil {
		writePartialSaveError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleSbSubsPut(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Subs []SubDTO `json:"subs"`
		Hy2  struct {
			Up   int `json:"up"`
			Down int `json:"down"`
		} `json:"hy2"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "请求格式错误: "+err.Error())
		return
	}

	err := s.savePartialConfig(true, func(cfg *config.Config) error {
		applySubsToConfig(body.Subs, cfg)
		cfg.Hy2.Up = max(0, body.Hy2.Up)
		cfg.Hy2.Down = max(0, body.Hy2.Down)
		if len(cfg.Subs) > 0 {
			if valErr := cfg.ValidateSubs(); valErr != nil {
				return &apiStatusError{status: http.StatusBadRequest, msg: valErr.Error()}
			}
		}
		return nil
	})
	if err != nil {
		writePartialSaveError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func validateMirrorURL(raw string) (string, error) {
	u := strings.TrimSpace(raw)
	if u == "" {
		return "", nil
	}
	if strings.ContainsAny(u, " \t\r\n") {
		return "", fmt.Errorf("镜像地址不能包含空格或换行符")
	}
	parsed, err := url.Parse(u)
	if err != nil || parsed.Host == "" {
		return "", fmt.Errorf("GitHub 镜像地址格式无效（需为完整 http/https 地址）")
	}
	scheme := strings.ToLower(parsed.Scheme)
	if scheme != "http" && scheme != "https" {
		return "", fmt.Errorf("GitHub 镜像地址仅支持 http 或 https 协议")
	}
	return u, nil
}

func (s *Server) handleSystemMirrorPut(w http.ResponseWriter, r *http.Request) {
	var body struct {
		MirrorURL string `json:"mirrorUrl"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "请求格式错误: "+err.Error())
		return
	}

	mirror, err := validateMirrorURL(body.MirrorURL)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}

	err = s.savePartialConfig(false, func(cfg *config.Config) error {
		cfg.GitHub.MirrorURL = mirror
		return nil
	})
	if err != nil {
		writePartialSaveError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":        true,
		"mirrorUrl": mirror,
	})
}

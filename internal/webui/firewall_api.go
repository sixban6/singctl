package webui

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"singctl/internal/config"
	"singctl/internal/firewall"
)

func extractCallerIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr))
	if err != nil || host == "" {
		host = strings.TrimSpace(r.RemoteAddr)
	}
	if addr, parseErr := netip.ParseAddr(host); parseErr == nil {
		return addr.Unmap().String()
	}
	return host
}

func parseOverviewQuery(r *http.Request) firewall.OverviewQuery {
	q := r.URL.Query()
	page, _ := strconv.Atoi(strings.TrimSpace(q.Get("page")))
	pageSize, _ := strconv.Atoi(strings.TrimSpace(q.Get("pageSize")))
	return firewall.OverviewQuery{
		Scope:    strings.TrimSpace(q.Get("scope")),
		Search:   strings.TrimSpace(q.Get("search")),
		SortBy:   strings.TrimSpace(q.Get("sort")),
		Page:     page,
		PageSize: pageSize,
	}
}

func (s *Server) loadConfigOrEmpty() *config.Config {
	cfg, _ := config.Load(s.opts.ConfigPath)
	if cfg == nil {
		return &config.Config{}
	}
	return cfg
}

// handleFirewallOverviewGet 返回防火墙内核态、4格拦截战果、预检清单与分页规则列表。
func (s *Server) handleFirewallOverviewGet(w http.ResponseWriter, r *http.Request) {
	cfg := s.loadConfigOrEmpty()
	ov := firewall.BuildOverview(r.Context(), cfg, extractCallerIP(r), parseOverviewQuery(r))
	writeJSON(w, http.StatusOK, ov)
}

// handleFirewallLogsGet 返回近期内核 [NFT] 拦截记录（自动脱敏，不含本机公网 IP）。
func (s *Server) handleFirewallLogsGet(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(strings.TrimSpace(r.URL.Query().Get("limit")))
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	events := firewall.ReadRecentNFTLogs(limit)
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":     true,
		"events": events,
	})
}

type firewallApplyRequest struct {
	Mode            string `json:"mode"`
	BanTimeoutDays  int    `json:"banTimeoutDays"`
	PingLimitPerSec int    `json:"pingLimitPerSec"`
	ProtectedPorts  []int  `json:"protectedPorts"`
	ResetDefaults   bool   `json:"resetDefaults"`
}

// handleFirewallApplyPost 保存防火墙定制参数，保留已有白名单/动态黑名单并热重载内核表与开机自启。
func (s *Server) handleFirewallApplyPost(w http.ResponseWriter, r *http.Request) {
	var req firewallApplyRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 64*1024)).Decode(&req); err != nil && err != io.EOF {
		writeJSONError(w, http.StatusBadRequest, "无效的 JSON 请求体")
		return
	}

	callerIP := extractCallerIP(r)

	s.cfgMu.Lock()
	defer s.cfgMu.Unlock()

	cfg := s.loadConfigOrEmpty()
	if req.ResetDefaults {
		cfg.Firewall = config.FirewallConfig{}
	} else {
		if strings.TrimSpace(req.Mode) != "" {
			if strings.EqualFold(strings.TrimSpace(req.Mode), "minimal") {
				cfg.Firewall.Mode = "minimal"
			} else {
				cfg.Firewall.Mode = "standard"
			}
		}
		if req.BanTimeoutDays > 0 {
			cfg.Firewall.BanTimeoutDays = min(30, max(1, req.BanTimeoutDays))
		}
		if req.PingLimitPerSec > 0 {
			cfg.Firewall.PingLimitPerSec = min(100, max(1, req.PingLimitPerSec))
		}
		if req.ProtectedPorts != nil {
			var cleanPorts []int
			for _, p := range req.ProtectedPorts {
				if p > 0 && p <= 65535 && !slices.Contains(cleanPorts, p) {
					cleanPorts = append(cleanPorts, p)
				}
			}
			cfg.Firewall.ProtectedPorts = cleanPorts
		}
	}

	if strings.TrimSpace(s.opts.ConfigPath) != "" {
		if saveErr := config.Save(s.opts.ConfigPath, cfg); saveErr != nil {
			writeJSONError(w, http.StatusInternalServerError, "保存防火墙配置失败: "+saveErr.Error())
			return
		}
	}

	opts := firewall.OptionsFromConfig(cfg, callerIP)
	if err := firewall.EnableWithOptions(opts, true); err != nil {
		writeJSONError(w, http.StatusBadRequest, "应用防火墙规则失败: "+err.Error())
		return
	}

	ov := firewall.BuildOverview(r.Context(), cfg, callerIP, firewall.OverviewQuery{Page: 1, PageSize: 25})
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":       true,
		"message":  "防火墙加固规则已生效并保留现有白名单与动态黑名单",
		"overview": ov,
	})
}

// handleFirewallDisablePost 停用并彻底移除 `inet security` 表及自启服务。
func (s *Server) handleFirewallDisablePost(w http.ResponseWriter, r *http.Request) {
	if err := firewall.Disable(); err != nil {
		writeJSONError(w, http.StatusBadRequest, "移除防火墙规则失败: "+err.Error())
		return
	}
	cfg := s.loadConfigOrEmpty()
	ov := firewall.BuildOverview(r.Context(), cfg, extractCallerIP(r), firewall.OverviewQuery{Page: 1, PageSize: 25})
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":       true,
		"message":  "已关闭防火墙加固并清理内核规则与自启脚本",
		"overview": ov,
	})
}

type firewallBanRequest struct {
	Target      string `json:"target"`
	Scope       string `json:"scope"` // "dynamic" | "forever"
	TimeoutDays int    `json:"timeoutDays"`
}

// handleFirewallBanPost 手动封禁公网 IP 或威胁网段（带防自锁校验，实时写入内核集合且永久段同步落盘）。
func (s *Server) handleFirewallBanPost(w http.ResponseWriter, r *http.Request) {
	var req firewallBanRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 64*1024)).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "无效的 JSON 请求体")
		return
	}
	scope := strings.ToLower(strings.TrimSpace(req.Scope))
	if scope == "" {
		scope = "dynamic"
	}
	if scope != "dynamic" && scope != "forever" {
		writeJSONError(w, http.StatusBadRequest, "不支持的 scope 参数 (支持 dynamic / forever)")
		return
	}

	callerIP := extractCallerIP(r)

	s.cfgMu.Lock()
	defer s.cfgMu.Unlock()

	cfg := s.loadConfigOrEmpty()
	norm, _, err := firewall.AddBanLive(req.Target, scope, req.TimeoutDays, callerIP, cfg)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}

	if scope == "forever" && !slices.Contains(cfg.Firewall.ExtraForeverBan, norm) {
		cfg.Firewall.ExtraForeverBan = append(cfg.Firewall.ExtraForeverBan, norm)
		if strings.TrimSpace(s.opts.ConfigPath) != "" {
			if saveErr := config.Save(s.opts.ConfigPath, cfg); saveErr != nil {
				writeJSONError(w, http.StatusInternalServerError, "持久化永久封禁列表失败: "+saveErr.Error())
				return
			}
		}
	}

	ov := firewall.BuildOverview(r.Context(), cfg, callerIP, firewall.OverviewQuery{Page: 1, PageSize: 25})
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":       true,
		"target":   norm,
		"scope":    scope,
		"message":  "已立即封禁 " + norm,
		"overview": ov,
	})
}

type firewallUnbanRequest struct {
	Target string `json:"target"`
	Scope  string `json:"scope"`
}

// handleFirewallUnbanPost 从内核黑名单实时解封单条 IP/网段，并同步清理配置中的自定义永久条目。
func (s *Server) handleFirewallUnbanPost(w http.ResponseWriter, r *http.Request) {
	var req firewallUnbanRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 64*1024)).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "无效的 JSON 请求体")
		return
	}
	if err := firewall.RemoveBanLive(req.Target, req.Scope); err != nil {
		writeJSONError(w, http.StatusBadRequest, "解封失败: "+err.Error())
		return
	}

	callerIP := extractCallerIP(r)

	s.cfgMu.Lock()
	defer s.cfgMu.Unlock()

	cfg := s.loadConfigOrEmpty()
	trimmed := strings.TrimSpace(req.Target)
	beforeLen := len(cfg.Firewall.ExtraForeverBan)
	cfg.Firewall.ExtraForeverBan = slices.DeleteFunc(cfg.Firewall.ExtraForeverBan, func(item string) bool {
		return strings.EqualFold(strings.TrimSpace(item), trimmed)
	})
	if len(cfg.Firewall.ExtraForeverBan) != beforeLen && strings.TrimSpace(s.opts.ConfigPath) != "" {
		if saveErr := config.Save(s.opts.ConfigPath, cfg); saveErr != nil {
			writeJSONError(w, http.StatusInternalServerError, "更新配置失败: "+saveErr.Error())
			return
		}
	}

	ov := firewall.BuildOverview(r.Context(), cfg, callerIP, firewall.OverviewQuery{Page: 1, PageSize: 25})
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":       true,
		"message":  "已解封 " + trimmed,
		"overview": ov,
	})
}

type firewallClearDynamicRequest struct {
	Family string `json:"family"` // "" / "all" / "ipv4" / "ipv6"
}

// handleFirewallClearDynamicPost 清空 7 天动态黑名单（保留永久段与历史计数）。
func (s *Server) handleFirewallClearDynamicPost(w http.ResponseWriter, r *http.Request) {
	var req firewallClearDynamicRequest
	_ = json.NewDecoder(io.LimitReader(r.Body, 16*1024)).Decode(&req)
	if err := firewall.ClearDynamicBansLive(req.Family); err != nil {
		writeJSONError(w, http.StatusBadRequest, "清空动态黑名单失败: "+err.Error())
		return
	}
	cfg := s.loadConfigOrEmpty()
	ov := firewall.BuildOverview(r.Context(), cfg, extractCallerIP(r), firewall.OverviewQuery{Page: 1, PageSize: 25})
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":       true,
		"message":  "已清空动态黑名单",
		"overview": ov,
	})
}

type firewallWhitelistRequest struct {
	Action string `json:"action"` // "add" | "remove"
	Target string `json:"target"`
}

// handleFirewallWhitelistPost 维护防火墙自定义信任白名单（持久化 0600 并实时同步内核白名单集合）。
func (s *Server) handleFirewallWhitelistPost(w http.ResponseWriter, r *http.Request) {
	var req firewallWhitelistRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 64*1024)).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "无效的 JSON 请求体")
		return
	}
	norm, isV6, err := firewall.ValidateWhitelistTarget(req.Target)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}

	action := strings.ToLower(strings.TrimSpace(req.Action))
	if action == "" {
		action = "add"
	}
	if action != "add" && action != "remove" {
		writeJSONError(w, http.StatusBadRequest, "不支持的 action 参数 (支持 add / remove)")
		return
	}
	if action == "remove" && firewall.IsBuiltinWhitelist(norm) {
		writeJSONError(w, http.StatusBadRequest, "安全拦截: 系统内置私网/Tailscale 防锁死白名单不可删除")
		return
	}

	callerIP := extractCallerIP(r)

	s.cfgMu.Lock()
	defer s.cfgMu.Unlock()

	cfg := s.loadConfigOrEmpty()
	if action == "add" {
		if !slices.Contains(cfg.Firewall.Whitelist, norm) && !firewall.IsBuiltinWhitelist(norm) {
			cfg.Firewall.Whitelist = append(cfg.Firewall.Whitelist, norm)
		}
	} else {
		cfg.Firewall.Whitelist = slices.DeleteFunc(cfg.Firewall.Whitelist, func(item string) bool {
			n, _, vErr := firewall.ValidateWhitelistTarget(item)
			return (vErr == nil && n == norm) || strings.EqualFold(strings.TrimSpace(item), norm)
		})
	}

	if strings.TrimSpace(s.opts.ConfigPath) != "" {
		if saveErr := config.Save(s.opts.ConfigPath, cfg); saveErr != nil {
			writeJSONError(w, http.StatusInternalServerError, "保存白名单失败: "+saveErr.Error())
			return
		}
	}

	needReload, syncErr := firewall.SyncWhitelistElementLive(norm, isV6, action == "add")
	if syncErr != nil {
		writeJSONError(w, http.StatusBadRequest, "同步内核白名单集合失败: "+syncErr.Error())
		return
	}
	if needReload {
		_ = firewall.EnableWithOptions(firewall.OptionsFromConfig(cfg, callerIP), true)
	}

	ov := firewall.BuildOverview(r.Context(), cfg, callerIP, firewall.OverviewQuery{Page: 1, PageSize: 25})
	msg := "已将 " + norm + " 加入防火墙信任白名单"
	if action == "remove" {
		msg = "已将 " + norm + " 移出防火墙信任白名单"
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":        true,
		"target":    norm,
		"whitelist": cfg.Firewall.Whitelist,
		"message":   msg,
		"overview":  ov,
	})
}

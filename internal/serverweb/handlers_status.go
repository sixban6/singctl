package serverweb

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"singctl/internal/config"
	"singctl/internal/deploy"
	"singctl/internal/subhub"
)

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	cfg, err := config.Load(s.opts.ConfigPath)
	if err != nil || cfg == nil {
		cfg = &config.Config{}
	}

	subDomain := cfg.Server.GetSubstoreDomain()
	if subDomain == "" {
		subDomain = cfg.Server.GetNodeDomain()
	}
	adminPath := cfg.Server.GetWebAdminPath()
	httpsURL := ""
	if subDomain != "" && adminPath != "" {
		httpsURL = fmt.Sprintf("https://%s%s/", subDomain, adminPath)
	}

	caddyRunning := checkServiceRunning("caddy")
	singboxRunning := checkServiceRunning("sing-box")
	substoreRunning := checkServiceRunning("singctl-sub") || subhub.IsRunning()
	warpRunning := checkServiceRunning("wireproxy") || checkServiceRunning("warp-svc")

	caddyVer := deploy.GetInstalledCaddyVersion()
	singboxVer := deploy.GetInstalledSingBoxVersion()
	substoreVer := deploy.GetInstalledSubstoreVersion()
	warpVer := deploy.GetInstalledWarpVersion()

	substoreAdminURL := ""
	sbt := deploy.NewSubstore(cfg, "")
	if adminURL, err := sbt.GetAdminURL(); err == nil && adminURL != "" {
		substoreAdminURL = adminURL
	} else if vercelURL, err := sbt.GetVercelAdminURL(); err == nil && vercelURL != "" {
		substoreAdminURL = vercelURL
	}

	status := map[string]any{
		"version":     s.opts.Version,
		"authEnabled": s.getPassword() != "",
		"system":      getSystemMetrics(),
		"admin": map[string]any{
			"username": s.getUsername(),
			"path":     adminPath,
			"httpsUrl": httpsURL,
			"port":     cfg.Server.GetWebAdminPort(),
		},
		"services": map[string]any{
			"caddy": map[string]any{
				"running": caddyRunning,
				"version": caddyVer,
				"pid":     getServicePID("caddy"),
				"uptime":  getServiceUptime("caddy"),
			},
			"singbox": map[string]any{
				"running": singboxRunning,
				"version": singboxVer,
				"pid":     getServicePID("sing-box"),
				"uptime":  getServiceUptime("sing-box"),
			},
			"substore": map[string]any{
				"running": substoreRunning,
				"version": substoreVer,
				"pid":     getServicePID("singctl-sub"),
				"uptime":  getServiceUptime("singctl-sub"),
				"engine":  "native-go",
			},
			"warp": map[string]any{
				"running":   warpRunning,
				"version":   warpVer,
				"pid":       getServicePID("wireproxy"),
				"socksPort": 40000,
			},
		},
		"config": map[string]any{
			"nodeDomain":       cfg.Server.GetNodeDomain(),
			"substoreDomain":   cfg.Server.GetSubstoreDomain(),
			"substoreAdminUrl": substoreAdminURL,
			"nodeTag":          cfg.Server.NodeTag,
			"sni":              cfg.Server.Sni,
			"hasCFToken":       cfg.Server.CFDNSKey != "",
		},
	}
	if s.audit != nil {
		rawLogs := s.audit.List()
		enriched := make([]map[string]any, 0, len(rawLogs))
		for _, entry := range rawLogs {
			item := map[string]any{
				"time":   entry.Time,
				"action": entry.Action,
				"ip":     entry.IP,
			}
			if s.geo != nil {
				geo := s.geo.Resolve(entry.IP)
				item["geo"] = geo.Geo
				item["isp"] = geo.ISP
				item["country"] = geo.Country
				item["countryCode"] = geo.CountryCode
				item["flag"] = geo.Flag
			}
			enriched = append(enriched, item)
		}
		status["auditLogs"] = enriched
	}
	if s.pendingAck() && !config.IsHashedPassword(s.getPassword()) {
		status["initialCredentials"] = map[string]any{
			"pending":  true,
			"username": s.getUsername(),
			"password": s.getPassword(),
		}
	}
	writeJSON(w, http.StatusOK, status)
}

func (s *Server) handleNodes(w http.ResponseWriter, r *http.Request) {
	cfg, err := config.Load(s.opts.ConfigPath)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "加载配置失败: "+err.Error())
		return
	}

	sbs, err := deploy.NewSingBoxServer(cfg)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "初始化服务端实例失败: "+err.Error())
		return
	}
	_ = sbs.LoadExistingCredentials()

	sbt := deploy.NewSubstore(cfg, "")
	adminURL, _ := sbt.GetAdminURL()
	vercelURL, _ := sbt.GetVercelAdminURL()

	nodePort := sbs.AnyTLSPort()
	res := map[string]any{
		"hy2": map[string]any{
			"link":     sbs.ShareLinkHy2,
			"port":     nodePort,
			"protocol": "hysteria2",
			"domain":   cfg.Server.GetNodeDomain(),
		},
		"vless": map[string]any{
			"link":     sbs.ShareLinkVless,
			"port":     nodePort,
			"protocol": "vless",
			"sni":      cfg.Server.Sni,
		},
		"substore": map[string]any{
			"adminUrl":  adminURL,
			"vercelUrl": vercelURL,
		},
	}
	writeJSON(w, http.StatusOK, res)
}

func getSystemMetrics() map[string]any {
	m := map[string]any{
		"bbr":    isBBREnabled(),
		"uptime": getSystemUptime(),
	}

	if data, err := os.ReadFile("/proc/meminfo"); err == nil {
		var total, available uint64
		for _, line := range strings.Split(string(data), "\n") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				switch fields[0] {
				case "MemTotal:":
					total, _ = strconv.ParseUint(fields[1], 10, 64)
				case "MemAvailable:":
					available, _ = strconv.ParseUint(fields[1], 10, 64)
				}
			}
		}
		if total > 0 {
			used := total - available
			m["memTotalMB"] = total / 1024
			m["memUsedMB"] = used / 1024
			m["memUsagePercent"] = fmt.Sprintf("%.1f%%", float64(used)/float64(total)*100)
		}
	}

	if data, err := os.ReadFile("/proc/loadavg"); err == nil {
		fields := strings.Fields(string(data))
		if len(fields) >= 3 {
			m["loadAvg"] = fmt.Sprintf("%s, %s, %s", fields[0], fields[1], fields[2])
			m["load1"] = fields[0]
			m["load5"] = fields[1]
			m["load15"] = fields[2]
		}
	}

	out, err := exec.Command("df", "-h", "/").Output()
	if err == nil {
		lines := strings.Split(strings.TrimSpace(string(out)), "\n")
		if len(lines) >= 2 {
			fields := strings.Fields(lines[1])
			if len(fields) >= 5 {
				m["diskUsed"] = fields[2]
				m["diskTotal"] = fields[1]
				m["diskPercent"] = fields[4]
			}
		}
	}

	return m
}

func getSystemUptime() string {
	data, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return ""
	}
	fields := strings.Fields(string(data))
	if len(fields) > 0 {
		secs, _ := strconv.ParseFloat(fields[0], 64)
		dur := (time.Duration(secs) * time.Second).Round(time.Minute)
		return dur.String()
	}
	return ""
}

func getServicePID(name string) string {
	out, err := exec.Command("systemctl", "show", "--property", "MainPID", "--value", name).Output()
	if err != nil {
		return ""
	}
	pid := strings.TrimSpace(string(out))
	if pid == "0" {
		return ""
	}
	return pid
}

func getServiceUptime(name string) string {
	out, err := exec.Command("systemctl", "show", "--property", "ActiveEnterTimestamp", "--value", name).Output()
	if err != nil {
		return ""
	}
	val := strings.TrimSpace(string(out))
	if val == "" {
		return ""
	}
	t, err := time.Parse("Mon 2006-01-02 15:04:05 MST", val)
	if err != nil {
		return val
	}
	return time.Since(t).Round(time.Second).String()
}

func checkServiceRunning(name string) bool {
	cmd := exec.Command("systemctl", "is-active", name)
	out, _ := cmd.Output()
	return strings.TrimSpace(string(out)) == "active"
}

func isBBREnabled() bool {
	data, err := os.ReadFile("/proc/sys/net/ipv4/tcp_congestion_control")
	if err != nil {
		return false
	}
	return strings.Contains(strings.TrimSpace(string(data)), "bbr")
}

func diagnoseWARP() map[string]any {
	client := &http.Client{
		Timeout: 4 * time.Second,
		Transport: &http.Transport{
			Proxy: func(req *http.Request) (*url.URL, error) {
				return url.Parse("socks5://127.0.0.1:40000")
			},
		},
	}
	start := time.Now()
	resp, err := client.Get("https://cloudflare.com/cdn-cgi/trace")
	latency := time.Since(start).Milliseconds()
	if err != nil {
		return map[string]any{
			"connected": false,
			"error":     err.Error(),
		}
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	trace := string(body)

	res := map[string]any{
		"connected": true,
		"latencyMs": latency,
		"warp":      "off",
	}
	for _, line := range strings.Split(trace, "\n") {
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			k, v := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
			switch k {
			case "ip":
				res["ip"] = v
			case "loc":
				res["loc"] = v
			case "warp":
				res["warp"] = v
			}
		}
	}
	return res
}

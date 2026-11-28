// 文件职责：承载服务端总览状态聚合、systemd 批量探针解析，并统一通过 common/swrcache 托管五路有界单飞缓存。
package serverweb

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"maps"
	"net"
	"net/http"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"singctl/internal/common/socktune"
	"singctl/internal/common/swrcache"
	"singctl/internal/common/sysinfo"
	"singctl/internal/component"
	"singctl/internal/config"
	"singctl/internal/deploy"
	"singctl/internal/platform/servicemgr"
	"singctl/internal/subhub"
	"singctl/internal/telemetry"
)

const (
	statusCmdTimeout        = 1200 * time.Millisecond
	statusSelectMaxWait     = 600 * time.Millisecond
	configSelectMaxWait     = 150 * time.Millisecond
	configCacheTTL          = 5 * time.Second
	serviceProbeCacheTTL    = 5 * time.Second
	serviceVersionCacheTTL  = 5 * time.Minute
	certProbeCacheTTL       = 3 * time.Minute
	rootDiskMetricsCacheTTL = 15 * time.Second
)

// ServiceProbeSnapshot 描述单个受管服务的运行状态、PID 与可读运行时长。
type ServiceProbeSnapshot struct {
	Running bool
	PID     string
	Uptime  string
}

type cachedConfigBundle struct {
	cfg         *config.Config
	subAdminURL string
}

type diskUsageSnapshot struct {
	used    string
	total   string
	percent string
	ok      bool
}

type statusCaches struct {
	config        *swrcache.Bounded[cachedConfigBundle]
	serviceProbes *swrcache.Bounded[map[string]ServiceProbeSnapshot]
	versions      *swrcache.Bounded[map[string]string]
	certs         *swrcache.Bounded[[]CertHealth]
	disk          *swrcache.Bounded[diskUsageSnapshot]
	heal          *healCacheState
	sse           *sseFrameCache
	subWarmup     atomic.Bool
}

func newStatusCaches(s *Server) *statusCaches {
	c := &statusCaches{
		heal: &healCacheState{},
		sse:  &sseFrameCache{},
	}
	c.config = swrcache.NewBounded(configCacheTTL, configSelectMaxWait, func(context.Context) (cachedConfigBundle, error) {
		if strings.TrimSpace(s.opts.ConfigPath) == "" {
			if s.cfgStore != nil && s.cfgStore.Revision() > 0 {
				cfg := s.cfgStore.Get()
				return cachedConfigBundle{cfg: cfg, subAdminURL: s.resolveSubstoreAdminURLFast(cfg)}, nil
			}
			return cachedConfigBundle{cfg: &config.Config{}}, nil
		}
		loaded, err := s.loadConfigSnapshot()
		if err != nil || loaded == nil {
			if err == nil {
				err = errors.New("empty config")
			}
			return cachedConfigBundle{}, err
		}
		if s.cfgStore != nil && s.cfgStore.Get() != loaded {
			s.cfgStore.Set(loaded)
		}
		return cachedConfigBundle{
			cfg:         loaded,
			subAdminURL: s.resolveSubstoreAdminURLFast(loaded),
		}, nil
	})
	c.serviceProbes = swrcache.NewBounded(serviceProbeCacheTTL, statusSelectMaxWait, func(context.Context) (map[string]ServiceProbeSnapshot, error) {
		var probes map[string]ServiceProbeSnapshot
		if prober := s.snapshotDeps().StatusProber; prober != nil {
			probes = prober()
		} else {
			probes = s.probeSystemdServicesBatch("caddy", "sing-box", "singctl-sub", "wireproxy")
		}
		if len(probes) == 0 {
			return nil, errors.New("empty service probes")
		}
		return maps.Clone(probes), nil
	})
	c.versions = swrcache.NewBounded(serviceVersionCacheTTL, statusSelectMaxWait, func(context.Context) (map[string]string, error) {
		return collectInstalledComponentVersions(), nil
	})
	c.certs = swrcache.NewBounded(certProbeCacheTTL, 500*time.Millisecond, func(context.Context) ([]CertHealth, error) {
		cfg := s.readConfigOrNil()
		return deploy.InspectServerCerts(cfg), nil
	})
	c.disk = swrcache.NewBounded(rootDiskMetricsCacheTTL, configSelectMaxWait, func(context.Context) (diskUsageSnapshot, error) {
		u, t, p, ok := getRootDiskUsage()
		if !ok {
			return diskUsageSnapshot{}, errors.New("root statfs unavailable")
		}
		return diskUsageSnapshot{used: u, total: t, percent: p, ok: true}, nil
	})
	return c
}

func collectInstalledComponentVersions() map[string]string {
	fetchWithTimeout := func(fn func() string) string {
		ch := make(chan string, 1)
		go func() {
			ch <- fn()
		}()
		t := time.NewTimer(1500 * time.Millisecond)
		defer t.Stop()
		select {
		case v := <-ch:
			return v
		case <-t.C:
			return ""
		}
	}

	type verEntry struct {
		id  string
		ver string
	}
	var targets []component.Component
	for _, comp := range deploy.ServerRegistry().All() {
		if _, ok := comp.(component.Versioned); ok {
			targets = append(targets, comp)
		}
	}

	resCh := make(chan verEntry, len(targets))
	var wg sync.WaitGroup
	for _, comp := range targets {
		verComp := comp.(component.Versioned)
		id := comp.ID()
		wg.Go(func() {
			resCh <- verEntry{id: id, ver: fetchWithTimeout(verComp.InstalledVersion)}
		})
	}
	wg.Wait()
	close(resCh)

	res := make(map[string]string, len(targets))
	for entry := range resCh {
		res[entry.id] = entry.ver
	}
	return res
}

func probeLoopbackTCP(addr string, timeout time.Duration) bool {
	if timeout <= 0 {
		timeout = 100 * time.Millisecond
	}
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

func probeServicesByLoopbackPorts() map[string]ServiceProbeSnapshot {
	return map[string]ServiceProbeSnapshot{
		"caddy":       {Running: probeLoopbackTCP("127.0.0.1:443", 80*time.Millisecond)},
		"sing-box":    {Running: probeLoopbackTCP(telemetry.DefaultControllerAddr, 80*time.Millisecond)},
		"singctl-sub": {Running: probeLoopbackTCP(subhub.DefaultListenAddr, 80*time.Millisecond)},
		"wireproxy":   {Running: probeLoopbackTCP("127.0.0.1:40000", 80*time.Millisecond)},
	}
}

func (s *Server) resolveSubstoreAdminURLFast(cfg *config.Config) string {
	if cfg == nil {
		return ""
	}
	sbt := deploy.NewSubstore(cfg, "")
	if adminURL, err := sbt.GetAdminURL(); err == nil {
		return adminURL
	}
	return ""
}

func (s *Server) fallbackConfigBundle() cachedConfigBundle {
	if s.cfgStore != nil && s.cfgStore.Revision() > 0 {
		cfg := s.cfgStore.Get()
		return cachedConfigBundle{cfg: cfg, subAdminURL: s.resolveSubstoreAdminURLFast(cfg)}
	}
	return cachedConfigBundle{cfg: &config.Config{}}
}

func (s *Server) loadConfigBounded(maxWait time.Duration) (*config.Config, error) {
	wait := cmp.Or(maxWait, configSelectMaxWait)
	bundle, err := s.caches.config.GetWithFallback(context.Background(), wait, s.fallbackConfigBundle())
	if bundle.cfg == nil {
		return &config.Config{}, err
	}
	return bundle.cfg, nil
}

func (s *Server) getConfigSnapshot(maxWait time.Duration) (*config.Config, string) {
	wait := cmp.Or(maxWait, configSelectMaxWait)
	bundle, _ := s.caches.config.GetWithFallback(context.Background(), wait, s.fallbackConfigBundle())
	cfg := bundle.cfg
	if cfg == nil {
		cfg = &config.Config{}
	}
	subURL := bundle.subAdminURL
	if subURL == "" {
		subURL = s.resolveSubstoreAdminURLFast(cfg)
	}
	return cfg, subURL
}

func formatServiceUptime(val string) string {
	val = strings.TrimSpace(val)
	if val == "" || val == "n/a" {
		return ""
	}
	t, err := time.Parse("Mon 2006-01-02 15:04:05 MST", val)
	if err != nil {
		return val
	}
	return time.Since(t).Round(time.Second).String()
}

// ParseSystemdShowBatchOutput 解析 `systemctl show` 批量输出并转换为面板服务探针结构。
func ParseSystemdShowBatchOutput(raw string) map[string]ServiceProbeSnapshot {
	parsed := servicemgr.ParseSystemdShowBatch(raw)
	out := make(map[string]ServiceProbeSnapshot, len(parsed))
	for unit, st := range parsed {
		out[unit] = ServiceProbeSnapshot{
			Running: st.Running,
			PID:     st.PID,
			Uptime:  formatServiceUptime(st.ActiveEnterTimestamp),
		}
	}
	return out
}

func (s *Server) probeSystemdServicesBatch(units ...string) map[string]ServiceProbeSnapshot {
	parsed := servicemgr.NewSystemd(s.activeCmdRunner()).ShowUnitsBatch(context.Background(), statusCmdTimeout, units...)
	out := make(map[string]ServiceProbeSnapshot, len(parsed))
	for unit, st := range parsed {
		out[unit] = ServiceProbeSnapshot{
			Running: st.Running,
			PID:     st.PID,
			Uptime:  formatServiceUptime(st.ActiveEnterTimestamp),
		}
	}
	return out
}

func (s *Server) getCachedServiceProbes() map[string]ServiceProbeSnapshot {
	probes, _ := s.caches.serviceProbes.GetWithFallback(context.Background(), statusSelectMaxWait, nil)
	if len(probes) > 0 {
		return maps.Clone(probes)
	}
	return probeServicesByLoopbackPorts()
}

func (s *Server) getCachedServiceVersions() (caddyVer, singboxVer, subhubVer, warpVer string) {
	m, _ := s.caches.versions.GetWithFallback(context.Background(), statusSelectMaxWait, map[string]string{})
	return m["caddy"], m["singbox"], m["subhub"], m["warp"]
}

func (s *Server) getCachedCerts() []CertHealth {
	certs, _ := s.caches.certs.GetWithFallback(context.Background(), 500*time.Millisecond, []CertHealth{})
	if certs == nil {
		return []CertHealth{}
	}
	return slices.Clone(certs)
}

func (s *Server) getCachedRootDiskUsage() (used, total, pct string, ok bool) {
	d, _ := s.caches.disk.GetWithFallback(context.Background(), configSelectMaxWait, diskUsageSnapshot{})
	return d.used, d.total, d.percent, d.ok
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	cfg, substoreAdminURL := s.getConfigSnapshot(configSelectMaxWait)

	subDomain := cmp.Or(cfg.Server.GetSubstoreDomain(), cfg.Server.GetNodeDomain())
	adminPath := cfg.Server.GetWebAdminPath()
	httpsURL := ""
	if subDomain != "" && adminPath != "" {
		httpsURL = fmt.Sprintf("https://%s%s/", subDomain, adminPath)
	}

	var probes map[string]ServiceProbeSnapshot
	var caddyVer, singboxVer, subhubVer, warpVer string
	var sysMetrics map[string]any
	var certs []CertHealth

	var wg sync.WaitGroup
	wg.Go(func() { probes = s.getCachedServiceProbes() })
	wg.Go(func() { caddyVer, singboxVer, subhubVer, warpVer = s.getCachedServiceVersions() })
	wg.Go(func() { sysMetrics = s.getSystemMetricsBounded() })
	wg.Go(func() { certs = s.getCachedCerts() })
	wg.Wait()

	caddyProbe := probes["caddy"]
	singboxProbe := probes["sing-box"]
	subhubProbe := probes["singctl-sub"]
	warpProbe := probes["wireproxy"]

	subhubRunning := subhubProbe.Running || probeLoopbackTCP(subhub.DefaultListenAddr, 80*time.Millisecond)

	status := map[string]any{
		"version":     s.opts.Version,
		"authEnabled": s.GetPassword() != "",
		"system":      sysMetrics,
		"admin": map[string]any{
			"username": s.GetUsername(),
			"path":     adminPath,
			"httpsUrl": httpsURL,
			"port":     cfg.Server.GetWebAdminPort(),
		},
		"services": map[string]any{
			"caddy": map[string]any{
				"running": caddyProbe.Running,
				"version": caddyVer,
				"pid":     caddyProbe.PID,
				"uptime":  caddyProbe.Uptime,
			},
			"singbox": map[string]any{
				"running": singboxProbe.Running,
				"version": singboxVer,
				"pid":     singboxProbe.PID,
				"uptime":  singboxProbe.Uptime,
			},
			"subhub": map[string]any{
				"running": subhubRunning,
				"version": subhubVer,
				"pid":     subhubProbe.PID,
				"uptime":  subhubProbe.Uptime,
				"engine":  "native-go",
			},
			"warp": map[string]any{
				"running":   warpProbe.Running,
				"version":   warpVer,
				"pid":       warpProbe.PID,
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
		"certs": certs,
	}
	if s.audit != nil {
		rawLogs := s.audit.List()
		enriched := make([]map[string]any, 0, len(rawLogs))
		for _, entry := range rawLogs {
			item := map[string]any{
				"time":     entry.Time,
				"action":   entry.Action,
				"ip":       entry.IP,
				"category": ClassifyAuditCategory(entry.Action),
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
	if s.pendingAck() && !config.IsHashedPassword(s.GetPassword()) {
		status["initialCredentials"] = map[string]any{
			"pending":  true,
			"username": s.GetUsername(),
			"password": s.GetPassword(),
		}
	}
	writeJSON(w, http.StatusOK, status)
}

func (s *Server) handleNodes(w http.ResponseWriter, r *http.Request) {
	cfg, err := s.loadConfigSnapshot()
	if err != nil && s.cfgStore != nil && s.cfgStore.Revision() > 0 {
		cfg = s.cfgStore.Get()
		err = nil
	}
	if err != nil || cfg == nil {
		errMsg := "empty config"
		if err != nil {
			errMsg = err.Error()
		}
		writeJSONError(w, http.StatusInternalServerError, "加载配置失败: "+errMsg)
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

	writeJSON(w, http.StatusOK, map[string]any{
		"hy2": map[string]any{
			"link":     sbs.ShareLinkHy2,
			"port":     sbs.Hy2Port(),
			"protocol": "hysteria2",
			"domain":   cfg.Server.GetNodeDomain(),
		},
		"vless": map[string]any{
			"link":     sbs.ShareLinkVless,
			"port":     sbs.VlessPort(),
			"protocol": "vless",
			"sni":      cfg.Server.Sni,
		},
		"substore": map[string]any{
			"adminUrl": adminURL,
		},
	})
}

func (s *Server) getSystemMetricsBounded() map[string]any {
	m := readProcSystemMetrics()
	m["socketTune"] = socktune.Inspect(socktune.ProfileServer, s.sockTuneEnv())
	if used, total, pct, ok := s.getCachedRootDiskUsage(); ok {
		m["diskUsed"] = used
		m["diskTotal"] = total
		m["diskPercent"] = pct
	}
	return m
}

func readProcSystemMetrics() map[string]any {
	m := map[string]any{
		"bbr":    isBBREnabled(),
		"uptime": getSystemUptime(),
	}

	if mi, err := sysinfo.ReadMemInfo(); err == nil && mi.TotalBytes > 0 {
		used := mi.TotalBytes - min(mi.AvailableBytes, mi.TotalBytes)
		m["memTotalMB"] = mi.TotalBytes / (1024 * 1024)
		m["memUsedMB"] = used / (1024 * 1024)
		m["memUsagePercent"] = fmt.Sprintf("%.1f%%", float64(used)/float64(mi.TotalBytes)*100)
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
		return (time.Duration(secs) * time.Second).Round(time.Minute).String()
	}
	return ""
}

func checkServiceRunning(name string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), statusCmdTimeout)
	defer cancel()
	return servicemgr.NewSystemd(nil).IsActive(ctx, name)
}

func isBBREnabled() bool {
	data, err := os.ReadFile("/proc/sys/net/ipv4/tcp_congestion_control")
	if err != nil {
		return false
	}
	return strings.Contains(strings.TrimSpace(string(data)), "bbr")
}

// 文件职责：提供 SubHub 聚合订阅管理、预览、密钥轮换与访问日志审计薄 HTTP 接口（风险评估委托 internal/subhub）。
package serverweb

import (
	"cmp"
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"singctl/internal/common/httpx"
	"singctl/internal/deploy"
	"singctl/internal/logger"
	"singctl/internal/subhub"
)

func (s *Server) handleSubscriptions(w http.ResponseWriter, r *http.Request) {
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

	hy2Link, vlessLink, hy2Port, vlessPort := deploy.InspectExistingShareLinks(cfg, s.opts.SingBoxConfigPath)

	sbt := deploy.NewSubstore(cfg, "")
	adminURL, _ := sbt.GetAdminURL()
	ssKey, err := s.subStore.GetKey()
	if err != nil || ssKey == "" {
		ssKey, _ = sbt.GetSubstoreKey()
	}
	if ssKey == "" {
		ssKey, _ = s.subStore.EnsureKey()
	}

	subDomain := cmp.Or(cfg.Server.GetSubstoreDomain(), cfg.Server.GetNodeDomain())
	rawSubURL := fmt.Sprintf("https://%s/download/collection/all", subDomain)
	if ssKey != "" {
		rawSubURL = fmt.Sprintf("https://%s/%s/download/collection/all", subDomain, ssKey)
	}

	if r.URL.Query().Get("refresh") == "1" {
		warmupCtx, cancelWarmup := context.WithTimeout(r.Context(), 6*time.Second)
		s.subStore.WarmupUncachedSources(warmupCtx)
		cancelWarmup()
	} else {
		tryRunSingleFlight(&s.caches.subWarmup, 15*time.Second, func(bgCtx context.Context) {
			s.subStore.WarmupUncachedSources(bgCtx)
		})
	}

	sources, err := s.subStore.ListSources()
	if err != nil || sources == nil {
		sources = []subhub.SourceItem{}
	}

	importLinks := map[string]string{
		"shadowrocket": "sub://" + base64.StdEncoding.EncodeToString([]byte(rawSubURL+"?target=Shadowrocket")),
		"clash":        "clash://install-config?url=" + url.QueryEscape(rawSubURL+"?target=ClashMeta"),
		"singbox":      "sing-box://import-remote-profile?url=" + url.QueryEscape(rawSubURL+"?target=Sing-Box"),
		"surge":        "surge:///install-config?url=" + url.QueryEscape(rawSubURL+"?target=Surge"),
		"loon":         "loon://import?url=" + url.QueryEscape(rawSubURL+"?target=Loon"),
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"engine":           "native-go",
		"substoreKey":      ssKey,
		"substoreAdminUrl": adminURL,
		"subscriptionUrl":  rawSubURL,
		"importLinks":      importLinks,
		"sources":          sources,
		"nodes": map[string]any{
			"hy2": map[string]any{
				"link":   hy2Link,
				"domain": cfg.Server.GetNodeDomain(),
				"port":   hy2Port,
			},
			"vless": map[string]any{
				"link": vlessLink,
				"sni":  cfg.Server.Sni,
				"port": vlessPort,
			},
		},
	})
}

func (s *Server) handleUpsertSubscriptionSource(w http.ResponseWriter, r *http.Request) {
	in, ok := decodeBodyJSON[subhub.SourceUpsertInput](w, r, httpx.DefaultMaxBodyBytes, false, "")
	if !ok {
		return
	}
	item, err := s.subStore.UpsertSource(r.Context(), in)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.recordAudit(r, fmt.Sprintf("保存聚合订阅源 [%s (%s)]", item.DisplayName, item.Source))
	writeJSON(w, http.StatusOK, map[string]any{
		"message": "订阅源已保存并实时加入聚合节点池",
		"source":  item,
	})
}

func (s *Server) handleDeleteSubscriptionSource(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimSpace(r.URL.Query().Get("name"))
	if name == "" {
		type reqBody struct {
			Name string `json:"name"`
		}
		body, ok := decodeBodyJSON[reqBody](w, r, httpx.DefaultMaxBodyBytes, true, "")
		if !ok {
			return
		}
		name = strings.TrimSpace(body.Name)
	}
	if err := s.subStore.DeleteSource(name); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.recordAudit(r, fmt.Sprintf("删除聚合订阅源 [%s]", name))
	writeJSON(w, http.StatusOK, map[string]string{
		"message": "订阅源已成功移除",
	})
}

func (s *Server) handleRefreshSubscriptionSources(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimSpace(r.URL.Query().Get("name"))
	if name == "" && r.Body != nil {
		type reqBody struct {
			Name string `json:"name"`
		}
		body, ok := decodeBodyJSON[reqBody](w, r, httpx.DefaultMaxBodyBytes, true, "")
		if !ok {
			return
		}
		name = strings.TrimSpace(body.Name)
	}

	ctx, cancel := context.WithTimeout(r.Context(), 25*time.Second)
	defer cancel()

	sources, err := s.subStore.RefreshSources(ctx, name)
	if name != "" && err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"error":   "刷新远程订阅源失败: " + err.Error(),
			"sources": sources,
		})
		return
	}

	if name != "" {
		s.recordAudit(r, fmt.Sprintf("手动刷新远程订阅源 [%s]", name))
	} else {
		s.recordAudit(r, "手动刷新全部远程订阅源")
	}

	msg := "远程订阅源已刷新并同步最新节点"
	var warnMsg string
	if err != nil {
		warnMsg = err.Error()
		msg = "部分远程订阅源刷新存在告警: " + err.Error()
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"message": msg,
		"warning": warnMsg,
		"sources": sources,
	})
}

func (s *Server) handleRotateSubscriptionKey(w http.ResponseWriter, r *http.Request) {
	newKey, err := s.subStore.RotateKey()
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "轮换订阅密钥失败: "+err.Error())
		return
	}
	s.InvalidateConfigCache()

	cfg := s.readConfigOrNil()
	if cfg != nil {
		if err := deploy.SyncCaddyfile(cfg); err != nil {
			logger.Warn("轮换订阅密钥后同步 Caddyfile 警告: %v", err)
		}
	}

	subDomain := ""
	if cfg != nil {
		subDomain = cmp.Or(cfg.Server.GetSubstoreDomain(), cfg.Server.GetNodeDomain())
	}
	newSubURL := ""
	if subDomain != "" {
		newSubURL = fmt.Sprintf("https://%s/%s/download/collection/all", subDomain, newKey)
	}

	s.recordAudit(r, "轮换客户端聚合订阅访问密钥")
	writeJSON(w, http.StatusOK, map[string]any{
		"message":         "订阅访问密钥已成功轮换，旧订阅链接已立即失效",
		"substoreKey":     newKey,
		"subscriptionUrl": newSubURL,
	})
}

func (s *Server) handlePreviewSubscription(w http.ResponseWriter, r *http.Request) {
	qTarget := cmp.Or(strings.TrimSpace(r.URL.Query().Get("target")), "ClashMeta")
	target := subhub.DetectTarget(qTarget, r.URL.Query().Get("raw"), "")

	bundle, err := s.subStore.ResolveCollection(r.Context(), "all")
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "解析聚合节点池失败: "+err.Error())
		return
	}

	renderOpts := subhub.RenderOptions{
		Target:   target,
		Platform: r.URL.Query().Get("platform"),
	}
	if cfg := s.readConfigOrNil(); cfg != nil {
		renderOpts.MirrorURL = cfg.GitHub.MirrorURL
		renderOpts.UpMbps = cfg.Hy2.Up
		renderOpts.DownMbps = cfg.Hy2.Down
		subDomain := cmp.Or(cfg.Server.GetSubstoreDomain(), cfg.Server.GetNodeDomain())
		if key, kErr := s.subStore.GetKey(); kErr == nil && key != "" && subDomain != "" {
			renderOpts.RequestURL = fmt.Sprintf("https://%s/%s/download/collection/all?target=%s", subDomain, key, qTarget)
		}
	}

	res, err := subhub.RenderBundle(r.Context(), bundle, renderOpts)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"target":      string(res.Format),
		"filename":    res.Filename,
		"contentType": res.ContentType,
		"nodeCount":   len(bundle.Nodes),
		"content":     string(res.Body),
	})
}

func (s *Server) handleListSubscriptionAccessLogs(w http.ResponseWriter, r *http.Request) {
	logs, err := s.subStore.ListAccessLogs()
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "读取订阅拉取审计失败: "+err.Error())
		return
	}
	enriched := make([]subhub.AccessLogEntry, len(logs))
	for i, item := range logs {
		if s.geo != nil && item.IP != "" {
			if item.CountryCode != "" {
				s.geo.SeedCountry(item.IP, item.CountryCode)
			}
			geo := s.geo.Resolve(item.IP)
			if geo.Geo != "" {
				item.Geo = geo.Geo
			}
			if geo.Flag != "" {
				item.Flag = geo.Flag
			}
			if item.CountryCode == "" && geo.CountryCode != "" {
				item.CountryCode = geo.CountryCode
			}
		} else if item.CountryCode != "" && item.Flag == "" {
			item.Flag = CountryCodeToFlag(item.CountryCode)
		}
		enriched[i] = item
	}

	bannedIPs := make([]string, 0)
	if s.limiter != nil {
		for ip := range s.limiter.ListBans() {
			bannedIPs = append(bannedIPs, ip)
		}
	}

	riskSummary := subhub.EvaluateAccessRisk(enriched)
	writeJSON(w, http.StatusOK, map[string]any{
		"logs":        enriched,
		"riskSummary": riskSummary,
		"bannedIps":   bannedIPs,
	})
}

func (s *Server) handleClearSubscriptionAccessLogs(w http.ResponseWriter, r *http.Request) {
	if err := s.subStore.ClearAccessLogs(); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "清空订阅访问记录失败: "+err.Error())
		return
	}
	s.recordAudit(r, "清空客户端订阅拉取审计日志")
	writeJSON(w, http.StatusOK, map[string]string{
		"message": "订阅访问记录已清空",
	})
}

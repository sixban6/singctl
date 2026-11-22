// 文件职责：提供 SubHub HTTP 订阅转换服务端路由、密钥鉴权、多客户端模板协商与确定性生命周期管理。
package subhub

import (
	"cmp"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"singctl/internal/config"
	"singctl/internal/lifecycle"
	"singctl/internal/logger"
)

const DefaultListenAddr = "127.0.0.1:3001"

// Options configures the SubHub HTTP subscription server.
type Options struct {
	Listen              string
	ConfigPath          string
	ConfigStore         *config.Store
	DataDir             string
	FilePath            string
	Version             string
	AllowLoopbackRemote bool
	OnReady             func(listenAddr string)
}

// Server serves dynamic multi-target subscriptions compatible with legacy Sub-Store download URLs.
type Server struct {
	opts     Options
	store    *Store
	cfgStore *config.Store
}

// NewServer constructs a SubHub HTTP server.
func NewServer(opts Options) *Server {
	opts.Listen = cmp.Or(strings.TrimSpace(opts.Listen), DefaultListenAddr)
	opts.Version = cmp.Or(strings.TrimSpace(opts.Version), "dev")
	st := NewStore(opts.DataDir, opts.FilePath)
	st.AllowLoopbackRemote = opts.AllowLoopbackRemote
	cfgStore := opts.ConfigStore
	if cfgStore == nil && strings.TrimSpace(opts.ConfigPath) != "" {
		cfgStore = config.NewStore(opts.ConfigPath)
	}
	return &Server{
		opts:     opts,
		store:    st,
		cfgStore: cfgStore,
	}
}

// Store returns the underlying subscription Store.
func (s *Server) Store() *Store {
	return s.store
}

// Handler returns the HTTP handler for the SubHub server.
func (s *Server) Handler() http.Handler {
	return http.HandlerFunc(s.serveHTTP)
}

func (s *Server) buildLifecycle() *lifecycle.Group {
	g := lifecycle.NewGroup(lifecycle.WithCloseTimeout(5 * time.Second))
	g.Add(lifecycle.FuncService{
		ServiceName: "subhub-keystore",
		OnInit: func(context.Context) error {
			if _, err := s.store.EnsureKey(); err != nil {
				logger.Warn("SubHub failed to initialize key file: %v", err)
			}
			return nil
		},
	})
	return g
}

// ServeContext runs the SubHub HTTP server under deterministic lifecycle management until ctx is cancelled.
func (s *Server) ServeContext(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}

	lc := s.buildLifecycle()
	if err := lc.Start(ctx); err != nil {
		return err
	}
	defer func() {
		_ = lc.Close()
	}()

	ln, err := net.Listen("tcp", s.opts.Listen)
	if err != nil {
		return err
	}
	actualAddr := ln.Addr().String()
	if s.opts.OnReady != nil {
		s.opts.OnReady(actualAddr)
	}

	httpServer := &http.Server{
		Handler:           s.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       20 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	serveDone := make(chan struct{})
	defer close(serveDone)
	go func() {
		select {
		case <-ctx.Done():
			logger.Info("Shutting down SubHub server...")
			shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			_ = httpServer.Shutdown(shutCtx)
			cancel()
		case <-serveDone:
		}
	}()

	logger.Info("SubHub native subscription engine listening on http://%s (version=%s)", actualAddr, s.opts.Version)
	err = httpServer.Serve(ln)
	if errors.Is(err, http.ErrServerClosed) && ctx.Err() != nil {
		return nil
	}
	return err
}

// Start runs the SubHub HTTP server until SIGINT/SIGTERM is received.
func (s *Server) Start() error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return s.ServeContext(ctx)
}

func isDirectLoopback(r *http.Request) bool {
	if r.Header.Get("X-Forwarded-For") != "" ||
		r.Header.Get("CF-Connecting-IP") != "" ||
		r.Header.Get("X-Real-IP") != "" {
		return false
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip := net.ParseIP(strings.TrimSpace(host))
	return ip == nil || ip.IsLoopback()
}

func (s *Server) serveHTTP(w http.ResponseWriter, r *http.Request) {
	cleanPath := strings.TrimSpace(r.URL.Path)

	// 1. Direct loopback health & version probes (used by singctl doctor / version checks)
	if cleanPath == "/healthz" {
		if !isDirectLoopback(r) {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":  "ok",
			"engine":  "subhub",
			"version": s.opts.Version,
		})
		return
	}

	if cleanPath == "/" || cleanPath == "" {
		if !isDirectLoopback(r) {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = fmt.Fprintf(w, "<!doctype html><html><head><meta charset=\"utf-8\"><meta name=\"version\" content=%q><title>SingCtl SubHub</title></head><body>OK</body></html>", s.opts.Version)
		return
	}

	// CORS preflight for subscription clients
	if r.Method == http.MethodOptions {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, HEAD, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, User-Agent")
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	// 2. Verify secret path key in constant time: /{key}/download/... or /{key}/api/file/...
	expectedKey, err := s.store.GetKey()
	if err != nil || expectedKey == "" {
		expectedKey, err = s.store.EnsureKey()
		if err != nil {
			http.Error(w, "Subscription key unavailable", http.StatusInternalServerError)
			return
		}
	}

	trimmed := strings.TrimPrefix(cleanPath, "/")
	slashIdx := strings.IndexByte(trimmed, '/')
	if slashIdx <= 0 {
		http.NotFound(w, r)
		return
	}
	providedKey := trimmed[:slashIdx]
	rest := trimmed[slashIdx+1:]

	if len(providedKey) != len(expectedKey) || subtle.ConstantTimeCompare([]byte(providedKey), []byte(expectedKey)) != 1 {
		if r.Method == http.MethodGet {
			clientIP, country := extractRequestIPAndCountry(r)
			ua := strings.TrimSpace(r.Header.Get("User-Agent"))
			s.store.RecordAccess(AccessLogEntry{
				IP:          clientIP,
				CountryCode: country,
				ClientApp:   IdentifyClientApp(ua),
				UserAgent:   ua,
				Target:      "-",
				Collection:  rest,
				Status:      "denied",
			})
		}
		http.NotFound(w, r)
		return
	}

	// Supported routes after /{key}/:
	//   - download/collection/{name}
	//   - api/file/{name}
	//   - download/{name}
	var bundle *ResolvedBundle
	switch {
	case strings.HasPrefix(rest, "download/collection/"):
		colName := strings.Trim(strings.TrimPrefix(rest, "download/collection/"), "/")
		colName = cmp.Or(colName, DefaultCollectionName)
		bundle, err = s.store.ResolveCollection(r.Context(), colName)

	case strings.HasPrefix(rest, "api/file/"):
		name := strings.Trim(strings.TrimPrefix(rest, "api/file/"), "/")
		name = cmp.Or(name, DefaultCollectionName)
		bundle, err = s.store.ResolveCollection(r.Context(), name)
		if err != nil {
			bundle, err = s.store.ResolveSubscription(r.Context(), name)
		}

	case strings.HasPrefix(rest, "download/"):
		name := strings.Trim(strings.TrimPrefix(rest, "download/"), "/")
		name = cmp.Or(name, DefaultCollectionName)
		bundle, err = s.store.ResolveSubscription(r.Context(), name)
		if err != nil {
			bundle, err = s.store.ResolveCollection(r.Context(), name)
		}

	default:
		http.NotFound(w, r)
		return
	}

	if err != nil {
		http.NotFound(w, r)
		return
	}

	q := r.URL.Query()
	target := DetectTarget(
		cmp.Or(q.Get("target"), q.Get("format"), q.Get("type")),
		q.Get("raw"),
		r.Header.Get("User-Agent"),
	)

	renderOpts := s.loadRenderOptions(r, target)
	res, err := RenderBundle(r.Context(), bundle, renderOpts)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Type", res.ContentType)
	w.Header().Set("Cache-Control", "private, no-cache, no-store, max-age=0, must-revalidate")
	w.Header().Set("Profile-Update-Interval", "12")
	w.Header().Set("Content-Disposition", fmt.Sprintf("inline; filename=%q", res.Filename))
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		_, _ = w.Write(res.Body)
		clientIP, country := extractRequestIPAndCountry(r)
		ua := strings.TrimSpace(r.Header.Get("User-Agent"))
		colLabel := DefaultCollectionName
		if bundle != nil && bundle.Name != "" {
			colLabel = bundle.Name
		}
		nodeCount := 0
		if bundle != nil {
			nodeCount = max(len(bundle.Nodes), len(bundle.URIs))
		}
		s.store.RecordAccess(AccessLogEntry{
			IP:          clientIP,
			CountryCode: country,
			ClientApp:   IdentifyClientApp(ua),
			UserAgent:   ua,
			Target:      string(res.Format),
			Collection:  colLabel,
			NodeCount:   nodeCount,
			Status:      "ok",
		})
	}
}

// LoadRenderOptions resolves target rendering options from the HTTP request and ConfigStore snapshot.
func (s *Server) LoadRenderOptions(r *http.Request, target TargetFormat) RenderOptions {
	return s.loadRenderOptions(r, target)
}

func (s *Server) loadRenderOptions(r *http.Request, target TargetFormat) RenderOptions {
	q := r.URL.Query()
	sbVer := strings.TrimSpace(q.Get("ver"))
	if sbVer == "" {
		sbVer = inferSingBoxTemplateFromUA(r.Header.Get("User-Agent"))
	}
	opts := RenderOptions{
		Target:         target,
		Platform:       q.Get("platform"),
		SingBoxVersion: sbVer,
		RequestURL:     buildExternalRequestURL(r),
	}

	if s.cfgStore != nil {
		cfg, err := s.cfgStore.LoadLatest()
		if err != nil || cfg == nil {
			cfg = s.cfgStore.Get()
		}
		if cfg != nil {
			opts.MirrorURL = cfg.GitHub.MirrorURL
			opts.UpMbps = cfg.Hy2.Up
			opts.DownMbps = cfg.Hy2.Down
		}
	}
	return opts
}

// inferSingBoxTemplateFromUA 在未显式指定 ?ver= 时，为旧版 SFI/SFA/SFM (1.12/1.13) 自动协商兼容模板，
// 其余 1.14+ 或通用客户端默认走 v1.14 新标准。
func inferSingBoxTemplateFromUA(userAgent string) string {
	ua := strings.ToLower(strings.TrimSpace(userAgent))
	for _, prefix := range []string{"sfi/", "sfa/", "sfm/", "sing-box/", "sing-box "} {
		if idx := strings.Index(ua, prefix); idx >= 0 {
			ver := ua[idx+len(prefix):]
			if strings.HasPrefix(ver, "1.12") {
				return "v1.12"
			}
			if strings.HasPrefix(ver, "1.13") {
				return "v1.13"
			}
		}
	}
	return ""
}

func buildExternalRequestURL(r *http.Request) string {
	proto := strings.TrimSpace(strings.Split(r.Header.Get("X-Forwarded-Proto"), ",")[0])
	if proto == "" {
		if r.TLS != nil {
			proto = "https"
		} else {
			proto = "http"
		}
	}
	host := strings.TrimSpace(strings.Split(r.Header.Get("X-Forwarded-Host"), ",")[0])
	if host == "" {
		host = strings.TrimSpace(r.Host)
	}
	if host == "" {
		return ""
	}
	return fmt.Sprintf("%s://%s%s", proto, host, r.URL.RequestURI())
}

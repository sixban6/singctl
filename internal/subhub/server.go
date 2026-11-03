package subhub

import (
	"cmp"
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"singctl/internal/config"
	"singctl/internal/logger"
)

const DefaultListenAddr = "127.0.0.1:3001"

// Options configures the SubHub HTTP subscription server.
type Options struct {
	Listen              string
	ConfigPath          string
	DataDir             string
	FilePath            string
	Version             string
	AllowLoopbackRemote bool
}

// Server serves dynamic multi-target subscriptions compatible with legacy Sub-Store download URLs.
type Server struct {
	opts  Options
	store *Store
}

// NewServer constructs a SubHub HTTP server.
func NewServer(opts Options) *Server {
	opts.Listen = cmp.Or(strings.TrimSpace(opts.Listen), DefaultListenAddr)
	opts.Version = cmp.Or(strings.TrimSpace(opts.Version), "dev")
	st := NewStore(opts.DataDir, opts.FilePath)
	st.AllowLoopbackRemote = opts.AllowLoopbackRemote
	return &Server{
		opts:  opts,
		store: st,
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

// Start runs the SubHub HTTP server until SIGINT/SIGTERM is received.
func (s *Server) Start() error {
	if _, err := s.store.EnsureKey(); err != nil {
		logger.Warn("SubHub failed to initialize key file: %v", err)
	}

	httpServer := &http.Server{
		Addr:              s.opts.Listen,
		Handler:           s.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       20 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	errCh := make(chan error, 1)
	go func() {
		logger.Info("SubHub native subscription engine listening on http://%s (version=%s)", s.opts.Listen, s.opts.Version)
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
	}()

	select {
	case err := <-errCh:
		return err
	case <-stop:
		logger.Info("Shutting down SubHub server...")
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return httpServer.Shutdown(ctx)
	}
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
	}
}

func (s *Server) loadRenderOptions(r *http.Request, target TargetFormat) RenderOptions {
	q := r.URL.Query()
	opts := RenderOptions{
		Target:         target,
		Platform:       q.Get("platform"),
		SingBoxVersion: q.Get("ver"),
		RequestURL:     buildExternalRequestURL(r),
	}

	if s.opts.ConfigPath != "" {
		if cfg, err := config.Load(s.opts.ConfigPath); err == nil && cfg != nil {
			opts.MirrorURL = cfg.GitHub.MirrorURL
			opts.UpMbps = cfg.Hy2.Up
			opts.DownMbps = cfg.Hy2.Down
		}
	}
	return opts
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

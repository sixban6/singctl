// 文件职责：提供同时兼容未压缩与预压缩 .gz 静态资源的 HTTP 静态文件处理器（零拷贝直出 + 透明解压兜底）。
package webui

import (
	"compress/gzip"
	"io"
	"io/fs"
	"mime"
	"net/http"
	"path"
	"strconv"
	"strings"
)

// staticMIMETypes 显式内置常见前端资源 MIME 表，确保 OpenWrt 等精简系统在缺失 /etc/mime.types 时仍能准确响应。
var staticMIMETypes = map[string]string{
	".html":        "text/html; charset=utf-8",
	".htm":         "text/html; charset=utf-8",
	".js":          "text/javascript; charset=utf-8",
	".mjs":         "text/javascript; charset=utf-8",
	".css":         "text/css; charset=utf-8",
	".svg":         "image/svg+xml",
	".json":        "application/json; charset=utf-8",
	".webmanifest": "application/manifest+json; charset=utf-8",
	".png":         "image/png",
	".ico":         "image/x-icon",
	".webp":        "image/webp",
	".jpg":         "image/jpeg",
	".jpeg":        "image/jpeg",
	".woff2":       "font/woff2",
	".woff":        "font/woff",
	".txt":         "text/plain; charset=utf-8",
}

// NewStaticHandler 返回支持 .gz 预压缩内嵌与未压缩双形态的静态资源处理器。
func NewStaticHandler(fsys fs.FS) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if fsys == nil {
			http.NotFound(w, r)
			return
		}

		rel, cleanURL, ok := resolveStaticRelPath(r.URL.Path, r.URL.RawPath)
		if !ok {
			http.NotFound(w, r)
			return
		}

		// 1. 优先精确匹配未压缩原文件（兼容极小文件、图标及未启用 .gz 预压缩的历史磁盘形态）
		if serveExactStaticFile(w, r, fsys, rel, cleanURL) {
			return
		}

		// 2. 精确路径不存在时匹配同名 .gz 预压缩产物
		if !strings.HasSuffix(rel, ".gz") && serveGzipStaticFile(w, r, fsys, rel, cleanURL) {
			return
		}

		http.NotFound(w, r)
	})
}

func resolveStaticRelPath(urlPath, rawPath string) (rel string, cleanURL string, ok bool) {
	for _, raw := range []string{urlPath, rawPath} {
		if raw == "" {
			continue
		}
		if strings.ContainsRune(raw, '\x00') || strings.ContainsRune(raw, '\\') {
			return "", "", false
		}
		lower := strings.ToLower(raw)
		if strings.Contains(lower, "%2e") || strings.Contains(lower, "%2f") || strings.Contains(lower, "%5c") {
			return "", "", false
		}
		for seg := range strings.SplitSeq(raw, "/") {
			if seg == ".." {
				return "", "", false
			}
		}
	}

	if urlPath == "" || urlPath == "/" {
		return "index.html", "/", true
	}
	cleaned := path.Clean("/" + urlPath)
	if strings.HasSuffix(urlPath, "/") && cleaned != "/" {
		cleaned += "/index.html"
	} else if cleaned == "/" {
		cleaned = "/index.html"
	}

	rel = strings.TrimPrefix(cleaned, "/")
	if rel == "" || rel == "." || !fs.ValidPath(rel) {
		return "", "", false
	}
	return rel, cleaned, true
}

func serveExactStaticFile(w http.ResponseWriter, r *http.Request, fsys fs.FS, rel, cleanURL string) bool {
	f, err := fsys.Open(rel)
	if err != nil {
		return false
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil || info.IsDir() {
		return false
	}

	setStaticCacheHeaders(w, cleanURL)
	if ct := detectStaticContentType(rel); ct != "" {
		w.Header().Set("Content-Type", ct)
	}
	w.Header().Set("Content-Length", strconv.FormatInt(info.Size(), 10))
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		_, _ = io.Copy(w, f)
	}
	return true
}

func serveGzipStaticFile(w http.ResponseWriter, r *http.Request, fsys fs.FS, rel, cleanURL string) bool {
	gzPath := rel + ".gz"
	f, err := fsys.Open(gzPath)
	if err != nil {
		return false
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil || info.IsDir() {
		return false
	}

	ct := detectStaticContentType(rel)
	if acceptsGzipEncoding(r.Header.Get("Accept-Encoding")) {
		setStaticCacheHeaders(w, cleanURL)
		addVaryAcceptEncoding(w)
		if ct != "" {
			w.Header().Set("Content-Type", ct)
		}
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Content-Length", strconv.FormatInt(info.Size(), 10))
		w.WriteHeader(http.StatusOK)
		if r.Method != http.MethodHead {
			_, _ = io.Copy(w, f)
		}
		return true
	}

	// 不支持 gzip 的客户端（老代理 / curl / httptest 默认请求）走标准库透明解压
	gr, err := gzip.NewReader(f)
	if err != nil {
		http.Error(w, "corrupt compressed static asset", http.StatusInternalServerError)
		return true
	}
	plain, err := io.ReadAll(gr)
	closeErr := gr.Close()
	if err != nil || closeErr != nil {
		http.Error(w, "failed to decompress static asset", http.StatusInternalServerError)
		return true
	}

	setStaticCacheHeaders(w, cleanURL)
	addVaryAcceptEncoding(w)
	if ct == "" {
		ct = http.DetectContentType(plain)
	}
	w.Header().Set("Content-Type", ct)
	w.Header().Set("Content-Length", strconv.Itoa(len(plain)))
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		_, _ = w.Write(plain)
	}
	return true
}

func detectStaticContentType(origPath string) string {
	ext := strings.ToLower(path.Ext(origPath))
	if ct, ok := staticMIMETypes[ext]; ok {
		return ct
	}
	if ext != "" {
		if ct := mime.TypeByExtension(ext); ct != "" {
			return ct
		}
	}
	return ""
}

func setStaticCacheHeaders(w http.ResponseWriter, cleanURL string) {
	if w.Header().Get("Cache-Control") != "" {
		return
	}
	if strings.HasPrefix(cleanURL, "/assets/") {
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	}
}

func addVaryAcceptEncoding(w http.ResponseWriter) {
	for _, existing := range w.Header().Values("Vary") {
		for token := range strings.SplitSeq(existing, ",") {
			if strings.EqualFold(strings.TrimSpace(token), "Accept-Encoding") {
				return
			}
		}
	}
	w.Header().Add("Vary", "Accept-Encoding")
}

func acceptsGzipEncoding(header string) bool {
	if header == "" {
		return false
	}
	for part := range strings.SplitSeq(header, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		enc, params, hasParams := strings.Cut(part, ";")
		if !strings.EqualFold(strings.TrimSpace(enc), "gzip") {
			continue
		}
		if !hasParams {
			return true
		}
		allowed := true
		for p := range strings.SplitSeq(params, ";") {
			k, v, ok := strings.Cut(strings.TrimSpace(p), "=")
			if ok && strings.EqualFold(strings.TrimSpace(k), "q") {
				if q, err := strconv.ParseFloat(strings.TrimSpace(v), 64); err == nil && q <= 0 {
					allowed = false
				}
			}
		}
		if allowed {
			return true
		}
	}
	return false
}

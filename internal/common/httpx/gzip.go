// 文件职责：提供基于 sync.Pool 复用 DEFLATE 字典的低分配 HTTP Gzip 透明压缩中间件（自动跳过小包、SSE 与 WebSocket）。
package httpx

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
)

const minCompressBytes = 1024

var (
	gzipWriterPool = sync.Pool{
		New: func() any {
			gw, _ := gzip.NewWriterLevel(io.Discard, gzip.BestSpeed)
			return gw
		},
	}
	sniffBufPool = sync.Pool{
		New: func() any {
			return bytes.NewBuffer(make([]byte, 0, minCompressBytes))
		},
	}
)

// PoolGzip 返回包装 next 的低分配透明 Gzip 中间件。
func PoolGzip(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ServeGzip(w, r, next)
	}
}

// ServeGzip 对体积达到 >= 1024B 的文本/JSON 响应透明启用 sync.Pool Gzip 压缩，保留 Flusher 与 Hijacker 能力。
func ServeGzip(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	if next == nil {
		return
	}
	if r == nil ||
		r.Method == http.MethodHead ||
		r.Header.Get("Upgrade") != "" ||
		strings.Contains(strings.ToLower(r.Header.Get("Accept")), "text/event-stream") ||
		strings.HasSuffix(r.URL.Path, "/stream") ||
		w.Header().Get("Content-Encoding") != "" ||
		!acceptsGzip(r.Header.Get("Accept-Encoding")) {
		next(w, r)
		return
	}

	gw := &gzipResponseWriter{
		w:          w,
		statusCode: http.StatusOK,
		buf:        sniffBufPool.Get().(*bytes.Buffer),
	}
	gw.buf.Reset()
	defer gw.finish()

	next(gw, r)
}

func acceptsGzip(header string) bool {
	if header == "" {
		return false
	}
	for part := range strings.SplitSeq(header, ",") {
		part = strings.TrimSpace(strings.ToLower(part))
		name, params, hasParams := strings.Cut(part, ";")
		if strings.TrimSpace(name) != "gzip" && strings.TrimSpace(name) != "*" {
			continue
		}
		if hasParams {
			pClean := strings.ReplaceAll(params, " ", "")
			if pClean == "q=0" || pClean == "q=0.0" || pClean == "q=0.00" || pClean == "q=0.000" {
				return false
			}
		}
		return true
	}
	return false
}

func isCompressibleResponse(h http.Header, status int) bool {
	if (status >= 100 && status < 200) || status == http.StatusNoContent || status == http.StatusNotModified {
		return false
	}
	if h.Get("Content-Encoding") != "" {
		return false
	}
	ct := strings.ToLower(strings.TrimSpace(h.Get("Content-Type")))
	if ct == "" {
		return true
	}
	for _, skip := range []string{
		"text/event-stream", "image/", "video/", "audio/", "font/", "application/gzip", "application/zip",
	} {
		if strings.HasPrefix(ct, skip) {
			return false
		}
	}
	return true
}

type gzipResponseWriter struct {
	w           http.ResponseWriter
	statusCode  int
	wroteHeader bool
	decided     bool
	compressing bool
	buf         *bytes.Buffer
	gz          *gzip.Writer
}

func (g *gzipResponseWriter) Header() http.Header { return g.w.Header() }

func (g *gzipResponseWriter) WriteHeader(code int) {
	if g.wroteHeader {
		return
	}
	g.statusCode = code
	g.wroteHeader = true
	if !g.decided && !isCompressibleResponse(g.w.Header(), code) {
		g.decideRaw()
	}
}

func (g *gzipResponseWriter) Write(p []byte) (int, error) {
	if !g.wroteHeader {
		g.WriteHeader(http.StatusOK)
	}
	if g.decided {
		if g.compressing {
			return g.gz.Write(p)
		}
		return g.w.Write(p)
	}
	if !isCompressibleResponse(g.w.Header(), g.statusCode) {
		g.decideRaw()
		return g.w.Write(p)
	}
	if g.buf.Len()+len(p) < minCompressBytes {
		return g.buf.Write(p)
	}
	if err := g.startCompress(); err != nil {
		return 0, err
	}
	return g.gz.Write(p)
}

func (g *gzipResponseWriter) Flush() {
	if !g.decided {
		g.decideRaw()
	} else if g.compressing && g.gz != nil {
		_ = g.gz.Flush()
	}
	if f, ok := g.w.(http.Flusher); ok {
		f.Flush()
	}
}

func (g *gzipResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if hj, ok := g.w.(http.Hijacker); ok {
		return hj.Hijack()
	}
	return nil, nil, http.ErrNotSupported
}

func (g *gzipResponseWriter) Unwrap() http.ResponseWriter { return g.w }

func (g *gzipResponseWriter) startCompress() error {
	g.decided = true
	g.compressing = true

	h := g.w.Header()
	h.Del("Content-Length")
	h.Set("Content-Encoding", "gzip")
	addVaryAcceptEncoding(h)
	if g.wroteHeader {
		g.w.WriteHeader(g.statusCode)
	}

	gz := gzipWriterPool.Get().(*gzip.Writer)
	gz.Reset(g.w)
	g.gz = gz

	if g.buf != nil && g.buf.Len() > 0 {
		if _, err := g.gz.Write(g.buf.Bytes()); err != nil {
			g.releaseBuf()
			return err
		}
	}
	g.releaseBuf()
	return nil
}

func (g *gzipResponseWriter) decideRaw() {
	g.decided = true
	g.compressing = false
	if g.wroteHeader {
		g.w.WriteHeader(g.statusCode)
	}
	if g.buf != nil && g.buf.Len() > 0 {
		_, _ = g.w.Write(g.buf.Bytes())
	}
	g.releaseBuf()
}

func (g *gzipResponseWriter) finish() {
	if !g.decided {
		if g.buf != nil && g.buf.Len() >= minCompressBytes && isCompressibleResponse(g.w.Header(), g.statusCode) {
			_ = g.startCompress()
		} else if g.wroteHeader || (g.buf != nil && g.buf.Len() > 0) {
			g.decideRaw()
		} else {
			g.releaseBuf()
		}
	}
	if g.gz != nil {
		_ = g.gz.Close()
		g.gz.Reset(io.Discard)
		gzipWriterPool.Put(g.gz)
		g.gz = nil
	}
}

func (g *gzipResponseWriter) releaseBuf() {
	if g.buf == nil {
		return
	}
	if g.buf.Cap() <= 64<<10 {
		g.buf.Reset()
		sniffBufPool.Put(g.buf)
	}
	g.buf = nil
}

func addVaryAcceptEncoding(h http.Header) {
	for _, existing := range h.Values("Vary") {
		for token := range strings.SplitSeq(existing, ",") {
			if strings.EqualFold(strings.TrimSpace(token), "Accept-Encoding") {
				return
			}
		}
	}
	h.Add("Vary", "Accept-Encoding")
}

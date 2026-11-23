// 文件职责：验证客户端 WebUI 静态资源处理器在 .gz 预压缩与未压缩双形态下的直出、透明解压、Content-Type、缓存头、路径穿越防护与并发安全。
package webui_test

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"testing/fstest"

	"singctl/internal/webui"
)

func mustGzipBytes(t *testing.T, plain []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gw, err := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := gw.Write(plain); err != nil {
		t.Fatal(err)
	}
	if err := gw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func gunzipBytes(t *testing.T, gz []byte) []byte {
	t.Helper()
	gr, err := gzip.NewReader(bytes.NewReader(gz))
	if err != nil {
		t.Fatalf("gzip.NewReader failed: %v", err)
	}
	defer gr.Close()
	out, err := io.ReadAll(gr)
	if err != nil {
		t.Fatalf("gunzip read failed: %v", err)
	}
	return out
}

func TestStaticHandler_PrecompressedGzipAndPlainFallback(t *testing.T) {
	indexHTML := []byte("<!doctype html><html><head><title>SingCtl</title></head><body>" + strings.Repeat("hello ", 120) + "</body></html>")
	appJS := []byte("export const app = () => console.log('" + strings.Repeat("singctl", 100) + "');")
	styleCSS := []byte("body { background: #111; color: #eee; /* " + strings.Repeat("css", 200) + " */ }")
	logoSVG := []byte(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24">` + strings.Repeat(`<circle cx="12" cy="12" r="10"/>`, 30) + `</svg>`)
	tinyJS := []byte("export const x=1;")
	pngBytes := []byte{0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x01}

	indexGZ := mustGzipBytes(t, indexHTML)
	appJSGZ := mustGzipBytes(t, appJS)
	styleCSSGZ := mustGzipBytes(t, styleCSS)
	logoSVGGZ := mustGzipBytes(t, logoSVG)

	fsys := fstest.MapFS{
		"index.html.gz":       &fstest.MapFile{Data: indexGZ},
		"assets/app.js.gz":    &fstest.MapFile{Data: appJSGZ},
		"assets/style.css.gz": &fstest.MapFile{Data: styleCSSGZ},
		"assets/logo.svg.gz":  &fstest.MapFile{Data: logoSVGGZ},
		"assets/tiny.js":      &fstest.MapFile{Data: tinyJS},
		"icon.png":            &fstest.MapFile{Data: pngBytes},
		"assets/broken.js.gz": &fstest.MapFile{Data: []byte("not-a-valid-gzip-stream")},
	}
	h := webui.NewStaticHandler(fsys)

	t.Run("root_and_assets_gzip_zero_copy", func(t *testing.T) {
		cases := []struct {
			path         string
			acceptEnc    string
			wantCTPrefix string
			wantGZ       []byte
			wantPlain    []byte
			wantImmCache bool
		}{
			{"/", "gzip, deflate, br", "text/html", indexGZ, indexHTML, false},
			{"/index.html", "br, gzip", "text/html", indexGZ, indexHTML, false},
			{"/assets/app.js", "gzip", "javascript", appJSGZ, appJS, true},
			{"/assets/style.css", "gzip;q=1.0, identity;q=0.5", "text/css", styleCSSGZ, styleCSS, true},
			{"/assets/logo.svg", "gzip", "image/svg+xml", logoSVGGZ, logoSVG, true},
		}
		for _, tc := range cases {
			req := httptest.NewRequest(http.MethodGet, tc.path, nil)
			req.Header.Set("Accept-Encoding", tc.acceptEnc)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)

			if rec.Code != http.StatusOK {
				t.Fatalf("GET %s status = %d, want 200", tc.path, rec.Code)
			}
			if got := rec.Header().Get("Content-Encoding"); got != "gzip" {
				t.Fatalf("GET %s Content-Encoding = %q, want gzip", tc.path, got)
			}
			if got := rec.Header().Get("Content-Type"); !strings.Contains(got, tc.wantCTPrefix) {
				t.Fatalf("GET %s Content-Type = %q, want containing %q", tc.path, got, tc.wantCTPrefix)
			}
			if got := rec.Header().Get("Vary"); !strings.Contains(got, "Accept-Encoding") {
				t.Fatalf("GET %s Vary = %q, want Accept-Encoding", tc.path, got)
			}
			if got := rec.Header().Get("Content-Length"); got != strconv.Itoa(len(tc.wantGZ)) {
				t.Fatalf("GET %s Content-Length = %q, want %d", tc.path, got, len(tc.wantGZ))
			}
			if tc.wantImmCache {
				if cc := rec.Header().Get("Cache-Control"); !strings.Contains(cc, "immutable") {
					t.Fatalf("GET %s Cache-Control = %q, want immutable", tc.path, cc)
				}
			}
			if !bytes.Equal(rec.Body.Bytes(), tc.wantGZ) {
				t.Fatalf("GET %s body did not match precompressed .gz bytes", tc.path)
			}
			if !bytes.Equal(gunzipBytes(t, rec.Body.Bytes()), tc.wantPlain) {
				t.Fatalf("GET %s decompressed payload mismatch", tc.path)
			}
		}
	})

	t.Run("non_gzip_clients_receive_transparent_decompressed_plain_text", func(t *testing.T) {
		for _, ae := range []string{"", "identity", "br", "gzip;q=0"} {
			req := httptest.NewRequest(http.MethodGet, "/assets/app.js", nil)
			if ae != "" {
				req.Header.Set("Accept-Encoding", ae)
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)

			if rec.Code != http.StatusOK {
				t.Fatalf("GET /assets/app.js (Accept-Encoding=%q) status = %d, want 200", ae, rec.Code)
			}
			if ce := rec.Header().Get("Content-Encoding"); ce != "" {
				t.Fatalf("Accept-Encoding=%q must not set Content-Encoding, got %q", ae, ce)
			}
			if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "javascript") {
				t.Fatalf("Content-Type = %q, want javascript", ct)
			}
			if got := rec.Header().Get("Vary"); !strings.Contains(got, "Accept-Encoding") {
				t.Fatalf("Vary = %q, want Accept-Encoding", got)
			}
			if got := rec.Header().Get("Content-Length"); got != strconv.Itoa(len(appJS)) {
				t.Fatalf("Content-Length = %q, want %d", got, len(appJS))
			}
			if !bytes.Equal(rec.Body.Bytes(), appJS) {
				t.Fatalf("decompressed body mismatch for Accept-Encoding=%q", ae)
			}
		}

		// Root "/" without gzip header
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK || !bytes.Equal(rec.Body.Bytes(), indexHTML) {
			t.Fatalf("GET / without gzip failed: code=%d bodyLen=%d", rec.Code, rec.Body.Len())
		}
	})

	t.Run("head_requests_return_accurate_headers_without_body", func(t *testing.T) {
		reqGZ := httptest.NewRequest(http.MethodHead, "/assets/style.css", nil)
		reqGZ.Header.Set("Accept-Encoding", "gzip")
		recGZ := httptest.NewRecorder()
		h.ServeHTTP(recGZ, reqGZ)
		if recGZ.Code != http.StatusOK || recGZ.Body.Len() != 0 {
			t.Fatalf("HEAD gzip status=%d bodyLen=%d", recGZ.Code, recGZ.Body.Len())
		}
		if recGZ.Header().Get("Content-Encoding") != "gzip" || recGZ.Header().Get("Content-Length") != strconv.Itoa(len(styleCSSGZ)) {
			t.Fatalf("HEAD gzip headers unexpected: %v", recGZ.Header())
		}

		reqPlain := httptest.NewRequest(http.MethodHead, "/assets/style.css", nil)
		recPlain := httptest.NewRecorder()
		h.ServeHTTP(recPlain, reqPlain)
		if recPlain.Code != http.StatusOK || recPlain.Body.Len() != 0 {
			t.Fatalf("HEAD plain status=%d bodyLen=%d", recPlain.Code, recPlain.Body.Len())
		}
		if recPlain.Header().Get("Content-Encoding") != "" || recPlain.Header().Get("Content-Length") != strconv.Itoa(len(styleCSS)) {
			t.Fatalf("HEAD plain headers unexpected: %v", recPlain.Header())
		}
	})

	t.Run("exact_uncompressed_small_and_binary_files_served_directly", func(t *testing.T) {
		reqTiny := httptest.NewRequest(http.MethodGet, "/assets/tiny.js", nil)
		reqTiny.Header.Set("Accept-Encoding", "gzip")
		recTiny := httptest.NewRecorder()
		h.ServeHTTP(recTiny, reqTiny)
		if recTiny.Code != http.StatusOK || recTiny.Header().Get("Content-Encoding") != "" || !bytes.Equal(recTiny.Body.Bytes(), tinyJS) {
			t.Fatalf("exact small file unexpected: code=%d ce=%q body=%q", recTiny.Code, recTiny.Header().Get("Content-Encoding"), recTiny.Body.String())
		}

		reqPNG := httptest.NewRequest(http.MethodGet, "/icon.png", nil)
		recPNG := httptest.NewRecorder()
		h.ServeHTTP(recPNG, reqPNG)
		if recPNG.Code != http.StatusOK || !strings.Contains(recPNG.Header().Get("Content-Type"), "image/png") || !bytes.Equal(recPNG.Body.Bytes(), pngBytes) {
			t.Fatalf("exact png file unexpected: code=%d ct=%q", recPNG.Code, recPNG.Header().Get("Content-Type"))
		}
	})

	t.Run("path_traversal_not_found_and_method_validation", func(t *testing.T) {
		for _, badPath := range []string{
			"/../etc/passwd",
			"/assets/../../etc/shadow",
			"/%2e%2e/index.html",
			"/assets/missing.js",
			"/assets/",
			`/assets\..\index.html`,
		} {
			req := httptest.NewRequest(http.MethodGet, "http://example.test"+badPath, nil)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != http.StatusNotFound {
				t.Fatalf("bad path %q status = %d, want 404", badPath, rec.Code)
			}
		}

		// Corrupt .gz file on non-gzip client returns 500 instead of broken 200
		reqCorrupt := httptest.NewRequest(http.MethodGet, "/assets/broken.js", nil)
		recCorrupt := httptest.NewRecorder()
		h.ServeHTTP(recCorrupt, reqCorrupt)
		if recCorrupt.Code != http.StatusInternalServerError {
			t.Fatalf("corrupt gz fallback status = %d, want 500", recCorrupt.Code)
		}

		// Non-GET/HEAD rejected with 405
		reqPost := httptest.NewRequest(http.MethodPost, "/assets/app.js", nil)
		recPost := httptest.NewRecorder()
		h.ServeHTTP(recPost, reqPost)
		if recPost.Code != http.StatusMethodNotAllowed {
			t.Fatalf("POST static status = %d, want 405", recPost.Code)
		}
	})

	t.Run("plain_uncompressed_disk_layout_remains_100_percent_compatible", func(t *testing.T) {
		plainFS := fstest.MapFS{
			"index.html":       &fstest.MapFile{Data: indexHTML},
			"assets/client.js": &fstest.MapFile{Data: appJS},
		}
		ph := webui.NewStaticHandler(plainFS)
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Accept-Encoding", "gzip")
		rec := httptest.NewRecorder()
		ph.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK || rec.Header().Get("Content-Encoding") != "" || !bytes.Equal(rec.Body.Bytes(), indexHTML) {
			t.Fatalf("plain FS root failed: code=%d ce=%q", rec.Code, rec.Header().Get("Content-Encoding"))
		}
	})

	t.Run("concurrent_requests_race_free", func(t *testing.T) {
		var wg sync.WaitGroup
		for i := range 16 {
			wg.Go(func() {
				req := httptest.NewRequest(http.MethodGet, "/assets/app.js", nil)
				if i%2 == 0 {
					req.Header.Set("Accept-Encoding", "gzip")
				}
				rec := httptest.NewRecorder()
				h.ServeHTTP(rec, req)
				if rec.Code != http.StatusOK {
					t.Errorf("concurrent status = %d", rec.Code)
				}
			})
		}
		wg.Wait()
	})

	t.Run("embedded_server_root_works_for_both_plain_and_gz_static_builds", func(t *testing.T) {
		srv := webui.New(webui.Options{
			ConfigPath:              t.TempDir() + "/singctl.yaml",
			SkipAdGuardProbeForTest: true,
		})

		// Non-gzip request must always receive valid plain HTML (whether embedded asset is index.html or index.html.gz)
		reqPlain := httptest.NewRequest(http.MethodGet, "/", nil)
		recPlain := httptest.NewRecorder()
		srv.Mux.ServeHTTP(recPlain, reqPlain)
		if recPlain.Code != http.StatusOK {
			t.Fatalf("GET / plain status = %d, want 200", recPlain.Code)
		}
		if recPlain.Header().Get("Content-Encoding") != "" {
			t.Fatalf("GET / plain must not set Content-Encoding, got %q", recPlain.Header().Get("Content-Encoding"))
		}
		if !strings.Contains(strings.ToLower(recPlain.Body.String()), "<html") {
			t.Fatalf("GET / plain missing <html tag")
		}

		// Gzip-capable request must succeed and decode to identical HTML
		reqGZ := httptest.NewRequest(http.MethodGet, "/", nil)
		reqGZ.Header.Set("Accept-Encoding", "gzip")
		recGZ := httptest.NewRecorder()
		srv.Mux.ServeHTTP(recGZ, reqGZ)
		if recGZ.Code != http.StatusOK {
			t.Fatalf("GET / gzip status = %d, want 200", recGZ.Code)
		}
		body := recGZ.Body.Bytes()
		if recGZ.Header().Get("Content-Encoding") == "gzip" {
			body = gunzipBytes(t, body)
		}
		if !bytes.Equal(body, recPlain.Body.Bytes()) {
			t.Fatalf("GET / gzip decoded body differs from plain body")
		}
	})
}

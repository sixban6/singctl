package httpgzip

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

func TestServe_GzipThresholdsAndBypassCases(t *testing.T) {
	t.Run("large JSON >= 1024B compresses with Accept-Encoding gzip", func(t *testing.T) {
		payload := `{"items":[` + strings.Repeat(`"198.51.100.1",`, 120) + `"end"]}`
		req := httptest.NewRequest(http.MethodGet, "/api/data", nil)
		req.Header.Set("Accept-Encoding", "br, gzip, deflate")
		rec := httptest.NewRecorder()

		Serve(rec, req, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.Header().Set("Content-Length", "99999")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(payload))
		})

		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", rec.Code)
		}
		if ce := rec.Header().Get("Content-Encoding"); ce != "gzip" {
			t.Fatalf("expected Content-Encoding: gzip, got %q", ce)
		}
		if vary := rec.Header().Get("Vary"); !strings.Contains(vary, "Accept-Encoding") {
			t.Fatalf("expected Vary to contain Accept-Encoding, got %q", vary)
		}
		if cl := rec.Header().Get("Content-Length"); cl != "" {
			t.Fatalf("expected compressed response to clear stale Content-Length, got %q", cl)
		}
		zr, err := gzip.NewReader(bytes.NewReader(rec.Body.Bytes()))
		if err != nil {
			t.Fatalf("gzip.NewReader failed: %v", err)
		}
		decoded, err := io.ReadAll(zr)
		_ = zr.Close()
		if err != nil {
			t.Fatalf("gunzip failed: %v", err)
		}
		if string(decoded) != payload {
			t.Fatalf("gunzip mismatch: len=%d want=%d", len(decoded), len(payload))
		}
	})

	t.Run("small JSON < 1024B remains uncompressed", func(t *testing.T) {
		payload := `{"ok":true,"msg":"pong"}`
		req := httptest.NewRequest(http.MethodGet, "/api/ping", nil)
		req.Header.Set("Accept-Encoding", "gzip")
		rec := httptest.NewRecorder()

		Serve(rec, req, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(payload))
		})

		if ce := rec.Header().Get("Content-Encoding"); ce != "" {
			t.Fatalf("expected no Content-Encoding for tiny JSON, got %q", ce)
		}
		if rec.Body.String() != payload {
			t.Fatalf("body mismatch: %q", rec.Body.String())
		}
	})

	t.Run("missing Accept-Encoding gzip sends raw", func(t *testing.T) {
		payload := `{"big":"` + strings.Repeat("a", 2048) + `"}`
		req := httptest.NewRequest(http.MethodGet, "/api/data", nil)
		rec := httptest.NewRecorder()

		Serve(rec, req, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(payload))
		})

		if ce := rec.Header().Get("Content-Encoding"); ce != "" {
			t.Fatalf("expected empty Content-Encoding without Accept-Encoding, got %q", ce)
		}
		if rec.Body.String() != payload {
			t.Fatalf("body mismatch: len=%d", rec.Body.Len())
		}
	})

	t.Run("SSE and WebSocket bypass compression and keep Flusher/Hijacker", func(t *testing.T) {
		reqSSE := httptest.NewRequest(http.MethodGet, "/api/stream", nil)
		reqSSE.Header.Set("Accept-Encoding", "gzip")
		recSSE := httptest.NewRecorder()

		var sawFlusher bool
		Serve(recSSE, reqSSE, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/event-stream")
			if f, ok := w.(http.Flusher); ok {
				sawFlusher = true
				f.Flush()
			}
			_, _ = w.Write([]byte("data: " + strings.Repeat("x", 2048) + "\n\n"))
		})
		if !sawFlusher {
			t.Fatal("expected ResponseWriter to preserve http.Flusher")
		}
		if ce := recSSE.Header().Get("Content-Encoding"); ce != "" {
			t.Fatalf("expected SSE to bypass gzip, got %q", ce)
		}

		reqWS := httptest.NewRequest(http.MethodGet, "/ws", nil)
		reqWS.Header.Set("Accept-Encoding", "gzip")
		reqWS.Header.Set("Upgrade", "websocket")
		recHijack := &fakeHijackRecorder{ResponseRecorder: httptest.NewRecorder()}
		var sawHijacker bool
		Serve(recHijack, reqWS, func(w http.ResponseWriter, r *http.Request) {
			if _, ok := w.(http.Hijacker); ok {
				sawHijacker = true
			}
			w.WriteHeader(http.StatusSwitchingProtocols)
		})
		if !sawHijacker {
			t.Fatal("expected ResponseWriter to preserve http.Hijacker for websocket upgrades")
		}
	})

	t.Run("HEAD 204 304 and pre-encoded responses bypass cleanly", func(t *testing.T) {
		for _, code := range []int{http.StatusNoContent, http.StatusNotModified} {
			req := httptest.NewRequest(http.MethodGet, "/api/status", nil)
			req.Header.Set("Accept-Encoding", "gzip")
			rec := httptest.NewRecorder()
			Serve(rec, req, func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(code)
			})
			if rec.Code != code || rec.Header().Get("Content-Encoding") != "" {
				t.Fatalf("code=%d rec.Code=%d ce=%q", code, rec.Code, rec.Header().Get("Content-Encoding"))
			}
		}

		reqHead := httptest.NewRequest(http.MethodHead, "/api/status", nil)
		reqHead.Header.Set("Accept-Encoding", "gzip")
		recHead := httptest.NewRecorder()
		Serve(recHead, reqHead, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
		})
		if recHead.Header().Get("Content-Encoding") != "" {
			t.Fatalf("HEAD request must not set gzip encoding")
		}

		reqPre := httptest.NewRequest(http.MethodGet, "/api/pre", nil)
		reqPre.Header.Set("Accept-Encoding", "gzip")
		recPre := httptest.NewRecorder()
		Serve(recPre, reqPre, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Content-Encoding", "br")
			_, _ = w.Write([]byte(strings.Repeat("b", 2048)))
		})
		if ce := recPre.Header().Get("Content-Encoding"); ce != "br" {
			t.Fatalf("pre-encoded response must stay br, got %q", ce)
		}
	})
}

func TestServe_ConcurrentRace(t *testing.T) {
	payload := `{"data":"` + strings.Repeat("0123456789abcdef", 256) + `"}`
	var wg sync.WaitGroup
	for range 40 {
		wg.Go(func() {
			for range 40 {
				req := httptest.NewRequest(http.MethodGet, "/api/bulk", nil)
				req.Header.Set("Accept-Encoding", "gzip")
				rec := httptest.NewRecorder()
				Serve(rec, req, func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Type", "application/json")
					_, _ = w.Write([]byte(payload))
				})
				if rec.Header().Get("Content-Encoding") != "gzip" {
					t.Errorf("missing gzip header")
					return
				}
				zr, err := gzip.NewReader(bytes.NewReader(rec.Body.Bytes()))
				if err != nil {
					t.Errorf("gzip reader failed: %v", err)
					return
				}
				raw, err := io.ReadAll(zr)
				_ = zr.Close()
				if err != nil || string(raw) != payload {
					t.Errorf("gunzip mismatch err=%v", err)
					return
				}
			}
		})
	}
	wg.Wait()
}

func BenchmarkGzipServe_120KBJSON(b *testing.B) {
	payload := []byte(`{"flows":[` + strings.Repeat(`{"deviceIp":"192.168.100.50","target":"cdn.example.com","bytes":123456},`, 1500) + `{}]}`)
	b.SetBytes(int64(len(payload)))
	b.ReportAllocs()
	for b.Loop() {
		req := httptest.NewRequest(http.MethodGet, "/api/audit", nil)
		req.Header.Set("Accept-Encoding", "gzip")
		rec := httptest.NewRecorder()
		Serve(rec, req, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			_, _ = w.Write(payload)
		})
		if rec.Code != http.StatusOK || rec.Body.Len() == 0 {
			b.Fatal("unexpected benchmark response")
		}
	}
}

type fakeHijackRecorder struct {
	*httptest.ResponseRecorder
}

func (f *fakeHijackRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return nil, nil, nil
}

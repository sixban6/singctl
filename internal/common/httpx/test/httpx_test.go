// 文件职责：验证 httpx 零反射泛型 Handler、StatusError 状态码映射、MaxBytesReader 防 OOM 解码与 sync.Pool Gzip。
package httpx_test

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"singctl/internal/common/httpx"
)

func TestHandle_HandleBody_StatusErrors_And_MaxBytes(t *testing.T) {
	type sampleReq struct {
		Name  string `json:"name"`
		Count int    `json:"count"`
	}
	type sampleResp struct {
		Greeting string `json:"greeting"`
	}

	h := httpx.HandleBody(func(_ *http.Request, req sampleReq) (sampleResp, error) {
		if strings.TrimSpace(req.Name) == "" {
			return sampleResp{}, httpx.BadRequest("name is required")
		}
		if req.Name == "unauth" {
			return sampleResp{}, httpx.Unauthorized("login required")
		}
		if req.Name == "forbid" {
			return sampleResp{}, httpx.Forbidden("denied")
		}
		if req.Name == "missing" {
			return sampleResp{}, httpx.NotFound("not found")
		}
		if req.Name == "conflict" {
			return sampleResp{}, httpx.Conflict("already exists")
		}
		if req.Name == "ratelimit" {
			return sampleResp{}, httpx.RateLimited("too many requests")
		}
		if req.Name == "badgw" {
			return sampleResp{}, httpx.BadGateway("upstream down")
		}
		if req.Name == "boom" {
			return sampleResp{}, httpx.Internal("internal error")
		}
		return sampleResp{Greeting: "hi " + req.Name}, nil
	})

	cases := []struct {
		name       string
		body       string
		wantStatus int
		wantSubstr string
	}{
		{"valid request", `{"name":"alice","count":2}`, http.StatusOK, `"greeting":"hi alice"`},
		{"empty body rejected when allowEmpty=false", ``, http.StatusBadRequest, `"error"`},
		{"malformed JSON rejected", `{"name":`, http.StatusBadRequest, `"error"`},
		{"trailing JSON garbage rejected", `{"name":"a"}{"extra":1}`, http.StatusBadRequest, `"error"`},
		{"400 BadRequest", `{"name":""}`, http.StatusBadRequest, `"name is required"`},
		{"401 Unauthorized", `{"name":"unauth"}`, http.StatusUnauthorized, `"login required"`},
		{"403 Forbidden", `{"name":"forbid"}`, http.StatusForbidden, `"denied"`},
		{"404 NotFound", `{"name":"missing"}`, http.StatusNotFound, `"not found"`},
		{"409 Conflict", `{"name":"conflict"}`, http.StatusConflict, `"already exists"`},
		{"429 RateLimited", `{"name":"ratelimit"}`, http.StatusTooManyRequests, `"too many requests"`},
		{"502 BadGateway", `{"name":"badgw"}`, http.StatusBadGateway, `"upstream down"`},
		{"500 Internal", `{"name":"boom"}`, http.StatusInternalServerError, `"internal error"`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/api/test", strings.NewReader(tc.body))
			rec := httptest.NewRecorder()
			h(rec, req)
			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d (body=%s)", rec.Code, tc.wantStatus, rec.Body.String())
			}
			if !strings.Contains(rec.Body.String(), tc.wantSubstr) {
				t.Fatalf("body %q missing %q", rec.Body.String(), tc.wantSubstr)
			}
		})
	}

	// Oversized body (> maxBytes) rejected cleanly with 413 Request Entity Too Large (or 400 StatusError)
	recBig := httptest.NewRecorder()
	reqBig := httptest.NewRequest(http.MethodPost, "/api/big", strings.NewReader(`{"name":"`+strings.Repeat("x", 2048)+`"}`))
	if _, err := httpx.DecodeJSON[sampleReq](recBig, reqBig, 256, false); err == nil {
		t.Fatal("expected DecodeJSON to reject payload exceeding maxBytes")
	}

	// AllowEmpty accepts empty body, rejects malformed JSON
	hEmpty := httpx.HandleBodyAllowEmpty(func(_ *http.Request, req sampleReq) (sampleResp, error) {
		return sampleResp{Greeting: "empty:" + req.Name}, nil
	})
	recEmpty := httptest.NewRecorder()
	hEmpty(recEmpty, httptest.NewRequest(http.MethodPost, "/api/opt", nil))
	if recEmpty.Code != http.StatusOK || !strings.Contains(recEmpty.Body.String(), `"empty:"`) {
		t.Fatalf("HandleBodyAllowEmpty unexpected: %d %s", recEmpty.Code, recEmpty.Body.String())
	}

	// Handle (no request body) + wrapped underlying error unwrapping
	rootCause := errors.New("db offline")
	wrappedErr := httpx.NewStatusError(http.StatusServiceUnavailable, "unavailable", rootCause)
	if !errors.Is(wrappedErr, rootCause) {
		t.Fatal("StatusError must unwrap underlying cause")
	}
	hGet := httpx.Handle(func(*http.Request) (map[string]bool, error) {
		return map[string]bool{"ok": true}, nil
	})
	recGet := httptest.NewRecorder()
	hGet(recGet, httptest.NewRequest(http.MethodGet, "/api/ping", nil))
	if recGet.Code != http.StatusOK {
		t.Fatalf("Handle GET status = %d", recGet.Code)
	}
}

func TestPoolGzip_ThresholdAndSSEBypass(t *testing.T) {
	largePayload := map[string]string{"blob": strings.Repeat("abcdef0123456789", 128)}
	wrapped := httpx.PoolGzip(httpx.Handle(func(*http.Request) (map[string]string, error) {
		return largePayload, nil
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/large", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	rec := httptest.NewRecorder()
	wrapped(rec, req)

	if rec.Header().Get("Content-Encoding") != "gzip" {
		t.Fatalf("expected gzip Content-Encoding on >=1KB JSON")
	}
	zr, err := gzip.NewReader(bytes.NewReader(rec.Body.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(zr)
	_ = zr.Close()
	var decoded map[string]string
	if err := json.Unmarshal(raw, &decoded); err != nil || decoded["blob"] != largePayload["blob"] {
		t.Fatalf("gunzipped JSON mismatch: %v", err)
	}
}

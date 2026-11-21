package release

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestFetchTag_And_IsNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/sixban6/singctl/releases/tags/tailscale-latest":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(Info{
				TagName: "tailscale-latest",
				Assets: []Asset{
					{
						Name:               "tailscale_1.104.7_amd64.tgz",
						BrowserDownloadURL: "https://example.com/tailscale_1.104.7_amd64.tgz",
						Size:               6500000,
						Digest:             "sha256:" + strings.Repeat("a", 64),
					},
				},
			})
		case "/repos/sixban6/singctl/releases/tags/missing-tag":
			http.NotFound(w, r)
		case "/repos/sixban6/singctl/releases/tags/server-error":
			http.Error(w, "upstream failure", http.StatusInternalServerError)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	client := &Client{
		APIBase:     srv.URL,
		DLBase:      srv.URL,
		HTTP:        srv.Client(),
		DirectFirst: true,
	}

	tests := []struct {
		name        string
		repo        string
		tag         string
		cancelCtx   bool
		wantErr     bool
		wantNotFnd  bool
		wantTag     string
		wantAssetCt int
	}{
		{
			name:        "正常拉取指定通道 tag 元数据",
			repo:        "sixban6/singctl",
			tag:         "tailscale-latest",
			wantTag:     "tailscale-latest",
			wantAssetCt: 1,
		},
		{
			name:    "空仓库名应拒绝请求",
			repo:    "   ",
			tag:     "tailscale-latest",
			wantErr: true,
		},
		{
			name:    "空 tag 应拒绝请求",
			repo:    "sixban6/singctl",
			tag:     "",
			wantErr: true,
		},
		{
			name:       "404 返回 StatusError 且 IsNotFound 为 true",
			repo:       "sixban6/singctl",
			tag:        "missing-tag",
			wantErr:    true,
			wantNotFnd: true,
		},
		{
			name:       "500 返回错误但 IsNotFound 为 false",
			repo:       "sixban6/singctl",
			tag:        "server-error",
			wantErr:    true,
			wantNotFnd: false,
		},
		{
			name:       "上下文已取消应返回错误且非 404",
			repo:       "sixban6/singctl",
			tag:        "tailscale-latest",
			cancelCtx:  true,
			wantErr:    true,
			wantNotFnd: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx := t.Context()
			if tc.cancelCtx {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}

			info, err := client.FetchTag(ctx, tc.repo, tc.tag)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil (info=%+v)", info)
				}
				if IsNotFound(err) != tc.wantNotFnd {
					t.Fatalf("IsNotFound(%v) = %v, want %v", err, IsNotFound(err), tc.wantNotFnd)
				}
				if tc.wantNotFnd {
					var se *StatusError
					if !errors.As(err, &se) || se.StatusCode != http.StatusNotFound {
						t.Fatalf("expected *StatusError with 404, got %T (%v)", err, err)
					}
					if !strings.Contains(err.Error(), "github api returned status: 404") {
						t.Fatalf("expected backward-compatible status error string, got %q", err.Error())
					}
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if info.TagName != tc.wantTag || len(info.Assets) != tc.wantAssetCt {
				t.Fatalf("got info=%+v, want tag=%q assets=%d", info, tc.wantTag, tc.wantAssetCt)
			}
		})
	}

	if IsNotFound(nil) {
		t.Fatalf("IsNotFound(nil) must be false")
	}
	if IsNotFound(errors.New("plain error")) {
		t.Fatalf("IsNotFound(plain error) must be false")
	}
}

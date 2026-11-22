// 文件职责：提供浏览器安全 DNS（DoH）旁路检测薄 HTTP 壳，核心领域逻辑委托 internal/netdiag/dohprobe。
package webui

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"singctl/internal/daemon"
	"singctl/internal/netdiag"
	"singctl/internal/netdiag/dohprobe"
	"singctl/internal/singbox/clashapi"
	"singctl/internal/tailscale"
)

// BrowserDoHClashConn 兼容别名（底层指向 dohprobe.ClashConn）。
type BrowserDoHClashConn = dohprobe.ClashConn

// BrowserDoHCheckResponse 兼容别名（底层指向 dohprobe.CheckResponse）。
type BrowserDoHCheckResponse = dohprobe.CheckResponse

// BrowserDoHTestHooks 仅供离线单元测试注入浏览器安全 DNS 检测依赖。
type BrowserDoHTestHooks struct {
	ClientIP          string
	PeerIPsForMAC     func(clientIP string) []string
	ClashConnections  func(ctx context.Context) ([]BrowserDoHClashConn, error)
	GatewayEDNSProber func(ctx context.Context) (*netdiag.DNSResolverProfile, error)
	SingBoxRunning    func() bool
}

func newBrowserDoHProber(hooks *BrowserDoHTestHooks, clashCli *clashapi.Client) *dohprobe.Prober {
	if hooks != nil {
		deps := dohprobe.Deps{
			ClientIP: hooks.ClientIP,
			PeerIPsForMAC: func(_ context.Context, clientIP string) []string {
				if hooks.PeerIPsForMAC != nil {
					return hooks.PeerIPsForMAC(clientIP)
				}
				return nil
			},
			ClashConnections: func(ctx context.Context) ([]dohprobe.ClashConn, error) {
				if hooks.ClashConnections != nil {
					return hooks.ClashConnections(ctx)
				}
				return nil, nil
			},
			GatewayEDNSProber: func(ctx context.Context) (*netdiag.DNSResolverProfile, error) {
				if hooks.GatewayEDNSProber != nil {
					return hooks.GatewayEDNSProber(ctx)
				}
				return nil, nil
			},
			SingBoxRunning: hooks.SingBoxRunning,
		}
		return dohprobe.NewProber(deps)
	}
	return dohprobe.NewProber(dohprobe.Deps{
		SingBoxRunning: daemon.IsSingBoxRunning,
		ClashClient:    clashCli,
	})
}

func (s *Server) handleBrowserDoHCheckPost(w http.ResponseWriter, r *http.Request) {
	var body dohprobe.CheckRequest
	if r.Body != nil {
		dec := json.NewDecoder(io.LimitReader(r.Body, 16*1024))
		if err := dec.Decode(&body); err != nil && !errors.Is(err, io.EOF) {
			writeJSONError(w, http.StatusBadRequest, "无效的浏览器 DoH 检测请求参数: "+err.Error())
			return
		}
	}

	prober := s.dohProber
	if prober == nil {
		prober = newBrowserDoHProber(s.opts.BrowserDoHForTest, s.clashClient())
	}
	clientIP := prober.ResolveClientIP(r)
	viaTS := tailscale.IsTailscaleAddr(clientIP)
	if !viaTS && s.opts.BrowserDoHForTest == nil {
		viaTS = tailscale.IsTailscaleRequest(r)
	}

	resp := prober.Check(r.Context(), clientIP, viaTS, body)
	writeJSON(w, http.StatusOK, resp)
}

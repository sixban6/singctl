// 文件职责：提供客户端 WebUI 多链路 DNS 泄漏实测与综合判定接口。
package webui

import (
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"singctl/internal/adguard"
	"singctl/internal/daemon"
	"singctl/internal/gateway"
	"singctl/internal/netdiag"
)

func (s *Server) handleDNSLeakTestPost(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Mode   string `json:"mode"`
		Rounds int    `json:"rounds"`
	}
	if r.Body != nil {
		dec := json.NewDecoder(io.LimitReader(r.Body, 4096))
		if err := dec.Decode(&body); err != nil && !errors.Is(err, io.EOF) {
			writeJSONError(w, http.StatusBadRequest, "无效的体检请求参数: "+err.Error())
			return
		}
	}

	gatewayRounds := 8
	if body.Rounds > 0 {
		gatewayRounds = min(max(body.Rounds, 1), 20)
	} else if strings.EqualFold(strings.TrimSpace(body.Mode), "deep") {
		gatewayRounds = 16
	}

	cfg := s.readConfigOrEmpty()

	topo := s.probeGatewayTopology()
	ipv6Mode := cfg.Gateway.EffectiveIPv6Mode()
	gwMode := cfg.Gateway.EffectiveMode()

	dnsAddr := net.JoinHostPort("127.0.0.1", strconv.Itoa(cfg.DNS.GetDNSPort()))
	aghHealthy := adguard.ProbeDNSWithRetry(dnsAddr, 800*time.Millisecond, 2, 150*time.Millisecond) == nil
	sbRunning := daemon.IsSingBoxRunning()

	var ipv6Status gateway.IPv6StatusInfo
	if s.opts.GatewayProberForTest == nil {
		ipv6Status = gateway.ProbeIPv6Status(r.Context(), cfg.Gateway, topo)
	}

	opts := netdiag.DNSLeakTestOptions{
		IPv6Mode:       ipv6Mode,
		GatewayMode:    gwMode,
		SingBoxRunning: sbRunning,
		AdGuardHealthy: aghHealthy,
		IPv6Status:     ipv6Status,
		GatewayRounds:  gatewayRounds,
	}

	var report *netdiag.DNSLeakReport
	if s.opts.DNSLeakRunnerForTest != nil {
		report = s.opts.DNSLeakRunnerForTest(r.Context(), opts)
	} else {
		report = netdiag.RunDNSLeakTest(r.Context(), opts)
	}

	writeJSON(w, http.StatusOK, report)
}

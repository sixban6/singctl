// 文件职责：覆盖商业 PCDN/MCDN 域名识别精度、跨网段 UDP 蜂群标注及内置防 PCDN 规则集启停幂等测试。
package audit_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"singctl/configs"
	"singctl/internal/audit"
	"singctl/internal/config"
	"singctl/internal/singbox"
)

func TestMatchPCDNDomain_PrecisionAndNoFalsePositives(t *testing.T) {
	eng := audit.NewNonlinearEngine(&config.Config{})

	for _, benign := range []string{"ipcdn.apple.com", "pcdn.brave.com", "static1.dmcdn.net"} {
		f := &audit.FlowRecord{
			DeviceIP:      "192.168.1.50",
			Target:        benign,
			DestPort:      443,
			Network:       "tcp",
			UploadBytes:   30 * 1024,
			DownloadBytes: 6 * 1024 * 1024,
		}
		eng.EvaluateFlow(f)
		if f.PCDNKind != "" || f.RiskScore >= 20 {
			t.Fatalf("expected %s zero false-positive PCDN classification, got pcdnKind=%q score=%d reasons=%v",
				benign, f.PCDNKind, f.RiskScore, f.Reasons)
		}
	}

	dlFlow := &audit.FlowRecord{
		DeviceIP:      "192.168.1.51",
		Target:        "xy115x238x200x208xy.mcdn.bilivideo.cn",
		DestPort:      8000,
		Network:       "tcp",
		UploadBytes:   400 * 1024,
		DownloadBytes: 300 * 1024 * 1024,
	}
	eng.EvaluateFlow(dlFlow)
	if dlFlow.PCDNKind != "download" {
		t.Fatalf("expected mcdn download stream pcdnKind=download, got %q (reasons=%v)", dlFlow.PCDNKind, dlFlow.Reasons)
	}
	if dlFlow.State != audit.EnforcementBlocked {
		t.Fatalf("expected builtin PCDN block to mark mcdn.bilivideo.cn blocked by default, got state=%s", dlFlow.State)
	}

	offCfg := &config.Config{}
	offCfg.Audit.SetPCDNBlock(false)
	engOff := audit.NewNonlinearEngine(offCfg)

	upFlow := &audit.FlowRecord{
		DeviceIP:      "192.168.1.52",
		Target:        "node99.xycdn.com",
		DestPort:      8800,
		Network:       "udp",
		UploadBytes:   12 * 1024 * 1024,
		DownloadBytes: 256 * 1024,
	}
	engOff.EvaluateFlow(upFlow)
	if upFlow.PCDNKind != "upload" || upFlow.RiskScore < 75 {
		t.Fatalf("expected xycdn upload flow pcdnKind=upload & high score, got kind=%q score=%d factors=%v",
			upFlow.PCDNKind, upFlow.RiskScore, upFlow.NonlinearFactors)
	}

	mijiaUDP := &audit.FlowRecord{
		DeviceIP:      "192.168.1.53",
		Target:        "203.0.113.10",
		IsDirectIP:    true,
		DestPort:      8053,
		Network:       "udp",
		UploadBytes:   2 * 1024 * 1024,
		DownloadBytes: 2 * 1024 * 1024,
	}
	engOff.EvaluateFlow(mijiaUDP)
	for _, r := range mijiaUDP.Reasons {
		if strings.Contains(r, "疑似PCDN") {
			t.Fatalf("expected udp:8053 MiIO flow not to get 疑似PCDN label, reasons=%v", mijiaUDP.Reasons)
		}
	}
	if mijiaUDP.RiskScore >= 60 {
		t.Fatalf("expected light udp:8053 MiIO flow score < 60, got %d (%v)", mijiaUDP.RiskScore, mijiaUDP.Reasons)
	}
}

func TestAnnotatePCDNSwarmBehaviors(t *testing.T) {
	eng := audit.NewNonlinearEngine(&config.Config{})

	var flows []audit.FlowRecord
	for i := 1; i <= 10; i++ {
		flows = append(flows, audit.FlowRecord{
			Key:           fmt.Sprintf("swarm-%d", i),
			DeviceIP:      "192.168.1.60",
			Target:        fmt.Sprintf("198.%d.10.20", i),
			IsDirectIP:    true,
			Network:       "udp",
			DestPort:      22000 + i,
			UploadBytes:   900 * 1024,
			DownloadBytes: 120 * 1024,
		})
	}
	knownPorts := []int{8053, 8053, 32100, 32100, 3478, 3478, 5010, 5010}
	for i, p := range knownPorts {
		flows = append(flows, audit.FlowRecord{
			Key:           fmt.Sprintf("legit-%d", i),
			DeviceIP:      "192.168.1.61",
			Target:        fmt.Sprintf("203.%d.1.5", i+1),
			IsDirectIP:    true,
			Network:       "udp",
			DestPort:      p,
			UploadBytes:   900 * 1024,
			DownloadBytes: 100 * 1024,
		})
	}

	eng.AnnotatePCDNSwarmBehaviors(flows)
	for i := range 10 {
		eng.EvaluateFlow(&flows[i])
		if flows[i].PCDNSwarm == nil || !flows[i].PCDNSwarm.Suspicious || flows[i].PCDNKind != "swarm" {
			t.Fatalf("swarm flow[%d] expected PCDNSwarm suspicious & pcdnKind=swarm, got %+v kind=%q",
				i, flows[i].PCDNSwarm, flows[i].PCDNKind)
		}
		if flows[i].NonlinearFactors["pcdn_swarm"] <= 0 {
			t.Fatalf("swarm flow[%d] expected positive pcdn_swarm factor, got %+v", i, flows[i].NonlinearFactors)
		}
	}
	for i := 10; i < len(flows); i++ {
		eng.EvaluateFlow(&flows[i])
		if flows[i].PCDNSwarm != nil || flows[i].PCDNKind == "swarm" {
			t.Fatalf("legit port flow[%d] (port=%d) falsely flagged as swarm: %+v", i, flows[i].DestPort, flows[i].PCDNSwarm)
		}
	}
}

func TestEnforcer_SetPCDNBlock_Unblock_And_EnsureDefaultIdempotent(t *testing.T) {
	var mu sync.Mutex
	var killedIDs []string
	clashSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/connections":
			_, _ = w.Write([]byte(`{"connections":[{"id":"conn-bili-mcdn","metadata":{"network":"tcp","sourceIP":"192.168.1.90","destinationIP":"203.0.113.50","destinationPort":"8000","host":"xy1.mcdn.bilivideo.cn"}},{"id":"conn-normal","metadata":{"network":"tcp","sourceIP":"192.168.1.90","destinationIP":"203.0.113.51","destinationPort":"443","host":"example.com"}}]}`))
		case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/connections/"):
			mu.Lock()
			killedIDs = append(killedIDs, strings.TrimPrefix(r.URL.Path, "/connections/"))
			mu.Unlock()
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer clashSrv.Close()

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "singctl.yaml")
	if err := os.WriteFile(cfgPath, configs.ClientConfigYAML, 0600); err != nil {
		t.Fatal(err)
	}
	sbPath := filepath.Join(dir, "config.json")
	initialSB := `{"dns":{"servers":[{"tag":"dns_local","type":"udp","server":"127.0.0.1"}],"rules":[{"clash_mode":"Direct","server":"dns_local"}]},"route":{"rules":[{"action":"sniff"},{"ip_is_private":true,"outbound":"#DC"}]}}`
	if err := os.WriteFile(sbPath, []byte(initialSB), 0600); err != nil {
		t.Fatal(err)
	}

	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	enf := audit.NewEnforcer(cfg, cfgPath)
	enf.SetPathsForTest(sbPath, filepath.Join(dir, "agh.yaml"), []string{clashSrv.URL}, "")

	applied, err := enf.EnsureDefaultPCDNBlock(t.Context())
	if err != nil || !applied {
		t.Fatalf("expected EnsureDefaultPCDNBlock first run (true, nil), got (%v, %v)", applied, err)
	}
	applied2, err := enf.EnsureDefaultPCDNBlock(t.Context())
	if err != nil || applied2 {
		t.Fatalf("expected EnsureDefaultPCDNBlock second run idempotent (false, nil), got (%v, %v)", applied2, err)
	}
	mu.Lock()
	gotKilled := append([]string(nil), killedIDs...)
	mu.Unlock()
	if len(gotKilled) != 1 || gotKilled[0] != "conn-bili-mcdn" {
		t.Fatalf("expected only conn-bili-mcdn killed, got %v", gotKilled)
	}

	unRes, err := enf.Unblock(t.Context(), singbox.BuiltinPCDNRuleSetTarget, "")
	if err != nil || !unRes.ConfigSaved || !unRes.SingBoxSynced {
		t.Fatalf("Unblock builtin PCDN failed: %+v, err=%v", unRes, err)
	}
	reloaded, err := config.Load(cfgPath)
	if err != nil || reloaded.Audit.IsPCDNBlockEnabled() {
		t.Fatalf("expected persisted pcdn_block=false after Unblock, got %v (err=%v)", reloaded.Audit.PCDNBlock, err)
	}
	sbAfterOff, _ := os.ReadFile(sbPath)
	if strings.Contains(string(sbAfterOff), singbox.BuiltinPCDNRuleSetTag) {
		t.Fatalf("expected %s removed after Unblock, got:\n%s", singbox.BuiltinPCDNRuleSetTag, string(sbAfterOff))
	}

	onRes, err := enf.SetPCDNBlock(t.Context(), true)
	if err != nil || !onRes.ConfigSaved || !onRes.SingBoxSynced {
		t.Fatalf("SetPCDNBlock(true) failed: %+v, err=%v", onRes, err)
	}
	reloadedOn, err := config.Load(cfgPath)
	if err != nil || !reloadedOn.Audit.IsPCDNBlockEnabled() {
		t.Fatalf("expected persisted PCDNBlockEnabled=true after re-enable, err=%v", err)
	}
}

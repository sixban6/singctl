// 文件职责：守卫 sing-box 目标大版本单一数据源（.upstream-version == constant.SingBoxTargetMajor），
// 并提供全场景真实配置编译矩阵与外部 sing-box check / 弃用告警自动化兼容门禁。
package test

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"text/template"
	"time"

	"singctl/internal/config"
	"singctl/internal/constant"
	"singctl/internal/deploy"
	"singctl/internal/singbox"
)

type compatScenarioReport struct {
	Name       string   `json:"name"`
	Scope      string   `json:"scope"`
	Passed     bool     `json:"passed"`
	Deprecated bool     `json:"deprecated"`
	Warnings   []string `json:"warnings,omitempty"`
	Error      string   `json:"error,omitempty"`
}

type compatMatrixReport struct {
	TargetMajor   string                 `json:"targetMajor"`
	SingBoxBin    string                 `json:"singboxBin,omitempty"`
	SingBoxVer    string                 `json:"singboxVersion,omitempty"`
	Scope         string                 `json:"scope"`
	StrictDeprec  bool                   `json:"strictDeprecation"`
	AllPassed     bool                   `json:"allPassed"`
	HasDeprecated bool                   `json:"hasDeprecated"`
	Scenarios     []compatScenarioReport `json:"scenarios"`
}

func TestSingBoxTargetVersionSingleSourceOfTruth(t *testing.T) {
	root := repoRootDir(t)

	rawUpstream, err := os.ReadFile(filepath.Join(root, ".upstream-version"))
	if err != nil {
		t.Fatalf("read .upstream-version: %v", err)
	}
	fileMajor := strings.TrimSpace(string(rawUpstream))
	if fileMajor != constant.SingBoxTargetMajor {
		t.Fatalf(".upstream-version (%q) != constant.SingBoxTargetMajor (%q)", fileMajor, constant.SingBoxTargetMajor)
	}
	if constant.SingBoxTargetTemplateVersion != "v"+fileMajor {
		t.Fatalf("constant.SingBoxTargetTemplateVersion (%q) != %q", constant.SingBoxTargetTemplateVersion, "v"+fileMajor)
	}

	// AST guard: ensure production singbox config compilation files reference
	// constant.SingBoxTargetTemplateVersion instead of scattering hardcoded string literals.
	fset := token.NewFileSet()
	for _, rel := range []string{
		"internal/singbox/generator.go",
		"internal/singbox/compile_pipeline.go",
		"internal/singbox/ios_adapter.go",
	} {
		fullPath := filepath.Join(root, rel)
		parsed, parseErr := parser.ParseFile(fset, fullPath, nil, 0)
		if parseErr != nil {
			t.Fatalf("parse %s: %v", rel, parseErr)
		}
		ast.Inspect(parsed, func(n ast.Node) bool {
			lit, ok := n.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			val, err := strconv.Unquote(lit.Value)
			if err == nil && (val == constant.SingBoxTargetTemplateVersion || val == constant.SingBoxTargetMajor) {
				pos := fset.Position(lit.Pos())
				t.Errorf("%s:%d contains hardcoded %q string literal; must use constant.SingBoxTargetTemplateVersion", rel, pos.Line, val)
			}
			return true
		})
	}
}

func newMockSubscriptionServer(t *testing.T) *httptest.Server {
	t.Helper()
	// RFC 5737 mock proxy nodes covering VLESS Reality, Hysteria2, Trojan, and Shadowsocks.
	lines := []string{
		"vless://11111111-1111-1111-1111-111111111111@198.51.100.10:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=node.example.com&fp=chrome&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&sid=0123456789abcdef&type=tcp#JP-Reality-01",
		"hysteria2://smoke-test-hy2-pass@198.51.100.11:8443?sni=node.example.com#HK-Hy2-01",
		"trojan://smoke-test-trojan-pass@198.51.100.12:443?security=tls&sni=node.example.com#SG-Trojan-01",
		"ss://" + base64.StdEncoding.EncodeToString([]byte("aes-256-gcm:smoke-test-ss-pass")) + "@198.51.100.13:8388#US-SS-01",
	}
	encoded := base64.StdEncoding.EncodeToString([]byte(strings.Join(lines, "\n")))
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte(encoded))
	}))
}

func writeEphemeralSelfSignedCert(t *testing.T, dir string) (certPath, keyPath string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatalf("mkdir cert dir: %v", err)
	}
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ecdsa key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "node.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"node.example.com"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	keyBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	certPath = filepath.Join(dir, "server.crt")
	keyPath = filepath.Join(dir, "server.key")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes}), 0600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}

func renderRealServerConfig(t *testing.T, dir string, warpCfg config.WarpRoutingConfig) string {
	t.Helper()
	tmplData, err := deploy.TemplateFiles.ReadFile("templates/server_config.json")
	if err != nil {
		t.Fatalf("read server_config.json template: %v", err)
	}
	tmpl, err := template.New("server_compat").Parse(string(tmplData))
	if err != nil {
		t.Fatalf("parse server template: %v", err)
	}
	certPath, keyPath := writeEphemeralSelfSignedCert(t, dir)
	maskDir := filepath.Join(dir, "mask-site")
	if err := os.MkdirAll(maskDir, 0755); err != nil {
		t.Fatal(err)
	}
	ephemeralKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	err = tmpl.Execute(&buf, map[string]any{
		"HyUUID":                 "11111111-1111-1111-1111-111111111111",
		"SBDomain":               "node.example.com",
		"CertPath":               certPath,
		"KeyPath":                keyPath,
		"RealityPrivateKey":      base64.RawURLEncoding.EncodeToString(ephemeralKey.Bytes()),
		"RealityShortID":         "0123456789abcdef",
		"Sni":                    "www.apple.com",
		"RealityHandshakeServer": "www.apple.com",
		"RealityHandshakePort":   443,
		"TelemetrySecret":        "compat-test-secret-0123456789",
	})
	if err != nil {
		t.Fatalf("execute server template: %v", err)
	}

	raw := buf.Bytes()
	if !warpCfg.IsEmpty() {
		raw, err = deploy.ApplyWarpRoutingToServerConfigJSON(raw, warpCfg)
		if err != nil {
			t.Fatalf("ApplyWarpRoutingToServerConfigJSON failed: %v", err)
		}
	}
	// Redirect host-bound paths to t.TempDir() so sing-box check never touches /etc or /var.
	var obj map[string]any
	if err := json.Unmarshal(raw, &obj); err != nil {
		t.Fatalf("unmarshal rendered server config: %v", err)
	}
	if exp, ok := obj["experimental"].(map[string]any); ok {
		if cf, ok := exp["cache_file"].(map[string]any); ok {
			cf["path"] = filepath.Join(dir, "server-cache.db")
		}
	}
	if inbounds, ok := obj["inbounds"].([]any); ok {
		for _, item := range inbounds {
			if m, ok := item.(map[string]any); ok {
				if _, hasMasq := m["masquerade"]; hasMasq {
					m["masquerade"] = "file://" + maskDir
				}
			}
		}
	}
	patched, err := json.MarshalIndent(obj, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return string(patched)
}

func sanitizeConfigPathsForCheck(t *testing.T, rawJSON, dir, name string) string {
	t.Helper()
	var obj map[string]any
	if err := json.Unmarshal([]byte(rawJSON), &obj); err != nil {
		t.Fatalf("scenario %s generated invalid JSON: %v", name, err)
	}
	if exp, ok := obj["experimental"].(map[string]any); ok {
		if cf, ok := exp["cache_file"].(map[string]any); ok {
			if _, hasPath := cf["path"]; hasPath {
				cf["path"] = filepath.Join(dir, name+"-cache.db")
			}
		}
	}
	patched, err := json.MarshalIndent(obj, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return string(patched)
}

func scanDeprecationWarnings(output string) []string {
	var warnings []string
	for line := range strings.SplitSeq(output, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if strings.Contains(strings.ToLower(trimmed), "deprecated") {
			warnings = append(warnings, trimmed)
		}
	}
	return warnings
}

func matchesCompatScope(filter, scenarioScope string) bool {
	switch strings.ToLower(strings.TrimSpace(filter)) {
	case "", "all":
		return true
	case "client":
		return scenarioScope == "client_linux" || scenarioScope == "client_ios"
	default:
		return strings.EqualFold(strings.TrimSpace(filter), scenarioScope)
	}
}

func runSingBoxCheckBin(t *testing.T, binPath, cfgPath string) (string, error) {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), binPath, "check", "-c", cfgPath)
	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

func TestSingBoxRealConfigMatrixCompat(t *testing.T) {
	subSrv := newMockSubscriptionServer(t)
	defer subSrv.Close()

	workDir := t.TempDir()
	scope := strings.ToLower(strings.TrimSpace(os.Getenv("SINGBOX_CHECK_SCOPE")))
	if scope == "" {
		scope = "all"
	}
	checkBin := strings.TrimSpace(os.Getenv("SINGBOX_CHECK_BIN"))
	strictDeprecation := os.Getenv("SINGBOX_CHECK_STRICT_DEPRECATION") == "1"
	reportPath := strings.TrimSpace(os.Getenv("SINGBOX_COMPAT_REPORT_PATH"))

	type scenario struct {
		name  string
		scope string
		build func(t *testing.T) string
	}

	subSingle := []config.Subscription{{Name: "main", URL: subSrv.URL + "/main"}}
	subMulti := []config.Subscription{
		{Name: "main", URL: subSrv.URL + "/main"},
		{Name: "backup", URL: subSrv.URL + "/backup"},
	}

	buildClient := func(cfg *config.Config, platform string, localDNSReady bool) string {
		g := singbox.NewOfflineConfigGenerator(cfg)
		g.SetCacheDir("")
		g.SetLocalDNSProbe(func(string, int) bool { return localDNSReady })
		out, err := g.GenerateForPlatform(platform)
		if err != nil {
			t.Fatalf("GenerateForPlatform(%s) failed: %v", platform, err)
		}
		return out
	}

	scenarios := []scenario{
		{
			name:  "client_linux_main_ipv4_smartdns",
			scope: "client_linux",
			build: func(t *testing.T) string {
				cfg := &config.Config{
					Subs:    subSingle,
					Hy2:     config.Hy2Config{Up: 50, Down: 200},
					DNS:     config.ClientDNSConfig{Engine: constant.DNSEngineSmartDNS, DNSPort: 5353},
					Gateway: config.GatewayConfig{Mode: "main", IPv6Mode: config.GatewayIPv6Off},
					CustomRules: config.CustomRulesConfig{
						Block: []config.BlockRule{{Target: "ads.example.com", Reason: "compat-test"}},
					},
					TrafficRouting: config.TrafficRoutingConfig{
						Presets: map[string]config.TrafficRuleOverride{
							"openai": {Enabled: new(true), Outbound: "Proxy"},
						},
					},
				}
				return buildClient(cfg, "linux", true)
			},
		},
		{
			name:  "client_linux_main_ipv6_cn_only_adguard_multi_sub",
			scope: "client_linux",
			build: func(t *testing.T) string {
				cfg := &config.Config{
					Subs:    subMulti,
					Hy2:     config.Hy2Config{Up: 50, Down: 200},
					DNS:     config.ClientDNSConfig{Engine: constant.DNSEngineAdGuard, DNSPort: 5353},
					Gateway: config.GatewayConfig{Mode: "main", IPv6Mode: config.GatewayIPv6CNOnly},
				}
				return buildClient(cfg, "linux", true)
			},
		},
		{
			name:  "client_linux_main_ipv6_full_doh_fallback",
			scope: "client_linux",
			build: func(t *testing.T) string {
				cfg := &config.Config{
					Subs:    subSingle,
					Hy2:     config.Hy2Config{Up: 50, Down: 200},
					Gateway: config.GatewayConfig{Mode: "main", IPv6Mode: config.GatewayIPv6Full},
				}
				return buildClient(cfg, "linux", false)
			},
		},
		{
			name:  "client_linux_side_router",
			scope: "client_linux",
			build: func(t *testing.T) string {
				cfg := &config.Config{
					Subs:    subSingle,
					Hy2:     config.Hy2Config{Up: 50, Down: 200},
					Gateway: config.GatewayConfig{Mode: "side", MainRouterIP: "192.168.1.1"},
				}
				return buildClient(cfg, "linux", false)
			},
		},
		{
			name:  "client_linux_low_memory_lite",
			scope: "client_linux",
			build: func(t *testing.T) string {
				cfg := &config.Config{
					LowMemory: config.LowMemoryOn,
					Subs:      subSingle,
					Hy2:       config.Hy2Config{Up: 30, Down: 100},
					DNS:       config.ClientDNSConfig{Engine: constant.DNSEngineSmartDNS, DNSPort: 5353},
					Gateway:   config.GatewayConfig{Mode: "main", IPv6Mode: config.GatewayIPv6Off},
				}
				return buildClient(cfg, "linux", true)
			},
		},
		{
			name:  "client_ios_sfi",
			scope: "client_ios",
			build: func(t *testing.T) string {
				cfg := &config.Config{
					Subs:   subSingle,
					GitHub: config.GitHubConfig{MirrorURL: "https://gh-proxy.com"},
					Hy2:    config.Hy2Config{Up: 50, Down: 200},
				}
				out := buildClient(cfg, singbox.PlatformIOS, false)
				if err := singbox.CheckIOSCompatibility(out); err != nil {
					t.Fatalf("CheckIOSCompatibility failed: %v", err)
				}
				return out
			},
		},
		{
			name:  "server_hy2_vless_warp_split",
			scope: "server",
			build: func(t *testing.T) string {
				return renderRealServerConfig(t, filepath.Join(workDir, "srv-split"), config.WarpRoutingConfig{
					Mode:          "split",
					Presets:       map[string]bool{"openai": true, "reddit": true},
					WarpDomains:   []string{"ai.example.com"},
					DirectDomains: []string{"direct.example.com"},
				})
			},
		},
		{
			name:  "server_hy2_vless_warp_global",
			scope: "server",
			build: func(t *testing.T) string {
				return renderRealServerConfig(t, filepath.Join(workDir, "srv-global"), config.WarpRoutingConfig{
					Mode: "global_warp",
				})
			},
		},
	}

	report := compatMatrixReport{
		TargetMajor:  constant.SingBoxTargetMajor,
		SingBoxBin:   checkBin,
		Scope:        scope,
		StrictDeprec: strictDeprecation,
		AllPassed:    true,
	}
	if checkBin != "" {
		if verOut, err := exec.CommandContext(t.Context(), checkBin, "version").CombinedOutput(); err == nil {
			report.SingBoxVer = strings.TrimSpace(strings.Split(string(verOut), "\n")[0])
		}
	}

	for _, sc := range scenarios {
		if !matchesCompatScope(scope, sc.scope) {
			continue
		}
		scDir := filepath.Join(workDir, sc.name)
		if err := os.MkdirAll(scDir, 0755); err != nil {
			t.Fatal(err)
		}

		res := compatScenarioReport{
			Name:   sc.name,
			Scope:  sc.scope,
			Passed: true,
		}
		t.Run(sc.name, func(t *testing.T) {
			raw := sc.build(t)
			sanitized := sanitizeConfigPathsForCheck(t, raw, scDir, sc.name)
			cfgFile := filepath.Join(scDir, "config.json")
			if err := os.WriteFile(cfgFile, []byte(sanitized), 0600); err != nil {
				t.Fatal(err)
			}

			if checkBin == "" {
				return
			}
			out, checkErr := runSingBoxCheckBin(t, checkBin, cfgFile)
			warnings := scanDeprecationWarnings(out)
			res.Warnings = warnings
			res.Deprecated = len(warnings) > 0
			if checkErr != nil {
				res.Passed = false
				res.Error = fmt.Sprintf("%v: %s", checkErr, out)
				report.AllPassed = false
				t.Errorf("sing-box check failed for %s:\n%s", sc.name, res.Error)
				return
			}
			if res.Deprecated {
				report.HasDeprecated = true
				if strictDeprecation {
					res.Passed = false
					res.Error = "deprecation warnings detected:\n" + strings.Join(warnings, "\n")
					report.AllPassed = false
					t.Errorf("sing-box deprecation warning for %s:\n%s", sc.name, res.Error)
				}
			}
		})
		report.Scenarios = append(report.Scenarios, res)
	}

	if reportPath != "" {
		rawReport, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			t.Fatalf("marshal compat report: %v", err)
		}
		if err := os.WriteFile(reportPath, rawReport, 0600); err != nil {
			t.Fatalf("write compat report %s: %v", reportPath, err)
		}
	}
}

func TestScanDeprecationWarnings_Boundaries(t *testing.T) {
	cases := []struct {
		name   string
		output string
		want   int
	}{
		{name: "clean_empty", output: "", want: 0},
		{name: "clean_info_logs", output: "INFO[0000] check passed\n", want: 0},
		{name: "single_deprecation", output: "WARN[0000] legacy field is deprecated in sing-box 1.15.0\n", want: 1},
		{name: "mixed_case_multiple", output: "line1\nDEPRECATED: foo\nwarn: bar is deprecated\n", want: 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := len(scanDeprecationWarnings(tc.output)); got != tc.want {
				t.Fatalf("scanDeprecationWarnings(%q) = %d, want %d", tc.output, got, tc.want)
			}
		})
	}

	scopeCases := []struct {
		filter   string
		scenario string
		want     bool
	}{
		{filter: "", scenario: "client_linux", want: true},
		{filter: "all", scenario: "server", want: true},
		{filter: "client", scenario: "client_linux", want: true},
		{filter: "client", scenario: "client_ios", want: true},
		{filter: "client", scenario: "server", want: false},
		{filter: "client_linux", scenario: "client_linux", want: true},
		{filter: "client_linux", scenario: "client_ios", want: false},
		{filter: "server", scenario: "server", want: true},
		{filter: "server", scenario: "client_linux", want: false},
	}
	for _, sc := range scopeCases {
		if got := matchesCompatScope(sc.filter, sc.scenario); got != sc.want {
			t.Fatalf("matchesCompatScope(%q, %q) = %v, want %v", sc.filter, sc.scenario, got, sc.want)
		}
	}
}

// 文件职责：验证全局契约常量定义及全仓无重复硬编码仓库坐标/默认回环监听端点。
package constant_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"singctl/internal/constant"
)

func TestSharedConstants_ContractsAndPaths(t *testing.T) {
	if constant.GitHubRepo != "sixban6/singctl" {
		t.Fatalf("GitHubRepo = %q, want %q", constant.GitHubRepo, "sixban6/singctl")
	}
	if constant.GitHubRepoURL != "https://github.com/sixban6/singctl" {
		t.Fatalf("GitHubRepoURL = %q, want %q", constant.GitHubRepoURL, "https://github.com/sixban6/singctl")
	}
	if constant.RuleSetsReleaseTag != "rulesets-latest" {
		t.Fatalf("RuleSetsReleaseTag = %q, want %q", constant.RuleSetsReleaseTag, "rulesets-latest")
	}
	if wantBase := "https://github.com/sixban6/singctl/releases/download/rulesets-latest"; constant.RuleSetReleaseBaseURL != wantBase {
		t.Fatalf("RuleSetReleaseBaseURL = %q, want %q", constant.RuleSetReleaseBaseURL, wantBase)
	}
	if constant.SingBoxConfigFile == "" || constant.AdGuardConfigFile == "" || constant.CaddyMtlsCACert == "" {
		t.Fatalf("expected non-empty platform paths on %s: singbox=%q adguard=%q ca=%q",
			runtime.GOOS, constant.SingBoxConfigFile, constant.AdGuardConfigFile, constant.CaddyMtlsCACert)
	}
}

func TestDNSEngineAndSmartDNSConstants(t *testing.T) {
	cases := []struct {
		name string
		got  string
		want string
	}{
		{"DNSEngineAuto", constant.DNSEngineAuto, "auto"},
		{"DNSEngineAdGuard", constant.DNSEngineAdGuard, "adguard"},
		{"DNSEngineSmartDNS", constant.DNSEngineSmartDNS, "smartdns"},
		{"SmartDNSInstallPath", constant.SmartDNSInstallPath, "/usr/bin/smartdns"},
		{"SmartDNSConfigDir", constant.SmartDNSConfigDir, "/etc/singctl"},
		{"SmartDNSConfigFile", constant.SmartDNSConfigFile, "/etc/singctl/smartdns.conf"},
		{"SmartDNSRulesDir", constant.SmartDNSRulesDir, "/etc/singctl/smartdns-rules.d"},
		{"SmartDNSAuditLogPath", constant.SmartDNSAuditLogPath, "/tmp/singctl-smartdns-audit.log"},
		{"SmartDNSServiceName", constant.SmartDNSServiceName, "singctl-smartdns"},
	}
	for _, tc := range cases {
		if tc.got != tc.want {
			t.Errorf("%s = %q, want %q", tc.name, tc.got, tc.want)
		}
	}
}

func TestSafeCommitConstants(t *testing.T) {
	strCases := []struct {
		name string
		got  string
		want string
	}{
		{"SafeCommitDir", constant.SafeCommitDir, "/tmp/singctl-safecommit"},
		{"SafeCommitStateFile", constant.SafeCommitStateFile, "/tmp/singctl-safecommit/state.json"},
		{"SafeCommitLastRollbackFile", constant.SafeCommitLastRollbackFile, "/tmp/singctl-safecommit/last_rollback.json"},
		{"SafeCommitWatchLogFile", constant.SafeCommitWatchLogFile, "/tmp/singctl-safecommit/watch.log"},
	}
	for _, tc := range strCases {
		if tc.got != tc.want {
			t.Errorf("%s = %q, want %q", tc.name, tc.got, tc.want)
		}
	}

	if constant.SafeCommitDefaultTTLSec != 180 {
		t.Errorf("SafeCommitDefaultTTLSec = %d, want 180", constant.SafeCommitDefaultTTLSec)
	}
	if constant.SafeCommitMinTTLSec != 60 {
		t.Errorf("SafeCommitMinTTLSec = %d, want 60", constant.SafeCommitMinTTLSec)
	}
	if constant.SafeCommitMaxTTLSec != 600 {
		t.Errorf("SafeCommitMaxTTLSec = %d, want 600", constant.SafeCommitMaxTTLSec)
	}
	if !(constant.SafeCommitMinTTLSec < constant.SafeCommitDefaultTTLSec && constant.SafeCommitDefaultTTLSec < constant.SafeCommitMaxTTLSec) {
		t.Errorf("invalid SafeCommit TTL ordering: min=%d default=%d max=%d",
			constant.SafeCommitMinTTLSec, constant.SafeCommitDefaultTTLSec, constant.SafeCommitMaxTTLSec)
	}
}

func TestNoDuplicateSharedContractLiterals(t *testing.T) {
	repoRoot, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatalf("resolve repo root: %v", err)
	}

	forbiddenLiterals := map[string]string{
		"sixban6/singctl":                    "internal/constant/default.go",
		"https://github.com/sixban6/singctl": "internal/constant/default.go",
		"127.0.0.1:3001":                     "internal/subhub/server.go",
		"http://127.0.0.1:3001/":             "internal/subhub/server.go",
		"http://127.0.0.1:3001/healthz":      "internal/subhub/server.go",
		"127.0.0.1:8092":                     "internal/serverweb/background.go",
		"127.0.0.1:9099":                     "internal/telemetry/telemetry.go",
	}

	fset := token.NewFileSet()
	scanDirs := []string{
		filepath.Join(repoRoot, "cmd"),
		filepath.Join(repoRoot, "internal"),
	}

	for _, root := range scanDirs {
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if d.IsDir() {
				if d.Name() == "static" {
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}

			rel, err := filepath.Rel(repoRoot, path)
			if err != nil {
				return err
			}
			rel = filepath.ToSlash(rel)

			fileAST, err := parser.ParseFile(fset, path, nil, 0)
			if err != nil {
				return err
			}

			ast.Inspect(fileAST, func(n ast.Node) bool {
				lit, ok := n.(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					return true
				}
				val, err := strconv.Unquote(lit.Value)
				if err != nil {
					return true
				}
				if allowedRel, forbidden := forbiddenLiterals[val]; forbidden && rel != allowedRel {
					pos := fset.Position(lit.Pos())
					t.Errorf("%s:%d: duplicate shared contract literal %q; use constant defined in %s",
						rel, pos.Line, val, allowedRel)
				}
				return true
			})
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", root, err)
		}
	}
}

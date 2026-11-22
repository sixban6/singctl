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
	if constant.SingBoxConfigFile == "" || constant.AdGuardConfigFile == "" || constant.CaddyMtlsCACert == "" {
		t.Fatalf("expected non-empty platform paths on %s: singbox=%q adguard=%q ca=%q",
			runtime.GOOS, constant.SingBoxConfigFile, constant.AdGuardConfigFile, constant.CaddyMtlsCACert)
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

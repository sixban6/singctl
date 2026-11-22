package test

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

const (
	maxProductionGoFileLines = 1000
	maxFrontendFileLines     = 1000
)

func repoRootDir(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs("..")
	if err != nil {
		t.Fatalf("resolve repo root: %v", err)
	}
	return root
}

func collectProductionGoFiles(t *testing.T, root string) []string {
	t.Helper()
	var files []string
	for _, sub := range []string{"cmd", "internal"} {
		base := filepath.Join(root, sub)
		if err := filepath.WalkDir(base, func(path string, d fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if d.IsDir() {
				if strings.HasPrefix(d.Name(), ".") {
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(d.Name(), ".go") || strings.HasSuffix(d.Name(), "_test.go") {
				return nil
			}
			rel, err := filepath.Rel(root, path)
			if err != nil {
				return err
			}
			files = append(files, filepath.ToSlash(rel))
			return nil
		}); err != nil {
			t.Fatalf("walk %s: %v", base, err)
		}
	}
	return files
}

func collectFrontendSourceFiles(t *testing.T, root string) []string {
	t.Helper()
	base := filepath.Join(root, "web", "src")
	var files []string
	if err := filepath.WalkDir(base, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			if strings.HasPrefix(d.Name(), ".") || d.Name() == "node_modules" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(d.Name(), ".ts") && !strings.HasSuffix(d.Name(), ".tsx") {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		files = append(files, filepath.ToSlash(rel))
		return nil
	}); err != nil {
		t.Fatalf("walk %s: %v", base, err)
	}
	return files
}

func findDuplicateLiteralViolations(relPath string, fset *token.FileSet, file *ast.File, owners map[string]string) []string {
	var violations []string
	ast.Inspect(file, func(n ast.Node) bool {
		lit, ok := n.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return true
		}
		val, err := strconv.Unquote(lit.Value)
		if err != nil {
			return true
		}
		if canonicalOwner, guarded := owners[val]; guarded && relPath != canonicalOwner {
			pos := fset.Position(lit.Pos())
			violations = append(violations, fmt.Sprintf("%s:%d embeds %q (must reuse constant owned by %s)", relPath, pos.Line, val, canonicalOwner))
		}
		return true
	})
	return violations
}

func callExprTargetName(fun ast.Expr) string {
	switch x := fun.(type) {
	case *ast.Ident:
		return x.Name
	case *ast.SelectorExpr:
		return x.Sel.Name
	default:
		return ""
	}
}

func findRawSystemctlViolations(relPath string, fset *token.FileSet, file *ast.File, allowlist map[string]bool) []string {
	if allowlist[relPath] {
		return nil
	}
	var violations []string
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		fnName := callExprTargetName(call.Fun)
		// Allow binary-existence probing (`exec.LookPath("systemctl")`, `hasBinary("systemctl")`).
		if fnName == "LookPath" || fnName == "hasBinary" {
			return true
		}
		for _, arg := range call.Args {
			lit, ok := arg.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				continue
			}
			val, err := strconv.Unquote(lit.Value)
			if err == nil && val == "systemctl" {
				pos := fset.Position(call.Pos())
				violations = append(violations, fmt.Sprintf("%s:%d calls %s(\"systemctl\", ...) outside servicemgr/allowlist", relPath, pos.Line, fnName))
			}
		}
		return true
	})
	return violations
}

func findDirectConfigIOViolations(relPath string, fset *token.FileSet, file *ast.File, guardedPrefixes []string, allowlist map[string]bool) []string {
	if allowlist[relPath] {
		return nil
	}
	guarded := false
	for _, prefix := range guardedPrefixes {
		if strings.HasPrefix(relPath, prefix) {
			guarded = true
			break
		}
	}
	if !guarded {
		return nil
	}

	var violations []string
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		pkgIdent, ok := sel.X.(*ast.Ident)
		if !ok || pkgIdent.Name != "config" {
			return true
		}
		if sel.Sel.Name == "Load" || sel.Sel.Name == "Save" {
			pos := fset.Position(call.Pos())
			violations = append(violations, fmt.Sprintf("%s:%d calls config.%s directly on hot-path server package (must route via config.Store snapshot/save helpers)", relPath, pos.Line, sel.Sel.Name))
		}
		return true
	})
	return violations
}

func findOversizedFileViolations(relPath string, src []byte, maxLines int, exempt map[string]bool) string {
	if exempt[relPath] {
		return ""
	}
	lineCount := strings.Count(string(src), "\n")
	if len(src) > 0 && src[len(src)-1] != '\n' {
		lineCount++
	}
	if lineCount > maxLines {
		return fmt.Sprintf("%s has %d lines (exceeds limit %d)", relPath, lineCount, maxLines)
	}
	return ""
}

func findLayerCycleViolations(relPath string, file *ast.File, contractPrefixes []string, forbiddenImports map[string]bool) []string {
	isContractPkg := false
	for _, prefix := range contractPrefixes {
		if strings.HasPrefix(relPath, prefix) {
			isContractPkg = true
			break
		}
	}
	if !isContractPkg {
		return nil
	}
	var violations []string
	for _, imp := range file.Imports {
		pkgPath, err := strconv.Unquote(imp.Path.Value)
		if err != nil {
			continue
		}
		if forbiddenImports[pkgPath] {
			violations = append(violations, fmt.Sprintf("%s imports forbidden upper-layer package %q", relPath, pkgPath))
		}
	}
	return violations
}

// TestArchGuard_NoDuplicateSharedLiterals 防止跨包重复硬编码仓库名及本机服务回环地址。
func TestArchGuard_NoDuplicateSharedLiterals(t *testing.T) {
	root := repoRootDir(t)
	owners := map[string]string{
		"sixban6/singctl": "internal/constant/default.go",
		"127.0.0.1:9099":  "internal/telemetry/telemetry.go",
		"127.0.0.1:3001":  "internal/subhub/server.go",
		"127.0.0.1:8092":  "internal/serverweb/background.go",
	}

	var violations []string
	fset := token.NewFileSet()
	for _, relPath := range collectProductionGoFiles(t, root) {
		file, err := parser.ParseFile(fset, filepath.Join(root, filepath.FromSlash(relPath)), nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", relPath, err)
		}
		violations = append(violations, findDuplicateLiteralViolations(relPath, fset, file, owners)...)
	}
	if len(violations) > 0 {
		t.Fatalf("duplicate shared literals detected:\n%s", strings.Join(violations, "\n"))
	}
}

// TestArchGuard_SystemctlIsolatedToPlatformAllowlist 防止绕过 servicemgr 直接扩散裸 exec.Command("systemctl", ...)。
func TestArchGuard_SystemctlIsolatedToPlatformAllowlist(t *testing.T) {
	root := repoRootDir(t)
	allowlist := map[string]bool{
		"internal/platform/servicemgr/systemd.go":         true,
		"internal/platform/servicemgr/systemd_inspect.go": true,
	}

	var violations []string
	fset := token.NewFileSet()
	for _, relPath := range collectProductionGoFiles(t, root) {
		file, err := parser.ParseFile(fset, filepath.Join(root, filepath.FromSlash(relPath)), nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", relPath, err)
		}
		violations = append(violations, findRawSystemctlViolations(relPath, fset, file, allowlist)...)
	}
	if len(violations) > 0 {
		t.Fatalf("unauthorized raw systemctl calls detected:\n%s", strings.Join(violations, "\n"))
	}
}

// TestArchGuard_HotPathServersUseConfigStore 防止长驻 HTTP 服务 handler 绕过 config.Store 直接裸调 config.Load / config.Save。
func TestArchGuard_HotPathServersUseConfigStore(t *testing.T) {
	root := repoRootDir(t)
	guardedPrefixes := []string{
		"internal/subhub/",
		"internal/webui/",
		"internal/serverweb/",
	}
	// 仅放行各服务自身的 Store 桥接层与独立 CLI 辅助入口。
	allowlist := map[string]bool{
		"internal/webui/webui.go":              true,
		"internal/webui/api.go":                true,
		"internal/serverweb/serverweb.go":      true,
		"internal/serverweb/background.go":     true,
		"internal/serverweb/warp_local_cli.go": true,
	}

	var violations []string
	fset := token.NewFileSet()
	for _, relPath := range collectProductionGoFiles(t, root) {
		file, err := parser.ParseFile(fset, filepath.Join(root, filepath.FromSlash(relPath)), nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", relPath, err)
		}
		violations = append(violations, findDirectConfigIOViolations(relPath, fset, file, guardedPrefixes, allowlist)...)
	}
	if len(violations) > 0 {
		t.Fatalf("direct config.Load/config.Save calls in hot-path servers detected:\n%s", strings.Join(violations, "\n"))
	}
}

// TestArchGuard_MaxProductionFileLines 强制非静态模板生产代码单文件不超过 1,000 行。
func TestArchGuard_MaxProductionFileLines(t *testing.T) {
	root := repoRootDir(t)
	exempt := map[string]bool{
		"internal/deploy/masksite/generator.go": true,
	}

	var violations []string
	for _, relPath := range collectProductionGoFiles(t, root) {
		src, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(relPath)))
		if err != nil {
			t.Fatalf("read %s: %v", relPath, err)
		}
		if v := findOversizedFileViolations(relPath, src, maxProductionGoFileLines, exempt); v != "" {
			violations = append(violations, v)
		}
	}
	if len(violations) > 0 {
		t.Fatalf("oversized production files detected:\n%s", strings.Join(violations, "\n"))
	}
}

// TestArchGuard_MaxFrontendFileLines 强制前端 TypeScript/React 源码单文件不超过 1,000 行。
func TestArchGuard_MaxFrontendFileLines(t *testing.T) {
	root := repoRootDir(t)
	var violations []string
	for _, relPath := range collectFrontendSourceFiles(t, root) {
		src, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(relPath)))
		if err != nil {
			t.Fatalf("read %s: %v", relPath, err)
		}
		if v := findOversizedFileViolations(relPath, src, maxFrontendFileLines, nil); v != "" {
			violations = append(violations, v)
		}
	}
	if len(violations) > 0 {
		t.Fatalf("oversized frontend files detected:\n%s", strings.Join(violations, "\n"))
	}
}

// TestArchGuard_CoreContractPackagesAcyclic 防止基础契约层反向依赖上层业务实现产生循环依赖。
func TestArchGuard_CoreContractPackagesAcyclic(t *testing.T) {
	root := repoRootDir(t)
	contractPrefixes := []string{
		"internal/constant/",
		"internal/component/",
		"internal/lifecycle/",
		"internal/platform/servicemgr/",
	}
	forbiddenImports := map[string]bool{
		"singctl/internal/cmd":       true,
		"singctl/internal/webui":     true,
		"singctl/internal/serverweb": true,
		"singctl/internal/daemon":    true,
		"singctl/internal/deploy":    true,
		"singctl/internal/singbox":   true,
		"singctl/internal/fleet":     true,
		"singctl/internal/audit":     true,
		"singctl/internal/subhub":    true,
		"singctl/internal/adguard":   true,
		"singctl/internal/firewall":  true,
		"singctl/internal/tailscale": true,
		"singctl/internal/netdiag":   true,
		"singctl/internal/heal":      true,
		"singctl/internal/doctor":    true,
		"singctl/internal/gfw":       true,
		"singctl/internal/terminal":  true,
		"singctl/internal/telemetry": true,
	}

	var violations []string
	fset := token.NewFileSet()
	for _, relPath := range collectProductionGoFiles(t, root) {
		file, err := parser.ParseFile(fset, filepath.Join(root, filepath.FromSlash(relPath)), nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("parse %s: %v", relPath, err)
		}
		violations = append(violations, findLayerCycleViolations(relPath, file, contractPrefixes, forbiddenImports)...)
	}
	if len(violations) > 0 {
		t.Fatalf("architecture layer dependency violations detected:\n%s", strings.Join(violations, "\n"))
	}
}

// TestArchGuard_SyntheticViolationDetectors 验证 AST 规则检测器对违规样本可准确命中（防止测试空转）。
func TestArchGuard_SyntheticViolationDetectors(t *testing.T) {
	src := `package bad
import (
	"os/exec"
	"singctl/internal/config"
	"singctl/internal/webui"
)
func oops() {
	_ = "sixban6/singctl"
	_ = exec.Command("systemctl", "restart", "caddy")
	_ = exec.LookPath("systemctl")
	_, _ = config.Load("/tmp/singctl.yaml")
	_ = config.Save("/tmp/singctl.yaml", nil)
	_ = webui.SessionCookieName
}
`
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "bad.go", src, 0)
	if err != nil {
		t.Fatal(err)
	}

	dup := findDuplicateLiteralViolations("internal/bad/bad.go", fset, file, map[string]string{"sixban6/singctl": "internal/constant/default.go"})
	if len(dup) != 1 {
		t.Fatalf("expected 1 duplicate literal violation, got %v", dup)
	}

	sys := findRawSystemctlViolations("internal/bad/bad.go", fset, file, map[string]bool{})
	if len(sys) != 1 {
		t.Fatalf("expected 1 raw systemctl violation (and LookPath allowed), got %v", sys)
	}

	cfgViolations := findDirectConfigIOViolations("internal/webui/bad_api.go", fset, file, []string{"internal/webui/"}, map[string]bool{})
	if len(cfgViolations) != 2 {
		t.Fatalf("expected 2 direct config.Load/Save violations, got %v", cfgViolations)
	}

	oversized := findOversizedFileViolations("internal/bad/bad.go", []byte(strings.Repeat("line\n", 1001)), maxProductionGoFileLines, map[string]bool{})
	if oversized == "" {
		t.Fatal("expected oversized violation for 1001-line snippet")
	}

	cycles := findLayerCycleViolations(
		"internal/component/bad.go",
		file,
		[]string{"internal/component/"},
		map[string]bool{"singctl/internal/webui": true},
	)
	if len(cycles) != 1 {
		t.Fatalf("expected 1 layer cycle violation, got %v", cycles)
	}
}

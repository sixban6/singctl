// 文件职责：提供双后端单事务防火墙原子执行器（AtomicNFT 同批 add+flush+建表无空窗提交、iptables-restore --noflush 批量提交与表幂等删除）。
package fwtx

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"regexp"
	"slices"
	"strings"
)

// Runner 抽象带标准输入的防火墙命令执行契约，便于单测注入零宿主机污染替身。
type Runner interface {
	RunStdin(ctx context.Context, stdin, name string, args ...string) ([]byte, error)
}

// ExecRunner 是基于标准库 os/exec 的默认防火墙命令执行器。
type ExecRunner struct{}

// RunStdin 通过 stdin 向目标命令投喂批处理脚本并返回合并输出。
func (ExecRunner) RunStdin(ctx context.Context, stdin, name string, args ...string) ([]byte, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	cmd := exec.CommandContext(ctx, name, args...)
	if stdin != "" {
		cmd.Stdin = bytes.NewBufferString(stdin)
	}
	return cmd.CombinedOutput()
}

var (
	validNFTFamilies = []string{"inet", "ip", "ip6", "arp", "bridge", "netdev"}
	validTableNameRe = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
)

func effectiveRunner(r Runner) Runner {
	if r != nil {
		return r
	}
	return ExecRunner{}
}

func validateFamilyAndTable(family, tableName string) error {
	f := strings.TrimSpace(family)
	if !slices.Contains(validNFTFamilies, f) {
		return fmt.Errorf("fwtx: unsupported nftables family %q", family)
	}
	if !validTableNameRe.MatchString(tableName) {
		return fmt.Errorf("fwtx: invalid nftables table name %q", tableName)
	}
	return nil
}

// WrapAtomicNFTTable 将声明式 `table <family> <name> { ... }` 脚本幂等包装为单批次无空窗事务：
//
//	add table <family> <name>
//	flush table <family> <name>
//	table <family> <name> { ... }
//
// 确保单次 `nft -f` 提交在同一内核 NFNL_MSG_BATCH 内完成建表、清旧与重载，切换空窗严格为 0ms。
func WrapAtomicNFTTable(family, tableName, tableDecl string) (string, error) {
	if err := validateFamilyAndTable(family, tableName); err != nil {
		return "", err
	}
	trimmed := strings.TrimSpace(tableDecl)
	if trimmed == "" {
		return "", fmt.Errorf("fwtx: nftables table declaration is empty")
	}
	tableToken := "table " + family + " " + tableName
	if !strings.Contains(trimmed, tableToken) {
		return "", fmt.Errorf("fwtx: declaration missing %q", tableToken)
	}

	addLine := "add " + tableToken
	flushLine := "flush " + tableToken

	var preservedShebang string
	var bodyLines []string
	for line := range strings.SplitSeq(strings.ReplaceAll(tableDecl, "\r\n", "\n"), "\n") {
		trimLine := strings.TrimSpace(line)
		if preservedShebang == "" && len(bodyLines) == 0 && strings.HasPrefix(trimLine, "#!") {
			preservedShebang = trimLine
			continue
		}
		if trimLine == addLine || trimLine == flushLine {
			continue
		}
		bodyLines = append(bodyLines, line)
	}

	var b strings.Builder
	if preservedShebang != "" {
		b.WriteString(preservedShebang)
		b.WriteByte('\n')
	}
	b.WriteString(addLine)
	b.WriteByte('\n')
	b.WriteString(flushLine)
	b.WriteByte('\n')
	body := strings.TrimLeft(strings.Join(bodyLines, "\n"), "\n")
	b.WriteString(body)
	if !strings.HasSuffix(body, "\n") {
		b.WriteByte('\n')
	}
	return b.String(), nil
}

// ApplyAtomicNFT 通过标准输入向 `nft` 提交单流原子事务；checkFirst=true 时先执行 `nft -c -f -` 干跑校验。
func ApplyAtomicNFT(ctx context.Context, runner Runner, script string, checkFirst bool) error {
	if strings.TrimSpace(script) == "" {
		return fmt.Errorf("fwtx: empty nftables batch script")
	}
	r := effectiveRunner(runner)
	if checkFirst {
		if out, err := r.RunStdin(ctx, script, "nft", "-c", "-f", "-"); err != nil {
			return fmt.Errorf("nftables dry-run check failed: %w (%s)", err, strings.TrimSpace(string(out)))
		}
	}
	if out, err := r.RunStdin(ctx, script, "nft", "-f", "-"); err != nil {
		return fmt.Errorf("nftables atomic apply failed: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// DeleteNFTTableIdempotent 幂等删除指定 nftables 表（表不存在时静默返回 nil）。
func DeleteNFTTableIdempotent(ctx context.Context, runner Runner, family, tableName string) error {
	if err := validateFamilyAndTable(family, tableName); err != nil {
		return err
	}
	r := effectiveRunner(runner)
	out, err := r.RunStdin(ctx, "", "nft", "delete", "table", family, tableName)
	if err == nil {
		return nil
	}
	msg := strings.ToLower(strings.TrimSpace(string(out)) + " " + err.Error())
	if strings.Contains(msg, "no such file or directory") || strings.Contains(msg, "does not exist") {
		return nil
	}
	return fmt.Errorf("nftables delete table %s %s failed: %w (%s)", family, tableName, err, strings.TrimSpace(string(out)))
}

// ApplyIPTablesRestoreNoFlush 通过 `iptables-restore --noflush` / `ip6tables-restore --noflush` 单次事务提交隔离链规则。
func ApplyIPTablesRestoreNoFlush(ctx context.Context, runner Runner, ipv6 bool, batch string, testFirst bool) error {
	if strings.TrimSpace(batch) == "" {
		return fmt.Errorf("fwtx: empty iptables-restore batch")
	}
	hasCommit := false
	for line := range strings.SplitSeq(batch, "\n") {
		if strings.TrimSpace(line) == "COMMIT" {
			hasCommit = true
			break
		}
	}
	if !hasCommit {
		return fmt.Errorf("fwtx: iptables-restore batch missing COMMIT line")
	}

	bin := "iptables-restore"
	if ipv6 {
		bin = "ip6tables-restore"
	}
	r := effectiveRunner(runner)
	if testFirst {
		if out, err := r.RunStdin(ctx, batch, bin, "--noflush", "--test"); err != nil {
			return fmt.Errorf("%s syntax test failed: %w (%s)", bin, err, strings.TrimSpace(string(out)))
		}
	}

	out, err := r.RunStdin(ctx, batch, bin, "--noflush", "-w", "5")
	if err == nil {
		return nil
	}
	lowerOut := strings.ToLower(string(out))
	if strings.Contains(lowerOut, "unrecognized option") || strings.Contains(lowerOut, "unknown option") || strings.Contains(lowerOut, "invalid option") {
		if fbOut, fbErr := r.RunStdin(ctx, batch, bin, "--noflush"); fbErr == nil {
			return nil
		} else {
			return fmt.Errorf("%s --noflush failed: %w (%s)", bin, fbErr, strings.TrimSpace(string(fbOut)))
		}
	}
	return fmt.Errorf("%s --noflush -w 5 failed: %w (%s)", bin, err, strings.TrimSpace(string(out)))
}

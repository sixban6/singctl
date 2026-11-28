// 文件职责：实现 QUIC/UDP Socket 缓冲区与 BBR/FQ 的安全校验、冲突清理、持久化落盘、内核应用与写后回读校验。
package socktune

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

type resolvedTarget struct {
	rmemMax     int
	wmemMax     int
	rmemDefault int
	wmemDefault int
	wantBBR     bool
}

// Apply 校验参数、按需加载内核模块、清理冲突 sysctl 键、持久化并写后回读校验内核生效状态。
func Apply(ctx context.Context, profile Profile, req ApplyRequest, env Env) (*ApplyResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	profile = normalizeProfile(profile)
	if profile != ProfileClient && profile != ProfileServer {
		return nil, fmt.Errorf("%w: 不支持的角色 %q", ErrInvalidRequest, profile)
	}

	cur := Inspect(profile, env)
	if !cur.Supported {
		return nil, ErrUnsupported
	}

	target, err := resolveApplyTarget(profile, req, cur)
	if err != nil {
		return nil, err
	}

	var warnings []string

	// 按需加载内核拥塞控制与队列模块；不可用时不阻断缓冲区优化
	targetQdisc := cur.RecommendedQdisc
	bbrOK := false
	if target.wantBBR {
		bbrOK = ensureBBRModule(ctx, env)
		if !bbrOK {
			warnings = append(warnings, "当前内核未提供 tcp_bbr 模块，已跳过 BBR 仅应用 UDP 缓冲区优化")
		}
	}

	if targetQdisc == "fq" {
		if err := runOptionalModprobe(ctx, env, "sch_fq"); err != nil && cur.DefaultQdisc == "fq_codel" && profile == ProfileClient {
			// OpenWrt 部分精简内核仅内置 fq_codel，回退保留以避免 sysctl -p 报错
			targetQdisc = "fq_codel"
			warnings = append(warnings, "当前内核缺少 sch_fq 模块，已保留内置 fq_codel 队列调度")
		}
	}

	sysctlContent, sysctlPairs := renderSysctlFile(profile, target, targetQdisc, bbrOK)
	targetKeys := make([]string, 0, len(sysctlPairs))
	for _, kv := range sysctlPairs {
		targetKeys = append(targetKeys, kv.key)
	}

	// 在写入新配置前清理可能先加载或后加载覆盖的旧配置键值（如 99-custom.conf 中遗留的超大默认缓冲）
	for _, conflictPath := range env.conflictSysctlFiles() {
		if conflictPath == "" || conflictPath == env.quicSysctlFile() {
			continue
		}
		if err := stripConflictSysctlKeys(env, conflictPath, targetKeys); err != nil {
			warnings = append(warnings, fmt.Sprintf("清理旧配置 %s 冲突键警告: %v", conflictPath, err))
		}
	}

	if err := env.writeFile(env.quicSysctlFile(), []byte(sysctlContent), 0644); err != nil {
		return nil, fmt.Errorf("写入 %s 失败: %w", env.quicSysctlFile(), err)
	}

	if err := applySysctlToKernel(ctx, env, env.quicSysctlFile(), sysctlPairs); err != nil {
		return nil, err
	}

	if err := verifyKernelReadback(env, target); err != nil {
		return nil, err
	}

	// OpenWrt /etc/modules.d 持久化加载 tcp_bbr / sch_fq，防止重启后模块未加载导致 sysctl 失效
	persistOpenWrtModules(env, bbrOK, targetQdisc == "fq")

	after := Inspect(profile, env)
	actions := buildApplyActions(cur, after, bbrOK, targetQdisc)
	defaultChanged := cur.RmemDefault != after.RmemDefault || cur.WmemDefault != after.WmemDefault
	anyBufferChanged := defaultChanged || cur.RmemMax != after.RmemMax || cur.WmemMax != after.WmemMax

	return &ApplyResult{
		OK:                   true,
		Actions:              actions,
		Warnings:             warnings,
		DefaultBufferChanged: defaultChanged,
		RestartRecommended:   anyBufferChanged,
		Status:               after,
	}, nil
}

func resolveApplyTarget(profile Profile, req ApplyRequest, cur Status) (resolvedTarget, error) {
	preset := strings.ToLower(strings.TrimSpace(req.DefaultPreset))
	presetBytes := 0
	switch preset {
	case "", "auto":
	case "2m":
		if profile != ProfileServer {
			return resolvedTarget{}, fmt.Errorf("%w: 客户端模式不支持 defaultPreset=%q", ErrInvalidRequest, req.DefaultPreset)
		}
		presetBytes = 2 * mb
	case "4m":
		if profile != ProfileServer {
			return resolvedTarget{}, fmt.Errorf("%w: 客户端模式不支持 defaultPreset=%q", ErrInvalidRequest, req.DefaultPreset)
		}
		presetBytes = 4 * mb
	case "8m":
		if profile != ProfileServer {
			return resolvedTarget{}, fmt.Errorf("%w: 客户端模式不支持 defaultPreset=%q", ErrInvalidRequest, req.DefaultPreset)
		}
		presetBytes = 8 * mb
	default:
		return resolvedTarget{}, fmt.Errorf("%w: 不支持的 defaultPreset %q（仅允许 auto / 2m / 4m / 8m）", ErrInvalidRequest, req.DefaultPreset)
	}

	t := resolvedTarget{
		rmemMax:     cur.RecommendedRmemMax,
		wmemMax:     cur.RecommendedWmemMax,
		rmemDefault: cur.RecommendedRmemDefault,
		wmemDefault: cur.RecommendedWmemDefault,
		wantBBR:     true,
	}
	if req.EnableBBR != nil {
		t.wantBBR = *req.EnableBBR
	}
	if presetBytes > 0 {
		t.rmemDefault = presetBytes
		t.wmemDefault = presetBytes
	}
	if req.RmemMax != 0 {
		t.rmemMax = req.RmemMax
	}
	if req.WmemMax != 0 {
		t.wmemMax = req.WmemMax
	}
	if req.RmemDefault != 0 {
		t.rmemDefault = req.RmemDefault
	}
	if req.WmemDefault != 0 {
		t.wmemDefault = req.WmemDefault
	}

	if err := validateBufferBounds(profile, t); err != nil {
		return resolvedTarget{}, err
	}
	return t, nil
}

func validateBufferBounds(profile Profile, t resolvedTarget) error {
	for _, pair := range []struct {
		name string
		val  int
	}{
		{"rmemMax", t.rmemMax},
		{"wmemMax", t.wmemMax},
	} {
		if pair.val < minBufferBytes || pair.val > maxAllowedBufferBytes {
			return fmt.Errorf("%w: %s 必须在 %d~%d 之间", ErrInvalidRequest, pair.name, minBufferBytes, maxAllowedBufferBytes)
		}
	}

	maxDef := maxClientDefaultBytes
	if profile == ProfileServer {
		maxDef = maxServerDefaultBytes
	}
	for _, pair := range []struct {
		name string
		val  int
	}{
		{"rmemDefault", t.rmemDefault},
		{"wmemDefault", t.wmemDefault},
	} {
		if pair.val < minBufferBytes || pair.val > maxDef {
			return fmt.Errorf("%w: %s 必须在 %d~%d 之间", ErrInvalidRequest, pair.name, minBufferBytes, maxDef)
		}
	}
	return nil
}

func ensureBBRModule(ctx context.Context, env Env) bool {
	if containsWord(env.readProcString(procTCPAvailCC), "bbr") || env.readProcString(procTCPCC) == "bbr" {
		return true
	}
	if err := runOptionalModprobe(ctx, env, "tcp_bbr"); err != nil {
		return containsWord(env.readProcString(procTCPAvailCC), "bbr")
	}
	// 部分内核仅需 modprobe 成功即允许设置 bbr；若 /proc 列表可读且仍不含 bbr 则视作不可用
	avail := env.readProcString(procTCPAvailCC)
	if avail == "" {
		return true
	}
	return containsWord(avail, "bbr")
}

func runOptionalModprobe(ctx context.Context, env Env, module string) error {
	if env.RunCmd != nil {
		_, err := env.RunCmd(ctx, "modprobe", module)
		return err
	}
	return exec.CommandContext(ctx, "modprobe", module).Run()
}

type sysctlKV struct {
	key      string
	val      string
	procPath string
}

func renderSysctlFile(profile Profile, t resolvedTarget, qdisc string, bbrOK bool) (string, []sysctlKV) {
	pairs := []sysctlKV{
		{key: "net.core.rmem_max", val: strconv.Itoa(t.rmemMax), procPath: procRmemMax},
		{key: "net.core.wmem_max", val: strconv.Itoa(t.wmemMax), procPath: procWmemMax},
		{key: "net.core.rmem_default", val: strconv.Itoa(t.rmemDefault), procPath: procRmemDefault},
		{key: "net.core.wmem_default", val: strconv.Itoa(t.wmemDefault), procPath: procWmemDefault},
	}
	if qdisc != "" {
		pairs = append(pairs, sysctlKV{key: "net.core.default_qdisc", val: qdisc, procPath: procDefaultQdisc})
	}
	if bbrOK {
		pairs = append(pairs, sysctlKV{key: "net.ipv4.tcp_congestion_control", val: "bbr", procPath: procTCPCC})
	}

	var b strings.Builder
	fmt.Fprintf(&b, "# Managed by singctl socktune (profile=%s) - do not edit manually\n", profile)
	for _, kv := range pairs {
		fmt.Fprintf(&b, "%s=%s\n", kv.key, kv.val)
	}
	return b.String(), pairs
}

func stripConflictSysctlKeys(env Env, path string, keys []string) error {
	raw, err := env.readFile(path)
	if err != nil {
		return nil
	}
	keySet := make(map[string]bool, len(keys))
	for _, k := range keys {
		keySet[k] = true
	}

	var kept []string
	changed := false
	for line := range strings.SplitSeq(strings.TrimRight(string(raw), "\n"), "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "#") && !strings.HasPrefix(trimmed, ";") {
			if k, _, ok := strings.Cut(trimmed, "="); ok && keySet[strings.TrimSpace(k)] {
				changed = true
				continue
			}
		}
		kept = append(kept, line)
	}
	if !changed {
		return nil
	}

	// 首次清理前保留原文件只读备份（*.bak），已存在则不覆盖以保留原始快照
	bakPath := path + ".bak"
	if _, err := env.readFile(bakPath); err != nil {
		_ = env.writeFile(bakPath, raw, 0644)
	}
	return env.writeFile(path, []byte(strings.Join(kept, "\n")+"\n"), 0644)
}

func applySysctlToKernel(ctx context.Context, env Env, sysctlPath string, pairs []sysctlKV) error {
	var (
		out []byte
		err error
	)
	if env.RunCmd != nil {
		out, err = env.RunCmd(ctx, "sysctl", "-p", sysctlPath)
	} else {
		out, err = exec.CommandContext(ctx, "sysctl", "-p", sysctlPath).CombinedOutput()
	}
	if err == nil {
		return nil
	}
	if isReadOnlyKernelErr(err, out) {
		return fmt.Errorf("%w: %s", ErrReadOnlyKernel, strings.TrimSpace(string(out)))
	}

	// 部分精简镜像（BusyBox / 无 sysctl 二进制）不支持 sysctl -p，回退直接写入 /proc/sys
	for _, kv := range pairs {
		if wErr := env.writeProc(kv.procPath, []byte(kv.val+"\n")); wErr != nil {
			if isReadOnlyKernelErr(wErr, nil) {
				return fmt.Errorf("%w: %v", ErrReadOnlyKernel, wErr)
			}
			return fmt.Errorf("应用 %s=%s 失败: %w", kv.key, kv.val, wErr)
		}
	}
	return nil
}

func isReadOnlyKernelErr(err error, output []byte) bool {
	if errors.Is(err, syscall.EROFS) || errors.Is(err, os.ErrPermission) {
		return true
	}
	msg := strings.ToLower(err.Error() + " " + string(output))
	return strings.Contains(msg, "read-only file system") ||
		strings.Contains(msg, "erofs") ||
		strings.Contains(msg, "operation not permitted")
}

func verifyKernelReadback(env Env, target resolvedTarget) error {
	checks := []struct {
		name string
		path string
		want int
	}{
		{"rmem_max", procRmemMax, target.rmemMax},
		{"wmem_max", procWmemMax, target.wmemMax},
		{"rmem_default", procRmemDefault, target.rmemDefault},
		{"wmem_default", procWmemDefault, target.wmemDefault},
	}
	for _, c := range checks {
		actual, ok := env.readProcInt(c.path)
		if !ok {
			return fmt.Errorf("回读校验 %s 失败：无法读取内核值", c.name)
		}
		if actual != c.want {
			return fmt.Errorf("回读校验失败：内核未接受 %s=%d（当前回读仍为 %d）", c.name, c.want, actual)
		}
	}
	return nil
}

func persistOpenWrtModules(env Env, withBBR, withFQ bool) {
	if !withBBR && !withFQ {
		return
	}
	modDir := env.modulesDir()
	fi, err := env.stat(modDir)
	if err != nil || !fi.IsDir() {
		return
	}
	var lines []string
	if withBBR {
		lines = append(lines, "tcp_bbr")
	}
	if withFQ {
		lines = append(lines, "sch_fq")
	}
	_ = env.writeFile(filepath.Join(modDir, "99-singctl-bbr-fq"), []byte(strings.Join(lines, "\n")+"\n"), 0644)
}

func buildApplyActions(before, after Status, bbrOK bool, qdisc string) []string {
	actions := []string{
		fmt.Sprintf("rmem_max/wmem_max: %s -> %s", formatBufferSize(before.RmemMax), formatBufferSize(after.RmemMax)),
		fmt.Sprintf("rmem_default/wmem_default: %s -> %s", formatBufferSize(before.RmemDefault), formatBufferSize(after.RmemDefault)),
	}
	if qdisc != "" {
		actions = append(actions, fmt.Sprintf("default_qdisc: %s -> %s", before.DefaultQdisc, after.DefaultQdisc))
	}
	if bbrOK {
		actions = append(actions, fmt.Sprintf("tcp_congestion_control: %s -> %s", before.TCPCongestion, after.TCPCongestion))
	}
	return actions
}

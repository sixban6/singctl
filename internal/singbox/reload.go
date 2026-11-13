package singbox

import (
	"cmp"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"singctl/internal/constant"
)

// LookPathFunc 可注入的命令查找函数（供单测覆盖）。
var LookPathFunc = exec.LookPath

// FindSingBoxBin 返回系统可用的 sing-box 可执行文件路径（未安装时返回空字符串）。
func FindSingBoxBin() string {
	if info, err := os.Stat(constant.SingBoxInstallDir); err == nil && !info.IsDir() {
		return constant.SingBoxInstallDir
	}
	if p, err := LookPathFunc("sing-box"); err == nil {
		return p
	}
	return ""
}

// CheckSingBoxConfigFile 使用 `sing-box check -c <path>` 校验磁盘配置文件语义合法性。
// 若系统未安装 sing-box 二进制，则直接返回 nil。
func CheckSingBoxConfigFile(ctx context.Context, path string) error {
	sbBin := FindSingBoxBin()
	if sbBin == "" {
		return nil
	}
	checkCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	out, err := exec.CommandContext(checkCtx, sbBin, "check", "-c", path).CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg == "" {
			msg = err.Error()
		}
		if len(msg) > 800 {
			msg = msg[:800] + "…"
		}
		return fmt.Errorf("sing-box check failed: %w (%s)", err, msg)
	}
	return nil
}

// CheckSingBoxConfigContent 将 JSON 内容写入临时文件并通过 `sing-box check` 校验。
func CheckSingBoxConfigContent(ctx context.Context, content string) error {
	sbBin := FindSingBoxBin()
	if sbBin == "" {
		return nil
	}
	tmp, err := os.CreateTemp("", "sbcheck-*.json")
	if err != nil {
		return fmt.Errorf("创建临时校验文件失败: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.WriteString(content); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("写入临时校验文件失败: %w", err)
	}
	_ = tmp.Close()
	_ = os.Chmod(tmpName, 0600)
	return CheckSingBoxConfigFile(ctx, tmpName)
}

// RewriteSandboxWorkConfig 将 ujail 沙盒工作目录引用 (/etc/sing-box/{cache.db,ui,dashboard})
// 重写为 sandbox 工作目录对应路径，与 start_singbox.sh 沙盒引导逻辑保持一致。
func RewriteSandboxWorkConfig(rawJSON, srcDir, workDir string) string {
	srcDir = filepath.ToSlash(strings.TrimRight(srcDir, "/\\"))
	workDir = filepath.ToSlash(strings.TrimRight(workDir, "/\\"))
	var pairs []string
	addPair := func(base, name string) {
		if base == "" || base == workDir {
			return
		}
		pairs = append(pairs,
			`"`+base+`/`+name+`"`,
			`"`+workDir+`/`+name+`"`,
		)
	}
	for _, name := range []string{"cache.db", "ui", "dashboard"} {
		addPair("/etc/sing-box", name)
		if srcDir != "/etc/sing-box" {
			addPair(srcDir, name)
		}
	}
	if len(pairs) == 0 {
		return rawJSON
	}
	return strings.NewReplacer(pairs...).Replace(rawJSON)
}

// ValidateAndReplaceSingBoxConfig 遵循规则 02：先写入临时文件并以 `sing-box check` 校验，
// 校验通过后再以 0600 权限原子 rename 覆盖目标配置文件。
func ValidateAndReplaceSingBoxConfig(ctx context.Context, dstPath, content, tmpSuffix string) error {
	suffix := cmp.Or(strings.TrimSpace(tmpSuffix), ".stage.tmp")
	atomicTmp := dstPath + suffix
	if err := os.WriteFile(atomicTmp, []byte(content), 0600); err != nil {
		return err
	}
	_ = os.Chmod(atomicTmp, 0600)

	if err := CheckSingBoxConfigFile(ctx, atomicTmp); err != nil {
		_ = os.Remove(atomicTmp)
		return err
	}

	if err := os.Rename(atomicTmp, dstPath); err != nil {
		_ = os.Remove(atomicTmp)
		return err
	}
	_ = os.Chmod(dstPath, 0600)
	return nil
}

// SyncSandboxWorkConfig 若存在 ujail 沙盒副本配置 (/tmp/sing-box-work/config.json)，
// 同步改写路径并以同样两阶段校验+原子替换更新，避免 SIGHUP 热重载继续读取旧沙盒配置。
func SyncSandboxWorkConfig(ctx context.Context, sbConfigPath, sbWorkConfigPath, updatedJSON, tmpSuffix string) error {
	workPath := strings.TrimSpace(sbWorkConfigPath)
	if workPath == "" || workPath == sbConfigPath {
		return nil
	}
	info, err := os.Stat(workPath)
	if err != nil || info.IsDir() {
		return nil
	}
	workJSON := RewriteSandboxWorkConfig(updatedJSON, filepath.Dir(sbConfigPath), filepath.Dir(workPath))
	return ValidateAndReplaceSingBoxConfig(ctx, workPath, workJSON, tmpSuffix)
}

// ReloadSingBoxProcess 向运行中的 sing-box 进程发送 SIGHUP 无损热重载配置。
func ReloadSingBoxProcess() {
	if _, err := exec.LookPath("pkill"); err == nil {
		if exec.Command("pkill", "-HUP", "-x", "sing-box").Run() == nil {
			return
		}
	}
	if _, err := exec.LookPath("killall"); err == nil {
		_ = exec.Command("killall", "-HUP", "sing-box").Run()
	}
}

// ApplyLiveSingBoxConfig 执行两阶段原子切换 + 0600 备份 + 沙盒副本同步 + SIGHUP 热重载。
func ApplyLiveSingBoxConfig(ctx context.Context, sbConfigPath, sbWorkConfigPath, updatedJSON, tag string) error {
	rawBytes, err := os.ReadFile(sbConfigPath)
	if err != nil {
		return err
	}
	cleanTag := cmp.Or(strings.Trim(tag, ". "), "reload")
	tmpSuffix := "." + cleanTag + ".tmp"
	bakPath := sbConfigPath + "." + cleanTag + ".bak"

	if err := ValidateAndReplaceSingBoxConfig(ctx, sbConfigPath, updatedJSON, tmpSuffix); err != nil {
		return err
	}
	_ = os.WriteFile(bakPath, rawBytes, 0600)
	_ = os.Chmod(bakPath, 0600)

	if err := SyncSandboxWorkConfig(ctx, sbConfigPath, sbWorkConfigPath, updatedJSON, tmpSuffix); err != nil {
		return err
	}
	ReloadSingBoxProcess()
	return nil
}

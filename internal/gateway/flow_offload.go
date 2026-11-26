// 文件职责：负责宿主机软硬件流量卸载（OpenWrt UCI firewall、TurboACC、MediaTek HNAT、SFE）的状态探测、0600 快照备份与在线热启停。
package gateway

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"

	"singctl/internal/common/fsx"
	"singctl/internal/platform/servicemgr"
)

const (
	// DefaultFlowOffloadBackupPath 为软硬件流量卸载原始配置快照路径（0600）。
	DefaultFlowOffloadBackupPath = "/etc/singctl/flow-offload-backup.json"

	defaultTurboACCConfigPath = "/etc/config/turboacc"
	defaultProcModulesPath    = "/proc/modules"
	defaultHNATHookTogglePath = "/sys/kernel/debug/hnat/hook_toggle"
	defaultHNATSettingPath    = "/sys/kernel/debug/hnat/hnat_setting"
	defaultFastClassifierPath = "/sys/fast_classifier/skip_to_bridge_ingress"
)

// FlowOffloadDeps 显式注入流量卸载探测与热开关所需外部依赖（nil 自动回退生产默认实现）。
type FlowOffloadDeps struct {
	BackupPath         string
	TurboACCConfigPath string
	ProcModulesPath    string
	HNATHookTogglePath string
	HNATSettingPath    string
	FastClassifierPath string
	IsOpenWrt          func() bool
	HasCommand         func(string) bool
	RunCmd             func(ctx context.Context, name string, args ...string) ([]byte, error)
	ReadFile           func(path string) ([]byte, error)
	WriteFile          func(path string, data []byte) error
	ServiceMgr         servicemgr.Manager
}

// FlowOffloadStatus 描述当前宿主软/硬件流量卸载的真实生效状态与保留的加速特性。
type FlowOffloadStatus struct {
	Supported         bool     `json:"supported"`
	IsOpenWrt         bool     `json:"isOpenWrt"`
	Enabled           bool     `json:"enabled"`
	UCISoftware       bool     `json:"uciSoftware"`
	UCIHardware       bool     `json:"uciHardware"`
	TurboACCPresent   bool     `json:"turboaccPresent"`
	TurboACCFastpath  string   `json:"turboaccFastpath,omitempty"`
	HNATSupported     bool     `json:"hnatSupported"`
	HNATActive        bool     `json:"hnatActive"`
	SFEActive         bool     `json:"sfeActive"`
	KernelFlowActive  bool     `json:"kernelFlowActive"`
	PreservedFeatures []string `json:"preservedFeatures,omitempty"`
	ActiveEngines     []string `json:"activeEngines,omitempty"`
	HasBackup         bool     `json:"hasBackup"`
}

// FlowOffloadApplyResult 记录切换流量卸载并回读内核真实验证后的执行结果。
type FlowOffloadApplyResult struct {
	Enabled        bool              `json:"enabled"`
	AppliedLive    bool              `json:"appliedLive"`
	RebootRequired bool              `json:"rebootRequired"`
	RestoredBackup bool              `json:"restoredBackup"`
	Actions        []string          `json:"actions,omitempty"`
	Message        string            `json:"message"`
	Status         FlowOffloadStatus `json:"status"`
}

type flowOffloadBackup struct {
	SavedAtUnix        int64                     `json:"savedAtUnix"`
	Firewall           map[string]uciBackupValue `json:"firewall"`
	TurboACCSection    string                    `json:"turboaccSection,omitempty"`
	TurboACCHasSection bool                      `json:"turboaccHasSection,omitempty"`
	TurboACC           map[string]uciBackupValue `json:"turboacc,omitempty"`
	HadHNAT            bool                      `json:"hadHnat,omitempty"`
	SFEModule          string                    `json:"sfeModule,omitempty"`
}

// DetectLoadedSFEModules 从 /proc/modules 原始内容中提取已加载的 SFE 内核模块列表（去重保序）。
func DetectLoadedSFEModules(rawMods []byte) []string {
	var mods []string
	for line := range strings.SplitSeq(string(rawMods), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		switch fields[0] {
		case "fast_classifier", "shortcut_fe_cm", "shortcut_fe":
			mods = appendUniqueStr(mods, fields[0])
		}
	}
	return mods
}

type resolvedFlowOffloadDeps struct {
	backupPath         string
	turboACCConfigPath string
	procModulesPath    string
	hnatHookTogglePath string
	hnatSettingPath    string
	fastClassifierPath string
	isOpenWrt          func() bool
	hasCommand         func(string) bool
	runCmd             func(ctx context.Context, name string, args ...string) ([]byte, error)
	readFile           func(path string) ([]byte, error)
	writeFile          func(path string, data []byte) error
	serviceMgr         servicemgr.Manager
}

func (d FlowOffloadDeps) resolve() resolvedFlowOffloadDeps {
	isOW := d.IsOpenWrt
	if isOW == nil {
		isOW = isOpenWrtSystem
	}
	hasCmd := d.HasCommand
	if hasCmd == nil {
		if d.RunCmd != nil {
			hasCmd = func(string) bool { return true }
		} else {
			hasCmd = func(name string) bool {
				_, err := exec.LookPath(name)
				return err == nil
			}
		}
	}
	runCmd := d.RunCmd
	if runCmd == nil {
		runCmd = func(ctx context.Context, name string, args ...string) ([]byte, error) {
			return exec.CommandContext(ctx, name, args...).CombinedOutput()
		}
	}
	readFile := d.ReadFile
	if readFile == nil {
		readFile = os.ReadFile
	}
	writeFile := d.WriteFile
	if writeFile == nil {
		writeFile = func(path string, data []byte) error {
			return os.WriteFile(path, data, 0644)
		}
	}
	mgr := d.ServiceMgr
	if mgr == nil {
		if d.RunCmd == nil && runtime.GOOS == "linux" {
			mgr = servicemgr.Detect(nil)
		} else {
			mgr = servicemgr.NewNoop()
		}
	}
	return resolvedFlowOffloadDeps{
		backupPath:         cmp.Or(strings.TrimSpace(d.BackupPath), DefaultFlowOffloadBackupPath),
		turboACCConfigPath: cmp.Or(strings.TrimSpace(d.TurboACCConfigPath), defaultTurboACCConfigPath),
		procModulesPath:    cmp.Or(strings.TrimSpace(d.ProcModulesPath), defaultProcModulesPath),
		hnatHookTogglePath: cmp.Or(strings.TrimSpace(d.HNATHookTogglePath), defaultHNATHookTogglePath),
		hnatSettingPath:    cmp.Or(strings.TrimSpace(d.HNATSettingPath), defaultHNATSettingPath),
		fastClassifierPath: cmp.Or(strings.TrimSpace(d.FastClassifierPath), defaultFastClassifierPath),
		isOpenWrt:          isOW,
		hasCommand:         hasCmd,
		runCmd:             runCmd,
		readFile:           readFile,
		writeFile:          writeFile,
		serviceMgr:         mgr,
	}
}

type turboACCConfig struct {
	section string
	options map[string]string
}

func parseTurboACCUCI(raw []byte) turboACCConfig {
	cfg := turboACCConfig{
		section: "config",
		options: make(map[string]string),
	}
	currentSec := ""
	targetSec := ""
	allOpts := make(map[string]map[string]string)

	for line := range strings.SplitSeq(string(raw), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		fields := strings.Fields(trimmed)
		if len(fields) >= 2 && fields[0] == "config" {
			secName := ""
			if len(fields) >= 3 {
				secName = trimUCIQuote(fields[2])
			} else {
				secName = "@turboacc[0]"
			}
			currentSec = secName
			if secName == "config" || (targetSec == "" && secName != "global") {
				targetSec = secName
			}
			if allOpts[currentSec] == nil {
				allOpts[currentSec] = make(map[string]string)
			}
			continue
		}
		if len(fields) >= 3 && fields[0] == "option" && currentSec != "" {
			key := trimUCIQuote(fields[1])
			val := trimUCIQuote(strings.Join(fields[2:], " "))
			allOpts[currentSec][key] = val
		}
	}

	if targetSec != "" {
		cfg.section = targetSec
		cfg.options = allOpts[targetSec]
	} else if len(allOpts) > 0 {
		for sec, opts := range allOpts {
			cfg.section = sec
			cfg.options = opts
			break
		}
	}
	if cfg.options == nil {
		cfg.options = make(map[string]string)
	}
	return cfg
}

func trimUCIQuote(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 {
		if (s[0] == '\'' && s[len(s)-1] == '\'') || (s[0] == '"' && s[len(s)-1] == '"') {
			return s[1 : len(s)-1]
		}
	}
	return s
}

func isTurboACCFastpathEnabled(cfg turboACCConfig) (active bool, fastpath string) {
	fp := strings.ToLower(strings.TrimSpace(cfg.options["fastpath"]))
	if fp != "" && fp != "none" && fp != "0" {
		if fp == "mediatek_hnat" && strings.TrimSpace(cfg.options["fastpath_mh_eth_hnat"]) == "0" {
			return false, fp
		}
		return true, fp
	}
	if strings.TrimSpace(cfg.options["sw_flow"]) == "1" {
		return true, cmp.Or(fp, "sw_flow")
	}
	if strings.TrimSpace(cfg.options["hw_flow"]) == "1" {
		return true, cmp.Or(fp, "hw_flow")
	}
	if strings.TrimSpace(cfg.options["sfe_flow"]) == "1" {
		return true, cmp.Or(fp, "sfe_flow")
	}
	return false, fp
}

func appendUniqueStr(slice []string, val string) []string {
	if val == "" || slices.Contains(slice, val) {
		return slice
	}
	return append(slice, val)
}

func uciGetTrimmed(ctx context.Context, runCmd func(context.Context, string, ...string) ([]byte, error), key string) (string, bool) {
	out, err := runCmd(ctx, "uci", "-q", "get", key)
	if err != nil {
		return "", false
	}
	return strings.TrimSpace(string(out)), true
}

// ProbeFlowOffloadStatus 探测当前宿主的软件/硬件流量卸载与 TurboACC/HNAT 运行状态。
func ProbeFlowOffloadStatus(ctx context.Context, deps FlowOffloadDeps) FlowOffloadStatus {
	if ctx == nil {
		ctx = context.Background()
	}
	d := deps.resolve()

	isOW := d.isOpenWrt()
	hasUCI := d.hasCommand("uci")
	st := FlowOffloadStatus{
		IsOpenWrt: isOW,
	}

	var uciFullcone bool
	if isOW && hasUCI {
		if val, ok := uciGetTrimmed(ctx, d.runCmd, "firewall.@defaults[0].flow_offloading"); ok && val == "1" {
			st.UCISoftware = true
		}
		if val, ok := uciGetTrimmed(ctx, d.runCmd, "firewall.@defaults[0].flow_offloading_hw"); ok && val == "1" {
			st.UCIHardware = true
		}
		if val, ok := uciGetTrimmed(ctx, d.runCmd, "firewall.@defaults[0].fullcone"); ok && val == "1" {
			uciFullcone = true
		}
	}

	var turboParsed turboACCConfig
	var turboConfiguredActive bool
	if rawTurbo, err := d.readFile(d.turboACCConfigPath); err == nil {
		st.TurboACCPresent = true
		turboParsed = parseTurboACCUCI(rawTurbo)
		turboConfiguredActive, st.TurboACCFastpath = isTurboACCFastpathEnabled(turboParsed)
		if strings.EqualFold(strings.TrimSpace(turboParsed.options["tcpcca"]), "bbr") {
			st.PreservedFeatures = appendUniqueStr(st.PreservedFeatures, "TCP BBR 拥塞控制")
		}
		if strings.TrimSpace(turboParsed.options["fullcone"]) == "1" || uciFullcone {
			st.PreservedFeatures = appendUniqueStr(st.PreservedFeatures, "FullCone NAT")
		}
	} else if uciFullcone {
		st.PreservedFeatures = appendUniqueStr(st.PreservedFeatures, "FullCone NAT")
	}

	if rawHook, err := d.readFile(d.hnatHookTogglePath); err == nil {
		st.HNATSupported = true
		hookVal := strings.ToLower(strings.TrimSpace(string(rawHook)))
		if hookVal == "enabled" || hookVal == "1" {
			st.HNATActive = true
		}
	}

	if rawMods, err := d.readFile(d.procModulesPath); err == nil {
		for line := range strings.SplitSeq(string(rawMods), "\n") {
			fields := strings.Fields(line)
			if len(fields) == 0 {
				continue
			}
			refcnt := 0
			if len(fields) >= 3 {
				if parsed, convErr := strconv.Atoi(fields[2]); convErr == nil {
					refcnt = parsed
				}
			}
			switch fields[0] {
			case "mtkhnat":
				if !st.HNATSupported {
					st.HNATActive = true
				}
			case "fast_classifier", "shortcut_fe_cm", "shortcut_fe":
				st.SFEActive = true
			case "xt_FLOWOFFLOAD", "nft_flow_offload":
				if refcnt > 0 {
					st.KernelFlowActive = true
				}
			}
		}
	}

	if _, err := d.readFile(d.backupPath); err == nil {
		st.HasBackup = true
	}

	st.Supported = (isOW && hasUCI) || st.HNATSupported || st.TurboACCPresent
	st.Enabled = st.UCISoftware || st.UCIHardware || st.HNATActive || st.SFEActive || st.KernelFlowActive || turboConfiguredActive

	if st.UCISoftware {
		st.ActiveEngines = appendUniqueStr(st.ActiveEngines, "UCI 软件流量卸载")
	}
	if st.UCIHardware {
		st.ActiveEngines = appendUniqueStr(st.ActiveEngines, "UCI 硬件流量卸载")
	}
	if st.HNATActive {
		st.ActiveEngines = appendUniqueStr(st.ActiveEngines, "MediaTek HNAT 硬件加速")
	}
	if st.SFEActive {
		st.ActiveEngines = appendUniqueStr(st.ActiveEngines, "SFE 快捷转发")
	}
	if turboConfiguredActive && !st.HNATActive && !st.SFEActive {
		st.ActiveEngines = appendUniqueStr(st.ActiveEngines, fmt.Sprintf("TurboACC (%s)", cmp.Or(st.TurboACCFastpath, "已启用")))
	}
	if st.KernelFlowActive && !st.UCISoftware && !st.UCIHardware {
		st.ActiveEngines = appendUniqueStr(st.ActiveEngines, "内核 Flowtable 快速转发")
	}

	return st
}

// ApplyFlowOffload 在线热关闭或热开启软/硬件流量卸载，支持 0600 快照还原与写后内核状态回读验证。
func ApplyFlowOffload(ctx context.Context, enable bool, deps FlowOffloadDeps) (FlowOffloadApplyResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	d := deps.resolve()
	before := ProbeFlowOffloadStatus(ctx, deps)
	if !before.Supported {
		return FlowOffloadApplyResult{}, errors.New("当前宿主机不支持可控的软硬件流量卸载配置（仅支持 OpenWrt / ImmortalWrt 宿主机）")
	}

	hasUCI := d.hasCommand("uci") && d.isOpenWrt()
	var actions []string
	var restoredBackup bool

	if !enable {
		// 1. 仅在尚未存在有效快照时记录当前配置，防止重复关闭覆盖原始参数
		if err := ensureFlowOffloadBackup(ctx, d, before); err != nil {
			return FlowOffloadApplyResult{}, fmt.Errorf("保存流量卸载快照失败: %w", err)
		}

		// 2. 置零标准 OpenWrt firewall 软件/硬件卸载
		if hasUCI {
			for _, kv := range []string{"firewall.@defaults[0].flow_offloading=0", "firewall.@defaults[0].flow_offloading_hw=0"} {
				if err := runUCICommand(ctx, d.runCmd, "set", kv); err != nil {
					return FlowOffloadApplyResult{}, err
				}
			}
			if err := runUCICommand(ctx, d.runCmd, "commit", "firewall"); err != nil {
				return FlowOffloadApplyResult{}, err
			}
			actions = append(actions, "已置零 OpenWrt 防火墙软/硬件流量卸载 (flow_offloading=0)")
		}

		// 3. 精准停用 TurboACC 快速转发字段（严格保留 BBR 与 FullCone）
		if before.TurboACCPresent {
			turboActions, tErr := disableTurboACCFastpath(ctx, d)
			if tErr != nil {
				return FlowOffloadApplyResult{}, tErr
			}
			actions = append(actions, turboActions...)
		}

		// 4. 内核热摘除 HNAT / Fast Classifier Hook，绝不卸载正在被 Wi-Fi 引用的 mtkhnat 模块
		if _, err := d.readFile(d.hnatHookTogglePath); err == nil {
			if wErr := d.writeFile(d.hnatHookTogglePath, []byte("0\n")); wErr != nil {
				return FlowOffloadApplyResult{}, fmt.Errorf("写入 %s=0 失败: %w", d.hnatHookTogglePath, wErr)
			}
			actions = append(actions, "已热关闭 MediaTek HNAT 内核 Hook（无线驱动零影响）")
		}
		if _, err := d.readFile(d.fastClassifierPath); err == nil {
			_ = d.writeFile(d.fastClassifierPath, []byte("0\n"))
			actions = append(actions, "已关闭 SFE 快速分类器桥接转发")
		}
		if before.SFEActive && d.hasCommand("rmmod") {
			if rawMods, mErr := d.readFile(d.procModulesPath); mErr == nil {
				for _, mod := range DetectLoadedSFEModules(rawMods) {
					if _, rErr := d.runCmd(ctx, "rmmod", mod); rErr == nil {
						actions = append(actions, fmt.Sprintf("已在线卸载 SFE 内核模块 (%s)", mod))
					}
				}
			}
		}
	} else {
		var turboCfg turboACCConfig
		if rawTurbo, err := d.readFile(d.turboACCConfigPath); err == nil {
			turboCfg = parseTurboACCUCI(rawTurbo)
		}
		snap, hasSnap := readFlowOffloadBackup(d)
		if hasSnap {
			restoredBackup = true
			rActions, rErr := restoreFlowOffloadFromBackup(ctx, d, snap, hasUCI)
			if rErr != nil {
				return FlowOffloadApplyResult{}, rErr
			}
			actions = append(actions, rActions...)
		} else {
			dActions, dErr := enableFlowOffloadDefaults(ctx, d, before, turboCfg, hasUCI)
			if dErr != nil {
				return FlowOffloadApplyResult{}, dErr
			}
			actions = append(actions, dActions...)
		}
	}

	reloadAct, reloadErr := reloadFirewallSoftly(ctx, d)
	if reloadErr != nil {
		return FlowOffloadApplyResult{}, reloadErr
	}
	actions = append(actions, reloadAct)

	// reload 之后再次同步一次 HNAT hook 与参数，确保 fw3/fw4 reload 期间不重置调试开关
	if enable {
		if rawTurbo, err := d.readFile(d.turboACCConfigPath); err == nil {
			tCfg := parseTurboACCUCI(rawTurbo)
			if active, fp := isTurboACCFastpathEnabled(tCfg); active && fp == "mediatek_hnat" {
				if _, hookErr := d.readFile(d.hnatHookTogglePath); hookErr == nil {
					_ = d.writeFile(d.hnatHookTogglePath, []byte("1\n"))
					syncHNATKernelSettings(d, tCfg)
				}
			}
		}
	}

	// 写后回读内核真实验证
	after := ProbeFlowOffloadStatus(ctx, deps)
	appliedLive := after.Enabled == enable
	rebootRequired := !appliedLive

	var msg string
	switch {
	case rebootRequired:
		msg = "配置已保存并写入，但内核流量卸载状态未立即翻转；当前固件驱动需重启路由器后完全生效"
	case !enable:
		preservedSuffix := ""
		if len(after.PreservedFeatures) > 0 {
			preservedSuffix = "，已保留 " + strings.Join(after.PreservedFeatures, " 与 ")
		}
		msg = fmt.Sprintf("已关闭软/硬件流量卸载并在线热生效（无需重启路由器%s）", preservedSuffix)
	case restoredBackup:
		msg = "已按原厂配置还原并开启流量卸载（无需重启路由器；新建连接立即生效，老长连接重连后进入加速）"
	default:
		msg = "已开启软/硬件流量卸载并在线热生效（无需重启路由器；新建连接立即生效，老长连接重连后进入加速）"
	}

	return FlowOffloadApplyResult{
		Enabled:        after.Enabled,
		AppliedLive:    appliedLive,
		RebootRequired: rebootRequired,
		RestoredBackup: restoredBackup,
		Actions:        actions,
		Message:        msg,
		Status:         after,
	}, nil
}

func runUCICommand(ctx context.Context, runCmd func(context.Context, string, ...string) ([]byte, error), args ...string) error {
	out, err := runCmd(ctx, "uci", args...)
	if err != nil {
		detail := strings.TrimSpace(string(out))
		if detail != "" {
			return fmt.Errorf("uci %s 失败: %w (%s)", strings.Join(args, " "), err, detail)
		}
		return fmt.Errorf("uci %s 失败: %w", strings.Join(args, " "), err)
	}
	return nil
}

var managedTurboACCOffloadKeys = []string{
	"fastpath",
	"fastpath_mh_eth_hnat",
	"fastpath_mh_eth_hnat_v6",
	"fastpath_mh_eth_hnat_bind_rate",
	"fastpath_mh_eth_hnat_macvlan",
	"fastpath_fc_br",
	"fastpath_fc_ipv6",
	"sw_flow",
	"hw_flow",
	"sfe_flow",
}

func ensureFlowOffloadBackup(ctx context.Context, d resolvedFlowOffloadDeps, before FlowOffloadStatus) error {
	if _, err := d.readFile(d.backupPath); err == nil {
		return nil
	}
	snap := flowOffloadBackup{
		SavedAtUnix: time.Now().Unix(),
		Firewall:    make(map[string]uciBackupValue),
		HadHNAT:     before.HNATActive || before.TurboACCFastpath == "mediatek_hnat",
	}
	if rawMods, mErr := d.readFile(d.procModulesPath); mErr == nil {
		if mods := DetectLoadedSFEModules(rawMods); len(mods) > 0 {
			snap.SFEModule = mods[0]
		}
	}
	if d.hasCommand("uci") && d.isOpenWrt() {
		for _, k := range []string{"firewall.@defaults[0].flow_offloading", "firewall.@defaults[0].flow_offloading_hw"} {
			if val, ok := uciGetTrimmed(ctx, d.runCmd, k); ok {
				snap.Firewall[k] = uciBackupValue{Set: true, Value: val}
			} else {
				snap.Firewall[k] = uciBackupValue{Set: false}
			}
		}
	}
	if rawTurbo, err := d.readFile(d.turboACCConfigPath); err == nil {
		parsed := parseTurboACCUCI(rawTurbo)
		snap.TurboACCHasSection = true
		snap.TurboACCSection = parsed.section
		snap.TurboACC = make(map[string]uciBackupValue)
		for _, k := range managedTurboACCOffloadKeys {
			if val, ok := parsed.options[k]; ok {
				snap.TurboACC[k] = uciBackupValue{Set: true, Value: val}
			} else {
				snap.TurboACC[k] = uciBackupValue{Set: false}
			}
		}
	}

	raw, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(d.backupPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	_ = os.Chmod(dir, 0700)
	return fsx.WriteAtomic0600(d.backupPath, append(raw, '\n'))
}

func readFlowOffloadBackup(d resolvedFlowOffloadDeps) (flowOffloadBackup, bool) {
	raw, err := d.readFile(d.backupPath)
	if err != nil || len(raw) == 0 {
		return flowOffloadBackup{}, false
	}
	var snap flowOffloadBackup
	if err := json.Unmarshal(raw, &snap); err != nil {
		return flowOffloadBackup{}, false
	}
	return snap, true
}

func disableTurboACCFastpath(ctx context.Context, d resolvedFlowOffloadDeps) ([]string, error) {
	rawTurbo, err := d.readFile(d.turboACCConfigPath)
	if err != nil {
		return nil, nil
	}
	parsed := parseTurboACCUCI(rawTurbo)
	sec := cmp.Or(parsed.section, "config")
	uciAvailable := d.hasCommand("uci") && d.isOpenWrt()
	if !uciAvailable {
		return nil, nil
	}

	setKey := func(opt, val string) error {
		return runUCICommand(ctx, d.runCmd, "set", fmt.Sprintf("turboacc.%s.%s=%s", sec, opt, val))
	}

	hasFastpath := false
	if _, ok := parsed.options["fastpath"]; ok {
		hasFastpath = true
		if err := setKey("fastpath", "none"); err != nil {
			return nil, err
		}
	}
	if _, ok := parsed.options["fastpath_mh_eth_hnat"]; ok {
		hasFastpath = true
		if err := setKey("fastpath_mh_eth_hnat", "0"); err != nil {
			return nil, err
		}
	}
	for _, legacyKey := range []string{"sw_flow", "hw_flow", "sfe_flow"} {
		if _, ok := parsed.options[legacyKey]; ok {
			hasFastpath = true
			if err := setKey(legacyKey, "0"); err != nil {
				return nil, err
			}
		}
	}
	if !hasFastpath {
		if err := setKey("fastpath", "none"); err != nil {
			return nil, err
		}
	}
	if err := runUCICommand(ctx, d.runCmd, "commit", "turboacc"); err != nil {
		return nil, err
	}
	return []string{"已停用 TurboACC 快速转发路径（保留 tcpcca/fullcone 原配置）"}, nil
}

func restoreFlowOffloadFromBackup(ctx context.Context, d resolvedFlowOffloadDeps, snap flowOffloadBackup, hasUCI bool) ([]string, error) {
	var actions []string
	hasRestoredRule := false

	if hasUCI && len(snap.Firewall) > 0 {
		fwKeys := make([]string, 0, len(snap.Firewall))
		for k := range snap.Firewall {
			fwKeys = append(fwKeys, k)
		}
		slices.Sort(fwKeys)
		for _, k := range fwKeys {
			orig := snap.Firewall[k]
			if orig.Set && orig.Value != "" {
				if err := runUCICommand(ctx, d.runCmd, "set", k+"="+orig.Value); err != nil {
					return nil, err
				}
				if orig.Value == "1" {
					hasRestoredRule = true
				}
			}
		}
		if err := runUCICommand(ctx, d.runCmd, "commit", "firewall"); err != nil {
			return nil, err
		}
		actions = append(actions, "已从快照恢复 OpenWrt 防火墙流量卸载配置")
	}

	if snap.TurboACCHasSection && hasUCI {
		sec := cmp.Or(snap.TurboACCSection, "config")
		tKeys := make([]string, 0, len(snap.TurboACC))
		for k := range snap.TurboACC {
			tKeys = append(tKeys, k)
		}
		slices.Sort(tKeys)
		for _, k := range tKeys {
			orig := snap.TurboACC[k]
			if !orig.Set || orig.Value == "" {
				continue
			}
			if err := runUCICommand(ctx, d.runCmd, "set", fmt.Sprintf("turboacc.%s.%s=%s", sec, k, orig.Value)); err != nil {
				return nil, err
			}
			if (k == "fastpath" && orig.Value != "none" && orig.Value != "0") || ((k == "sw_flow" || k == "hw_flow" || k == "sfe_flow") && orig.Value == "1") {
				hasRestoredRule = true
			}
		}
		if err := runUCICommand(ctx, d.runCmd, "commit", "turboacc"); err != nil {
			return nil, err
		}
		actions = append(actions, "已从快照还原 TurboACC 加速配置")
	}

	if !hasRestoredRule {
		var turboCfg turboACCConfig
		if rawTurbo, err := d.readFile(d.turboACCConfigPath); err == nil {
			turboCfg = parseTurboACCUCI(rawTurbo)
		}
		fallbackActs, fErr := enableFlowOffloadDefaults(ctx, d, ProbeFlowOffloadStatus(ctx, d.toPublic()), turboCfg, hasUCI)
		if fErr != nil {
			return nil, fErr
		}
		actions = append(actions, fallbackActs...)
		return actions, nil
	}

	if _, err := d.readFile(d.hnatHookTogglePath); err == nil {
		if origFP, ok := snap.TurboACC["fastpath"]; (ok && origFP.Value == "mediatek_hnat") || snap.HadHNAT {
			if wErr := d.writeFile(d.hnatHookTogglePath, []byte("1\n")); wErr != nil {
				return nil, fmt.Errorf("恢复 %s=1 失败: %w", d.hnatHookTogglePath, wErr)
			}
			var turboCfg turboACCConfig
			if rawTurbo, tErr := d.readFile(d.turboACCConfigPath); tErr == nil {
				turboCfg = parseTurboACCUCI(rawTurbo)
			}
			syncHNATKernelSettings(d, turboCfg)
			actions = append(actions, "已热重新启用 MediaTek HNAT 内核 Hook")
		}
	}

	targetSFEMod := ""
	origFP := strings.ToLower(strings.TrimSpace(snap.TurboACC["fastpath"].Value))
	switch {
	case origFP == "fast_classifier" || origFP == "shortcut_fe_cm" || origFP == "shortcut_fe":
		targetSFEMod = origFP
	case snap.SFEModule != "":
		targetSFEMod = snap.SFEModule
	case strings.TrimSpace(snap.TurboACC["sfe_flow"].Value) == "1":
		targetSFEMod = "fast_classifier"
	}
	if targetSFEMod != "" {
		if d.hasCommand("modprobe") {
			if _, mErr := d.runCmd(ctx, "modprobe", targetSFEMod); mErr == nil {
				actions = append(actions, fmt.Sprintf("已在线加载恢复 SFE 内核模块 (%s)", targetSFEMod))
			}
		}
		if targetSFEMod == "fast_classifier" {
			if _, fErr := d.readFile(d.fastClassifierPath); fErr == nil {
				fcBr := cmp.Or(strings.TrimSpace(snap.TurboACC["fastpath_fc_br"].Value), "0")
				_ = d.writeFile(d.fastClassifierPath, []byte(fcBr+"\n"))
			}
		}
	}

	return actions, nil
}

func (d resolvedFlowOffloadDeps) toPublic() FlowOffloadDeps {
	return FlowOffloadDeps{
		BackupPath:         d.backupPath,
		TurboACCConfigPath: d.turboACCConfigPath,
		ProcModulesPath:    d.procModulesPath,
		HNATHookTogglePath: d.hnatHookTogglePath,
		HNATSettingPath:    d.hnatSettingPath,
		FastClassifierPath: d.fastClassifierPath,
		IsOpenWrt:          d.isOpenWrt,
		HasCommand:         d.hasCommand,
		RunCmd:             d.runCmd,
		ReadFile:           d.readFile,
		WriteFile:          d.writeFile,
		ServiceMgr:         d.serviceMgr,
	}
}

func enableFlowOffloadDefaults(ctx context.Context, d resolvedFlowOffloadDeps, before FlowOffloadStatus, turboCfg turboACCConfig, hasUCI bool) ([]string, error) {
	var actions []string
	if before.TurboACCPresent && before.HNATSupported && hasUCI {
		sec := cmp.Or(turboCfg.section, "config")
		if err := runUCICommand(ctx, d.runCmd, "set", fmt.Sprintf("turboacc.%s.fastpath=mediatek_hnat", sec)); err != nil {
			return nil, err
		}
		if err := runUCICommand(ctx, d.runCmd, "set", fmt.Sprintf("turboacc.%s.fastpath_mh_eth_hnat=1", sec)); err != nil {
			return nil, err
		}
		if err := runUCICommand(ctx, d.runCmd, "commit", "turboacc"); err != nil {
			return nil, err
		}
		if err := d.writeFile(d.hnatHookTogglePath, []byte("1\n")); err != nil {
			return nil, fmt.Errorf("开启 %s 失败: %w", d.hnatHookTogglePath, err)
		}
		syncHNATKernelSettings(d, turboCfg)
		actions = append(actions, "已启用 TurboACC MediaTek HNAT 硬件加速")
		return actions, nil
	}

	if hasUCI {
		if err := runUCICommand(ctx, d.runCmd, "set", "firewall.@defaults[0].flow_offloading=1"); err != nil {
			return nil, err
		}
		if err := runUCICommand(ctx, d.runCmd, "commit", "firewall"); err != nil {
			return nil, err
		}
		actions = append(actions, "已开启 OpenWrt UCI 软件流量卸载 (flow_offloading=1)")
	}
	return actions, nil
}

func syncHNATKernelSettings(d resolvedFlowOffloadDeps, turboCfg turboACCConfig) {
	v6 := cmp.Or(strings.TrimSpace(turboCfg.options["fastpath_mh_eth_hnat_v6"]), "1")
	bindRate := cmp.Or(strings.TrimSpace(turboCfg.options["fastpath_mh_eth_hnat_bind_rate"]), "30")
	_ = d.writeFile(d.hnatSettingPath, []byte("8 "+v6+"\n"))
	_ = d.writeFile(d.hnatSettingPath, []byte("11 "+bindRate+"\n"))
	if macvlan := strings.TrimSpace(turboCfg.options["fastpath_mh_eth_hnat_macvlan"]); macvlan != "" {
		_ = d.writeFile(d.hnatSettingPath, []byte("12 "+macvlan+"\n"))
	}
}

func reloadFirewallSoftly(ctx context.Context, d resolvedFlowOffloadDeps) (string, error) {
	if d.hasCommand("fw4") {
		if out, err := d.runCmd(ctx, "fw4", "reload"); err != nil {
			detail := strings.TrimSpace(string(out))
			if detail != "" {
				return "", fmt.Errorf("fw4 reload 失败: %w (%s)", err, detail)
			}
			return "", fmt.Errorf("fw4 reload 失败: %w", err)
		}
		return "已执行 fw4 reload 平滑刷新防火墙规则（sing-box 透明代理表零中断）", nil
	}
	if err := d.serviceMgr.Reload(ctx, "firewall"); err != nil {
		return "", fmt.Errorf("重载 firewall 服务失败: %w", err)
	}
	return "已重载 firewall 服务生效", nil
}

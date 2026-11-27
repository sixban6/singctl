// 文件职责：实现 Wi-Fi 安全一键优化、双频合一与单频参数微调引擎（含 0600 备份、批量 UCI、单次重载与网桥就绪校验回滚）。
package wifiopt

import (
	"cmp"
	"context"
	"fmt"
	"slices"
	"strconv"
	"strings"
)

type uciOp struct {
	Key   string
	Value string
}

// PreparedReload 封装已提交 UCI 无线变更后延迟执行 wifi reload 与网桥验收所需的不可变上下文。
type PreparedReload struct {
	origWireless    []byte
	haveOrig        bool
	expectedBridges map[string][]string
}

// Apply 执行一键全自动优化、一键双频合一或单频微调（同步模式：含 0600 备份、批量 UCI、单次 wifi reload 与网桥自检回滚）。
func (s *Service) Apply(ctx context.Context, req ApplyRequest) (*ApplyResult, error) {
	res, prep, err := s.CommitWithoutReload(ctx, req)
	if err != nil || prep == nil {
		return res, err
	}
	waitMs, err := s.ExecutePreparedReload(ctx, prep)
	if err != nil {
		return nil, err
	}
	res.Reloaded = true
	res.BridgeVerified = true
	res.BridgeWaitMs = waitMs
	res.Summary = fmt.Sprintf("已成功应用 %d 项无线优化，全部射频与网桥已就绪。", len(res.Changes))
	return res, nil
}

// CommitWithoutReload 仅执行参数校验、0600 快照、批量 uci set 与单次 uci commit，返回待重载上下文供 HTTP 层先返回 200 后异步重载（避免 Wi-Fi 客户端操作误报断网）。
func (s *Service) CommitWithoutReload(ctx context.Context, req ApplyRequest) (*ApplyResult, *PreparedReload, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	ov, err := s.Overview(ctx)
	if err != nil {
		return nil, nil, err
	}
	if !ov.Supported {
		return nil, nil, ErrUnsupported
	}
	st, _, _, err := s.probe(ctx)
	if err != nil {
		return nil, nil, err
	}

	action := strings.TrimSpace(req.Action)
	var ops []uciOp
	var changes []OptimizationStep
	expectedBridges := make(map[string][]string) // bridge -> []expectedIfName

	switch action {
	case "auto_optimize":
		ops, changes, expectedBridges, err = buildAutoOptimizeOps(ov, st, req)
	case "dual_band_merge":
		ops, changes, expectedBridges, err = buildDualBandMergeOps(ov, st, req)
	case "tune_radio":
		ops, changes, expectedBridges, err = buildTuneRadioOps(ov, st, req)
	default:
		return nil, nil, fmt.Errorf("%w: 不支持的操作类型 %q", ErrInvalidRequest, req.Action)
	}
	if err != nil {
		return nil, nil, err
	}

	if req.DryRun || len(ops) == 0 {
		summary := "当前配置已是推荐状态，无需修改。"
		if len(changes) > 0 {
			summary = fmt.Sprintf("预览共 %d 项无线优化，确认后将单次提交并带防失联回滚生效。", len(changes))
		}
		return &ApplyResult{
			OK:      true,
			DryRun:  req.DryRun,
			Action:  action,
			Summary: summary,
			Changes: changes,
		}, nil, nil
	}

	// 1. 变更前只读快照 /etc/config/wireless（用于网桥校验失败时当场秒级回滚）
	origWireless, backupErr := s.readFile(s.wirelessFile())

	// 2. 批量执行 uci set + 单次 uci commit wireless
	for _, op := range ops {
		if _, err := s.runCmd(ctx, "uci", "set", op.Key+"="+op.Value); err != nil {
			s.rollbackWirelessFile(ctx, origWireless, backupErr == nil)
			return nil, nil, fmt.Errorf("写入 UCI 无线参数失败: %w", err)
		}
	}
	if _, err := s.runCmd(ctx, "uci", "commit", "wireless"); err != nil {
		s.rollbackWirelessFile(ctx, origWireless, backupErr == nil)
		return nil, nil, fmt.Errorf("提交 UCI 无线配置失败: %w", err)
	}

	return &ApplyResult{
			OK:      true,
			Action:  action,
			Summary: fmt.Sprintf("已提交 %d 项无线优化配置，即将平滑重载无线（约 8 秒瞬断）。", len(changes)),
			Changes: changes,
		}, &PreparedReload{
			origWireless:    origWireless,
			haveOrig:        backupErr == nil,
			expectedBridges: expectedBridges,
		}, nil
}

// ExecutePreparedReload 执行单次纯无线重载（绝不触碰有线/WAN/network）与 25 秒网桥就绪验收，失败自动 0600 还原并重拉无线。
func (s *Service) ExecutePreparedReload(ctx context.Context, prep *PreparedReload) (int64, error) {
	if prep == nil {
		return 0, nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := s.reloadWifi(ctx); err != nil {
		s.rollbackWirelessFile(ctx, prep.origWireless, prep.haveOrig)
		return 0, fmt.Errorf("重载无线服务失败并已自动回滚: %w", err)
	}
	start := s.now()
	verified := s.waitBridgesReady(ctx, prep.expectedBridges)
	waitMs := s.now().Sub(start).Milliseconds()
	if !verified {
		s.rollbackWirelessFile(ctx, prep.origWireless, prep.haveOrig)
		return waitMs, ErrBridgeVerifyFailed
	}
	return waitMs, nil
}

func (s *Service) rollbackWirelessFile(ctx context.Context, orig []byte, haveOrig bool) {
	if haveOrig && len(orig) > 0 {
		_ = s.writeFile0600(s.wirelessFile(), orig)
		_ = s.reloadWifi(ctx)
	}
}

func (s *Service) waitBridgesReady(ctx context.Context, expected map[string][]string) bool {
	if len(expected) == 0 {
		return true
	}
	deadline := s.now().Add(s.verifyTimeout())
	maxChecks := max(1, int(s.verifyTimeout()/s.pollInterval())+1)
	for range maxChecks {
		if err := s.sleep(ctx, s.pollInterval()); err != nil {
			return false
		}
		raw, err := s.runCmd(ctx, "brctl", "show")
		if err == nil {
			bridges := parseBrctlShow(string(raw))
			if bridgesMatchExpected(bridges, expected) {
				return true
			}
		}
		if s.now().After(deadline) {
			break
		}
	}
	return false
}

func bridgesMatchExpected(actual map[string][]string, expected map[string][]string) bool {
	for br, needIfs := range expected {
		gotIfs := actual[br]
		for _, need := range needIfs {
			if !slices.Contains(gotIfs, need) {
				return false
			}
		}
	}
	return true
}

func buildDualBandMergeOps(ov *Overview, st *probeState, req ApplyRequest) ([]uciOp, []OptimizationStep, map[string][]string, error) {
	srcName := strings.TrimSpace(req.SourceSection)
	if !isValidUCISectionName(srcName) {
		return nil, nil, nil, fmt.Errorf("%w: 非法源无线节名 %q", ErrInvalidRequest, srcName)
	}
	src := st.IfaceBySec[srcName]
	if src == nil || src.Type != "wifi-iface" {
		return nil, nil, nil, fmt.Errorf("%w: %q", ErrInterfaceNotFound, srcName)
	}
	r5 := findRadioByBand(ov, "5g")
	if r5 == nil {
		return nil, nil, nil, fmt.Errorf("%w: 未检测到 5 GHz 射频", ErrRadioNotFound)
	}
	targetSecName := pickPrimary5GIfaceSection(st, r5.Device)
	if targetSecName == "" {
		return nil, nil, nil, fmt.Errorf("%w: 5G 射频下未找到主 AP 接口节", ErrInterfaceNotFound)
	}

	target5Ch := req.Recommended5GCh
	if !valid5GChannels[target5Ch] || isDFSChannel(target5Ch) {
		target5Ch = 149
	}
	target5W := "HE80"
	if req.Preferred5GWidth == "HE160" {
		target5W = "HE160"
	}

	ssid := src.opt("ssid")
	enc := cmp.Or(src.opt("encryption"), "sae-mixed")
	netName := cmp.Or(src.opt("network"), "lan")
	key := src.opt("key")
	if ssid == "" {
		return nil, nil, nil, fmt.Errorf("%w: 源接口 %q 未配置 SSID", ErrInvalidRequest, srcName)
	}

	ops := []uciOp{
		{Key: "wireless." + r5.Device + ".disabled", Value: "0"},
		{Key: "wireless." + r5.Device + ".channel", Value: strconv.Itoa(target5Ch)},
		{Key: "wireless." + r5.Device + ".htmode", Value: target5W},
		{Key: "wireless." + targetSecName + ".disabled", Value: "0"},
		{Key: "wireless." + targetSecName + ".ssid", Value: ssid},
		{Key: "wireless." + targetSecName + ".encryption", Value: enc},
		{Key: "wireless." + targetSecName + ".network", Value: netName},
		{Key: "wireless." + targetSecName + ".ieee80211k", Value: "1"},
		{Key: "wireless." + srcName + ".ieee80211k", Value: "1"},
	}
	if key != "" {
		// 仅通过参数数组传给 uci set（不经 shell），且绝不写入 OptimizationStep 摘要
		ops = append(ops, uciOp{Key: "wireless." + targetSecName + ".key", Value: key})
	}

	changes := []OptimizationStep{
		{
			Target: r5.Device + " (5G)",
			Field:  "射频配置",
			Before: fmt.Sprintf("%s / %s / %s", boolState(!r5.Disabled), r5.Channel, r5.HTMode),
			After:  fmt.Sprintf("开启 / 信道 %d (非DFS) / %s", target5Ch, target5W),
			Reason: "启用 5G Wi-Fi 6 高速射频并锁定非 DFS 信道",
		},
		{
			Target: fmt.Sprintf("5G 热点 (%s)", targetSecName),
			Field:  "双频合一",
			Before: fmt.Sprintf("%s (%s)", st.IfaceBySec[targetSecName].opt("ssid"), st.IfaceBySec[targetSecName].opt("network")),
			After:  fmt.Sprintf("同名「%s」/ 同加密(%s) / 同网桥(%s) / 802.11k", ssid, enc, netName),
			Reason: "复用 2.4G 原密码与网桥，实现双频无缝漫游",
		},
	}

	expected := collectExpectedBridges(st, map[string]string{targetSecName: netName}, map[string]bool{r5.Device: true, src.opt("device"): true})
	return ops, changes, expected, nil
}

func buildAutoOptimizeOps(ov *Overview, st *probeState, req ApplyRequest) ([]uciOp, []OptimizationStep, map[string][]string, error) {
	var ops []uciOp
	var changes []OptimizationStep
	ifaceNetOverride := make(map[string]string)
	enableRadios := make(map[string]bool)

	r2 := findRadioByBand(ov, "2g")
	r5 := findRadioByBand(ov, "5g")

	if r2 != nil && !r2.Disabled {
		enableRadios[r2.Device] = true
		if r2.OverlappingCh || r2.Channel == "auto" {
			ch := req.Recommended2GCh
			if !isNonOverlapping2GChannel(ch) {
				ch = 1
			}
			ops = append(ops, uciOp{Key: "wireless." + r2.Device + ".channel", Value: strconv.Itoa(ch)})
			changes = append(changes, OptimizationStep{
				Target: r2.Device + " (2.4G)",
				Field:  "channel",
				Before: fmt.Sprintf("%s (实测 %d)", r2.Channel, r2.CurrentChannel),
				After:  strconv.Itoa(ch),
				Reason: "锁定正交无重叠信道，消除邻频碰撞",
			})
		}
		if strings.Contains(strings.ToUpper(r2.HTMode), "40") {
			ops = append(ops, uciOp{Key: "wireless." + r2.Device + ".htmode", Value: "HE20"})
			changes = append(changes, OptimizationStep{
				Target: r2.Device + " (2.4G)",
				Field:  "htmode",
				Before: r2.HTMode,
				After:  "HE20",
				Reason: "2.4G 固定 20MHz 降低底噪，提升稳定性",
			})
		}
	}

	if r5 != nil {
		if main2G := findPrimary2GMainSSID(ov); main2G != nil {
			mergeOps, mergeChanges, _, err := buildDualBandMergeOps(ov, st, ApplyRequest{
				Action:           "dual_band_merge",
				SourceSection:    main2G.Section,
				Recommended5GCh:  req.Recommended5GCh,
				Preferred5GWidth: req.Preferred5GWidth,
			})
			if err != nil {
				return nil, nil, nil, err
			}
			ops = append(ops, mergeOps...)
			changes = append(changes, mergeChanges...)
			enableRadios[r5.Device] = true
			if targetSec := pickPrimary5GIfaceSection(st, r5.Device); targetSec != "" {
				ifaceNetOverride[targetSec] = main2G.Network
			}
		} else if !r5.Disabled && (r5.DFSChannel || r5.Channel == "auto") {
			enableRadios[r5.Device] = true
			ch := req.Recommended5GCh
			if !valid5GChannels[ch] || isDFSChannel(ch) {
				ch = 149
			}
			w := "HE80"
			if req.Preferred5GWidth == "HE160" {
				w = "HE160"
			}
			ops = append(ops,
				uciOp{Key: "wireless." + r5.Device + ".channel", Value: strconv.Itoa(ch)},
				uciOp{Key: "wireless." + r5.Device + ".htmode", Value: w},
			)
			changes = append(changes, OptimizationStep{
				Target: r5.Device + " (5G)",
				Field:  "channel/htmode",
				Before: fmt.Sprintf("%s (实测 %d) / %s", r5.Channel, r5.CurrentChannel, r5.HTMode),
				After:  fmt.Sprintf("%d (非DFS) / %s", ch, w),
				Reason: "离开 DFS 雷达信道，保障全设备秒连与零闪断",
			})
		}
	}

	// 确保活跃非隔离 SSID 均开启 802.11k
	for _, ss := range ov.SSIDs {
		if !ss.Disabled && !ss.Isolate && !ss.IEEE80211k {
			ops = append(ops, uciOp{Key: "wireless." + ss.Section + ".ieee80211k", Value: "1"})
		}
	}

	expected := collectExpectedBridges(st, ifaceNetOverride, enableRadios)
	return ops, changes, expected, nil
}

func buildTuneRadioOps(ov *Overview, st *probeState, req ApplyRequest) ([]uciOp, []OptimizationStep, map[string][]string, error) {
	if len(req.Radios) == 0 {
		return nil, nil, nil, fmt.Errorf("%w: 未指定需要调整的射频参数", ErrInvalidRequest)
	}
	radioByName := make(map[string]RadioInfo, len(ov.Radios))
	for _, r := range ov.Radios {
		radioByName[r.Device] = r
	}

	var ops []uciOp
	var changes []OptimizationStep
	enableRadios := make(map[string]bool)

	for _, patch := range req.Radios {
		devName := strings.TrimSpace(patch.Device)
		if !isValidUCISectionName(devName) {
			return nil, nil, nil, fmt.Errorf("%w: 非法射频名称 %q", ErrInvalidRequest, patch.Device)
		}
		cur, ok := radioByName[devName]
		if !ok {
			return nil, nil, nil, fmt.Errorf("%w: %q", ErrRadioNotFound, devName)
		}

		if patch.Disabled != nil {
			val := "0"
			if *patch.Disabled {
				val = "1"
			} else {
				enableRadios[devName] = true
			}
			ops = append(ops, uciOp{Key: "wireless." + devName + ".disabled", Value: val})
			changes = append(changes, OptimizationStep{
				Target: devName,
				Field:  "disabled",
				Before: boolState(!cur.Disabled),
				After:  boolState(!*patch.Disabled),
				Reason: "手动调整射频开关",
			})
		} else if !cur.Disabled {
			enableRadios[devName] = true
		}

		if ch := strings.TrimSpace(patch.Channel); ch != "" {
			if err := validateChannelForBand(cur.Band, ch); err != nil {
				return nil, nil, nil, err
			}
			ops = append(ops, uciOp{Key: "wireless." + devName + ".channel", Value: ch})
			changes = append(changes, OptimizationStep{
				Target: devName,
				Field:  "channel",
				Before: cur.Channel,
				After:  ch,
				Reason: "手动调整无线信道",
			})
		}

		if hm := strings.TrimSpace(patch.HTMode); hm != "" {
			if err := validateHTModeForBand(cur.Band, hm); err != nil {
				return nil, nil, nil, err
			}
			ops = append(ops, uciOp{Key: "wireless." + devName + ".htmode", Value: hm})
			changes = append(changes, OptimizationStep{
				Target: devName,
				Field:  "htmode",
				Before: cur.HTMode,
				After:  hm,
				Reason: "手动调整无线频宽",
			})
		}

		if patch.TxPowerPct != nil {
			p := *patch.TxPowerPct
			if p < 10 || p > 100 {
				return nil, nil, nil, fmt.Errorf("%w: 发射功率需在 10~100 之间", ErrInvalidRequest)
			}
			ops = append(ops, uciOp{Key: "wireless." + devName + ".txpower", Value: strconv.Itoa(p)})
			changes = append(changes, OptimizationStep{
				Target: devName,
				Field:  "txpower",
				Before: strconv.Itoa(cur.TxPowerPct) + "%",
				After:  strconv.Itoa(p) + "%",
				Reason: "手动调整射频功率",
			})
		}

		if patch.IEEE80211k != nil {
			val := "0"
			if *patch.IEEE80211k {
				val = "1"
			}
			for _, sec := range st.WirelessUCI.byType("wifi-iface") {
				if sec.opt("device") == devName && strings.ToLower(cmp.Or(sec.opt("mode"), "ap")) == "ap" {
					ops = append(ops, uciOp{Key: "wireless." + sec.Name + ".ieee80211k", Value: val})
				}
			}
			changes = append(changes, OptimizationStep{
				Target: devName,
				Field:  "ieee80211k",
				Before: "-",
				After:  boolState(*patch.IEEE80211k),
				Reason: "调整 802.11k 漫游邻居报告",
			})
		}
	}

	expected := collectExpectedBridges(st, nil, enableRadios)
	return ops, changes, expected, nil
}

func validateChannelForBand(band, ch string) error {
	if hasShellMetaOrControl(ch) {
		return fmt.Errorf("%w: 信道包含非法字符", ErrInvalidRequest)
	}
	if ch == "auto" {
		return nil
	}
	n, err := strconv.Atoi(ch)
	if err != nil {
		return fmt.Errorf("%w: 非法信道 %q", ErrInvalidRequest, ch)
	}
	if band == "5g" {
		if !valid5GChannels[n] {
			return fmt.Errorf("%w: 5G 不支持信道 %d", ErrInvalidRequest, n)
		}
		return nil
	}
	if !valid2GChannels[n] {
		return fmt.Errorf("%w: 2.4G 不支持信道 %d", ErrInvalidRequest, n)
	}
	return nil
}

func validateHTModeForBand(band, hm string) error {
	if hasShellMetaOrControl(hm) {
		return fmt.Errorf("%w: 频宽包含非法字符", ErrInvalidRequest)
	}
	if band == "5g" {
		if !validHTModes5G[hm] {
			return fmt.Errorf("%w: 5G 不支持频宽 %q", ErrInvalidRequest, hm)
		}
		return nil
	}
	if !validHTModes2G[hm] {
		return fmt.Errorf("%w: 2.4G 不支持频宽 %q", ErrInvalidRequest, hm)
	}
	return nil
}

func collectExpectedBridges(st *probeState, ifaceNetOverride map[string]string, enabledRadios map[string]bool) map[string][]string {
	out := make(map[string][]string)
	for _, sec := range st.WirelessUCI.byType("wifi-iface") {
		if strings.ToLower(cmp.Or(sec.opt("mode"), "ap")) != "ap" {
			continue
		}
		devName := sec.opt("device")
		netName := sec.opt("network")
		willBeEnabled := sec.opt("disabled") != "1"
		if override, ok := ifaceNetOverride[sec.Name]; ok {
			netName = override
			willBeEnabled = true
		}
		dev := st.RadioByDev[devName]
		radioUp := enabledRadios[devName] || (dev != nil && dev.opt("disabled") != "1")
		if !willBeEnabled || !radioUp {
			continue
		}
		br := st.NetToBridge[netName]
		if base, _, ok := strings.Cut(br, "."); ok {
			// OpenWrt DSA Bridge-VLAN（如 br-lan.27 / br-lan.28）在 brctl show 中挂载于父网桥 br-lan
			br = base
		}
		ifName := st.IfNameBySec[sec.Name]
		if br != "" && ifName != "" {
			out[br] = append(out[br], ifName)
		}
	}
	return out
}

func boolState(on bool) string {
	if on {
		return "开启"
	}
	return "关闭"
}

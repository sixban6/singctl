// 文件职责：实现按需周边无线信道干扰扫描解析、隐私脱敏与 2.4G/5G 最优无干扰信道评分推荐算法。
package wifiopt

import (
	"context"
	"fmt"
	"math"
	"regexp"
	"slices"
	"strings"
)

var (
	reScanChannel = regexp.MustCompile(`Channel:\s*(\d+)`)
	reScanSignal  = regexp.MustCompile(`Signal:\s*(-?\d+)\s*dBm`)
)

type scannedCell struct {
	Channel   int
	SignalDBm int
}

// Scan 按需扫描周边 2.4G/5G 信道干扰并返回脱敏后的信道评分与最优推荐。
func (s *Service) Scan(ctx context.Context) (*ScanResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	st, supported, _, err := s.probe(ctx)
	if err != nil {
		return nil, err
	}
	if !supported {
		return nil, ErrUnsupported
	}

	var if2G, if5G string
	cur2G, cur5G := 0, 0
	for _, sec := range st.WirelessUCI.byType("wifi-iface") {
		if sec.opt("disabled") == "1" {
			continue
		}
		dev := st.RadioByDev[sec.opt("device")]
		if dev == nil || dev.opt("disabled") == "1" {
			continue
		}
		band := normalizeBand(dev.opt("band"), dev.opt("htmode"), parseInt(dev.opt("channel")))
		ifName := st.IfNameBySec[sec.Name]
		if ifName == "" {
			continue
		}
		if band == "2g" && if2G == "" {
			if2G = ifName
			cur2G = st.Iwinfo[ifName].Channel
		}
		if band == "5g" && if5G == "" {
			if5G = ifName
			cur5G = st.Iwinfo[ifName].Channel
		}
	}

	res := &ScanResult{
		ScannedAt:  s.now().Unix(),
		Channels2G: []ChannelStat{},
		Channels5G: []ChannelStat{},
	}

	if if2G != "" {
		raw, scanErr := s.runCmd(ctx, "iwinfo", if2G, "scan")
		if scanErr != nil {
			res.Warnings = append(res.Warnings, "2.4G 扫描返回告警: "+scanErr.Error())
		}
		cells := parseScanCells(string(raw))
		res.Channels2G, res.Recommended2GCh = score2GChannels(cells, cur2G)
	}

	if if5G != "" {
		raw, scanErr := s.runCmd(ctx, "iwinfo", if5G, "scan")
		if scanErr != nil {
			res.Warnings = append(res.Warnings, "5G 扫描返回告警: "+scanErr.Error())
		}
		cells := parseScanCells(string(raw))
		res.Channels5G, res.Recommended5GCh = score5GChannels(cells, cur5G)
	} else {
		// 5G 未开启时仍提供默认非 DFS 推荐信道，避免前端缺失推荐值
		res.Channels5G, res.Recommended5GCh = score5GChannels(nil, cur5G)
	}

	var parts []string
	if res.Recommended2GCh > 0 {
		parts = append(parts, fmt.Sprintf("2.4G 推荐正交信道 %d", res.Recommended2GCh))
	}
	if res.Recommended5GCh > 0 {
		parts = append(parts, fmt.Sprintf("5G 推荐非 DFS 信道 %d", res.Recommended5GCh))
	}
	res.Summary = strings.Join(parts, "；")
	return res, nil
}

// parseScanCells 仅提取信道号与信号强度，彻底丢弃邻居 ESSID 与 MAC 地址（严格隐私脱敏）。
func parseScanCells(raw string) []scannedCell {
	var cells []scannedCell
	curCh, curSig := 0, 0
	flush := func() {
		if curCh > 0 {
			if curSig == 0 {
				curSig = -95
			}
			cells = append(cells, scannedCell{Channel: curCh, SignalDBm: curSig})
		}
		curCh, curSig = 0, 0
	}
	for line := range strings.SplitSeq(raw, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "Cell ") {
			flush()
			continue
		}
		if m := reScanChannel.FindStringSubmatch(trimmed); len(m) == 2 {
			curCh = parseInt(m[1])
		}
		if m := reScanSignal.FindStringSubmatch(trimmed); len(m) == 2 {
			curSig = parseInt(m[1])
		}
	}
	flush()
	return cells
}

func signalWeight(dbm int) float64 {
	// -100 dBm -> ~0.1, -90 -> 1.0, -70 -> 10, -50 -> 50
	if dbm <= -100 {
		return 0.1
	}
	if dbm >= -30 {
		return 100
	}
	return math.Pow(10, float64(dbm+95)/22.0)
}

func score2GChannels(cells []scannedCell, currentCh int) ([]ChannelStat, int) {
	countMap := make(map[int]int)
	strongestMap := make(map[int]int)
	for _, c := range cells {
		if c.Channel < 1 || c.Channel > 13 {
			continue
		}
		countMap[c.Channel]++
		if cur, ok := strongestMap[c.Channel]; !ok || c.SignalDBm > cur {
			strongestMap[c.Channel] = c.SignalDBm
		}
	}

	stats := make([]ChannelStat, 0, 13)
	bestCh := 1
	bestScore := math.MaxFloat64

	for ch := 1; ch <= 13; ch++ {
		// 计算同频 + 邻频泄漏综合干扰分（距离 1~3 信道存在严重非正交碰撞权重）
		score := 0.0
		for _, c := range cells {
			if c.Channel < 1 || c.Channel > 13 {
				continue
			}
			dist := c.Channel - ch
			if dist < 0 {
				dist = -dist
			}
			if dist > 4 {
				continue
			}
			w := signalWeight(c.SignalDBm)
			switch dist {
			case 0:
				score += w
			case 1:
				score += w * 1.15 // 邻频碰撞破坏力更大
			case 2:
				score += w * 0.85
			case 3:
				score += w * 0.45
			case 4:
				score += w * 0.15
			}
		}
		score = math.Round(score*10) / 10
		level := "clean"
		if score >= 25 || countMap[ch] >= 4 {
			level = "busy"
		} else if score >= 6 || countMap[ch] >= 2 {
			level = "moderate"
		}

		nonOverlap := isNonOverlapping2GChannel(ch)
		if nonOverlap && score < bestScore {
			bestScore = score
			bestCh = ch
		}

		stats = append(stats, ChannelStat{
			Channel:        ch,
			Band:           "2g",
			APCount:        countMap[ch],
			StrongestDBm:   strongestMap[ch],
			Score:          score,
			Level:          level,
			NonOverlapping: nonOverlap,
			Current:        ch == currentCh,
		})
	}

	for i := range stats {
		if stats[i].Channel == bestCh {
			stats[i].Recommended = true
		}
	}
	return stats, bestCh
}

func score5GChannels(cells []scannedCell, currentCh int) ([]ChannelStat, int) {
	candidates := []int{36, 40, 44, 48, 52, 56, 60, 64, 149, 153, 157, 161, 165}
	countMap := make(map[int]int)
	strongestMap := make(map[int]int)
	for _, c := range cells {
		if !slices.Contains(candidates, c.Channel) {
			continue
		}
		countMap[c.Channel]++
		if cur, ok := strongestMap[c.Channel]; !ok || c.SignalDBm > cur {
			strongestMap[c.Channel] = c.SignalDBm
		}
	}

	stats := make([]ChannelStat, 0, len(candidates))
	// 优先选择 HE80 主信道（149 优先于 36，高功率无 DFS）
	preferredOrder := []int{149, 153, 157, 161, 36, 40, 44, 48}
	bestCh := 149
	bestScore := math.MaxFloat64

	for _, ch := range candidates {
		score := 0.0
		for _, c := range cells {
			if c.Channel == ch {
				score += signalWeight(c.SignalDBm)
			}
		}
		dfs := isDFSChannel(ch)
		if dfs {
			score += 200 // 强惩罚 DFS 信道
		}
		score = math.Round(score*10) / 10
		level := "clean"
		if dfs || score >= 25 || countMap[ch] >= 3 {
			level = "busy"
		} else if score >= 5 || countMap[ch] >= 1 {
			level = "moderate"
		}
		stats = append(stats, ChannelStat{
			Channel:        ch,
			Band:           "5g",
			APCount:        countMap[ch],
			StrongestDBm:   strongestMap[ch],
			Score:          score,
			Level:          level,
			NonOverlapping: true,
			DFS:            dfs,
			Current:        ch == currentCh,
		})
	}

	scoreByCh := make(map[int]float64, len(stats))
	for _, st := range stats {
		scoreByCh[st.Channel] = st.Score
	}
	for _, ch := range preferredOrder {
		sc := scoreByCh[ch]
		if sc < bestScore {
			bestScore = sc
			bestCh = ch
		}
	}
	for i := range stats {
		if stats[i].Channel == bestCh {
			stats[i].Recommended = true
		}
	}
	return stats, bestCh
}

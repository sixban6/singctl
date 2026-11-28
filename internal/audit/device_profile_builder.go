// 文件职责：基于 24h 分钟位图与 7 天日汇总合成单设备行为画像、会话切分与确定性特征标签。
package audit

import (
	"cmp"
	"context"
	"fmt"
	"math"
	"os"
	"slices"
	"strings"
	"time"

	"singctl/internal/config"
)

const sessionMergeGapMinutes = 3

// BuildDeviceProfile 基于 24h 位图与 7 天历史日汇总构建单台局域网设备的行为画像报告（纯内存聚合，零外部 CLI/网络调用）。
func (c *Collector) BuildDeviceProfile(ctx context.Context, cfg *config.Config, deviceIP string, rng DeviceProfileRange) *DeviceProfileReport {
	_ = ctx
	c.mu.Lock()
	defer c.mu.Unlock()

	now := c.currentTimeLocked()
	if rng != ProfileRange7d {
		rng = ProfileRange24h
	}
	normIP := strings.TrimSpace(deviceIP)

	state := c.loadStateLocked(now.Unix())
	devDir := c.resolveLANDevicesLocked()
	hist := c.loadProfileHistoryLocked(now)

	rep := newEmptyDeviceProfileReport(normIP, rng, now, c.profileHistoryPath, hist, c.effectiveProfileHistoryMaxBytesLocked())
	identity := resolveProfileDeviceIdentity(cfg, state, hist, devDir, normIP)
	rep.DeviceName = identity.name
	rep.DeviceMAC = identity.mac
	rep.DeviceRole = identity.role
	rep.IsNatSubRouter = detectNatSubRouter(state, normIP, identity.role)

	loc := now.Location()
	if rng == ProfileRange7d {
		populateProfileFrom7d(rep, state, hist, normIP, identity.mac, now, loc)
	} else {
		populateProfileFrom24h(rep, state, normIP, identity.mac, now, loc)
	}
	finalizeProfileMetrics(rep)
	return rep
}

func newEmptyDeviceProfileReport(
	deviceIP string,
	rng DeviceProfileRange,
	now time.Time,
	histPath string,
	hist *persistedProfileHistory,
	maxHistBytes int,
) *DeviceProfileReport {
	hourly := make([]DeviceHourStat, 24)
	for h := range 24 {
		hourly[h] = DeviceHourStat{Hour: h}
	}
	var histBytes int
	if histPath != "" {
		if fi, err := os.Stat(histPath); err == nil {
			histBytes = int(fi.Size())
		}
	}
	histDays := 0
	if hist != nil {
		histDays = len(hist.Days)
	}
	return &DeviceProfileReport{
		DeviceIP:       deviceIP,
		DeviceName:     deviceIP,
		DeviceRole:     "unknown",
		Range:          rng,
		GeneratedAt:    now.Format("2006-01-02 15:04:05"),
		PersonaTags:    []DevicePersonaTag{},
		Categories:     []DeviceCategoryStat{},
		TopApps:        []DeviceAppStat{},
		SystemApps:     []DeviceAppStat{},
		HourlyTimeline: hourly,
		DailyTrend:     []DeviceDayStat{},
		Storage: DeviceProfileStorage{
			RetentionDays:   profileRetentionDays,
			HistoryDays:     histDays,
			HistoryBytes:    histBytes,
			MaxHistoryBytes: maxHistBytes,
			AutoCleanup:     true,
		},
	}
}

type resolvedProfileIdentity struct {
	name string
	mac  string
	role string
}

func resolveProfileDeviceIdentity(
	cfg *config.Config,
	state *persistedAuditState,
	hist *persistedProfileHistory,
	devDir map[string]lanDeviceInfo,
	ip string,
) resolvedProfileIdentity {
	var rawName, mac string
	if info, ok := devDir[ip]; ok {
		rawName = info.Name
		mac = strings.ToLower(strings.TrimSpace(info.MAC))
	}
	if state != nil {
		if dp := findPersistedDeviceProfile(state.Profiles, ip, mac); dp != nil {
			if rawName == "" {
				rawName = dp.DeviceName
			}
			if mac == "" {
				mac = strings.ToLower(strings.TrimSpace(dp.DeviceMAC))
			}
		}
	}
	if (rawName == "" || mac == "") && hist != nil {
		for _, snap := range hist.Days {
			if snap == nil {
				continue
			}
			if dr := findDailyDeviceRollup(snap.Devices, ip, mac); dr != nil {
				if rawName == "" {
					rawName = dr.DeviceName
				}
				if mac == "" {
					mac = strings.ToLower(strings.TrimSpace(dr.DeviceMAC))
				}
			}
		}
	}
	friendly := FormatFriendlyDeviceName(cfg, ip, mac, cmp.Or(rawName, ip))
	return resolvedProfileIdentity{
		name: cmp.Or(friendly, ip),
		mac:  mac,
		role: InferDeviceRole(friendly),
	}
}

func detectNatSubRouter(state *persistedAuditState, ip, role string) bool {
	if role == "router" {
		return true
	}
	if state == nil || len(state.Flows) < 20 {
		return false
	}
	count := 0
	for _, f := range state.Flows {
		if f != nil && f.DeviceIP == ip {
			count++
		}
	}
	return float64(count)/float64(len(state.Flows)) >= 0.7
}

func findPersistedDeviceProfile(profiles map[string]*persistedDeviceProfile, ip, mac string) *persistedDeviceProfile {
	if len(profiles) == 0 {
		return nil
	}
	if p := profiles[ip]; p != nil {
		return p
	}
	for _, p := range profiles {
		if p != nil && (p.DeviceIP == ip || (mac != "" && strings.EqualFold(p.DeviceMAC, mac))) {
			return p
		}
	}
	return nil
}

func findDailyDeviceRollup(devices map[string]*dailyDeviceRollup, ip, mac string) *dailyDeviceRollup {
	if len(devices) == 0 {
		return nil
	}
	if d := devices[ip]; d != nil {
		return d
	}
	for _, d := range devices {
		if d != nil && (d.DeviceIP == ip || (mac != "" && strings.EqualFold(d.DeviceMAC, mac))) {
			return d
		}
	}
	return nil
}

func extractActiveBitMinutes(app *persistedAppBitset, curMin int64) []int64 {
	if app == nil || app.EpochMinute == 0 {
		return nil
	}
	startMin := curMin - (profileDayMinutes - 1)
	if startMin < 0 {
		startMin = 0
	}
	if app.EpochMinute < startMin {
		return nil
	}
	var out []int64
	for m := startMin; m <= app.EpochMinute; m++ {
		if hasBit(app.Bits, m) {
			out = append(out, m)
		}
	}
	return out
}

func summarizeBitMinutes(mins []int64, loc *time.Location) (fgMins, sessions, avgSess, longest int, peakPeriod string) {
	fgMins = len(mins)
	if fgMins == 0 {
		return 0, 0, 0, 0, ""
	}
	var periodCounts [4]int
	sessStart := mins[0]
	prev := mins[0]
	sessions = 1
	activeInSess := 1
	longest = 1

	countPeriod := func(minVal int64) {
		hr := time.Unix(minVal*60, 0).In(loc).Hour()
		periodCounts[hr/6]++
	}
	countPeriod(mins[0])

	for i := 1; i < len(mins); i++ {
		m := mins[i]
		countPeriod(m)
		if m-prev <= sessionMergeGapMinutes {
			activeInSess++
			span := int(m - sessStart + 1)
			longest = max(longest, activeInSess, min(span, activeInSess+sessionMergeGapMinutes))
		} else {
			sessions++
			sessStart = m
			activeInSess = 1
		}
		prev = m
	}
	avgSess = max(1, int(math.Round(float64(fgMins)/float64(sessions))))
	bestIdx := 0
	for i := 1; i < 4; i++ {
		if periodCounts[i] > periodCounts[bestIdx] {
			bestIdx = i
		}
	}
	periodNames := [4]string{"凌晨 00-06", "上午 06-12", "下午 12-18", "晚间 18-24"}
	peakPeriod = periodNames[bestIdx]
	return fgMins, sessions, avgSess, longest, peakPeriod
}

func populateProfileFrom24h(rep *DeviceProfileReport, state *persistedAuditState, ip, mac string, now time.Time, loc *time.Location) {
	if state == nil {
		return
	}
	devProf := findPersistedDeviceProfile(state.Profiles, ip, mac)
	if devProf == nil {
		return
	}
	curMin := now.Unix() / 60

	// 按小时填充流量统计（注意淘汰过期 >24h 小时桶）
	hourAge := (curMin / 60) - (devProf.EpochMinute / 60)
	if devProf.EpochMinute > 0 && hourAge < 24 {
		for h := range 24 {
			rep.HourlyTimeline[h].Bytes = int64(devProf.HourlyKB[h]) * 1024
		}
	}

	devFgMinUnion := make(map[int64]struct{})
	var proxySum, directSum int64 = devProf.ProxyBytes, devProf.DirectBytes

	for _, app := range devProf.Apps {
		if app == nil {
			continue
		}
		mins := extractActiveBitMinutes(app, curMin)
		fgMins, sessions, avgSess, longest, peakPeriod := summarizeBitMinutes(mins, loc)
		if !app.IsInfra {
			for _, m := range mins {
				devFgMinUnion[m] = struct{}{}
			}
		}

		stat := DeviceAppStat{
			AppName:           app.AppName,
			Category:          app.Category,
			CategoryLabel:     CategoryDisplayLabel(app.Category),
			IsInfra:           app.IsInfra,
			ForegroundMinutes: fgMins,
			BackgroundMinutes: app.BgMinutes,
			Sessions:          sessions,
			AvgSessionMin:     avgSess,
			LongestSessionMin: longest,
			UploadBytes:       app.UploadBytes,
			DownloadBytes:     app.DownloadBytes,
			PeakPeriod:        peakPeriod,
			SampleTargets:     slices.Clone(app.SampleTargets),
		}
		if app.LastSeenUnix > 0 {
			stat.LastSeen = time.Unix(app.LastSeenUnix, 0).In(loc).Format("15:04:05")
		}
		rep.UploadBytes += app.UploadBytes
		rep.DownloadBytes += app.DownloadBytes
		rep.TotalBackgroundMinutes += app.BgMinutes

		if app.IsInfra || fgMins == 0 {
			rep.SystemApps = append(rep.SystemApps, stat)
		} else {
			rep.TopApps = append(rep.TopApps, stat)
		}
	}

	// 从去重后的用户前景分钟集合反推每小时活跃分钟（保证设备小时柱总和等于去重总前台时长）
	for m := range devFgMinUnion {
		h := time.Unix(m*60, 0).In(loc).Hour()
		if rep.HourlyTimeline[h].ForegroundMinutes < 60 {
			rep.HourlyTimeline[h].ForegroundMinutes++
		}
	}
	rep.TotalForegroundMinutes = len(devFgMinUnion)

	// 若未产生应用级流量但设备级别有统计，保底使用设备累加总量
	if rep.UploadBytes+rep.DownloadBytes == 0 && proxySum+directSum > 0 {
		rep.DownloadBytes = proxySum + directSum
	}
	if proxySum+directSum > 0 {
		rep.ProxySharePct = math.Round((float64(proxySum)/float64(proxySum+directSum))*1000) / 10
	}
}

func populateProfileFrom7d(rep *DeviceProfileReport, state *persistedAuditState, hist *persistedProfileHistory, ip, mac string, now time.Time, loc *time.Location) {
	todayStr := now.Format("2006-01-02")
	curMin := now.Unix() / 60
	todayStartMin := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, loc).Unix() / 60

	// 如 live state 中存在今天的新鲜位图，提前提取（兜底跨进程读取未及时刷盘的今天实时增量）
	var liveTodayDev *persistedDeviceProfile
	liveTodayAppFg := make(map[string]int)
	if state != nil {
		liveTodayDev = findPersistedDeviceProfile(state.Profiles, ip, mac)
		if liveTodayDev != nil {
			for _, app := range liveTodayDev.Apps {
				if app == nil {
					continue
				}
				cnt := 0
				for _, m := range extractActiveBitMinutes(app, curMin) {
					if m >= todayStartMin {
						cnt++
					}
				}
				if cnt > 0 {
					liveTodayAppFg[app.AppName] = cnt
				}
			}
		}
	}

	aggApps := make(map[string]*DeviceAppStat)
	var proxySum, directSum int64

	// 构建近 7 天日期序列（从最早到今天）
	rep.DailyTrend = make([]DeviceDayStat, 0, profileRetentionDays)
	for offset := profileRetentionDays - 1; offset >= 0; offset-- {
		dStr := now.AddDate(0, 0, -offset).Format("2006-01-02")
		dayStat := DeviceDayStat{Date: dStr}

		var dr *dailyDeviceRollup
		if hist != nil && hist.Days[dStr] != nil {
			dr = findDailyDeviceRollup(hist.Days[dStr].Devices, ip, mac)
		}

		var topDayApp string
		var topDayMins int

		if dr != nil {
			dayStat.ForegroundMinutes = dr.FgMins
			dayStat.UploadBytes = dr.UploadBytes
			dayStat.DownloadBytes = dr.DownloadBytes
			proxySum += dr.ProxyBytes
			directSum += dr.DirectBytes

			for h := range 24 {
				rep.HourlyTimeline[h].ForegroundMinutes += int(dr.HourlyActiveMins[h])
			}

			for _, a := range dr.Apps {
				if a == nil {
					continue
				}
				fg := a.FgMins
				if dStr == todayStr && liveTodayAppFg[a.AppName] > fg {
					fg = liveTodayAppFg[a.AppName]
				}
				if !a.IsInfra && fg > topDayMins {
					topDayMins = fg
					topDayApp = a.AppName
				}

				cur := aggApps[a.AppName]
				if cur == nil {
					cur = &DeviceAppStat{
						AppName:       a.AppName,
						Category:      a.Category,
						CategoryLabel: CategoryDisplayLabel(a.Category),
						IsInfra:       a.IsInfra,
						PeakPeriod:    a.PeakPeriod,
					}
					aggApps[a.AppName] = cur
				}
				cur.ForegroundMinutes += fg
				cur.BackgroundMinutes += a.BgMins
				cur.Sessions += max(0, a.Sessions)
				cur.LongestSessionMin = max(cur.LongestSessionMin, a.LongestMin)
				cur.UploadBytes += a.UploadBytes
				cur.DownloadBytes += a.DownloadBytes
				if cur.PeakPeriod == "" {
					cur.PeakPeriod = a.PeakPeriod
				}
			}
			if dStr == todayStr && topDayMins > dayStat.ForegroundMinutes {
				dayStat.ForegroundMinutes = topDayMins
			}
		} else if dStr == todayStr && liveTodayDev != nil {
			// 纯跨进程未落盘首日兜底：直接合并 liveTodayDev
			var tmpRep DeviceProfileReport
			tmpRep.HourlyTimeline = make([]DeviceHourStat, 24)
			populateProfileFrom24h(&tmpRep, state, ip, mac, now, loc)
			dayStat.ForegroundMinutes = tmpRep.TotalForegroundMinutes
			dayStat.UploadBytes = tmpRep.UploadBytes
			dayStat.DownloadBytes = tmpRep.DownloadBytes
			for h := range 24 {
				rep.HourlyTimeline[h].ForegroundMinutes += tmpRep.HourlyTimeline[h].ForegroundMinutes
			}
			for _, list := range [][]DeviceAppStat{tmpRep.TopApps, tmpRep.SystemApps} {
				for _, a := range list {
					if !a.IsInfra && a.ForegroundMinutes > topDayMins {
						topDayMins = a.ForegroundMinutes
						topDayApp = a.AppName
					}
					cur := aggApps[a.AppName]
					if cur == nil {
						cp := a
						aggApps[a.AppName] = &cp
					} else {
						cur.ForegroundMinutes += a.ForegroundMinutes
						cur.BackgroundMinutes += a.BackgroundMinutes
						cur.Sessions += a.Sessions
						cur.LongestSessionMin = max(cur.LongestSessionMin, a.LongestSessionMin)
						cur.UploadBytes += a.UploadBytes
						cur.DownloadBytes += a.DownloadBytes
					}
				}
			}
		}

		dayStat.TopApp = topDayApp
		dayStat.TopAppMinutes = topDayMins
		rep.TotalForegroundMinutes += dayStat.ForegroundMinutes
		rep.UploadBytes += dayStat.UploadBytes
		rep.DownloadBytes += dayStat.DownloadBytes
		rep.DailyTrend = append(rep.DailyTrend, dayStat)
	}

	for _, stat := range aggApps {
		if stat.Sessions > 0 && stat.ForegroundMinutes > 0 {
			stat.AvgSessionMin = max(1, int(math.Round(float64(stat.ForegroundMinutes)/float64(stat.Sessions))))
		}
		rep.TotalBackgroundMinutes += stat.BackgroundMinutes
		if stat.IsInfra || stat.ForegroundMinutes == 0 {
			rep.SystemApps = append(rep.SystemApps, *stat)
		} else {
			rep.TopApps = append(rep.TopApps, *stat)
		}
	}

	if proxySum+directSum > 0 {
		rep.ProxySharePct = math.Round((float64(proxySum)/float64(proxySum+directSum))*1000) / 10
	}
}

func sortDeviceAppStats(list []DeviceAppStat) {
	slices.SortFunc(list, func(a, b DeviceAppStat) int {
		if c := cmp.Compare(b.ForegroundMinutes, a.ForegroundMinutes); c != 0 {
			return c
		}
		if c := cmp.Compare(b.DownloadBytes+b.UploadBytes, a.DownloadBytes+a.UploadBytes); c != 0 {
			return c
		}
		if c := cmp.Compare(b.BackgroundMinutes, a.BackgroundMinutes); c != 0 {
			return c
		}
		return cmp.Compare(a.AppName, b.AppName)
	})
}

func finalizeProfileMetrics(rep *DeviceProfileReport) {
	sortDeviceAppStats(rep.TopApps)
	sortDeviceAppStats(rep.SystemApps)

	// 计算活跃 App 数（至少有前景停留或 64KB 以上流量）
	activeApps := 0
	for _, a := range rep.TopApps {
		if a.ForegroundMinutes > 0 || a.UploadBytes+a.DownloadBytes >= 64*1024 {
			activeApps++
		}
	}
	rep.ActiveAppCount = activeApps

	// 若多 App 并发叠加导致 TopApps 与 TotalForegroundMinutes 不完全一致但均大于 0，保留合理展示；
	// 品类占比聚合（基于非系统底座的应用）
	catMins := make(map[AppCategory]int)
	catBytes := make(map[AppCategory]int64)
	totalCatMins := 0
	var totalCatBytes int64
	for _, a := range rep.TopApps {
		catMins[a.Category] += a.ForegroundMinutes
		totalCatMins += a.ForegroundMinutes
		b := a.UploadBytes + a.DownloadBytes
		catBytes[a.Category] += b
		totalCatBytes += b
	}
	for cat, bytesSum := range catBytes {
		mins := catMins[cat]
		var pct float64
		if totalCatMins > 0 {
			pct = math.Round((float64(mins)/float64(totalCatMins))*1000) / 10
		} else if totalCatBytes > 0 {
			pct = math.Round((float64(bytesSum)/float64(totalCatBytes))*1000) / 10
		}
		rep.Categories = append(rep.Categories, DeviceCategoryStat{
			Category: cat,
			Label:    CategoryDisplayLabel(cat),
			Minutes:  mins,
			SharePct: pct,
			Bytes:    bytesSum,
		})
	}
	slices.SortFunc(rep.Categories, func(a, b DeviceCategoryStat) int {
		if c := cmp.Compare(b.Minutes, a.Minutes); c != 0 {
			return c
		}
		if c := cmp.Compare(b.Bytes, a.Bytes); c != 0 {
			return c
		}
		return cmp.Compare(a.Label, b.Label)
	})

	// 活跃高峰小时
	bestHour := -1
	bestMin := 0
	nightMin := 0
	for _, h := range rep.HourlyTimeline {
		if h.ForegroundMinutes > bestMin {
			bestMin = h.ForegroundMinutes
			bestHour = h.Hour
		}
		if h.Hour >= 1 && h.Hour <= 5 {
			nightMin += h.ForegroundMinutes
		}
	}
	if bestHour >= 0 {
		rep.PeakHourLabel = fmt.Sprintf("%s %02d:00–%02d:00", formatDayPeriod(bestHour), bestHour, (bestHour+1)%24)
	}

	// 确定性设备性格/行为标签
	if rep.IsNatSubRouter {
		rep.PersonaTags = append(rep.PersonaTags, DevicePersonaTag{
			ID:     "nat_router",
			Label:  "下级路由 NAT 汇总",
			Tone:   "warn",
			Detail: "当前流量由多台下级终端共用此路由 IP 汇聚而成，建议参考整体倾向或至下级路由查看单机画像",
		})
	}
	if nightMin >= 15 || (rep.TotalForegroundMinutes > 0 && float64(nightMin)/float64(rep.TotalForegroundMinutes) >= 0.25) {
		rep.PersonaTags = append(rep.PersonaTags, DevicePersonaTag{
			ID:     "night_owl",
			Label:  "凌晨夜猫子",
			Tone:   "warn",
			Detail: fmt.Sprintf("凌晨 01:00–05:59 累计存在 %d 分钟主动交互", nightMin),
		})
	}
	for _, c := range rep.Categories {
		switch c.Category {
		case AppCategoryVideo:
			if c.SharePct >= 45 && c.Minutes >= 10 {
				rep.PersonaTags = append(rep.PersonaTags, DevicePersonaTag{
					ID:     "video_heavy",
					Label:  "重度影音",
					Tone:   "accent",
					Detail: fmt.Sprintf("视频娱乐占前景活跃时长的 %.0f%%（%d 分钟）", c.SharePct, c.Minutes),
				})
			}
		case AppCategoryAIDev:
			if c.SharePct >= 30 && c.Minutes >= 10 {
				rep.PersonaTags = append(rep.PersonaTags, DevicePersonaTag{
					ID:     "ai_dev_heavy",
					Label:  "AI / 开发高频",
					Tone:   "ok",
					Detail: fmt.Sprintf("AI 工具与研发类应用占 %.0f%%（%d 分钟）", c.SharePct, c.Minutes),
				})
			}
		case AppCategorySocial:
			if c.SharePct >= 35 && c.Minutes >= 10 {
				rep.PersonaTags = append(rep.PersonaTags, DevicePersonaTag{
					ID:     "social_active",
					Label:  "高频社交",
					Tone:   "accent",
					Detail: fmt.Sprintf("社交互动占前景活跃时长的 %.0f%%", c.SharePct),
				})
			}
		}
	}
	if rep.ProxySharePct >= 50 && rep.UploadBytes+rep.DownloadBytes >= 1024*1024 {
		rep.PersonaTags = append(rep.PersonaTags, DevicePersonaTag{
			ID:     "proxy_heavy",
			Label:  "出海分流高频",
			Tone:   "accent",
			Detail: fmt.Sprintf("%.0f%% 的通信流量经由代理策略组出站", rep.ProxySharePct),
		})
	}
	if rep.TotalBackgroundMinutes >= 20 && rep.TotalBackgroundMinutes > rep.TotalForegroundMinutes*2 {
		rep.PersonaTags = append(rep.PersonaTags, DevicePersonaTag{
			ID:     "high_bg",
			Label:  "后台保活较多",
			Tone:   "neutral",
			Detail: fmt.Sprintf("息屏推送/底座同步累计 %d 分钟，已自动剥离出前台时长", rep.TotalBackgroundMinutes),
		})
	}
}

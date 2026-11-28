// 文件职责：实现 1 分钟环形位图前景活跃度追踪、四维去噪判别、7 天日汇总滚动清理与磁盘体积硬上限保护。
package audit

import (
	"cmp"
	"encoding/json"
	"maps"
	"math"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

const (
	profileHistorySchemaVersion   = 1
	profileHistoryFlushInterval   = 20 * time.Minute
	profileHistoryFlushMinDelta   = 5
	defaultUnclassifiedWebsiteApp = "其他网站 / 服务"
)

type profileConnDelta struct {
	DeviceIP     string
	DeviceName   string
	DeviceMAC    string
	Target       string
	RawHost      string
	DestIP       string
	Rule         string
	Outbound     string
	DeltaUp      int64
	DeltaDown    int64
	IsNewConn    bool
	ArrivalCount int
	IntervalCV   float64
}

// SetProfileHistoryPathForTest 供单元测试显式指定 7 天画像历史存储路径与磁盘体积上限。
func (c *Collector) SetProfileHistoryPathForTest(path string, maxBytes int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.profileHistoryPath = path
	if maxBytes > 0 {
		c.profileHistoryMaxBytes = maxBytes
	}
	c.cachedHistory = nil
	c.cachedHistoryFp = ""
	c.historyDirty = false
	c.historyDirtyNewMins = 0
	c.lastHistorySavedUnix = 0
	c.lastHistoryDate = ""
}

// FlushProfileHistory 将内存中的 7 天日汇总画像快照经过过期淘汰与容量裁剪后原子落盘（0600）。
func (c *Collector) FlushProfileHistory() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cachedHistory == nil && !c.historyDirty {
		return
	}
	c.flushProfileHistoryLocked(c.currentTimeLocked())
}

func (c *Collector) effectiveMaxProfileDevicesLocked() int {
	return cmp.Or(c.maxProfileDevices, 64)
}

func (c *Collector) effectiveMaxAppsPerDeviceLocked() int {
	return cmp.Or(c.maxAppsPerDevice, 24)
}

func (c *Collector) effectiveProfileHistoryMaxBytesLocked() int {
	return cmp.Or(c.profileHistoryMaxBytes, 128<<10)
}

func bitSlot(min int64) (int, uint64) {
	slot := ((min % profileDayMinutes) + profileDayMinutes) % profileDayMinutes
	return int(slot / 64), uint64(1) << (uint(slot) % 64)
}

func hasBit(bits [profileBitsetWords]uint64, min int64) bool {
	word, mask := bitSlot(min)
	return (bits[word] & mask) != 0
}

func setBit(bits *[profileBitsetWords]uint64, min int64) {
	word, mask := bitSlot(min)
	bits[word] |= mask
}

func clearBit(bits *[profileBitsetWords]uint64, min int64) {
	word, mask := bitSlot(min)
	bits[word] &^= mask
}

func advanceBitsetEpoch(epoch *int64, bits *[profileBitsetWords]uint64, targetMin int64) {
	if *epoch == 0 {
		*epoch = targetMin
		return
	}
	if targetMin <= *epoch {
		return
	}
	diff := targetMin - *epoch
	if diff >= profileDayMinutes {
		*bits = [profileBitsetWords]uint64{}
		*epoch = targetMin
		return
	}
	for m := *epoch + 1; m <= targetMin; m++ {
		clearBit(bits, m)
	}
	*epoch = targetMin
}

func advanceDeviceHourBuckets(dev *persistedDeviceProfile, targetMin int64) {
	if dev.EpochMinute == 0 {
		dev.EpochMinute = targetMin
		return
	}
	if targetMin <= dev.EpochMinute {
		return
	}
	oldHour := dev.EpochMinute / 60
	newHour := targetMin / 60
	if newHour-oldHour >= 24 {
		dev.HourlyActiveMins = [24]uint8{}
		dev.HourlyKB = [24]uint32{}
	} else {
		for h := oldHour + 1; h <= newHour; h++ {
			slot := ((int(h) % 24) + 24) % 24
			dev.HourlyActiveMins[slot] = 0
			dev.HourlyKB[slot] = 0
		}
	}
	dev.EpochMinute = targetMin
}

func isDirectOutboundTag(outbound string) bool {
	lower := strings.ToLower(strings.TrimSpace(outbound))
	return lower == "" || lower == "direct" || lower == "#dc" || lower == "#direct" || lower == "block"
}

func appendUniqueSampleTarget(dst *[]string, target string, maxItems int) {
	t := strings.TrimSpace(target)
	if t == "" || slices.Contains(*dst, t) {
		return
	}
	if len(*dst) >= maxItems {
		return
	}
	*dst = append(*dst, t)
}

func formatDayPeriod(hour int) string {
	switch {
	case hour < 6:
		return "凌晨 00-06"
	case hour < 12:
		return "上午 06-12"
	case hour < 18:
		return "下午 12-18"
	default:
		return "晚间 18-24"
	}
}

func evaluateForegroundGate(cat AppCategory, isInfra bool, up, down int64, newConns int, hasNonBeacon bool) bool {
	if isInfra {
		return false
	}
	// 四维去噪：规则周期心跳小包不计入前景停留
	if !hasNonBeacon && (up+down) < 64*1024 {
		return false
	}
	// 四维去噪：无新建连且下行极微弱的静默长连保活不计入前景停留
	if newConns == 0 && down < 8*1024 {
		return false
	}
	switch cat {
	case AppCategoryVideo:
		return down >= 120*1024
	case AppCategorySocial, AppCategoryAIDev:
		return (up+down) >= 12*1024 && (newConns > 0 || (up > 0 && down > 0))
	default:
		return (up+down) >= 20*1024 && down >= 15*1024
	}
}

func (c *Collector) loadProfileHistoryLocked(now time.Time) *persistedProfileHistory {
	path := c.profileHistoryPath
	if path != "" {
		fp := auditFileFingerprint(path)
		if c.cachedHistory != nil && c.cachedHistoryFp == fp {
			if pruneExpiredProfileDays(c.cachedHistory, now) {
				c.historyDirty = true
			}
			return c.cachedHistory
		}
	}

	hist := &persistedProfileHistory{
		SchemaVersion: profileHistorySchemaVersion,
		Days:          make(map[string]*dailyProfileSnapshot),
	}
	if path != "" {
		if raw, err := os.ReadFile(path); err == nil && len(raw) > 0 {
			_ = json.Unmarshal(raw, hist)
		}
	}
	if hist.Days == nil {
		hist.Days = make(map[string]*dailyProfileSnapshot)
	}
	for d, snap := range hist.Days {
		if snap == nil {
			delete(hist.Days, d)
			continue
		}
		if snap.Date == "" {
			snap.Date = d
		}
		if snap.Devices == nil {
			snap.Devices = make(map[string]*dailyDeviceRollup)
		}
	}
	pruneExpiredProfileDays(hist, now)
	c.cachedHistory = hist
	c.cachedHistoryFp = auditFileFingerprint(path)
	return hist
}

func pruneExpiredProfileDays(hist *persistedProfileHistory, now time.Time) bool {
	if hist == nil || len(hist.Days) == 0 {
		return false
	}
	cutoff := now.AddDate(0, 0, -(profileRetentionDays - 1)).Format("2006-01-02")
	before := len(hist.Days)
	maps.DeleteFunc(hist.Days, func(dateKey string, snap *dailyProfileSnapshot) bool {
		return snap == nil || dateKey == "" || dateKey < cutoff
	})
	return len(hist.Days) != before
}

func getOrCreateDeviceProfileLocked(
	state *persistedAuditState,
	devIP, devName, devMAC string,
	devDir map[string]lanDeviceInfo,
	nowUnix int64,
) *persistedDeviceProfile {
	if state.Profiles == nil {
		state.Profiles = make(map[string]*persistedDeviceProfile)
	}
	macNorm := strings.ToLower(strings.TrimSpace(devMAC))
	if info, ok := devDir[devIP]; ok {
		if devName == "" && info.Name != "" {
			devName = info.Name
		}
		if macNorm == "" && info.MAC != "" {
			macNorm = strings.ToLower(strings.TrimSpace(info.MAC))
		}
	}
	prof := state.Profiles[devIP]
	if prof == nil && macNorm != "" {
		for oldKey, cand := range state.Profiles {
			if cand != nil && strings.EqualFold(cand.DeviceMAC, macNorm) {
				delete(state.Profiles, oldKey)
				cand.DeviceIP = devIP
				prof = cand
				state.Profiles[devIP] = prof
				break
			}
		}
	}
	if prof == nil {
		prof = &persistedDeviceProfile{
			DeviceIP: devIP,
			Apps:     make(map[string]*persistedAppBitset),
		}
		state.Profiles[devIP] = prof
	}
	if prof.Apps == nil {
		prof.Apps = make(map[string]*persistedAppBitset)
	}
	if devName != "" {
		prof.DeviceName = devName
	}
	if macNorm != "" {
		prof.DeviceMAC = macNorm
	}
	prof.DeviceRole = InferDeviceRole(cmp.Or(prof.DeviceName, devIP))
	prof.UpdatedUnix = nowUnix
	return prof
}

func getOrCreateDailyDeviceLocked(snap *dailyProfileSnapshot, devIP, devName, devMAC, role string) *dailyDeviceRollup {
	if snap.Devices == nil {
		snap.Devices = make(map[string]*dailyDeviceRollup)
	}
	macNorm := strings.ToLower(strings.TrimSpace(devMAC))
	dr := snap.Devices[devIP]
	if dr == nil && macNorm != "" {
		for oldKey, cand := range snap.Devices {
			if cand != nil && strings.EqualFold(cand.DeviceMAC, macNorm) {
				delete(snap.Devices, oldKey)
				cand.DeviceIP = devIP
				dr = cand
				snap.Devices[devIP] = dr
				break
			}
		}
	}
	if dr == nil {
		dr = &dailyDeviceRollup{
			DeviceIP: devIP,
			Apps:     make(map[string]*dailyAppRollup),
		}
		snap.Devices[devIP] = dr
	}
	if dr.Apps == nil {
		dr.Apps = make(map[string]*dailyAppRollup)
	}
	if devName != "" {
		dr.DeviceName = devName
	}
	if macNorm != "" {
		dr.DeviceMAC = macNorm
	}
	if role != "" {
		dr.DeviceRole = role
	}
	return dr
}

type touchedAppKey struct {
	devIP string
	app   string
}

func (c *Collector) recordProfileSamplesLocked(
	state *persistedAuditState,
	samples []profileConnDelta,
	devDir map[string]lanDeviceInfo,
	now time.Time,
) bool {
	if state == nil || len(samples) == 0 {
		return false
	}
	nowUnix := now.Unix()
	curMin := nowUnix / 60
	todayStr := now.Format("2006-01-02")
	hour := now.Hour()

	hist := c.loadProfileHistoryLocked(now)
	if c.lastHistoryDate != "" && c.lastHistoryDate != todayStr {
		c.historyDirty = true
	}
	c.lastHistoryDate = todayStr

	todaySnap := hist.Days[todayStr]
	if todaySnap == nil {
		todaySnap = &dailyProfileSnapshot{
			Date:    todayStr,
			Devices: make(map[string]*dailyDeviceRollup),
		}
		hist.Days[todayStr] = todaySnap
	}

	type pollBucketMeta struct {
		hasNonBeacon bool
	}
	touched := make(map[touchedAppKey]*pollBucketMeta)
	mutated := false

	for _, s := range samples {
		devProf := getOrCreateDeviceProfileLocked(state, s.DeviceIP, s.DeviceName, s.DeviceMAC, devDir, nowUnix)
		advanceDeviceHourBuckets(devProf, curMin)

		histDev := getOrCreateDailyDeviceLocked(todaySnap, s.DeviceIP, devProf.DeviceName, devProf.DeviceMAC, devProf.DeviceRole)

		totalDelta := s.DeltaUp + s.DeltaDown
		if totalDelta > 0 {
			mutated = true
			if isDirectOutboundTag(s.Outbound) {
				devProf.DirectBytes += totalDelta
				histDev.DirectBytes += totalDelta
			} else {
				devProf.ProxyBytes += totalDelta
				histDev.ProxyBytes += totalDelta
			}
			kb := uint64(totalDelta / 1024)
			if kb > 0 {
				sumKB := uint64(devProf.HourlyKB[hour]) + kb
				if sumKB > math.MaxUint32 {
					sumKB = math.MaxUint32
				}
				devProf.HourlyKB[hour] = uint32(sumKB)
			}
			histDev.UploadBytes += s.DeltaUp
			histDev.DownloadBytes += s.DeltaDown
			c.historyDirty = true
		}

		cat := ClassifyApp(s.Target, s.DestIP, s.Rule, s.RawHost)
		appName := cat.Name
		if appName == "" {
			if !isValidAuditDomain(s.Target) {
				continue
			}
			appName = defaultUnclassifiedWebsiteApp
			cat = AppCatalogEntry{
				Name:          appName,
				Category:      AppCategoryOther,
				CategoryLabel: CategoryDisplayLabel(AppCategoryOther),
				IsInfra:       false,
			}
		}

		appEntry := devProf.Apps[appName]
		if appEntry == nil {
			appEntry = &persistedAppBitset{
				AppName:  appName,
				Category: cat.Category,
				IsInfra:  cat.IsInfra,
			}
			devProf.Apps[appName] = appEntry
		}
		appEntry.Category = cat.Category
		appEntry.IsInfra = cat.IsInfra
		advanceBitsetEpoch(&appEntry.EpochMinute, &appEntry.Bits, curMin)

		if appEntry.curBucketMin != curMin {
			appEntry.curBucketMin = curMin
			appEntry.curUpBytes = 0
			appEntry.curDownBytes = 0
			appEntry.curNewConns = 0
			appEntry.curMinCV = 0
		}
		appEntry.curUpBytes += s.DeltaUp
		appEntry.curDownBytes += s.DeltaDown
		if s.IsNewConn {
			appEntry.curNewConns++
		}
		appEntry.UploadBytes += s.DeltaUp
		appEntry.DownloadBytes += s.DeltaDown
		appEntry.LastSeenUnix = nowUnix
		appendUniqueSampleTarget(&appEntry.SampleTargets, s.Target, 5)

		histApp := histDev.Apps[appName]
		if histApp == nil {
			histApp = &dailyAppRollup{
				AppName:  appName,
				Category: cat.Category,
				IsInfra:  cat.IsInfra,
			}
			histDev.Apps[appName] = histApp
		}
		histApp.UploadBytes += s.DeltaUp
		histApp.DownloadBytes += s.DeltaDown

		tk := touchedAppKey{devIP: s.DeviceIP, app: appName}
		meta := touched[tk]
		if meta == nil {
			meta = &pollBucketMeta{}
			touched[tk] = meta
		}
		isBeacon := s.ArrivalCount >= 4 && s.IntervalCV < 0.15 && totalDelta < 64*1024
		if !isBeacon {
			meta.hasNonBeacon = true
		}
	}

	for tk, meta := range touched {
		devProf := state.Profiles[tk.devIP]
		if devProf == nil {
			continue
		}
		appEntry := devProf.Apps[tk.app]
		if appEntry == nil {
			continue
		}
		histDev := todaySnap.Devices[tk.devIP]
		var histApp *dailyAppRollup
		if histDev != nil {
			histApp = histDev.Apps[tk.app]
		}

		isFg := evaluateForegroundGate(
			appEntry.Category,
			appEntry.IsInfra,
			appEntry.curUpBytes,
			appEntry.curDownBytes,
			appEntry.curNewConns,
			meta.hasNonBeacon,
		)
		if isFg {
			if appEntry.lastBgRecorded == curMin {
				appEntry.BgMinutes = max(0, appEntry.BgMinutes-1)
				appEntry.lastBgRecorded = 0
				if histApp != nil && histApp.LastBgMinute == curMin {
					histApp.BgMins = max(0, histApp.BgMins-1)
					histApp.LastBgMinute = 0
				}
			}
			if !hasBit(appEntry.Bits, curMin) {
				setBit(&appEntry.Bits, curMin)
				mutated = true
				if devProf.lastDevFgMin != curMin {
					devProf.lastDevFgMin = curMin
					if devProf.HourlyActiveMins[hour] < 60 {
						devProf.HourlyActiveMins[hour]++
					}
				}
				if histApp != nil && histApp.LastMinute < curMin {
					if histApp.LastMinute > 0 && curMin-histApp.LastMinute <= 3 {
						histApp.CurRunMins++
					} else {
						histApp.Sessions++
						histApp.CurRunMins = 1
					}
					histApp.LongestMin = max(histApp.LongestMin, histApp.CurRunMins)
					histApp.LastMinute = curMin
					histApp.FgMins++
					histApp.PeakPeriod = cmp.Or(histApp.PeakPeriod, formatDayPeriod(hour))
					if histDev.LastFgMinute < curMin {
						histDev.LastFgMinute = curMin
						histDev.FgMins++
						if histDev.HourlyActiveMins[hour] < 60 {
							histDev.HourlyActiveMins[hour]++
						}
					}
					c.historyDirty = true
					c.historyDirtyNewMins++
				}
			}
			continue
		}

		if !hasBit(appEntry.Bits, curMin) && appEntry.lastBgRecorded != curMin {
			appEntry.BgMinutes++
			appEntry.lastBgRecorded = curMin
			mutated = true
			if histApp != nil && histApp.LastMinute != curMin && histApp.LastBgMinute < curMin {
				histApp.BgMins++
				histApp.LastBgMinute = curMin
				c.historyDirty = true
			}
		}
	}

	hist.UpdatedUnix = nowUnix
	return mutated
}

func (c *Collector) shouldFlushProfileHistoryLocked(now time.Time) bool {
	if c.profileHistoryPath == "" || c.cachedHistory == nil || !c.historyDirty {
		return false
	}
	if _, err := os.Stat(c.profileHistoryPath); os.IsNotExist(err) && len(c.cachedHistory.Days) > 0 {
		return true
	}
	if c.lastHistoryDate != "" && c.lastHistoryDate != now.Format("2006-01-02") {
		return true
	}
	if c.historyDirtyNewMins >= profileHistoryFlushMinDelta && (c.lastHistorySavedUnix == 0 || now.Unix()-c.lastHistorySavedUnix >= int64(profileHistoryFlushInterval.Seconds())) {
		return true
	}
	return c.lastHistorySavedUnix > 0 && now.Unix()-c.lastHistorySavedUnix >= 3600
}

func (c *Collector) maybeFlushProfileHistoryLocked(now time.Time) {
	if c.shouldFlushProfileHistoryLocked(now) {
		c.flushProfileHistoryLocked(now)
	}
}

func (c *Collector) flushProfileHistoryLocked(now time.Time) {
	if c.profileHistoryPath == "" {
		return
	}
	hist := c.loadProfileHistoryLocked(now)
	hist.SchemaVersion = profileHistorySchemaVersion
	hist.UpdatedUnix = now.Unix()

	pruneExpiredProfileDays(hist, now)
	maxDevs := c.effectiveMaxProfileDevicesLocked()
	maxApps := c.effectiveMaxAppsPerDeviceLocked()
	for _, snap := range hist.Days {
		trimDailySnapshot(snap, maxDevs, maxApps)
	}

	payload := marshalCappedProfileHistory(hist, now.Format("2006-01-02"), c.effectiveProfileHistoryMaxBytesLocked())
	if len(payload) == 0 {
		return
	}
	writeProfileHistoryAtomically(c.profileHistoryPath, payload)
	c.cachedHistory = hist
	c.cachedHistoryFp = auditFileFingerprint(c.profileHistoryPath)
	c.historyDirty = false
	c.historyDirtyNewMins = 0
	c.lastHistorySavedUnix = now.Unix()
}

func trimDailySnapshot(snap *dailyProfileSnapshot, maxDevs, maxApps int) {
	if snap == nil || len(snap.Devices) == 0 {
		return
	}
	for _, dev := range snap.Devices {
		if dev == nil || len(dev.Apps) <= maxApps {
			continue
		}
		type appScore struct {
			name  string
			fg    int
			bytes int64
		}
		list := make([]appScore, 0, len(dev.Apps))
		for k, a := range dev.Apps {
			if a == nil {
				continue
			}
			list = append(list, appScore{name: k, fg: a.FgMins, bytes: a.UploadBytes + a.DownloadBytes})
		}
		slices.SortFunc(list, func(a, b appScore) int {
			if c := cmp.Compare(b.fg, a.fg); c != 0 {
				return c
			}
			if c := cmp.Compare(b.bytes, a.bytes); c != 0 {
				return c
			}
			return cmp.Compare(a.name, b.name)
		})
		if len(list) > maxApps {
			list = list[:maxApps]
		}
		kept := make(map[string]*dailyAppRollup, len(list))
		for _, item := range list {
			kept[item.name] = dev.Apps[item.name]
		}
		dev.Apps = kept
	}
	if len(snap.Devices) <= maxDevs {
		return
	}
	type devScore struct {
		key   string
		fg    int
		bytes int64
	}
	devs := make([]devScore, 0, len(snap.Devices))
	for k, d := range snap.Devices {
		if d == nil {
			continue
		}
		devs = append(devs, devScore{key: k, fg: d.FgMins, bytes: d.UploadBytes + d.DownloadBytes})
	}
	slices.SortFunc(devs, func(a, b devScore) int {
		if c := cmp.Compare(b.fg, a.fg); c != 0 {
			return c
		}
		if c := cmp.Compare(b.bytes, a.bytes); c != 0 {
			return c
		}
		return cmp.Compare(a.key, b.key)
	})
	if len(devs) > maxDevs {
		devs = devs[:maxDevs]
	}
	kept := make(map[string]*dailyDeviceRollup, len(devs))
	for _, d := range devs {
		kept[d.key] = snap.Devices[d.key]
	}
	snap.Devices = kept
}

func evictOneProfileItem(hist *persistedProfileHistory, todayStr string) bool {
	if hist == nil || len(hist.Days) == 0 {
		return false
	}
	dates := make([]string, 0, len(hist.Days))
	for d := range hist.Days {
		dates = append(dates, d)
	}
	slices.Sort(dates) // 最旧日期优先淘汰

	for _, d := range dates {
		if d == todayStr && len(dates) > 1 {
			continue
		}
		snap := hist.Days[d]
		if snap == nil || len(snap.Devices) == 0 {
			delete(hist.Days, d)
			return true
		}
		var worstDevKey string
		worstDevFg := math.MaxInt
		worstDevBytes := int64(math.MaxInt64)
		for dk, dev := range snap.Devices {
			if dev == nil {
				delete(snap.Devices, dk)
				return true
			}
			tot := dev.UploadBytes + dev.DownloadBytes
			if dev.FgMins < worstDevFg || (dev.FgMins == worstDevFg && tot < worstDevBytes) {
				worstDevKey = dk
				worstDevFg = dev.FgMins
				worstDevBytes = tot
			}
		}
		if worstDevKey != "" {
			delete(snap.Devices, worstDevKey)
			if len(snap.Devices) == 0 {
				delete(hist.Days, d)
			}
			return true
		}
	}
	return false
}

func marshalCappedProfileHistory(hist *persistedProfileHistory, todayStr string, maxBytes int) []byte {
	encoded, err := json.Marshal(hist)
	if err != nil {
		return nil
	}
	if maxBytes <= 0 || len(encoded) <= maxBytes {
		return encoded
	}
	for range 256 {
		if len(encoded) <= maxBytes || !evictOneProfileItem(hist, todayStr) {
			break
		}
		next, mErr := json.Marshal(hist)
		if mErr != nil {
			break
		}
		encoded = next
	}
	return encoded
}

func writeProfileHistoryAtomically(path string, payload []byte) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return
	}
	tmpFile, err := os.CreateTemp(dir, ".audit-profile-history-*.tmp")
	if err != nil {
		return
	}
	tmpPath := tmpFile.Name()
	_, wErr := tmpFile.Write(payload)
	chErr := tmpFile.Chmod(0600)
	clErr := tmpFile.Close()
	if wErr != nil || chErr != nil || clErr != nil {
		_ = os.Remove(tmpPath)
		return
	}
	if os.Rename(tmpPath, path) != nil {
		_ = os.Remove(tmpPath)
	}
}

func trimLiveProfilesLocked(st *persistedAuditState, maxDevs, maxApps int) bool {
	if st == nil || len(st.Profiles) == 0 {
		return false
	}
	changed := false
	for _, dev := range st.Profiles {
		if dev == nil || len(dev.Apps) <= maxApps {
			continue
		}
		type aPair struct {
			name  string
			last  int64
			bytes int64
		}
		list := make([]aPair, 0, len(dev.Apps))
		for k, a := range dev.Apps {
			if a == nil {
				continue
			}
			list = append(list, aPair{name: k, last: a.LastSeenUnix, bytes: a.UploadBytes + a.DownloadBytes})
		}
		slices.SortFunc(list, func(a, b aPair) int {
			if c := cmp.Compare(b.last, a.last); c != 0 {
				return c
			}
			return cmp.Compare(b.bytes, a.bytes)
		})
		if len(list) > maxApps {
			list = list[:maxApps]
		}
		kept := make(map[string]*persistedAppBitset, len(list))
		for _, item := range list {
			kept[item.name] = dev.Apps[item.name]
		}
		dev.Apps = kept
		changed = true
	}
	if len(st.Profiles) > maxDevs {
		type dPair struct {
			ip    string
			up    int64
			bytes int64
		}
		list := make([]dPair, 0, len(st.Profiles))
		for k, d := range st.Profiles {
			if d == nil {
				continue
			}
			list = append(list, dPair{ip: k, up: d.UpdatedUnix, bytes: d.ProxyBytes + d.DirectBytes})
		}
		slices.SortFunc(list, func(a, b dPair) int {
			if c := cmp.Compare(b.up, a.up); c != 0 {
				return c
			}
			return cmp.Compare(b.bytes, a.bytes)
		})
		if len(list) > maxDevs {
			list = list[:maxDevs]
		}
		kept := make(map[string]*persistedDeviceProfile, len(list))
		for _, item := range list {
			kept[item.ip] = st.Profiles[item.ip]
		}
		st.Profiles = kept
		changed = true
	}
	return changed
}

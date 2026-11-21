package serverweb

import (
	"cmp"
	"context"
	"net"
	"slices"
	"strings"
	"time"

	"singctl/internal/fleet"
)

type mergedSniffRecord struct {
	rec   sniffRecord
	nodes []SniffNodeRef
}

type enrichedSniffItem struct {
	rec   sniffRecord
	nodes []SniffNodeRef
	geo   IPGeoInfo
	tag   string
}

// Snapshot 采集并生成默认视角（全集群/本机）的活跃嗅探态势快照 (用于 SSE 遥测，非阻塞纯内存快照 + 后台异步采集)
func (t *SniffTracker) Snapshot(ctx context.Context, activeProxyClientIPs ...string) SniffSummary {
	if len(activeProxyClientIPs) > 0 {
		t.MarkTrustedClientIPs(activeProxyClientIPs...)
	}
	t.triggerBackgroundSystemHarvestIfNeeded()
	t.triggerBackgroundFleetHarvestIfNeeded()
	return t.buildSnapshot(ctx, "all", false, true)
}

// SnapshotForNode 采集并生成指定主机视角 ("all" | "local" | "<node_id>") 的全量活跃嗅探三维态势快照。
// 默认 (forceRefresh=false) 采用 SWR 非阻塞模式立即返回内存快照并后台异步刷新；显式刷新 (?refresh=1) 执行同步采集。
func (t *SniffTracker) SnapshotForNode(ctx context.Context, nodeScope string, forceRefresh bool, activeProxyClientIPs ...string) SniffSummary {
	if len(activeProxyClientIPs) > 0 {
		t.MarkTrustedClientIPs(activeProxyClientIPs...)
	}
	if !forceRefresh {
		t.triggerBackgroundSystemHarvestIfNeeded()
		t.triggerBackgroundFleetHarvestIfNeeded()
		return t.buildSnapshot(ctx, nodeScope, false, true)
	}
	return t.buildSnapshot(ctx, nodeScope, true, false)
}

func (t *SniffTracker) buildSnapshot(ctx context.Context, nodeScope string, forceRefresh, nonBlocking bool) SniffSummary {
	nodeScope = cmp.Or(strings.TrimSpace(nodeScope), "all")

	// 1. 同步本机 Web IPLimiter 中的密码试探与封禁记录（跳过嗅探手动拉黑记录，避免污染原探测攻击向量）
	t.syncLimiterAttempts()

	// 2. 采集本机系统级防火墙、fail2ban 与外部探测连接 (SSE 热路径由后台协程异步采集，不阻塞请求)
	if !nonBlocking && (nodeScope == "all" || nodeScope == "local") {
		t.maybeHarvestSystemSources(ctx, forceRefresh)
	}

	// 3. 若配置了节点舰队且请求了子节点或全集群数据，按需并发采集子节点嗅探态势
	fleetNodes, enableProbe := t.loadClusterFleetNodes()
	if !nonBlocking && enableProbe && len(fleetNodes) > 0 && nodeScope != "local" {
		t.maybeHarvestFleetNodes(ctx, fleetNodes, nodeScope, forceRefresh)
	}

	// 4. 清理过期条目并快照内存记录
	now := time.Now()
	nodeSummaries, mergedByIP, blockedCIDRs := t.collectActiveSniffRecords(nodeScope, fleetNodes, now)
	t.scheduleAsyncSaveIfNeeded()

	// 5. GeoIP 富化与 IP/网段/国家三维聚合
	enriched, totalBanned := t.resolveAndSortSniffIPs(ctx, mergedByIP, nonBlocking)
	topIPs := buildSniffIPStats(enriched)
	subnets := aggregateSniffSubnets(enriched, blockedCIDRs)
	countries := aggregateSniffCountries(enriched)

	return SniffSummary{
		UpdatedAt:      now.Format(time.RFC3339),
		SelectedNode:   nodeScope,
		Nodes:          nodeSummaries,
		TotalSniffIPs:  len(enriched),
		TotalSubnets:   len(subnets),
		TotalCountries: len(countries),
		TotalBannedIPs: totalBanned,
		TopIPs:         topIPs,
		TopSubnets:     subnets,
		TopCountries:   countries,
	}
}

func (t *SniffTracker) syncLimiterAttempts() {
	if t.limiter == nil {
		return
	}
	attempts := t.limiter.ListAllAttempts()
	if len(attempts) == 0 {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, att := range attempts {
		if isIgnoredInternalIP(att.IP) || att.Source == BanSourceManualSniff {
			continue
		}
		st := "observing"
		if att.Banned {
			st = "banned"
		}
		t.observeNodeAtLocked("local", "本机网关", att.IP, "Web 管理端密码试探", st, att.FailCount, true, att.LastFail, att.LastFail)
	}
}

func (t *SniffTracker) loadClusterFleetNodes() ([]fleet.Node, bool) {
	t.mu.RLock()
	fleetMgr := t.fleetMgr
	enableProbe := t.EnableSystemProbe
	t.mu.RUnlock()

	if fleetMgr == nil || fleetMgr.Store == nil {
		return nil, enableProbe
	}
	list, err := fleetMgr.Store.List()
	if err != nil {
		return nil, enableProbe
	}
	var clusterHosts []string
	for _, fn := range list {
		if h := strings.TrimSpace(fn.Host); h != "" {
			clusterHosts = append(clusterHosts, h)
		}
	}
	if len(clusterHosts) > 0 {
		t.MarkTrustedClientIPs(clusterHosts...)
	}
	return list, enableProbe
}

func appendUniqueNodeRef(nodes []SniffNodeRef, ref SniffNodeRef) []SniffNodeRef {
	for _, existing := range nodes {
		if existing.ID == ref.ID {
			return nodes
		}
	}
	return append(nodes, ref)
}

func (t *SniffTracker) collectActiveSniffRecords(nodeScope string, fleetNodes []fleet.Node, now time.Time) ([]SniffNodeSummary, map[string]*mergedSniffRecord, map[string]*net.IPNet) {
	t.mu.Lock()
	defer t.mu.Unlock()

	for _, nodeMap := range t.recordsByNode {
		for ip, rec := range nodeMap {
			if now.Sub(rec.lastSeen) > sniffEntryTTL {
				delete(nodeMap, ip)
				t.dirty = true
				continue
			}
			if exp, trusted := t.trustedClients[ip]; trusted && now.Before(exp) && rec.status != "banned" {
				delete(nodeMap, ip)
				t.dirty = true
				continue
			}
		}
	}

	nodeInfoMap := map[string]SniffNodeRef{
		"local": {ID: "local", Name: "本机网关"},
	}
	for _, fn := range fleetNodes {
		nodeInfoMap[fn.ID] = SniffNodeRef{
			ID:   fn.ID,
			Name: cmp.Or(fn.Name, fn.ID),
			Host: fn.Host,
		}
	}

	clusterIPSet := make(map[string]struct{})
	clusterSubnetSet := make(map[string]struct{})
	clusterBannedSet := make(map[string]struct{})

	buildSingleNodeSummary := func(nid, name, host string, online bool) SniffNodeSummary {
		nm := t.recordsByNode[nid]
		subs := make(map[string]struct{})
		banned := 0
		for _, rec := range nm {
			clusterIPSet[rec.ip] = struct{}{}
			if rec.subnet != "" {
				subs[rec.subnet] = struct{}{}
				clusterSubnetSet[rec.subnet] = struct{}{}
			}
			if rec.status == "banned" {
				banned++
				clusterBannedSet[rec.ip] = struct{}{}
			}
		}
		meta := t.nodeMeta[nid]
		var lastHarv, errStr string
		if meta != nil {
			if !meta.lastHarvest.IsZero() {
				lastHarv = formatSniffTime(meta.lastHarvest)
			}
			errStr = meta.lastError
		}
		return SniffNodeSummary{
			ID:            nid,
			Name:          name,
			Host:          host,
			Online:        online,
			TotalSniffIPs: len(nm),
			TotalSubnets:  len(subs),
			TotalBanned:   banned,
			LastHarvestAt: lastHarv,
			Error:         errStr,
		}
	}

	localSum := buildSingleNodeSummary("local", "本机网关", "", true)
	fleetSums := make([]SniffNodeSummary, 0, len(fleetNodes))
	for _, fn := range fleetNodes {
		fleetSums = append(fleetSums, buildSingleNodeSummary(fn.ID, cmp.Or(fn.Name, fn.ID), fn.Host, fn.Online))
	}
	// 若内存中存在测试注入但未在 fleet.Store 注册的自定义节点，也纳入统计
	for nid, nm := range t.recordsByNode {
		if nid == "local" || len(nm) == 0 {
			continue
		}
		if _, exists := nodeInfoMap[nid]; !exists {
			sampleName := nid
			for _, r := range nm {
				if r.nodeName != "" {
					sampleName = r.nodeName
					break
				}
			}
			nodeInfoMap[nid] = SniffNodeRef{ID: nid, Name: sampleName}
			fleetSums = append(fleetSums, buildSingleNodeSummary(nid, sampleName, "", true))
		}
	}

	nodeSummaries := make([]SniffNodeSummary, 0, 2+len(fleetSums))
	nodeSummaries = append(nodeSummaries, SniffNodeSummary{
		ID:            "all",
		Name:          "全集群汇总",
		Online:        true,
		TotalSniffIPs: len(clusterIPSet),
		TotalSubnets:  len(clusterSubnetSet),
		TotalBanned:   len(clusterBannedSet),
		LastHarvestAt: formatSniffTime(now),
	})
	nodeSummaries = append(nodeSummaries, localSum)
	nodeSummaries = append(nodeSummaries, fleetSums...)

	mergedByIP := make(map[string]*mergedSniffRecord)
	collectFromNode := func(nid string) {
		nm := t.recordsByNode[nid]
		nRef, ok := nodeInfoMap[nid]
		if !ok {
			nRef = SniffNodeRef{ID: nid, Name: nid}
		}
		for _, r := range nm {
			existing, ok := mergedByIP[r.ip]
			if !ok {
				cp := *r
				if cp.firstSeen.IsZero() {
					cp.firstSeen = cp.lastSeen
				}
				mergedByIP[r.ip] = &mergedSniffRecord{
					rec:   cp,
					nodes: []SniffNodeRef{nRef},
				}
				continue
			}
			existing.rec.hits += r.hits
			if !r.firstSeen.IsZero() && (existing.rec.firstSeen.IsZero() || r.firstSeen.Before(existing.rec.firstSeen)) {
				existing.rec.firstSeen = r.firstSeen
			}
			if r.lastSeen.After(existing.rec.lastSeen) {
				existing.rec.lastSeen = r.lastSeen
			}
			if statusPriority(r.status) > statusPriority(existing.rec.status) {
				existing.rec.status = r.status
			}
			if r.vector != "" && (existing.rec.vector == "" || existing.rec.vector == "异常端口探测") {
				existing.rec.vector = r.vector
			}
			if r.scannerTag != "" && existing.rec.scannerTag == "" {
				existing.rec.scannerTag = r.scannerTag
			}
			existing.nodes = appendUniqueNodeRef(existing.nodes, nRef)
		}
	}

	if nodeScope == "all" {
		collectFromNode("local")
		for _, fs := range fleetSums {
			collectFromNode(fs.ID)
		}
	} else {
		collectFromNode(nodeScope)
	}

	blockedCIDRs := make(map[string]*net.IPNet, len(t.manualBlockedCIDRs))
	for k, v := range t.manualBlockedCIDRs {
		blockedCIDRs[k] = v
	}
	if nodeScope != "all" {
		if nb, ok := t.nodeBlockedCIDRs[nodeScope]; ok {
			for k, v := range nb {
				blockedCIDRs[k] = v
			}
		}
	}
	return nodeSummaries, mergedByIP, blockedCIDRs
}

func (t *SniffTracker) resolveAndSortSniffIPs(ctx context.Context, mergedByIP map[string]*mergedSniffRecord, nonBlocking bool) ([]enrichedSniffItem, int) {
	var geoMap map[string]IPGeoInfo
	if t.geo != nil && len(mergedByIP) > 0 {
		ipList := make([]string, 0, len(mergedByIP))
		for ip := range mergedByIP {
			ipList = append(ipList, ip)
		}
		if nonBlocking {
			geoMap = t.geo.ResolveCachedOrEnqueue(ipList)
		} else {
			geoMap = t.geo.ResolveBatch(ctx, ipList)
		}
	}

	enriched := make([]enrichedSniffItem, 0, len(mergedByIP))
	totalBanned := 0
	for _, m := range mergedByIP {
		var geo IPGeoInfo
		if geoMap != nil {
			geo = geoMap[m.rec.ip]
		}
		tag := cmp.Or(m.rec.scannerTag, MatchScannerTag(m.rec.ip, geo.ISP))
		if m.rec.status == "banned" {
			totalBanned++
		}
		enriched = append(enriched, enrichedSniffItem{
			rec:   m.rec,
			nodes: m.nodes,
			geo:   geo,
			tag:   tag,
		})
	}

	slices.SortFunc(enriched, func(a, b enrichedSniffItem) int {
		if a.rec.hits != b.rec.hits {
			return cmp.Compare(b.rec.hits, a.rec.hits)
		}
		if !a.rec.lastSeen.Equal(b.rec.lastSeen) {
			if a.rec.lastSeen.After(b.rec.lastSeen) {
				return -1
			}
			return 1
		}
		return cmp.Compare(a.rec.ip, b.rec.ip)
	})
	return enriched, totalBanned
}

func buildSniffIPStats(enriched []enrichedSniffItem) []SniffIPStat {
	topIPs := make([]SniffIPStat, 0, len(enriched))
	for _, it := range enriched {
		topIPs = append(topIPs, SniffIPStat{
			IP:          it.rec.ip,
			Subnet:      it.rec.subnet,
			Hits:        it.rec.hits,
			Vector:      it.rec.vector,
			Status:      it.rec.status,
			Country:     it.geo.Country,
			CountryCode: it.geo.CountryCode,
			Flag:        it.geo.Flag,
			Geo:         it.geo.Geo,
			ISP:         it.geo.ISP,
			ScannerTag:  it.tag,
			FirstSeen:   formatSniffTime(it.rec.firstSeen),
			LastSeen:    formatSniffTime(it.rec.lastSeen),
			Nodes:       it.nodes,
		})
	}
	return topIPs
}

func aggregateSniffSubnets(enriched []enrichedSniffItem, blockedCIDRs map[string]*net.IPNet) []SniffSubnetStat {
	type subnetAgg struct {
		cidr        string
		uniqueIPs   int
		totalHits   int
		bannedCount int
		country     string
		countryCode string
		flag        string
		isp         string
		scannerTag  string
		samples     []string
		firstSeen   time.Time
		lastSeen    time.Time
		nodes       []SniffNodeRef
	}
	subnetMap := make(map[string]*subnetAgg)
	for _, it := range enriched {
		cidr := cmp.Or(it.rec.subnet, ComputeSubnetCIDR(it.rec.ip))
		if cidr == "" {
			continue
		}
		agg, exists := subnetMap[cidr]
		if !exists {
			agg = &subnetAgg{
				cidr:       cidr,
				scannerTag: it.tag,
				firstSeen:  it.rec.firstSeen,
				lastSeen:   it.rec.lastSeen,
			}
			subnetMap[cidr] = agg
		}
		agg.uniqueIPs++
		agg.totalHits += it.rec.hits
		if it.rec.status == "banned" {
			agg.bannedCount++
		}
		if !it.rec.firstSeen.IsZero() && (agg.firstSeen.IsZero() || it.rec.firstSeen.Before(agg.firstSeen)) {
			agg.firstSeen = it.rec.firstSeen
		}
		if it.rec.lastSeen.After(agg.lastSeen) {
			agg.lastSeen = it.rec.lastSeen
		}
		if agg.country == "" && it.geo.Country != "" {
			agg.country = it.geo.Country
			agg.countryCode = it.geo.CountryCode
			agg.flag = it.geo.Flag
		}
		if agg.isp == "" && it.geo.ISP != "" {
			agg.isp = it.geo.ISP
		}
		if agg.scannerTag == "" && it.tag != "" {
			agg.scannerTag = it.tag
		}
		if len(agg.samples) < 5 {
			agg.samples = append(agg.samples, it.rec.ip)
		}
		for _, nRef := range it.nodes {
			agg.nodes = appendUniqueNodeRef(agg.nodes, nRef)
		}
	}

	subnets := make([]SniffSubnetStat, 0, len(subnetMap))
	for _, agg := range subnetMap {
		st := "active"
		if _, wholeBanned := blockedCIDRs[agg.cidr]; wholeBanned || (agg.uniqueIPs > 0 && agg.bannedCount == agg.uniqueIPs) {
			st = "banned"
		} else if agg.bannedCount > 0 {
			st = "partial"
		}
		subnets = append(subnets, SniffSubnetStat{
			CIDR:        agg.cidr,
			UniqueIPs:   agg.uniqueIPs,
			TotalHits:   agg.totalHits,
			BannedCount: agg.bannedCount,
			Status:      st,
			Country:     agg.country,
			CountryCode: agg.countryCode,
			Flag:        agg.flag,
			ISP:         agg.isp,
			ScannerTag:  agg.scannerTag,
			SampleIPs:   agg.samples,
			FirstSeen:   formatSniffTime(agg.firstSeen),
			LastSeen:    formatSniffTime(agg.lastSeen),
			Nodes:       agg.nodes,
		})
	}
	slices.SortFunc(subnets, func(a, b SniffSubnetStat) int {
		if a.UniqueIPs != b.UniqueIPs {
			return cmp.Compare(b.UniqueIPs, a.UniqueIPs)
		}
		if a.TotalHits != b.TotalHits {
			return cmp.Compare(b.TotalHits, a.TotalHits)
		}
		return cmp.Compare(a.CIDR, b.CIDR)
	})
	return subnets
}

func aggregateSniffCountries(enriched []enrichedSniffItem) []SniffCountryStat {
	type countryAgg struct {
		code    string
		country string
		flag    string
		ips     int
		subnets map[string]struct{}
		hits    int
	}
	countryMap := make(map[string]*countryAgg)
	for _, it := range enriched {
		code := strings.ToUpper(strings.TrimSpace(it.geo.CountryCode))
		name := strings.TrimSpace(it.geo.Country)
		flag := it.geo.Flag
		if code == "" {
			if it.tag != "" {
				code = "SCAN"
				name = it.tag
				flag = "🛰️"
			} else {
				code = "UNK"
				name = "解析中 / 未知地区"
				flag = "🌐"
			}
		} else if name == "" {
			if cn, ok := commonCountryNames[code]; ok {
				name = cn
			} else {
				name = code
			}
		}
		cAgg, exists := countryMap[code]
		if !exists {
			cAgg = &countryAgg{
				code:    code,
				country: name,
				flag:    flag,
				subnets: make(map[string]struct{}),
			}
			countryMap[code] = cAgg
		}
		cAgg.ips++
		cAgg.hits += it.rec.hits
		if it.rec.subnet != "" {
			cAgg.subnets[it.rec.subnet] = struct{}{}
		}
	}

	totalIPCount := len(enriched)
	countries := make([]SniffCountryStat, 0, len(countryMap))
	for _, cAgg := range countryMap {
		ratio := 0.0
		if totalIPCount > 0 {
			ratio = float64(cAgg.ips) * 100.0 / float64(totalIPCount)
			ratio = float64(int(ratio*10+0.5)) / 10.0
		}
		countries = append(countries, SniffCountryStat{
			CountryCode:   cAgg.code,
			Country:       cAgg.country,
			Flag:          cAgg.flag,
			UniqueIPs:     cAgg.ips,
			UniqueSubnets: len(cAgg.subnets),
			TotalHits:     cAgg.hits,
			RatioPercent:  ratio,
		})
	}
	slices.SortFunc(countries, func(a, b SniffCountryStat) int {
		if a.UniqueIPs != b.UniqueIPs {
			return cmp.Compare(b.UniqueIPs, a.UniqueIPs)
		}
		if a.TotalHits != b.TotalHits {
			return cmp.Compare(b.TotalHits, a.TotalHits)
		}
		return cmp.Compare(a.CountryCode, b.CountryCode)
	})
	return countries
}

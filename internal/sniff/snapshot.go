// 文件职责：负责构建外部活跃嗅探三维聚合态势快照（分主机/全集群汇总、四维版本号缓存与 GeoIP 富化）。
package sniff

import (
	"cmp"
	"context"
	"maps"
	"net"
	"slices"
	"strings"
	"time"

	"singctl/internal/netdiag/ipgeo"
)

type mergedSniffRecord struct {
	rec   sniffRecord
	nodes []NodeRef
}

type enrichedSniffItem struct {
	rec   sniffRecord
	nodes []NodeRef
	geo   ipgeo.Info
	tag   string
}

// Snapshot 采集并生成默认视角（全集群/本机）的活跃嗅探态势快照（非阻塞纯内存快照 + 后台异步采集）。
func (t *Tracker) Snapshot(ctx context.Context, activeProxyClientIPs ...string) Summary {
	if len(activeProxyClientIPs) > 0 {
		t.MarkTrustedClientIPs(activeProxyClientIPs...)
	}
	t.triggerBackgroundSystemHarvestIfNeeded()
	t.triggerBackgroundRemoteHarvestIfNeeded()
	return t.buildSnapshot(ctx, "all", false, true)
}

// SnapshotForNode 采集并生成指定主机视角 ("all" | "local" | "<node_id>") 的全量活跃嗅探三维态势快照。
func (t *Tracker) SnapshotForNode(ctx context.Context, nodeScope string, forceRefresh bool, activeProxyClientIPs ...string) Summary {
	if len(activeProxyClientIPs) > 0 {
		t.MarkTrustedClientIPs(activeProxyClientIPs...)
	}
	if !forceRefresh {
		t.triggerBackgroundSystemHarvestIfNeeded()
		t.triggerBackgroundRemoteHarvestIfNeeded()
		return t.buildSnapshot(ctx, nodeScope, false, true)
	}
	return t.buildSnapshot(ctx, nodeScope, true, false)
}

func (t *Tracker) currentDepsRevisions() (geoRev, limiterRev, remoteRev uint64) {
	if t.geo != nil {
		geoRev = t.geo.Revision()
	}
	if t.limiter != nil {
		limiterRev = t.limiter.Revision()
	}
	t.mu.RLock()
	rp := t.remote
	t.mu.RUnlock()
	if rp != nil && rp.Revision != nil {
		remoteRev = rp.Revision()
	}
	return geoRev, limiterRev, remoteRev
}

func cloneSummary(src Summary) Summary {
	cp := src
	cp.Nodes = slices.Clone(src.Nodes)
	cp.TopIPs = slices.Clone(src.TopIPs)
	cp.TopSubnets = slices.Clone(src.TopSubnets)
	cp.TopCountries = slices.Clone(src.TopCountries)
	return cp
}

func (t *Tracker) buildSnapshot(ctx context.Context, nodeScope string, forceRefresh, nonBlocking bool) Summary {
	if ctx == nil {
		ctx = context.Background()
	}
	nodeScope = cmp.Or(strings.TrimSpace(nodeScope), "all")
	remoteNodes, enableProbe := t.loadClusterRemoteTargets()

	if nonBlocking && !forceRefresh {
		geoRev, limiterRev, remoteRev := t.currentDepsRevisions()
		t.mu.RLock()
		entry, hit := t.snapCache[nodeScope]
		curDataRev := t.dataRev
		t.mu.RUnlock()
		if hit &&
			entry.dataRev == curDataRev &&
			entry.geoRev == geoRev &&
			entry.limiterRev == limiterRev &&
			entry.remoteRev == remoteRev &&
			entry.nodeCount == len(remoteNodes) &&
			time.Since(entry.builtAt) < 5*time.Second {
			return cloneSummary(entry.summary)
		}
	}

	t.snapshotRebuilds.Add(1)
	startGeoRev, startLimiterRev, startRemoteRev := t.currentDepsRevisions()

	t.syncLimiterAttempts()
	if !nonBlocking && (nodeScope == "all" || nodeScope == "local") {
		t.maybeHarvestSystemSources(ctx, forceRefresh)
	}
	if !nonBlocking && enableProbe && len(remoteNodes) > 0 && nodeScope != "local" {
		t.maybeHarvestRemoteTargets(ctx, remoteNodes, nodeScope, forceRefresh)
	}

	now := time.Now()
	nodeSummaries, mergedByIP, blockedCIDRs, builtDataRev := t.collectActiveSniffRecords(nodeScope, remoteNodes, now)
	t.scheduleAsyncSaveIfNeeded()

	enriched, totalBanned := t.resolveAndSortSniffIPs(ctx, mergedByIP, nonBlocking)
	topIPs := buildIPStats(enriched)
	subnets := aggregateSubnets(enriched, blockedCIDRs)
	countries := aggregateCountries(enriched)

	summary := Summary{
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

	t.mu.Lock()
	if t.snapCache == nil {
		t.snapCache = make(map[string]snapshotCacheEntry)
	}
	if len(t.snapCache) >= 32 {
		clear(t.snapCache)
	}
	t.snapCache[nodeScope] = snapshotCacheEntry{
		dataRev:    builtDataRev,
		geoRev:     startGeoRev,
		limiterRev: startLimiterRev,
		remoteRev:  startRemoteRev,
		nodeCount:  len(remoteNodes),
		builtAt:    time.Now(),
		summary:    cloneSummary(summary),
	}
	t.mu.Unlock()
	return summary
}

func (t *Tracker) syncLimiterAttempts() {
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
		if IsIgnoredInternalIP(att.IP) || att.Source == BanSourceManualSniff {
			continue
		}
		st := "observing"
		if att.Banned {
			st = "banned"
		}
		t.observeNodeAtLocked("local", "本机网关", att.IP, "Web 管理端密码试探", st, att.FailCount, true, att.LastFail, att.LastFail)
	}
}

func (t *Tracker) loadClusterRemoteTargets() ([]RemoteTarget, bool) {
	t.mu.RLock()
	rp := t.remote
	enableProbe := t.EnableSystemProbe
	t.mu.RUnlock()

	if rp == nil || rp.ListTargets == nil {
		return nil, enableProbe
	}
	list, err := rp.ListTargets()
	if err != nil {
		return nil, enableProbe
	}
	var clusterHosts []string
	for _, rn := range list {
		if h := strings.TrimSpace(rn.Host); h != "" {
			clusterHosts = append(clusterHosts, h)
		}
	}
	if len(clusterHosts) > 0 {
		t.MarkTrustedClientIPs(clusterHosts...)
	}
	return list, enableProbe
}

func appendUniqueNodeRef(nodes []NodeRef, ref NodeRef) []NodeRef {
	for _, existing := range nodes {
		if existing.ID == ref.ID {
			return nodes
		}
	}
	return append(nodes, ref)
}

func (t *Tracker) pruneExpiredRecordsLocked(now time.Time) {
	for _, nodeMap := range t.recordsByNode {
		for ip, rec := range nodeMap {
			if now.Sub(rec.lastSeen) > sniffEntryTTL {
				delete(nodeMap, ip)
				t.markDirtyLocked()
				continue
			}
			if exp, trusted := t.trustedClients[ip]; trusted && now.Before(exp) && rec.status != "banned" {
				delete(nodeMap, ip)
				t.markDirtyLocked()
			}
		}
	}
}

func (t *Tracker) buildSingleNodeSummaryLocked(nid, name, host string, online bool, clusterIPs, clusterSubnets, clusterBanned map[string]struct{}) NodeSummary {
	nm := t.recordsByNode[nid]
	subs := make(map[string]struct{})
	banned := 0
	for _, rec := range nm {
		clusterIPs[rec.ip] = struct{}{}
		if rec.subnet != "" {
			subs[rec.subnet] = struct{}{}
			clusterSubnets[rec.subnet] = struct{}{}
		}
		if rec.status == "banned" {
			banned++
			clusterBanned[rec.ip] = struct{}{}
		}
	}
	var lastHarv, errStr string
	if meta := t.nodeMeta[nid]; meta != nil {
		if !meta.lastHarvest.IsZero() {
			lastHarv = formatSniffTime(meta.lastHarvest)
		}
		errStr = meta.lastError
	}
	return NodeSummary{
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

func (t *Tracker) buildNodeSummariesLocked(remoteNodes []RemoteTarget, now time.Time) ([]NodeSummary, map[string]NodeRef, []NodeSummary) {
	nodeInfoMap := map[string]NodeRef{"local": {ID: "local", Name: "本机网关"}}
	for _, fn := range remoteNodes {
		nodeInfoMap[fn.ID] = NodeRef{ID: fn.ID, Name: cmp.Or(fn.Name, fn.ID), Host: fn.Host}
	}

	clusterIPSet := make(map[string]struct{})
	clusterSubnetSet := make(map[string]struct{})
	clusterBannedSet := make(map[string]struct{})

	localSum := t.buildSingleNodeSummaryLocked("local", "本机网关", "", true, clusterIPSet, clusterSubnetSet, clusterBannedSet)
	remoteSums := make([]NodeSummary, 0, len(remoteNodes))
	for _, fn := range remoteNodes {
		remoteSums = append(remoteSums, t.buildSingleNodeSummaryLocked(fn.ID, cmp.Or(fn.Name, fn.ID), fn.Host, fn.Online, clusterIPSet, clusterSubnetSet, clusterBannedSet))
	}
	for nid, nm := range t.recordsByNode {
		if nid == "local" || len(nm) == 0 {
			continue
		}
		if _, exists := nodeInfoMap[nid]; exists {
			continue
		}
		sampleName := nid
		for _, r := range nm {
			if r.nodeName != "" {
				sampleName = r.nodeName
				break
			}
		}
		nodeInfoMap[nid] = NodeRef{ID: nid, Name: sampleName}
		remoteSums = append(remoteSums, t.buildSingleNodeSummaryLocked(nid, sampleName, "", true, clusterIPSet, clusterSubnetSet, clusterBannedSet))
	}

	all := make([]NodeSummary, 0, 2+len(remoteSums))
	all = append(all, NodeSummary{
		ID:            "all",
		Name:          "全集群汇总",
		Online:        true,
		TotalSniffIPs: len(clusterIPSet),
		TotalSubnets:  len(clusterSubnetSet),
		TotalBanned:   len(clusterBannedSet),
		LastHarvestAt: formatSniffTime(now),
	}, localSum)
	all = append(all, remoteSums...)
	return all, nodeInfoMap, remoteSums
}

func (t *Tracker) mergeNodeRecordsIntoLocked(nid string, nodeInfoMap map[string]NodeRef, dst map[string]*mergedSniffRecord) {
	nm := t.recordsByNode[nid]
	nRef, ok := nodeInfoMap[nid]
	if !ok {
		nRef = NodeRef{ID: nid, Name: nid}
	}
	for _, r := range nm {
		existing, ok := dst[r.ip]
		if !ok {
			cp := *r
			cp.firstSeen = cmp.Or(cp.firstSeen, cp.lastSeen)
			dst[r.ip] = &mergedSniffRecord{rec: cp, nodes: []NodeRef{nRef}}
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

func (t *Tracker) collectActiveSniffRecords(nodeScope string, remoteNodes []RemoteTarget, now time.Time) ([]NodeSummary, map[string]*mergedSniffRecord, map[string]*net.IPNet, uint64) {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.pruneExpiredRecordsLocked(now)
	nodeSummaries, nodeInfoMap, remoteSums := t.buildNodeSummariesLocked(remoteNodes, now)

	mergedByIP := make(map[string]*mergedSniffRecord)
	if nodeScope == "all" {
		t.mergeNodeRecordsIntoLocked("local", nodeInfoMap, mergedByIP)
		for _, rs := range remoteSums {
			t.mergeNodeRecordsIntoLocked(rs.ID, nodeInfoMap, mergedByIP)
		}
	} else {
		t.mergeNodeRecordsIntoLocked(nodeScope, nodeInfoMap, mergedByIP)
	}

	blockedCIDRs := maps.Clone(t.manualBlockedCIDRs)
	if blockedCIDRs == nil {
		blockedCIDRs = make(map[string]*net.IPNet)
	}
	if nodeScope != "all" {
		maps.Copy(blockedCIDRs, t.nodeBlockedCIDRs[nodeScope])
	}
	return nodeSummaries, mergedByIP, blockedCIDRs, t.dataRev
}

func (t *Tracker) resolveAndSortSniffIPs(ctx context.Context, mergedByIP map[string]*mergedSniffRecord, nonBlocking bool) ([]enrichedSniffItem, int) {
	var geoMap map[string]ipgeo.Info
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
		var geo ipgeo.Info
		if geoMap != nil {
			geo = geoMap[m.rec.ip]
		}
		tag := cmp.Or(m.rec.scannerTag, MatchScannerTag(m.rec.ip, geo.ISP))
		if m.rec.status == "banned" {
			totalBanned++
		}
		enriched = append(enriched, enrichedSniffItem{rec: m.rec, nodes: m.nodes, geo: geo, tag: tag})
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

func buildIPStats(enriched []enrichedSniffItem) []IPStat {
	topIPs := make([]IPStat, 0, len(enriched))
	for _, it := range enriched {
		topIPs = append(topIPs, IPStat{
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

func aggregateSubnets(enriched []enrichedSniffItem, blockedCIDRs map[string]*net.IPNet) []SubnetStat {
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
		nodes       []NodeRef
	}
	subnetMap := make(map[string]*subnetAgg)
	for _, it := range enriched {
		cidr := cmp.Or(it.rec.subnet, ComputeSubnetCIDR(it.rec.ip))
		if cidr == "" {
			continue
		}
		agg, exists := subnetMap[cidr]
		if !exists {
			agg = &subnetAgg{cidr: cidr, scannerTag: it.tag, firstSeen: it.rec.firstSeen, lastSeen: it.rec.lastSeen}
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

	subnets := make([]SubnetStat, 0, len(subnetMap))
	for _, agg := range subnetMap {
		st := "active"
		if _, wholeBanned := blockedCIDRs[agg.cidr]; wholeBanned || (agg.uniqueIPs > 0 && agg.bannedCount == agg.uniqueIPs) {
			st = "banned"
		} else if agg.bannedCount > 0 {
			st = "partial"
		}
		subnets = append(subnets, SubnetStat{
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
	slices.SortFunc(subnets, func(a, b SubnetStat) int {
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

func aggregateCountries(enriched []enrichedSniffItem) []CountryStat {
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
				code, name, flag = "SCAN", it.tag, "🛰️"
			} else {
				code, name, flag = "UNK", "解析中 / 未知地区", "🌐"
			}
		} else if name == "" {
			name = ipgeo.ResolveCountryDisplayName(code, code)
		}
		cAgg, exists := countryMap[code]
		if !exists {
			cAgg = &countryAgg{code: code, country: name, flag: flag, subnets: make(map[string]struct{})}
			countryMap[code] = cAgg
		}
		cAgg.ips++
		cAgg.hits += it.rec.hits
		if it.rec.subnet != "" {
			cAgg.subnets[it.rec.subnet] = struct{}{}
		}
	}

	totalIPCount := len(enriched)
	countries := make([]CountryStat, 0, len(countryMap))
	for _, cAgg := range countryMap {
		ratio := 0.0
		if totalIPCount > 0 {
			ratio = float64(cAgg.ips) * 100.0 / float64(totalIPCount)
			ratio = float64(int(ratio*10+0.5)) / 10.0
		}
		countries = append(countries, CountryStat{
			CountryCode:   cAgg.code,
			Country:       cAgg.country,
			Flag:          cAgg.flag,
			UniqueIPs:     cAgg.ips,
			UniqueSubnets: len(cAgg.subnets),
			TotalHits:     cAgg.hits,
			RatioPercent:  ratio,
		})
	}
	slices.SortFunc(countries, func(a, b CountryStat) int {
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

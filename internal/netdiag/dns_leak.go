package netdiag

import (
	"bytes"
	"cmp"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"singctl/internal/config"
	"singctl/internal/gateway"
)

const (
	dnsTypeA     uint16 = 1
	dnsTypeTXT   uint16 = 16
	dnsTypeAAAA  uint16 = 28
	dnsTypeHTTPS uint16 = 65
)

var fakeIPv4Prefix = netip.MustParsePrefix("198.18.0.0/15")

// DNSLeakCheckItem 表示单项 DNS 防泄漏或分流探测结果。
type DNSLeakCheckItem struct {
	ID        string `json:"id"`
	Title     string `json:"title"`
	Status    string `json:"status"` // "pass" | "warn" | "fail"
	LatencyMs int64  `json:"latencyMs,omitempty"`
	Summary   string `json:"summary"`
	Detail    string `json:"detail,omitempty"`
}

// DNSResolverProfile 描述实际触达海外权威节点的递归 DNS 解析器画像。
type DNSResolverProfile struct {
	IP             string `json:"ip,omitempty"`
	Country        string `json:"country,omitempty"`
	CountryCode    string `json:"countryCode,omitempty"`
	ISP            string `json:"isp,omitempty"`
	ECS            string `json:"ecs,omitempty"`
	ECSCountryCode string `json:"ecsCountryCode,omitempty"`
}

// EgressEndpoint 描述单条外网出口链路的实测 IP 与地理归属详情。
type EgressEndpoint struct {
	IP          string `json:"ip,omitempty"`
	Country     string `json:"country,omitempty"`
	CountryCode string `json:"countryCode,omitempty"`
	Region      string `json:"region,omitempty"`
	City        string `json:"city,omitempty"`
	ISP         string `json:"isp,omitempty"`
	ASN         string `json:"asn,omitempty"`
	LatencyMs   int64  `json:"latencyMs,omitempty"`
	Reachable   bool   `json:"reachable"`
	Error       string `json:"error,omitempty"`
}

// EgressMatrix 汇总网关侧四路双栈（国内/海外 × IPv4/IPv6）外网出口探测结果。
type EgressMatrix struct {
	DomesticIPv4 *EgressEndpoint `json:"domesticIpv4,omitempty"`
	DomesticIPv6 *EgressEndpoint `json:"domesticIpv6,omitempty"`
	OverseasIPv4 *EgressEndpoint `json:"overseasIpv4,omitempty"`
	OverseasIPv6 *EgressEndpoint `json:"overseasIpv6,omitempty"`
}

// DNSServerObservation 描述多轮防缓存扫描聚合出的单个递归 DNS 解析器记录。
type DNSServerObservation struct {
	IP             string `json:"ip"`
	Country        string `json:"country,omitempty"`
	CountryCode    string `json:"countryCode,omitempty"`
	ISP            string `json:"isp,omitempty"`
	ECS            string `json:"ecs,omitempty"`
	ECSCountryCode string `json:"ecsCountryCode,omitempty"`
	Hits           int    `json:"hits"`
	Source         string `json:"source"` // "gateway" | "port53_hijack"
	Leaked         bool   `json:"leaked"`
	LeakReason     string `json:"leakReason,omitempty"`
}

// EDNSProbeResult 描述单次随机子域 edns.ip-api.com 探测返回。
type EDNSProbeResult struct {
	DNSIP   string
	DNSGeo  string
	EDNSIP  string
	EDNSGeo string
}

// DNSLeakReport 汇总 WebUI 与诊断终端展示的 5 维 DNS 防泄漏与 IPv6 分流实测报告。
type DNSLeakReport struct {
	Verdict          string                 `json:"verdict"` // "safe" | "warning" | "leaked"
	IPv6Mode         string                 `json:"ipv6Mode"`
	CheckedAt        string                 `json:"checkedAt"`
	DurationMs       int64                  `json:"durationMs"`
	HomePublicIP     string                 `json:"homePublicIp,omitempty"`
	HomeISP          string                 `json:"homeIsp,omitempty"`
	OverseasResolver *DNSResolverProfile    `json:"overseasResolver,omitempty"`
	Egress           *EgressMatrix          `json:"egress,omitempty"`
	DNSServers       []DNSServerObservation `json:"dnsServers,omitempty"`
	GatewayRounds    int                    `json:"gatewayRounds"`
	Checks           []DNSLeakCheckItem     `json:"checks"`
}

// DNSLeakTestOptions 配置实测环境参数及单测可注入的探测钩子。
type DNSLeakTestOptions struct {
	IPv6Mode          string
	GatewayMode       string
	SingBoxRunning    bool
	AdGuardHealthy    bool
	IPv6Status        gateway.IPv6StatusInfo
	PrimaryDNS        string
	PlaintextProbeDNS string
	SkipTCP6Dial      bool
	GatewayRounds     int
	SkipMultiProbe    bool
	MultiProbeFetcher func(ctx context.Context, round int) (*EDNSProbeResult, error)
	EgressProber      func(ctx context.Context) *EgressMatrix
	LookupISP         func(ctx context.Context, ip string) (*ISPInfo, error)
	LookupHomeISP     func(ctx context.Context) (*ISPInfo, error)
}

type dnsAnswerSet struct {
	As         []string
	AAAAs      []string
	TXTs       []string
	HTTPSCount int
	RCode      uint8
}

func clampGatewayRounds(n int) int {
	if n <= 0 {
		return 8
	}
	if n > 20 {
		return 20
	}
	return n
}

// RunDNSLeakTest 并发执行四路双栈出口、多轮唯一随机子域 DNS 扫描与 5 维真实防泄漏检查。
func RunDNSLeakTest(ctx context.Context, opts DNSLeakTestOptions) *DNSLeakReport {
	start := time.Now()
	testCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	ipv6Mode, ok := config.NormalizeGatewayIPv6Mode(opts.IPv6Mode)
	if !ok {
		ipv6Mode = config.GatewayIPv6Off
	}
	gwMode := strings.ToLower(strings.TrimSpace(opts.GatewayMode))
	if gwMode == "" {
		gwMode = gateway.ModeMain
	}
	plaintextDNS := cmp.Or(strings.TrimSpace(opts.PlaintextProbeDNS), "114.114.114.114:53")
	lookupBase := opts.LookupISP
	if lookupBase == nil {
		lookupBase = lookupTargetISPWithFallback
	}
	lookupISP := newMemoizedISPLookup(lookupBase)

	lookupHome := opts.LookupHomeISP
	if lookupHome == nil {
		lookupHome = GetPublicISP
	}

	var homeOnce sync.Once
	var homeCached *ISPInfo
	getHome := func() *ISPInfo {
		homeOnce.Do(func() {
			info, err := lookupHome(testCtx)
			if err == nil && info != nil {
				homeCached = info
			}
		})
		return homeCached
	}

	runMultiProbe := !opts.SkipMultiProbe && !(strings.TrimSpace(opts.PrimaryDNS) != "" && opts.MultiProbeFetcher == nil)
	requestedRounds := clampGatewayRounds(opts.GatewayRounds)
	if !runMultiProbe {
		requestedRounds = 0
	}

	var egress *EgressMatrix
	var txtResIP, txtECSCIDR, txtViaAddr string
	var txtErr error
	var txtLatencyMs int64
	var ednsSamples []*EDNSProbeResult
	var port53Item DNSLeakCheckItem
	var overseasResItem DNSLeakCheckItem
	var ipv6SplitItem DNSLeakCheckItem

	var wg sync.WaitGroup
	wg.Add(5)

	// 1. 四路双栈出口矩阵探测（或单测离线 mock 构建）
	go func() {
		defer wg.Done()
		switch {
		case opts.EgressProber != nil:
			egress = opts.EgressProber(testCtx)
		case opts.LookupHomeISP != nil || strings.TrimSpace(opts.PrimaryDNS) != "":
			if info := getHome(); info != nil && strings.TrimSpace(info.IP) != "" {
				egress = &EgressMatrix{
					DomesticIPv4: &EgressEndpoint{
						IP:          strings.TrimSpace(info.IP),
						Country:     info.Country,
						CountryCode: strings.ToUpper(strings.TrimSpace(info.CountryCode)),
						Region:      info.Region,
						City:        info.City,
						ISP:         cmp.Or(info.ISP, info.Org),
						ASN:         info.ASN,
						Reachable:   true,
					},
				}
			}
		default:
			egress = probeEgressMatrix(testCtx, ipv6Mode, lookupISP)
		}
	}()

	// 2. 海外代理 DNS 出口 TXT 溯源 + 多轮唯一随机子域防缓存扫探
	go func() {
		defer wg.Done()
		var subWg sync.WaitGroup
		subWg.Add(1)
		go func() {
			defer subWg.Done()
			t0 := time.Now()
			txtResIP, txtECSCIDR, txtViaAddr, txtErr = probeDNSEgressResolver(testCtx, opts.PrimaryDNS)
			txtLatencyMs = max(1, time.Since(t0).Milliseconds())
		}()
		if runMultiProbe {
			subWg.Add(1)
			go func() {
				defer subWg.Done()
				ednsSamples = probeGatewayEDNSRounds(testCtx, requestedRounds, opts.MultiProbeFetcher)
			}()
		}
		subWg.Wait()
	}()

	// 3. 明文 :53 透明劫持检验
	go func() {
		defer wg.Done()
		port53Item = checkPort53Hijack(testCtx, plaintextDNS, lookupISP, getHome)
	}()

	// 4. 海外域名防投毒解析校验
	go func() {
		defer wg.Done()
		overseasResItem = checkOverseasResolution(testCtx, opts.PrimaryDNS)
	}()

	// 5. IPv6 AAAA 分流与防泄漏 DNS 实测
	go func() {
		defer wg.Done()
		ipv6SplitItem = checkIPv6Split(testCtx, ipv6Mode, opts)
	}()

	wg.Wait()

	// 补全家庭出口基准（优先复用四路矩阵中的国内 IPv4，避免重复查外网）
	homeIPv4 := ""
	homeISPDesc := ""
	homeIPv6 := ""
	if egress != nil {
		if egress.DomesticIPv4 != nil && egress.DomesticIPv4.Reachable && egress.DomesticIPv4.IP != "" {
			homeIPv4 = egress.DomesticIPv4.IP
			homeISPDesc = strings.TrimSpace(cmp.Or(egress.DomesticIPv4.ISP, egress.DomesticIPv4.ASN, egress.DomesticIPv4.Country))
		}
		if egress.DomesticIPv6 != nil && egress.DomesticIPv6.Reachable && egress.DomesticIPv6.IP != "" {
			homeIPv6 = egress.DomesticIPv6.IP
		}
	}
	if homeIPv4 == "" {
		if info := getHome(); info != nil {
			homeIPv4 = strings.TrimSpace(info.IP)
			homeISPDesc = strings.TrimSpace(cmp.Or(info.ISP, info.ASN, info.Country))
		}
	}

	dnsServers, resolverProfile := aggregateDNSObservations(
		testCtx,
		ednsSamples,
		txtResIP,
		txtECSCIDR,
		homeIPv4,
		homeIPv6,
		lookupISP,
	)

	egressItem := buildOverseasDNSEgressCheck(
		dnsServers,
		resolverProfile,
		txtViaAddr,
		txtErr,
		txtLatencyMs,
		len(ednsSamples),
		requestedRounds,
	)
	ipv6SplitItem = refineIPv6SplitWithEgress(ipv6SplitItem, ipv6Mode, egress, homeIPv6)
	baselineItem := checkGatewayBaseline(ipv6Mode, gwMode, opts)

	results := []DNSLeakCheckItem{
		egressItem,
		port53Item,
		overseasResItem,
		ipv6SplitItem,
		baselineItem,
	}

	verdict := "safe"
	for _, item := range results {
		if item.Status == "fail" {
			verdict = "leaked"
			break
		}
		if item.Status == "warn" {
			verdict = "warning"
		}
	}

	return &DNSLeakReport{
		Verdict:          verdict,
		IPv6Mode:         ipv6Mode,
		CheckedAt:        time.Now().Format(time.RFC3339),
		DurationMs:       max(1, time.Since(start).Milliseconds()),
		HomePublicIP:     homeIPv4,
		HomeISP:          homeISPDesc,
		OverseasResolver: resolverProfile,
		Egress:           egress,
		DNSServers:       dnsServers,
		GatewayRounds:    requestedRounds,
		Checks:           results,
	}
}

func newMemoizedISPLookup(fn func(context.Context, string) (*ISPInfo, error)) func(context.Context, string) (*ISPInfo, error) {
	var mu sync.Mutex
	cache := make(map[string]*ISPInfo)
	return func(ctx context.Context, ip string) (*ISPInfo, error) {
		key := strings.TrimSpace(ip)
		if key == "" {
			return nil, errors.New("empty ip")
		}
		mu.Lock()
		if cached, ok := cache[key]; ok {
			mu.Unlock()
			if cached == nil {
				return nil, errors.New("cached lookup failure")
			}
			return cached, nil
		}
		mu.Unlock()

		info, err := fn(ctx, key)
		mu.Lock()
		if err == nil && info != nil {
			cache[key] = info
		} else {
			cache[key] = nil
		}
		mu.Unlock()
		return info, err
	}
}

func sameIPv6Prefix48(a, b string) bool {
	addrA, errA := netip.ParseAddr(strings.TrimSpace(a))
	addrB, errB := netip.ParseAddr(strings.TrimSpace(b))
	if errA != nil || errB != nil {
		return false
	}
	addrA = addrA.Unmap()
	addrB = addrB.Unmap()
	if !addrA.Is6() || !addrB.Is6() {
		return false
	}
	return netip.PrefixFrom(addrA, 48).Masked() == netip.PrefixFrom(addrB, 48).Masked()
}

var countryNameToISO2 = map[string]string{
	"china":                "CN",
	"peoples republic of china": "CN",
	"united states":        "US",
	"united states of america": "US",
	"usa":                  "US",
	"japan":                "JP",
	"hong kong":            "HK",
	"taiwan":               "TW",
	"macao":                "MO",
	"macau":                "MO",
	"singapore":            "SG",
	"united kingdom":       "GB",
	"great britain":        "GB",
	"germany":              "DE",
	"south korea":          "KR",
	"korea":                "KR",
	"republic of korea":    "KR",
	"netherlands":          "NL",
	"the netherlands":      "NL",
	"canada":               "CA",
	"australia":            "AU",
	"france":               "FR",
	"russia":               "RU",
	"russian federation":   "RU",
	"india":                "IN",
	"switzerland":          "CH",
	"sweden":               "SE",
	"finland":              "FI",
	"ireland":              "IE",
	"brazil":               "BR",
	"indonesia":            "ID",
	"malaysia":             "MY",
	"thailand":             "TH",
	"vietnam":              "VN",
	"philippines":          "PH",
	"turkey":               "TR",
	"türkiye":              "TR",
	"united arab emirates": "AE",
	"italy":                "IT",
	"spain":                "ES",
	"poland":               "PL",
	"ukraine":              "UA",
	"norway":               "NO",
	"denmark":              "DK",
	"austria":              "AT",
	"belgium":              "BE",
	"new zealand":          "NZ",
	"mexico":               "MX",
	"argentina":            "AR",
	"south africa":         "ZA",
	"israel":               "IL",
}

func parseEDNSGeo(geo string) (country, countryCode, isp string) {
	trimmed := strings.TrimSpace(geo)
	if trimmed == "" {
		return "", "", ""
	}
	if left, right, ok := strings.Cut(trimmed, " - "); ok {
		country = strings.TrimSpace(left)
		isp = strings.TrimSpace(right)
	} else {
		country = trimmed
	}
	if code, ok := countryNameToISO2[strings.ToLower(country)]; ok {
		countryCode = code
	} else if len(country) == 2 {
		countryCode = strings.ToUpper(country)
	} else if country == "中国" {
		countryCode = "CN"
	}
	return country, countryCode, isp
}

func probeGatewayEDNSRounds(
	ctx context.Context,
	rounds int,
	fetcher func(context.Context, int) (*EDNSProbeResult, error),
) []*EDNSProbeResult {
	if rounds <= 0 {
		return nil
	}
	if fetcher == nil {
		client := &http.Client{Timeout: 4 * time.Second}
		fetcher = func(reqCtx context.Context, _ int) (*EDNSProbeResult, error) {
			return fetchOneEDNSProbe(reqCtx, client)
		}
	}

	out := make([]*EDNSProbeResult, rounds)
	sem := make(chan struct{}, 6)
	var wg sync.WaitGroup
	for i := range rounds {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				return
			}
			res, err := fetcher(ctx, idx)
			if err == nil && res != nil && strings.TrimSpace(res.DNSIP) != "" {
				out[idx] = res
			}
		}(i)
	}
	wg.Wait()

	cleaned := make([]*EDNSProbeResult, 0, rounds)
	for _, r := range out {
		if r != nil {
			cleaned = append(cleaned, r)
		}
	}
	return cleaned
}

func fetchOneEDNSProbe(ctx context.Context, client *http.Client) (*EDNSProbeResult, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return nil, err
	}
	url := fmt.Sprintf("https://%x.edns.ip-api.com/json", raw[:])
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("edns probe HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8192))
	if err != nil {
		return nil, err
	}
	var payload struct {
		DNS *struct {
			IP  string `json:"ip"`
			Geo string `json:"geo"`
		} `json:"dns"`
		EDNS *struct {
			IP  string `json:"ip"`
			Geo string `json:"geo"`
		} `json:"edns"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, err
	}
	if payload.DNS == nil || strings.TrimSpace(payload.DNS.IP) == "" {
		return nil, errors.New("edns probe missing dns.ip")
	}
	res := &EDNSProbeResult{
		DNSIP:  strings.TrimSpace(payload.DNS.IP),
		DNSGeo: strings.TrimSpace(payload.DNS.Geo),
	}
	if payload.EDNS != nil {
		res.EDNSIP = strings.TrimSpace(payload.EDNS.IP)
		res.EDNSGeo = strings.TrimSpace(payload.EDNS.Geo)
	}
	return res, nil
}

func newFamilyHTTPClient(network string, timeout time.Duration) *http.Client {
	dialer := &net.Dialer{Timeout: timeout}
	tr := &http.Transport{
		DisableKeepAlives: true,
		DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, addr)
		},
	}
	return &http.Client{
		Timeout:   timeout,
		Transport: tr,
	}
}

func probeEgressMatrix(
	ctx context.Context,
	ipv6Mode string,
	lookupISP func(context.Context, string) (*ISPInfo, error),
) *EgressMatrix {
	matrix := &EgressMatrix{}
	var wg sync.WaitGroup
	wg.Add(4)

	go func() {
		defer wg.Done()
		ep := probeIPIPNetEndpoint(ctx, "tcp4")
		if !ep.Reachable || ep.IP == "" {
			if info, err := GetPublicISP(ctx); err == nil && info != nil && strings.TrimSpace(info.IP) != "" {
				ep = &EgressEndpoint{
					IP:          strings.TrimSpace(info.IP),
					Country:     info.Country,
					CountryCode: strings.ToUpper(strings.TrimSpace(info.CountryCode)),
					Region:      info.Region,
					City:        info.City,
					ISP:         cmp.Or(info.ISP, info.Org),
					ASN:         info.ASN,
					LatencyMs:   ep.LatencyMs,
					Reachable:   true,
				}
			}
		}
		matrix.DomesticIPv4 = ep
	}()

	go func() {
		defer wg.Done()
		if ipv6Mode == config.GatewayIPv6Off {
			matrix.DomesticIPv6 = &EgressEndpoint{
				Reachable: false,
				Error:     "纯 IPv4 模式（ipv6_mode=off）未启用双栈",
			}
			return
		}
		matrix.DomesticIPv6 = probeIPIPNetEndpoint(ctx, "tcp6")
	}()

	go func() {
		defer wg.Done()
		matrix.OverseasIPv4 = probeGeoJSEndpoint(ctx, "tcp4", "https://ipv4.geojs.io/v1/ip/geo.json", "https://api4.ipify.org?format=json", lookupISP)
	}()

	go func() {
		defer wg.Done()
		matrix.OverseasIPv6 = probeGeoJSEndpoint(ctx, "tcp6", "https://ipv6.geojs.io/v1/ip/geo.json", "", lookupISP)
	}()

	wg.Wait()
	return matrix
}

func probeIPIPNetEndpoint(ctx context.Context, network string) *EgressEndpoint {
	t0 := time.Now()
	client := newFamilyHTTPClient(network, 3500*time.Millisecond)
	defer client.CloseIdleConnections()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://myip.ipip.net/json", nil)
	if err != nil {
		return &EgressEndpoint{Error: err.Error()}
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (singctl netdiag)")
	resp, err := client.Do(req)
	latency := max(1, time.Since(t0).Milliseconds())
	if err != nil {
		return &EgressEndpoint{LatencyMs: latency, Error: err.Error()}
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return &EgressEndpoint{LatencyMs: latency, Error: err.Error()}
	}

	var parsed struct {
		Ret  string `json:"ret"`
		Data struct {
			IP       string   `json:"ip"`
			Location []string `json:"location"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil || strings.TrimSpace(parsed.Data.IP) == "" {
		return &EgressEndpoint{LatencyMs: latency, Error: "myip.ipip.net 返回格式异常"}
	}

	ep := &EgressEndpoint{
		IP:        strings.TrimSpace(parsed.Data.IP),
		LatencyMs: latency,
		Reachable: true,
	}
	loc := parsed.Data.Location
	if len(loc) >= 1 {
		ep.Country = strings.TrimSpace(loc[0])
		if ep.Country == "中国" || strings.EqualFold(ep.Country, "China") {
			ep.CountryCode = "CN"
		}
	}
	if len(loc) >= 2 {
		ep.Region = strings.TrimSpace(loc[1])
	}
	if len(loc) >= 3 {
		ep.City = strings.TrimSpace(loc[2])
	}
	if len(loc) >= 5 && strings.TrimSpace(loc[4]) != "" {
		ep.ISP = strings.TrimSpace(loc[4])
	} else if len(loc) >= 4 && strings.TrimSpace(loc[3]) != "" {
		ep.ISP = strings.TrimSpace(loc[3])
	}
	return ep
}

func probeGeoJSEndpoint(
	ctx context.Context,
	network string,
	geoURL string,
	ipifyFallbackURL string,
	lookupISP func(context.Context, string) (*ISPInfo, error),
) *EgressEndpoint {
	t0 := time.Now()
	client := newFamilyHTTPClient(network, 3500*time.Millisecond)
	defer client.CloseIdleConnections()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, geoURL, nil)
	if err == nil {
		req.Header.Set("Accept", "application/json")
		if resp, dErr := client.Do(req); dErr == nil {
			defer resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				if body, rErr := io.ReadAll(io.LimitReader(resp.Body, 8192)); rErr == nil {
					var g struct {
						IP          string `json:"ip"`
						Country     string `json:"country"`
						CountryCode string `json:"country_code"`
						Region      string `json:"region"`
						City        string `json:"city"`
						OrgName     string `json:"organization_name"`
						Org         string `json:"organization"`
						ASN         int    `json:"asn"`
					}
					if jErr := json.Unmarshal(body, &g); jErr == nil && strings.TrimSpace(g.IP) != "" {
						asnStr := ""
						if g.ASN > 0 {
							asnStr = fmt.Sprintf("AS%d %s", g.ASN, cmp.Or(strings.TrimSpace(g.OrgName), strings.TrimSpace(g.Org)))
						}
						return &EgressEndpoint{
							IP:          strings.TrimSpace(g.IP),
							Country:     strings.TrimSpace(g.Country),
							CountryCode: strings.ToUpper(strings.TrimSpace(g.CountryCode)),
							Region:      strings.TrimSpace(g.Region),
							City:        strings.TrimSpace(g.City),
							ISP:         cmp.Or(strings.TrimSpace(g.OrgName), strings.TrimSpace(g.Org)),
							ASN:         strings.TrimSpace(asnStr),
							LatencyMs:   max(1, time.Since(t0).Milliseconds()),
							Reachable:   true,
						}
					}
				}
			}
		} else {
			err = dErr
		}
	}

	if ipifyFallbackURL != "" {
		if fReq, fErr := http.NewRequestWithContext(ctx, http.MethodGet, ipifyFallbackURL, nil); fErr == nil {
			if resp, dErr := client.Do(fReq); dErr == nil {
				defer resp.Body.Close()
				if resp.StatusCode == http.StatusOK {
					if body, rErr := io.ReadAll(io.LimitReader(resp.Body, 2048)); rErr == nil {
						var ipRes struct {
							IP string `json:"ip"`
						}
						if json.Unmarshal(body, &ipRes) == nil && strings.TrimSpace(ipRes.IP) != "" {
							ep := &EgressEndpoint{
								IP:        strings.TrimSpace(ipRes.IP),
								LatencyMs: max(1, time.Since(t0).Milliseconds()),
								Reachable: true,
							}
							if lookupISP != nil {
								if info, iErr := lookupISP(ctx, ep.IP); iErr == nil && info != nil {
									ep.Country = info.Country
									ep.CountryCode = strings.ToUpper(strings.TrimSpace(info.CountryCode))
									ep.Region = info.Region
									ep.City = info.City
									ep.ISP = cmp.Or(info.ISP, info.Org)
									ep.ASN = info.ASN
								}
							}
							return ep
						}
					}
				}
			}
		}
	}

	errMsg := "unreachable"
	if err != nil {
		errMsg = err.Error()
	}
	return &EgressEndpoint{
		LatencyMs: max(1, time.Since(t0).Milliseconds()),
		Reachable: false,
		Error:     errMsg,
	}
}

func aggregateDNSObservations(
	ctx context.Context,
	samples []*EDNSProbeResult,
	txtResIP string,
	txtECSCIDR string,
	homeIPv4 string,
	homeIPv6 string,
	lookupISP func(context.Context, string) (*ISPInfo, error),
) ([]DNSServerObservation, *DNSResolverProfile) {
	obsMap := make(map[string]*DNSServerObservation)
	addObs := func(ip, country, code, isp, ecs, ecsCode, source string) {
		addr, err := netip.ParseAddr(strings.TrimSpace(ip))
		if err != nil {
			return
		}
		normIP := addr.Unmap().String()
		item, exists := obsMap[normIP]
		if !exists {
			item = &DNSServerObservation{
				IP:          normIP,
				Country:     strings.TrimSpace(country),
				CountryCode: strings.ToUpper(strings.TrimSpace(code)),
				ISP:         strings.TrimSpace(isp),
				ECS:         strings.TrimSpace(ecs),
				ECSCountryCode: strings.ToUpper(strings.TrimSpace(ecsCode)),
				Source:      cmp.Or(source, "gateway"),
			}
			obsMap[normIP] = item
		} else {
			if item.Country == "" && country != "" {
				item.Country = strings.TrimSpace(country)
			}
			if item.CountryCode == "" && code != "" {
				item.CountryCode = strings.ToUpper(strings.TrimSpace(code))
			}
			if item.ISP == "" && isp != "" {
				item.ISP = strings.TrimSpace(isp)
			}
			if item.ECS == "" && ecs != "" {
				item.ECS = strings.TrimSpace(ecs)
			}
			if item.ECSCountryCode == "" && ecsCode != "" {
				item.ECSCountryCode = strings.ToUpper(strings.TrimSpace(ecsCode))
			}
		}
		item.Hits++
	}

	for _, s := range samples {
		if s == nil {
			continue
		}
		c, cc, isp := parseEDNSGeo(s.DNSGeo)
		_, ecsCC, _ := parseEDNSGeo(s.EDNSGeo)
		addObs(s.DNSIP, c, cc, isp, s.EDNSIP, ecsCC, "gateway")
	}
	if strings.TrimSpace(txtResIP) != "" {
		addObs(txtResIP, "", "", "", txtECSCIDR, "", "gateway")
	}

	out := make([]DNSServerObservation, 0, len(obsMap))
	for _, obs := range obsMap {
		if obs.CountryCode == "" || obs.ISP == "" {
			if info, err := lookupISP(ctx, obs.IP); err == nil && info != nil {
				obs.Country = cmp.Or(obs.Country, info.Country)
				obs.CountryCode = cmp.Or(obs.CountryCode, strings.ToUpper(strings.TrimSpace(info.CountryCode)))
				obs.ISP = cmp.Or(obs.ISP, info.ISP, info.Org, info.ASN)
			}
		}
		if obs.ECS != "" && obs.ECSCountryCode == "" {
			ecsQueryIP := strings.TrimSpace(obs.ECS)
			if pfx, err := netip.ParsePrefix(ecsQueryIP); err == nil {
				ecsQueryIP = pfx.Addr().String()
			}
			if info, err := lookupISP(ctx, ecsQueryIP); err == nil && info != nil {
				obs.ECSCountryCode = strings.ToUpper(strings.TrimSpace(info.CountryCode))
			}
		}
		obs.Leaked, obs.LeakReason = evaluateObservationLeak(obs, homeIPv4, homeIPv6)
		out = append(out, *obs)
	}

	slices.SortFunc(out, func(a, b DNSServerObservation) int {
		if a.Leaked != b.Leaked {
			if a.Leaked {
				return -1
			}
			return 1
		}
		if a.Hits != b.Hits {
			return b.Hits - a.Hits
		}
		return strings.Compare(a.IP, b.IP)
	})

	var primary *DNSResolverProfile
	if len(out) > 0 {
		first := out[0]
		primary = &DNSResolverProfile{
			IP:             first.IP,
			Country:        first.Country,
			CountryCode:    first.CountryCode,
			ISP:            first.ISP,
			ECS:            first.ECS,
			ECSCountryCode: first.ECSCountryCode,
		}
	}
	return out, primary
}

func evaluateObservationLeak(obs *DNSServerObservation, homeIPv4, homeIPv6 string) (bool, string) {
	var reasons []string
	if obs.CountryCode == "CN" {
		reasons = append(reasons, fmt.Sprintf("海外解析请求实际由国内 DNS (%s · %s) 代发", obs.IP, cmp.Or(obs.ISP, "CN")))
	}
	if homeIPv4 != "" && obs.IP == homeIPv4 {
		reasons = append(reasons, fmt.Sprintf("DNS 出口暴露为家庭本地公网 IPv4 (%s)", obs.IP))
	}
	if homeIPv6 != "" && (obs.IP == homeIPv6 || sameIPv6Prefix48(obs.IP, homeIPv6)) {
		reasons = append(reasons, fmt.Sprintf("DNS 出口暴露为家庭原生 IPv6 (%s)", obs.IP))
	}
	if obs.ECS != "" {
		if obs.ECSCountryCode == "CN" {
			reasons = append(reasons, fmt.Sprintf("ECS 子网 (%s) 暴露了中国大陆归属", obs.ECS))
		}
		if ecsPrefix, pErr := netip.ParsePrefix(obs.ECS); pErr == nil {
			if homeIPv4 != "" {
				if hAddr, hErr := netip.ParseAddr(homeIPv4); hErr == nil && ecsPrefix.Contains(hAddr.Unmap()) {
					reasons = append(reasons, fmt.Sprintf("ECS 子网 (%s) 直接包含家庭宽带 IP", obs.ECS))
				}
			}
			if homeIPv6 != "" && sameIPv6Prefix48(ecsPrefix.Addr().String(), homeIPv6) {
				reasons = append(reasons, fmt.Sprintf("ECS 子网 (%s) 命中家庭 IPv6 前缀", obs.ECS))
			}
		} else if ecsAddr, aErr := netip.ParseAddr(obs.ECS); aErr == nil {
			ecsUnmapped := ecsAddr.Unmap()
			if homeIPv4 != "" {
				if hAddr, hErr := netip.ParseAddr(homeIPv4); hErr == nil {
					if ecsUnmapped == hAddr.Unmap() || (ecsUnmapped.Is4() && ecsUnmapped.As4()[3] == 0 && netip.PrefixFrom(ecsUnmapped, 24).Contains(hAddr.Unmap())) {
						reasons = append(reasons, fmt.Sprintf("ECS 子网 (%s) 匹配家庭宽带 IP", obs.ECS))
					}
				}
			}
			if homeIPv6 != "" && sameIPv6Prefix48(ecsUnmapped.String(), homeIPv6) {
				reasons = append(reasons, fmt.Sprintf("ECS 子网 (%s) 命中家庭 IPv6 前缀", obs.ECS))
			}
		}
	}
	if len(reasons) > 0 {
		return true, strings.Join(reasons, "；")
	}
	return false, ""
}

func buildOverseasDNSEgressCheck(
	servers []DNSServerObservation,
	primary *DNSResolverProfile,
	viaAddr string,
	txtErr error,
	txtLatencyMs int64,
	ednsSuccessCount int,
	requestedRounds int,
) DNSLeakCheckItem {
	item := DNSLeakCheckItem{
		ID:        "overseas_egress",
		Title:     "海外代理 DNS 出口溯源",
		LatencyMs: max(1, txtLatencyMs),
	}

	if len(servers) == 0 {
		item.Status = "warn"
		item.Summary = "海外 DNS 出口探针暂不可达"
		if txtErr != nil {
			item.Detail = txtErr.Error()
		}
		return item
	}

	leakedCount := 0
	var leakDetails []string
	for _, s := range servers {
		if s.Leaked {
			leakedCount++
			if s.LeakReason != "" {
				leakDetails = append(leakDetails, s.LeakReason)
			}
		}
	}

	if leakedCount > 0 {
		item.Status = "fail"
		item.Summary = fmt.Sprintf("检测到 %d/%d 个海外出口解析器存在本地泄漏风险", leakedCount, len(servers))
		item.Detail = strings.Join(leakDetails, "；")
		return item
	}

	if primary != nil && primary.CountryCode == "" {
		item.Status = "warn"
		item.Summary = fmt.Sprintf("经 %s 探测出口 IP 为 %s（归属库查询超时）", cmp.Or(viaAddr, "gateway"), primary.IP)
		item.Detail = formatResolverProfileLine(primary)
		return item
	}

	item.Status = "pass"
	if ednsSuccessCount > 0 {
		item.Summary = fmt.Sprintf(
			"多轮扫描 %d 轮（%d 轮命中）共发现 %d 个海外出口解析器，零国内泄漏",
			max(requestedRounds, ednsSuccessCount),
			ednsSuccessCount,
			len(servers),
		)
	} else {
		item.Summary = fmt.Sprintf(
			"出口解析器 %s (%s · %s)，零国内泄漏",
			primary.IP,
			primary.CountryCode,
			cmp.Or(primary.ISP, primary.Country, "Overseas"),
		)
	}
	if primary != nil {
		item.Detail = fmt.Sprintf("经 %s 探测 · %s", cmp.Or(viaAddr, "edns-sweep"), formatResolverProfileLine(primary))
	}
	return item
}

func refineIPv6SplitWithEgress(item DNSLeakCheckItem, ipv6Mode string, egress *EgressMatrix, homeIPv6 string) DNSLeakCheckItem {
	if egress == nil || egress.OverseasIPv6 == nil || !egress.OverseasIPv6.Reachable {
		return item
	}
	if ipv6Mode == config.GatewayIPv6Off || ipv6Mode == config.GatewayIPv6CNOnly {
		ov6 := egress.OverseasIPv6
		if strings.EqualFold(ov6.CountryCode, "CN") || (homeIPv6 != "" && sameIPv6Prefix48(ov6.IP, homeIPv6)) {
			item.Status = "fail"
			item.Summary = fmt.Sprintf("检测到海外 IPv6 出口泄漏了家庭宽带 IPv6 (%s)", ov6.IP)
			item.Detail = "海外 HTTPS-IPv6 探针成功经原生 IPv6 直连并返回本地宽带前缀，请检查 AAAA 拦截与路由规则"
		}
	}
	return item
}

func checkPort53Hijack(
	ctx context.Context,
	plaintextDNS string,
	lookupISP func(context.Context, string) (*ISPInfo, error),
	getHome func() *ISPInfo,
) DNSLeakCheckItem {
	t0 := time.Now()
	item := DNSLeakCheckItem{
		ID:    "port53_hijack",
		Title: "明文 :53 透明劫持防护",
	}

	ans, err := queryDNSWithFallback(ctx, []string{plaintextDNS}, "o-o.myaddr.l.google.com", dnsTypeTXT)
	item.LatencyMs = max(1, time.Since(t0).Milliseconds())
	if err != nil {
		item.Status = "warn"
		item.Summary = fmt.Sprintf("向 %s 发送明文 :53 探针超时", plaintextDNS)
		item.Detail = err.Error()
		return item
	}

	resIP, ecsCIDR := parseResolverTXT(ans.TXTs)
	if resIP == "" {
		item.Status = "warn"
		item.Summary = fmt.Sprintf("明文 :53 (%s) 未返回溯源地址", plaintextDNS)
		return item
	}

	info, lErr := lookupISP(ctx, resIP)
	home := getHome()
	if (lErr == nil && info != nil && strings.EqualFold(info.CountryCode, "CN")) || (home != nil && home.IP != "" && resIP == home.IP) {
		item.Status = "fail"
		item.Summary = fmt.Sprintf("明文 :53 发往 %s 未被有效劫持，出口落回 %s", plaintextDNS, resIP)
		item.Detail = "请检查 table inet sing-box 是否正常运行及 th dport 53 劫持链是否生效"
		return item
	}

	locLabel := "海外节点"
	if lErr == nil && info != nil {
		locLabel = fmt.Sprintf("%s · %s", cmp.Or(info.CountryCode, "Overseas"), cmp.Or(info.ISP, info.Country, ""))
	}
	extraECS := ""
	if ecsCIDR != "" {
		extraECS = "，ECS=" + ecsCIDR
	}
	item.Status = "pass"
	item.Summary = fmt.Sprintf("直连 %s 的明文 :53 已被劫持至 %s (%s)", plaintextDNS, resIP, locLabel)
	item.Detail = fmt.Sprintf("局域网设备私自直连外部/光猫 :53 明文 DNS 均会被强制拉回代理隧道%s", extraECS)
	return item
}

func checkOverseasResolution(ctx context.Context, primaryDNS string) DNSLeakCheckItem {
	t0 := time.Now()
	item := DNSLeakCheckItem{
		ID:    "overseas_resolution",
		Title: "海外核心域名防投毒校验",
	}

	targets := []string{"www.google.com", "github.com"}
	resolvedParts := make([]string, 0, len(targets))
	for _, domain := range targets {
		ans, err := queryGatewayDNS(ctx, primaryDNS, domain, dnsTypeA)
		if err != nil || len(ans.As) == 0 {
			item.LatencyMs = max(1, time.Since(t0).Milliseconds())
			item.Status = "fail"
			item.Summary = fmt.Sprintf("海外域名 %s 解析失败或未返回 A 记录", domain)
			if err != nil {
				item.Detail = err.Error()
			}
			return item
		}
		validIP := ""
		for _, ipStr := range ans.As {
			addr, pErr := netip.ParseAddr(ipStr)
			if pErr != nil || !addr.IsGlobalUnicast() || addr.IsPrivate() || addr.IsLoopback() || fakeIPv4Prefix.Contains(addr) {
				continue
			}
			validIP = addr.String()
			break
		}
		if validIP == "" {
			item.LatencyMs = max(1, time.Since(t0).Milliseconds())
			item.Status = "fail"
			item.Summary = fmt.Sprintf("%s 返回异常或内网保留 IP (%v)", domain, ans.As)
			return item
		}
		resolvedParts = append(resolvedParts, fmt.Sprintf("%s → %s", domain, validIP))
	}

	item.LatencyMs = max(1, time.Since(t0).Milliseconds())
	item.Status = "pass"
	item.Summary = strings.Join(resolvedParts, " · ")
	item.Detail = "海外域名经由可信隧道递归解析并返回正常公网 IPv4"
	return item
}

func checkIPv6Split(ctx context.Context, ipv6Mode string, opts DNSLeakTestOptions) DNSLeakCheckItem {
	t0 := time.Now()
	item := DNSLeakCheckItem{
		ID:    "ipv6_split",
		Title: "IPv6 AAAA 分流与防泄漏实测",
	}

	cnANS, cnErr := queryGatewayDNS(ctx, opts.PrimaryDNS, "www.bilibili.com", dnsTypeAAAA)
	if (cnErr != nil || len(cnANS.AAAAs) == 0) && strings.TrimSpace(opts.PrimaryDNS) == "" {
		if fbANS, fbErr := queryGatewayDNS(ctx, opts.PrimaryDNS, "www.taobao.com", dnsTypeAAAA); fbErr == nil && len(fbANS.AAAAs) > 0 {
			cnANS, cnErr = fbANS, nil
		}
	}
	overseasANS, ovErr := queryGatewayDNS(ctx, opts.PrimaryDNS, "www.google.com", dnsTypeAAAA)
	item.LatencyMs = max(1, time.Since(t0).Milliseconds())

	cnCount := len(cnANS.AAAAs)
	ovCount := len(overseasANS.AAAAs)

	switch ipv6Mode {
	case config.GatewayIPv6Off:
		if ovCount > 0 {
			item.Status = "fail"
			item.Summary = fmt.Sprintf("ipv6_mode=off 下仍返回了海外 AAAA 记录 (%s)", overseasANS.AAAAs[0])
			item.Detail = "请检查 dns.strategy=ipv4_only 与 OpenWrt dnsmasq filter_aaaa=1 是否生效"
			return item
		}
		if cnCount > 0 {
			item.Status = "warn"
			item.Summary = fmt.Sprintf("已拦截海外 AAAA，但国内查询仍返回了 AAAA (%s)", cnANS.AAAAs[0])
			item.Detail = "若不开启双栈建议确认 dnsmasq filter_aaaa=1 缓存已刷新"
			return item
		}
		item.Status = "pass"
		item.Summary = "纯 IPv4 策略生效：国内外域名均无 AAAA 返回，零 IPv6 泄漏"
		item.Detail = "www.bilibili.com (0 条 AAAA) · www.google.com (0 条 AAAA)"
		return item

	case config.GatewayIPv6Full:
		if cnErr != nil || ovErr != nil || cnCount == 0 || ovCount == 0 {
			item.Status = "warn"
			item.Summary = fmt.Sprintf("全双栈探测未完全返回 AAAA (国内 %d 条 / 海外 %d 条)", cnCount, ovCount)
			item.Detail = "请确认上级 AdGuard Home 与代理节点均支持并返回 AAAA 记录"
			return item
		}
		tcpNote := probeCNTCPv6(ctx, cnANS.AAAAs[0], opts.SkipTCP6Dial)
		item.Status = "pass"
		item.Summary = fmt.Sprintf("全双栈生效：国内 %s · 海外 %s", cnANS.AAAAs[0], overseasANS.AAAAs[0])
		item.Detail = cmp.Or(tcpNote, "国内外均正常解析 AAAA（确保所有主力节点均支持 IPv6 出站）")
		return item

	default: // cn_only
		overseasHTTPS, _ := queryGatewayDNS(ctx, opts.PrimaryDNS, "www.google.com", dnsTypeHTTPS)
		item.LatencyMs = max(1, time.Since(t0).Milliseconds())
		if ovCount > 0 {
			item.Status = "fail"
			item.Summary = fmt.Sprintf("智能双栈异常：海外域名返回了 AAAA (%s)，存在回落或泄露风险", overseasANS.AAAAs[0])
			item.Detail = "sing-box dns_proxy 规则前的 query_type=[AAAA] predefined NOERROR 规则未命中，请重新保存应用 IPv6 模式"
			return item
		}
		if overseasHTTPS.HTTPSCount > 0 {
			item.Status = "fail"
			item.Summary = fmt.Sprintf("智能双栈异常：海外域名返回了 %d 条 HTTPS (Type 65) 记录，可能携带 ipv6hint 引发 IPv6 卡顿或泄漏", overseasHTTPS.HTTPSCount)
			item.Detail = "sing-box dns_proxy 规则前的 query_type=[AAAA,HTTPS] predefined NOERROR 规则未生效，请重新保存应用 IPv6 模式"
			return item
		}
		if cnCount == 0 {
			item.Status = "warn"
			item.Summary = "海外 AAAA/HTTPS 已 0ms 拦截，但国内域名暂未返回 AAAA"
			item.Detail = "请检查 OpenWrt dnsmasq filter_aaaa 是否为 0 以及上游加密 DNS 是否返回 IPv6"
			return item
		}
		tcpNote := probeCNTCPv6(ctx, cnANS.AAAAs[0], opts.SkipTCP6Dial)
		item.Status = "pass"
		item.Summary = fmt.Sprintf("智能双栈分流正常：国内解析 %s · 海外 AAAA/HTTPS 均已静音 (0 条)", cnANS.AAAAs[0])
		item.Detail = cmp.Or(tcpNote, "国内站点直连 IPv6 双栈，海外站点纯走 IPv4 隧道防风控卡顿")
		return item
	}
}

func checkGatewayBaseline(ipv6Mode, gwMode string, opts DNSLeakTestOptions) DNSLeakCheckItem {
	item := DNSLeakCheckItem{
		ID:    "gateway_baseline",
		Title: "网关接管与 OpenWrt RA 防护基线",
	}

	var issues []string
	var warns []string
	if !opts.SingBoxRunning {
		issues = append(issues, "sing-box 代理核心当前未运行，无法拦截与转发 DNS")
	}
	if gwMode == gateway.ModeSide && ipv6Mode != config.GatewayIPv6Off {
		issues = append(issues, "旁路由模式下禁止启用 IPv6 透明代理（主路由 RA 会绕过旁路由引发泄漏）")
	}
	if !opts.AdGuardHealthy {
		warns = append(warns, "本地 AdGuard Home 防劫持 DNS 未就绪")
	}

	st := opts.IPv6Status
	if st.IsOpenWrt {
		if ipv6Mode == config.GatewayIPv6Off && st.DnsmasqFilterAAAA == "0" {
			warns = append(warns, "OpenWrt dnsmasq.filter_aaaa 当前为 0（ipv4_only 模式下建议保持 1）")
		}
		if ipv6Mode != config.GatewayIPv6Off {
			if st.DnsmasqFilterAAAA == "1" {
				warns = append(warns, "OpenWrt dnsmasq.filter_aaaa 仍为 1，可能屏蔽国内 IPv6 解析")
			}
			if st.RADNSAnnounce {
				warns = append(warns, "OpenWrt odhcpd 仍在通告 IPv6 DNS (ra_dns/dns_service 未关闭)，多级路由或链路本地 fe80:: DNS 易超时回退泄漏，建议重新保存 IPv6 模式自动关闭")
			}
			if st.DnsmasqForwardMax == "" {
				warns = append(warns, "OpenWrt dnsmasq 未提高并发上限（默认 150），高并发 DNS 探测时易丢包触发手机回退蜂窝泄漏，建议重新保存 IPv6 模式自动提升至 1024")
			} else if maxQ, err := strconv.Atoi(st.DnsmasqForwardMax); err == nil && maxQ < 512 {
				warns = append(warns, fmt.Sprintf("OpenWrt dnsmasq 并发上限偏低 (dnsforwardmax=%d)，高并发 DNS 探测时易丢包触发手机回退蜂窝泄漏", maxQ))
			}
		}
	}

	if len(issues) > 0 {
		item.Status = "fail"
		item.Summary = strings.Join(issues, "；")
		return item
	}
	if len(warns) > 0 {
		item.Status = "warn"
		item.Summary = strings.Join(warns, "；")
		return item
	}

	var notes []string
	notes = append(notes, "sing-box 运行正常")
	if opts.AdGuardHealthy {
		notes = append(notes, "AdGuard Home 加密上游就绪")
	}
	if st.IsOpenWrt {
		if ipv6Mode == config.GatewayIPv6Off {
			notes = append(notes, "dnsmasq 已过滤 AAAA")
		} else {
			notes = append(notes, fmt.Sprintf("dnsmasq 已放行 AAAA (并发=%s · 已关闭 IPv6 RDNSS) · LAN=%s", cmp.Or(st.DnsmasqForwardMax, "1024"), cmp.Or(strings.Join(st.LANPrefixes, ","), "待分配")))
		}
	}
	item.Status = "pass"
	item.Summary = strings.Join(notes, " · ")
	item.Detail = "网关本地 DNS 劫持与局域网通告基线均符合无泄漏要求"
	return item
}

func probeCNTCPv6(ctx context.Context, ipStr string, skip bool) string {
	if skip || strings.TrimSpace(ipStr) == "" {
		return ""
	}
	t0 := time.Now()
	d := net.Dialer{Timeout: 2500 * time.Millisecond}
	conn, err := d.DialContext(ctx, "tcp6", net.JoinHostPort(ipStr, "443"))
	if err != nil {
		return fmt.Sprintf("已获取国内 AAAA (%s)，本机 TCPv6 :443 握手未通: %s", ipStr, err.Error())
	}
	_ = conn.Close()
	return fmt.Sprintf("本机已实测 TCPv6 直连 %s:443 成功 (%dms)", ipStr, max(1, time.Since(t0).Milliseconds()))
}

func probeDNSEgressResolver(ctx context.Context, primaryDNS string) (resolverIP, ecsCIDR, viaAddr string, err error) {
	cands := candidateGatewayDNSServers(primaryDNS)
	var lastErr error
	for _, srv := range cands {
		if ans, qErr := queryDNSUDP(ctx, srv, "o-o.myaddr.l.google.com", dnsTypeTXT); qErr == nil {
			ip, ecs := parseResolverTXT(ans.TXTs)
			if ip != "" {
				return ip, ecs, srv, nil
			}
		} else {
			lastErr = qErr
		}
		if ans2, qErr2 := queryDNSUDP(ctx, srv, "whoami.ds.akahelp.net", dnsTypeTXT); qErr2 == nil {
			ip, ecs := parseResolverTXT(ans2.TXTs)
			if ip != "" {
				return ip, ecs, srv, nil
			}
		} else if lastErr == nil {
			lastErr = qErr2
		}
	}
	if lastErr == nil {
		lastErr = errors.New("未收到有效的 DNS TXT 溯源响应")
	}
	return "", "", "", lastErr
}

func parseResolverTXT(txts []string) (resolverIP, ecsCIDR string) {
	for _, raw := range txts {
		s := strings.Trim(strings.TrimSpace(raw), `"`)
		if s == "" {
			continue
		}
		if addr, err := netip.ParseAddr(s); err == nil {
			if resolverIP == "" {
				resolverIP = addr.Unmap().String()
			}
			continue
		}
		lower := strings.ToLower(s)
		if rest, ok := strings.CutPrefix(lower, "edns0-client-subnet "); ok {
			cand := strings.TrimSpace(rest)
			if pfx, err := netip.ParsePrefix(cand); err == nil {
				ecsCIDR = pfx.String()
			} else if addr, err := netip.ParseAddr(cand); err == nil {
				ecsCIDR = netip.PrefixFrom(addr.Unmap(), addr.Unmap().BitLen()).String()
			}
			continue
		}
		fields := strings.Fields(s)
		if len(fields) == 2 {
			switch strings.ToLower(fields[0]) {
			case "ns", "ip":
				if resolverIP == "" {
					if addr, err := netip.ParseAddr(fields[1]); err == nil {
						resolverIP = addr.Unmap().String()
					}
				}
			case "ecs":
				if ecsCIDR == "" {
					if pfx, err := netip.ParsePrefix(fields[1]); err == nil {
						ecsCIDR = pfx.String()
					} else if addr, err := netip.ParseAddr(fields[1]); err == nil {
						ecsCIDR = netip.PrefixFrom(addr.Unmap(), addr.Unmap().BitLen()).String()
					}
				}
			}
		}
	}
	return resolverIP, ecsCIDR
}

func formatResolverProfileLine(p *DNSResolverProfile) string {
	if p == nil {
		return ""
	}
	parts := []string{"解析器=" + cmp.Or(p.IP, "unknown")}
	if p.CountryCode != "" {
		parts = append(parts, "归属="+p.CountryCode)
	}
	if p.ISP != "" {
		parts = append(parts, "ISP="+p.ISP)
	}
	if p.ECS != "" {
		ecsStr := "ECS=" + p.ECS
		if p.ECSCountryCode != "" {
			ecsStr += " (" + p.ECSCountryCode + ")"
		}
		parts = append(parts, ecsStr)
	}
	return strings.Join(parts, " · ")
}

func candidateGatewayDNSServers(primaryDNS string) []string {
	if trimmed := strings.TrimSpace(primaryDNS); trimmed != "" {
		return []string{ensureDNSPort(trimmed)}
	}
	return []string{"127.0.0.1:53", "8.8.8.8:53"}
}

func ensureDNSPort(addr string) string {
	if _, _, err := net.SplitHostPort(addr); err == nil {
		return addr
	}
	return net.JoinHostPort(strings.Trim(addr, "[]"), "53")
}

func queryGatewayDNS(ctx context.Context, primaryDNS, domain string, qType uint16) (dnsAnswerSet, error) {
	return queryDNSWithFallback(ctx, candidateGatewayDNSServers(primaryDNS), domain, qType)
}

func queryDNSWithFallback(ctx context.Context, servers []string, domain string, qType uint16) (dnsAnswerSet, error) {
	var lastErr error
	for _, srv := range servers {
		ans, err := queryDNSUDP(ctx, srv, domain, qType)
		if err == nil {
			return ans, nil
		}
		lastErr = err
	}
	return dnsAnswerSet{}, lastErr
}

func queryDNSUDP(ctx context.Context, serverAddr, domain string, qType uint16) (dnsAnswerSet, error) {
	pkt, txid, err := buildDNSLeakQueryPacket(domain, qType)
	if err != nil {
		return dnsAnswerSet{}, err
	}

	dialCtx, cancel := context.WithTimeout(ctx, 2500*time.Millisecond)
	defer cancel()

	var d net.Dialer
	conn, err := d.DialContext(dialCtx, "udp", ensureDNSPort(serverAddr))
	if err != nil {
		return dnsAnswerSet{}, err
	}
	defer conn.Close()

	if deadline, ok := dialCtx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	if _, err := conn.Write(pkt); err != nil {
		return dnsAnswerSet{}, err
	}

	resp := make([]byte, 4096)
	n, err := conn.Read(resp)
	if err != nil {
		return dnsAnswerSet{}, err
	}
	return parseDNSAnswerPacket(resp[:n], txid)
}

func buildDNSLeakQueryPacket(domain string, qType uint16) ([]byte, [2]byte, error) {
	var txid [2]byte
	_, _ = rand.Read(txid[:])

	clean := strings.TrimSuffix(strings.TrimSpace(domain), ".")
	if clean == "" {
		return nil, txid, errors.New("DNS 探测域名不能为空")
	}

	var buf bytes.Buffer
	buf.Write(txid[:])
	buf.Write([]byte{
		0x01, 0x00, // RD=1
		0x00, 0x01, // QDCOUNT=1
		0x00, 0x00, // ANCOUNT=0
		0x00, 0x00, // NSCOUNT=0
		0x00, 0x00, // ARCOUNT=0
	})
	for label := range strings.SplitSeq(clean, ".") {
		if len(label) == 0 || len(label) > 63 {
			return nil, txid, fmt.Errorf("invalid domain label %q", label)
		}
		buf.WriteByte(byte(len(label)))
		buf.WriteString(label)
	}
	buf.WriteByte(0x00)
	var qt [4]byte
	binary.BigEndian.PutUint16(qt[0:2], qType)
	binary.BigEndian.PutUint16(qt[2:4], 1) // QCLASS=IN
	buf.Write(qt[:])
	return buf.Bytes(), txid, nil
}

func parseDNSAnswerPacket(msg []byte, expectedTxID [2]byte) (dnsAnswerSet, error) {
	var out dnsAnswerSet
	if len(msg) < 12 {
		return out, errors.New("DNS 响应报文过短")
	}
	if msg[0] != expectedTxID[0] || msg[1] != expectedTxID[1] {
		return out, errors.New("DNS 事务 ID 不匹配")
	}
	out.RCode = msg[3] & 0x0F
	if out.RCode != 0 {
		return out, fmt.Errorf("DNS RCODE=%d", out.RCode)
	}
	qdCount := int(binary.BigEndian.Uint16(msg[4:6]))
	anCount := int(binary.BigEndian.Uint16(msg[6:8]))

	offset := 12
	for range qdCount {
		next, err := skipDNSLeakName(msg, offset)
		if err != nil {
			return out, err
		}
		if next+4 > len(msg) {
			return out, errors.New("DNS Question 截断")
		}
		offset = next + 4
	}

	for range anCount {
		next, err := skipDNSLeakName(msg, offset)
		if err != nil {
			return out, err
		}
		if next+10 > len(msg) {
			return out, errors.New("DNS Answer 头部截断")
		}
		rrType := binary.BigEndian.Uint16(msg[next : next+2])
		rdLen := int(binary.BigEndian.Uint16(msg[next+8 : next+10]))
		rdataStart := next + 10
		if rdataStart+rdLen > len(msg) {
			return out, errors.New("DNS Answer 数据截断")
		}
		rdata := msg[rdataStart : rdataStart+rdLen]
		switch rrType {
		case dnsTypeA:
			if rdLen == 4 {
				ip := netip.AddrFrom4([4]byte(rdata)).String()
				if !slices.Contains(out.As, ip) {
					out.As = append(out.As, ip)
				}
			}
		case dnsTypeAAAA:
			if rdLen == 16 {
				ip := netip.AddrFrom16([16]byte(rdata)).Unmap().String()
				if !slices.Contains(out.AAAAs, ip) {
					out.AAAAs = append(out.AAAAs, ip)
				}
			}
		case dnsTypeTXT:
			var txtBuilder strings.Builder
			pos := 0
			for pos < len(rdata) {
				segLen := int(rdata[pos])
				pos++
				if pos+segLen > len(rdata) {
					break
				}
				txtBuilder.Write(rdata[pos : pos+segLen])
				pos += segLen
			}
			if txtVal := strings.TrimSpace(txtBuilder.String()); txtVal != "" {
				out.TXTs = append(out.TXTs, txtVal)
			}
		case dnsTypeHTTPS:
			out.HTTPSCount++
		}
		offset = rdataStart + rdLen
	}
	return out, nil
}

func skipDNSLeakName(msg []byte, offset int) (int, error) {
	cur := offset
	for range 128 {
		if cur >= len(msg) {
			return 0, errors.New("DNS 域名越界")
		}
		b := msg[cur]
		if b == 0 {
			return cur + 1, nil
		}
		if b&0xC0 == 0xC0 {
			if cur+1 >= len(msg) {
				return 0, errors.New("DNS 压缩指针截断")
			}
			return cur + 2, nil
		}
		cur += 1 + int(b)
	}
	return 0, errors.New("DNS 域名层级过深")
}

func lookupTargetISPWithFallback(ctx context.Context, ip string) (*ISPInfo, error) {
	if info, err := GetTargetISP(ctx, ip); err == nil && info != nil {
		return info, nil
	}
	client := &http.Client{Timeout: 3 * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.ip.sb/geoip/"+ip, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (singctl netdiag)")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 16*1024))
	if err != nil {
		return nil, err
	}
	var data ipSBResponse
	if err := json.Unmarshal(body, &data); err != nil || data.IP == "" {
		return nil, fmt.Errorf("ip.sb lookup failed for %s", ip)
	}
	asnStr := ""
	if data.ASN > 0 {
		asnStr = fmt.Sprintf("AS%d %s", data.ASN, data.ASNOrg)
	}
	info := &ISPInfo{
		IP:          data.IP,
		Country:     data.Country,
		CountryCode: data.CountryCode,
		Region:      data.Region,
		City:        data.City,
		ISP:         data.ISP,
		Org:         data.ASNOrg,
		ASN:         asnStr,
	}
	info.Type = CategorizeISP(info.ISP, info.Org, info.ASN, info.CountryCode)
	return info, nil
}

// ProbeGatewayEDNSOnce 从路由器网关视角发起单次随机子域 EDNS 探测，返回实际触达海外权威的递归解析器画像。
func ProbeGatewayEDNSOnce(ctx context.Context) (*DNSResolverProfile, error) {
	probeCtx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()

	client := &http.Client{Timeout: 4 * time.Second}
	res, err := fetchOneEDNSProbe(probeCtx, client)
	if err != nil {
		return nil, err
	}
	c, cc, isp := parseEDNSGeo(res.DNSGeo)
	_, ecsCC, _ := parseEDNSGeo(res.EDNSGeo)
	return &DNSResolverProfile{
		IP:             res.DNSIP,
		Country:        c,
		CountryCode:    cc,
		ISP:            isp,
		ECS:            res.EDNSIP,
		ECSCountryCode: ecsCC,
	}, nil
}

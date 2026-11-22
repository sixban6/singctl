// 文件职责：定义 DNS 泄漏检测聚合报告模型、主检测流水线 RunDNSLeakTest 及网关 EDNS 解析器画像采样。
package netdiag

import (
	"cmp"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"singctl/internal/config"
	"singctl/internal/gateway"
	"strings"
	"sync"
	"time"
)

const (
	DNSTypeA     uint16 = 1
	DNSTypeTXT   uint16 = 16
	DNSTypeAAAA  uint16 = 28
	DNSTypeHTTPS uint16 = 65
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

func SameIPv6Prefix48(a, b string) bool {
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
	"china":                     "CN",
	"peoples republic of china": "CN",
	"united states":             "US",
	"united states of america":  "US",
	"usa":                       "US",
	"japan":                     "JP",
	"hong kong":                 "HK",
	"taiwan":                    "TW",
	"macao":                     "MO",
	"macau":                     "MO",
	"singapore":                 "SG",
	"united kingdom":            "GB",
	"great britain":             "GB",
	"germany":                   "DE",
	"south korea":               "KR",
	"korea":                     "KR",
	"republic of korea":         "KR",
	"netherlands":               "NL",
	"the netherlands":           "NL",
	"canada":                    "CA",
	"australia":                 "AU",
	"france":                    "FR",
	"russia":                    "RU",
	"russian federation":        "RU",
	"india":                     "IN",
	"switzerland":               "CH",
	"sweden":                    "SE",
	"finland":                   "FI",
	"ireland":                   "IE",
	"brazil":                    "BR",
	"indonesia":                 "ID",
	"malaysia":                  "MY",
	"thailand":                  "TH",
	"vietnam":                   "VN",
	"philippines":               "PH",
	"turkey":                    "TR",
	"türkiye":                   "TR",
	"united arab emirates":      "AE",
	"italy":                     "IT",
	"spain":                     "ES",
	"poland":                    "PL",
	"ukraine":                   "UA",
	"norway":                    "NO",
	"denmark":                   "DK",
	"austria":                   "AT",
	"belgium":                   "BE",
	"new zealand":               "NZ",
	"mexico":                    "MX",
	"argentina":                 "AR",
	"south africa":              "ZA",
	"israel":                    "IL",
}

func ParseEDNSGeo(geo string) (country, countryCode, isp string) {
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

// ProbeGatewayEDNSOnce 从路由器网关视角发起单次随机子域 EDNS 探测，返回实际触达海外权威的递归解析器画像。
func ProbeGatewayEDNSOnce(ctx context.Context) (*DNSResolverProfile, error) {
	probeCtx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()

	client := &http.Client{Timeout: 4 * time.Second}
	res, err := fetchOneEDNSProbe(probeCtx, client)
	if err != nil {
		return nil, err
	}
	c, cc, isp := ParseEDNSGeo(res.DNSGeo)
	_, ecsCC, _ := ParseEDNSGeo(res.EDNSGeo)
	return &DNSResolverProfile{
		IP:             res.DNSIP,
		Country:        c,
		CountryCode:    cc,
		ISP:            isp,
		ECS:            res.EDNSIP,
		ECSCountryCode: ecsCC,
	}, nil
}

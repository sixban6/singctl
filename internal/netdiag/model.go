package netdiag

import "time"

// ISPType 运营商分类
type ISPType string

const (
	ISPTelecom  ISPType = "China Telecom (电信)"
	ISPUnicom   ISPType = "China Unicom (联通)"
	ISPMobile   ISPType = "China Mobile (移动)"
	ISPBroadnet ISPType = "China Broadnet / CERNET (广电/教育网)"
	ISPOverseas ISPType = "Overseas / Other (海外/其它)"
)

// RouteQuality 线路质量评级
type RouteQuality string

const (
	QualityExcellent RouteQuality = "极优 (Excellent)"
	QualityGood      RouteQuality = "良好 (Good)"
	QualityCongested RouteQuality = "拥堵 (Congested)"
	QualitySevere    RouteQuality = "严重恶化 (Severely Degraded)"
)

// ProtocolType 推荐协议类型
type ProtocolType string

const (
	ProtocolVLESSReality ProtocolType = "VLESS-Reality (TCP)"
	ProtocolHysteria2    ProtocolType = "Hysteria 2 (UDP/QUIC)"
)

// ISPInfo 本地或远端公网出口与运营商画像
type ISPInfo struct {
	IP          string  `json:"ip"`
	Country     string  `json:"country"`
	CountryCode string  `json:"country_code"`
	Region      string  `json:"region"`
	City        string  `json:"city"`
	ISP         string  `json:"isp"`
	Org         string  `json:"org"`
	ASN         string  `json:"asn"`
	Type        ISPType `json:"isp_type"`
}

// PingResult 多轮 Ping 测算指标
type PingResult struct {
	Target       string          `json:"target"`
	Port         int             `json:"port"`
	IsTCP        bool            `json:"is_tcp"`
	Sent         int             `json:"sent"`
	Received     int             `json:"received"`
	LossCount    int             `json:"loss_count"`
	LossRate     float64         `json:"loss_rate"` // 百分比, 如 15.0 表示 15%
	MinRTT       time.Duration   `json:"min_rtt"`
	AvgRTT       time.Duration   `json:"avg_rtt"`
	MaxRTT       time.Duration   `json:"max_rtt"`
	Jitter       time.Duration   `json:"jitter"` // RTT 标准差
	RTTs         []time.Duration `json:"rtts,omitempty"`
	QualityLevel RouteQuality    `json:"quality_level"`
}

// HopInfo 路由跳点信息
type HopInfo struct {
	Hop     int           `json:"hop"`
	IP      string        `json:"ip"`
	Host    string        `json:"host,omitempty"`
	ASN     string        `json:"asn,omitempty"`
	Carrier string        `json:"carrier,omitempty"`
	City    string        `json:"city,omitempty"`
	RTT     time.Duration `json:"rtt"`
	Tag     string        `json:"tag,omitempty"` // 特征标识，如 59.43 CN2, 202.97 163 等
}

// TraceResult 路由追踪判定结果
type TraceResult struct {
	Target       string    `json:"target"`
	Hops         []HopInfo `json:"hops"`
	Identified   string    `json:"identified"`    // 识别出的骨干网全称，如 "电信 CN2 GIA (AS4809 精品骨干网)"
	RouteType    string    `json:"route_type"`    // 简短类型代码: CN2_GIA, CN2_GT, 163, CU4837, CU9929, CMI, CMIN2, TIER1, UNKNOWN
	Details      string    `json:"details"`       // 判定依据与说明
	HasOverseas  bool      `json:"has_overseas"`  // 是否途经海外节点
	HasCN2       bool      `json:"has_cn2"`       // 途经 59.43
	Has163       bool      `json:"has_163"`       // 途经 202.97
	Has4837      bool      `json:"has_4837"`      // 途经 219.158
	Has9929      bool      `json:"has_9929"`      // 途经 218.105 / 210.51
	HasCMI       bool      `json:"has_cmi"`       // 途经 221.183 / 221.179
	HasCMIN2     bool      `json:"has_cmin2"`     // 途经 223.120
	DurationSecs float64   `json:"duration_secs"` // 耗时秒数
}

// ReturnTarget 回程测试目标节点
type ReturnTarget struct {
	Carrier  ISPType `json:"carrier"`
	Name     string  `json:"name"`
	TargetIP string  `json:"target_ip"`
	City     string  `json:"city"`
	Expected string  `json:"expected_route"`
}

// ReturnHopResult 回程单目标测试结果
type ReturnHopResult struct {
	Carrier   ISPType       `json:"carrier"`
	Name      string        `json:"name"`
	TargetIP  string        `json:"target_ip"`
	City      string        `json:"city"`
	AvgRTT    time.Duration `json:"avg_rtt"`
	LossRate  float64       `json:"loss_rate"`
	RouteType string        `json:"route_type"`
	RouteName string        `json:"route_name"`
	KeyHops   []string      `json:"key_hops"`
}

// ReturnSummary 服务端回程综合评估
type ReturnSummary struct {
	ServerIP   string            `json:"server_ip"`
	ScanTime   time.Time         `json:"scan_time"`
	Results    []ReturnHopResult `json:"results"`
	Summary    string            `json:"summary"`
	BestForISP []ISPType         `json:"best_for_isp"`
}

// AdviceResult 智能建议引擎输出
type AdviceResult struct {
	QualityLevel        RouteQuality `json:"quality_level"`
	RecommendedProtocol ProtocolType `json:"recommended_protocol"`
	ProtocolReason      string       `json:"protocol_reason"`
	SuggestedHy2Up      int          `json:"suggested_hy2_up"`   // 建议填写到 singctl.yaml 的 hy2.up (Mbps)
	SuggestedHy2Down    int          `json:"suggested_hy2_down"` // 建议填写到 singctl.yaml 的 hy2.down (Mbps)
	CarrierMatchScore   int          `json:"carrier_match_score"`// 0-100 本地宽带与该 VPS 线路匹配度评分
	CarrierAdvice       string       `json:"carrier_advice"`     // 选型与晚高峰稳定性分析
	CanAutoApply        bool         `json:"can_auto_apply"`     // 是否可将参数直接应用到 singctl.yaml
}

// DiagReport 综合诊断报告
type DiagReport struct {
	Target     string       `json:"target"`
	TargetIP   string       `json:"target_ip"`
	TargetPort int          `json:"target_port"`
	ScanTime   time.Time    `json:"scan_time"`
	IsPeakHour bool         `json:"is_peak_hour"` // 是否晚高峰 (20:00-24:00)
	LocalISP   *ISPInfo     `json:"local_isp"`
	TargetISP  *ISPInfo     `json:"target_isp,omitempty"`
	Ping       *PingResult  `json:"ping"`
	Trace      *TraceResult `json:"trace,omitempty"`
	Advice     *AdviceResult`json:"advice"`
}

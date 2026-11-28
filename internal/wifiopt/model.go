// 文件职责：定义 OpenWrt Wi-Fi 体检、周边信道干扰扫描、安全一键优化与高并发底盘调优的纯数据模型与入参校验契约。
package wifiopt

import (
	"errors"

	"singctl/internal/common/socktune"
)

var (
	// ErrUnsupported 表示当前宿主机无 OpenWrt 无线射频环境。
	ErrUnsupported = errors.New("当前设备未检测到 OpenWrt 无线射频")
	// ErrInvalidRequest 表示请求参数不合法或包含非法控制/注入字符。
	ErrInvalidRequest = errors.New("Wi-Fi 优化参数不合法")
	// ErrRadioNotFound 表示请求指定的射频设备不存在。
	ErrRadioNotFound = errors.New("未找到指定的无线射频设备")
	// ErrInterfaceNotFound 表示请求指定的无线接口不存在。
	ErrInterfaceNotFound = errors.New("未找到指定的无线 SSID 接口")
	// ErrBridgeVerifyFailed 表示无线重载后目标接口未在超时内回归网桥，已自动回滚。
	ErrBridgeVerifyFailed = errors.New("无线重载后网桥就绪校验超时，已自动回滚原配置")
)

// RadioInfo 描述单个 OpenWrt 无线射频设备（2.4G 或 5G）的配置与实时运行状态。
type RadioInfo struct {
	Device          string   `json:"device"`
	Driver          string   `json:"driver"` // mtwifi / mac80211
	Phy             string   `json:"phy,omitzero"`
	Band            string   `json:"band"` // 2g / 5g / 6g
	Hardware        string   `json:"hardware,omitzero"`
	Disabled        bool     `json:"disabled"`
	Up              bool     `json:"up"`
	Channel         string   `json:"channel"`                  // UCI 配置值，如 "auto" / "1" / "149"
	CurrentChannel  int      `json:"currentChannel,omitzero"`  // 实测工作信道
	FrequencyGHz    string   `json:"frequencyGhz,omitzero"`    // 如 "2.412" / "5.745"
	HTMode          string   `json:"htmode"`                   // 如 "HE20" / "HE40" / "HE80" / "HE160"
	Country         string   `json:"country,omitzero"`         // 如 "AU" / "CN" / "US"
	TxPowerPct      int      `json:"txPowerPct"`               // UCI txpower 百分比或 dBm
	TxPowerDBm      int      `json:"txPowerDbm,omitzero"`      // 实测 dBm
	BitRateMbps     float64  `json:"bitRateMbps,omitzero"`     // 理论 PHY 上限
	MuBeamformer    bool     `json:"muBeamformer"`
	WHNAT           bool     `json:"whnat"`
	OverlappingCh   bool     `json:"overlappingChannel"`       // 2.4G 非正交重叠信道
	DFSChannel      bool     `json:"dfsChannel"`               // 5G DFS 雷达信道
	SupportedModes  []string `json:"supportedModes,omitzero"`  // 可选频宽列表
	RecommendChs    []int    `json:"recommendChannels,omitzero"`
	InterfaceCount    int     `json:"interfaceCount"`
	ClientCount       int     `json:"clientCount"`
	RxPackets         uint64  `json:"rxPackets"`
	RxErrors          uint64  `json:"rxErrors"`
	RxDropped         uint64  `json:"rxDropped"`
	TxPackets         uint64  `json:"txPackets"`
	TxDropped         uint64  `json:"txDropped"`
	RxErrorRatePct    float64 `json:"rxErrorRatePct"`
	PacketLossRatePct float64 `json:"packetLossRatePct"`
}

// SSIDInfo 描述单个无线 AP 接口（wifi-iface）及其运行统计（绝不含明文密钥）。
type SSIDInfo struct {
	Section            string  `json:"section"`
	Device             string  `json:"device"`
	Band               string  `json:"band"`
	IfName             string  `json:"ifname,omitzero"`
	SSID               string  `json:"ssid"`
	Network            string  `json:"network"`
	Bridge             string  `json:"bridge,omitzero"`
	Encryption         string  `json:"encryption"`
	PasswordConfigured bool    `json:"passwordConfigured"`
	Disabled           bool    `json:"disabled"`
	Isolate            bool    `json:"isolate"`
	IEEE80211k         bool    `json:"ieee80211k"`
	ClientCount        int     `json:"clientCount"`
	RxPackets          uint64  `json:"rxPackets"`
	RxErrors           uint64  `json:"rxErrors"`
	RxDropped          uint64  `json:"rxDropped"`
	TxPackets          uint64  `json:"txPackets"`
	TxDropped          uint64  `json:"txDropped"`
	RxErrorRatePct     float64 `json:"rxErrorRatePct"`
	PacketLossRatePct  float64 `json:"packetLossRatePct"`
	DualBandPaired     bool    `json:"dualBandPaired"`
	CanUpgradeDualBand bool    `json:"canUpgradeDualBand"`
}

// ClientInfo 描述单个已关联无线终端的信号与协商速率。
type ClientInfo struct {
	MAC          string  `json:"mac"`
	Hostname     string  `json:"hostname,omitzero"`
	IP           string  `json:"ip,omitzero"`
	IfName       string  `json:"ifname"`
	SSID         string  `json:"ssid"`
	Band         string  `json:"band"`
	SignalDBm    int     `json:"signalDbm"`
	RxMbps       float64 `json:"rxMbps"`
	TxMbps       float64 `json:"txMbps"`
	BandwidthMHz int     `json:"bandwidthMhz,omitzero"`
	WeakSignal   bool    `json:"weakSignal"`
}

// DiagnosisItem 描述一条可扩展的 Wi-Fi 体检结论与修复动作提示。
type DiagnosisItem struct {
	ID         string `json:"id"`
	Severity   string `json:"severity"` // critical / warn / info
	Band       string `json:"band,omitzero"`
	Title      string `json:"title"`
	Detail     string `json:"detail"`
	ActionHint string `json:"actionHint,omitzero"`
	AutoFix    bool   `json:"autoFix"`
}

// ChannelStat 描述单个信道的周边干扰统计（严格脱敏，不包含任何邻居 SSID 或 MAC）。
type ChannelStat struct {
	Channel        int     `json:"channel"`
	Band           string  `json:"band"`
	APCount        int     `json:"apCount"`
	StrongestDBm   int     `json:"strongestDbm,omitzero"`
	Score          float64 `json:"score"` // 越低越干净
	Level          string  `json:"level"` // clean / moderate / busy
	NonOverlapping bool    `json:"nonOverlapping"`
	DFS            bool    `json:"dfs"`
	Recommended    bool    `json:"recommended"`
	Current        bool    `json:"current"`
}

// ScanResult 描述按需周边信道扫描结果与最优信道推荐。
type ScanResult struct {
	ScannedAt       int64         `json:"scannedAt"`
	Channels2G      []ChannelStat `json:"channels2g"`
	Channels5G      []ChannelStat `json:"channels5g"`
	Recommended2GCh int           `json:"recommended2gChannel,omitzero"`
	Recommended5GCh int           `json:"recommended5gChannel,omitzero"`
	Summary         string        `json:"summary"`
	Warnings        []string      `json:"warnings,omitzero"`
}

// RPSInterfaceStatus 描述单个物理网卡队列的多核 RPS 均衡状态。
type RPSInterfaceStatus struct {
	Interface   string `json:"interface"`
	CurrentMask string `json:"currentMask"`
	TargetMask  string `json:"targetMask"`
	Balanced    bool   `json:"balanced"`
}

// ChassisStatus 描述高并发有线底盘状态（多核 RPS 均衡、Conntrack 连接表上限与 QUIC/UDP Socket 缓冲）。
type ChassisStatus struct {
	Supported            bool                 `json:"supported"`
	CPUCores             int                  `json:"cpuCores"`
	TotalMemMB           int                  `json:"totalMemMb"`
	RPSInterfaces        []RPSInterfaceStatus `json:"rpsInterfaces"`
	RPSOptimal           bool                 `json:"rpsOptimal"`
	ConntrackCount       int                  `json:"conntrackCount"`
	ConntrackMax         int                  `json:"conntrackMax"`
	RecommendedConntrack int                  `json:"recommendedConntrack"`
	ConntrackOptimal     bool                 `json:"conntrackOptimal"`
	SocketBuffer         *socktune.Status     `json:"socketBuffer,omitempty"`
	Optimal              bool                 `json:"optimal"`
}

// OptimizationStep 描述一条人类可读的配置变更预览项。
type OptimizationStep struct {
	Target string `json:"target"`
	Field  string `json:"field"`
	Before string `json:"before"`
	After  string `json:"after"`
	Reason string `json:"reason"`
}

// Overview 为 GET /api/wifi/overview 的完整聚合视图。
type Overview struct {
	Supported        bool               `json:"supported"`
	UnsupportedHint  string             `json:"unsupportedHint,omitzero"`
	Driver           string             `json:"driver,omitzero"`
	HealthScore      int                `json:"healthScore"`
	HealthLevel      string             `json:"healthLevel"` // excellent / good / warn / critical
	HealthSummary    string             `json:"healthSummary"`
	Radios           []RadioInfo        `json:"radios"`
	SSIDs            []SSIDInfo         `json:"ssids"`
	Clients          []ClientInfo       `json:"clients"`
	Diagnostics      []DiagnosisItem    `json:"diagnostics"`
	AutoOptimizePlan []OptimizationStep `json:"autoOptimizePlan"`
	Chassis          ChassisStatus      `json:"chassis"`
	SampledAt        int64              `json:"sampledAt"`
	StatsScope       string             `json:"statsScope"`               // boot / post_optimize / retest
	StatsBaselineAt  int64              `json:"statsBaselineAt,omitzero"` // 最近一次统计基准重置时间（Unix 秒）
	StatsWindowSec   int64              `json:"statsWindowSec,omitzero"`  // 距离基准重置已累计采样秒数
}

// RadioPatch 描述单张射频的精细调优入参。
type RadioPatch struct {
	Device     string `json:"device"`
	Disabled   *bool  `json:"disabled,omitempty"`
	Channel    string `json:"channel,omitempty"`
	HTMode     string `json:"htmode,omitempty"`
	TxPowerPct *int   `json:"txPowerPct,omitempty"`
	IEEE80211k *bool  `json:"ieee80211k,omitempty"`
}

// ApplyRequest 描述 POST /api/wifi/apply 请求（支持一键全自动优化、一键双频合一、单频微调）。
type ApplyRequest struct {
	Action           string       `json:"action"` // auto_optimize / dual_band_merge / tune_radio
	SourceSection    string       `json:"sourceSection,omitempty"`
	Recommended2GCh  int          `json:"recommended2gChannel,omitempty"`
	Recommended5GCh  int          `json:"recommended5gChannel,omitempty"`
	Preferred5GWidth string       `json:"preferred5gWidth,omitempty"` // HE80 (default) / HE160
	Radios           []RadioPatch `json:"radios,omitempty"`
	TTLSec           int          `json:"ttlSec,omitempty"`
	DryRun           bool         `json:"dryRun,omitempty"`
}

// ApplyResult 描述 POST /api/wifi/apply 的执行结果与网桥自检详情。
type ApplyResult struct {
	OK               bool               `json:"ok"`
	DryRun           bool               `json:"dryRun"`
	Action           string             `json:"action"`
	Summary          string             `json:"summary"`
	Changes          []OptimizationStep `json:"changes"`
	Reloaded         bool               `json:"reloaded"`
	BridgeVerified   bool               `json:"bridgeVerified"`
	BridgeWaitMs     int64              `json:"bridgeWaitMs,omitzero"`
	SafeCommitToken  string             `json:"safeCommitToken,omitzero"`
	SafeCommitTTLSec int                `json:"safeCommitTtlSec,omitzero"`
	Warnings         []string           `json:"warnings,omitzero"`
}

// ChassisApplyRequest 描述 POST /api/wifi/chassis 请求。
type ChassisApplyRequest struct {
	EnableRPS        bool `json:"enableRps"`
	TuneConntrack    bool `json:"tuneConntrack"`
	ConntrackMax     int  `json:"conntrackMax,omitempty"`
	TuneSocketBuffer bool `json:"tuneSocketBuffer,omitempty"`
}

// ChassisApplyResult 描述底盘加速应用结果。
type ChassisApplyResult struct {
	OK                        bool          `json:"ok"`
	Actions                   []string      `json:"actions"`
	Warnings                  []string      `json:"warnings,omitzero"`
	RestartSingBoxRecommended bool          `json:"restartSingBoxRecommended,omitempty"`
	Chassis                   ChassisStatus `json:"chassis"`
}

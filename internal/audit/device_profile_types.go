// 文件职责：定义局域网设备行为画像的数据模型、24小时分钟位图快照与7天有界日汇总持久化结构。
package audit

// DeviceProfileRange 定义设备画像查询的时间窗口。
type DeviceProfileRange string

const (
	ProfileRange24h DeviceProfileRange = "24h"
	ProfileRange7d  DeviceProfileRange = "7d"
)

const (
	profileRetentionDays = 7
	profileBitsetWords   = 23 // ceil(1440 / 64) = 23 uint64 = 184 bytes/app
	profileDayMinutes    = 1440
)

// DeviceAppStat 汇总单台设备对某一应用在选定周期内的交互停留、会话切分与流量特征。
type DeviceAppStat struct {
	AppName           string      `json:"appName"`
	Category          AppCategory `json:"category"`
	CategoryLabel     string      `json:"categoryLabel"`
	IsInfra           bool        `json:"isInfra"`
	ForegroundMinutes int         `json:"foregroundMinutes"`
	BackgroundMinutes int         `json:"backgroundMinutes"`
	Sessions          int         `json:"sessions"`
	AvgSessionMin     int         `json:"avgSessionMin"`
	LongestSessionMin int         `json:"longestSessionMin"`
	UploadBytes       int64       `json:"uploadBytes"`
	DownloadBytes     int64       `json:"downloadBytes"`
	PeakPeriod        string      `json:"peakPeriod"`
	LastSeen          string      `json:"lastSeen,omitempty"`
	SampleTargets     []string    `json:"sampleTargets,omitempty"`
}

// DeviceCategoryStat 汇总设备在各兴趣品类的前景停留时长与占比。
type DeviceCategoryStat struct {
	Category AppCategory `json:"category"`
	Label    string      `json:"label"`
	Minutes  int         `json:"minutes"`
	SharePct float64     `json:"sharePct"`
	Bytes    int64       `json:"bytes"`
}

// DeviceHourStat 记录单小时（0-23）的设备活跃分钟数与流量总计。
type DeviceHourStat struct {
	Hour              int   `json:"hour"`
	ForegroundMinutes int   `json:"foregroundMinutes"`
	Bytes             int64 `json:"bytes"`
}

// DeviceDayStat 记录 7 天历史趋势中的单日画像摘要。
type DeviceDayStat struct {
	Date              string `json:"date"`
	ForegroundMinutes int    `json:"foregroundMinutes"`
	UploadBytes       int64  `json:"uploadBytes"`
	DownloadBytes     int64  `json:"downloadBytes"`
	TopApp            string `json:"topApp,omitempty"`
	TopAppMinutes     int    `json:"topAppMinutes,omitempty"`
}

// DevicePersonaTag 描述由本地算法确定性生成的设备行为特征标签。
type DevicePersonaTag struct {
	ID     string `json:"id"`
	Label  string `json:"label"`
	Tone   string `json:"tone"` // "accent" | "ok" | "warn" | "neutral"
	Detail string `json:"detail"`
}

// DeviceProfileStorage 向前端透明汇报 7 天历史留存与自动裁剪上限。
type DeviceProfileStorage struct {
	RetentionDays   int  `json:"retentionDays"`
	HistoryDays     int  `json:"historyDays"`
	HistoryBytes    int  `json:"historyBytes"`
	MaxHistoryBytes int  `json:"maxHistoryBytes"`
	AutoCleanup     bool `json:"autoCleanup"`
}

// DeviceProfileReport 汇总单台局域网设备的 24h/7d 完整行为画像。
type DeviceProfileReport struct {
	DeviceIP               string               `json:"deviceIp"`
	DeviceName             string               `json:"deviceName"`
	DeviceMAC              string               `json:"deviceMac,omitempty"`
	DeviceRole             string               `json:"deviceRole"`
	Range                  DeviceProfileRange   `json:"range"`
	GeneratedAt            string               `json:"generatedAt"`
	TotalForegroundMinutes int                  `json:"totalForegroundMinutes"`
	TotalBackgroundMinutes int                  `json:"totalBackgroundMinutes"`
	ActiveAppCount         int                  `json:"activeAppCount"`
	UploadBytes            int64                `json:"uploadBytes"`
	DownloadBytes          int64                `json:"downloadBytes"`
	ProxySharePct          float64              `json:"proxySharePct"`
	IsNatSubRouter         bool                 `json:"isNatSubRouter"`
	PeakHourLabel          string               `json:"peakHourLabel"`
	PersonaTags            []DevicePersonaTag   `json:"personaTags"`
	Categories             []DeviceCategoryStat `json:"categories"`
	TopApps                []DeviceAppStat      `json:"topApps"`
	SystemApps             []DeviceAppStat      `json:"systemApps"`
	HourlyTimeline         []DeviceHourStat     `json:"hourlyTimeline"`
	DailyTrend             []DeviceDayStat      `json:"dailyTrend"`
	Storage                DeviceProfileStorage `json:"storage"`
}

// DeviceProfileAISummary 承载用户手动触发的脱敏 AI 画像总结结果（或本地回退总结）。
type DeviceProfileAISummary struct {
	OK          bool   `json:"ok"`
	Source      string `json:"source"`
	Summary     string `json:"summary"`
	GeneratedAt string `json:"generatedAt"`
}

type persistedAppBitset struct {
	AppName       string                   `json:"n"`
	Category      AppCategory              `json:"c"`
	IsInfra       bool                     `json:"i,omitempty"`
	EpochMinute   int64                    `json:"em"`
	Bits          [profileBitsetWords]uint64 `json:"b"`
	UploadBytes   int64                    `json:"up,omitempty"`
	DownloadBytes int64                    `json:"dn,omitempty"`
	BgMinutes     int                      `json:"bg,omitempty"`
	LastSeenUnix  int64                    `json:"ls,omitempty"`
	SampleTargets []string                 `json:"st,omitempty"`

	// 当分钟增量采样累积状态（不落盘）
	curBucketMin  int64
	curUpBytes    int64
	curDownBytes  int64
	curNewConns   int
	curMinCV      float64
	lastBgRecorded int64
}

type persistedDeviceProfile struct {
	DeviceIP         string                        `json:"ip"`
	DeviceName       string                        `json:"name,omitempty"`
	DeviceMAC        string                        `json:"mac,omitempty"`
	DeviceRole       string                        `json:"role,omitempty"`
	EpochMinute      int64                         `json:"em"`
	HourlyActiveMins [24]uint8                     `json:"hm"`
	HourlyKB         [24]uint32                    `json:"hk"`
	ProxyBytes       int64                         `json:"pb,omitempty"`
	DirectBytes      int64                         `json:"db,omitempty"`
	Apps             map[string]*persistedAppBitset `json:"apps,omitempty"`
	UpdatedUnix      int64                         `json:"ut,omitempty"`

	lastHourBucket [24]int64
	lastDevFgMin   int64
}

type dailyAppRollup struct {
	AppName       string      `json:"n"`
	Category      AppCategory `json:"c"`
	IsInfra       bool        `json:"i,omitempty"`
	FgMins        int         `json:"fg,omitempty"`
	BgMins        int         `json:"bg,omitempty"`
	Sessions      int         `json:"sc,omitempty"`
	LongestMin    int         `json:"lm,omitempty"`
	UploadBytes   int64       `json:"up,omitempty"`
	DownloadBytes int64       `json:"dn,omitempty"`
	PeakPeriod    string      `json:"pp,omitempty"`
	LastMinute    int64       `json:"lt,omitempty"`
	LastBgMinute  int64       `json:"lb,omitempty"`
	CurRunMins    int         `json:"cr,omitempty"`
}

type dailyDeviceRollup struct {
	DeviceIP         string                     `json:"ip"`
	DeviceName       string                     `json:"name,omitempty"`
	DeviceMAC        string                     `json:"mac,omitempty"`
	DeviceRole       string                     `json:"role,omitempty"`
	FgMins           int                        `json:"fg,omitempty"`
	UploadBytes      int64                      `json:"up,omitempty"`
	DownloadBytes    int64                      `json:"dn,omitempty"`
	ProxyBytes       int64                      `json:"pb,omitempty"`
	DirectBytes      int64                      `json:"db,omitempty"`
	HourlyActiveMins [24]uint8                  `json:"hm,omitempty"`
	LastFgMinute     int64                      `json:"lt,omitempty"`
	Apps             map[string]*dailyAppRollup `json:"apps,omitempty"`
}

type dailyProfileSnapshot struct {
	Date    string                        `json:"date"`
	Devices map[string]*dailyDeviceRollup `json:"devices,omitempty"`
}

type persistedProfileHistory struct {
	SchemaVersion int                              `json:"schemaVersion,omitempty"`
	UpdatedUnix   int64                            `json:"updatedUnix,omitempty"`
	Days          map[string]*dailyProfileSnapshot `json:"days,omitempty"`
}

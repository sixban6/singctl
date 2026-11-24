// 文件职责：定义 OpenWrt VLAN 硬件驱动抽象契约（Driver）与自动探测注册表（OCP 策略分派，屏蔽 DSA/swconfig/软路由差异）。
package vlan

// parsedState 保存从宿主机 UCI 与系统接口实时采集到的内部解析态，供各驱动生成精确命令。
type parsedState struct {
	Driver      Driver
	Board       *boardInfo
	NetUCI      *UCIConfig
	WirelessUCI *UCIConfig
	DHCP        *UCIConfig
	Firewall    *UCIConfig
	NetDevs     []string
	IPv4Addrs   map[string]string
	WANDevice   string
	WANIP       string
	WANSubnet   string
	Ports       []PortInfo
	Segments    []Segment
	// Switch-specific hints populated by SwconfigDriver
	SwitchName  string
	CPUPort     string
	WANPortNum  string
	LANBridge   string
}

// Driver 定义单种 OpenWrt 交换/网口架构的拓扑解析与网络层 UCI 编译策略。
type Driver interface {
	ID() string
	Label() string
	Matches(netUCI *UCIConfig, board *boardInfo, netDevs []string) bool
	ParseTopology(state *parsedState, readLink func(dev string) (bool, int)) (ports []PortInfo, segPorts map[string]map[string]string, segVLANs map[string]int)
	BuildNetworkCommands(state *parsedState, req SaveSegmentRequest, existing *Segment) (cmds []string, l3Device string, err error)
	BuildDeleteNetworkCommands(state *parsedState, seg Segment) ([]string, error)
}

// DriverRegistry 按优先级持有所有可用硬件驱动实现，实现新增交换芯片零修改核心编排（OCP）。
type DriverRegistry struct {
	drivers []Driver
}

// NewDefaultRegistry 返回内置三驱动注册表：swconfig 优先精确匹配，其次 DSA，最后 x86 多网口软路由。
func NewDefaultRegistry() *DriverRegistry {
	return &DriverRegistry{
		drivers: []Driver{
			&SwconfigDriver{},
			&DSADriver{},
			&SoftRouterDriver{},
		},
	}
}

// Detect 根据当前宿主 UCI 与网络接口自动选择匹配的硬件驱动。
func (r *DriverRegistry) Detect(netUCI *UCIConfig, board *boardInfo, netDevs []string) Driver {
	for _, d := range r.drivers {
		if d.Matches(netUCI, board, netDevs) {
			return d
		}
	}
	return nil
}

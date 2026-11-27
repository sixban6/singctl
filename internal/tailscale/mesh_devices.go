// 文件职责：从本地 DHCP 租约、内核 ARP 邻居表、静态保留与连接跟踪无损发现按网段归类的局域网终端设备。
package tailscale

import (
	"cmp"
	"context"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"runtime"
	"slices"
	"strings"
	"time"
)

// LocalDevice 描述某个本机直连网段或下级静态路由子网内部发现的一台具体设备。
type LocalDevice struct {
	IP           string `json:"ip"`
	Name         string `json:"name"`
	MAC          string `json:"mac,omitempty"`
	Online       bool   `json:"online"`
	StaticLease  bool   `json:"staticLease"`
	IsDownstream bool   `json:"isDownstream,omitempty"`
}

func populateNetworkDevices(ctx context.Context, nets []LocalNetwork, opts DiscoverOptions) {
	leaseText := opts.LeaseText
	if leaseText == "" && runtime.GOOS == "linux" {
		leaseText = readFirstExistingText([]string{
			"/tmp/dhcp.leases",
			"/var/lib/misc/dnsmasq.leases",
			"/var/lib/dhcp/dhcpd.leases",
		})
	}
	neighText := opts.NeighText
	if neighText == "" && runtime.GOOS == "linux" {
		nCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		if out, err := exec.CommandContext(nCtx, "ip", "-4", "neigh", "show").Output(); err == nil {
			neighText = string(out)
		}
		cancel()
	}
	staticHosts := opts.StaticHostIPs
	if staticHosts == nil && runtime.GOOS == "linux" {
		staticHosts = parseUCIStaticHostIPs("/etc/config/dhcp")
	}

	conntrackText := opts.ConntrackText
	hasDownstream := false
	for _, n := range nets {
		if n.Kind == LocalNetDownstreamSubnet {
			hasDownstream = true
			break
		}
	}
	if conntrackText == "" && hasDownstream && runtime.GOOS == "linux" {
		conntrackText = readCappedText("/proc/net/nf_conntrack", 256*1024)
	}

	type rawDev struct {
		ip          string
		mac         string
		hostname    string
		online      bool
		staticLease bool
	}
	devByIP := make(map[string]*rawDev)
	ensureDev := func(ipStr string) *rawDev {
		if d, ok := devByIP[ipStr]; ok {
			return d
		}
		d := &rawDev{ip: ipStr}
		devByIP[ipStr] = d
		return d
	}

	for line := range strings.SplitSeq(leaseText, "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) < 4 {
			continue
		}
		addr, err := netip.ParseAddr(fields[2])
		if err != nil || !addr.Unmap().Is4() {
			continue
		}
		ipStr := addr.Unmap().String()
		d := ensureDev(ipStr)
		if d.mac == "" && fields[1] != "*" {
			d.mac = strings.ToLower(strings.TrimSpace(fields[1]))
		}
		host := strings.TrimSpace(fields[3])
		if host != "*" && host != "" && d.hostname == "" {
			d.hostname = host
		}
		if fields[0] == "0" || staticHosts[ipStr] {
			d.staticLease = true
		}
	}

	for line := range strings.SplitSeq(neighText, "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) < 3 {
			continue
		}
		addr, err := netip.ParseAddr(fields[0])
		if err != nil || !addr.Unmap().Is4() {
			continue
		}
		var mac string
		for i := 1; i+1 < len(fields); i++ {
			if fields[i] == "lladdr" {
				mac = strings.ToLower(strings.TrimSpace(fields[i+1]))
			}
		}
		state := strings.ToUpper(fields[len(fields)-1])
		if mac == "" && (state == "FAILED" || state == "INCOMPLETE") {
			continue
		}
		ipStr := addr.Unmap().String()
		d := ensureDev(ipStr)
		if d.mac == "" {
			d.mac = mac
		}
		switch state {
		case "REACHABLE", "DELAY", "PROBE", "PERMANENT", "STALE":
			d.online = true
		}
		if staticHosts[ipStr] {
			d.staticLease = true
		}
	}

	for ipStr := range staticHosts {
		addr, err := netip.ParseAddr(ipStr)
		if err == nil && addr.Unmap().Is4() {
			d := ensureDev(addr.Unmap().String())
			d.staticLease = true
		}
	}

	// 记录所有被识别为下级路由网关的本网 IP（例如 192.168.31.151），供前端清晰标识 [下级路由]。
	downstreamGWs := make(map[string]bool)
	downstreamPrefixes := make([]netip.Prefix, 0)
	for _, n := range nets {
		if n.ViaGateway != "" {
			downstreamGWs[n.ViaGateway] = true
		}
		if n.Kind == LocalNetDownstreamSubnet {
			if pfx, err := netip.ParsePrefix(n.CIDR); err == nil {
				downstreamPrefixes = append(downstreamPrefixes, pfx)
			}
		}
	}

	if len(downstreamPrefixes) > 0 && conntrackText != "" {
		extractConntrackDownstreamIPs(conntrackText, downstreamPrefixes, func(ipStr string) {
			d := ensureDev(ipStr)
			d.online = true
		})
	}

	selfIP := strings.TrimSpace(opts.SelfLANIP)
	// 将已保存在 LocalRules 中的指定 IP 补入列表，确保离线主机仍可被管理/取消。
	for _, n := range nets {
		for _, selIP := range n.SelectedDevices {
			if selIP != "" && selIP != selfIP {
				ensureDev(selIP)
			}
		}
	}

	type netBucket struct {
		pfx     netip.Prefix
		devices []LocalDevice
	}
	buckets := make([]netBucket, len(nets))
	for i, n := range nets {
		if pfx, err := netip.ParsePrefix(n.CIDR); err == nil {
			buckets[i].pfx = pfx
		}
	}

	for ipStr, rd := range devByIP {
		if ipStr == selfIP {
			continue
		}
		addr, err := netip.ParseAddr(ipStr)
		if err != nil {
			continue
		}
		isDS := downstreamGWs[ipStr]
		staticLease := rd.staticLease || (rd.mac != "" && rd.hostname == "" && isDS) || (rd.mac != "" && rd.hostname == "")
		name := strings.TrimSpace(opts.DeviceNicknames[ipStr])
		if name == "" {
			name = strings.TrimSpace(rd.hostname)
		}
		if name == "" {
			if isDS {
				name = "下级路由器"
			} else {
				name = "静态/未知设备"
			}
		}
		item := LocalDevice{
			IP:           ipStr,
			Name:         name,
			MAC:          rd.mac,
			Online:       rd.online,
			StaticLease:  staticLease || staticHosts[ipStr],
			IsDownstream: isDS,
		}
		for i := range buckets {
			if buckets[i].pfx.IsValid() && buckets[i].pfx.Contains(addr) {
				buckets[i].devices = append(buckets[i].devices, item)
			}
		}
	}

	for i := range nets {
		devs := buckets[i].devices
		slices.SortFunc(devs, func(a, b LocalDevice) int {
			if a.IsDownstream != b.IsDownstream {
				if a.IsDownstream {
					return -1
				}
				return 1
			}
			if a.Online != b.Online {
				if a.Online {
					return -1
				}
				return 1
			}
			ap, _ := netip.ParseAddr(a.IP)
			bp, _ := netip.ParseAddr(b.IP)
			if c := ap.Compare(bp); c != 0 {
				return c
			}
			return cmp.Compare(a.Name, b.Name)
		})
		nets[i].Devices = devs
	}
}

func extractConntrackDownstreamIPs(conntrackText string, prefixes []netip.Prefix, onMatch func(ip string)) {
	for line := range strings.SplitSeq(conntrackText, "\n") {
		for tok := range strings.FieldsSeq(line) {
			raw, ok := strings.CutPrefix(tok, "src=")
			if !ok {
				raw, ok = strings.CutPrefix(tok, "dst=")
			}
			if !ok {
				continue
			}
			addr, err := netip.ParseAddr(raw)
			if err != nil || !addr.Unmap().Is4() {
				continue
			}
			u := addr.Unmap()
			for _, pfx := range prefixes {
				if pfx.Contains(u) {
					onMatch(u.String())
					break
				}
			}
		}
	}
}

func parseUCIStaticHostIPs(dhcpPath string) map[string]bool {
	out := make(map[string]bool)
	raw, err := os.ReadFile(dhcpPath)
	if err != nil {
		return out
	}
	inHost := false
	for line := range strings.SplitSeq(string(raw), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "config ") {
			inHost = strings.HasPrefix(trimmed, "config host")
			continue
		}
		if !inHost {
			continue
		}
		if strings.HasPrefix(trimmed, "option ip ") {
			val := strings.TrimSpace(strings.TrimPrefix(trimmed, "option ip "))
			val = strings.Trim(val, "'\"")
			if addr, err := netip.ParseAddr(val); err == nil && addr.Unmap().Is4() {
				out[addr.Unmap().String()] = true
			}
		}
	}
	return out
}

func readFirstExistingText(paths []string) string {
	for _, p := range paths {
		if b, err := os.ReadFile(p); err == nil {
			return string(b)
		}
	}
	return ""
}

func readCappedText(path string, maxBytes int64) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	b, _ := io.ReadAll(io.LimitReader(f, maxBytes))
	return string(b)
}

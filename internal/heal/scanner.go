package heal

import (
	"cmp"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"singctl/internal/config"
	"singctl/internal/deploy"
	"singctl/internal/util/github"
)

// CriticalSecurityPkgPrefixes lists security-sensitive packages always flagged even on custom mirrors.
var CriticalSecurityPkgPrefixes = []string{
	"openssl", "libssl", "libc6", "glibc", "openssh-", "ca-certificates",
	"curl", "libcurl", "gnutls", "libgnutls", "systemd", "sudo", "linux-image-",
}

// Scan inspects all 3 security layers + systemd timer + persisted policy/history without mutating system state.
func Scan(ctx context.Context, configPath string, currentSingctlVer string) StatusReport {
	var cfg *config.Config
	if strings.TrimSpace(configPath) != "" {
		cfg, _ = config.Load(configPath)
	}
	if cfg == nil {
		cfg, _ = config.Load("/etc/singctl/singctl.yaml")
	}

	statePath := ResolveStateFilePath(configPath)
	persisted := loadPersistedState(statePath)

	var (
		coreStatus   CoreLayerStatus
		osStatus     OSLayerStatus
		kernelStatus KernelLayerStatus
		timerStatus  TimerStatus
		wg           sync.WaitGroup
	)

	wg.Add(4)
	go func() {
		defer wg.Done()
		coreStatus = scanCoreLayer(ctx, cfg, currentSingctlVer)
	}()
	go func() {
		defer wg.Done()
		osStatus = scanOSLayer(ctx)
	}()
	go func() {
		defer wg.Done()
		kernelStatus = scanKernelLayer()
	}()
	go func() {
		defer wg.Done()
		timerStatus = GetTimerStatus(persisted.Policy.Schedule)
	}()
	wg.Wait()

	// Sync policy.AutoHealEnabled with live systemd timer if supported
	policy := persisted.Policy
	if timerStatus.Supported && timerStatus.Enabled {
		policy.AutoHealEnabled = true
	}

	posture, label := evaluatePosture(coreStatus, osStatus, kernelStatus)

	return StatusReport{
		CheckedAt:    time.Now().Format(time.RFC3339),
		Posture:      posture,
		PostureLabel: label,
		Core:         coreStatus,
		OS:           osStatus,
		Kernel:       kernelStatus,
		Timer:        timerStatus,
		Policy:       policy,
		History:      persisted.History,
	}
}

func evaluatePosture(core CoreLayerStatus, osLayer OSLayerStatus, kernel KernelLayerStatus) (string, string) {
	if !core.Healthy || !osLayer.Healthy {
		return PostureUpdatesPending, "发现待修复更新"
	}
	if !kernel.Healthy || kernel.RebootRequired {
		return PostureRebootRequired, "补丁已装·待重启生效"
	}
	return PostureHealthy, "三层防线已全面免疫"
}

func scanCoreLayer(_ context.Context, cfg *config.Config, currentSingctlVer string) CoreLayerStatus {
	mirror := ""
	if cfg != nil {
		mirror = cfg.GitHub.MirrorURL
	}
	fetcher := github.NewReleaseFetcher(mirror, deploy.ReleaseClient)

	curSingctl := strings.TrimPrefix(strings.TrimSpace(currentSingctlVer), "v")
	if curSingctl == "" || curSingctl == "dev" {
		if out, err := exec.Command("singctl", "version").CombinedOutput(); err == nil {
			for line := range strings.SplitSeq(string(out), "\n") {
				if idx := strings.Index(line, "SingCtl v"); idx != -1 {
					fields := strings.Fields(line[idx:])
					if len(fields) >= 2 {
						curSingctl = strings.TrimPrefix(fields[1], "v")
						break
					}
				}
			}
		}
	}

	type targetSpec struct {
		name    string
		display string
	}
	specs := []targetSpec{
		{"singctl", "SingCtl 主控/订阅内核"},
		{"singbox", "sing-box 代理核心"},
		{"caddy", "Caddy 网关 (TLS/L4)"},
		{"warp", "WARP (wireproxy)"},
	}

	checks := make([]ComponentCheck, len(specs))
	var wg sync.WaitGroup
	for i, sp := range specs {
		wg.Add(1)
		go func(idx int, spec targetSpec) {
			defer wg.Done()
			if spec.name == "singctl" {
				latest := curSingctl
				if tag, err := fetcher.FetchLatestTag("sixban6/singctl"); err == nil && strings.TrimSpace(tag) != "" {
					latest = strings.TrimPrefix(strings.TrimSpace(tag), "v")
				}
				installed := curSingctl != ""
				hasUp := installed && curSingctl != "dev" && compareVersionTokens(curSingctl, latest) < 0
				checks[idx] = ComponentCheck{
					Name:           "singctl",
					DisplayName:    spec.display,
					CurrentVersion: cmp.Or(curSingctl, "dev"),
					LatestVersion:  cmp.Or(latest, curSingctl, "dev"),
					Installed:      installed,
					HasUpdate:      hasUp,
				}
				return
			}

			res, err := deploy.CheckComponentUpdate(spec.name, cfg)
			if err != nil || res == nil {
				checks[idx] = ComponentCheck{
					Name:           spec.name,
					DisplayName:    spec.display,
					CurrentVersion: "未知",
					LatestVersion:  "未知",
				}
				return
			}
			installed := res.CurrentVersion != "" && res.CurrentVersion != "未安装"
			checks[idx] = ComponentCheck{
				Name:           spec.name,
				DisplayName:    spec.display,
				CurrentVersion: cmp.Or(res.CurrentVersion, "未安装"),
				LatestVersion:  cmp.Or(res.LatestVersion, res.CurrentVersion),
				Installed:      installed,
				// Only flag installed components for security self-healing (e.g. OpenWrt clients don't run Caddy/WARP)
				HasUpdate: installed && res.HasUpdate,
			}
		}(i, sp)
	}
	wg.Wait()

	pending := 0
	for _, c := range checks {
		if c.HasUpdate {
			pending++
		}
	}
	return CoreLayerStatus{
		Components:   checks,
		PendingCount: pending,
		Healthy:      pending == 0,
	}
}

func scanOSLayer(ctx context.Context) OSLayerStatus {
	st := OSLayerStatus{
		Distro:          detectDistroPrettyName(),
		PackageManager:  "unknown",
		SecurityUpdates: []string{},
		StaleServices:   []string{},
		Healthy:         true,
	}
	if runtime.GOOS != "linux" {
		return st
	}

	if isOpenWrtSystem() {
		st.PackageManager = "opkg"
		st.OpenWrtProtected = true
		return st
	}

	cCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	switch {
	case hasBinary("apt-get"):
		st.PackageManager = "apt"
		if fi, err := os.Stat("/var/cache/apt/pkgcache.bin"); err == nil {
			st.LastAptCacheUpdate = fi.ModTime().Format(time.RFC3339)
		}
		cmd := exec.CommandContext(cCtx, "apt-get", "-s", "-o", "Debug::NoLocking=true", "upgrade")
		cmd.Env = append(os.Environ(), "LC_ALL=C")
		if out, err := cmd.CombinedOutput(); err == nil {
			st.SecurityUpdates = ParseAptSimulateSecurityUpdates(string(out))
		}
	case hasBinary("dnf"):
		st.PackageManager = "dnf"
		cmd := exec.CommandContext(cCtx, "dnf", "check-update", "--security", "-q")
		cmd.Env = append(os.Environ(), "LC_ALL=C")
		out, _ := cmd.CombinedOutput() // dnf check-update exits 100 when updates are available
		st.SecurityUpdates = ParseDnfSecurityCheckUpdate(string(out))
	}

	st.SecurityCount = len(st.SecurityUpdates)
	st.StaleServices = ScanStaleSharedLibraryServices()
	st.Healthy = st.SecurityCount == 0 && len(st.StaleServices) == 0
	return st
}

// ParseAptSimulateSecurityUpdates extracts security-related package names from `apt-get -s upgrade` output.
func ParseAptSimulateSecurityUpdates(raw string) []string {
	seen := make(map[string]bool)
	var pkgs []string
	for line := range strings.SplitSeq(raw, "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "Inst ") {
			continue
		}
		fields := strings.Fields(trimmed)
		if len(fields) < 2 {
			continue
		}
		pkg := fields[1]
		lowerLine := strings.ToLower(trimmed)
		isSecRepo := strings.Contains(lowerLine, "security")
		isCritPkg := false
		for _, pfx := range CriticalSecurityPkgPrefixes {
			if strings.HasPrefix(strings.ToLower(pkg), pfx) {
				isCritPkg = true
				break
			}
		}
		if (isSecRepo || isCritPkg) && !seen[pkg] {
			seen[pkg] = true
			pkgs = append(pkgs, pkg)
		}
	}
	slices.Sort(pkgs)
	return pkgs
}

// ParseDnfSecurityCheckUpdate extracts package names from `dnf check-update --security -q`.
func ParseDnfSecurityCheckUpdate(raw string) []string {
	seen := make(map[string]bool)
	var pkgs []string
	for line := range strings.SplitSeq(raw, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "Last metadata") || strings.HasPrefix(trimmed, "Obsoleting") {
			continue
		}
		fields := strings.Fields(trimmed)
		if len(fields) >= 3 {
			pkg := fields[0]
			if idx := strings.LastIndex(pkg, "."); idx > 0 {
				pkg = pkg[:idx]
			}
			if !seen[pkg] {
				seen[pkg] = true
				pkgs = append(pkgs, pkg)
			}
		}
	}
	slices.Sort(pkgs)
	return pkgs
}

// ScanStaleSharedLibraryServices inspects /proc/[pid]/maps for core services still holding (deleted) .so files in RAM.
func ScanStaleSharedLibraryServices() []string {
	if runtime.GOOS != "linux" {
		return []string{}
	}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return []string{}
	}
	staleSet := make(map[string]bool)
	for _, ent := range entries {
		if !ent.IsDir() {
			continue
		}
		pid := ent.Name()
		if _, err := strconv.Atoi(pid); err != nil {
			continue
		}
		commBytes, err := os.ReadFile(filepath.Join("/proc", pid, "comm"))
		if err != nil {
			continue
		}
		comm := strings.TrimSpace(string(commBytes))
		svc := mapProcessToServiceUnit(pid, comm)
		if svc == "" || staleSet[svc] {
			continue
		}
		mapsBytes, err := os.ReadFile(filepath.Join("/proc", pid, "maps"))
		if err != nil {
			continue
		}
		if HasDeletedSharedLibInMaps(string(mapsBytes)) {
			staleSet[svc] = true
		}
	}
	out := make([]string, 0, len(staleSet))
	for svc := range staleSet {
		out = append(out, svc)
	}
	slices.Sort(out)
	return out
}

// HasDeletedSharedLibInMaps returns true if a /proc/<pid>/maps snapshot contains a `(deleted)` .so mapping.
func HasDeletedSharedLibInMaps(mapsContent string) bool {
	for line := range strings.SplitSeq(mapsContent, "\n") {
		if !strings.Contains(line, "(deleted)") {
			continue
		}
		if strings.Contains(line, ".so") {
			return true
		}
	}
	return false
}

func mapProcessToServiceUnit(pid, comm string) string {
	switch comm {
	case "sing-box":
		return "sing-box"
	case "caddy":
		return "caddy"
	case "wireproxy":
		return "wireproxy"
	case "sshd":
		return "sshd"
	case "singctl":
		cmdline, _ := os.ReadFile(filepath.Join("/proc", pid, "cmdline"))
		s := strings.ReplaceAll(string(cmdline), "\x00", " ")
		if strings.Contains(s, " sub") {
			return "singctl-sub"
		}
		if strings.Contains(s, " web") {
			return "singctl-web"
		}
	}
	return ""
}

func scanKernelLayer() KernelLayerStatus {
	st := KernelLayerStatus{
		Healthy: true,
	}
	if out, err := exec.Command("uname", "-r").Output(); err == nil {
		st.RunningKernel = strings.TrimSpace(string(out))
	}
	if runtime.GOOS != "linux" || isOpenWrtSystem() {
		return st
	}

	// 1. Check /boot/vmlinuz-* for newly installed kernel images
	matches, _ := filepath.Glob("/boot/vmlinuz-*")
	var bestVer string
	for _, m := range matches {
		base := filepath.Base(m)
		if strings.Contains(base, "rescue") {
			continue
		}
		ver := strings.TrimPrefix(base, "vmlinuz-")
		if bestVer == "" || compareVersionTokens(bestVer, ver) < 0 {
			bestVer = ver
		}
	}
	st.InstalledKernel = bestVer

	// 2. Check Debian/Ubuntu /var/run/reboot-required
	if _, err := os.Stat("/var/run/reboot-required"); err == nil {
		st.RebootRequired = true
		if rawPkgs, pErr := os.ReadFile("/var/run/reboot-required.pkgs"); pErr == nil {
			seen := make(map[string]bool)
			for line := range strings.SplitSeq(string(rawPkgs), "\n") {
				p := strings.TrimSpace(line)
				if p != "" && !seen[p] {
					seen[p] = true
					st.AffectedPkgs = append(st.AffectedPkgs, p)
				}
			}
		}
	}

	// 3. Compare running kernel vs highest installed kernel
	if st.RunningKernel != "" && st.InstalledKernel != "" &&
		st.RunningKernel != st.InstalledKernel &&
		compareVersionTokens(st.RunningKernel, st.InstalledKernel) < 0 {
		st.RebootRequired = true
		st.RebootReason = "检测到新内核安全补丁待重启加载 (" + st.RunningKernel + " → " + st.InstalledKernel + ")"
	} else if st.RebootRequired && st.RebootReason == "" {
		st.RebootReason = "系统标记 /var/run/reboot-required 待重启生效底层安全更新"
	}

	st.Healthy = !st.RebootRequired
	return st
}

// CompareKernelVersions returns -1 if a < b, 0 if a == b, +1 if a > b using natural alphanumeric token ordering.
func CompareKernelVersions(a, b string) int {
	return compareVersionTokens(a, b)
}

func compareVersionTokens(a, b string) int {
	ta := splitAlphaNumTokens(strings.TrimPrefix(strings.TrimSpace(a), "v"))
	tb := splitAlphaNumTokens(strings.TrimPrefix(strings.TrimSpace(b), "v"))
	n := max(len(ta), len(tb))
	for i := range n {
		var sa, sb string
		if i < len(ta) {
			sa = ta[i]
		}
		if i < len(tb) {
			sb = tb[i]
		}
		if sa == sb {
			continue
		}
		na, errA := strconv.Atoi(sa)
		nb, errB := strconv.Atoi(sb)
		if errA == nil && errB == nil {
			if na < nb {
				return -1
			}
			if na > nb {
				return 1
			}
			continue
		}
		if sa < sb {
			return -1
		}
		return 1
	}
	return 0
}

func splitAlphaNumTokens(s string) []string {
	var tokens []string
	var cur strings.Builder
	lastDigit := false
	for i, r := range s {
		isSep := (r < '0' || r > '9') && (r < 'a' || r > 'z') && (r < 'A' || r > 'Z')
		if isSep {
			if cur.Len() > 0 {
				tokens = append(tokens, cur.String())
				cur.Reset()
			}
			continue
		}
		isDigit := r >= '0' && r <= '9'
		if i > 0 && cur.Len() > 0 && isDigit != lastDigit {
			tokens = append(tokens, cur.String())
			cur.Reset()
		}
		cur.WriteRune(r)
		lastDigit = isDigit
	}
	if cur.Len() > 0 {
		tokens = append(tokens, cur.String())
	}
	return tokens
}

func detectDistroPrettyName() string {
	if runtime.GOOS != "linux" {
		return runtime.GOOS
	}
	if raw, err := os.ReadFile("/etc/os-release"); err == nil {
		for line := range strings.SplitSeq(string(raw), "\n") {
			if after, ok := strings.CutPrefix(strings.TrimSpace(line), "PRETTY_NAME="); ok {
				return strings.Trim(after, `"'`)
			}
		}
	}
	return "Linux"
}

func isOpenWrtSystem() bool {
	if _, err := os.Stat("/etc/openwrt_release"); err == nil {
		return true
	}
	if raw, err := os.ReadFile("/etc/os-release"); err == nil {
		return strings.Contains(strings.ToLower(string(raw)), "openwrt")
	}
	return false
}

func hasBinary(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

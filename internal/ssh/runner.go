package ssh

import (
	"fmt"
	"slices"
	"sync"
	"time"

	"singctl/internal/logger"
)

// Runner manages multi-host concurrent operations.
type Runner struct{}

// NewRunner creates a new Runner instance.
func NewRunner() *Runner {
	return &Runner{}
}

// RunInit runs the full lifecycle: push key -> verify 22 -> dual-port -> verify 2222 -> close 22 & password -> sync ~/.ssh/config.
func (r *Runner) RunInit(hosts []*Host, concurrency int, dryRun bool, skipConfig bool) []*HostResult {
	if concurrency <= 0 {
		concurrency = 5
	}

	logger.Info("🚀 开始执行 SSH 批量初始化与安全加固 (主机数: %d, 并发: %d)...", len(hosts), concurrency)
	if dryRun {
		logger.Warn("⚠️ 处于 DRY-RUN 演练模式：仅检测连通性与配置，不下发破坏性变更。")
	}

	results := make([]*HostResult, len(hosts))
	jobs := make(chan int, len(hosts))
	var wg sync.WaitGroup

	for w := 0; w < concurrency; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for idx := range jobs {
				results[idx] = r.executeInitHost(hosts[idx], dryRun)
			}
		}()
	}

	for i := range hosts {
		jobs <- i
	}
	close(jobs)
	wg.Wait()

	// Sync local ~/.ssh/config only for successful DIRECT hosts (alias hosts are already managed in ~/.ssh/config)
	if !skipConfig && !dryRun {
		var successHosts []*Host
		for _, res := range results {
			if res.Status == StatusSuccess && !res.Host.IsAliasMode {
				successHosts = append(successHosts, res.Host)
			}
		}
		if len(successHosts) > 0 {
			cfgMgr := NewLocalConfigManager("")
			if err := cfgMgr.SyncHosts(successHosts); err != nil {
				logger.Error("回写本地 ~/.ssh/config 失败: %v", err)
			} else {
				for _, res := range results {
					if res.Status == StatusSuccess && !res.Host.IsAliasMode {
						res.ConfigUpdated = true
					}
				}
				logger.Success("已增量同步 %d 台主机配置至本地 %s", len(successHosts), cfgMgr.GetConfigPath())
			}
		}
	}

	return results
}

func (r *Runner) executeInitHost(h *Host, dryRun bool) *HostResult {
	start := time.Now()
	res := &HostResult{
		Host:        h,
		InitialPort: h.CurrentPort,
		FinalPort:   h.CurrentPort,
		Status:      StatusFailed,
	}

	// Case A: Host already configured in ~/.ssh/config (Alias mode)
	if h.IsAliasMode {
		logger.Info("[%s] 🌐 检测到 ~/.ssh/config 中已配置的主机 (别名: %s)", h.Name, h.Alias)
		executor, err := CreateExecutor(h, h.CurrentPort, false)
		if err != nil {
			res.Error = fmt.Errorf("alias client init failed: %w", err)
			res.Duration = time.Since(start)
			return res
		}
		defer executor.Close()

		if dryRun {
			if !ProbeAliasLogin(h, h.Timeout) {
				res.Error = fmt.Errorf("alias '%s' connection probe failed", h.Alias)
				res.Duration = time.Since(start)
				logger.Error("[%s] ❌ [DRY-RUN] 连接失败", h.Name)
				return res
			}
			res.Status = StatusSuccess
			res.KeyPushed = true
			res.KeyVerified = true
			res.Duration = time.Since(start)
			logger.Success("[%s] ✅ [DRY-RUN] ~/.ssh/config 主机通道畅通", h.Name)
			return res
		}

		// 1. Inject public key
		logger.Info("[%s] 🔑 [1/3] 注入本地公钥至 ~/.ssh/authorized_keys...", h.Name)
		if err := executor.InjectPublicKey(h.IdentityFile); err != nil {
			res.Error = fmt.Errorf("inject public key failed: %w", err)
			res.Duration = time.Since(start)
			logger.Error("[%s] ❌ 公钥注入失败: %v", h.Name, err)
			return res
		}
		res.KeyPushed = true
		logger.Success("[%s] 🔑 [1/3] 公钥已写入", h.Name)

		// 2. Probe key login
		time.Sleep(500 * time.Millisecond)
		logger.Info("[%s] 🩺 [2/3] 验证免密登录连通性...", h.Name)
		if !ProbeAliasLogin(h, h.Timeout) {
			res.Error = fmt.Errorf("verification of key login via alias '%s' failed", h.Alias)
			res.Duration = time.Since(start)
			logger.Error("[%s] ❌ 免密登录验证失败 (中止加固以防失联): %v", h.Name, res.Error)
			return res
		}
		res.KeyVerified = true
		logger.Success("[%s] ✅ [2/3] 免密验证通过", h.Name)

		// 3. Finalize hardening: enforce h.TargetPort (never 0!) and disable password auth
		logger.Info("[%s] 🔒 [3/3] 执行安全加固 (端口: %d, 禁用密码登录: %v)...", h.Name, h.TargetPort, h.DisablePasswordAuth)
		harden := NewSshdHarden(executor)
		if err := harden.FinalizeHardening(h.TargetPort, h.DisablePasswordAuth); err != nil {
			res.Error = fmt.Errorf("finalize hardening failed: %w", err)
			res.Duration = time.Since(start)
			logger.Error("[%s] ❌ 安全加固失败: %v", h.Name, err)
			return res
		}

		// 4. Post-check verification
		time.Sleep(500 * time.Millisecond)
		if !ProbeAliasLogin(h, h.Timeout) {
			res.Error = fmt.Errorf("post-hardening key login verification via alias '%s' failed", h.Alias)
			res.Duration = time.Since(start)
			logger.Error("[%s] ❌ 加固后通道免密验证失败: %v", h.Name, res.Error)
			return res
		}

		res.FinalPort = h.TargetPort
		res.PasswordDisabled = h.DisablePasswordAuth
		res.Status = StatusSuccess
		res.Duration = time.Since(start)
		logger.Success("[%s] 🎉 ~/.ssh/config 已配置主机加固完成！", h.Name)
		return res
	}

	// Case B: Direct Host (IP / Hostname)
	targetAddr := h.Host
	if targetAddr == "" {
		targetAddr = h.IP
	}

	logger.Info("[%s] 🔑 [1/5] 连接初始端口 %d 并注入公钥...", h.Name, h.CurrentPort)

	// Step 1: Initial connection with password or initial key
	client, err := DialHost(h, h.CurrentPort, false)
	if err != nil {
		res.Error = fmt.Errorf("initial connection failed on %s:%d: %w", targetAddr, h.CurrentPort, err)
		res.Duration = time.Since(start)
		logger.Error("[%s] ❌ 初始连接失败: %v", h.Name, err)
		return res
	}
	defer client.Close()

	if dryRun {
		res.Status = StatusSuccess
		res.KeyPushed = true
		res.KeyVerified = true
		res.FinalPort = h.TargetPort
		res.Duration = time.Since(start)
		logger.Success("[%s] ✅ [DRY-RUN] 初始通道连通性正常", h.Name)
		return res
	}

	// Step 2: Inject public key
	if err := client.InjectPublicKey(h.IdentityFile); err != nil {
		res.Error = fmt.Errorf("failed to inject public key: %w", err)
		res.Duration = time.Since(start)
		logger.Error("[%s] ❌ 公钥注入失败: %v", h.Name, err)
		return res
	}
	res.KeyPushed = true
	logger.Success("[%s] 🔑 [2/5] 公钥已写入 ~/.ssh/authorized_keys", h.Name)

	// Step 3: Gate 1 - Verify key login on current port
	time.Sleep(500 * time.Millisecond)
	ok, err := ProbeKeyLogin(h, h.CurrentPort, h.Timeout)
	if !ok || err != nil {
		res.Error = fmt.Errorf("verification of newly injected key on port %d failed: %v", h.CurrentPort, err)
		res.Duration = time.Since(start)
		logger.Error("[%s] ❌ 新密钥首验失败 (中止加固以防失联): %v", h.Name, res.Error)
		return res
	}
	res.KeyVerified = true
	logger.Success("[%s] ✅ [3/5] 新私钥免密登录首验成功 (端口 %d)", h.Name, h.CurrentPort)

	fw := NewFirewallManager(client)
	harden := NewSshdHarden(client)

	if h.TargetPort != h.CurrentPort {
		// Step 4: Firewall allow target port
		if h.ManageFirewall {
			_ = fw.AllowPort(h.TargetPort)
			res.FirewallConfigured = true
		}

		// Step 5: Enable dual-port (Port 22 + TargetPort)
		logger.Info("[%s] 🛡️ [4/5] 开启双端口过渡 (Port %d + Port %d)...", h.Name, h.CurrentPort, h.TargetPort)
		if err := harden.EnableDualPort(h.CurrentPort, h.TargetPort); err != nil {
			res.Error = fmt.Errorf("enable dual-port failed: %w", err)
			res.Duration = time.Since(start)
			logger.Error("[%s] ❌ 启用双端口失败: %v", h.Name, err)
			return res
		}

		// Step 6: Gate 2 - Verify key login on target port from local machine
		time.Sleep(1 * time.Second)
		targetOk, targetErr := ProbeKeyLogin(h, h.TargetPort, h.Timeout)
		if !targetOk {
			// CIRCUIT BREAKER TRIGGERED!
			logger.Warn("[%s] 🚨 熔断保护触发: 目标端口 %d 外部拨测失败 (错误: %v)！", h.Name, h.TargetPort, targetErr)
			logger.Warn("[%s] 🚨 正在自动回滚, 维持安全端口 %d 监听并保留密码访问...", h.Name, h.CurrentPort)
			_ = harden.RollbackToPort(h.CurrentPort)

			res.Status = StatusWarning
			res.FinalPort = h.CurrentPort
			res.WarningMsg = fmt.Sprintf("Target port %d is unreachable (check cloud security group/firewall). Rolled back to port %d safely.", h.TargetPort, h.CurrentPort)
			res.Duration = time.Since(start)
			return res
		}
		logger.Success("[%s] ✅ [4/5] 目标端口 %d 外部免密直连拨测成功！", h.Name, h.TargetPort)
	}

	// Step 7: Finalize hardening: switch only to target port, disable password auth if requested
	logger.Info("[%s] 🔒 [5/5] 收敛安全基线 (锁定端口 %d, 关闭密码认证: %v)...", h.Name, h.TargetPort, h.DisablePasswordAuth)
	if err := harden.FinalizeHardening(h.TargetPort, h.DisablePasswordAuth); err != nil {
		res.Error = fmt.Errorf("finalize hardening failed: %w", err)
		res.Duration = time.Since(start)
		logger.Error("[%s] ❌ 收敛加固失败: %v", h.Name, err)
		return res
	}

	if h.TargetPort != h.CurrentPort && h.ManageFirewall {
		_ = fw.DisallowPort(h.CurrentPort)
	}

	res.FinalPort = h.TargetPort
	res.PasswordDisabled = h.DisablePasswordAuth
	res.Status = StatusSuccess
	res.Duration = time.Since(start)
	logger.Success("[%s] 🎉 该节点全流程加固完成！", h.Name)
	return res
}

// RunTest executes diagnostic probing for all hosts in the list.
func (r *Runner) RunTest(hosts []*Host, concurrency int) []*TestResult {
	if concurrency <= 0 {
		concurrency = 5
	}

	logger.Info("🩺 正在对 %d 台主机进行连通性与合规性体检 (并发: %d)...", len(hosts), concurrency)

	results := make([]*TestResult, len(hosts))
	jobs := make(chan int, len(hosts))
	var wg sync.WaitGroup

	for w := 0; w < concurrency; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for idx := range jobs {
				h := hosts[idx]
				start := time.Now()

				tr := &TestResult{
					Host:     h,
					Duration: 0,
				}

				var currentPortOpen bool
				var port22Open bool
				var targetPortOpen bool
				var keyAuthWork bool
				var passwordAuthWork bool

				if h.IsAliasMode {
					// 1. In alias mode, probe key login via system SSH alias
					keyAuthWork = ProbeAliasLogin(h, h.Timeout)
					if keyAuthWork {
						// 2. Query remote sshd -T for authoritative port & password auth state
						aliasClient := NewAliasClient(h)
						if info, err := InspectRemoteSshd(aliasClient); err == nil {
							port22Open = slices.Contains(info.Ports, 22)
							currentPortOpen = slices.Contains(info.Ports, h.CurrentPort)
							targetPortOpen = slices.Contains(info.Ports, h.TargetPort)
							passwordAuthWork = info.PasswordAuth
						} else {
							currentPortOpen = true
							targetPortOpen = true
							port22Open = (h.CurrentPort == 22)
						}
					}
				} else {
					hostTarget := h.Host
					if hostTarget == "" {
						hostTarget = h.IP
					}

					// 1. Probe ports
					currentPortOpen = TestTCPPort(hostTarget, h.CurrentPort, h.Timeout)
					port22Open = TestTCPPort(hostTarget, 22, h.Timeout)
					if h.TargetPort == h.CurrentPort {
						targetPortOpen = currentPortOpen
					} else {
						targetPortOpen = TestTCPPort(hostTarget, h.TargetPort, h.Timeout)
					}

					// 2. Test Key Auth on whichever port is open
					activePort := h.CurrentPort
					if targetPortOpen {
						activePort = h.TargetPort
					}

					keyAuthWork, _ = ProbeKeyLogin(h, activePort, h.Timeout)

					if keyAuthWork {
						// Query remote sshd -T for authoritative password authentication status
						if executor, err := CreateExecutor(h, activePort, true); err == nil {
							if info, err := InspectRemoteSshd(executor); err == nil {
								port22Open = slices.Contains(info.Ports, 22)
								currentPortOpen = slices.Contains(info.Ports, h.CurrentPort)
								targetPortOpen = slices.Contains(info.Ports, h.TargetPort)
								passwordAuthWork = info.PasswordAuth
							}
							_ = executor.Close()
						}
					} else {
						passAccepted, _ := ProbePasswordLogin(h, activePort, "", h.Timeout)
						passwordAuthWork = passAccepted
					}
				}

				tr.CurrentPortOpen = currentPortOpen
				tr.Port22Open = port22Open
				tr.TargetPortOpen = targetPortOpen
				tr.KeyAuthWork = keyAuthWork
				tr.PasswordAuthWork = passwordAuthWork
				tr.Duration = time.Since(start)
				results[idx] = tr
			}
		}()
	}

	for i := range hosts {
		jobs <- i
	}
	close(jobs)
	wg.Wait()

	return results
}

// RunPushKey only pushes the public key to target machines.
func (r *Runner) RunPushKey(hosts []*Host, concurrency int) []*HostResult {
	if concurrency <= 0 {
		concurrency = 5
	}

	logger.Info("🔑 开始批量分发公钥至 %d 台主机 (并发: %d)...", len(hosts), concurrency)

	results := make([]*HostResult, len(hosts))
	jobs := make(chan int, len(hosts))
	var wg sync.WaitGroup

	for w := 0; w < concurrency; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for idx := range jobs {
				h := hosts[idx]
				start := time.Now()
				res := &HostResult{
					Host:        h,
					InitialPort: h.CurrentPort,
					FinalPort:   h.CurrentPort,
					Status:      StatusFailed,
				}

				executor, err := CreateExecutor(h, h.CurrentPort, false)
				if err != nil {
					res.Error = fmt.Errorf("connect failed: %w", err)
					res.Duration = time.Since(start)
					results[idx] = res
					continue
				}

				if err := executor.InjectPublicKey(h.IdentityFile); err != nil {
					_ = executor.Close()
					res.Error = fmt.Errorf("inject key failed: %w", err)
					res.Duration = time.Since(start)
					results[idx] = res
					continue
				}
				_ = executor.Close()

				res.KeyPushed = true
				var ok bool
				if h.IsAliasMode {
					ok = ProbeAliasLogin(h, h.Timeout)
				} else {
					ok, _ = ProbeKeyLogin(h, h.CurrentPort, h.Timeout)
				}
				res.KeyVerified = ok
				if ok {
					res.Status = StatusSuccess
					logger.Success("[%s] 🔑 公钥注入与免密验证通过", h.Name)
				} else {
					res.Status = StatusWarning
					res.WarningMsg = "Public key injected but external key probe failed"
					logger.Warn("[%s] ⚠️ 公钥已注入，但外部免密探测未通过", h.Name)
				}

				res.Duration = time.Since(start)
				results[idx] = res
			}
		}()
	}

	for i := range hosts {
		jobs <- i
	}
	close(jobs)
	wg.Wait()

	return results
}

// RunHarden applies port switching and disables password authentication for hosts that already have key authentication.
func (r *Runner) RunHarden(hosts []*Host, concurrency int, overridePort int, disablePassword bool, skipConfig bool) []*HostResult {
	if concurrency <= 0 {
		concurrency = 5
	}

	logger.Info("🔒 开始批量执行 SSH 端口切换与密码禁用安全加固 (主机数: %d)...", len(hosts))

	results := make([]*HostResult, len(hosts))
	jobs := make(chan int, len(hosts))
	var wg sync.WaitGroup

	for w := 0; w < concurrency; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for idx := range jobs {
				h := hosts[idx]
				start := time.Now()

				if overridePort > 0 {
					h.TargetPort = overridePort
				}
				if disablePassword {
					h.DisablePasswordAuth = true
				}

				res := &HostResult{
					Host:        h,
					InitialPort: h.CurrentPort,
					FinalPort:   h.CurrentPort,
					Status:      StatusFailed,
				}

				executor, err := CreateExecutor(h, h.CurrentPort, true)
				if err != nil {
					// In direct mode, try target port if already switched
					if !h.IsAliasMode && h.TargetPort != h.CurrentPort {
						if altExecutor, altErr := CreateExecutor(h, h.TargetPort, true); altErr == nil {
							executor = altExecutor
							h.CurrentPort = h.TargetPort
						}
					}
					if executor == nil {
						res.Error = fmt.Errorf("connect on port %d failed: %w", h.CurrentPort, err)
						res.Duration = time.Since(start)
						results[idx] = res
						continue
					}
				}
				defer executor.Close()

				// Step 1: Ensure public key is injected to avoid lockout
				if err := executor.InjectPublicKey(h.IdentityFile); err != nil {
					logger.Warn("[%s] 注入公钥提示: %v", h.Name, err)
				}

				// Step 2: Verify key authentication works BEFORE modifying anything
				var preCheckOk bool
				if h.IsAliasMode {
					preCheckOk = ProbeAliasLogin(h, h.Timeout)
				} else {
					preCheckOk, _ = ProbeKeyLogin(h, h.CurrentPort, h.Timeout)
				}
				if !preCheckOk {
					res.Error = fmt.Errorf("pre-check key authentication failed on port %d, aborting hardening to prevent lockout", h.CurrentPort)
					res.Duration = time.Since(start)
					results[idx] = res
					continue
				}

				res.KeyVerified = true
				fw := NewFirewallManager(executor)
				harden := NewSshdHarden(executor)

				// Step 3: Dual-port transition if TargetPort differs from CurrentPort (direct mode)
				if !h.IsAliasMode && h.TargetPort != h.CurrentPort {
					if h.ManageFirewall {
						_ = fw.AllowPort(h.TargetPort)
					}

					if err := harden.EnableDualPort(h.CurrentPort, h.TargetPort); err != nil {
						res.Error = fmt.Errorf("enable dual-port failed: %w", err)
						res.Duration = time.Since(start)
						results[idx] = res
						continue
					}

					time.Sleep(1 * time.Second)
					ok, probeErr := ProbeKeyLogin(h, h.TargetPort, h.Timeout)
					if !ok {
						_ = harden.RollbackToPort(h.CurrentPort)
						res.Status = StatusWarning
						res.WarningMsg = fmt.Sprintf("Target port %d probe failed (%v), rolled back safely to %d.", h.TargetPort, probeErr, h.CurrentPort)
						res.Duration = time.Since(start)
						results[idx] = res
						continue
					}
				}

				// Step 4: Finalize hardening with h.TargetPort (NEVER 0!)
				if err := harden.FinalizeHardening(h.TargetPort, h.DisablePasswordAuth); err != nil {
					res.Error = fmt.Errorf("finalize hardening failed: %w", err)
					res.Duration = time.Since(start)
					results[idx] = res
					continue
				}

				// Step 5: Post-hardening verification
				time.Sleep(500 * time.Millisecond)
				var postCheckOk bool
				if h.IsAliasMode {
					postCheckOk = ProbeAliasLogin(h, h.Timeout)
				} else {
					postCheckOk, _ = ProbeKeyLogin(h, h.TargetPort, h.Timeout)
				}
				if !postCheckOk {
					// Post verification failed! Rollback to prevent lockout!
					if !h.IsAliasMode && h.TargetPort != h.CurrentPort {
						_ = harden.EnableDualPort(h.CurrentPort, h.TargetPort)
					}
					res.Error = fmt.Errorf("post-hardening key login verification failed on port %d", h.TargetPort)
					res.Status = StatusWarning
					res.WarningMsg = "Post verification failed; dual-port safely maintained to prevent lockout."
					res.Duration = time.Since(start)
					results[idx] = res
					continue
				}

				// Step 6: Close old port in firewall if TargetPort != CurrentPort and not alias mode
				if !h.IsAliasMode && h.TargetPort != h.CurrentPort && h.ManageFirewall {
					_ = fw.DisallowPort(h.CurrentPort)
				}

				res.FinalPort = h.TargetPort
				res.PasswordDisabled = h.DisablePasswordAuth
				res.Status = StatusSuccess
				res.Duration = time.Since(start)
				results[idx] = res
			}
		}()
	}

	for i := range hosts {
		jobs <- i
	}
	close(jobs)
	wg.Wait()

	if !skipConfig {
		var successHosts []*Host
		for _, res := range results {
			if res.Status == StatusSuccess && !res.Host.IsAliasMode {
				successHosts = append(successHosts, res.Host)
			}
		}
		if len(successHosts) > 0 {
			cfgMgr := NewLocalConfigManager("")
			_ = cfgMgr.SyncHosts(successHosts)
			for _, res := range results {
				if res.Status == StatusSuccess && !res.Host.IsAliasMode {
					res.ConfigUpdated = true
				}
			}
		}
	}

	return results
}

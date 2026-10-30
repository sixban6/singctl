package ssh

import (
	"fmt"
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

	// Sync local ~/.ssh/config for successful hosts
	if !skipConfig && !dryRun {
		var successHosts []*Host
		for _, res := range results {
			if res.Status == StatusSuccess {
				successHosts = append(successHosts, res.Host)
			}
		}
		if len(successHosts) > 0 {
			cfgMgr := NewLocalConfigManager("")
			if err := cfgMgr.SyncHosts(successHosts); err != nil {
				logger.Error("回写本地 ~/.ssh/config 失败: %v", err)
			} else {
				for _, res := range results {
					if res.Status == StatusSuccess {
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

	logger.Info("[%s] 🔑 [1/5] 连接初始端口 %d 并注入公钥...", h.Name, h.CurrentPort)

	// Step 1: Initial connection with password or initial key
	client, err := DialHost(h, h.CurrentPort, false)
	if err != nil {
		res.Error = fmt.Errorf("initial connection failed on port %d: %w", h.CurrentPort, err)
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

	// If target port is same as current port and no port change is required
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

				// 1. Probe current port
				tr.Port22Open = TestTCPPort(h.IP, h.CurrentPort, h.Timeout)

				// 2. Probe target port
				if h.TargetPort == h.CurrentPort {
					tr.TargetPortOpen = tr.Port22Open
				} else {
					tr.TargetPortOpen = TestTCPPort(h.IP, h.TargetPort, h.Timeout)
				}

				// 3. Test Key Auth on whichever port is open
				activePort := h.CurrentPort
				if tr.TargetPortOpen {
					activePort = h.TargetPort
				}

				keyOk, _ := ProbeKeyLogin(h, activePort, h.Timeout)
				tr.KeyAuthWork = keyOk

				// 4. Test Password Auth status
				passAccepted, _ := ProbePasswordLogin(h, activePort, "", h.Timeout)
				tr.PasswordAuthWork = passAccepted

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

				client, err := DialHost(h, h.CurrentPort, false)
				if err != nil {
					res.Error = fmt.Errorf("connect failed: %w", err)
					res.Duration = time.Since(start)
					results[idx] = res
					continue
				}

				if err := client.InjectPublicKey(h.IdentityFile); err != nil {
					_ = client.Close()
					res.Error = fmt.Errorf("inject key failed: %w", err)
					res.Duration = time.Since(start)
					results[idx] = res
					continue
				}
				_ = client.Close()

				res.KeyPushed = true
				// Test key
				ok, _ := ProbeKeyLogin(h, h.CurrentPort, h.Timeout)
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

	logger.Info("🛡️ 开始对 %d 台主机执行安全加固 (并发: %d)...", len(hosts), concurrency)

	results := make([]*HostResult, len(hosts))
	jobs := make(chan int, len(hosts))
	var wg sync.WaitGroup

	for w := 0; w < concurrency; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for idx := range jobs {
				h := hosts[idx]
				if overridePort > 0 {
					h.TargetPort = overridePort
				}
				if disablePassword {
					h.DisablePasswordAuth = true
				}

				start := time.Now()
				res := &HostResult{
					Host:        h,
					InitialPort: h.CurrentPort,
					FinalPort:   h.CurrentPort,
					Status:      StatusFailed,
				}

				// Must connect with key
				client, err := DialHost(h, h.CurrentPort, true)
				if err != nil {
					res.Error = fmt.Errorf("connect with key on port %d failed: %w", h.CurrentPort, err)
					res.Duration = time.Since(start)
					results[idx] = res
					continue
				}
				defer client.Close()

				res.KeyVerified = true
				fw := NewFirewallManager(client)
				harden := NewSshdHarden(client)

				if h.TargetPort != h.CurrentPort {
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

				if err := harden.FinalizeHardening(h.TargetPort, h.DisablePasswordAuth); err != nil {
					res.Error = fmt.Errorf("finalize hardening failed: %w", err)
					res.Duration = time.Since(start)
					results[idx] = res
					continue
				}

				if h.TargetPort != h.CurrentPort && h.ManageFirewall {
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
			if res.Status == StatusSuccess {
				successHosts = append(successHosts, res.Host)
			}
		}
		if len(successHosts) > 0 {
			cfgMgr := NewLocalConfigManager("")
			_ = cfgMgr.SyncHosts(successHosts)
			for _, res := range results {
				if res.Status == StatusSuccess {
					res.ConfigUpdated = true
				}
			}
		}
	}

	return results
}

package osutil

import (
	"fmt"
	"singctl/internal/logger"
	"strings"
)

// OpenWrtManager implements ServiceManager for OpenWrt using init.d
type OpenWrtManager struct{}

func (s *OpenWrtManager) Start(servicePath string) error {
	return RunCommand(servicePath, "start")
}

func (s *OpenWrtManager) Stop(servicePath string) error {
	return RunCommand(servicePath, "stop")
}

func (s *OpenWrtManager) Restart(servicePath string) error {
	return RunCommand(servicePath, "restart")
}

func (s *OpenWrtManager) Enable(servicePath string) error {
	return RunCommand(servicePath, "enable")
}

func (s *OpenWrtManager) Disable(servicePath string) error {
	return RunCommand(servicePath, "disable")
}

func (s *OpenWrtManager) DaemonReload() error {
	// Usually not strictly needed for init.d scripts unless reloading procd
	return RunCommand("/sbin/procd", "reload_config")
}

func (s *OpenWrtManager) IsRunning(servicePath string) (bool, error) {
	// Checking if procd knows about it or checking status
	err := RunCommand(servicePath, "status")
	if err != nil {
		return false, nil
	}
	return true, nil
}

// UciSet safely sets a UCI configuration value.
// It forms the standard `uci set config.section.option=value` command.
func UciSet(config, section, option, value string) error {
	target := fmt.Sprintf("%s.%s", config, section)
	if option != "" {
		target = fmt.Sprintf("%s.%s", target, option)
	}
	if value != "" {
		target = fmt.Sprintf("%s=%s", target, value)
	}

	return RunCommand("uci", "set", target)
}

// UciCommit commits the specified UCI configuration.
func UciCommit(config string) error {
	return RunCommand("uci", "commit", config)
}

// UciDelete safely deletes a UCI configuration element.
func UciDelete(config, section, option string) error {
	target := fmt.Sprintf("%s.%s", config, section)
	if option != "" {
		target = fmt.Sprintf("%s.%s", target, option)
	}
	return RunCommand("uci", "delete", target)
}

// UciDeleteAnonymous removes all anonymous sections matching a specific key-value pair.
func UciDeleteAnonymous(config, sectionType, key, value string) {
	// uci show <config> 输出所有配置；逐行找匿名 section 中匹配的条目
	out, err := RunCommandWithOutput("uci", "show", config)
	if err != nil {
		return
	}

	targetPrefix := config + ".@" + sectionType + "["
	matchSuffix := "." + key + "='" + value + "'"

	indexSet := map[int]struct{}{}
	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		if !strings.HasPrefix(line, targetPrefix) {
			continue
		}
		if !strings.HasSuffix(strings.TrimRight(line, "\r"), matchSuffix) {
			continue
		}
		// 解析 index：firewall.@zone[2].name=... → 2
		rest := strings.TrimPrefix(line, targetPrefix)
		closeBracket := strings.Index(rest, "]")
		if closeBracket < 0 {
			continue
		}
		var idx int
		if _, err := fmt.Sscanf(rest[:closeBracket], "%d", &idx); err == nil {
			indexSet[idx] = struct{}{}
		}
	}

	// 倒序删除，防止删除后 index 错位
	indices := make([]int, 0, len(indexSet))
	for idx := range indexSet {
		indices = append(indices, idx)
	}
	// 简单冒泡降序
	for i := 0; i < len(indices); i++ {
		for j := i + 1; j < len(indices); j++ {
			if indices[j] > indices[i] {
				indices[i], indices[j] = indices[j], indices[i]
			}
		}
	}

	for _, idx := range indices {
		section := fmt.Sprintf("%s.@%s[%d]", config, sectionType, idx)
		_ = RunCommand("uci", "delete", section)
		logger.Info("Removed duplicate anonymous section: %s", section)
	}
	if len(indices) > 0 {
		_ = UciCommit(config)
	}
}

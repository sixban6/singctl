// 文件职责：SingCtl 单二进制极薄启动入口，负责本地时区校准与委托 internal/cmd 执行。
package main

import (
	"os"

	"singctl/internal/cmd"
	"singctl/internal/common/sysinfo"
	"singctl/internal/logger"
)

var (
	Version   = "dev"
	BuildTime = "unknown"
	GitCommit = "unknown"
)

func init() {
	sysinfo.InitLocalTimezone()
}

func main() {
	if err := cmd.Execute(cmd.BuildInfo{
		Version:   Version,
		BuildTime: BuildTime,
		GitCommit: GitCommit,
	}); err != nil {
		logger.Error("Command execution failed: %v", err)
		os.Exit(1)
	}
}

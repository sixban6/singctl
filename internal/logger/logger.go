package logger

import (
	"log"
	"os"
)

const (
	ColorReset  = "\033[0m"
	ColorCyan   = "\033[0;36m" // 青色 - 一般信息
	ColorRed    = "\033[0;31m" // 红色 - 错误信息
	ColorYellow = "\033[0;33m" // 黄色 - 警告信息
)

var (
	// 标准输出logger - 用于INFO级别
	infoLogger = log.New(os.Stdout, "", log.LstdFlags)
	// 错误输出logger - 用于ERROR和WARN级别
	errorLogger = log.New(os.Stderr, "", log.LstdFlags)
)

// Info 输出信息级别日志到stdout
func Info(format string, v ...interface{}) {
	infoLogger.Printf("%s[INFO] "+format+"%s", append([]interface{}{ColorCyan}, append(v, ColorReset)...)...)
}

// Error 输出错误级别日志到stderr
func Error(format string, v ...interface{}) {
	errorLogger.Printf("%s[ERROR] "+format+"%s", append([]interface{}{ColorRed}, append(v, ColorReset)...)...)
}

// Warn 输出警告级别日志到stderr
func Warn(format string, v ...interface{}) {
	errorLogger.Printf("%s[WARN] "+format+"%s", append([]interface{}{ColorYellow}, append(v, ColorReset)...)...)
}

// Success 输出成功信息（用绿色）
func Success(format string, v ...interface{}) {
	infoLogger.Printf("\033[0;32m[SUCCESS] "+format+"%s", append(v, ColorReset)...)
}
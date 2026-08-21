package logger

import (
	"fmt"
	"io"
	"log"
	"os"
	"sync"
)

const (
	ColorReset  = "\033[0m"
	ColorCyan   = "\033[0;36m" // 青色 - 一般信息
	ColorRed    = "\033[0;31m" // 红色 - 错误信息
	ColorYellow = "\033[0;33m" // 黄色 - 警告信息
	ColorGreen  = "\033[0;32m" // 绿色 - 成功信息
)

var (
	// 标准输出logger - 用于INFO级别
	infoLogger = log.New(os.Stdout, "", log.LstdFlags)
	// 错误输出logger - 用于ERROR和WARN级别
	errorLogger = log.New(os.Stderr, "", log.LstdFlags)

	mu           sync.Mutex
	colorEnabled = true
)

// SetOutput 将所有内部 logger 的输出重定向到 w。
// 注意:log.SetOutput 对本包无效,因为这里持有私有的 *log.Logger 实例,
// 守护进程等需要落盘日志的场景必须调用本函数。
func SetOutput(w io.Writer) {
	mu.Lock()
	defer mu.Unlock()
	infoLogger.SetOutput(w)
	errorLogger.SetOutput(w)
}

// SetColor 开关 ANSI 颜色输出。输出重定向到文件时应关闭,
// 避免日志文件中出现转义序列。
func SetColor(enabled bool) {
	mu.Lock()
	defer mu.Unlock()
	colorEnabled = enabled
}

// wrap 按需包裹颜色与格式化后的消息
func wrap(color, prefix, format string, v ...interface{}) string {
	msg := prefix + fmt.Sprintf(format, v...)
	if colorEnabled {
		return color + msg + ColorReset
	}
	return msg
}

// Info 输出信息级别日志到stdout
func Info(format string, v ...interface{}) {
	infoLogger.Print(wrap(ColorCyan, "[INFO] ", format, v...))
}

// Error 输出错误级别日志到stderr
func Error(format string, v ...interface{}) {
	errorLogger.Print(wrap(ColorRed, "[ERROR] ", format, v...))
}

// Warn 输出警告级别日志到stderr
func Warn(format string, v ...interface{}) {
	errorLogger.Print(wrap(ColorYellow, "[WARN] ", format, v...))
}

// Success 输出成功信息（用绿色）
func Success(format string, v ...interface{}) {
	infoLogger.Print(wrap(ColorGreen, "[SUCCESS] ", format, v...))
}

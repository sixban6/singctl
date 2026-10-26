package gfw

import (
	"context"
	"crypto/rand"
	"fmt"
	"net"
	"strings"
	"time"
)

// probeEntropy 执行高熵随机垃圾数据探测（满分 20 分 - GFW 核心 Active Probing 手段）
func probeEntropy(ctx context.Context, opts ProbeOptions) Category {
	cat := Category{
		Name:     "高熵随机垃圾数据探测 (GFW Active Probing)",
		MaxScore: 20,
		Items:    make([]CheckItem, 0),
	}

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	// 1. 发送 64 字节高熵随机数据并测量挂起超时时间
	itemEntropy := CheckItem{
		Name:        "高熵未知随机数据包注入测试",
		Description: "模拟 GFW 主动探测器注入 64 字节加密随机数据，观测服务端超时与断开行为",
		MaxScore:    20,
	}

	duration, responseBytes, err := testEntropyPayload(opts.IP, 64, timeout)
	if err != nil {
		// 读取超时或连接重置
		if strings.Contains(err.Error(), "i/o timeout") {
			itemEntropy.Score = 20
			itemEntropy.Passed = false
			itemEntropy.Details = fmt.Sprintf("服务端在接收随机二进制数据后处于挂起等待状态 (超时耗时: %v)！这是翻墙协议等待客户端认证的典型翻墙特征！", duration)
			itemEntropy.Mitigation = "优化前端伪装回落，配置 Web 服务器在收到非 HTTP/TLS 数据时立即关闭连接 (ReadTimeout < 1s) 或快速返回 HTTP 400。"
		} else if duration > 2*time.Second {
			itemEntropy.Score = 15
			itemEntropy.Passed = false
			itemEntropy.Details = fmt.Sprintf("服务端挂起长达 %v 后异常断开，具备高可疑度的代理服务端特征。", duration)
			itemEntropy.Mitigation = "配置激进的空闲读取超时 (ReadHeaderTimeout)，防止主动探测器利用等待时长对节点进行行为画像。"
		} else {
			// 短时间内被重置（< 2s），分析是否有明确响应
			if len(responseBytes) > 0 && strings.Contains(string(responseBytes), "400") {
				itemEntropy.Score = 0
				itemEntropy.Passed = true
				itemEntropy.Details = fmt.Sprintf("服务端在 %v 内快速响应了 HTTP 400 Bad Request 并断开，表现与正规 Web 服务器完全一致。", duration)
			} else {
				// 快速 RST / FIN 断开（对齐主流 Web 基础设施如 Apple/Microsoft/Baidu 在处理非法握手时的行为）
				itemEntropy.Score = 0
				itemEntropy.Passed = true
				itemEntropy.Details = fmt.Sprintf("服务端在 %v 内快速拒绝并关闭连接 (TCP RST/FIN)，无挂起等待翻墙认证特征，表现符合现代标准 TLS 协议栈规范。", duration)
			}
		}
	} else {
		// 服务端返回了数据
		respStr := string(responseBytes)
		if strings.Contains(respStr, "400 Bad Request") || (len(responseBytes) >= 2 && responseBytes[0] == 0x15) {
			itemEntropy.Score = 0
			itemEntropy.Passed = true
			itemEntropy.Details = fmt.Sprintf("服务端反应迅速 (%v)，正确返回标准错误报文 (响应长度: %d 字节)", duration, len(responseBytes))
		} else {
			itemEntropy.Score = 10
			itemEntropy.Passed = false
			itemEntropy.Details = fmt.Sprintf("服务端返回了未知数据 (响应首字节: 0x%02x, 长度: %d 字节)", responseBytes[0], len(responseBytes))
			itemEntropy.Mitigation = "检查端口转发与回落逻辑，避免将未知数据流转发至代理后端产生异常回声。"
		}
	}
	cat.Items = append(cat.Items, itemEntropy)

	// 统计当前分类总分
	for _, it := range cat.Items {
		cat.Score += it.Score
	}
	if cat.Score > cat.MaxScore {
		cat.Score = cat.MaxScore
	}

	return cat
}

func testEntropyPayload(ip string, payloadLen int, timeout time.Duration) (time.Duration, []byte, error) {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, "443"), 3*time.Second)
	if err != nil {
		return 0, nil, err
	}
	defer conn.Close()

	payload := make([]byte, payloadLen)
	_, _ = rand.Read(payload)

	// 设置探测超时
	_ = conn.SetDeadline(time.Now().Add(timeout))

	start := time.Now()
	if _, err := conn.Write(payload); err != nil {
		return time.Since(start), nil, err
	}

	buf := make([]byte, 1024)
	n, readErr := conn.Read(buf)
	duration := time.Since(start)

	if readErr != nil {
		return duration, buf[:n], readErr
	}

	return duration, buf[:n], nil
}

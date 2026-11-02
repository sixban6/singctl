package terminalqr

import (
	"strings"

	"github.com/skip2/go-qrcode"
)

// RenderString 将文本编码为高密度终端 ASCII 二维码（双行半块合一渲染）
// 适合在各种终端终端界面、SSH 会话中输出，手机相机和客户端等客户端可即刻扫码导入
func RenderString(content string) (string, error) {
	qr, err := qrcode.New(content, qrcode.Medium)
	if err != nil {
		return "", err
	}

	bitmap := qr.Bitmap()
	if len(bitmap) == 0 {
		return "", nil
	}

	// 边框留白 (Quiet Zone): 1 块
	border := 1
	origWidth := len(bitmap)
	width := origWidth + border*2
	height := len(bitmap[0]) + border*2

	// 构造带留白的二维 bool 矩阵 (true=黑色, false=白色)
	grid := make([][]bool, height)
	for y := 0; y < height; y++ {
		grid[y] = make([]bool, width)
		for x := 0; x < width; x++ {
			origX := x - border
			origY := y - border
			if origX >= 0 && origX < origWidth && origY >= 0 && origY < origWidth {
				grid[y][x] = bitmap[origX][origY]
			}
		}
	}

	var sb strings.Builder

	// 双行合一：每两行用半高字符渲染：
	// 顶部黑色, 底部白色: ▀
	// 顶部白色, 底部黑色: ▄
	// 顶部黑色, 底部黑色: █
	// 顶部白色, 底部白色: ' '
	// 终端背景一般为深色，所以：
	// 黑色像素显示反色(白字背景)或直接用统一的前景/背景色
	// 为获得在深色/浅色终端均有最高对比度的效果，使用标准的白色反色输出：
	for y := 0; y < height; y += 2 {
		sb.WriteString("  ") // 左边距
		for x := 0; x < width; x++ {
			top := grid[y][x]
			bottom := false
			if y+1 < height {
				bottom = grid[y+1][x]
			}

			// 深色终端下，白色字符为前景色，黑色为背景
			// top=true (黑块), bottom=true (黑块) -> 反色空格
			switch {
			case top && bottom:
				sb.WriteString("\033[7m \033[0m") // 全黑（反色空格）
			case top && !bottom:
				sb.WriteString("▀") // 上黑下白
			case !top && bottom:
				sb.WriteString("▄") // 上白下黑
			default:
				sb.WriteString(" ") // 全白
			}
		}
		sb.WriteString("\n")
	}

	return sb.String(), nil
}

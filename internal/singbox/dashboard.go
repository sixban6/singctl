package singbox

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	log "singctl/internal/logger"
)

// ProvisionDashboard 检查配置中的 api dashboard 设置, 若本地静态文件未就绪
// 则预下载并解压到 dashboard.path。
//
// 背景: sing-box 1.14.0 的 http_client 对"detour 指向空 direct 出站"校验过严,
// dashboard 自带下载器必然失败("detour to an empty direct outbound makes no
// sense"); singctl 在生成配置阶段代为下载, 彻底绕过该问题。
// 幂等: path/index.html 已存在时跳过。
func ProvisionDashboard(configJSON string) error {
	var cfg struct {
		Services []struct {
			Type      string `json:"type"`
			Dashboard struct {
				Enabled     bool   `json:"enabled"`
				Path        string `json:"path"`
				DownloadURL string `json:"download_url"`
			} `json:"dashboard"`
		} `json:"services"`
	}
	if err := json.Unmarshal([]byte(configJSON), &cfg); err != nil {
		return fmt.Errorf("dashboard provision: invalid JSON: %w", err)
	}

	for _, svc := range cfg.Services {
		if svc.Type != "api" || !svc.Dashboard.Enabled {
			continue
		}
		if svc.Dashboard.Path == "" || svc.Dashboard.DownloadURL == "" {
			return nil
		}
		index := filepath.Join(svc.Dashboard.Path, "index.html")
		if _, err := os.Stat(index); err == nil {
			return nil // 已就绪
		}

		log.Info("正在预下载 Dashboard 静态面板文件至 %s ...", svc.Dashboard.Path)

		client := &http.Client{
			Timeout: 15 * time.Second,
			Transport: &http.Transport{
				DialContext: (&net.Dialer{
					Timeout: 5 * time.Second,
				}).DialContext,
				TLSHandshakeTimeout:   5 * time.Second,
				ResponseHeaderTimeout: 8 * time.Second,
			},
		}

		candidates := dashboardDownloadCandidates(svc.Dashboard.DownloadURL)
		var lastErr error
		for _, u := range candidates {
			data, err := downloadDashboardArchive(client, u)
			if err != nil {
				lastErr = err
				continue
			}
			if err := extractDashboardZip(data, svc.Dashboard.Path); err != nil {
				lastErr = err
				continue
			}
			return nil
		}
		return fmt.Errorf("dashboard provision: %w", lastErr)
	}
	return nil
}

func dashboardDownloadCandidates(rawURL string) []string {
	var out []string
	out = append(out, rawURL)
	// 若配置了镜像前缀 (如 https://mirror.example/https://github.com/...)，追加直连候选兜底
	if idx := strings.Index(rawURL, "/https://github.com/"); idx > 0 {
		direct := rawURL[idx+1:]
		if direct != rawURL {
			out = append(out, direct)
		}
	}
	return out
}

func downloadDashboardArchive(client *http.Client, url string) ([]byte, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "singctl-dashboard-provisioner")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("download: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download failed: HTTP %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}
	return data, nil
}

// extractDashboardZip 解压 dashboard zip 到 dir, 自动剥掉 GitHub archive 的
// 单一顶层目录(如 sing-box-dashboard-gh-pages/), 并防御 zip-slip 路径穿越。
func extractDashboardZip(data []byte, dir string) error {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return fmt.Errorf("invalid zip: %w", err)
	}

	prefix := ""
	for _, f := range zr.File {
		parts := strings.SplitN(filepath.ToSlash(f.Name), "/", 2)
		if len(parts) < 2 {
			prefix = "" // 顶层存在文件, 无需剥离目录
			break
		}
		if prefix == "" {
			prefix = parts[0] + "/"
		} else if prefix != parts[0]+"/" {
			prefix = ""
			break
		}
	}

	for _, f := range zr.File {
		name := strings.TrimPrefix(filepath.ToSlash(f.Name), prefix)
		rel := strings.TrimPrefix(filepath.Clean("/"+name), "/")
		if rel == "" || rel == "." {
			continue
		}
		if strings.HasPrefix(rel, "..") {
			continue // zip-slip 防御
		}
		target := filepath.Join(dir, rel)
		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		rc, err := f.Open()
		if err != nil {
			return err
		}
		out, err := os.OpenFile(target, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
		if err != nil {
			rc.Close()
			return err
		}
		_, err = io.Copy(out, rc)
		rc.Close()
		out.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

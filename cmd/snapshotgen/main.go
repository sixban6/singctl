// snapshotgen 内置规则集快照生成器（开发工具，不参与产品发布构建）。
//
// 用法:
//
//	go run ./cmd/snapshotgen [-mirror https://gh-proxy.com]
//
// 从 GitHub 下载 snapshotItems 列出的规则集（直连优先，失败回退镜像），
// gzip 压缩后写入 internal/singbox/ruleset_snapshot/assets/，并生成
// manifest.json（记录规范 URL、原始内容 sha256/size）。之后重新编译
// singctl，快照即通过 go:embed 打包进二进制，作为"网络不可用且无本地
// 缓存"时的最终兜底。
//
// 更新快照的时机：规则集列表变更、或距离上次快照时间过久时由维护者
// 手动执行并提交。
package main

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type snapshotItem struct {
	Tag    string // sing-box rule_set tag
	URL    string // 规范直连 URL（不含镜像前缀）
	Format string // binary | source
}

// snapshotItems 内置快照清单。与 singctl.yaml 模板中的 rule_set 列表对应，
// URL 为剥离 {mirror_url} 前缀后的规范地址。
var snapshotItems = []snapshotItem{
	// ── MetaCubeX meta-rules-dat geosite ──
	{"geosite-bank-cn", "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/category-bank-cn.srs", "binary"},
	{"geosite-chat", "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/category-ai-chat-!cn.srs", "binary"},
	{"geosite-steam", "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/steam.srs", "binary"},
	{"geosite-epic", "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/epicgames.srs", "binary"},
	{"geosite-playstation", "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/sony.srs", "binary"},
	{"geosite-xbox", "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/xbox.srs", "binary"},
	{"geosite-disney", "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/disney.srs", "binary"},
	{"geosite-hbo", "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/hbo.srs", "binary"},
	{"geosite-primevideo", "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/primevideo.srs", "binary"},
	{"geosite-spotify", "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/spotify.srs", "binary"},
	{"geosite-youtube", "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/youtube.srs", "binary"},
	{"geosite-google", "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/google.srs", "binary"},
	{"geosite-github", "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/github.srs", "binary"},
	{"geosite-telegram", "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/telegram.srs", "binary"},
	{"geosite-tiktok", "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/tiktok.srs", "binary"},
	{"geosite-netflix", "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/netflix.srs", "binary"},
	{"geosite-apple", "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/apple.srs", "binary"},
	{"geosite-microsoft", "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/microsoft.srs", "binary"},
	{"geosite-onedrive", "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/onedrive.srs", "binary"},
	{"geosite-geolocation-!cn", "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/geolocation-!cn.srs", "binary"},
	{"geosite-cn", "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/cn.srs", "binary"},
	{"geosite-private", "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/private.srs", "binary"},
	{"geosite-paypal", "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/paypal.srs", "binary"},
	{"geosite-cryptocurrency", "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/category-cryptocurrency.srs", "binary"},
	{"geosite-jd", "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/jd.srs", "binary"},
	{"geosite-ali", "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/alibaba.srs", "binary"},
	{"geosite-baidu", "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/baidu.srs", "binary"},
	{"geosite-bytedance", "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/bytedance.srs", "binary"},
	{"geosite-pdd", "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/pinduoduo.srs", "binary"},
	{"geosite-bili", "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/bilibili.srs", "binary"},
	{"geosite-meituan", "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/meituan.srs", "binary"},
	{"geosite-ctrip", "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/ctrip.srs", "binary"},
	{"geosite-tencent", "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/tencent.srs", "binary"},
	{"geosite-porn", "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/category-porn.srs", "binary"},
	{"geosite-sourcehut", "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/sourcehut.srs", "binary"},
	{"geosite-x", "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/x.srs", "binary"},
	// ── MetaCubeX meta-rules-dat geoip ──
	{"geoip-google", "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geoip/google.srs", "binary"},
	{"geoip-telegram", "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geoip/telegram.srs", "binary"},
	{"geoip-netflix", "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geoip/netflix.srs", "binary"},
	{"geoip-apple", "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo-lite/geoip/apple.srs", "binary"},
	{"geoip-cn", "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geoip/cn.srs", "binary"},
	{"geoip-private", "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geoip/private.srs", "binary"},
	// ── 第三方维护源 ──
	{"geosite-ad1", "https://github.com/Toperlock/sing-box-geosite/raw/main/rule/adservers.srs", "binary"},
	{"geosite-ad2", "https://raw.githubusercontent.com/privacy-protection-tools/anti-ad.github.io/master/docs/anti-ad-sing-box.srs", "binary"},
	{"geosite-ctm_cn", "https://github.com/sixban6/rulesets/raw/refs/heads/main/rule/direct_cn.srs", "binary"},
	{"geosite-hok", "https://github.com/sixban6/rulesets/raw/refs/heads/main/rule/hok.srs", "binary"},
}

const (
	// sing-box 二进制规则集魔数：
	//   旧格式 (sing-box < 1.12): "RULE" + version(1)
	//   新格式 (sing-box >= 1.12): "SRS" + version(2)
	legacyMagic = "RULE"
	srsMagic    = "SRS"
	workers     = 6
	maxSize     = 64 << 20 // 64MB 防御性上限
	retryWait   = time.Second
)

type result struct {
	item  snapshotItem
	data  []byte
	err   error
	retry int
	via   string // direct | mirror
}

func sanitizeTag(tag string) string {
	var b strings.Builder
	for _, r := range tag {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9',
			r == '-', r == '_', r == '.':
			b.WriteRune(r)
		default:
			b.WriteRune('_')
		}
	}
	if b.Len() == 0 {
		return "ruleset"
	}
	return b.String()
}

func fileName(item snapshotItem) string {
	if item.Format == "source" {
		return sanitizeTag(item.Tag) + ".json.gz"
	}
	return sanitizeTag(item.Tag) + ".srs.gz"
}

// validate 校验下载内容确实是规则集，防止把错误页缓存下来。
func validate(data []byte, format string) error {
	if len(data) == 0 {
		return fmt.Errorf("empty content")
	}
	if format == "source" {
		if !json.Valid(data) {
			return fmt.Errorf("invalid source-format rule set (not JSON)")
		}
		return nil
	}
	if !bytes.HasPrefix(data, []byte(srsMagic)) && !bytes.HasPrefix(data, []byte(legacyMagic)) {
		return fmt.Errorf("invalid binary rule set (missing %q/%q magic)", srsMagic, legacyMagic)
	}
	return nil
}

func fetch(client *http.Client, url string) ([]byte, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "singctl-snapshotgen")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxSize+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxSize {
		return nil, fmt.Errorf("content exceeds %d bytes", maxSize)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return body, nil
}

func candidates(url, mirror string) []string {
	var out []string
	seen := map[string]bool{}
	add := func(u string) {
		if u != "" && !seen[u] {
			seen[u] = true
			out = append(out, u)
		}
	}
	add(url)
	trimmed := strings.TrimSuffix(mirror, "/")
	if trimmed != "" {
		add(trimmed + "/" + url)
	}
	return out
}

func main() {
	mirror := flag.String("mirror", "", "镜像前缀（默认空：只用直连；仅当直连不可用时手动指定）")
	outDir := flag.String("out", "internal/singbox/ruleset_snapshot/assets", "快照输出目录")
	timeout := flag.Duration("timeout", 90*time.Second, "单个下载超时")
	retries := flag.Int("retries", 3, "每个候选地址的重试次数")
	flag.Parse()

	if err := os.MkdirAll(*outDir, 0755); err != nil {
		fatal("create out dir: %v", err)
	}
	// 清理旧快照，避免残留已从清单移除的条目
	entries, _ := os.ReadDir(*outDir)
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if strings.HasSuffix(name, ".srs.gz") || strings.HasSuffix(name, ".json.gz") ||
			name == "manifest.json" || name == ".gitkeep" {
			_ = os.Remove(filepath.Join(*outDir, name))
		}
	}

	client := &http.Client{Timeout: *timeout}
	results := make([]result, len(snapshotItems))

	var wg sync.WaitGroup
	sem := make(chan struct{}, workers)
	for i, item := range snapshotItems {
		wg.Add(1)
		go func(i int, item snapshotItem) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			r := result{item: item}
			for attempt, cand := range candidates(item.URL, *mirror) {
				via := "direct"
				if attempt > 0 {
					via = "mirror"
				}
				for try := 1; try <= *retries; try++ {
					data, err := fetch(client, cand)
					if err == nil {
						if err := validate(data, item.Format); err != nil {
							r.err = fmt.Errorf("%s: %w", cand, err)
							break // 内容非法，换下一个候选地址
						}
						r.data, r.err, r.via, r.retry = data, nil, via, try
						results[i] = r
						return
					}
					r.err = fmt.Errorf("%s: %w", cand, err)
					time.Sleep(retryWait * time.Duration(try))
				}
			}
			results[i] = r
		}(i, item)
	}
	wg.Wait()

	type manifestEntry struct {
		URL       string `json:"url"`
		Format    string `json:"format"`
		File      string `json:"file"`
		SHA256    string `json:"sha256"`
		Size      int64  `json:"size"`
		Via       string `json:"via,omitempty"`
		UpdatedAt string `json:"updated_at"`
	}
	manifest := struct {
		GeneratedAt string                   `json:"generated_at"`
		Count       int                      `json:"count"`
		Entries     map[string]manifestEntry `json:"entries"`
	}{
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Entries:     map[string]manifestEntry{},
	}

	var rawTotal, gzTotal int64
	var failed []string
	for _, r := range results {
		if r.err != nil {
			failed = append(failed, fmt.Sprintf("  ✗ %-28s %v", r.item.Tag, r.err))
			continue
		}

		sum := sha256.Sum256(r.data)
		var buf bytes.Buffer
		zw, _ := gzip.NewWriterLevel(&buf, gzip.BestCompression)
		if _, err := zw.Write(r.data); err != nil {
			fatal("gzip %s: %v", r.item.Tag, err)
		}
		if err := zw.Close(); err != nil {
			fatal("gzip %s: %v", r.item.Tag, err)
		}

		name := fileName(r.item)
		path := filepath.Join(*outDir, name)
		tmp := path + ".tmp"
		if err := os.WriteFile(tmp, buf.Bytes(), 0644); err != nil {
			fatal("write %s: %v", path, err)
		}
		if err := os.Rename(tmp, path); err != nil {
			fatal("rename %s: %v", path, err)
		}

		rawTotal += int64(len(r.data))
		gzTotal += int64(buf.Len())
		manifest.Entries[r.item.Tag] = manifestEntry{
			URL:       r.item.URL,
			Format:    r.item.Format,
			File:      name,
			SHA256:    hex.EncodeToString(sum[:]),
			Size:      int64(len(r.data)),
			Via:       r.via,
			UpdatedAt: time.Now().UTC().Format(time.RFC3339),
		}
		fmt.Printf("  ✓ %-28s %8d → %7d bytes  (%s)\n",
			r.item.Tag, len(r.data), buf.Len(), r.via)
	}
	manifest.Count = len(manifest.Entries)

	if len(failed) > 0 {
		fmt.Println("下载失败的规则集:")
		for _, f := range failed {
			fmt.Println(f)
		}
		fatal("%d/%d 个规则集下载失败，快照未生成（请重试）", len(failed), len(snapshotItems))
	}

	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		fatal("marshal manifest: %v", err)
	}
	if err := os.WriteFile(filepath.Join(*outDir, "manifest.json"), data, 0644); err != nil {
		fatal("write manifest: %v", err)
	}

	fmt.Printf("\n快照生成完成: %d 个规则集 → %s\n", manifest.Count, *outDir)
	fmt.Printf("原始总大小: %s, 压缩后: %s ( %.1f%% )\n",
		humanSize(rawTotal), humanSize(gzTotal), float64(gzTotal)/float64(rawTotal)*100)
	fmt.Println("请重新编译 singctl 使快照生效，并提交 assets/ 目录。")
}

func humanSize(n int64) string {
	switch {
	case n >= 1<<20:
		return fmt.Sprintf("%.1fMB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1fKB", float64(n)/(1<<10))
	default:
		return fmt.Sprintf("%dB", n)
	}
}

func fatal(format string, v ...any) {
	fmt.Fprintf(os.Stderr, "snapshotgen: "+format+"\n", v...)
	os.Exit(1)
}

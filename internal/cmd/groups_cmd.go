package cmd

import (
	"cmp"
	"fmt"
	"os"
	"strings"

	"singctl/configs"
	"singctl/internal/config"
	"singctl/internal/constant"
	"singctl/internal/daemon"
	"singctl/internal/logger"
	"singctl/internal/singbox"

	"github.com/spf13/cobra"
)

func newGroupsCmd(defaultConfigPath string) *cobra.Command {
	var customFile string
	cmd := &cobra.Command{
		Use:   "groups",
		Short: "管理与预览声明式策略组配置 (groups.yaml) / Manage declarative outbound groups",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runGroupsPreview(cmd, defaultConfigPath, customFile)
		},
	}
	cmd.Flags().StringVarP(&customFile, "file", "f", "", "指定预览的 groups.yaml 文件路径（默认读取 singctl.yaml 同目录下的 groups.yaml）")

	var previewFile string
	previewCmd := &cobra.Command{
		Use:   "preview",
		Short: "干跑预览 groups.yaml 在当前节点池下的分组命中结果 / Dry-run preview group node matches",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runGroupsPreview(cmd, defaultConfigPath, previewFile)
		},
	}
	previewCmd.Flags().StringVarP(&previewFile, "file", "f", "", "指定预览的 groups.yaml 文件路径")

	var forceInit bool
	initCmd := &cobra.Command{
		Use:   "init",
		Short: "生成带注释示例的默认 groups.yaml 模板 / Initialize starter groups.yaml",
		RunE: func(cmd *cobra.Command, _ []string) error {
			resolvedCfgPath := resolveCmdConfigPath(cmd, defaultConfigPath)
			gPath := config.GroupsPathForConfig(resolvedCfgPath)
			if !forceInit {
				if _, err := os.Stat(gPath); err == nil {
					logger.Info("groups.yaml 已存在: %s（如需覆盖重置请添加 --force）", gPath)
					return nil
				}
			}
			if _, err := config.SaveGroupsFile(gPath, configs.DefaultGroupsYAML); err != nil {
				return err
			}
			logger.Success("已初始化声明式分组配置模板 (0600): %s", gPath)
			return nil
		},
	}
	initCmd.Flags().BoolVar(&forceInit, "force", false, "强制覆盖已存在的 groups.yaml")

	applyCmd := &cobra.Command{
		Use:   "apply",
		Short: "校验 groups.yaml 并无损热更新至运行中的 sing-box / Validate and hot-apply groups.yaml",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, resolvedCfgPath, err := loadCmdConfig(cmd, defaultConfigPath)
			if err != nil {
				return err
			}
			gPath := config.GroupsPathForConfig(resolvedCfgPath)
			gc, exists, err := config.LoadGroupsFile(gPath)
			if err != nil {
				return err
			}
			if !exists {
				logger.Warn("未找到 %s，可执行 `singctl sb groups init` 创建模板", gPath)
				return nil
			}

			rawSB, sbErr := os.ReadFile(constant.SingBoxConfigFile)
			if sbErr != nil || strings.TrimSpace(string(rawSB)) == "" {
				return fmt.Errorf("未读取到现有 %s，请先执行 `singctl sb gen` 或 `singctl sb start`", constant.SingBoxConfigFile)
			}

			updatedJSON, report, err := singbox.RecompileLiveConfigWithGroups(string(rawSB), cfg, gc, "")
			if err != nil {
				return err
			}
			if err := singbox.ApplyLiveSingBoxConfig(cmd.Context(), constant.SingBoxConfigFile, constant.SingBoxWorkConfigFile, updatedJSON, "groups"); err != nil {
				return err
			}
			if baseRaw, bErr := singbox.LoadBaseSnapshot(constant.SingBoxConfigFile); bErr == nil && strings.TrimSpace(baseRaw) != "" {
				if updatedBase, _, uErr := singbox.RecompileLiveConfigWithGroups(baseRaw, cfg, gc, ""); uErr == nil {
					_ = singbox.SaveBaseSnapshot(constant.SingBoxConfigFile, updatedBase)
				}
			}
			_ = daemon.NotifyReload()
			printGroupsPreviewReport(gPath, true, report)
			logger.Success("groups.yaml 已通过 sing-box check 并无损热重载生效")
			return nil
		},
	}

	cmd.AddCommand(previewCmd, initCmd, applyCmd)
	return cmd
}

func runGroupsPreview(cmd *cobra.Command, defaultConfigPath, overrideGroupFile string) error {
	cfg, resolvedCfgPath, err := loadCmdConfig(cmd, defaultConfigPath)
	if err != nil {
		cfg = &config.Config{}
	}
	gPath := strings.TrimSpace(overrideGroupFile)
	if gPath == "" {
		gPath = config.GroupsPathForConfig(resolvedCfgPath)
	}

	gc, exists, err := config.LoadGroupsFile(gPath)
	if err != nil {
		return err
	}

	rawSBBytes, sbErr := os.ReadFile(constant.SingBoxConfigFile)
	rawSB := string(rawSBBytes)
	if sbErr != nil || strings.TrimSpace(rawSB) == "" {
		if cfg == nil || len(cfg.Subs) == 0 {
			return fmt.Errorf("本地尚无 %s 且未配置订阅，无法预览节点命中", constant.SingBoxConfigFile)
		}
		gen := singbox.NewConfigGenerator(cfg)
		gen.SetSilent(true)
		generated, gErr := gen.Generate()
		if gErr != nil {
			return fmt.Errorf("拉取订阅生成预览基线失败: %w", gErr)
		}
		rawSB = generated
	}

	_, report, err := singbox.RecompileLiveConfigWithGroups(rawSB, cfg, gc, "")
	if err != nil {
		return err
	}
	printGroupsPreviewReport(gPath, exists, report)
	return nil
}

func printGroupsPreviewReport(gPath string, exists bool, report *singbox.GroupsPreviewReport) {
	statusLabel := "已启用"
	if !exists {
		statusLabel = "未创建 (当前展示默认内置分组)"
	}
	logger.Info("配置文件: %s [%s] | 模式: %s | 默认兜底: %s | 海外 DNS: %s | 底层代理节点总数: %d",
		gPath, statusLabel, report.Mode, cmp.Or(report.DefaultOutbound, "Proxy"), cmp.Or(report.DNSDetour, "#VPS"), report.TotalLeafNodes)
	for _, g := range report.Groups {
		role := "自定义"
		if g.Builtin && !g.Customized {
			role = "内置"
		} else if g.Builtin && g.Customized {
			role = "内置·已定制"
		}
		fbMark := ""
		if g.FallbackUsed {
			fbMark = fmt.Sprintf(" [⚠️ 0节点兜底->%s]", g.FallbackTag)
		}
		previewMembers := strings.Join(g.Members, ", ")
		if runes := []rune(previewMembers); len(runes) > 52 {
			previewMembers = string(runes[:52]) + "..."
		}
		logger.Info("  • %-12s (%-8s | %s | 共 %2d 项)%s => [%s]",
			g.Name, g.Type, role, g.TotalCount, fbMark, previewMembers)
	}
	for _, w := range report.Warnings {
		logger.Warn("  ⚠️ %s", w)
	}
}

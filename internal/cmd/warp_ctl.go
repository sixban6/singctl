//go:build !lite

// 文件职责：承载 `singctl sr warp-ctl` 隐藏子命令，委托 internal/deploy 执行本机非交互 WARP JSON RPC 控制。
package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"singctl/internal/deploy"

	"github.com/spf13/cobra"
)

func newServerWarpCtlCmd(configPath string) *cobra.Command {
	var refresh bool
	var query string
	var outbound string
	var actionName string

	cmd := &cobra.Command{
		Use:    "warp-ctl <status|apply|quick-switch|connections|action>",
		Short:  "Internal cluster JSON RPC endpoint for WARP routing control",
		Hidden: true,
		Args:   cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			resolvedPath := resolveConfigPath(cmd, configPath)
			sub := args[0]

			var payload []byte
			switch sub {
			case "status":
				payload, _ = json.Marshal(map[string]any{"refresh": refresh})
			case "connections":
				payload, _ = json.Marshal(map[string]any{"q": query, "outbound": outbound})
			case "action":
				if actionName != "" {
					payload, _ = json.Marshal(map[string]any{"action": actionName})
				} else {
					raw, err := io.ReadAll(os.Stdin)
					if err != nil {
						return err
					}
					payload = raw
				}
			default:
				raw, err := io.ReadAll(os.Stdin)
				if err != nil {
					return err
				}
				payload = raw
			}

			out, err := deploy.ExecuteLocalWarpCLI(cmd.Context(), sub, payload, deploy.LocalWarpCLIOptions{
				ConfigPath: resolvedPath,
			})
			if err != nil {
				return err
			}
			_, err = fmt.Fprintln(os.Stdout, string(out))
			return err
		},
	}

	cmd.Flags().BoolVar(&refresh, "refresh", false, "force refresh WARP exit IP")
	cmd.Flags().StringVar(&query, "q", "", "connection search query")
	cmd.Flags().StringVar(&outbound, "outbound", "all", "outbound filter")
	cmd.Flags().StringVar(&actionName, "name", "", "action name (rekey|ensure|enable_telemetry)")
	return cmd
}

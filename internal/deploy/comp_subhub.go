package deploy

import (
	"context"

	"singctl/internal/component"
	"singctl/internal/platform/servicemgr"
	"singctl/internal/subhub"
)

type subhubServerComponent struct{}

func (*subhubServerComponent) ID() string          { return "subhub" }
func (*subhubServerComponent) Aliases() []string   { return []string{"substore", "sub-store"} }
func (*subhubServerComponent) DisplayName() string { return "SubHub 订阅引擎" }
func (*subhubServerComponent) UnitName() string    { return subhub.ServiceName }

func (s *subhubServerComponent) ExecuteServiceAction(ctx context.Context, action string, mgr servicemgr.Manager, _ servicemgr.CmdRunner, _ string) error {
	if action == "reload" {
		action = "restart"
	}
	return component.DispatchServiceAction(ctx, mgr, action, s.UnitName())
}

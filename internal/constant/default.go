package constant

const (
	// GitHubRepo 与 GitHubRepoURL 定义本项目的官方 GitHub 仓库标识与主页地址，
	// 供自更新、健康体检、安全自愈及统一组件发布通道共享复用。
	GitHubRepo    = "sixban6/singctl"
	GitHubRepoURL = "https://github.com/" + GitHubRepo

	AppName          = "SFM"
	ExitNode         = "exit-node"
	MainRouter       = "router"
	AcceptRoutes     = "accept-routes"
	TailscaleMode    = "mode"
	TailscaleSubnets = "subnets"
)

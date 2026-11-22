package constant

const (
	// GitHubRepo 与 GitHubRepoURL 定义本项目的官方 GitHub 仓库标识与主页地址，
	// 供自更新、健康体检、安全自愈及统一组件发布通道共享复用。
	GitHubRepo    = "sixban6/singctl"
	GitHubRepoURL = "https://github.com/" + GitHubRepo

	// SingBoxLiteReleaseTag 为本仓库独立托管的裁剪版 sing-box 滚动 Prerelease 标签（--latest=false）。
	SingBoxLiteReleaseTag = "singbox-lite-latest"

	AppName          = "SFM"
	ExitNode         = "exit-node"
	MainRouter       = "router"
	AcceptRoutes     = "accept-routes"
	TailscaleMode    = "mode"
	TailscaleSubnets = "subnets"
)

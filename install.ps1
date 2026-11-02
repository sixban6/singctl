#Requires -RunAsAdministrator
<#
.SYNOPSIS
    SingCtl 一键安装脚本（Windows PowerShell 版）
.DESCRIPTION
    功能与官方 install.bat 一致，去除编码/路径/依赖烦恼。
#>

param(
    [switch]$Server,
    [switch]$Client
)

$ErrorActionPreference = 'Stop'
$ProgressPreference    = 'SilentlyContinue'

#--------------------------------------------------
# 配置
$GitHubRepo   = 'sixban6/singctl'
$InstallDir   = "$env:LOCALAPPDATA\Programs\singctl"
$ConfigDir    = "$env:LOCALAPPDATA\singctl"
$ConfigFile   = "$ConfigDir\singctl.yaml"
$TempDir      = "$env:TEMP\singctl-install"

#--------------------------------------------------
# 小工具函数
function Write-Info    { Write-Host "[INFO]    $($args[0])"    -ForegroundColor Cyan }
function Write-Success { Write-Host "[SUCCESS] $($args[0])"    -ForegroundColor Green }
function Write-Warning { Write-Host "[WARNING] $($args[0])"    -ForegroundColor Yellow }
function Write-Error   { Write-Host "[ERROR]   $($args[0])"    -ForegroundColor Red }
function Cleanup {
    if (Test-Path $TempDir) {
        Remove-Item $TempDir -Recurse -Force -ErrorAction SilentlyContinue
        Write-Info "清理临时目录: $TempDir"
    }
}

#--------------------------------------------------
# 欢迎横幅
Write-Host ''
Write-Host '===============================================' -ForegroundColor Magenta
Write-Host '          SingCtl Windows Installer'            -ForegroundColor Magenta
Write-Host '        Native Windows sing-box support'        -ForegroundColor Magenta
Write-Host '===============================================' -ForegroundColor Magenta
Write-Host ''

#--------------------------------------------------
# 获取最新版本
Write-Info '获取最新版本信息...'
try {
    $release = Invoke-RestMethod "https://api.github.com/repos/$GitHubRepo/releases/latest"
    $LatestVersion = $release.tag_name
} catch {
    Write-Error '无法取得版本信息，请检查网络'
    exit 1
}
Write-Success "最新版本: $LatestVersion"

#--------------------------------------------------
# 系统架构
$OS   = 'windows'

# 获取原生系统架构
$ARCH = if ((Get-CimInstance Win32_Processor).Architecture -contains 12) { 'arm64' } else { 'amd64' }

Write-Info "系统: $OS, 架构: $ARCH"

#--------------------------------------------------
# 下载地址
$FileName    = "singctl-$OS-$ARCH.zip"
$DownloadURL = $release.assets | Where-Object name -eq $FileName | Select-Object -ExpandProperty browser_download_url
if (-not $DownloadURL) {
    Write-Error "未找到对应架构的发行包: $FileName"
    exit 1
}
Write-Info "下载链接: $DownloadURL"

#--------------------------------------------------
# 下载 & 解压
Cleanup
New-Item $TempDir -ItemType Directory -Force | Out-Null
$ZipPath = "$TempDir\singctl.zip"

Write-Info '开始下载安装包...'
try {
    Invoke-WebRequest -Uri $DownloadURL -OutFile $ZipPath
} catch {
    Write-Error "下载失败: $($_.Exception.Message)"
    exit 1
}
Write-Success '下载完成'

Write-Info '解压安装包...'
try {
    Expand-Archive -Path $ZipPath -DestinationPath $TempDir -Force
} catch {
    Write-Error '解压失败'
    exit 1
}
Write-Success '解压完成'

#--------------------------------------------------
# 安装二进制
Write-Info '开始安装...'

# 停掉旧进程
Get-Process -Name 'singctl' -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue

New-Item $InstallDir -ItemType Directory -Force | Out-Null
$Binary = Get-ChildItem -Path $TempDir -Recurse -Filter 'singctl.exe' | Select-Object -First 1
if (-not $Binary) {
    Write-Error '未找到 singctl.exe'
    exit 1
}
Copy-Item $Binary.FullName "$InstallDir\singctl.exe" -Force
Write-Success "已复制到 $InstallDir"

#--------------------------------------------------
# 配置文件
New-Item $ConfigDir -ItemType Directory -Force | Out-Null
$ConfigsDir = Get-ChildItem -Path $TempDir -Recurse -Filter 'configs' -Directory | Select-Object -First 1
if ($ConfigsDir) {
    if (Test-Path $ConfigFile) {
        $Backup = "$ConfigFile.backup.$(Get-Date -Format 'yyyyMMdd_HHmmss')"
        Copy-Item $ConfigFile $Backup
        Write-Warning "主配置文件已存在，已备份到 $Backup"
    }
    Copy-Item -Path "$($ConfigsDir.FullName)\*" -Destination $ConfigDir -Recurse -Force
    Write-Success "所有配置文件已复制到: $ConfigDir"
} else {
    Write-Warning '未找到配置目录，稍后可手动创建'
}

#--------------------------------------------------
# 加入 PATH
$RegPath = 'Registry::HKEY_CURRENT_USER\Environment'
$OldPath = (Get-ItemProperty -Path $RegPath -Name PATH -ErrorAction SilentlyContinue).PATH
if ($OldPath -split ';' -notcontains $InstallDir) {
    $NewPath = ($OldPath, $InstallDir) -join ';'
    Set-ItemProperty -Path $RegPath -Name PATH -Value $NewPath
    Write-Success '已将 singctl 目录加入用户 PATH'
} else {
    Write-Info 'singctl 已在 PATH 中'
}

#--------------------------------------------------
# 验证
Write-Info '验证安装...'
if (-not (Test-Path "$InstallDir\singctl.exe")) {
    Write-Error '二进制文件未找到'
    exit 1
}
try {
    & "$InstallDir\singctl.exe" version | Out-Null
    Write-Success '安装验证通过'
} catch {
    Write-Error '二进制文件无法执行'
    exit 1
}

#--------------------------------------------------
# 运行模式选择
$Mode = if ($Server) { 'server' } elseif ($Client) { 'client' } else { '' }

if (-not $Mode) {
    Write-Host ''
    Write-Host '====================================================' -ForegroundColor Cyan
    Write-Host '          请选择 SingCtl 运行模式:'                      -ForegroundColor Cyan
    Write-Host '  1) 客户端模式 (Client Mode) [回车默认]'           -ForegroundColor White
    Write-Host '     • 本地 / 透明代理加速'
    Write-Host '     • 订阅导入与智能分流规则'
    Write-Host '     • 本地轻量 Web 管理控制台 (http://127.0.0.1:8090)'
    Write-Host ''
    Write-Host '  2) 服务端模式 (Server Mode)'                     -ForegroundColor White
    Write-Host '     • VLESS Reality + Hysteria 2 节点服务'
    Write-Host '     • 自动化 TLS / 域名反代与配置管理'
    Write-Host '     • 服务端 Web 管理控制台'
    Write-Host '     • Sub-Store 节点聚合与分发'
    Write-Host '====================================================' -ForegroundColor Cyan
    Write-Host ''

    $Choice = Read-Host '请输入选项 [1-2] (默认 1)'
    if ($Choice -eq '2' -or $Choice -eq 'server' -or $Choice -eq 's') {
        $Mode = 'server'
    } else {
        $Mode = 'client'
    }
}

if ($Mode -eq 'server') {
    Write-Info '已选择【服务端模式】'
    Write-Info '正在启动 SingCtl 服务端初始化向导...'
    Write-Host ''
    Cleanup
    & "$InstallDir\singctl.exe" sr init
    exit 0
}

Write-Info '已选择【客户端模式】'

#--------------------------------------------------
# 配置订阅（客户端可选）
Write-Host ''
$SubUrl = Read-Host '请输入订阅链接（留空跳过）'
if ($SubUrl) {
    @"
subs:
  - name: "main"
    url: "$SubUrl"
    skip_tls_verify: false
    remove-emoji: true

github:
  mirror_url: "https://ghfast.top"

hy2:
  up: 20                                         # Hysteria2 上行带宽 (Mbps)
  down: 200                                      # Hysteria2 下行带宽 (Mbps)

tailscale:
  auth_key: ""
"@ | Out-File $ConfigFile -Encoding utf8
    Write-Success '订阅已写入配置文件'
} else {
    Write-Info '跳过订阅配置'
}

#--------------------------------------------------
Write-Info '安装并启动 sing-box 客户端...'
try {
    & "$InstallDir\singctl.exe" sb install
    & "$InstallDir\singctl.exe" sb start
    & "$InstallDir\singctl.exe" web start
    Write-Success 'sing-box 客户端与本地 Web 控制台已启动'
} catch {
    Write-Warning 'sing-box 安装/启动失败，请手动执行：singctl sb install / singctl sb start'
}

#--------------------------------------------------
Cleanup
Write-Host ''
Write-Host '=======================================' -ForegroundColor Green
Write-Host '      SingCtl 安装完成！'                 -ForegroundColor Green
Write-Host '=======================================' -ForegroundColor Green
Write-Host "二进制: $InstallDir\singctl.exe"
Write-Host "配置  : $ConfigFile"
Write-Host ''
Write-Host '重新打开终端即可使用 singctl 命令。'

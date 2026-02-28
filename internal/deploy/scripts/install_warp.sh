#!/bin/bash
set -e

echo "Starting WARP (wireproxy) deployment..."
echo "Downloading WARP script..."

curl -fsSLO https://gitlab.com/fscarmen/warp/-/raw/main/menu.sh
chmod +x menu.sh

echo "Executing WARP installation (wireproxy on port 40000)..."

# fscarmen 的脚本支持通过环境变量提前指定语言，跳过交互提示
# L=C 代表中文，L=E 代表英文
export L=C

# 移除 || true，通过 if 语句真实捕获安装结果
# 使用 sed 修改 menu.sh 跳过 reading 输入，直接给 WIREPROXY_CHOOSE 赋值 1
sed -i 's/reading " $(text 50) " WIREPROXY_CHOOSE/WIREPROXY_CHOOSE=1/' menu.sh

if bash ./menu.sh w 40000; then
    echo "WARP (wireproxy) deployed successfully on 127.0.0.1:40000"
else
    echo "Error: WARP (wireproxy) deployment failed. Please check the logs above."
    # 退出脚本并返回错误码，防止静默失败
    exit 1
fi
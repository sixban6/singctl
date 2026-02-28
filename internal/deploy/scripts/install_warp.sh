#!/bin/bash
# 开启错误中断，并确保管道命令的错误也会被捕获
set -e
set -o pipefail

echo "Starting WARP (wireproxy) deployment..."
echo "Downloading WARP script..."

curl -fsSLO https://gitlab.com/fscarmen/warp/-/raw/main/menu.sh
chmod +x menu.sh

echo "Executing WARP installation (wireproxy on port 40000)..."

# 设置环境变量，指定中文并跳过语言交互
export L=C

# 使用 echo 将 "1" 通过管道传给脚本，模拟用户键盘输入 "1" 后回车
# 这样即使原作者修改了代码中的提示文字，只要逻辑还是“输入1选择默认”，就不会受影响
if echo "1" | bash ./menu.sh w 40000; then
    echo "WARP (wireproxy) deployed successfully on 127.0.0.1:40000"
else
    echo "Error: WARP (wireproxy) deployment failed. Please check the logs above."
    # 退出脚本并返回错误码，防止静默失败
    exit 1
fi
#!/bin/bash

echo "=== 简化版 Debian 测试 ==="

# 创建简化 Dockerfile，不安装 sing-box，只测试脚本逻辑
cat > Dockerfile.simple << 'EOF'
FROM debian:11

# 只安装基本工具
RUN apt update && apt install -y \
    curl \
    iproute2 \
    iptables \
    nftables \
    lsb-release \
    procps \
    && rm -rf /var/lib/apt/lists/*

# 创建 fake sing-box 用于测试
RUN echo '#!/bin/bash' > /usr/local/bin/sing-box \
    && echo 'case "$1" in' >> /usr/local/bin/sing-box \
    && echo '  version) echo "sing-box version 1.12.4 (test)" ;;' >> /usr/local/bin/sing-box \
    && echo '  check) echo "Configuration check passed" ;;' >> /usr/local/bin/sing-box \
    && echo '  *) echo "sing-box test command: $*" ;;' >> /usr/local/bin/sing-box \
    && echo 'esac' >> /usr/local/bin/sing-box \
    && chmod +x /usr/local/bin/sing-box

# 创建必要目录
RUN mkdir -p /etc/sing-box /var/log

WORKDIR /app
CMD ["/bin/bash"]
EOF

echo "1. 构建简化测试镜像..."
docker build -f Dockerfile.simple -t singctl-debian-simple .
if [ $? -ne 0 ]; then
    echo "❌ 构建失败"
    exit 1
fi

echo "2. 运行测试..."
docker run --rm \
    --privileged \
    -v $(pwd)/singctl:/app/singctl:ro \
    -v $(pwd)/test_config:/etc/sing-box:ro \
    singctl-debian-simple /bin/bash -c "
    echo '=== Debian 系统识别测试 ==='
    echo '系统版本:'
    cat /etc/os-release | grep PRETTY_NAME
    echo
    
    echo '检查是否为 Debian:'
    [ -f /etc/debian_version ] && echo '✅ 检测到 /etc/debian_version'
    [ -f /etc/apt/sources.list ] && echo '✅ 检测到 /etc/apt/sources.list' 
    echo
    
    echo 'fake sing-box 测试:'
    sing-box version
    echo
    
    echo 'singctl 版本:'
    /app/singctl version
    echo
    
    echo '系统工具检查:'
    command -v iptables && echo '✅ iptables 可用'
    command -v nft && echo '✅ nftables 可用'  
    command -v ip && echo '✅ ip 工具可用'
    echo
    
    echo '脚本权限检查:'
    id
    echo
    
    echo '✅ Debian 基础环境测试完成'
"

echo "3. 清理..."
rm -f Dockerfile.simple
docker rmi singctl-debian-simple

echo "✅ 简化测试完成"
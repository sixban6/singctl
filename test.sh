#!/bin/bash

# 编译 singctl
echo "Compiling singctl..."
go build -o ./singctl cmd/singctl/main.go

if [ $? -eq 0 ]; then
    echo "Compilation successful! Executable is at ./singctl"
else
    echo "Compilation failed!"
    exit 1
fi

./singctl sb gen -c /etc/singctl/singctl.yaml
cat /etc/sing-box/config.json | grep tailscale


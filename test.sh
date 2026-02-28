#!/bin/bash

# 编译 singctl
echo "Compiling singctl..."
go build -o ./singctl cmd/singctl/main.go

if [ $? -eq 0 ]; then
    echo "Compilation successful! Executable is at bin/singctl"
    echo "You can run tests with: ./singctl test bd"
else
    echo "Compilation failed!"
    exit 1
fi

#!/bin/bash

echo "pulling dnscrypt-proxy source code"
git pull origin odns-probe

export GOOS=linux
echo "Building for $GOOS"

# 尝试进行编译
if go build -o dnscrypt ./dnscrypt-proxy; then
    echo "Build successful"
    echo "Running dnscrypt"
    sudo ./dnscrypt --config ./dnscrypt-proxy.toml
else
    # 如果编译失败，打印错误信息并退出
    echo "Build failed"
    exit 1
fi

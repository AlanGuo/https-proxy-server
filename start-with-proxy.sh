#!/bin/bash

echo "🚀 启动HTTPS代理服务器 (支持代理链)"
echo "========================================"

# 设置上游代理环境变量
# 根据你的实际代理配置修改这些值
export http_proxy=http://127.0.0.1:10808
export https_proxy=http://127.0.0.1:10808
export all_proxy=socks5://127.0.0.1:10808

export HTTP_PROXY=http://127.0.0.1:10808
export HTTPS_PROXY=http://127.0.0.1:10808
export ALL_PROXY=socks5://127.0.0.1:10808

echo "🔧 当前代理环境变量配置："
echo "   http_proxy=$http_proxy"
echo "   https_proxy=$https_proxy"
echo "   all_proxy=$all_proxy"
echo ""

# 检查上游代理是否可用
echo "🔍 检查上游代理连接..."
if curl -s --connect-timeout 5 --proxy $http_proxy http://httpbin.org/ip > /dev/null 2>&1; then
    echo "✅ 上游代理连接正常"
else
    echo "⚠️  警告: 上游代理 $http_proxy 连接失败"
    echo "   代理服务器将在没有上游代理的情况下运行"
    echo "   如果你需要代理链功能，请检查上游代理配置"
fi
echo ""

# 设置HTTPS代理服务器端口
HTTPS_PROXY_PORT=${HTTPS_PROXY_PORT:-10443}
PROXY_TIMEOUT=${PROXY_TIMEOUT:-30000}

echo "🔧 HTTPS代理服务器配置："
echo "   端口: $HTTPS_PROXY_PORT"
echo "   超时: $PROXY_TIMEOUT ms"
echo ""

# 检查端口是否被占用
if lsof -ti:$HTTPS_PROXY_PORT > /dev/null 2>&1; then
    echo "❌ 端口 $HTTPS_PROXY_PORT 已被占用"
    echo "请选择其他端口或停止占用该端口的进程"
    echo ""
    echo "查看占用进程:"
    lsof -ti:$HTTPS_PROXY_PORT | xargs ps -p
    exit 1
fi

echo "🚀 启动HTTPS代理服务器..."
echo "按 Ctrl+C 停止服务器"
echo ""

# 启动HTTPS代理服务器
HTTPS_PROXY_PORT=$HTTPS_PROXY_PORT PROXY_TIMEOUT=$PROXY_TIMEOUT yarn https

# 捕获退出信号
trap 'echo; echo "👋 正在关闭HTTPS代理服务器..."; exit 0' INT TERM

echo "✨ HTTPS代理服务器已停止"
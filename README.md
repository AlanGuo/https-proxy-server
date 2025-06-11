# HTTPS 代理服务器

一个支持HTTPS协议的本地代理服务器，专门用于解决HTTP代理访问HTTPS网站时的重定向问题。

## 特性

- ✅ 支持HTTPS协议
- ✅ 支持CONNECT方法进行SSL隧道
- ✅ 支持HTTP/HTTPS请求转发
- ✅ 支持WebSocket (WSS) 透明转发
- ✅ 自动生成SSL证书
- ✅ 支持Binance API等HTTPS服务
- ✅ 简单易用的Web管理界面
- ✅ 支持代理链（通过上游代理访问目标地址）
- ✅ 自动检测环境变量中的代理配置
- ✅ 支持HTTP、HTTPS、SOCKS5代理协议

## 快速开始

### 1. 安装依赖

```bash
yarn install
```

### 2. 生成SSL证书

```bash
./generate-cert.sh
```

### 3. 启动HTTPS代理服务器

#### 普通启动

```bash
yarn https
```

#### 带代理链启动

如果你需要通过上游代理访问目标地址，使用以下方式：

```bash
# 使用启动脚本（推荐）
./start-with-proxy.sh

# 或者手动设置环境变量
export http_proxy=http://127.0.0.1:10808
export https_proxy=http://127.0.0.1:10808
export all_proxy=socks5://127.0.0.1:10808
yarn https
```

服务器将在 `https://127.0.0.1:10443` 启动。

### 4. 测试代理功能

```bash
# 基本功能测试
./test-proxy.sh

# 代理链功能测试
./test-proxy-chain.sh
```

## 使用方法

### 命令行使用

```bash
# 设置环境变量
export https_proxy=https://127.0.0.1:10443

# 测试Binance API
curl -k https://api.binance.com/api/v3/ping

# 或者直接指定代理
curl -k --proxy https://127.0.0.1:10443 https://api.binance.com/api/v3/ping

# 测试WebSocket连接 (需要安装 wscat: yarn global add wscat)
wscat -c wss://echo.websocket.org --ca certs/ca.crt
```

### 浏览器配置

1. 打开浏览器代理设置
2. 设置HTTPS代理为：`127.0.0.1:10443`
3. 访问 `https://127.0.0.1:10443` 查看管理界面

### 程序中使用

```javascript
// Node.js HTTPS 示例
const https = require('https');

const agent = new https.Agent({
  proxy: 'https://127.0.0.1:10443',
  rejectUnauthorized: false // 忽略自签名证书
});

https.get('https://api.binance.com/api/v3/ping', { agent }, (res) => {
  // 处理响应
});

// WebSocket 示例
const WebSocket = require('ws');

// 设置代理环境变量
process.env.https_proxy = 'https://127.0.0.1:10443';

const ws = new WebSocket('wss://echo.websocket.org', {
  agent: new https.Agent({
    rejectUnauthorized: false
  })
});

ws.on('open', function open() {
  console.log('WebSocket 连接已建立');
  ws.send('Hello from WebSocket!');
});

ws.on('message', function message(data) {
  console.log('收到消息:', data.toString());
});
```

## 配置选项

### 环境变量

#### 代理服务器配置
- `HTTPS_PROXY_PORT`: 代理服务器端口（默认：10443）
- `PROXY_TIMEOUT`: 请求超时时间（默认：30000ms）

#### 上游代理配置（代理链）
- `http_proxy` / `HTTP_PROXY`: HTTP代理地址
- `https_proxy` / `HTTPS_PROXY`: HTTPS代理地址  
- `all_proxy` / `ALL_PROXY`: 通用代理地址（支持SOCKS5）

支持的代理协议：
- HTTP: `http://127.0.0.1:8080`
- HTTPS: `https://127.0.0.1:8080`
- SOCKS5: `socks5://127.0.0.1:1080`

### 启动选项

```bash
# 自定义端口启动
HTTPS_PROXY_PORT=8443 yarn https
```

## 脚本说明

- `generate-cert.sh`: 生成SSL自签名证书
- `test-proxy.sh`: 测试代理服务器功能
- `test-proxy-chain.sh`: 测试代理链功能
- `start-with-proxy.sh`: 带代理链配置的启动脚本
- `https-proxy.ts`: HTTPS代理服务器主程序
- `start.ts`: HTTP代理服务器（原版本）

## 常见问题

### 1. 证书验证失败

由于使用自签名证书，需要添加 `-k` 参数跳过证书验证：

```bash
curl -k --proxy https://127.0.0.1:10443 https://api.binance.com/api/v3/ping
```

### 2. 端口被占用

修改端口号：

```bash
HTTPS_PROXY_PORT=8443 yarn https
```

### 3. 连接超时

检查目标服务是否可访问，或增加超时时间：

```bash
PROXY_TIMEOUT=60000 yarn https
```

### 4. 代理链不工作

检查上游代理是否可用：

```bash
# 测试上游代理连接
curl --proxy http://127.0.0.1:10808 http://httpbin.org/ip

# 检查环境变量
echo $http_proxy
echo $https_proxy
echo $all_proxy
```

## 代理链工作原理

当设置了上游代理环境变量时，HTTPS代理服务器会：

1. 检测环境变量中的代理配置
2. 对于CONNECT请求，通过上游代理建立到目标服务器的连接
3. 对于HTTP/HTTPS请求，使用相应的代理Agent转发请求
4. 支持HTTP、HTTPS、SOCKS5等多种上游代理协议

```
客户端 → HTTPS代理服务器 → 上游代理 → 目标服务器
```

## 与HTTP代理的区别

| 特性 | HTTP代理 | HTTPS代理 |
|------|----------|-----------|
| 协议 | HTTP | HTTPS |
| 安全性 | 明文传输 | 加密传输 |
| 证书 | 不需要 | 需要SSL证书 |
| 重定向问题 | 可能出现 | 解决 |
| 代理链 | ✅ 支持 | ✅ 支持 |
| Binance API | ❌ 可能失败 | ✅ 正常工作 |

## 测试结果

运行 `./test-proxy.sh` 可以测试以下API：

- ✅ Binance API: `https://api.binance.com/api/v3/ping`
- ✅ HTTPBin: `https://httpbin.org/ip`
- ✅ GitHub API: `https://api.github.com`
- ✅ JSONPlaceholder: `https://jsonplaceholder.typicode.com/posts/1`
- ✅ WebSocket (WSS): `wss://echo.websocket.org`

## 安全说明

⚠️ **重要提醒**：

1. 此代理使用自签名证书，仅适用于开发和测试环境
2. 生产环境请使用有效的SSL证书
3. 不要在公网环境中运行此代理服务器

## 故障排除

### 查看日志

代理服务器会输出详细的请求日志，包括：

- CONNECT请求（SSL隧道）
- HTTP/HTTPS请求转发
- 连接错误和超时信息

### 常见错误处理

1. **SSL handshake failed**: 检查证书文件是否存在
2. **Connection refused**: 检查目标服务器是否可访问
3. **Timeout**: 增加超时时间或检查网络连接
4. **ECONNRESET during SSL handshake**: 客户端在SSL握手期间断开连接，这是正常现象
5. **Client network socket disconnected**: WebSocket或其他客户端在连接建立过程中断开，代理会自动清理连接

## 许可证

MIT License
#!/bin/bash

# 生成HTTPS代理服务器所需的SSL证书（包括CA证书）

echo "正在生成SSL证书..."

# 创建certs目录
mkdir -p certs

# 清理旧证书
rm -f certs/*

# 1. 生成CA私钥
echo "🔑 生成CA私钥..."
openssl genrsa -out certs/ca.key 4096

# 2. 生成CA证书
echo "📜 生成CA证书..."
openssl req -new -x509 -days 3650 -key certs/ca.key -out certs/ca.crt -subj "/C=CN/ST=Local/L=Local/O=Local CA/OU=Local CA/CN=Local CA"

# 3. 生成服务器私钥
echo "🔑 生成服务器私钥..."
openssl genrsa -out certs/server.key 2048

# 4. 生成服务器证书请求
echo "📝 生成服务器证书请求..."
openssl req -new -key certs/server.key -out certs/server.csr -subj "/C=CN/ST=Local/L=Local/O=Proxy Server/OU=Proxy Server/CN=localhost"

# 5. 创建扩展配置文件
echo "⚙️  创建证书扩展配置..."
cat > certs/server.ext << EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
DNS.2 = *.localhost
DNS.3 = *.binance.com
DNS.4 = *.binance.vision
DNS.5 = *.tradingview.com
IP.1 = 127.0.0.1
IP.2 = ::1
EOF

# 6. 使用CA签名生成服务器证书
echo "✍️  使用CA签名生成服务器证书..."
openssl x509 -req -in certs/server.csr -CA certs/ca.crt -CAkey certs/ca.key -CAcreateserial -out certs/server.crt -days 365 -extfile certs/server.ext

# 7. 创建证书链文件
echo "🔗 创建证书链文件..."
cat certs/server.crt certs/ca.crt > certs/fullchain.crt

# 8. 删除临时文件
rm certs/server.csr certs/server.ext certs/ca.srl

# 9. 设置文件权限
chmod 600 certs/*.key
chmod 644 certs/*.crt

echo ""
echo "✅ SSL证书生成完成！"
echo "📁 证书文件:"
echo "   CA证书: certs/ca.crt"
echo "   服务器证书: certs/server.crt"
echo "   服务器私钥: certs/server.key"
echo "   完整证书链: certs/fullchain.crt"
echo ""
echo "🔧 安装CA证书到系统（可选）："
echo "   macOS: security add-trusted-cert -d -r trustRoot -k ~/Library/Keychains/login.keychain certs/ca.crt"
echo "   Linux: sudo cp certs/ca.crt /usr/local/share/ca-certificates/ && sudo update-ca-certificates"
echo ""
echo "🧪 测试命令："
echo "   curl --cacert certs/ca.crt --proxy https://127.0.0.1:10443 https://api.binance.com/api/v3/ping"
echo "   或者忽略证书验证："
echo "   curl --proxy-insecure --proxy https://127.0.0.1:10443 https://api.binance.com/api/v3/ping"

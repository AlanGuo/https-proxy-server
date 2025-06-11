import * as http from 'http';
import * as https from 'https';
import * as fs from 'fs';
import * as url from 'url';
import * as path from 'path';
import { IncomingMessage, ServerResponse } from 'http';
import { Socket } from 'net';
import { HttpProxyAgent } from 'http-proxy-agent';
import { HttpsProxyAgent } from 'https-proxy-agent';
import { SocksProxyAgent } from 'socks-proxy-agent';

interface HttpsProxyOptions {
  port?: number;
  timeout?: number;
  certFile?: string;
  keyFile?: string;
  caFile?: string;
}

class HttpsProxy {
  private port: number;
  private timeout: number;
  private certFile: string;
  private keyFile: string;
  private caFile: string;
  private httpsOptions: https.ServerOptions;
  private upstreamProxy: string | null;

  constructor(options: HttpsProxyOptions = {}) {
    this.port = options.port || 10443;
    this.timeout = options.timeout || 30000;
    // 修复路径：从 dist 目录向上找到项目根目录
    const projectRoot = path.resolve(__dirname, '..');
    this.certFile = options.certFile || path.join(projectRoot, 'certs', 'server.crt');
    this.keyFile = options.keyFile || path.join(projectRoot, 'certs', 'server.key');
    this.caFile = options.caFile || path.join(projectRoot, 'certs', 'ca.crt');

    // 读取SSL证书
    try {
      // 优先使用完整证书链
      const fullchainPath = path.join(projectRoot, 'certs', 'fullchain.crt');
      const certToUse = fs.existsSync(fullchainPath) ? fullchainPath : this.certFile;

      this.httpsOptions = {
        key: fs.readFileSync(this.keyFile),
        cert: fs.readFileSync(certToUse),
        // If not using fullchain, and caFile exists, add it as an array.
        ...(certToUse !== fullchainPath && fs.existsSync(this.caFile) && { ca: [fs.readFileSync(this.caFile)] }),
        honorCipherOrder: true,
        ciphers: [
          'ECDHE-RSA-AES128-GCM-SHA256',
          'ECDHE-RSA-AES256-GCM-SHA384',
          'ECDHE-RSA-AES128-SHA256',
          'ECDHE-RSA-AES256-SHA384',
          'ECDHE-RSA-AES256-SHA256',
          'ECDHE-RSA-AES128-SHA',
          'ECDHE-RSA-AES256-SHA',
          'AES128-GCM-SHA256',
          'AES256-GCM-SHA384',
          'AES128-SHA256',
          'AES256-SHA256',
          'AES128-SHA',
          'AES256-SHA'
        ].join(':'),
        // 处理SNI
        SNICallback: (servername: string, callback: (err: Error | null, ctx?: any) => void) => {
          // 对所有域名返回相同的证书
          callback(null);
        },
        // 允许不安全的连接用于代理
        rejectUnauthorized: false,
        requestCert: false,
        // 处理会话恢复
        sessionTimeout: 300,
        // 优化SSL握手超时设置 - 增加到45秒以适应复杂网络环境和SSL协议协商
        handshakeTimeout: 45000,
        // 当SSL握手失败时不抛出未捕获异常
        allowHalfOpen: false,
        // Allow OpenSSL to automatically negotiate the best protocol version.
        // This provides maximum compatibility with various clients and servers.
        secureProtocol: undefined,
        // Session resumption settings
        sessionIdContext: 'https-proxy',
        // sessionTimeout: 300, // 5 minutes - This was a duplicate, removed.
        // DH parameters for DHE ciphers (if used, though modern ciphers prefer ECDHE)
        // Leaving undefined allows Node.js to use built-in defaults if necessary.
        dhparam: undefined,
        // Keep-alive and header timeouts for the HTTPS server itself
        keepAliveTimeout: 30000, // 30 seconds
        headersTimeout: 60000,   // 60 seconds
        // SSL/TLS options for security and compatibility.
        // For broader compatibility (e.g., with LibreSSL or older clients), these might be removed.
        secureOptions:
          require('constants').SSL_OP_NO_SSLv2 |
          require('constants').SSL_OP_NO_SSLv3 |
          // Comment out TLSv1 and TLSv1.1 restrictions for max compatibility
          // require('constants').SSL_OP_NO_TLSv1 |
          // require('constants').SSL_OP_NO_TLSv1_1 |
          require('constants').SSL_OP_CIPHER_SERVER_PREFERENCE,
        // Remove explicit min/max versions for auto-negotiation
        // minVersion: undefined,
        // maxVersion: undefined,
      };
    } catch (error) {
      throw new Error(`无法读取SSL证书文件: ${error}`);
    }

    // 检测上游代理配置
    this.upstreamProxy = this.detectUpstreamProxy();
  }

  /**
   * 检测环境变量中的上游代理配置
   */
  private detectUpstreamProxy(): string | null {
    const proxies = [
      process.env.https_proxy,
      process.env.HTTPS_PROXY,
      process.env.http_proxy,
      process.env.HTTP_PROXY,
      process.env.all_proxy,
      process.env.ALL_PROXY
    ];

    for (const proxy of proxies) {
      if (proxy && proxy.trim()) {
        console.log(`🔗 检测到上游代理: ${proxy}`);
        return proxy.trim();
      }
    }

    console.log('ℹ️  未检测到上游代理配置');
    return null;
  }

  /**
   * 创建代理Agent
   */
  private createProxyAgent(targetUrl: string, isConnectMethod: boolean = false): any { // targetUrl is the FINAL destination
    if (!this.upstreamProxy) {
      return undefined;
    }

    try {
      const upstreamProxyUrl = new URL(this.upstreamProxy);

      if (upstreamProxyUrl.protocol === 'socks5:' || upstreamProxyUrl.protocol === 'socks4:') {
        console.log(`🧦 使用SOCKS上游代理: ${this.upstreamProxy}`);
        return new SocksProxyAgent(this.upstreamProxy);
      } else if (upstreamProxyUrl.protocol === 'http:') {
        // HttpProxyAgent适用于CONNECT方法建立的隧道（如curl）
        console.log(`🌐 使用HTTP上游代理: ${this.upstreamProxy} (${isConnectMethod ? 'CONNECT隧道' : 'HTTP转发'})`);
        return new HttpProxyAgent(this.upstreamProxy);
      } else if (upstreamProxyUrl.protocol === 'https:') {
        if (isConnectMethod) {
          // 对于CONNECT方法，使用HttpsProxyAgent
          console.log(`🔒 使用HTTPS上游代理: ${this.upstreamProxy} (CONNECT隧道)`);
          return new HttpsProxyAgent(this.upstreamProxy);
        } else {
          // 对于直接HTTP请求，判断目标URL协议
          const targetUrlObj = new URL(targetUrl);
          if (targetUrlObj.protocol === 'https:') {
            console.log(`🔒 使用HTTPS上游代理: ${this.upstreamProxy} (HTTPS->HTTPS)`);
            return new HttpsProxyAgent(this.upstreamProxy);
          } else {
            console.log(`🌐 使用HTTPS上游代理: ${this.upstreamProxy} (HTTP->HTTPS)`);
            return new HttpProxyAgent(this.upstreamProxy);
          }
        }
      } else {
        console.error(`❌ 不支持的上游代理协议: ${upstreamProxyUrl.protocol}`);
        return undefined;
      }
    } catch (error) {
      console.error(`❌ 解析或创建上游代理Agent失败:`, error);
      return undefined;
    }
  }

  /**
   * 处理 HTTPS CONNECT 请求（HTTPS 隧道）
   */
  private handleConnect(req: IncomingMessage, socket: Socket, head: Buffer): void {
    if (!req.url) {
      console.error('❌ CONNECT请求缺少URL');
      this.sendConnectError(socket, '400 Bad Request', 'CONNECT请求缺少URL');
      return;
    }

    // 解析CONNECT请求的目标地址
    // CONNECT格式: hostname:port
    let hostname: string;
    let targetPort: number;

    // 尝试多种解析方式
    if (req.url.includes(':')) {
      // 标准格式: hostname:port
      const parts = req.url.split(':');
      hostname = parts[0];
      targetPort = parseInt(parts[1] || '443', 10);
    } else {
      // 备用解析方式，使用url.parse
      const parsed = url.parse(`//${req.url}`);
      hostname = parsed.hostname || req.url;
      targetPort = parseInt(parsed.port || '443', 10);
    }

    // 验证hostname和port - 添加更严格的验证
    if (!hostname || hostname === 'null' || hostname === 'undefined') {
      console.error(`❌ 无效的hostname: ${req.url}`);
      this.sendConnectError(socket, '400 Bad Request', `无效的hostname: ${req.url}`);
      return;
    }

    // 验证hostname格式 - 防止恶意输入
    if (!/^[a-zA-Z0-9.-]+$/.test(hostname) || hostname.length > 253) {
      console.error(`❌ hostname格式不正确: ${hostname}`);
      this.sendConnectError(socket, '400 Bad Request', `hostname格式不正确: ${hostname}`);
      return;
    }

    if (isNaN(targetPort) || targetPort <= 0 || targetPort > 65535) {
      console.error(`❌ 无效的端口: ${targetPort}`);
      this.sendConnectError(socket, '400 Bad Request', `无效的端口: ${targetPort}`);
      return;
    }

    console.log(`🔗 CONNECT ${hostname}:${targetPort} - ${new Date().toISOString()}`);

    // 检查客户端socket状态 - 增强稳定性检查
    if (socket.destroyed || socket.readyState !== 'open') {
      console.error(`❌ 客户端socket状态异常: destroyed=${socket.destroyed}, readyState=${socket.readyState}`);
      this.sendConnectError(socket, '400 Bad Request', '客户端连接状态异常');
      return;
    }

    // 为SSL握手设置更优的socket选项
    try {
      socket.setKeepAlive(true, 30000);
      socket.setNoDelay(true);
      socket.setTimeout(60000); // 60秒超时，给SSL握手充足时间（特别是WebSocket）
    } catch (err: any) {
      console.error(`⚠️  设置客户端socket选项失败:`, err.message);
    }

    if (this.upstreamProxy) {
      // 如果有上游代理，使用代理Agent创建连接
      this.handleConnectViaProxy(req, socket, head, hostname, targetPort);
    } else {
      // 直接连接
      this.handleDirectConnect(socket, hostname, targetPort, head);
    }
  }

  /**
   * 通过上游代理处理CONNECT请求
   */
  private handleConnectViaProxy(req: IncomingMessage, socket: Socket, head: Buffer, hostname: string, targetPort: number): void {
    try {
      const proxyAgent = this.createProxyAgent(`https://${hostname}:${targetPort}`, true);

      if (!proxyAgent) {
        console.error('❌ 无法创建代理Agent');
        this.sendConnectError(socket, '502 Bad Gateway', '无法创建代理连接');
        return;
      }

      // 创建到上游代理的连接
      const proxyReq = http.request({
        host: hostname,
        port: targetPort,
        method: 'CONNECT',
        path: `${hostname}:${targetPort}`,
        agent: proxyAgent,
        timeout: this.timeout
      });

      proxyReq.on('connect', (proxyRes: IncomingMessage, proxySocket: Socket, proxyHead: Buffer) => {
        console.log(`✅ 通过代理连接到 ${hostname}:${targetPort}`);

        // 确保socket没有被销毁
        if (socket.destroyed) {
          console.log(`⚠️  客户端socket已断开，关闭代理连接 ${hostname}:${targetPort}`);
          proxySocket.destroy();
          return;
        }

        // 先设置socket选项，确保在发送响应前就优化好连接
        try {
          // 禁用Nagle算法，减少延迟，对SSL握手特别重要
          socket.setNoDelay(true);
          proxySocket.setNoDelay(true);
          // 启用TCP Keep-Alive机制
          socket.setKeepAlive(true, 30000);
          proxySocket.setKeepAlive(true, 30000);
          // 设置更长的超时时间，给不同TLS版本协商更多时间
          socket.setTimeout(120000); // 增加到120秒，适应各种TLS版本
          proxySocket.setTimeout(120000);
          // 增加socket缓冲区大小以处理SSL握手数据
          if (socket.setMaxListeners) socket.setMaxListeners(20);
          if (proxySocket.setMaxListeners) proxySocket.setMaxListeners(20);
        } catch (err: any) {
          console.error(`⚠️  设置socket选项失败 ${hostname}:${targetPort}:`, err.message);
        }

        // 发送连接成功响应 - 增强SSL握手稳定性
        try {
          const response = 'HTTP/1.1 200 Connection Established\r\n' +
                          'Proxy-agent: HTTPS-Proxy/1.0\r\n' +
                          'Connection: keep-alive\r\n' +
                          'Keep-Alive: timeout=60, max=1000\r\n' +
                          'Proxy-Connection: keep-alive\r\n' +
                          '\r\n';
          socket.write(response, (err) => {
            if (err) {
              console.error(`❌ 发送CONNECT响应失败 ${hostname}:${targetPort}:`, err);
              proxySocket.destroy();
              return;
            }
            // 强制刷新缓冲区，确保响应立即发送
            if (socket.writable && typeof (socket as any).flush === 'function') {
              (socket as any).flush();
            }
          });
        } catch (err: any) {
          console.error(`❌ 发送CONNECT响应失败 ${hostname}:${targetPort}:`, err);
          proxySocket.destroy();
          return;
        }

        // 如果有预先接收的数据，先写入
        if (head && head.length > 0) {
          try {
            proxySocket.write(head);
          } catch (err: any) {
            console.error(`❌ 写入head数据失败 ${hostname}:${targetPort}:`, err);
          }
        }
        if (proxyHead && proxyHead.length > 0) {
          try {
            socket.write(proxyHead);
          } catch (err: any) {
            console.error(`❌ 写入proxyHead数据失败 ${hostname}:${targetPort}:`, err);
          }
        }

        // 设置连接错误处理（在数据转发之前）
        this.setupSocketErrorHandlers(socket, proxySocket, hostname, targetPort);

        // 确保在数据转发开始前，socket状态正常
        process.nextTick(() => {
          if (socket.destroyed || proxySocket.destroyed) {
            console.log(`⚠️  Socket在数据转发前已关闭 ${hostname}:${targetPort}`);
            return;
          }

          // 双向数据转发 - 使用更好的错误处理
          const proxyToClient = proxySocket.pipe(socket, { end: false });
          const clientToProxy = socket.pipe(proxySocket, { end: false });

          // 减少verbose logging，只记录非常见错误
          proxyToClient.on('error', (err) => {
            if (!err.message.includes('ECONNRESET') &&
                !err.message.includes('EPIPE') &&
                !err.message.includes('ENOTCONN') &&
                !err.message.includes('Client network socket disconnected') &&
                !err.message.includes('before secure TLS connection')) {
              console.error(`❌ proxySocket->socket pipe错误 ${hostname}:${targetPort}:`, err.message);
            }
          });

          clientToProxy.on('error', (err) => {
            if (!err.message.includes('ECONNRESET') &&
                !err.message.includes('EPIPE') &&
                !err.message.includes('ENOTCONN') &&
                !err.message.includes('Client network socket disconnected') &&
                !err.message.includes('before secure TLS connection')) {
              console.error(`❌ socket->proxySocket pipe错误 ${hostname}:${targetPort}:`, err.message);
            }
          });
        });
      });

      proxyReq.on('error', (err: Error) => {
        console.error(`❌ 代理连接错误 ${hostname}:${targetPort}:`, err.message);
        this.sendConnectError(socket, '502 Bad Gateway', `代理连接失败: ${err.message}`);
      });

      proxyReq.on('timeout', () => {
        console.log(`⏰ 代理连接超时 ${hostname}:${targetPort}`);
        proxyReq.destroy();
        this.sendConnectError(socket, '504 Gateway Timeout', '代理连接超时');
      });

      proxyReq.end();

    } catch (error) {
      console.error(`❌ 代理连接异常 ${hostname}:${targetPort}:`, error);
      this.sendConnectError(socket, '502 Bad Gateway', `代理连接异常: ${error}`);
    }
  }

  /**
   * 直接连接处理CONNECT请求
   */
  private handleDirectConnect(socket: Socket, hostname: string, targetPort: number, head: Buffer): void {
    const serverSocket = new (require('net').Socket)();

    serverSocket.setTimeout(this.timeout);

    serverSocket.connect(targetPort, hostname, () => {
      console.log(`✅ 直接连接到 ${hostname}:${targetPort}`);

      // 确保客户端socket没有被销毁
      if (socket.destroyed) {
        console.log(`⚠️  客户端socket已断开，关闭服务器连接 ${hostname}:${targetPort}`);
        serverSocket.destroy();
        return;
      }

      // 发送连接成功响应 - 添加keep-alive头改善SSL稳定性
      try {
        socket.write('HTTP/1.1 200 Connection Established\r\n');
        socket.write('Proxy-agent: HTTPS-Proxy/1.0\r\n');
        socket.write('Connection: keep-alive\r\n');
        socket.write('Keep-Alive: timeout=60, max=1000\r\n');
        socket.write('Proxy-Connection: keep-alive\r\n');
        socket.write('\r\n');
      } catch (err: any) {
        console.error(`❌ 发送CONNECT响应失败 ${hostname}:${targetPort}:`, err);
        serverSocket.destroy();
        return;
      }

      // 立即设置socket选项以提高SSL握手稳定性
      try {
        socket.setKeepAlive(true, 30000); // 增加到30秒，给SSL握手更多时间
        serverSocket.setKeepAlive(true, 30000);
        socket.setNoDelay(true);
        serverSocket.setNoDelay(true);
        // 设置更长的超时以适应不同TLS版本的协商过程
        socket.setTimeout(120000); // 120秒超时，适应各种TLS版本协商
        serverSocket.setTimeout(120000);
        // 优化socket监听器数量
        if (socket.setMaxListeners) socket.setMaxListeners(20);
        if (serverSocket.setMaxListeners) serverSocket.setMaxListeners(20);
      } catch (err: any) {
        console.error(`⚠️  设置socket选项失败 ${hostname}:${targetPort}:`, err.message);
      }

      // 如果有预先接收的数据，先写入
      if (head && head.length > 0) {
        try {
          serverSocket.write(head);
        } catch (err: any) {
          console.error(`❌ 写入head数据失败 ${hostname}:${targetPort}:`, err);
        }
      }

      // 设置连接错误处理（在数据转发之前）
      this.setupSocketErrorHandlers(socket, serverSocket, hostname, targetPort);

      // 双向数据转发 - 使用更好的错误处理
      const serverToClient = serverSocket.pipe(socket, { end: false });
      const clientToServer = socket.pipe(serverSocket, { end: false });

      serverToClient.on('error', (err: any) => {
        if (!err.message.includes('ECONNRESET') &&
            !err.message.includes('EPIPE') &&
            !err.message.includes('ENOTCONN') &&
            !err.message.includes('Client network socket disconnected')) {
          console.error(`❌ serverSocket->socket pipe错误 ${hostname}:${targetPort}:`, err.message);
        }
      });

      clientToServer.on('error', (err: any) => {
        if (!err.message.includes('ECONNRESET') &&
            !err.message.includes('EPIPE') &&
            !err.message.includes('ENOTCONN') &&
            !err.message.includes('Client network socket disconnected')) {
          console.error(`❌ socket->serverSocket pipe错误 ${hostname}:${targetPort}:`, err.message);
        }
      });
    });

    serverSocket.on('error', (err: Error) => {
      console.error(`❌ 直接连接错误 ${hostname}:${targetPort}:`, err.message);
      this.sendConnectError(socket, '502 Bad Gateway', `连接目标服务器失败: ${err.message}`);
    });
  }

  /**
   * 发送CONNECT错误响应
   */
  private sendConnectError(socket: Socket, status: string, message: string): void {
    if (!socket.destroyed) {
      socket.write(`HTTP/1.1 ${status}\r\n`);
      socket.write('Content-Type: text/plain\r\n');
      socket.write('\r\n');
      socket.write(message);
      socket.end();
    }
  }

  /**
   * 设置Socket错误处理
   */
  private setupSocketErrorHandlers(clientSocket: Socket, serverSocket: Socket, hostname: string, targetPort: number): void {
    let connectionClosed = false;

    const cleanup = () => {
      if (connectionClosed) return;
      connectionClosed = true;

      try {
        if (!clientSocket.destroyed) {
          clientSocket.unpipe(serverSocket);
          clientSocket.destroy();
        }
      } catch (err) {
        // 忽略清理错误
      }

      try {
        if (!serverSocket.destroyed) {
          serverSocket.unpipe(clientSocket);
          serverSocket.destroy();
        }
      } catch (err) {
        // 忽略清理错误
      }
    };

    clientSocket.on('error', (err: any) => {
      // 过滤更多SSL相关的常见错误，避免大量日志输出
      const isCommonError =
        err.message.includes('ECONNRESET') ||
        err.message.includes('EPIPE') ||
        err.message.includes('ENOTCONN') ||
        err.message.includes('Client network socket disconnected') ||
        err.message.includes('before secure TLS connection') ||
        err.message.includes('socket hang up') ||
        err.message.includes('PROTOCOL_WRONG_VERSION') ||
        err.message.includes('SSL routines') ||
        err.message.includes('ETIMEDOUT');

      if (!isCommonError) {
        console.error(`❌ 客户端连接错误 ${hostname}:${targetPort}:`, err.message);
      } else if (err.code === 'ECONNRESET' && err.message.includes('before secure TLS connection')) {
        // WebSocket SSL握手特殊处理
        console.log(`⚠️  WebSocket SSL握手中断 ${hostname}:${targetPort}`);
      } else {
        // 对常见的SSL握手错误，只记录简要信息
        console.log(`⚠️  客户端连接断开 ${hostname}:${targetPort} (${err.code || 'SSL'})`);
      }
      cleanup();
    });

    clientSocket.on('close', (hadError) => {
      if (hadError) {
        console.log(`🔌 客户端连接异常关闭 ${hostname}:${targetPort}`);
      }
      cleanup();
    });

    serverSocket.on('error', (err: any) => {
      const isCommonError = err.message.includes('ECONNRESET') ||
                           err.message.includes('EPIPE') ||
                           err.message.includes('ENOTCONN') ||
                           err.message.includes('socket hang up');

      if (!isCommonError) {
        console.error(`❌ 服务器连接错误 ${hostname}:${targetPort}:`, err.message);
      }
      cleanup();
    });

    serverSocket.on('close', (hadError) => {
      if (hadError) {
        console.log(`🔌 服务器连接异常关闭 ${hostname}:${targetPort}`);
      }
      cleanup();
    });

    // 对于WebSocket连接，使用更长的超时时间
    const timeoutMs = hostname.includes('tradingview') || targetPort === 443 ? 60000 : this.timeout;

    clientSocket.setTimeout(timeoutMs, () => {
      console.log(`⏰ 客户端连接超时 ${hostname}:${targetPort}`);
      cleanup();
    });

    serverSocket.setTimeout(timeoutMs, () => {
      console.log(`⏰ 服务器连接超时 ${hostname}:${targetPort}`);
      cleanup();
    });

    // 处理意外断开
    clientSocket.on('end', () => {
      cleanup();
    });

    serverSocket.on('end', () => {
      cleanup();
    });
  }

  /**
   * 处理 HTTP/HTTPS 请求转发
   */
  private handleHttpRequest(req: IncomingMessage, res: ServerResponse): void {
    const targetUrl = req.url;

    // 严格的请求过滤 - 防止SSL数据被误解析为HTTP
    if (!targetUrl) {
      console.log('❌ HTTP请求缺少URL');
      res.writeHead(400, { 'Content-Type': 'text/plain; charset=utf-8' });
      res.end('缺少 URL');
      return;
    }

    // 检查请求方法 - 只处理标准HTTP方法
    const validMethods = ['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'PATCH'];
    if (!req.method || !validMethods.includes(req.method)) {
      console.log(`❌ 无效的HTTP方法: ${req.method}`);
      res.writeHead(405, { 'Content-Type': 'text/plain; charset=utf-8' });
      res.end(`不支持的HTTP方法: ${req.method}`);
      return;
    }

    // 严格URL验证 - 只处理绝对URL（代理请求）
    if (!targetUrl.startsWith('http://') && !targetUrl.startsWith('https://')) {
      // 检查是否是SSL握手数据被误解析（常见的SSL错误模式）
      if (req.headers && (
          !req.headers.host ||
          typeof req.headers.host !== 'string' ||
          req.headers.host.length > 255 ||
          /[\x00-\x1f\x7f-\xff]/.test(req.headers.host)
        )) {
        console.log('⚠️  疑似SSL数据被误解析为HTTP请求，拒绝处理');
        res.writeHead(400, { 'Content-Type': 'text/plain; charset=utf-8' });
        res.end('Bad Request - 请使用CONNECT方法建立SSL隧道');
        return;
      }

      // 对于非代理请求，返回代理配置说明
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(`
        <!DOCTYPE html>
        <html>
        <head>
          <title>🔒 HTTPS 代理服务器</title>
          <meta charset="utf-8">
          <style>
            body { font-family: Arial, sans-serif; margin: 40px; line-height: 1.6; }
            .container { max-width: 800px; margin: 0 auto; }
            .header { background: #2c3e50; color: white; padding: 20px; border-radius: 5px; }
            .content { background: #f8f9fa; padding: 20px; border-radius: 5px; margin-top: 20px; }
            pre { background: #343a40; color: #f8f9fa; padding: 15px; border-radius: 5px; overflow-x: auto; }
            .status { color: #28a745; font-weight: bold; }
            .warning { color: #dc3545; font-weight: bold; }
            .info { color: #007bff; font-weight: bold; }
            ul { list-style-type: none; padding: 0; }
            li { margin: 10px 0; padding: 10px; background: white; border-radius: 3px; }
          </style>
        </head>
        <body>
          <div class="container">
            <div class="header">
              <h1>🔒 HTTPS 代理服务器</h1>
              <p>端口: <span class="status">${this.port}</span> | 状态: <span class="status">运行中</span></p>
            </div>

            <div class="content">
              <h2>📋 使用说明</h2>
              <ul>
                <li><strong>🌐 浏览器设置:</strong> 设置HTTPS代理为 <code>127.0.0.1:${this.port}</code></li>
                <li><strong>📱 命令行设置:</strong>
                  <pre>export https_proxy=https://127.0.0.1:${this.port}</pre>
                </li>
                <li><strong>🧪 测试Binance API (忽略证书验证):</strong>
                  <pre>curl --proxy-insecure --proxy https://127.0.0.1:${this.port} https://api.binance.com/api/v3/ping</pre>
                </li>
                <li><strong>🔐 使用CA证书 (推荐):</strong>
                  <pre>curl --cacert certs/ca.crt --proxy https://127.0.0.1:${this.port} https://api.binance.com/api/v3/ping</pre>
                </li>
                <li><strong>🌐 WebSocket测试 (WSS):</strong>
                  <pre># 使用wscat测试WebSocket连接
export https_proxy=https://127.0.0.1:${this.port}
wscat -c wss://echo.websocket.org --ca certs/ca.crt</pre>
                </li>
                <li><strong>📦 安装CA证书到系统:</strong>
                  <pre># macOS
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain certs/ca.crt

# Linux (Ubuntu/Debian)
sudo cp certs/ca.crt /usr/local/share/ca-certificates/
sudo update-ca-certificates</pre>
                </li>
              </ul>

              <h2>⚙️ 证书信息</h2>
              <p><span class="info">CA证书:</span> certs/ca.crt</p>
              <p><span class="info">服务器证书:</span> certs/server.crt</p>
              <p><span class="warning">注意:</span> 使用自签名证书，需要添加 <code>--proxy-insecure</code> 参数或安装CA证书</p>

              <h2>🚀 支持的功能</h2>
              <ul>
                <li>✅ HTTPS CONNECT 隧道</li>
                <li>✅ HTTP/HTTPS 请求转发</li>
                <li>✅ WebSocket (WSS) 透明转发</li>
                <li>✅ Binance API 访问</li>
                <li>✅ SSL/TLS 安全连接</li>
                <li>✅ 代理链支持</li>
              </ul>
            </div>
          </div>
        </body>
        </html>
      `);
      return;
    }

    console.log(`🌐 ${req.method} ${targetUrl} - ${new Date().toISOString()}`);

    // URL解析和验证
    let parsedUrl: URL;
    try {
      parsedUrl = new URL(targetUrl);
    } catch (error) {
      console.error(`❌ 无效的URL: ${targetUrl}`, error);
      res.writeHead(400, { 'Content-Type': 'text/plain; charset=utf-8' });
      res.end(`无效的URL: ${targetUrl}`);
      return;
    }

    // 额外的URL验证 - 确保协议正确
    if (parsedUrl.protocol !== 'http:' && parsedUrl.protocol !== 'https:') {
      console.error(`❌ 不支持的协议: ${parsedUrl.protocol}`);
      res.writeHead(400, { 'Content-Type': 'text/plain; charset=utf-8' });
      res.end(`不支持的协议: ${parsedUrl.protocol}`);
      return;
    }

    const isHttps = parsedUrl.protocol === 'https:';
    const httpModule = isHttps ? https : http;

    // 创建代理Agent（如果有上游代理）
    const proxyAgent = this.createProxyAgent(targetUrl, false);

    const options = {
      hostname: parsedUrl.hostname,
      port: parsedUrl.port || (isHttps ? 443 : 80),
      path: parsedUrl.pathname + parsedUrl.search,
      method: req.method,
      headers: { ...req.headers },
      // 对于HTTPS请求，使用默认的系统CA验证目标服务器
      ...(isHttps && {
        rejectUnauthorized: true,
        // 使用代理Agent或创建新的HTTPS Agent
        agent: proxyAgent || new https.Agent({
          rejectUnauthorized: true,
          keepAlive: false
        })
      }),
      // 对于HTTP请求，也可能需要代理Agent
      ...(!isHttps && proxyAgent && { agent: proxyAgent })
    };

    // 清理可能有问题的 headers - 防止SSL协议错误
    delete options.headers.host;
    delete options.headers['proxy-connection'];
    delete options.headers['proxy-authorization'];
    delete options.headers.connection;
    delete options.headers['upgrade'];
    delete options.headers['sec-websocket-key'];
    delete options.headers['sec-websocket-version'];
    delete options.headers['sec-websocket-protocol'];

    // 设置正确的Host头
    if (parsedUrl.hostname) {
      options.headers.host = parsedUrl.hostname;
      // URL API的port属性已经是字符串，如果有端口且不是默认端口则添加
      if (parsedUrl.port || (!isHttps && parsedUrl.port !== '80') || (isHttps && parsedUrl.port !== '443')) {
        if (parsedUrl.port) {
          options.headers.host += `:${parsedUrl.port}`;
        }
      }
    }

    const proxyReq = httpModule.request(options, (proxyRes) => {
      console.log(`📥 响应: ${proxyRes.statusCode} ${targetUrl}`);

      // 转发响应头和状态码
      res.writeHead(proxyRes.statusCode || 200, proxyRes.headers);
      proxyRes.pipe(res);
    });

    proxyReq.on('error', (err: Error) => {
      console.error(`❌ 请求错误 ${targetUrl}:`, err.message);
      if (!res.headersSent) {
        res.writeHead(502, { 'Content-Type': 'text/plain; charset=utf-8' });
        res.end(`代理错误: ${err.message}`);
      }
    });

    proxyReq.setTimeout(this.timeout, () => {
      console.log(`⏰ 请求超时 ${targetUrl}`);
      proxyReq.destroy();
      if (!res.headersSent) {
        res.writeHead(504, { 'Content-Type': 'text/plain; charset=utf-8' });
        res.end('请求超时');
      }
    });

    // 转发请求体
    req.pipe(proxyReq);
  }

  /**
   * 启动HTTPS代理服务器
   */
  public start(): Promise<void> {
    return new Promise((resolve, reject) => {
      const server = https.createServer(this.httpsOptions, (req, res) => {
        // 添加 CORS 头
        res.setHeader('Access-Control-Allow-Origin', '*');
        res.setHeader('Access-Control-Allow-Methods', '*');
        res.setHeader('Access-Control-Allow-Headers', '*');

        if (req.method === 'OPTIONS') {
          res.writeHead(200);
          res.end();
          return;
        }

        this.handleHttpRequest(req, res);
      });

      // 处理 HTTPS CONNECT 请求
      server.on('connect', this.handleConnect.bind(this));

      server.on('error', (err) => {
        console.error('❌ 服务器错误:', err);
        // 只在启动阶段拒绝Promise，运行时错误不应该停止服务器
        if (!server.listening) {
          reject(err);
        } else {
          console.error('服务器运行时错误，但继续运行...');
        }
      });

      server.on('clientError', (err: any, socket) => {
        // 过滤常见的客户端错误，包括EPROTO错误
        const isCommonError = err.message.includes('ECONNRESET') ||
                             err.message.includes('Parse Error') ||
                             err.message.includes('HPE_INVALID_METHOD') ||
                             err.message.includes('socket hang up') ||
                             err.message.includes('wrong version number') ||
                             err.message.includes('SSL_ERROR_WANT_READ') ||
                             err.message.includes('SSL_ERROR_WANT_WRITE') ||
                             err.code === 'EPROTO';

        // 特殊处理EPROTO错误 - 增强诊断信息
        if (err.code === 'EPROTO' || err.message.includes('wrong version number')) {
          console.log(`⚠️  SSL协议版本错误 (EPROTO) - 可能原因:`);
          console.log('   1. 客户端使用HTTP协议连接HTTPS代理');
          console.log('   2. SSL/TLS版本不兼容');
          console.log('   3. 客户端发送了格式错误的SSL握手数据');
          console.log('💡 建议: 确保客户端使用HTTPS协议连接代理服务器');
        } else if (!isCommonError) {
          console.error('❌ 客户端错误:', err.message);
        } else {
          console.log(`⚠️  客户端连接问题 (${err.code || 'CLIENT_ERROR'})`);
        }

        try {
          if (socket && !socket.destroyed) {
            // 对于SSL协议错误，立即关闭连接避免进一步错误
            if (err.code === 'EPROTO' || err.message.includes('wrong version number')) {
              // socket.destroy();
            } else {
              socket.end('HTTP/1.1 400 Bad Request\r\n\r\n');
            }
          }
        } catch (cleanupErr) {
          // 忽略清理错误
        }
      });

      // 处理SSL握手错误 - 特别针对EPROTO协议版本错误优化
      server.on('tlsClientError', (err: any, tlsSocket) => {
        // 过滤常见的SSL握手错误，避免大量日志输出
        const isCommonSSLError = err.message.includes('Client network socket disconnected') ||
                                err.message.includes('before secure TLS connection') ||
                                err.message.includes('ECONNRESET') ||
                                err.message.includes('PROTOCOL_WRONG_VERSION') ||
                                err.message.includes('SSL routines') ||
                                err.message.includes('socket hang up') ||
                                err.message.includes('wrong version number') ||
                                err.message.includes('SSL_ERROR_WANT_READ') ||
                                err.message.includes('SSL_ERROR_WANT_WRITE') ||
                                err.message.includes('TLSV1_ALERT_PROTOCOL_VERSION') ||
                                err.code === 'EPROTO';

        // 特殊处理EPROTO错误 - 增强诊断
        if (err.code === 'EPROTO' || err.message.includes('wrong version number')) {
          console.log(`⚠️  SSL协议版本错误 (EPROTO) - 详细诊断:`);
          console.log('   可能原因:');
          console.log('   1. 客户端使用HTTP协议连接HTTPS代理服务器');
          console.log('   2. SSL/TLS版本不兼容 (代理支持TLSv1.2-1.3)');
          console.log('   3. 客户端发送了格式错误的SSL握手数据');
          console.log('   4. 防火墙或中间件篡改了SSL数据包');
          console.log('💡 解决方案:');
          console.log('   - 确保客户端配置使用HTTPS代理 (https://127.0.0.1:10443)');
          console.log('   - 检查客户端SSL/TLS设置，确保支持TLSv1.2或更高版本');
          console.log('   - 使用 openssl s_client 测试SSL连接');
        } else if (err.message.includes('TLSV1_ALERT_PROTOCOL_VERSION')) {
          console.log(`⚠️  TLS版本协商失败 - 客户端可能使用了过旧的TLS版本`);
          console.log('💡 提示: 代理服务器要求TLSv1.2或更高版本');
        } else if (!isCommonSSLError) {
          console.error('❌ TLS客户端错误:', err.message);

          // 如果是证书错误，提供解决方案
          if (err.message.includes('unknown ca') || err.message.includes('self signed')) {
            console.error('💡 提示: 客户端不信任代理服务器的CA证书');
            console.error('   解决方案1: 使用 curl --proxy-insecure 参数忽略证书验证');
            console.error('   解决方案2: 使用 --cacert certs/ca.crt 参数指定CA证书');
            console.error('   解决方案3: 将 certs/ca.crt 安装到系统信任的证书存储中');
          }
        } else {
          // 对常见SSL错误，只记录简要信息
          console.log(`⚠️  SSL握手断开 (${err.code || 'TLS_ERROR'})`);
        }

        // 优雅处理错误，不让服务器崩溃
        try {
          if (tlsSocket && !tlsSocket.destroyed) {
            // 对于协议版本错误，直接关闭连接
            if (err.code === 'EPROTO' || err.message.includes('wrong version number')) {
              tlsSocket.destroy();
            } else {
              tlsSocket.end();
            }
          }
        } catch (cleanupErr) {
          console.error('清理TLS连接时出错:', cleanupErr instanceof Error ? cleanupErr.message : String(cleanupErr));
        }
      });

      server.listen(this.port, '0.0.0.0', () => {
        console.log('');
        console.log('🚀 HTTPS 代理服务器启动成功！');
        console.log('═══════════════════════════════════');
        console.log(`📍 监听地址: https://0.0.0.0:${this.port}`);
        console.log(`🔒 使用HTTPS协议 (SSL/TLS)`);
        console.log(`📋 管理界面: https://127.0.0.1:${this.port}`);
        console.log(`🌐 代理设置: https://127.0.0.1:${this.port}`);
        if (this.upstreamProxy) {
          console.log(`🔗 上游代理: ${this.upstreamProxy}`);
        }
        console.log('');
        console.log('📝 测试命令:');
        console.log(`   curl --proxy-insecure --proxy https://127.0.0.1:${this.port} https://api.binance.com/api/v3/ping`);
        console.log('');
        console.log('🌐 WebSocket测试:');
        console.log(`   export https_proxy=https://127.0.0.1:${this.port}`);
        console.log(`   wscat -c wss://echo.websocket.org --ca certs/ca.crt`);
        console.log('');
        console.log('🔐 使用CA证书 (更安全):');
        console.log(`   curl --cacert certs/ca.crt --proxy https://127.0.0.1:${this.port} https://api.binance.com/api/v3/ping`);
        console.log('');
        console.log('🔧 环境变量设置:');
        console.log(`   export https_proxy=https://127.0.0.1:${this.port}`);
        console.log(`   export SSL_CERT_FILE=certs/ca.crt  # 某些工具可能需要`);
        console.log('');
        console.log('⚠️  注意: 使用自签名证书，需要以下任一方法:');
        console.log('   1. 使用 -k/--proxy-insecure 参数忽略证书验证');
        console.log('   2. 使用 --cacert 参数指定CA证书');
        console.log('   3. 将CA证书安装到系统信任存储');
        console.log('═══════════════════════════════════');
        console.log('');
        resolve();
      });
    });
  }
}

// 导出
export default HttpsProxy;

// 如果直接运行此文件
if (require.main === module) {
  // 添加全局异常处理，防止服务器意外退出
  process.on('uncaughtException', (error) => {
    console.error('❌ 未捕获的异常:', error.message);
    console.error('📍 错误堆栈:', error.stack);
    console.log('🔄 服务器继续运行...');
  });

  process.on('unhandledRejection', (reason, promise) => {
    console.error('❌ 未处理的Promise拒绝:', reason);
    console.error('📍 Promise:', promise);
    console.log('🔄 服务器继续运行...');
  });

  const proxy = new HttpsProxy({
    port: parseInt(process.env.HTTPS_PROXY_PORT || '10443'),
    timeout: parseInt(process.env.PROXY_TIMEOUT || '30000')
  });

  proxy.start().catch((error) => {
    console.error('❌ 启动代理服务器失败:', error.message);
    process.exit(1);
  });

  // 优雅关闭处理
  process.on('SIGINT', () => {
    console.log('\n👋 正在关闭HTTPS代理服务器...');
    process.exit(0);
  });

  process.on('SIGTERM', () => {
    console.log('\n👋 正在关闭HTTPS代理服务器...');
    process.exit(0);
  });
}

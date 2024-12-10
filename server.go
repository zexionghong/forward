package main

import (
    "crypto/tls"
    "fmt"
    "io"
    "log"
    "net"
    "sync"
)

type ProxyServer struct {
    HTTPHost    string
    HTTPPort    int
    SOCKS5Host  string
    SOCKS5Port  int
    TLSConfig   *tls.Config
    logger      *log.Logger
}

func NewProxyServer(httpHost string, httpPort int,
    socks5Host string, socks5Port int,
    certFile, keyFile string) *ProxyServer {
    
    // 加载TLS证书
    cert, err := tls.LoadX509KeyPair(certFile, keyFile)
    if err != nil {
        log.Fatalf("加载证书失败: %v", err)
    }

    tlsConfig := &tls.Config{
        Certificates: []tls.Certificate{cert},
        MinVersion:   tls.VersionTLS12,
    }

    return &ProxyServer{
        HTTPHost:   httpHost,
        HTTPPort:   httpPort,
        SOCKS5Host: socks5Host,
        SOCKS5Port: socks5Port,
        TLSConfig:  tlsConfig,
        logger:     log.Default(),
    }
}

func (ps *ProxyServer) handleHTTPProxy(conn net.Conn) {
    defer conn.Close()
    
    ps.logger.Printf("收到新的HTTP代理请求: %s", conn.RemoteAddr().String())
    
    targetConn, err := net.Dial("tcp", fmt.Sprintf("%s:%d", ps.HTTPHost, ps.HTTPPort))
    if err != nil {
        ps.logger.Printf("连接目标HTTP服务器失败: %v", err)
        return
    }
    defer targetConn.Close()

    ps.logger.Printf("成功连接到HTTP目标服务器: %s:%d", ps.HTTPHost, ps.HTTPPort)
    ps.startForwarding(conn, targetConn)
}

func (ps *ProxyServer) handleSOCKS5Proxy(conn net.Conn) {
    defer conn.Close()
    
    ps.logger.Printf("收到新的SOCKS5代理请求: %s", conn.RemoteAddr().String())
    
    targetConn, err := net.Dial("tcp", fmt.Sprintf("%s:%d", ps.SOCKS5Host, ps.SOCKS5Port))
    if err != nil {
        ps.logger.Printf("连接目标SOCKS5服务器失败: %v", err)
        return
    }
    defer targetConn.Close()

    ps.logger.Printf("成功连接到SOCKS5目标服务器: %s:%d", ps.SOCKS5Host, ps.SOCKS5Port)
    ps.startForwarding(conn, targetConn)
}

func (ps *ProxyServer) startForwarding(conn1, conn2 net.Conn) {
    var wg sync.WaitGroup
    wg.Add(2)

    copy := func(dst, src net.Conn) {
        defer wg.Done()
        written, err := io.Copy(dst, src)
        if err != nil {
            ps.logger.Printf("数据转发错误: %v", err)
        }
        ps.logger.Printf("转发完成 %d 字节数据", written)
    }

    ps.logger.Printf("开始双向数据转发")
    go copy(conn1, conn2)
    go copy(conn2, conn1)

    wg.Wait()
    ps.logger.Printf("数据转发结束")
}

func (ps *ProxyServer) Start() {
    ps.logger.Printf("代理服务器启动中...")
    
    // 启动HTTP代理监听
    go ps.startListener(ps.HTTPPort, ps.handleHTTPProxy)
    
    // 启动SOCKS5代理监听
    go ps.startListener(ps.SOCKS5Port, ps.handleSOCKS5Proxy)

    ps.logger.Printf("代理服务器启动完成")
    
    // 阻塞主线程
    select {}
}

func (ps *ProxyServer) startListener(port int, handler func(net.Conn)) {
    listener, err := tls.Listen("tcp", fmt.Sprintf(":%d", port), ps.TLSConfig)
    if err != nil {
        ps.logger.Fatalf("监听端口 %d 失败: %v", port, err)
    }
    defer listener.Close()

    ps.logger.Printf("服务启动在端口 %d", port)

    for {
        conn, err := listener.Accept()
        if err != nil {
            ps.logger.Printf("接受连接失败: %v", err)
            continue
        }

        ps.logger.Printf("接受新连接: %s", conn.RemoteAddr().String())
        go handler(conn)
    }
}

func main() {
    // 配置日志
    logger := log.New(io.MultiWriter(log.Writer()), "[PROXY] ", log.LstdFlags|log.Lshortfile)

    // 服务器配置
    HTTP_HOST := "43.198.80.215"
    HTTP_PORT := 12345
    SOCKS5_HOST := "43.198.80.215" 
    SOCKS5_PORT := 12346

    // TLS证书文件路径
    CERT_FILE := "server.crt"
    KEY_FILE := "server.key"

    logger.Printf("初始化代理服务器...")
    server := NewProxyServer(
        HTTP_HOST, HTTP_PORT,
        SOCKS5_HOST, SOCKS5_PORT,
        CERT_FILE, KEY_FILE)

    server.logger = logger
    server.Start()
} 
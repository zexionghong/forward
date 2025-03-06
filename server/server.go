package main

import (
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
)

type ProxyServer struct {
	HTTPHost        string
	HTTPPort        int
	SOCKS5Host      string
	SOCKS5Port      int
	TLSConfig       *tls.Config
	logger          *log.Logger
	localHTTPPort   int
	localSocks5Port int
}

// SOCKS5 协议常量
const (
	SOCKS5_VERSION = 0x05
	NO_AUTH        = 0x00
	NO_ACCEPTABLE  = 0xFF
	CONNECT        = 0x01
	IPV4           = 0x01
	DOMAIN         = 0x03
	IPV6           = 0x04
)

func NewProxyServer(httpHost string, httpPort int,
	socks5Host string, socks5Port int,
	certFile, keyFile string,
	localHTTPPort int, localSocks5Port int) *ProxyServer {

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
		HTTPHost:        httpHost,
		HTTPPort:        httpPort,
		SOCKS5Host:      socks5Host,
		SOCKS5Port:      socks5Port,
		TLSConfig:       tlsConfig,
		logger:          log.Default(),
		localHTTPPort:   localHTTPPort,
		localSocks5Port: localSocks5Port,
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

	// 1. 版本识别和方法选择
	if err := ps.handleHandshake(conn); err != nil {
		ps.logger.Printf("SOCKS5握手失败: %v", err)
		return
	}

	// 2. 处理客户端请求
	targetAddr, err := ps.handleRequest(conn)
	if err != nil {
		ps.logger.Printf("处理SOCKS5请求失败: %v", err)
		return
	}

	// 3. 建立到目标服务器的连接
	targetConn, err := net.Dial("tcp", targetAddr)
	if err != nil {
		ps.logger.Printf("连接目标服务器失败: %v", err)
		ps.sendReply(conn, 0x04) // Host unreachable
		return
	}
	defer targetConn.Close()

	// 4. 发送成功响应
	if err := ps.sendReply(conn, 0x00); err != nil {
		ps.logger.Printf("发送SOCKS5响应失败: %v", err)
		return
	}

	// 5. 开始数据转发
	ps.startForwarding(conn, targetConn)
}

func (ps *ProxyServer) handleHandshake(conn net.Conn) error {
	// 读取版本和支持的认证方法数量
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return err
	}

	if header[0] != SOCKS5_VERSION {
		return errors.New("不支持的SOCKS版本")
	}

	methodCount := int(header[1])
	methods := make([]byte, methodCount)
	if _, err := io.ReadFull(conn, methods); err != nil {
		return err
	}

	// 检查是否支持无认证方式
	hasNoAuth := false
	for _, method := range methods {
		if method == NO_AUTH {
			hasNoAuth = true
			break
		}
	}

	// 发送认证方法选择响应
	response := []byte{SOCKS5_VERSION, NO_AUTH}
	if !hasNoAuth {
		response[1] = NO_ACCEPTABLE
	}

	if _, err := conn.Write(response); err != nil {
		return err
	}

	if !hasNoAuth {
		return errors.New("没有可接受的认证方法")
	}

	return nil
}

func (ps *ProxyServer) handleRequest(conn net.Conn) (string, error) {
	// 读取请求头
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return "", err
	}

	if header[0] != SOCKS5_VERSION {
		return "", errors.New("无效的SOCKS5请求")
	}

	if header[1] != CONNECT {
		return "", errors.New("仅支持CONNECT命令")
	}

	// 解析目标地址
	var targetAddr string
	switch header[3] {
	case IPV4:
		addr := make([]byte, 4)
		if _, err := io.ReadFull(conn, addr); err != nil {
			return "", err
		}
		targetAddr = net.IP(addr).String()

	case DOMAIN:
		domainLen := make([]byte, 1)
		if _, err := io.ReadFull(conn, domainLen); err != nil {
			return "", err
		}
		domain := make([]byte, domainLen[0])
		if _, err := io.ReadFull(conn, domain); err != nil {
			return "", err
		}
		targetAddr = string(domain)

	case IPV6:
		addr := make([]byte, 16)
		if _, err := io.ReadFull(conn, addr); err != nil {
			return "", err
		}
		targetAddr = net.IP(addr).String()

	default:
		return "", errors.New("不支持的地址类型")
	}

	// 读取端口
	portBytes := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBytes); err != nil {
		return "", err
	}
	port := binary.BigEndian.Uint16(portBytes)

	return fmt.Sprintf("%s:%d", targetAddr, port), nil
}

func (ps *ProxyServer) sendReply(conn net.Conn, replyCode byte) error {
	reply := []byte{
		SOCKS5_VERSION, // 版本
		replyCode,      // 响应码
		0x00,           // 保留字段
		0x01,           // IPv4地址类型
		0, 0, 0, 0,     // 绑定地址
		0, 0, // 绑定端口
	}
	_, err := conn.Write(reply)
	return err
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
	go ps.startListener(ps.localHTTPPort, ps.handleHTTPProxy)

	// 启动SOCKS5代理监听
	go ps.startListener(ps.localSocks5Port, ps.handleSOCKS5Proxy)

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
	REMOTE_HTTP_HOST := "127.0.0.1"
	REMOTE_HTTP_PORT := 12345
	REMOTE_SOCKS5_HOST := "127.0.0.1"
	REMOTE_SOCKS5_PORT := 12346

	LOCAL_HTTP_PORT := 12347
	LOCAL_SOCKS5_PORT := 12348

	// TLS证书文件路径
	CERT_FILE := "server.crt"
	KEY_FILE := "server.key"

	logger.Printf("初始化代理服务器...")
	server := NewProxyServer(
		REMOTE_HTTP_HOST, REMOTE_HTTP_PORT,
		REMOTE_SOCKS5_HOST, REMOTE_SOCKS5_PORT,
		CERT_FILE, KEY_FILE,
		LOCAL_HTTP_PORT, LOCAL_SOCKS5_PORT)

	server.logger = logger
	server.Start()
}

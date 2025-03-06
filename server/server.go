package main

import (
	"crypto/tls"
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
	Username        string
	Password        string
}

// SOCKS5 协议常量
const (
	SOCKS5_VERSION = 0x05
	NO_AUTH        = 0x00
	USER_PASS_AUTH = 0x02
	NO_ACCEPTABLE  = 0xFF
	CONNECT        = 0x01
	IPV4           = 0x01
	DOMAIN         = 0x03
	IPV6           = 0x04

	// 用户名密码认证版本
	USER_PASS_VERSION = 0x01
	AUTH_SUCCESS      = 0x00
	AUTH_FAILURE      = 0x01
)

func NewProxyServer(httpHost string, httpPort int,
	socks5Host string, socks5Port int,
	certFile, keyFile string,
	localHTTPPort int, localSocks5Port int,
	username, password string) *ProxyServer {

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
		Username:        username,
		Password:        password,
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

	// 1. 与客户端完成握手认证
	if err := ps.handleHandshake(conn); err != nil {
		ps.logger.Printf("SOCKS5握手失败: %v", err)
		return
	}

	// 2. 连接到远程SOCKS5服务器
	targetConn, err := net.Dial("tcp", fmt.Sprintf("%s:%d", ps.SOCKS5Host, ps.SOCKS5Port))
	if err != nil {
		ps.logger.Printf("连接远程SOCKS5服务器失败: %v", err)
		return
	}
	defer targetConn.Close()

	// 3. 与远程SOCKS5服务器完成握手认证
	if err := ps.handleRemoteHandshake(targetConn); err != nil {
		ps.logger.Printf("与远程SOCKS5服务器握手失败: %v", err)
		return
	}

	// 4. 读取客户端请求
	request, err := ps.readClientRequest(conn)
	if err != nil {
		ps.logger.Printf("读取客户端请求失败: %v", err)
		return
	}

	// 5. 转发请求到远程SOCKS5服务器
	if _, err := targetConn.Write(request); err != nil {
		ps.logger.Printf("转发请求到远程服务器失败: %v", err)
		return
	}

	// 6. 读取远程服务器响应
	reply := make([]byte, 10)
	if _, err := io.ReadFull(targetConn, reply); err != nil {
		ps.logger.Printf("读取远程服务器响应失败: %v", err)
		return
	}

	// 7. 将响应转发给客户端
	if _, err := conn.Write(reply); err != nil {
		ps.logger.Printf("发送响应给客户端失败: %v", err)
		return
	}

	// 8. 开始双向数据转发
	ps.startForwarding(conn, targetConn)
}

func (ps *ProxyServer) handleHandshake(conn net.Conn) error {
	// 读取版本和支持的认证方法数量
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return err
	}

	ps.logger.Printf("SOCKS5握手 - 版本: %d, 方法数量: %d", header[0], header[1])

	if header[0] != SOCKS5_VERSION {
		return errors.New("不支持的SOCKS版本")
	}

	methodCount := int(header[1])
	methods := make([]byte, methodCount)
	if _, err := io.ReadFull(conn, methods); err != nil {
		return err
	}

	ps.logger.Printf("客户端支持的认证方法: %v", methods)

	// 检查认证方法
	hasNoAuth := false
	for _, method := range methods {
		if method == NO_AUTH {
			hasNoAuth = true
			break
		}
	}

	if !hasNoAuth {
		return errors.New("客户端必须支持无认证方法")
	}

	// 与客户端使用无认证方法
	response := []byte{SOCKS5_VERSION, NO_AUTH}
	if _, err := conn.Write(response); err != nil {
		return err
	}

	ps.logger.Printf("发送认证方法选择响应: 版本=%d, 方法=%d", response[0], response[1])
	return nil
}

func (ps *ProxyServer) handleRemoteHandshake(conn net.Conn) error {
	// 发送握手请求到远程SOCKS5服务器，只提供用户名密码认证方法
	methods := []byte{
		SOCKS5_VERSION,
		1,               // 1个认证方法
		USER_PASS_AUTH, // 只使用用户名密码认证
	}
	
	if _, err := conn.Write(methods); err != nil {
		return fmt.Errorf("发送握手请求失败: %v", err)
	}

	// 读取响应
	response := make([]byte, 2)
	if _, err := io.ReadFull(conn, response); err != nil {
		return fmt.Errorf("读取握手响应失败: %v", err)
	}

	if response[0] != SOCKS5_VERSION {
		return errors.New("远程服务器SOCKS5版本不匹配")
	}

	if response[1] != USER_PASS_AUTH {
		return errors.New("远程服务器不接受用户名密码认证")
	}

	// 发送用户名密码认证
	auth := []byte{USER_PASS_VERSION}
	auth = append(auth, byte(len(ps.Username)))
	auth = append(auth, []byte(ps.Username)...)
	auth = append(auth, byte(len(ps.Password)))
	auth = append(auth, []byte(ps.Password)...)

	ps.logger.Printf("向远程服务器发送认证 - 用户名: '%s', 密码: '%s'", ps.Username, ps.Password)

	if _, err := conn.Write(auth); err != nil {
		return fmt.Errorf("发送用户名密码认证失败: %v", err)
	}

	// 读取认证响应
	authResponse := make([]byte, 2)
	if _, err := io.ReadFull(conn, authResponse); err != nil {
		return fmt.Errorf("读取认证响应失败: %v", err)
	}

	if authResponse[0] != USER_PASS_VERSION || authResponse[1] != AUTH_SUCCESS {
		return errors.New("远程服务器认证失败")
	}

	ps.logger.Printf("远程服务器认证成功")
	return nil
}

func (ps *ProxyServer) readClientRequest(conn net.Conn) ([]byte, error) {
	// 读取请求头
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, err
	}

	if header[0] != SOCKS5_VERSION {
		return nil, errors.New("无效的SOCKS5请求")
	}

	// 根据地址类型读取剩余数据
	var remainingBytes int
	switch header[3] {
	case IPV4:
		remainingBytes = 4 + 2 // IPv4(4) + Port(2)
	case IPV6:
		remainingBytes = 16 + 2 // IPv6(16) + Port(2)
	case DOMAIN:
		domainLen := make([]byte, 1)
		if _, err := io.ReadFull(conn, domainLen); err != nil {
			return nil, err
		}
		remainingBytes = int(domainLen[0]) + 2 // Domain + Port(2)
		header = append(header, domainLen[0])
	default:
		return nil, errors.New("不支持的地址类型")
	}

	// 读取剩余数据
	remaining := make([]byte, remainingBytes)
	if _, err := io.ReadFull(conn, remaining); err != nil {
		return nil, err
	}

	// 合并完整请求
	request := append(header, remaining...)
	return request, nil
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

	// 设置远程SOCKS5服务器的认证信息
	REMOTE_USERNAME := "afiL3jfPEGis"
	REMOTE_PASSWORD := "Z6b6uUeo"

	logger.Printf("初始化代理服务器...")
	server := NewProxyServer(
		REMOTE_HTTP_HOST, REMOTE_HTTP_PORT,
		REMOTE_SOCKS5_HOST, REMOTE_SOCKS5_PORT,
		CERT_FILE, KEY_FILE,
		LOCAL_HTTP_PORT, LOCAL_SOCKS5_PORT,
		REMOTE_USERNAME, REMOTE_PASSWORD) // 使用远程服务器的认证信息

	server.logger = logger
	server.Start()
}

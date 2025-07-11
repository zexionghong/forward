package main

import (
	"bufio"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
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
	Username        string // 默认用户名（仅作为后备）
	Password        string // 默认密码（仅作为后备）
	clientUsername  string // 保存客户端SOCKS5用户名
	clientPassword  string // 保存客户端SOCKS5密码
	clientIP        string // 保存客户端IP地址
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

	// 获取客户端IP地址
	clientIP := conn.RemoteAddr().(*net.TCPAddr).IP.String()
	ps.clientIP = clientIP

	targetConn, err := net.Dial("tcp", fmt.Sprintf("%s:%d", ps.HTTPHost, ps.HTTPPort))
	if err != nil {
		ps.logger.Printf("连接目标HTTP服务器失败: %v", err)
		return
	}
	defer targetConn.Close()

	// 读取HTTP请求头
	reader := bufio.NewReader(conn)
	request, err := reader.ReadString('\n')
	if err != nil {
		ps.logger.Printf("读取HTTP请求失败: %v", err)
		return
	}

	// 如果请求中包含Proxy-Authorization头，提取用户名
	username := ps.Username // 默认使用配置的用户名
	for {
		line, err := reader.ReadString('\n')
		if err != nil || line == "\r\n" {
			break
		}
		if strings.HasPrefix(strings.ToLower(line), "proxy-authorization:") {
			auth := strings.TrimSpace(strings.TrimPrefix(strings.ToLower(line), "proxy-authorization:"))
			if strings.HasPrefix(auth, "basic ") {
				decoded, err := base64.StdEncoding.DecodeString(auth[6:])
				if err == nil {
					parts := strings.SplitN(string(decoded), ":", 2)
					if len(parts) == 2 {
						username = parts[0]
					}
				}
			}
		}
	}

	// 构造新的认证头
	newAuth := fmt.Sprintf("%s,%s", clientIP, username)
	authHeader := fmt.Sprintf("Proxy-Authorization: Basic %s\r\n",
		base64.StdEncoding.EncodeToString([]byte(newAuth+":"+ps.Password)))

	// 重新构造请求
	newRequest := request
	if !strings.Contains(strings.ToLower(request), "proxy-authorization:") {
		newRequest = strings.TrimRight(request, "\r\n") + "\r\n" + authHeader
	}

	// 发送修改后的请求
	if _, err := targetConn.Write([]byte(newRequest)); err != nil {
		ps.logger.Printf("发送HTTP请求失败: %v", err)
		return
	}

	ps.startForwarding(conn, targetConn)
}

func (ps *ProxyServer) handleSOCKS5Proxy(conn net.Conn) {
	defer conn.Close()

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

	if header[0] != SOCKS5_VERSION {
		return errors.New("不支持的SOCKS版本")
	}

	methodCount := int(header[1])
	methods := make([]byte, methodCount)
	if _, err := io.ReadFull(conn, methods); err != nil {
		return err
	}

	// 检查支持的认证方法
	var useUserPassAuth bool
	for _, method := range methods {
		if method == USER_PASS_AUTH {
			useUserPassAuth = true
			break
		}
	}

	// 如果客户端支持用户名/密码认证，选择此方法
	if useUserPassAuth {
		// 告诉客户端使用用户名/密码认证
		response := []byte{SOCKS5_VERSION, USER_PASS_AUTH}
		if _, err := conn.Write(response); err != nil {
			return err
		}

		// 读取认证信息
		authHeader := make([]byte, 2)
		if _, err := io.ReadFull(conn, authHeader); err != nil {
			return err
		}

		if authHeader[0] != USER_PASS_VERSION {
			return errors.New("不支持的用户名/密码认证版本")
		}

		// 读取用户名
		userLen := int(authHeader[1])
		username := make([]byte, userLen)
		if _, err := io.ReadFull(conn, username); err != nil {
			return err
		}

		// 读取密码
		passLenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, passLenBuf); err != nil {
			return err
		}
		passLen := int(passLenBuf[0])
		password := make([]byte, passLen)
		if _, err := io.ReadFull(conn, password); err != nil {
			return err
		}

		// 保存客户端的用户名和密码以便后续使用
		ps.clientUsername = string(username)
		ps.clientPassword = string(password)

		// 简单认证（这里可以实现实际的认证逻辑）
		authResponse := []byte{USER_PASS_VERSION, AUTH_SUCCESS}
		if _, err := conn.Write(authResponse); err != nil {
			return err
		}

		return nil
	}

	// 检查是否支持无认证方法
	hasNoAuth := false
	for _, method := range methods {
		if method == NO_AUTH {
			hasNoAuth = true
			break
		}
	}

	if !hasNoAuth {
		return errors.New("客户端必须支持无认证方法或用户名/密码认证")
	}

	// 与客户端使用无认证方法
	response := []byte{SOCKS5_VERSION, NO_AUTH}
	if _, err := conn.Write(response); err != nil {
		return err
	}

	return nil
}

func (ps *ProxyServer) handleRemoteHandshake(conn net.Conn) error {
	// 发送握手请求到远程SOCKS5服务器，只提供用户名密码认证方法
	methods := []byte{
		SOCKS5_VERSION,
		1,              // 1个认证方法
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

	// 使用客户端的用户名密码（如果有），否则使用默认值
	username := ps.clientUsername
	password := ps.clientPassword

	// 如果客户端没有提供认证信息，则使用默认值
	if username == "" || password == "" {
		username = ps.Username
		password = ps.Password
	}

	// 获取客户端IP（如果还没有设置）
	if ps.clientIP == "" {
		if tcpAddr, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
			ps.clientIP = tcpAddr.IP.String()
		} else {
			ps.clientIP = "unknown"
		}
	}

	// 构造新的用户名格式：ip,username
	newUsername := fmt.Sprintf("%s,%s", ps.clientIP, username)

	// 发送用户名密码认证
	auth := []byte{USER_PASS_VERSION}
	auth = append(auth, byte(len(newUsername)))
	auth = append(auth, []byte(newUsername)...)
	auth = append(auth, byte(len(password)))
	auth = append(auth, []byte(password)...)

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
		_, err := io.Copy(dst, src)
		if err != nil {
			ps.logger.Printf("数据转发错误: %v", err)
		}
	}

	go copy(conn1, conn2)
	go copy(conn2, conn1)

	wg.Wait()
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

	// 设置远程SOCKS5服务器的默认认证信息（仅作为后备）
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


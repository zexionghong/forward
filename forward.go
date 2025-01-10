package main

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type ProxyServer struct {
	LocalPorts       []int
	LocalHost        string
	RemoteHTTPHost   string
	RemoteHTTPPort   int
	RemoteSOCKS5Host string
	RemoteSOCKS5Port int
	TLSConfig        *tls.Config
	logger           *log.Logger
	bufferPool       sync.Pool
	ReadTimeout      time.Duration
	WriteTimeout     time.Duration
	activeConns      sync.Map
	debug            bool
	maxIdleConns     int32         // 最大连接数
	currentConns     int32         // 当前连接数
	idleTimeout      time.Duration // 空闲连接超时时间
}

//go:embed cert.pem key.pem server.crt
var certFiles embed.FS

func NewProxyServer(localHost string, localPorts []int,
	remoteHTTPHost string, remoteHTTPPort int,
	remoteSOCKS5Host string, remoteSOCKS5Port int,
	certFile, keyFile string) *ProxyServer {

	certPEM, err := certFiles.ReadFile(certFile)
	if err != nil {
		log.Fatalf("Failed to read certificate: %v", err)
	}

	keyPEM, err := certFiles.ReadFile(keyFile)
	if err != nil {
		log.Fatalf("Failed to read key: %v", err)
	}
	serverCert, err := certFiles.ReadFile("server.crt")
	if err != nil {
		log.Fatalf("Failed to read key: %v", err)
	}

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		log.Fatalf("加载证书失败: %v", err)
	}

	rootCAs := x509.NewCertPool()
	if !rootCAs.AppendCertsFromPEM(serverCert) {
		log.Fatalf("添加证书失败")
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      rootCAs,
		ServerName:   "43.198.80.215",
		MinVersion:   tls.VersionTLS12,
	}

	ps := &ProxyServer{
		LocalHost:        localHost,
		LocalPorts:       localPorts,
		RemoteHTTPHost:   remoteHTTPHost,
		RemoteHTTPPort:   remoteHTTPPort,
		RemoteSOCKS5Host: remoteSOCKS5Host,
		RemoteSOCKS5Port: remoteSOCKS5Port,
		TLSConfig:        tlsConfig,
		logger:           log.Default(),
		bufferPool: sync.Pool{
			New: func() interface{} {
				return make([]byte, 64*1024)
			},
		},
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		maxIdleConns: 500,             // 设置最大连接数为10
		idleTimeout:  5 * time.Minute, // 设置空闲超时时间
	}
	return ps
}

func (ps *ProxyServer) logDebug(format string, v ...interface{}) {
	if ps.debug {
		ps.logger.Printf(format, v...)
	}
}

func (ps *ProxyServer) detectProtocol(conn net.Conn) (string, []byte, error) {
	buf := make([]byte, 1)
	_, err := conn.Read(buf)
	if err != nil {
		return "", nil, err
	}

	firstByte := buf[0]

	if firstByte == 0x05 {
		return "socks5", buf, nil
	} else {
		return "http", buf, nil
	}
}

func (ps *ProxyServer) handleClient(conn net.Conn) {
	newCount := atomic.AddInt32(&ps.currentConns, 1)
	ps.logger.Printf("新建客户端连接: 当前连接数 %d", newCount)

	defer func() {
		conn.Close()
		currentCount := atomic.AddInt32(&ps.currentConns, -1)
		if currentCount < 0 {
			ps.logger.Printf("警告：连接数出现负数，重置为0")
			atomic.StoreInt32(&ps.currentConns, 0)
		} else {
			ps.logger.Printf("关闭客户端连接: 当前连接数 %d", currentCount)
		}
	}()

	// 设置读写超时
	if tc, ok := conn.(*net.TCPConn); ok {
		tc.SetReadDeadline(time.Now().Add(ps.ReadTimeout))
		tc.SetWriteDeadline(time.Now().Add(ps.WriteTimeout))
		tc.SetKeepAlive(true)
		tc.SetKeepAlivePeriod(30 * time.Second)
	}

	protocol, firstByte, err := ps.detectProtocol(conn)
	if err != nil {
		ps.logDebug("协议检测错误: %v", err)
		return
	}

	switch protocol {
	case "socks5":
		ps.handleSOCKS5(conn, firstByte)
	case "http":
		ps.handleHTTP(conn, firstByte)
	default:
		ps.logDebug("未知协议，关闭连接")
	}
}

func (ps *ProxyServer) handleHTTP(clientConn net.Conn, firstByte []byte) {
	defer clientConn.Close()
	reader := bufio.NewReader(clientConn)

	// 读取请求头
	requestData, err := ps.readHTTPRequest(firstByte, reader)
	if err != nil {
		ps.logDebug("读取 HTTP 请求错误: %v", err)
		return
	}

	username, password := ps.extractAuth(requestData)
	if username == "" || password == "" {
		ps.logDebug("HTTP 认证失败")
		response := "HTTP/1.1 407 Proxy Authentication Required\r\n"
		response += "Proxy-Authenticate: Basic realm=\"Proxy\"\r\n\r\n"
		clientConn.Write([]byte(response))
		return
	}

	remoteConn, err := ps.dialRemote("tcp", fmt.Sprintf("%s:%d", ps.RemoteHTTPHost, ps.RemoteHTTPPort))
	if err != nil {
		ps.logDebug("连接远程 HTTP 代理错误")
		return
	}
	defer remoteConn.Close()

	remoteConn.Write(requestData)

	ps.startForwarding(clientConn, remoteConn)
}

func (ps *ProxyServer) handleSOCKS5(clientConn net.Conn, firstByte []byte) {
	defer clientConn.Close()
	reader := bufio.NewReader(clientConn)

	// 读取 nmethods
	nmethodsByte := make([]byte, 1)
	_, err := io.ReadFull(reader, nmethodsByte)
	if err != nil {
		ps.logDebug("读取 nmethods 错误")
		return
	}
	nmethods := int(nmethodsByte[0])

	// 读取 methods
	methods := make([]byte, nmethods)
	_, err = io.ReadFull(reader, methods)
	if err != nil {
		ps.logDebug("读取 methods 错误")
		return
	}

	// 连接到远程 SOCKS5 服务器
	remoteConn, err := ps.dialRemote("tcp", fmt.Sprintf("%s:%d", ps.RemoteSOCKS5Host, ps.RemoteSOCKS5Port))
	if err != nil {
		ps.logDebug("连接远程 SOCKS5 代理错误")
		return
	}
	defer remoteConn.Close()

	// 将握手数据转发给远程 SOCKS5 服务器
	remoteConn.Write(append(firstByte, nmethodsByte...))
	remoteConn.Write(methods)

	// 从远程 SOCKS5 服务器读取握手响应
	authResponse := make([]byte, 2)
	_, err = io.ReadFull(remoteConn, authResponse)
	if err != nil {
		ps.logDebug("读取远程 SOCKS5 握手响应错误")
		return
	}

	// 将握手响应发回客户端
	clientConn.Write(authResponse)

	if authResponse[1] == 0x02 {
		// 用户名/密码认证
		ps.logDebug("SOCKS5 开始用户认证")

		// 读取客户端的认证请求
		authVerAndUlen := make([]byte, 2)
		_, err = io.ReadFull(reader, authVerAndUlen)
		if err != nil {
			ps.logDebug("读取认证请求头错误: %v", err)
			return
		}
		ulen := int(authVerAndUlen[1])

		username := make([]byte, ulen)
		_, err = io.ReadFull(reader, username)
		if err != nil {
			ps.logDebug("读取用户名错误: %v", err)
			return
		}

		plenByte := make([]byte, 1)
		_, err = io.ReadFull(reader, plenByte)
		if err != nil {
			ps.logDebug("读取密码长度错误: %v", err)
			return
		}
		plen := int(plenByte[0])

		password := make([]byte, plen)
		_, err = io.ReadFull(reader, password)
		if err != nil {
			ps.logDebug("读取密码错误: %v", err)
			return
		}

		// 转发认证请求到远程 SOCKS5 服务器
		remoteConn.Write(authVerAndUlen)
		remoteConn.Write(username)
		remoteConn.Write(plenByte)
		remoteConn.Write(password)

		// 读取认证响应
		authResult := make([]byte, 2)
		_, err = io.ReadFull(remoteConn, authResult)
		if err != nil {
			ps.logDebug("读取认证响应错误")
			return
		}

		// 将认证响应发回客户端
		clientConn.Write(authResult)

		if authResult[1] == 0x00 {
			ps.logDebug("SOCKS5 认证成功")
		} else {
			ps.logDebug("SOCKS5 认证失败")
			return
		}
	} else if authResponse[1] != 0x00 {
		ps.logDebug("服务器不支持的认证方法")
		return
	}

	// 处理连接请求
	// 读取前 4 个字节 (VER CMD RSV ATYP)
	connReqHeader := make([]byte, 4)
	_, err = io.ReadFull(reader, connReqHeader)
	if err != nil {
		ps.logDebug("读取连接请求头错误")
		return
	}

	remoteConn.Write(connReqHeader)

	aty := connReqHeader[3]

	// 根据地址类型读取地址和端口
	var addr []byte
	switch aty {
	case 0x01:
		// IPv4 地址，4 字节
		addr = make([]byte, 4)
		_, err = io.ReadFull(reader, addr)
		if err != nil {
			ps.logDebug("读取 IPv4 地址错误")
			return
		}
	case 0x03:
		// 域名，第一个字节是长度
		addrLenByte := make([]byte, 1)
		_, err = io.ReadFull(reader, addrLenByte)
		if err != nil {
			ps.logDebug("读取域名长度错误")
			return
		}
		addrLen := int(addrLenByte[0])

		domainName := make([]byte, addrLen)
		_, err = io.ReadFull(reader, domainName)
		if err != nil {
			ps.logDebug("读取域名错误")
			return
		}

		addr = append(addrLenByte, domainName...)
	case 0x04:
		// IPv6 地址，16 字节
		addr = make([]byte, 16)
		_, err = io.ReadFull(reader, addr)
		if err != nil {
			ps.logDebug("读取 IPv6 地址错误")
			return
		}
	default:
		ps.logDebug("未知的 ATYP 值")
		return
	}

	// 读取端口号
	port := make([]byte, 2)
	_, err = io.ReadFull(reader, port)
	if err != nil {
		ps.logDebug("读取端口错误")
		return
	}

	// 将地址和端口转发给远程服务器
	remoteConn.Write(addr)
	remoteConn.Write(port)

	// 读取远程服务器的响应
	serverRespHeader := make([]byte, 4)
	_, err = io.ReadFull(remoteConn, serverRespHeader)
	if err != nil {
		ps.logDebug("读取服务器响应头错误")
		return
	}

	// 将响应发回客户端
	clientConn.Write(serverRespHeader)

	if serverRespHeader[1] != 0x00 {
		ps.logDebug("SOCKS5 连接失败")
		return
	}

	// 读取 BND.ADDR 和 BND.PORT
	var bndAddr []byte
	switch serverRespHeader[3] {
	case 0x01:
		// IPv4 地址，4 字节 + 2 字节端口
		bndAddr = make([]byte, 6)
	case 0x03:
		// 域名，第一个字节是长度
		addrLenByte := make([]byte, 1)
		_, err = io.ReadFull(remoteConn, addrLenByte)
		if err != nil {
			ps.logDebug("读取绑定地址长度错误: %v", err)
			return
		}
		addrLen := int(addrLenByte[0])
		domainName := make([]byte, addrLen)
		_, err = io.ReadFull(remoteConn, domainName)
		if err != nil {
			ps.logDebug("读取绑定域名错误: %v", err)
			return
		}
		port := make([]byte, 2)
		_, err = io.ReadFull(remoteConn, port)
		if err != nil {
			ps.logDebug("读取绑定端口错误: %v", err)
			return
		}
		bndAddr = append(addrLenByte, domainName...)
		bndAddr = append(bndAddr, port...)
	case 0x04:
		// IPv6 地址，16 字节 + 2 字节端口
		bndAddr = make([]byte, 18)
	default:
		ps.logDebug("未知的 BND.ATYP 值")
		return
	}

	// 从远程服务器读取 BND.ADDR 和 BND.PORT
	_, err = io.ReadFull(remoteConn, bndAddr)
	if err != nil {
		ps.logDebug("读取绑定地址错误")
		return
	}

	// 将 BND.ADDR 和 BND.PORT 发回客户端
	clientConn.Write(bndAddr)

	ps.logDebug("SOCKS5 连接成功，开始数据转发")

	ps.startForwarding(clientConn, remoteConn)
}

func (ps *ProxyServer) extractAuth(data []byte) (string, string) {
	re := regexp.MustCompile(`Proxy-Authorization: Basic (.+)\r\n`)
	matches := re.FindSubmatch(data)
	if len(matches) >= 2 {
		authStr, err := base64.StdEncoding.DecodeString(string(matches[1]))
		if err != nil {
			ps.logger.Printf("解码认证信息错误: %v", err)
			return "", ""
		}
		parts := strings.SplitN(string(authStr), ":", 2)
		if len(parts) == 2 {
			return parts[0], parts[1]
		}
	}
	return "", ""
}

func (ps *ProxyServer) readHTTPRequest(firstByte []byte, reader *bufio.Reader) ([]byte, error) {
	buf := ps.bufferPool.Get().([]byte)
	defer ps.bufferPool.Put(buf)

	requestData := make([]byte, 0, 8192) // 增加到8KB的初始容量
	requestData = append(requestData, firstByte...)

	// 使用 ReadSlice 代替 Read 来提高性能
	for {
		slice, err := reader.ReadSlice('\n')
		if err != nil {
			return nil, err
		}
		requestData = append(requestData, slice...)
		if len(slice) == 2 && slice[0] == '\r' && slice[1] == '\n' {
			break
		}
	}
	return requestData, nil
}

func (ps *ProxyServer) startForwarding(conn1, conn2 net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)

	copy := func(dst, src net.Conn) {
		defer wg.Done()
		defer func() {
			dst.Close()
			src.Close()
		}()

		buf := ps.bufferPool.Get().([]byte)
		defer ps.bufferPool.Put(buf)
		io.CopyBuffer(dst, src, buf)
	}

	go copy(conn1, conn2)
	go copy(conn2, conn1)
	wg.Wait()
}

func (ps *ProxyServer) start() {
	var wg sync.WaitGroup

	// 为每个端口启动一个监听器
	for _, port := range ps.LocalPorts {
		wg.Add(1)
		go func(port int) {
			defer wg.Done()
			address := fmt.Sprintf("%s:%d", ps.LocalHost, port)
			listener, err := net.Listen("tcp", address)
			if err != nil {
				ps.logger.Printf("监听端口 %d 失败: %v", port, err)
				return
			}
			ps.logger.Printf("代理服务器启动在 %s", address)

			for {
				conn, err := listener.Accept()
				if err != nil {
					ps.logDebug("接受连接失败")
					continue
				}

				go ps.handleClient(conn)
			}
		}(port)
	}

	wg.Wait()
}

func (ps *ProxyServer) dialRemote(network, address string) (net.Conn, error) {
	// 检查是否达到最大连接数
	currentConns := atomic.LoadInt32(&ps.currentConns)
	if currentConns >= ps.maxIdleConns {
		ps.logger.Printf("连接数达到上限: 当前 %d, 最大 %d", currentConns, ps.maxIdleConns)
		return nil, fmt.Errorf("达到最大连接数限制: %d", ps.maxIdleConns)
	}

	// 创建新连接
	dialer := &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
	}

	conn, err := tls.DialWithDialer(dialer, network, address, ps.TLSConfig)
	if err != nil {
		return nil, fmt.Errorf("TLS连接失败: %v", err)
	}

	// 记录活动连接
	ps.activeConns.Store(conn, time.Now())
	return conn, nil
}

func (ps *ProxyServer) cleanIdleConns() {
	ticker := time.NewTicker(ps.idleTimeout / 2)
	go func() {
		for range ticker.C {
			now := time.Now()
			ps.activeConns.Range(func(k, v interface{}) bool {
				conn := k.(net.Conn)
				lastUsed := v.(time.Time)
				if now.Sub(lastUsed) > ps.idleTimeout {
					conn.Close()
					ps.activeConns.Delete(k)
					atomic.AddInt32(&ps.currentConns, -1)
				}
				return true
			})
		}
	}()
}

func (ps *ProxyServer) CheckVersion(version string, checkVersionUrl string) {
	resp, err := http.Get(checkVersionUrl + "?version=" + version)
	if err != nil {
		ps.logger.Printf("获取版本号失败,请检查网络连接")
		os.Exit(1)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		ps.logger.Printf("获取版本号失败,请检查网络连接")
		os.Exit(1)
	}
	var data struct {
		/*
			        {
			  "code": 0,
			  "msg": "success",
			  "data": {
			    "is_latest": false,
			    "version": "1.0.0",
			    "is_deprecated": true,
			    "last_version": "1.1.1"
			  }
			}
		*/
		Code int    `json:"code"`
		Msg  string `json:"msg"`
		Data struct {
			IsLatest     bool   `json:"is_latest"`
			Version      string `json:"version"`
			IsDeprecated bool   `json:"is_deprecated"`
			LastVersion  string `json:"last_version"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		ps.logger.Printf("解析版本号失败： %v，10s后自动退出", err)
		time.Sleep(10 * time.Second)
		os.Exit(1)

	}
	if data.Data.IsDeprecated {
		ps.logger.Printf("当前版本 %s 已弃用，请到官网更新最新版本: %s，10s后自动退出", version, data.Data.LastVersion)
		time.Sleep(10 * time.Second)
		os.Exit(1)
	} else {
		if !data.Data.IsLatest {
			ps.logger.Printf("最新版本号为 %s,请及时更新", data.Data.LastVersion)
		}
	}
}
func main() {
	// 配置日志
	logger := log.New(io.MultiWriter(log.Writer()), "", log.LstdFlags)
	version := "1.0.0"                                                  // 版本号
	checkVersionUrl := "http://api.ipflex.ink/token/check/tool/version" // 检查版本的URL,做版本控制
	LOCAL_HOST := "127.0.0.1"
	LOCAL_PORTS := []int{12345, 12346} // 定义多个本地端口

	REMOTE_HTTP_HOST := "ipflex.ink"
	REMOTE_HTTP_PORT := 12345

	REMOTE_SOCKS_HOST := "ipflex.ink"
	REMOTE_SOCKS_PORT := 12346

	fmt.Println(" ______________________________________________________________________ ")
	fmt.Println("|                                                                      |")
	fmt.Println("|欢迎使用IPFLEX                                                        |")
	fmt.Println("|______________________________________________________________________|")
	fmt.Println("")

	proxy := NewProxyServer(
		LOCAL_HOST, LOCAL_PORTS,
		REMOTE_HTTP_HOST, REMOTE_HTTP_PORT,
		REMOTE_SOCKS_HOST, REMOTE_SOCKS_PORT,
		"cert.pem", "key.pem")

	proxy.debug = false // 设置为 false 关闭调试日志
	proxy.logger = logger

	// 启动连接清理
	proxy.cleanIdleConns()

	// 设置更高的 GOMAXPROCS
	runtime.GOMAXPROCS(runtime.NumCPU())

	proxy.CheckVersion(version, checkVersionUrl)

	proxy.start()
}

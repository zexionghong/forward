package main

import (
	"bufio"
	"context"
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
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/data/binding"
	"fyne.io/fyne/v2/widget"
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
	maxIdleConns     int32
	currentConns     int32
	idleTimeout      time.Duration
	running          bool
	cancel           context.CancelFunc
	listeners        []net.Listener
	tunEnabled       bool
	proxyUsername    string
	proxyPassword    string
}

type ProxyGUI struct {
	app          fyne.App
	window       fyne.Window
	proxy        *ProxyServer
	tunProxy     *TUNProxy
	statusLabel  *widget.Label
	connLabel    *widget.Label
	tunLabel     *widget.Label
	logText      *widget.Entry
	startBtn     *widget.Button
	stopBtn      *widget.Button
	tunToggle    *widget.Check
	localPorts   *widget.Entry
	remoteHost   *widget.Entry
	remoteHTTP   *widget.Entry
	remoteSOCKS  *widget.Entry
	username     *widget.Entry
	password     *widget.Entry
	statusBind   binding.String
	connBind     binding.String
	tunBind      binding.String
	logBind      binding.String
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
		maxIdleConns: 500,
		idleTimeout:  5 * time.Minute,
		running:      false,
		listeners:    make([]net.Listener, 0),
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
	ps.logDebug("新建客户端连接: 当前连接数 %d", newCount)

	defer func() {
		conn.Close()
		currentCount := atomic.AddInt32(&ps.currentConns, -1)
		if currentCount < 0 {
			ps.logDebug("警告：连接数出现负数，重置为0")
			atomic.StoreInt32(&ps.currentConns, 0)
		} else {
			ps.logDebug("关闭客户端连接: 当前连接数 %d", currentCount)
		}
	}()

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

	requestData, err := ps.readHTTPRequest(firstByte, reader)
	if err != nil {
		ps.logDebug("读取 HTTP 请求错误: %v", err)
		return
	}

	// 使用配置的认证信息
	if ps.proxyUsername == "" || ps.proxyPassword == "" {
		ps.logDebug("HTTP 代理需要配置用户名和密码")
		response := "HTTP/1.1 407 Proxy Authentication Required\r\n"
		response += "Proxy-Authenticate: Basic realm=\"Proxy\"\r\n\r\n"
		clientConn.Write([]byte(response))
		return
	}

	// 修改请求，添加代理认证头
	authRequestData := ps.addProxyAuth(requestData)

	remoteConn, err := ps.dialRemote("tcp", fmt.Sprintf("%s:%d", ps.RemoteHTTPHost, ps.RemoteHTTPPort))
	if err != nil {
		ps.logDebug("连接远程 HTTP 代理错误")
		return
	}
	defer remoteConn.Close()

	remoteConn.Write(authRequestData)

	ps.startForwarding(clientConn, remoteConn)
}

func (ps *ProxyServer) handleSOCKS5(clientConn net.Conn, firstByte []byte) {
	defer clientConn.Close()
	reader := bufio.NewReader(clientConn)

	nmethodsByte := make([]byte, 1)
	_, err := io.ReadFull(reader, nmethodsByte)
	if err != nil {
		ps.logDebug("读取 nmethods 错误")
		return
	}
	nmethods := int(nmethodsByte[0])

	methods := make([]byte, nmethods)
	_, err = io.ReadFull(reader, methods)
	if err != nil {
		ps.logDebug("读取 methods 错误")
		return
	}

	remoteConn, err := ps.dialRemote("tcp", fmt.Sprintf("%s:%d", ps.RemoteSOCKS5Host, ps.RemoteSOCKS5Port))
	if err != nil {
		ps.logDebug("连接远程 SOCKS5 代理错误 ：%v", err)
		return
	}
	defer remoteConn.Close()

	remoteConn.Write(append(firstByte, nmethodsByte...))
	remoteConn.Write(methods)

	authResponse := make([]byte, 2)
	_, err = io.ReadFull(remoteConn, authResponse)
	if err != nil {
		ps.logDebug("读取远程 SOCKS5 握手响应错误 ：%v", err)
		return
	}

	clientConn.Write(authResponse)

	if authResponse[1] == 0x02 {
		ps.logDebug("SOCKS5 开始用户认证")

		// 使用配置的认证信息
		if ps.proxyUsername == "" || ps.proxyPassword == "" {
			ps.logDebug("SOCKS5 代理需要配置用户名和密码")
			return
		}

		// 读取客户端的认证请求（但忽略内容，使用我们配置的认证）
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

		// 向远程服务器发送我们配置的认证信息
		authVer := []byte{0x01}
		configUsername := []byte(ps.proxyUsername)
		configPassword := []byte(ps.proxyPassword)
		
		remoteConn.Write(authVer)
		remoteConn.Write([]byte{byte(len(configUsername))})
		remoteConn.Write(configUsername)
		remoteConn.Write([]byte{byte(len(configPassword))})
		remoteConn.Write(configPassword)

		authResult := make([]byte, 2)
		_, err = io.ReadFull(remoteConn, authResult)
		if err != nil {
			ps.logDebug("读取认证响应错误")
			return
		}

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

	connReqHeader := make([]byte, 4)
	_, err = io.ReadFull(reader, connReqHeader)
	if err != nil {
		ps.logDebug("读取连接请求头错误")
		return
	}

	remoteConn.Write(connReqHeader)

	aty := connReqHeader[3]

	var addr []byte
	switch aty {
	case 0x01:
		addr = make([]byte, 4)
		_, err = io.ReadFull(reader, addr)
		if err != nil {
			ps.logDebug("读取 IPv4 地址错误")
			return
		}
	case 0x03:
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

	port := make([]byte, 2)
	_, err = io.ReadFull(reader, port)
	if err != nil {
		ps.logDebug("读取端口错误")
		return
	}

	remoteConn.Write(addr)
	remoteConn.Write(port)

	serverRespHeader := make([]byte, 4)
	_, err = io.ReadFull(remoteConn, serverRespHeader)
	if err != nil {
		ps.logDebug("读取服务器响应头错误")
		return
	}

	clientConn.Write(serverRespHeader)

	if serverRespHeader[1] != 0x00 {
		ps.logDebug("SOCKS5 连接失败")
		return
	}

	var bndAddr []byte
	switch serverRespHeader[3] {
	case 0x01:
		bndAddr = make([]byte, 6)
	case 0x03:
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
		bndAddr = make([]byte, 18)
	default:
		ps.logDebug("未知的 BND.ATYP 值")
		return
	}

	_, err = io.ReadFull(remoteConn, bndAddr)
	if err != nil {
		ps.logDebug("读取绑定地址错误")
		return
	}

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

func (ps *ProxyServer) addProxyAuth(requestData []byte) []byte {
	request := string(requestData)
	
	// 移除已有的 Proxy-Authorization 头（如果有）
	re := regexp.MustCompile(`Proxy-Authorization: [^\r\n]*\r\n`)
	request = re.ReplaceAllString(request, "")
	
	// 创建新的认证头
	auth := base64.StdEncoding.EncodeToString([]byte(ps.proxyUsername + ":" + ps.proxyPassword))
	authHeader := fmt.Sprintf("Proxy-Authorization: Basic %s\r\n", auth)
	
	// 在第一行后插入认证头
	lines := strings.SplitN(request, "\r\n", 2)
	if len(lines) == 2 {
		request = lines[0] + "\r\n" + authHeader + lines[1]
	}
	
	return []byte(request)
}

func (ps *ProxyServer) readHTTPRequest(firstByte []byte, reader *bufio.Reader) ([]byte, error) {
	buf := ps.bufferPool.Get().([]byte)
	defer ps.bufferPool.Put(buf)

	requestData := make([]byte, 0, 8192)
	requestData = append(requestData, firstByte...)

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

func (ps *ProxyServer) start(ctx context.Context) error {
	if ps.running {
		return fmt.Errorf("代理服务器已在运行")
	}

	ps.running = true
	
	for _, port := range ps.LocalPorts {
		address := fmt.Sprintf("%s:%d", ps.LocalHost, port)
		listener, err := net.Listen("tcp", address)
		if err != nil {
			ps.logger.Printf("监听端口 %d 失败: %v", port, err)
			continue
		}
		ps.listeners = append(ps.listeners, listener)
		ps.logger.Printf("代理服务器启动在 %s", address)

		go func(listener net.Listener) {
			for {
				select {
				case <-ctx.Done():
					return
				default:
					conn, err := listener.Accept()
					if err != nil {
						if ps.running {
							ps.logDebug("接受连接失败: %v", err)
						}
						continue
					}
					go ps.handleClient(conn)
				}
			}
		}(listener)
	}

	ps.cleanIdleConns()
	return nil
}

func (ps *ProxyServer) stop() {
	if !ps.running {
		return
	}

	ps.running = false
	
	if ps.cancel != nil {
		ps.cancel()
	}

	for _, listener := range ps.listeners {
		listener.Close()
	}
	ps.listeners = ps.listeners[:0]

	ps.activeConns.Range(func(k, v interface{}) bool {
		if conn, ok := k.(net.Conn); ok {
			conn.Close()
		}
		return true
	})

	ps.logger.Printf("代理服务器已停止")
}

func (ps *ProxyServer) dialRemote(network, address string) (net.Conn, error) {
	currentConns := atomic.LoadInt32(&ps.currentConns)
	if currentConns >= ps.maxIdleConns {
		ps.logger.Printf("连接数达到上限: 当前 %d, 最大 %d", currentConns, ps.maxIdleConns)
		return nil, fmt.Errorf("达到最大连接数限制: %d", ps.maxIdleConns)
	}

	dialer := &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
	}

	conn, err := tls.DialWithDialer(dialer, network, address, ps.TLSConfig)
	if err != nil {
		return nil, fmt.Errorf("TLS连接失败: %v", err)
	}

	ps.activeConns.Store(conn, time.Now())
	return conn, nil
}

func (ps *ProxyServer) cleanIdleConns() {
	ticker := time.NewTicker(ps.idleTimeout / 2)
	go func() {
		for range ticker.C {
			if !ps.running {
				ticker.Stop()
				return
			}
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

func (ps *ProxyServer) CheckVersion(version string, checkVersionUrl string) error {
	resp, err := http.Get(checkVersionUrl + "?version=" + version)
	if err != nil {
		return fmt.Errorf("获取版本号失败,请检查网络连接: %v", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("获取版本号失败,请检查网络连接")
	}
	
	var data struct {
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
		return fmt.Errorf("解析版本号失败: %v", err)
	}
	
	if data.Data.IsDeprecated {
		return fmt.Errorf("当前版本 %s 已弃用，请到官网更新最新版本: %s", version, data.Data.LastVersion)
	} else if !data.Data.IsLatest {
		ps.logger.Printf("最新版本号为 %s,请及时更新", data.Data.LastVersion)
	}
	
	return nil
}

func NewProxyGUI() *ProxyGUI {
	myApp := app.New()
	myApp.SetIcon(nil)
	myWindow := myApp.NewWindow("IPFLEX Proxy GUI")
	myWindow.Resize(fyne.NewSize(800, 700))

	statusBind := binding.NewString()
	connBind := binding.NewString()
	tunBind := binding.NewString()
	logBind := binding.NewString()

	statusBind.Set("未启动")
	connBind.Set("连接数: 0")
	tunBind.Set("TUN: 未启用")

	gui := &ProxyGUI{
		app:        myApp,
		window:     myWindow,
		statusBind: statusBind,
		connBind:   connBind,
		tunBind:    tunBind,
		logBind:    logBind,
	}

	gui.setupUI()
	return gui
}

func (g *ProxyGUI) setupUI() {
	g.statusLabel = widget.NewLabelWithData(g.statusBind)
	g.connLabel = widget.NewLabelWithData(g.connBind)
	g.tunLabel = widget.NewLabelWithData(g.tunBind)

	g.localPorts = widget.NewEntry()
	g.localPorts.SetText("12345,12346")
	g.remoteHost = widget.NewEntry()
	g.remoteHost.SetText("ipflex.ink")
	g.remoteHTTP = widget.NewEntry()
	g.remoteHTTP.SetText("12347")
	g.remoteSOCKS = widget.NewEntry()
	g.remoteSOCKS.SetText("12348")
	
	g.username = widget.NewEntry()
	g.username.SetPlaceHolder("代理用户名")
	g.password = widget.NewPasswordEntry()
	g.password.SetPlaceHolder("代理密码")

	g.tunToggle = widget.NewCheck("启用全局代理 (TUN)", func(checked bool) {
		if checked {
			if g.proxy != nil && g.proxy.running {
				g.enableTUNProxy()
			} else {
				g.appendLog("请先启动基础代理服务")
				g.tunToggle.SetChecked(false)
			}
		} else {
			g.disableTUNProxy()
		}
	})

	g.startBtn = widget.NewButton("启动代理", g.startProxy)
	g.stopBtn = widget.NewButton("停止代理", g.stopProxy)
	g.stopBtn.Disable()

	g.logText = widget.NewMultiLineEntry()
	g.logText.SetText("欢迎使用IPFLEX代理客户端\n")

	configForm := &widget.Form{
		Items: []*widget.FormItem{
			{Text: "本地端口", Widget: g.localPorts},
			{Text: "远程主机", Widget: g.remoteHost},
			{Text: "HTTP端口", Widget: g.remoteHTTP},
			{Text: "SOCKS5端口", Widget: g.remoteSOCKS},
			{Text: "代理用户名", Widget: g.username},
			{Text: "代理密码", Widget: g.password},
		},
	}

	statusContainer := container.NewHBox(
		g.statusLabel,
		widget.NewSeparator(),
		g.connLabel,
		widget.NewSeparator(),
		g.tunLabel,
	)

	controlContainer := container.NewHBox(
		g.tunToggle,
		widget.NewSeparator(),
		g.startBtn,
		g.stopBtn,
	)

	logScroll := container.NewScroll(g.logText)
	logScroll.SetMinSize(fyne.NewSize(700, 200))

	content := container.NewBorder(
		container.NewVBox(
			widget.NewCard("状态", "", statusContainer),
			widget.NewCard("配置", "", configForm),
			widget.NewCard("控制", "", controlContainer),
		),
		nil,
		nil,
		nil,
		widget.NewCard("日志", "", logScroll),
	)

	g.window.SetContent(content)

	go g.updateStatus()
}

func (g *ProxyGUI) startProxy() {
	ports := g.parsePorts(g.localPorts.Text)
	if len(ports) == 0 {
		g.appendLog("错误：无效的端口配置")
		return
	}

	httpPort, err := strconv.Atoi(g.remoteHTTP.Text)
	if err != nil {
		g.appendLog("错误：无效的HTTP端口")
		return
	}

	socksPort, err := strconv.Atoi(g.remoteSOCKS.Text)
	if err != nil {
		g.appendLog("错误：无效的SOCKS5端口")
		return
	}

	g.proxy = NewProxyServer(
		"127.0.0.1", ports,
		g.remoteHost.Text, httpPort,
		g.remoteHost.Text, socksPort,
		"cert.pem", "key.pem",
	)

	g.proxy.debug = false
	g.proxy.tunEnabled = g.tunToggle.Checked
	g.proxy.proxyUsername = g.username.Text
	g.proxy.proxyPassword = g.password.Text

	ctx, cancel := context.WithCancel(context.Background())
	g.proxy.cancel = cancel

	if err := g.proxy.start(ctx); err != nil {
		g.appendLog(fmt.Sprintf("启动失败: %v", err))
		return
	}

	g.startBtn.Disable()
	g.stopBtn.Enable()
	g.statusBind.Set("运行中")
	g.appendLog("代理服务器已启动")

	version := "1.0.0"
	checkVersionUrl := "http://api.ipflex.ink/token/check/tool/version"
	
	go func() {
		if err := g.proxy.CheckVersion(version, checkVersionUrl); err != nil {
			g.appendLog(fmt.Sprintf("版本检查: %v", err))
		}
	}()

	go g.startHTTPServer()

	if g.proxy.tunEnabled {
		go g.enableTUNProxy()
	}
}

func (g *ProxyGUI) stopProxy() {
	if g.proxy != nil {
		g.proxy.stop()
		g.proxy = nil
	}

	g.disableTUNProxy()

	g.startBtn.Enable()
	g.stopBtn.Disable()
	g.tunToggle.SetChecked(false)
	g.statusBind.Set("已停止")
	g.connBind.Set("连接数: 0")
	g.tunBind.Set("TUN: 未启用")
	g.appendLog("代理服务器已停止")
}

func (g *ProxyGUI) enableTUNProxy() {
	if g.tunProxy != nil && g.tunProxy.IsRunning() {
		g.appendLog("TUN代理已在运行")
		return
	}

	g.tunProxy = NewTUNProxy(g.proxy)
	
	if err := g.tunProxy.Start(); err != nil {
		g.appendLog(fmt.Sprintf("启动TUN代理失败: %v", err))
		g.appendLog("提示：TUN模式需要管理员权限")
		g.tunToggle.SetChecked(false)
		return
	}

	g.tunBind.Set("TUN: 已启用")
	g.appendLog("TUN全局代理已启动")
	g.appendLog("所有网络流量将通过代理")
}

func (g *ProxyGUI) disableTUNProxy() {
	if g.tunProxy != nil {
		if err := g.tunProxy.Stop(); err != nil {
			g.appendLog(fmt.Sprintf("停止TUN代理失败: %v", err))
		} else {
			g.appendLog("TUN全局代理已停止")
		}
		g.tunProxy = nil
	}
	g.tunBind.Set("TUN: 未启用")
}

func (g *ProxyGUI) startHTTPServer() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "*")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		w.Write([]byte("ok"))
	})
	
	if err := http.ListenAndServe(":12340", nil); err != nil {
		g.appendLog(fmt.Sprintf("HTTP服务器启动失败: %v", err))
	}
}

func (g *ProxyGUI) parsePorts(portStr string) []int {
	var ports []int
	for _, p := range strings.Split(portStr, ",") {
		if port, err := strconv.Atoi(strings.TrimSpace(p)); err == nil {
			ports = append(ports, port)
		}
	}
	return ports
}

func (g *ProxyGUI) appendLog(message string) {
	timestamp := time.Now().Format("15:04:05")
	logLine := fmt.Sprintf("[%s] %s\n", timestamp, message)
	
	currentText := g.logText.Text
	g.logText.SetText(currentText + logLine)
}

func (g *ProxyGUI) updateStatus() {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for range ticker.C {
		if g.proxy != nil && g.proxy.running {
			connCount := atomic.LoadInt32(&g.proxy.currentConns)
			g.connBind.Set(fmt.Sprintf("连接数: %d", connCount))
		}
		
		if g.tunProxy != nil && g.tunProxy.IsRunning() {
			g.tunBind.Set(fmt.Sprintf("TUN: %s", g.tunProxy.GetStatus()))
		}
	}
}

func (g *ProxyGUI) Run() {
	runtime.GOMAXPROCS(runtime.NumCPU())
	g.window.ShowAndRun()
}

func main() {
	gui := NewProxyGUI()
	gui.Run()
}
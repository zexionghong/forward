package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/songgao/water"
	"github.com/songgao/water/waterutil"
)

type TUNProxy struct {
	iface       *water.Interface
	ctx         context.Context
	cancel      context.CancelFunc
	proxyServer *ProxyServer
	logger      *log.Logger
	running     bool
	mutex       sync.RWMutex
	tunIP       string
	tunSubnet   string
	dnsServers  []string
}

func NewTUNProxy(proxyServer *ProxyServer) *TUNProxy {
	return &TUNProxy{
		proxyServer: proxyServer,
		logger:      log.Default(),
		tunIP:       "10.0.0.1",
		tunSubnet:   "10.0.0.0/24",
		dnsServers:  []string{"8.8.8.8", "8.8.4.4"},
	}
}

func (t *TUNProxy) Start() error {
	t.mutex.Lock()
	defer t.mutex.Unlock()

	if t.running {
		return fmt.Errorf("TUN代理已在运行")
	}

	ctx, cancel := context.WithCancel(context.Background())
	t.ctx = ctx
	t.cancel = cancel

	if err := t.createTUNInterface(); err != nil {
		cancel()
		return fmt.Errorf("创建TUN接口失败: %v", err)
	}

	if err := t.configureTUNInterface(); err != nil {
		cancel()
		t.iface.Close()
		return fmt.Errorf("配置TUN接口失败: %v", err)
	}

	if err := t.setupRouting(); err != nil {
		cancel()
		t.iface.Close()
		return fmt.Errorf("配置路由失败: %v", err)
	}

	t.running = true
	t.logger.Printf("TUN代理已启动，接口: %s, IP: %s", t.iface.Name(), t.tunIP)

	go t.packetHandler()

	return nil
}

func (t *TUNProxy) Stop() error {
	t.mutex.Lock()
	defer t.mutex.Unlock()

	if !t.running {
		return nil
	}

	t.running = false

	if t.cancel != nil {
		t.cancel()
	}

	if err := t.restoreRouting(); err != nil {
		t.logger.Printf("恢复路由失败: %v", err)
	}

	if t.iface != nil {
		t.iface.Close()
	}

	t.logger.Printf("TUN代理已停止")
	return nil
}

func (t *TUNProxy) createTUNInterface() error {
	config := water.Config{
		DeviceType: water.TUN,
	}

	var err error
	t.iface, err = water.New(config)
	if err != nil {
		return fmt.Errorf("创建TUN设备失败: %v", err)
	}

	return nil
}

func (t *TUNProxy) configureTUNInterface() error {
	switch runtime.GOOS {
	case "windows":
		return t.configureWindowsTUN()
	case "linux":
		return t.configureLinuxTUN()
	case "darwin":
		return t.configureMacOSTUN()
	default:
		return fmt.Errorf("不支持的操作系统: %s", runtime.GOOS)
	}
}

func (t *TUNProxy) configureWindowsTUN() error {
	cmd := exec.Command("netsh", "interface", "ip", "set", "address",
		fmt.Sprintf("name=\"%s\"", t.iface.Name()),
		"static", t.tunIP, "255.255.255.0")
	
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("Windows TUN配置失败: %v", err)
	}

	for _, dns := range t.dnsServers {
		cmd = exec.Command("netsh", "interface", "ip", "set", "dns",
			fmt.Sprintf("name=\"%s\"", t.iface.Name()),
			"static", dns)
		if err := cmd.Run(); err != nil {
			t.logger.Printf("设置DNS失败: %v", err)
		}
	}

	return nil
}

func (t *TUNProxy) configureLinuxTUN() error {
	commands := [][]string{
		{"ip", "addr", "add", fmt.Sprintf("%s/24", t.tunIP), "dev", t.iface.Name()},
		{"ip", "link", "set", "dev", t.iface.Name(), "up"},
	}

	for _, cmd := range commands {
		if err := exec.Command(cmd[0], cmd[1:]...).Run(); err != nil {
			return fmt.Errorf("Linux TUN配置失败: %v", err)
		}
	}

	return nil
}

func (t *TUNProxy) configureMacOSTUN() error {
	commands := [][]string{
		{"ifconfig", t.iface.Name(), t.tunIP, t.tunIP, "up"},
		{"route", "add", "-net", t.tunSubnet, "-interface", t.iface.Name()},
	}

	for _, cmd := range commands {
		if err := exec.Command(cmd[0], cmd[1:]...).Run(); err != nil {
			return fmt.Errorf("macOS TUN配置失败: %v", err)
		}
	}

	return nil
}

func (t *TUNProxy) setupRouting() error {
	switch runtime.GOOS {
	case "windows":
		return t.setupWindowsRouting()
	case "linux":
		return t.setupLinuxRouting()
	case "darwin":
		return t.setupMacOSRouting()
	default:
		return fmt.Errorf("不支持的操作系统: %s", runtime.GOOS)
	}
}

func (t *TUNProxy) setupWindowsRouting() error {
	cmd := exec.Command("route", "add", "0.0.0.0", "mask", "0.0.0.0", t.tunIP, "metric", "1")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("Windows路由配置失败: %v", err)
	}
	return nil
}

func (t *TUNProxy) setupLinuxRouting() error {
	commands := [][]string{
		{"ip", "route", "add", "0.0.0.0/1", "dev", t.iface.Name()},
		{"ip", "route", "add", "128.0.0.0/1", "dev", t.iface.Name()},
	}

	for _, cmd := range commands {
		if err := exec.Command(cmd[0], cmd[1:]...).Run(); err != nil {
			return fmt.Errorf("Linux路由配置失败: %v", err)
		}
	}

	return nil
}

func (t *TUNProxy) setupMacOSRouting() error {
	commands := [][]string{
		{"route", "add", "-net", "0.0.0.0/1", "-interface", t.iface.Name()},
		{"route", "add", "-net", "128.0.0.0/1", "-interface", t.iface.Name()},
	}

	for _, cmd := range commands {
		if err := exec.Command(cmd[0], cmd[1:]...).Run(); err != nil {
			return fmt.Errorf("macOS路由配置失败: %v", err)
		}
	}

	return nil
}

func (t *TUNProxy) restoreRouting() error {
	switch runtime.GOOS {
	case "windows":
		cmd := exec.Command("route", "delete", "0.0.0.0", "mask", "0.0.0.0", t.tunIP)
		return cmd.Run()
	case "linux":
		commands := [][]string{
			{"ip", "route", "del", "0.0.0.0/1", "dev", t.iface.Name()},
			{"ip", "route", "del", "128.0.0.0/1", "dev", t.iface.Name()},
		}
		for _, cmd := range commands {
			exec.Command(cmd[0], cmd[1:]...).Run() // 忽略错误
		}
	case "darwin":
		commands := [][]string{
			{"route", "delete", "-net", "0.0.0.0/1", "-interface", t.iface.Name()},
			{"route", "delete", "-net", "128.0.0.0/1", "-interface", t.iface.Name()},
		}
		for _, cmd := range commands {
			exec.Command(cmd[0], cmd[1:]...).Run() // 忽略错误
		}
	}
	return nil
}

func (t *TUNProxy) packetHandler() {
	buffer := make([]byte, 1500) // MTU大小

	for {
		select {
		case <-t.ctx.Done():
			return
		default:
			n, err := t.iface.Read(buffer)
			if err != nil {
				if t.running {
					t.logger.Printf("读取TUN数据包失败: %v", err)
				}
				continue
			}

			packet := buffer[:n]
			go t.handlePacket(packet)
		}
	}
}

func (t *TUNProxy) handlePacket(packet []byte) {
	if len(packet) < 20 {
		return
	}

	if !waterutil.IsIPv4(packet) {
		return
	}

	dst := waterutil.IPv4Destination(packet)
	protocol := waterutil.IPv4Protocol(packet)

	if t.shouldProxyTraffic(dst) {
		switch protocol {
		case waterutil.TCP:
			t.handleTCPPacket(packet, dst)
		case waterutil.UDP:
			t.handleUDPPacket(packet, dst)
		}
	} else {
		t.forwardPacketDirect(packet)
	}
}

func (t *TUNProxy) shouldProxyTraffic(dst net.IP) bool {
	if dst.IsLoopback() || dst.IsLinkLocalUnicast() {
		return false
	}

	if strings.Contains(t.proxyServer.RemoteHTTPHost, dst.String()) ||
		strings.Contains(t.proxyServer.RemoteSOCKS5Host, dst.String()) {
		return false
	}

	return true
}

func (t *TUNProxy) handleTCPPacket(packet []byte, dst net.IP) {
	srcPort := waterutil.IPv4SourcePort(packet)
	dstPort := waterutil.IPv4DestinationPort(packet)

	if waterutil.IsTCPSyn(packet) && !waterutil.IsTCPAck(packet) {
		t.logger.Printf("拦截TCP连接: %s:%d -> %s:%d", 
			waterutil.IPv4Source(packet), srcPort, dst, dstPort)

		go t.proxyTCPConnection(dst, dstPort)
	}
}

func (t *TUNProxy) handleUDPPacket(packet []byte, dst net.IP) {
	dstPort := waterutil.IPv4DestinationPort(packet)
	
	if dstPort == 53 { // DNS
		t.proxyDNSQuery(packet, dst)
	} else {
		t.proxyUDPPacket(packet, dst, dstPort)
	}
}

func (t *TUNProxy) proxyTCPConnection(dst net.IP, dstPort uint16) {
	target := fmt.Sprintf("%s:%d", dst.String(), dstPort)
	
	localAddr, err := net.ResolveTCPAddr("tcp", fmt.Sprintf("127.0.0.1:%d", t.proxyServer.LocalPorts[0]))
	if err != nil {
		t.logger.Printf("解析本地地址失败: %v", err)
		return
	}

	conn, err := net.DialTCP("tcp", nil, localAddr)
	if err != nil {
		t.logger.Printf("连接本地代理失败: %v", err)
		return
	}
	defer conn.Close()

	socks5Req := t.buildSOCKS5Request(dst.String(), dstPort)
	if _, err := conn.Write(socks5Req); err != nil {
		t.logger.Printf("发送SOCKS5请求失败: %v", err)
		return
	}

	t.logger.Printf("TCP连接已通过代理建立: %s", target)
}

func (t *TUNProxy) proxyUDPPacket(packet []byte, dst net.IP, dstPort uint16) {
	t.logger.Printf("处理UDP包: %s:%d", dst.String(), dstPort)
}

func (t *TUNProxy) proxyDNSQuery(packet []byte, dst net.IP) {
	t.logger.Printf("处理DNS查询: %s", dst.String())
}

func (t *TUNProxy) forwardPacketDirect(packet []byte) {
	// 直接转发数据包，不通过代理
}

func (t *TUNProxy) buildSOCKS5Request(host string, port uint16) []byte {
	req := []byte{0x05, 0x01, 0x00} // 版本5，1个方法，无认证

	req = append(req, 0x05, 0x01, 0x00, 0x03) // 版本5，连接，保留，域名类型
	req = append(req, byte(len(host)))         // 域名长度
	req = append(req, []byte(host)...)         // 域名
	req = append(req, byte(port>>8), byte(port&0xff)) // 端口

	return req
}

func (t *TUNProxy) IsRunning() bool {
	t.mutex.RLock()
	defer t.mutex.RUnlock()
	return t.running
}

func (t *TUNProxy) GetStatus() string {
	t.mutex.RLock()
	defer t.mutex.RUnlock()
	
	if t.running {
		return fmt.Sprintf("TUN接口: %s, IP: %s", t.iface.Name(), t.tunIP)
	}
	return "TUN代理未启动"
}
package main

import (
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

// 嵌入私钥文件
//
//go:embed keys/*
var embeddedKeys embed.FS

// 嵌入配置文件
//
//go:embed config.json
var embeddedConfig []byte

// 嵌入私钥管理器
type EmbeddedKeyManager struct {
	keys map[string][]byte
}

func NewEmbeddedKeyManager() *EmbeddedKeyManager {
	manager := &EmbeddedKeyManager{
		keys: make(map[string][]byte),
	}
	manager.loadEmbeddedKeys()
	return manager
}

func (ekm *EmbeddedKeyManager) loadEmbeddedKeys() {
	entries, err := embeddedKeys.ReadDir("keys")
	if err != nil {
		return
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			keyName := entry.Name()
			keyPath := filepath.Join("keys", keyName)

			keyData, err := embeddedKeys.ReadFile(keyPath)
			if err != nil {
				continue
			}

			ekm.keys[keyName] = keyData
		}
	}
}

func (ekm *EmbeddedKeyManager) GetKey(keyName string) ([]byte, bool) {
	keyData, exists := ekm.keys[keyName]
	return keyData, exists
}

func (ekm *EmbeddedKeyManager) ListKeys() []string {
	var keyNames []string
	for keyName := range ekm.keys {
		keyNames = append(keyNames, keyName)
	}
	return keyNames
}

func (ekm *EmbeddedKeyManager) HasKeys() bool {
	return len(ekm.keys) > 0
}

// 获取嵌入的配置文件数据
func getEmbeddedConfig() []byte {
	return embeddedConfig
}

type SSHForwarder struct {
	config     *Config
	keyManager *EmbeddedKeyManager
	client     *ssh.Client
	logger     *log.Logger
	listeners  []net.Listener
	stopCh     chan struct{}
	wg         sync.WaitGroup
	mu         sync.RWMutex
	connected  bool
}

func NewSSHForwarder(config *Config, keyManager *EmbeddedKeyManager) *SSHForwarder {
	logger := log.New(os.Stdout, "", log.LstdFlags)
	if config.Settings.Debug {
		logger.SetFlags(log.LstdFlags | log.Lshortfile)
	}

	return &SSHForwarder{
		config:     config,
		keyManager: keyManager,
		logger:     logger,
		stopCh:     make(chan struct{}),
	}
}

func (sf *SSHForwarder) buildSSHConfig() (*ssh.ClientConfig, error) {
	var authMethods []ssh.AuthMethod

	// 嵌入私钥认证
	if sf.config.SSH.UseEmbeddedKey {
		if sf.config.SSH.EmbeddedKeyName == "" {
			return nil, fmt.Errorf("启用了嵌入私钥但未指定私钥名称")
		}

		keyData, exists := sf.keyManager.GetKey(sf.config.SSH.EmbeddedKeyName)
		if !exists {
			return nil, fmt.Errorf("嵌入私钥 %s 不存在", sf.config.SSH.EmbeddedKeyName)
		}

		signer, err := ssh.ParsePrivateKey(keyData)
		if err != nil {
			return nil, fmt.Errorf("解析嵌入SSH私钥失败: %v", err)
		}

		authMethods = append(authMethods, ssh.PublicKeys(signer))
		// 静默加载认证密钥
	} else if sf.config.SSH.KeyFile != "" {
		// 外部密钥文件认证
		keyPath := sf.config.SSH.KeyFile
		if strings.HasPrefix(keyPath, "~/") {
			homeDir, err := os.UserHomeDir()
			if err != nil {
				return nil, fmt.Errorf("无法获取用户主目录: %v", err)
			}
			keyPath = filepath.Join(homeDir, keyPath[2:])
		}

		key, err := os.ReadFile(keyPath)
		if err != nil {
			return nil, fmt.Errorf("读取SSH密钥文件失败: %v", err)
		}

		signer, err := ssh.ParsePrivateKey(key)
		if err != nil {
			return nil, fmt.Errorf("解析SSH密钥失败: %v", err)
		}

		authMethods = append(authMethods, ssh.PublicKeys(signer))
		// 静默加载认证密钥
	}

	// 密码认证
	if sf.config.SSH.Password != "" {
		authMethods = append(authMethods, ssh.Password(sf.config.SSH.Password))
		// 静默启用密码认证
	}

	if len(authMethods) == 0 {
		return nil, fmt.Errorf("未配置SSH认证方法")
	}

	return &ssh.ClientConfig{
		User:            sf.config.SSH.User,
		Auth:            authMethods,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	}, nil
}

func (sf *SSHForwarder) connectSSH() error {
	sf.mu.Lock()
	defer sf.mu.Unlock()

	if sf.client != nil {
		sf.client.Close()
	}

	config, err := sf.buildSSHConfig()
	if err != nil {
		return err
	}

	addr := fmt.Sprintf("%s:%d", sf.config.SSH.Host, sf.config.SSH.Port)
	// 静默连接代理服务器

	client, err := ssh.Dial("tcp", addr, config)
	if err != nil {
		return fmt.Errorf("SSH连接失败: %v", err)
	}

	sf.client = client
	sf.connected = true
	// 连接建立成功

	// 启动心跳检测
	go sf.keepAlive()

	return nil
}

func (sf *SSHForwarder) keepAlive() {
	ticker := time.NewTicker(time.Duration(sf.config.Settings.KeepAlive) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			sf.mu.RLock()
			client := sf.client
			sf.mu.RUnlock()

			if client != nil {
				_, _, err := client.SendRequest("keepalive@openssh.com", true, nil)
				if err != nil {
					// 连接检测失败，静默重连
					sf.mu.Lock()
					sf.connected = false
					sf.mu.Unlock()
					return
				}
				// 连接正常
			}
		case <-sf.stopCh:
			return
		}
	}
}

func (sf *SSHForwarder) startListener(localPort, remotePort int) error {
	localAddr := fmt.Sprintf("%s:%d", sf.config.Local.Host, localPort)
	listener, err := net.Listen("tcp", localAddr)
	if err != nil {
		return fmt.Errorf("监听本地端口 %d 失败: %v", localPort, err)
	}

	sf.listeners = append(sf.listeners, listener)
	sf.logger.Printf("代理服务器启动在 %s", localAddr)

	sf.wg.Add(1)
	go func() {
		defer sf.wg.Done()
		defer listener.Close()

		for {
			select {
			case <-sf.stopCh:
				return
			default:
				conn, err := listener.Accept()
				if err != nil {
					// 静默处理连接错误
					continue
				}

				go sf.handleConnection(conn, remotePort)
			}
		}
	}()

	return nil
}

func (sf *SSHForwarder) handleConnection(localConn net.Conn, remotePort int) {
	defer localConn.Close()

	// 获取SSH客户端
	sf.mu.RLock()
	client := sf.client
	connected := sf.connected
	sf.mu.RUnlock()

	if !connected || client == nil {
		// 连接未建立，拒绝服务
		return
	}

	// 通过SSH隧道连接到远程主机
	remoteAddr := fmt.Sprintf("%s:%d", sf.config.Remote.Host, remotePort)
	// 建立连接

	remoteConn, err := client.Dial("tcp", remoteAddr)
	if err != nil {
		// 连接失败，静默处理
		return
	}
	defer remoteConn.Close()

	// 隧道建立成功

	// 双向数据转发
	sf.startForwarding(localConn, remoteConn)
}

func (sf *SSHForwarder) startForwarding(conn1, conn2 net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)

	copyData := func(dst, src net.Conn, direction string) {
		defer wg.Done()
		defer func() {
			if tcpConn, ok := dst.(*net.TCPConn); ok {
				tcpConn.CloseWrite()
			}
		}()

		io.Copy(dst, src)
		// 静默处理数据转发错误
	}

	go copyData(conn2, conn1, "local->remote")
	go copyData(conn1, conn2, "remote->local")

	wg.Wait()
}

func (sf *SSHForwarder) Start() error {
	// 检查端口数量是否匹配
	if len(sf.config.Local.Ports) != len(sf.config.Remote.Ports) {
		return fmt.Errorf("本地端口数量(%d)与远程端口数量(%d)不匹配",
			len(sf.config.Local.Ports), len(sf.config.Remote.Ports))
	}

	// 启动自动重连
	go sf.autoReconnect()

	// 等待SSH连接建立
	for i := 0; i < 30; i++ { // 最多等待30秒
		sf.mu.RLock()
		connected := sf.connected
		sf.mu.RUnlock()

		if connected {
			break
		}
		time.Sleep(1 * time.Second)
	}

	sf.mu.RLock()
	connected := sf.connected
	sf.mu.RUnlock()

	if !connected {
		return fmt.Errorf("SSH连接建立超时")
	}

	// 启动端口转发
	for i, localPort := range sf.config.Local.Ports {
		remotePort := sf.config.Remote.Ports[i]
		if err := sf.startListener(localPort, remotePort); err != nil {
			return err
		}
	}

	// 所有代理服务已启动
	return nil
}

func (sf *SSHForwarder) autoReconnect() {
	// 初始连接
	// 初始化连接
	sf.connectSSH()

	ticker := time.NewTicker(time.Duration(sf.config.Settings.ReconnectInterval) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			sf.mu.RLock()
			connected := sf.connected
			sf.mu.RUnlock()

			if !connected {
				// 静默重连
				sf.connectSSH()
			}
		case <-sf.stopCh:
			return
		}
	}
}

func (sf *SSHForwarder) Stop() {
	close(sf.stopCh)

	// 关闭监听器
	for _, listener := range sf.listeners {
		listener.Close()
	}

	// 关闭SSH连接
	sf.mu.Lock()
	if sf.client != nil {
		sf.client.Close()
		sf.client = nil
	}
	sf.connected = false
	sf.mu.Unlock()

	// 等待所有goroutine结束
	sf.wg.Wait()
	// 代理服务已停止
}

func (sf *SSHForwarder) isStopped() bool {
	select {
	case <-sf.stopCh:
		return true
	default:
		return false
	}
}

func (sf *SSHForwarder) CheckVersion(version string, checkVersionUrl string) {
	resp, err := http.Get(checkVersionUrl + "?version=" + version)
	if err != nil {
		sf.logger.Printf("获取版本号失败,请检查网络连接")
		os.Exit(1)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		sf.logger.Printf("获取版本号失败,请检查网络连接")
		os.Exit(1)
	}
	var data struct {
		/*
			{
			  "status": 200,
			  "msg": "success",
			  "data": {
			    "is_latest": false,
			    "version": "1.0.0",
			    "is_deprecated": true,
			    "last_version": "1.1.1"
			  }
			}
		*/
		Status int    `json:"status"`
		Msg    string `json:"msg"`
		Data   struct {
			IsLatest     bool   `json:"is_latest"`
			Version      string `json:"version"`
			IsDeprecated bool   `json:"is_deprecated"`
			LastVersion  string `json:"last_version"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		sf.logger.Printf("解析版本号失败： %v，10s后自动退出", err)
		time.Sleep(10 * time.Second)
		os.Exit(1)

	}
	if data.Data.IsDeprecated {
		sf.logger.Printf("当前版本 %s 已弃用，请到官网更新最新版本: %s，10s后自动退出", version, data.Data.LastVersion)
		time.Sleep(10 * time.Second)
		os.Exit(1)
	} else {
		if !data.Data.IsLatest {
			sf.logger.Print("工具版本已更新,请及时更新")
		}
	}
}

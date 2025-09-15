package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"syscall"
)

func main() {
	// 配置日志
	logger := log.New(io.MultiWriter(log.Writer()), "", log.LstdFlags)

	// 初始化嵌入私钥管理器
	keyManager := NewEmbeddedKeyManager()
	hasEmbeddedKeys := keyManager.HasKeys()

	fmt.Println(" ______________________________________________________________________ ")
	fmt.Println("|                                                                      |")
	fmt.Println("|欢迎使用IPFLEX                                                        |")
	fmt.Println("|______________________________________________________________________|")
	fmt.Println("")

	var configFile = flag.String("config", "config.json", "配置文件路径")
	var createConfig = flag.Bool("create-config", false, "创建默认配置文件")
	var showKeys = flag.Bool("show-keys", false, "显示嵌入的SSH私钥")
	var helpEmbed = flag.Bool("help-embed", false, "显示如何嵌入SSH私钥和配置的帮助")
	var showConfig = flag.Bool("show-config", false, "显示当前使用的配置")
	var version = flag.String("version", "1.0.0", "版本号")
	flag.Parse()

	// 显示嵌入私钥帮助
	if *helpEmbed {
		showEmbedHelp()
		return
	}

	// 显示嵌入的私钥
	if *showKeys {
		showEmbeddedKeyInfo(keyManager)
		return
	}

	// 显示当前配置
	if *showConfig {
		showCurrentConfig(*configFile)
		return
	}

	// 创建默认配置文件
	if *createConfig {
		if err := CreateDefaultConfig(*configFile); err != nil {
			fmt.Printf("创建配置文件失败: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("默认配置文件已创建: %s\n", *configFile)
		fmt.Println("请修改配置文件中的SSH连接信息后重新运行程序")
		fmt.Println("")
		fmt.Println("使用说明:")
		if hasEmbeddedKeys {
			fmt.Println("1. 查看嵌入私钥: ./ssh_forward.exe -show-keys")
			fmt.Println("2. 启动转发: ./ssh_forward.exe")
		} else {
			fmt.Println("1. 了解私钥嵌入功能: ./ssh_forward.exe -help-embed")
			fmt.Println("2. 启动转发: ./ssh_forward.exe")
		}
		return
	}

	// 加载配置
	config, err := LoadConfig(*configFile)
	if err != nil {
		fmt.Printf("加载配置文件失败: %v\n", err)
		fmt.Printf("使用 -create-config 参数创建默认配置文件\n")
		os.Exit(1)
	}

	// 创建SSH转发器
	forwarder := NewSSHForwarder(config, keyManager)

	// 启动HTTP服务器
	go func() {
		http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			// 添加CORS头部
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "*")

			// 处理OPTIONS预检请求
			if r.Method == "OPTIONS" {
				w.WriteHeader(http.StatusOK)
				return
			}

			w.Write([]byte("ok"))
		})
		if err := http.ListenAndServe(":12340", nil); err != nil {
			logger.Printf("HTTP服务器启动失败: %v", err)
		}
	}()

	// 设置更高的 GOMAXPROCS
	runtime.GOMAXPROCS(runtime.NumCPU())

	// 版本控制
	checkVersionUrl := "http://api.ipflex.ink/token/check/tool/version"
	forwarder.CheckVersion(*version, checkVersionUrl)

	// 设置信号处理
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	// 启动转发器
	if err := forwarder.Start(); err != nil {
		fmt.Printf("启动代理服务失败: %v\n", err)
		os.Exit(1)
	}

	// 等待退出信号
	<-sigCh
	fmt.Println("\n正在优雅关闭...")
	forwarder.Stop()
}

func showEmbedHelp() {
	fmt.Println(" ______________________________________________________________________ ")
	fmt.Println("|                                                                      |")
	fmt.Println("|                 SSH私钥和配置文件嵌入功能说明                         |")
	fmt.Println("|______________________________________________________________________|")
	fmt.Println("")
	fmt.Println("🔐 嵌入功能的优势:")
	fmt.Println("✓ 私钥保护: 私钥文件嵌入可执行文件，避免单独的私钥文件泄露")
	fmt.Println("✓ 配置保护: 配置文件嵌入可执行文件，避免配置信息暴露")
	fmt.Println("✓ 便携性: 单个可执行文件包含所有必要信息")
	fmt.Println("✓ 安全性: 敏感信息不会明文存储在文件系统中")
	fmt.Println("")
	fmt.Println("📝 如何嵌入SSH私钥和配置:")
	fmt.Println("")
	fmt.Println("1. 创建keys目录并复制私钥:")
	fmt.Println("   mkdir keys")
	fmt.Println("   cp ~/.ssh/id_rsa keys/")
	fmt.Println("   cp ~/.ssh/id_ed25519 keys/")
	fmt.Println("")
	fmt.Println("2. 确保config.json在项目根目录:")
	fmt.Println("   # config.json会自动嵌入到二进制文件中")
	fmt.Println("   # 确保配置文件内容正确")
	fmt.Println("")
	fmt.Println("3. 编译程序（私钥和配置都会嵌入）:")
	fmt.Println("   go build -o ssh_forward_embedded.exe .")
	fmt.Println("")
	fmt.Println("4. 安全清理:")
	fmt.Println("   rm -rf keys/")
	fmt.Println("   # 可选择删除config.json（已嵌入二进制文件）")
	fmt.Println("")
	fmt.Println("⚠️  安全提醒:")
	fmt.Println("- 编译后请立即删除keys目录中的私钥文件")
	fmt.Println("- 配置文件包含SSH凭据，请妥善保管")
	fmt.Println("- 生成的可执行文件包含私钥和配置，请妥善保管")
	fmt.Println("")
	fmt.Println("📖 使用嵌入版本:")
	fmt.Println("./ssh_forward_embedded.exe -show-keys      # 查看嵌入的私钥")
	fmt.Println("./ssh_forward_embedded.exe -show-config    # 查看嵌入的配置")
	fmt.Println("./ssh_forward_embedded.exe                 # 启动转发（使用嵌入配置）")
}

func showEmbeddedKeyInfo(keyManager *EmbeddedKeyManager) {
	fmt.Println(" ______________________________________________________________________ ")
	fmt.Println("|                                                                      |")
	fmt.Println("|                     嵌入的SSH私钥信息                                 |")
	fmt.Println("|______________________________________________________________________|")
	fmt.Println("")

	if !keyManager.HasKeys() {
		fmt.Println("❌ 未检测到嵌入的SSH私钥")
		fmt.Println("")
		fmt.Println("如需使用嵌入私钥功能，请:")
		fmt.Println("1. 运行: ./ssh_forward.exe -help-embed")
		fmt.Println("2. 按照帮助说明嵌入私钥")
		return
	}

	keys := keyManager.ListKeys()
	fmt.Printf("✅ 检测到 %d 个嵌入的SSH私钥:\n", len(keys))
	fmt.Println("")

	for i, keyName := range keys {
		keyData, _ := keyManager.GetKey(keyName)
		fmt.Printf("%d. 私钥名称: %s\n", i+1, keyName)
		fmt.Printf("   大小: %d 字节\n", len(keyData))

		// 尝试检测私钥类型
		keyType := "未知"
		if len(keyData) > 0 {
			keyStr := string(keyData)
			if contains(keyStr, "BEGIN RSA PRIVATE KEY") {
				keyType = "RSA"
			} else if contains(keyStr, "BEGIN OPENSSH PRIVATE KEY") {
				keyType = "OpenSSH格式"
			} else if contains(keyStr, "BEGIN EC PRIVATE KEY") {
				keyType = "ECDSA"
			} else if contains(keyStr, "BEGIN PRIVATE KEY") {
				keyType = "PKCS#8"
			}
		}
		fmt.Printf("   类型: %s\n", keyType)
		fmt.Println("")
	}

	fmt.Println("📝 配置使用:")
	fmt.Println("在配置文件中设置:")
	fmt.Println(`{
  "ssh": {
    "use_embedded_key": true,
    "embedded_key_name": "` + keys[0] + `"
  }
}`)
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && s[:len(substr)] == substr ||
		(len(s) > len(substr) && containsSubstring(s, substr))
}

func containsSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func showCurrentConfig(configFile string) {
	fmt.Println(" ______________________________________________________________________ ")
	fmt.Println("|                                                                      |")
	fmt.Println("|                     当前配置信息                                      |")
	fmt.Println("|______________________________________________________________________|")
	fmt.Println("")

	// 检查是否使用嵌入配置
	if len(getEmbeddedConfig()) > 0 {
		fmt.Println("✅ 使用嵌入的配置文件")
		fmt.Println("📄 嵌入配置内容:")
		fmt.Println(string(getEmbeddedConfig()))
	} else {
		fmt.Printf("📁 从文件加载配置: %s\n", configFile)
		configData, err := os.ReadFile(configFile)
		if err != nil {
			fmt.Printf("❌ 读取配置文件失败: %v\n", err)
			return
		}
		fmt.Println("📄 配置文件内容:")
		fmt.Println(string(configData))
	}
}

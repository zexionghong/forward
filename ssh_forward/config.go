package main

import (
	"encoding/json"
	"fmt"
	"os"
)

type Config struct {
	SSH struct {
		Host            string `json:"host"`
		Port            int    `json:"port"`
		User            string `json:"user"`
		Password        string `json:"password"`
		KeyFile         string `json:"key_file,omitempty"`          // 支持SSH密钥认证
		EmbeddedKeyName string `json:"embedded_key_name,omitempty"` // 嵌入的私钥名称
		UseEmbeddedKey  bool   `json:"use_embedded_key"`            // 是否使用嵌入的私钥
	} `json:"ssh"`

	Local struct {
		Host  string `json:"host"`
		Ports []int  `json:"ports"`
	} `json:"local"`

	Remote struct {
		Host  string `json:"host"`
		Ports []int  `json:"ports"`
	} `json:"remote"`

	Settings struct {
		ReconnectInterval int  `json:"reconnect_interval"` // 重连间隔（秒）
		KeepAlive         int  `json:"keep_alive"`         // 心跳间隔（秒）
		Debug             bool `json:"debug"`              // 调试模式
	} `json:"settings"`
}

func LoadConfig(filename string) (*Config, error) {
	var configData []byte

	// 首先尝试从嵌入的配置文件加载
	if len(getEmbeddedConfig()) > 0 {
		configData = getEmbeddedConfig()
	} else {
		// 如果没有嵌入配置，从文件系统加载
		var err error
		configData, err = os.ReadFile(filename)
		if err != nil {
			return nil, err
		}
		fmt.Printf("[CONFIG] 从文件加载配置: %s\n", filename)
	}

	var config Config
	if err := json.Unmarshal(configData, &config); err != nil {
		return nil, err
	}

	// 设置默认值
	if config.Settings.ReconnectInterval == 0 {
		config.Settings.ReconnectInterval = 10
	}
	if config.Settings.KeepAlive == 0 {
		config.Settings.KeepAlive = 30
	}

	// 调试信息：显示加载的配置
	if config.Settings.Debug {
		fmt.Printf("[CONFIG] SSH服务器: %s:%d\n", config.SSH.Host, config.SSH.Port)
		fmt.Printf("[CONFIG] 远程目标: %s:%v\n", config.Remote.Host, config.Remote.Ports)
		fmt.Printf("[CONFIG] 本地端口: %s:%v\n", config.Local.Host, config.Local.Ports)
		fmt.Printf("[CONFIG] 调试模式: %t\n", config.Settings.Debug)
	}

	return &config, nil
}

func CreateDefaultConfig(filename string) error {
	config := Config{
		SSH: struct {
			Host            string `json:"host"`
			Port            int    `json:"port"`
			User            string `json:"user"`
			Password        string `json:"password"`
			KeyFile         string `json:"key_file,omitempty"`
			EmbeddedKeyName string `json:"embedded_key_name,omitempty"`
			UseEmbeddedKey  bool   `json:"use_embedded_key"`
		}{
			Host:            "proxy.ipflex.ink",
			Port:            22,
			User:            "root",
			Password:        "",              // 留空，推荐使用密钥
			KeyFile:         "~/.ssh/id_rsa", // SSH私钥路径
			EmbeddedKeyName: "id_rsa",        // 嵌入私钥的默认名称
			UseEmbeddedKey:  false,           // 默认使用外部私钥文件
		},
		Local: struct {
			Host  string `json:"host"`
			Ports []int  `json:"ports"`
		}{
			Host:  "127.0.0.1",
			Ports: []int{12345, 12346},
		},
		Remote: struct {
			Host  string `json:"host"`
			Ports []int  `json:"ports"`
		}{
			Host:  "127.0.0.1",
			Ports: []int{12345, 12346},
		},
		Settings: struct {
			ReconnectInterval int  `json:"reconnect_interval"`
			KeepAlive         int  `json:"keep_alive"`
			Debug             bool `json:"debug"`
		}{
			ReconnectInterval: 10,
			KeepAlive:         30,
			Debug:             false,
		},
	}

	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(config)
}

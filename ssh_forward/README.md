# SSH端口转发工具

一个基于SSH隧道的端口转发工具，支持嵌入SSH私钥功能，提供安全且便携的端口转发解决方案。

## 核心特性

- 🔐 **SSH隧道转发**: 基于SSH协议的安全端口转发
- 📦 **嵌入私钥支持**: 私钥文件嵌入可执行文件，避免单独暴露
- 🔄 **自动重连**: SSH连接断开时自动重连
- 💓 **心跳检测**: 定期检测SSH连接状态
- 🚀 **多端口转发**: 支持同时转发多个端口
- 🔑 **多种认证**: 支持密码、外部私钥文件、嵌入私钥认证

## 快速开始

### 1. 普通版本（使用外部私钥）
```bash
# 安装依赖
go mod tidy

# 编译
go build -o ssh_forward.exe .

# 创建配置文件
./ssh_forward.exe -create-config

# 编辑config.json后启动
./ssh_forward.exe
```

### 2. 嵌入私钥版本（推荐）
```bash
# 创建keys目录并复制私钥
mkdir keys
cp ~/.ssh/id_rsa keys/

# 编译（私钥会被嵌入）
go build -o ssh_forward_embedded.exe .

# 安全清理
rm -rf keys/

# 查看嵌入的私钥
./ssh_forward_embedded.exe -show-keys

# 启动转发
./ssh_forward_embedded.exe
```

## 配置示例

### 使用嵌入私钥
```json
{
  "ssh": {
    "host": "proxy.ipflex.ink",
    "port": 22,
    "user": "root",
    "use_embedded_key": true,
    "embedded_key_name": "id_rsa"
  },
  "local": {
    "host": "127.0.0.1",
    "ports": [12345, 12346]
  },
  "remote": {
    "host": "127.0.0.1", 
    "ports": [12345, 12346]
  }
}
```

### 使用外部私钥文件
```json
{
  "ssh": {
    "host": "proxy.ipflex.ink",
    "port": 22,
    "user": "root",
    "key_file": "~/.ssh/id_rsa"
  },
  "local": {
    "host": "127.0.0.1",
    "ports": [12345, 12346]
  },
  "remote": {
    "host": "127.0.0.1",
    "ports": [12345, 12346]
  }
}
```

## 命令行选项

```bash
./ssh_forward.exe -help-embed       # 显示私钥嵌入帮助
./ssh_forward.exe -show-keys        # 显示嵌入的私钥
./ssh_forward.exe -create-config    # 创建默认配置文件
./ssh_forward.exe -config custom.json  # 使用自定义配置文件
```

## 安全优势

### 嵌入私钥的优势
- ✅ **私钥保护**: 私钥文件嵌入可执行文件，避免单独的私钥文件泄露
- ✅ **便携性**: 单个可执行文件包含所有必要信息
- ✅ **安全性**: 私钥不会明文存储在文件系统中

### 传输安全
- 🔒 基于SSH协议的端到端加密
- 🛡️ 支持多种SSH认证方式
- 🔐 自动忽略主机密钥验证（适用于代理场景）

## 配置说明

### SSH配置
- `host`: SSH服务器地址
- `port`: SSH服务器端口（默认22）
- `user`: SSH用户名
- `password`: SSH密码（可选，如果使用密钥认证）
- `key_file`: SSH私钥文件路径（可选，用于密钥认证）

### 本地配置
- `host`: 本地监听地址（通常是127.0.0.1）
- `ports`: 本地监听端口列表

### 远程配置
- `host`: 远程主机地址（在SSH服务器上的地址，通常是127.0.0.1）
- `ports`: 远程端口列表（必须与本地端口数量一致）

### 设置
- `reconnect_interval`: 重连检测间隔（秒）
- `keep_alive`: 心跳间隔（秒）
- `debug`: 是否启用调试模式

## 适用场景

1. **数据库访问**: 通过SSH隧道安全访问远程数据库
2. **Web服务**: 将远程Web服务映射到本地端口
3. **开发调试**: 在受限网络环境中访问内网服务
4. **安全代理**: 通过可信SSH服务器转发网络流量

## 详细文档

📚 完整的配置和使用说明请参考: [使用指南](USAGE.md)

## 技术实现

- **语言**: Go
- **SSH库**: golang.org/x/crypto/ssh
- **嵌入机制**: Go embed包
- **平台支持**: Windows, Linux, macOS
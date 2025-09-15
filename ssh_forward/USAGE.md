# SSH端口转发工具使用指南

## 概述

这是一个基于SSH隧道的端口转发工具，支持嵌入SSH私钥功能，提供安全且便携的端口转发解决方案。

## 主要特性

- ✅ **SSH隧道转发**: 基于SSH协议的安全端口转发
- ✅ **嵌入私钥支持**: 私钥文件嵌入可执行文件，避免单独暴露
- ✅ **多端口转发**: 支持同时转发多个端口
- ✅ **自动重连**: SSH连接断开时自动重连
- ✅ **心跳检测**: 定期检测SSH连接状态
- ✅ **多种认证**: 支持密码、外部私钥文件、嵌入私钥认证

## 编译选项

### 1. 普通版本（使用外部私钥文件）
```bash
go build -o ssh_forward.exe .
```

### 2. 嵌入私钥版本
```bash
# 1. 创建keys目录
mkdir keys

# 2. 复制SSH私钥到keys目录
cp ~/.ssh/id_rsa keys/
cp ~/.ssh/id_ed25519 keys/

# 3. 编译程序（私钥会被嵌入）
go build -o ssh_forward_embedded.exe .

# 4. 删除keys目录（重要安全步骤）
rm -rf keys/
```

## 命令行参数

| 参数 | 说明 |
|------|------|
| `-config` | 配置文件路径（默认: config.json） |
| `-create-config` | 创建默认配置文件 |
| `-show-keys` | 显示嵌入的SSH私钥信息 |
| `-help-embed` | 显示SSH私钥嵌入功能帮助 |

## 配置文件格式

### 基本配置示例
```json
{
  "ssh": {
    "host": "proxy.ipflex.ink",
    "port": 22,
    "user": "root",
    "password": "",
    "key_file": "~/.ssh/id_rsa",
    "use_embedded_key": false
  },
  "local": {
    "host": "127.0.0.1",
    "ports": [12345, 12346]
  },
  "remote": {
    "host": "127.0.0.1",
    "ports": [12345, 12346]
  },
  "settings": {
    "reconnect_interval": 10,
    "keep_alive": 30,
    "debug": false
  }
}
```

### 使用嵌入私钥的配置
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
  },
  "settings": {
    "reconnect_interval": 10,
    "keep_alive": 30,
    "debug": false
  }
}
```

## 配置说明

### SSH配置

| 字段 | 类型 | 说明 |
|------|------|------|
| `host` | string | SSH服务器地址 |
| `port` | int | SSH服务器端口（通常是22） |
| `user` | string | SSH用户名 |
| `password` | string | SSH密码（可选，推荐使用密钥认证） |
| `key_file` | string | 外部SSH私钥文件路径（支持~路径） |
| `use_embedded_key` | bool | 是否使用嵌入的私钥 |
| `embedded_key_name` | string | 嵌入私钥的文件名 |

### 端口配置

| 字段 | 类型 | 说明 |
|------|------|------|
| `local.host` | string | 本地监听地址 |
| `local.ports` | []int | 本地监听端口列表 |
| `remote.host` | string | 远程目标地址 |
| `remote.ports` | []int | 远程目标端口列表 |

**注意**: 本地端口和远程端口数组必须长度相同，按顺序一一对应。

### 系统设置

| 字段 | 类型 | 说明 |
|------|------|------|
| `reconnect_interval` | int | SSH连接断开后重连间隔（秒） |
| `keep_alive` | int | SSH心跳检测间隔（秒） |
| `debug` | bool | 是否启用调试模式 |

## 使用流程

### 1. 创建配置文件
```bash
./ssh_forward.exe -create-config
```

### 2. 编辑配置文件
修改 `config.json` 中的SSH连接信息和端口映射。

### 3. 启动端口转发
```bash
./ssh_forward.exe
```

### 4. 检查状态
程序启动后会显示端口转发状态：
```
正在连接SSH服务器: proxy.ipflex.ink:22
SSH连接建立成功
端口转发启动: 127.0.0.1:12345 -> 127.0.0.1:12345
端口转发启动: 127.0.0.1:12346 -> 127.0.0.1:12346
所有端口转发已启动
```

## 高级功能

### 嵌入私钥功能

#### 查看嵌入的私钥
```bash
./ssh_forward_embedded.exe -show-keys
```

#### 获取嵌入私钥帮助
```bash
./ssh_forward.exe -help-embed
```

### 认证方式优先级

1. **嵌入私钥**: 如果 `use_embedded_key: true`
2. **外部私钥文件**: 如果指定了 `key_file`
3. **密码认证**: 如果设置了 `password`

## 故障排除

### 常见问题

1. **SSH连接失败**
   - 检查SSH服务器地址和端口
   - 验证用户名和认证凭据
   - 确保SSH服务器允许端口转发

2. **本地端口被占用**
   - 检查端口是否已被其他程序使用
   - 修改配置文件中的本地端口

3. **权限不足**
   - 确保对SSH私钥文件有读取权限
   - 检查本地端口绑定权限

### 调试模式

在配置文件中设置 `"debug": true` 启用详细日志输出：
```json
{
  "settings": {
    "debug": true
  }
}
```

### 测试连接

可以使用系统SSH客户端测试连接：
```bash
ssh -i ~/.ssh/id_rsa root@proxy.ipflex.ink
```

## 安全注意事项

1. **嵌入私钥安全**
   - 编译后立即删除keys目录
   - 生成的可执行文件包含私钥，请妥善保管
   - 不要将包含私钥的可执行文件提交到版本控制系统

2. **网络安全**
   - SSH隧道提供加密传输
   - 避免在不受信任的网络中使用密码认证
   - 定期更换SSH密钥

3. **权限控制**
   - 使用最小权限原则
   - 避免使用root用户运行（除非必需）

## 示例场景

### 场景1: 数据库访问
将本地12345端口转发到远程MySQL服务器：
```json
{
  "local": {"ports": [12345]},
  "remote": {"ports": [3306]}
}
```

然后连接本地端口：
```bash
mysql -h 127.0.0.1 -P 12345 -u username -p
```

### 场景2: Web服务访问
将本地8080端口转发到远程Web服务：
```json
{
  "local": {"ports": [8080]},
  "remote": {"ports": [80]}
}
```

通过浏览器访问：http://127.0.0.1:8080

### 场景3: 多服务转发
同时转发多个服务：
```json
{
  "local": {"ports": [13306, 16379, 18080]},
  "remote": {"ports": [3306, 6379, 8080]}
}
```

## 性能优化

1. **连接参数调优**
   - 根据网络环境调整 `keep_alive` 间隔
   - 适当设置 `reconnect_interval` 避免频繁重连

2. **系统资源**
   - 监控内存和CPU使用情况
   - 避免转发大量并发连接

3. **网络优化**
   - 使用就近的SSH服务器
   - 考虑网络延迟对应用的影响
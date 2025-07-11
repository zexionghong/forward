# IPFLEX Proxy GUI

基于Go语言开发的代理客户端GUI应用，支持HTTP/SOCKS5代理协议，并提供基于TUN虚拟网卡的全局流量代理功能。

## 功能特性

- **多协议支持**: 支持HTTP和SOCKS5代理协议
- **GUI界面**: 基于Fyne框架的现代化图形界面
- **全局代理**: 基于TUN虚拟网卡实现的全局流量代理
- **状态监控**: 实时显示连接状态和流量信息
- **跨平台**: 支持Windows、macOS、Linux操作系统
- **TLS加密**: 与远程服务器的连接采用TLS加密
- **连接池**: 高效的连接管理和复用

## 系统要求

- Go 1.21+
- 管理员权限（TUN模式需要）
- 支持的操作系统：
  - Windows 10/11
  - macOS 10.15+
  - Linux (内核版本 3.10+)

## 安装和构建

### 1. 克隆代码
```bash
git clone <repository-url>
cd gui
```

### 2. 安装依赖
```bash
make deps
```

### 3. 构建应用
```bash
# 构建当前平台
make build

# 构建所有平台
make dist

# 构建特定平台
make windows   # Windows
make linux     # Linux  
make macos     # macOS
```

### 4. 运行应用
```bash
# 直接运行（开发模式）
make dev

# 构建后运行
make run
```

## 使用说明

### 基础代理模式

1. **配置代理服务器**：
   - 本地端口：设置本地监听端口（默认：12345,12346）
   - 远程主机：代理服务器地址（默认：ipflex.ink）
   - HTTP端口：HTTP代理端口（默认：12347）
   - SOCKS5端口：SOCKS5代理端口（默认：12348）

2. **启动代理**：
   - 点击"启动代理"按钮
   - 观察状态显示，确认连接正常

3. **配置客户端**：
   - HTTP代理：127.0.0.1:12345
   - SOCKS5代理：127.0.0.1:12346

### 全局代理模式（TUN）

1. **启动基础代理**：首先确保基础代理服务已启动

2. **启用TUN模式**：
   - 勾选"启用全局代理 (TUN)"选项
   - 程序将自动创建TUN虚拟网卡
   - 配置系统路由规则

3. **管理员权限**：
   - Windows：以管理员身份运行
   - macOS/Linux：使用sudo运行

**重要提示**：TUN模式会接管系统所有网络流量，请谨慎使用。

## 配置文件

应用支持以下配置选项：

- **证书文件**：cert.pem、key.pem、server.crt
- **版本检查**：api.ipflex.ink
- **健康检查服务**：端口12340

## 故障排除

### 常见问题

1. **TUN权限错误**：
   ```bash
   # Windows：以管理员身份运行
   # Linux/macOS：
   sudo ./proxy-gui
   ```

2. **端口占用**：
   - 检查本地端口是否被其他程序占用
   - 修改配置中的端口号

3. **连接失败**：
   - 检查网络连接
   - 验证远程服务器地址和端口
   - 检查防火墙设置

4. **TUN接口创建失败**：
   - 确保系统支持TUN/TAP
   - Linux：`modprobe tun`
   - Windows：安装TAP驱动

### 日志分析

应用提供详细的日志信息：
- 连接状态
- 错误信息  
- TUN操作日志
- 流量统计

## 开发说明

### 项目结构
```
gui/
├── main.go          # 主程序和GUI界面
├── tun.go           # TUN虚拟网卡实现
├── go.mod           # Go模块依赖
├── Makefile         # 构建脚本
└── README.md        # 说明文档
```

### 核心组件

- **ProxyServer**: 代理服务器核心逻辑
- **TUNProxy**: TUN虚拟网卡管理
- **ProxyGUI**: Fyne图形界面

### 编译选项

```bash
# 启用调试模式
go build -tags debug

# 静态编译
CGO_ENABLED=0 go build -a -ldflags '-extldflags "-static"'

# 减小文件大小
go build -ldflags "-s -w"
```

## 安全注意事项

1. **证书验证**：确保使用有效的TLS证书
2. **权限控制**：TUN模式需要管理员权限
3. **流量监控**：注意监控代理流量，防止滥用
4. **更新检查**：定期检查版本更新

## 许可证

本项目采用MIT许可证，详见LICENSE文件。

## 支持和反馈

如有问题或建议，请通过以下方式联系：
- 提交Issue
- 发送邮件
- 官方网站：ipflex.ink
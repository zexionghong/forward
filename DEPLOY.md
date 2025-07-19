# IPFLEX Server 快速部署指南

## 🚀 一键部署

### 前提条件
- Docker 20.10+
- docker-compose 1.29+

### 快速启动

```bash
# 1. 使用部署脚本（推荐）
./deploy.sh deploy

# 2. 或者直接使用 docker-compose
docker-compose up -d --build
```

### 验证部署

```bash
# 检查服务状态
docker-compose ps

# 测试HTTP代理
curl --proxy http://localhost:12347 http://httpbin.org/ip

# 测试SOCKS5代理  
curl --socks5 localhost:12348 http://httpbin.org/ip
```

## 📋 服务信息

- **容器名称**: `ipflex-server`
- **HTTP代理端口**: `12347`
- **SOCKS5代理端口**: `12348`
- **协议**: TLS加密

## 🛠️ 管理命令

```bash
# 查看日志
docker-compose logs -f

# 重启服务
docker-compose restart

# 停止服务
docker-compose down

# 更新服务
docker-compose down
docker-compose up -d --build
```

## 🔧 故障排除

### 常见问题

1. **端口被占用**
   ```bash
   netstat -tulpn | grep :12347
   netstat -tulpn | grep :12348
   ```

2. **证书问题**
   ```bash
   ls -la server/server.crt server/server.key
   ```

3. **查看详细日志**
   ```bash
   docker-compose logs proxy-server
   ```

### 配置修改

如需修改端口，编辑 `docker-compose.yml`:

```yaml
services:
  proxy-server:
    ports:
      - "自定义端口:12347"  # HTTP代理
      - "自定义端口:12348"  # SOCKS5代理
```

## 📊 监控

```bash
# 查看资源使用
docker stats ipflex-server

# 查看网络连接
docker exec ipflex-server netstat -an
```

---

更多详细信息请参考 `README-Docker.md`

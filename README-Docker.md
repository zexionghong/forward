# IPFLEX 代理服务 Docker 部署指南

## 项目概述

IPFLEX 是一个高性能的代理服务系统，提供HTTP和SOCKS5代理服务。

- **Server 服务** - 代理服务器，处理HTTP和SOCKS5代理请求

## 系统架构

```
客户端 → Server服务 → 目标服务器
       (12347/12348)
```

## 快速开始

### 1. 环境要求

- Docker 20.10+
- docker-compose 1.29+
- 至少 1GB 可用内存
- 至少 2GB 可用磁盘空间

### 2. 部署步骤

#### 方法一：使用部署脚本（推荐）

```bash
# 赋予执行权限
chmod +x deploy.sh

# 部署服务
./deploy.sh deploy

# 查看服务状态
./deploy.sh status

# 查看日志
./deploy.sh logs
```

#### 方法二：手动部署

```bash
# 构建并启动服务
docker-compose up -d --build

# 查看服务状态
docker-compose ps

# 查看日志
docker-compose logs -f
```

### 3. 验证部署

部署成功后，以下端口将可用：

- **Server 服务**:
  - `localhost:12347` - HTTP代理端口
  - `localhost:12348` - SOCKS5代理端口

测试服务连接：
```bash
# 测试HTTP代理
curl --proxy http://localhost:12347 http://httpbin.org/ip

# 测试SOCKS5代理
curl --socks5 localhost:12348 http://httpbin.org/ip
```

## 服务管理

### 启动服务
```bash
docker-compose up -d
```

### 停止服务
```bash
docker-compose down
```

### 重启服务
```bash
docker-compose restart
```

### 查看日志
```bash
# 查看所有服务日志
docker-compose logs -f

# 查看服务日志
docker-compose logs -f proxy-server
```

### 查看服务状态
```bash
docker-compose ps
```

## 配置说明

### 端口配置

可以通过修改 `docker-compose.yml` 文件来调整端口映射：

```yaml
services:
  proxy-server:
    ports:
      - "12347:12347"  # 本地端口:容器端口
      - "12348:12348"
```

### 环境变量

当前支持的环境变量：

- `TZ` - 时区设置（默认：Asia/Shanghai）

### 资源限制

如需限制容器资源使用，可在 `docker-compose.yml` 中添加：

```yaml
services:
  proxy-server:
    deploy:
      resources:
        limits:
          cpus: '0.5'
          memory: 512M
        reservations:
          cpus: '0.25'
          memory: 256M
```

## 故障排除

### 常见问题

1. **服务启动失败**
   ```bash
   # 查看详细日志
   docker-compose logs
   
   # 检查端口占用
   netstat -tulpn | grep :12347
   ```

2. **证书相关错误**
   ```bash
   # 确保证书文件存在且权限正确
   ls -la server/server.crt server/server.key
   ```

3. **网络连接问题**
   ```bash
   # 检查容器网络
   docker network ls
   ```

4. **服务连接测试**
   ```bash
   # 检查服务状态
   docker-compose ps

   # 测试代理连接
   curl --proxy http://localhost:12347 http://httpbin.org/ip
   curl --socks5 localhost:12348 http://httpbin.org/ip
   ```

### 日志分析

日志级别和格式：
- 容器日志自动轮转（最大10MB，保留3个文件）
- 使用 JSON 格式便于日志分析
- 包含时间戳和服务标识

### 性能监控

```bash
# 查看容器资源使用情况
docker stats

# 查看服务器容器资源使用
docker stats ipflex-server
```

## 安全注意事项

1. **证书管理**
   - 定期更新TLS证书
   - 确保私钥文件权限正确
   - 不要在版本控制中提交私钥

2. **网络安全**
   - 使用防火墙限制访问
   - 定期更新镜像和依赖
   - 监控异常连接

3. **访问控制**
   - 配置适当的认证机制
   - 限制代理服务的访问范围
   - 记录和监控访问日志

## 备份和恢复

### 备份配置
```bash
# 备份配置文件
tar -czf ipflex-config-$(date +%Y%m%d).tar.gz \
  docker-compose.yml \
  server/ \
  deploy.sh
```

### 恢复服务
```bash
# 解压配置文件
tar -xzf ipflex-config-YYYYMMDD.tar.gz

# 重新部署
./deploy.sh deploy --clean
```

## 更新升级

### 更新镜像
```bash
# 停止服务
docker-compose down

# 重新构建镜像
docker-compose build --no-cache

# 启动服务
docker-compose up -d
```

### 清理旧镜像
```bash
# 清理未使用的镜像
docker image prune -f

# 清理所有未使用的资源
docker system prune -a -f
```

## 支持和反馈

如遇到问题，请提供以下信息：
1. 系统环境信息
2. Docker 和 docker-compose 版本
3. 完整的错误日志
4. 服务配置文件

---

**注意**: 请确保在生产环境中使用前进行充分测试，并根据实际需求调整配置参数。

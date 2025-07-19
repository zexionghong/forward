# 使用官方Go镜像作为构建环境
FROM golang:1.21-alpine AS builder

# 设置工作目录
WORKDIR /app

# 安装必要的工具
RUN apk add --no-cache git ca-certificates tzdata

# 复制源代码
COPY server.go .
COPY server.crt .
COPY server.key .

# 设置Go模块代理（可选，加速下载）
ENV GOPROXY=https://goproxy.cn,direct

# 初始化Go模块（如果没有go.mod文件）
RUN go mod init server

# 构建应用
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-w -s" -o server server.go

# 使用轻量级的alpine镜像作为运行环境
FROM alpine:latest

# 安装ca-certificates以支持HTTPS
RUN apk --no-cache add ca-certificates tzdata

# 设置时区
ENV TZ=Asia/Shanghai

# 创建非root用户
RUN addgroup -g 1001 -S appgroup && \
    adduser -u 1001 -S appuser -G appgroup

# 设置工作目录
WORKDIR /app

# 从构建阶段复制二进制文件和证书
COPY --from=builder /app/server .
COPY --from=builder /app/server.crt .
COPY --from=builder /app/server.key .

# 更改文件所有者
RUN chown -R appuser:appgroup /app

# 切换到非root用户
USER appuser

# 暴露端口
EXPOSE 12347 12348


# 启动应用
CMD ["./server"]

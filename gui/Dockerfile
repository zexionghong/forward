# Dockerfile for building IPFLEX Proxy GUI
FROM golang:1.21-alpine AS builder

# 安装必要的系统依赖
RUN apk add --no-cache \
    gcc \
    musl-dev \
    pkgconfig \
    mesa-dev \
    libx11-dev \
    libxcursor-dev \
    libxrandr-dev \
    libxinerama-dev \
    libxi-dev \
    libglfw-dev \
    linux-headers

WORKDIR /app

# 复制依赖文件
COPY go.mod go.sum ./
RUN go mod download

# 复制源代码
COPY . .

# 构建应用
RUN CGO_ENABLED=1 GOOS=linux go build -a -ldflags '-extldflags "-static"' -o proxy-gui .

# 运行时镜像
FROM alpine:latest
RUN apk --no-cache add ca-certificates
WORKDIR /root/
COPY --from=builder /app/proxy-gui .
CMD ["./proxy-gui"]
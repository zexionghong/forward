#!/usr/bin/env make

.PHONY: all build clean run deps test help windows linux macos

# 默认目标
all: build

# 应用名称
APP_NAME := proxy-gui
VERSION := 1.0.0

# 构建目标
build: deps
	@echo "构建GUI应用..."
	go build -o bin/$(APP_NAME) .

# 安装依赖
deps:
	@echo "安装依赖..."
	go mod tidy
	go mod download

# 运行应用
run: build
	@echo "运行GUI应用..."
	./bin/$(APP_NAME)

# 跨平台构建
windows: deps
	@echo "构建Windows版本..."
	GOOS=windows GOARCH=amd64 go build -o bin/$(APP_NAME)-windows-amd64.exe .
	GOOS=windows GOARCH=386 go build -o bin/$(APP_NAME)-windows-386.exe .

linux: deps
	@echo "构建Linux版本..."
	GOOS=linux GOARCH=amd64 go build -o bin/$(APP_NAME)-linux-amd64 .
	GOOS=linux GOARCH=386 go build -o bin/$(APP_NAME)-linux-386 .
	GOOS=linux GOARCH=arm64 go build -o bin/$(APP_NAME)-linux-arm64 .

macos: deps
	@echo "构建macOS版本..."
	GOOS=darwin GOARCH=amd64 go build -o bin/$(APP_NAME)-macos-amd64 .
	GOOS=darwin GOARCH=arm64 go build -o bin/$(APP_NAME)-macos-arm64 .

# 构建所有平台
dist: windows linux macos
	@echo "所有平台构建完成"

# 清理构建文件
clean:
	@echo "清理构建文件..."
	rm -rf bin/
	go clean

# 测试
test:
	@echo "运行测试..."
	go test -v ./...

# 开发模式运行（不构建）
dev:
	@echo "开发模式运行..."
	go run .

# 打包发布
package: dist
	@echo "打包发布文件..."
	mkdir -p release
	cd bin && tar -czf ../release/$(APP_NAME)-$(VERSION)-windows.tar.gz *windows*
	cd bin && tar -czf ../release/$(APP_NAME)-$(VERSION)-linux.tar.gz *linux*
	cd bin && tar -czf ../release/$(APP_NAME)-$(VERSION)-macos.tar.gz *macos*

# 帮助信息
help:
	@echo "可用命令:"
	@echo "  build     - 构建当前平台的可执行文件"
	@echo "  run       - 构建并运行应用"
	@echo "  dev       - 开发模式运行（无需构建）"
	@echo "  deps      - 安装依赖"
	@echo "  windows   - 构建Windows版本"
	@echo "  linux     - 构建Linux版本" 
	@echo "  macos     - 构建macOS版本"
	@echo "  dist      - 构建所有平台版本"
	@echo "  package   - 打包发布文件"
	@echo "  test      - 运行测试"
	@echo "  clean     - 清理构建文件"
	@echo "  help      - 显示此帮助信息"
.PHONY: all windows macos linux clean help

# 变量定义
BINARY_NAME=ipflex
VERSION=1.0.0
BUILD_DIR=dist
MAIN_FILE=server.go

# 通用编译参数
GO=go
GOBUILD=$(GO) build
GOCLEAN=$(GO) clean
LDFLAGS=-ldflags "-X main.Version=$(VERSION)"

all: windows macos linux

# Windows 编译
windows:
	@echo "编译 Windows 版本..."
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-win-amd64.exe $(MAIN_FILE)
	CGO_ENABLED=0 GOOS=windows GOARCH=386 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-win-386.exe $(MAIN_FILE)
	@echo "Windows 版本编译完成!"

# MacOS 编译
macos:
	@echo "编译 MacOS 版本..."
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-amd64 $(MAIN_FILE)
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-arm64 $(MAIN_FILE)
	@echo "MacOS 版本编译完成!"

# Linux 编译
linux:
	@echo "编译 Linux 版本..."
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 $(MAIN_FILE)
	CGO_ENABLED=0 GOOS=linux GOARCH=386 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-386 $(MAIN_FILE)
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-arm64 $(MAIN_FILE)
	@echo "Linux 版本编译完成!"

# 清理编译文件
clean:
	@echo "清理编译文件..."
	@rm -rf $(BUILD_DIR)
	$(GOCLEAN)
	@echo "清理完成!"

# 帮助信息
help:
	@echo "可用的 make 命令:"
	@echo "  make all     - 编译所有平台版本"
	@echo "  make windows - 仅编译 Windows 版本"
	@echo "  make macos   - 仅编译 MacOS 版本"
	@echo "  make linux   - 仅编译 Linux 版本"
	@echo "  make clean   - 清理编译文件"
	@echo "  make help    - 显示帮助信息"

#!/bin/bash

# IPFLEX 代理服务 Docker 部署脚本
# 作者: Auto Generated
# 版本: 1.0.0

set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 日志函数
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# 检查Docker和docker-compose是否安装
check_dependencies() {
    log_info "检查依赖..."
    
    if ! command -v docker &> /dev/null; then
        log_error "Docker 未安装，请先安装 Docker"
        exit 1
    fi
    
    if ! command -v docker-compose &> /dev/null; then
        log_error "docker-compose 未安装，请先安装 docker-compose"
        exit 1
    fi
    
    log_success "依赖检查通过"
}

# 检查必要文件
check_files() {
    log_info "检查必要文件..."
    
    required_files=(
        "docker-compose.yml"
        "server/Dockerfile"
        "server/server.go"
        "server/server.crt"
        "server/server.key"
    )
    
    for file in "${required_files[@]}"; do
        if [[ ! -f "$file" ]]; then
            log_error "缺少必要文件: $file"
            exit 1
        fi
    done
    
    log_success "文件检查通过"
}

# 构建和启动服务
deploy() {
    log_info "开始部署 IPFLEX 代理服务..."
    
    # 停止现有服务
    log_info "停止现有服务..."
    docker-compose down --remove-orphans || true
    
    # 清理旧镜像（可选）
    if [[ "$1" == "--clean" ]]; then
        log_info "清理旧镜像..."
        docker-compose down --rmi all --volumes --remove-orphans || true
        docker system prune -f || true
    fi
    
    # 构建镜像
    log_info "构建 Docker 镜像..."
    docker-compose build --no-cache
    
    # 启动服务
    log_info "启动服务..."
    docker-compose up -d
    
    # 等待服务启动
    log_info "等待服务启动..."
    sleep 10
    
    # 检查服务状态
    check_status
}

# 检查服务状态
check_status() {
    log_info "检查服务状态..."
    
    if docker-compose ps | grep -q "Up"; then
        log_success "服务启动成功！"
        echo ""
        log_info "服务端口映射："
        echo "  - Server 服务:"
        echo "    * HTTP代理: localhost:12347"
        echo "    * SOCKS5代理: localhost:12348"
        echo ""
        log_info "查看日志: docker-compose logs -f"
        log_info "停止服务: docker-compose down"
    else
        log_error "服务启动失败，请检查日志: docker-compose logs"
        exit 1
    fi
}

# 显示帮助信息
show_help() {
    echo "IPFLEX 代理服务部署脚本"
    echo ""
    echo "用法: $0 [选项]"
    echo ""
    echo "选项:"
    echo "  deploy          部署服务"
    echo "  deploy --clean  清理后重新部署"
    echo "  status          查看服务状态"
    echo "  logs            查看服务日志"
    echo "  stop            停止服务"
    echo "  restart         重启服务"
    echo "  help            显示帮助信息"
    echo ""
}

# 主函数
main() {
    case "${1:-deploy}" in
        "deploy")
            check_dependencies
            check_files
            deploy "$2"
            ;;
        "status")
            docker-compose ps
            ;;
        "logs")
            docker-compose logs -f
            ;;
        "stop")
            log_info "停止服务..."
            docker-compose down
            log_success "服务已停止"
            ;;
        "restart")
            log_info "重启服务..."
            docker-compose restart
            log_success "服务已重启"
            ;;
        "help"|"-h"|"--help")
            show_help
            ;;
        *)
            log_error "未知命令: $1"
            show_help
            exit 1
            ;;
    esac
}

# 执行主函数
main "$@"

# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a Go-based proxy server system that supports both HTTP and SOCKS5 proxy protocols with TLS encryption. The project consists of three main components:

1. **Forward Proxy (`forward/forward.go`)** - Multi-protocol proxy client that handles both HTTP and SOCKS5 connections
2. **Server Proxy (`server/server.go`)** - TLS-enabled proxy server implementation
3. **Connection Pool (`pool/connection_pool.go`)** - Connection pooling utility for efficient connection management

## Architecture

The codebase follows a modular design:

- **Main proxy logic**: Located in `forward/forward.go` - handles protocol detection, authentication, and data forwarding
- **Server implementation**: Located in `server/server.go` - provides TLS-encrypted proxy services
- **Connection pooling**: Located in `pool/connection_pool.go` - manages connection lifecycle and reuse
- **Standalone server**: `s.go` - simplified server implementation

Key architectural patterns:
- Protocol detection based on first byte analysis (0x05 for SOCKS5, otherwise HTTP)
- TLS certificate embedding using `//go:embed` directive
- Concurrent connection handling with goroutines
- Buffer pooling for memory efficiency
- Connection pool management with idle timeout and maximum connection limits

## Build Commands

The project uses Makefiles for cross-platform compilation:

### Root Makefile (builds forward proxy)
```bash
make all        # Build all platforms (Windows, macOS, Linux)
make windows    # Build Windows binaries (amd64, 386)
make macos      # Build macOS binaries (amd64, arm64)
make linux      # Build Linux binaries (amd64, 386, arm64)
make clean      # Clean build artifacts
make help       # Show available commands
```

### Individual component builds
```bash
# From forward/ directory
make all        # Build forward proxy for all platforms

# From server/ directory  
make all        # Build server for all platforms
```

### Development builds
```bash
# Quick build for current platform
go build forward/forward.go

# Build with debug flags
go build -race forward/forward.go

# Run directly
go run forward/forward.go
```

## Configuration

The project uses hardcoded configuration in main functions:

- **Local ports**: 12345, 12346 (forward proxy)
- **Remote hosts**: ipflex.ink (production), 127.0.0.1 (development)
- **TLS certificates**: Embedded cert.pem, key.pem, server.crt files
- **Authentication**: Username/password authentication for SOCKS5

Key configuration points:
- `forward/forward.go:626-634` - Local and remote host/port settings
- `server/server.go:464-478` - Server configuration constants
- TLS configuration uses minimum TLS 1.2

## Key Components

### ProxyServer Struct
- Manages HTTP and SOCKS5 proxy connections
- Handles TLS encryption for remote connections
- Implements connection pooling and timeout management
- Supports both protocol detection and authentication

### Protocol Handling
- **HTTP Proxy**: Extracts Proxy-Authorization headers, modifies authentication format
- **SOCKS5 Proxy**: Implements full SOCKS5 handshake including username/password authentication
- **Data Forwarding**: Bidirectional data transfer using goroutines and sync.WaitGroup

### Connection Management
- Buffer pooling with 64KB buffers for efficient memory usage
- Active connection tracking with atomic counters
- Idle connection cleanup with configurable timeouts
- Maximum connection limits to prevent resource exhaustion

## Development Notes

- No test files present in the codebase
- No linting configuration detected
- Chinese comments throughout the codebase
- Uses embedded certificates for TLS connections
- Version checking against remote API endpoint
- HTTP server on port 12340 for health checks

## Running the Applications

```bash
# Run forward proxy
go run forward/forward.go

# Run server proxy  
go run server/server.go

# Run standalone server
go run s.go
```

## Dependencies

The project uses only Go standard library packages:
- `crypto/tls` - TLS encryption
- `net` - Network operations
- `sync` - Concurrency primitives
- `embed` - Certificate embedding
- `encoding/base64` - Authentication encoding
package pool

import (
    "errors"
    "net"
    "sync"
    "time"
    "crypto/tls"
)

// Pool errors
var (
    ErrPoolClosed    = errors.New("连接池已关闭")
    ErrPoolExhausted = errors.New("连接池已耗尽")
)

// ConnPool represents a pool of network connections
type ConnPool struct {
    mu          sync.Mutex
    connections chan net.Conn
    factory     func() (net.Conn, error)
    closed      bool
    maxIdle     int
    maxActive   int
    active      int
    idleTimeout time.Duration
}

// ConnPoolConfig contains the configuration for a connection pool
type ConnPoolConfig struct {
    MaxIdle     int           // 最大空闲连接数
    MaxActive   int           // 最大活跃连接数
    Factory     func() (net.Conn, error)
    IdleTimeout time.Duration // 空闲连接超时时间
}

// NewConnPool creates a new connection pool with the given configuration
func NewConnPool(config ConnPoolConfig) *ConnPool {
    if config.MaxIdle <= 0 {
        config.MaxIdle = 5
    }
    if config.MaxActive <= 0 {
        config.MaxActive = 10
    }
    if config.IdleTimeout <= 0 {
        config.IdleTimeout = 5 * time.Minute
    }

    return &ConnPool{
        connections: make(chan net.Conn, config.MaxIdle),
        factory:     config.Factory,
        maxIdle:     config.MaxIdle,
        maxActive:   config.MaxActive,
        idleTimeout: config.IdleTimeout,
    }
}

// Get retrieves a connection from the pool or creates a new one
func (p *ConnPool) Get() (net.Conn, error) {
    p.mu.Lock()
    if p.closed {
        p.mu.Unlock()
        return nil, ErrPoolClosed
    }

    if p.active >= p.maxActive {
        p.mu.Unlock()
        return nil, ErrPoolExhausted
    }
    p.active++
    p.mu.Unlock()

    // 尝试从空闲连接中获取
    select {
    case conn := <-p.connections:
        if conn == nil || !p.checkConn(conn) {
            conn.Close() // 关闭无效连接
            return p.factory()
        }
        return conn, nil
    default:
        // 没有空闲连接，创建新的
        conn, err := p.factory()
        if err != nil {
            p.mu.Lock()
            p.active--
            p.mu.Unlock()
            return nil, err
        }
        return conn, nil
    }
}

// Put returns a connection to the pool
func (p *ConnPool) Put(conn net.Conn) error {
    if conn == nil {
        return nil
    }

    p.mu.Lock()
    if p.closed {
        p.mu.Unlock()
        conn.Close()
        return nil
    }

    // 检查连接是否有效
    if !p.checkConn(conn) {
        p.active--
        p.mu.Unlock()
        return conn.Close()
    }

    select {
    case p.connections <- conn:
        p.mu.Unlock()
        return nil
    default:
        p.active--
        p.mu.Unlock()
        return conn.Close()
    }
}

// Close closes the connection pool and all its connections
func (p *ConnPool) Close() error {
    p.mu.Lock()
    if p.closed {
        p.mu.Unlock()
        return nil
    }
    p.closed = true
    close(p.connections)
    
    // 关闭所有空闲连接
    for conn := range p.connections {
        conn.Close()
    }
    p.mu.Unlock()
    return nil
}

// 添加连接检查方法
func (p *ConnPool) checkConn(conn net.Conn) bool {
    if tc, ok := conn.(*tls.Conn); ok {
        // 确保TLS连接已经完成握手
        if err := tc.Handshake(); err != nil {
            return false
        }
    }
    return true
} 
